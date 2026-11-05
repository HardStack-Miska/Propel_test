use anyhow::{Result, anyhow, bail};
use dhaba_triage::{
    config::analyzer_from_env,
    domain::{Ticket, TriageResult},
    policy,
    store::{Lookup, Store},
};
use serde::Serialize;
use std::{io::Read, process::ExitCode};

const HELP: &str = "Usage: rereview <database> <ticket.json> <review-id> <reason>

Reasons: provider_recovery | model_update | manual_review

Stop the service before opening its database with this offline command.
The input must be one ticket with the exact original payload, including billing.
Each review ID identifies one immutable review; reuse returns the stored result.
Configuration and model budget limits match the service.
Prints an explicit JSON export with inserted and result; it does not send a reply
or execute a payment. The original HTTP response remains unchanged.";

#[derive(Serialize)]
struct Output {
    inserted: bool,
    result: TriageResult,
}

#[tokio::main]
async fn main() -> ExitCode {
    match run().await {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            // Only fixed error codes from run cross this boundary, never a raw
            // database, filesystem, deserialization, or provider error chain.
            eprintln!("rereview_failed: {error}");
            ExitCode::FAILURE
        }
    }
}

async fn run() -> Result<()> {
    let args: Vec<_> = std::env::args_os().skip(1).collect();
    if args.len() == 1 && (args[0] == "--help" || args[0] == "-h") {
        println!("{HELP}");
        return Ok(());
    }
    if args.len() != 4 {
        bail!("invalid_arguments_use_help");
    }
    let review_id = args[2]
        .to_str()
        .ok_or_else(|| anyhow!("invalid_review_id"))?;
    let reason = args[3]
        .to_str()
        .ok_or_else(|| anyhow!("invalid_review_reason"))?;
    // Bound file reads just like the HTTP request body, before deserializing.
    let file = std::fs::File::open(&args[1]).map_err(|_| anyhow!("ticket_input_unavailable"))?;
    let mut input = Vec::new();
    file.take(65_537)
        .read_to_end(&mut input)
        .map_err(|_| anyhow!("ticket_input_unavailable"))?;
    if input.len() > 65_536 {
        bail!("ticket_input_too_large");
    }
    let ticket: Ticket =
        serde_json::from_slice(&input).map_err(|_| anyhow!("invalid_ticket_schema"))?;
    ticket.validate().map_err(|_| anyhow!("invalid_ticket"))?;
    if !std::path::Path::new(&args[0]).is_file() {
        bail!("original_database_missing");
    }
    let store =
        Store::open(&args[0]).map_err(|_| anyhow!("database_unavailable_stop_service_first"))?;
    let lookup = store
        .lookup_review(&ticket, review_id, reason)
        .map_err(|_| anyhow!("review_precondition_failed_check_original_id_and_reason"))?;
    let (result, inserted) = match lookup {
        Lookup::Found(result) => (result, false),
        Lookup::Conflict => bail!("review_id_or_original_payload_conflict"),
        Lookup::Missing => {
            // Configure or contact a provider only after all stored preconditions
            // pass. An existing review remains available even without API keys.
            let analyzer =
                analyzer_from_env().map_err(|_| anyhow!("invalid_model_configuration"))?;
            let outcome = analyzer.analyze(&ticket).await;
            let proposed = policy::evaluate(&ticket, &outcome);
            match store
                .review(&ticket, proposed, review_id, reason)
                .map_err(|_| anyhow!("review_commit_failed"))?
            {
                (Lookup::Found(result), inserted) => (result, inserted),
                (Lookup::Conflict, _) => bail!("review_id_or_original_payload_conflict"),
                (Lookup::Missing, _) => bail!("review_commit_failed"),
            }
        }
    };
    let output = serde_json::to_string_pretty(&Output { inserted, result })
        .map_err(|_| anyhow!("review_export_failed"))?;
    println!("{output}");
    Ok(())
}
