use anyhow::{Result, anyhow, bail};
use dhaba_triage::domain::{Ticket, TriageResult};
use serde::Deserialize;
use std::{io::Read, process::ExitCode};

#[derive(Deserialize)]
struct Input {
    tickets: Vec<Ticket>,
}

/// An explicit evaluation export, separate from operational logs.
#[tokio::main]
async fn main() -> ExitCode {
    match run().await {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            // Never forward input values, paths, URLs, or provider error chains.
            eprintln!("evaluation_failed: {error}");
            ExitCode::FAILURE
        }
    }
}

async fn run() -> Result<()> {
    let mut args = std::env::args_os().skip(1);
    let path = args.next().unwrap_or_else(|| "dhaba_tickets.json".into());
    let base = args
        .next()
        .unwrap_or_else(|| "http://127.0.0.1:3000".into());
    if args.next().is_some() {
        bail!("invalid_arguments");
    }
    // Use the same bounded input policy as the offline rereview command.
    let file = std::fs::File::open(path).map_err(|_| anyhow!("evaluation_input_unavailable"))?;
    let mut input = Vec::new();
    file.take(65_537)
        .read_to_end(&mut input)
        .map_err(|_| anyhow!("evaluation_input_unavailable"))?;
    if input.len() > 65_536 {
        bail!("evaluation_input_too_large");
    }
    let input: Input =
        serde_json::from_slice(&input).map_err(|_| anyhow!("invalid_evaluation_schema"))?;
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .redirect(reqwest::redirect::Policy::none())
        .no_proxy()
        .build()
        .map_err(|_| anyhow!("evaluation_client_unavailable"))?;
    let base = base
        .to_str()
        .ok_or_else(|| anyhow!("invalid_evaluation_target"))?;
    let endpoint = reqwest::Url::parse(&format!("{}/triage", base.trim_end_matches('/')))
        .map_err(|_| anyhow!("invalid_evaluation_target"))?;
    anyhow::ensure!(
        endpoint.scheme() == "http"
            && matches!(
                endpoint.host_str(),
                Some("localhost" | "127.0.0.1" | "[::1]")
            ),
        "evaluation_target_must_be_local_http"
    );
    let mut results = Vec::new();
    for ticket in input.tickets {
        let response = client
            .post(endpoint.clone())
            .json(&ticket)
            .send()
            .await
            .map_err(|_| anyhow!("evaluation_request_unavailable"))?;
        anyhow::ensure!(
            response.status().is_success(),
            "evaluation_request_failed_http_{}",
            response.status().as_u16()
        );
        results.push(
            response
                .json::<TriageResult>()
                .await
                .map_err(|_| anyhow!("invalid_evaluation_response"))?,
        );
    }
    let output =
        serde_json::to_string_pretty(&results).map_err(|_| anyhow!("evaluation_export_failed"))?;
    println!("{output}");
    Ok(())
}
