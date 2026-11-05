use anyhow::{Context, Result};
use dhaba_triage::domain::{Ticket, TriageResult};
use serde::Deserialize;

#[derive(Deserialize)]
struct Input { tickets: Vec<Ticket> }

/// An explicit evaluation export, separate from operational logs.
#[tokio::main]
async fn main() -> Result<()> {
    let mut args = std::env::args().skip(1);
    let path = args.next().unwrap_or_else(|| "dhaba_tickets.json".into());
    let base = args.next().unwrap_or_else(|| "http://127.0.0.1:3000".into());
    let input: Input = serde_json::from_slice(&std::fs::read(path).context("read evaluation input")?)?;
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .redirect(reqwest::redirect::Policy::none()).no_proxy().build()?;
    let endpoint = reqwest::Url::parse(&format!("{}/triage", base.trim_end_matches('/')))?;
    anyhow::ensure!(endpoint.scheme() == "http" && matches!(endpoint.host_str(), Some("localhost" | "127.0.0.1" | "[::1]")), "evaluation target must be local HTTP");
    let mut results = Vec::new();
    for ticket in input.tickets {
        let response = client.post(endpoint.clone()).json(&ticket).send().await?;
        anyhow::ensure!(response.status().is_success(), "evaluation request failed: HTTP {}", response.status());
        results.push(response.json::<TriageResult>().await?);
    }
    println!("{}", serde_json::to_string_pretty(&results)?);
    Ok(())
}

