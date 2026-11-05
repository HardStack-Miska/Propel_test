use anyhow::{Context, Result};
use dhaba_triage::{model::Analyzer, service::{AppState, router}, store::Store};
use std::{env, path::PathBuf, time::Duration};

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt().json().with_target(false).with_max_level(tracing::Level::INFO).init();
    let mode = env::var("TRIAGE_MODE").unwrap_or_else(|_| "replay".into());
    let analyzer = match mode.as_str() {
        "replay" => Analyzer::replay(),
        "ollama" => Analyzer::ollama(
            &env::var("OLLAMA_URL").unwrap_or_else(|_| "http://127.0.0.1:11434".into()),
            &env::var("OLLAMA_MODEL").unwrap_or_else(|_| "qwen2.5:3b".into()),
            positive_env("MODEL_CONCURRENCY", 4)?,
            Duration::from_millis(positive_env("MODEL_TIMEOUT_MS", 8000)? as u64),
        )?,
        _ => anyhow::bail!("TRIAGE_MODE must be replay or ollama"),
    };
    let db = PathBuf::from(env::var("TRIAGE_DB").unwrap_or_else(|_| ".runtime/triage.redb".into()));
    if let Some(parent) = db.parent().filter(|p| !p.as_os_str().is_empty()) {
        std::fs::create_dir_all(parent).context("create database directory")?;
    }
    let app = router(AppState::new(Store::open(db)?, analyzer, positive_env("HTTP_CONCURRENCY", 64)?));
    let addr = env::var("TRIAGE_ADDR").unwrap_or_else(|_| "127.0.0.1:3000".into());
    let listener = tokio::net::TcpListener::bind(&addr).await.context("bind service")?;
    tracing::info!(event = "service_started", mode);
    axum::serve(listener, app).with_graceful_shutdown(async { let _ = tokio::signal::ctrl_c().await; }).await?;
    Ok(())
}

fn positive_env(name: &str, default: usize) -> Result<usize> {
    match env::var(name) {
        Ok(value) => value.parse::<usize>().ok().filter(|v| *v > 0).with_context(|| format!("{name} must be a positive integer")),
        Err(env::VarError::NotPresent) => Ok(default),
        Err(_) => anyhow::bail!("{name} must be valid UTF-8"),
    }
}

