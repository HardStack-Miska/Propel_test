use anyhow::{Context, Result};
use dhaba_triage::{
    config::Config,
    service::{AppState, router},
    store::Store,
};
use std::path::PathBuf;

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .json()
        .with_target(false)
        .with_max_level(tracing::Level::INFO)
        .init();
    let config = Config::load()?;
    let mode = config.get("TRIAGE_MODE", "replay")?;
    let analyzer = config.analyzer()?;
    let db = PathBuf::from(config.get("TRIAGE_DB", ".runtime/triage.redb")?);
    if let Some(parent) = db.parent().filter(|p| !p.as_os_str().is_empty()) {
        std::fs::create_dir_all(parent).context("create database directory")?;
    }
    let app = router(AppState::new(
        Store::open(db)?,
        analyzer,
        usize::try_from(config.positive("HTTP_CONCURRENCY", 64)?)?,
    ));
    let addr = config.get("TRIAGE_ADDR", "127.0.0.1:3000")?;
    let listener = tokio::net::TcpListener::bind(&addr)
        .await
        .context("bind service")?;
    tracing::info!(event = "service_started", mode);
    axum::serve(listener, app)
        .with_graceful_shutdown(async {
            let _ = tokio::signal::ctrl_c().await;
        })
        .await?;
    Ok(())
}
