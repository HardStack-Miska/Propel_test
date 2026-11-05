use crate::{
    domain::{AnalysisSource, Ticket, TriageResult},
    model::Analyzer,
    policy,
    store::{Lookup, Store},
};
use axum::{
    Json, Router,
    extract::{DefaultBodyLimit, State, rejection::JsonRejection},
    http::{HeaderMap, HeaderValue, StatusCode},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use serde_json::json;
use std::{
    collections::HashMap,
    sync::{
        Arc, Mutex, Weak,
        atomic::{AtomicU64, Ordering},
    },
    time::{Instant, SystemTime, UNIX_EPOCH},
};
use tokio::sync::Semaphore;

#[derive(Default)]
struct Metrics {
    evaluated: AtomicU64,
    degraded: AtomicU64,
    cache_hits: AtomicU64,
    overload: AtomicU64,
}

#[derive(Clone, Copy)]
struct ErrorCode(&'static str);

#[derive(Clone)]
pub struct AppState {
    store: Store,
    analyzer: Analyzer,
    slots: Arc<Semaphore>,
    metrics: Arc<Metrics>,
    sequence: Arc<AtomicU64>,
    boot: u128,
    ticket_locks: Arc<Mutex<HashMap<String, Weak<tokio::sync::Mutex<()>>>>>,
}

impl AppState {
    pub fn new(store: Store, analyzer: Analyzer, capacity: usize) -> Self {
        assert!(capacity > 0);
        Self {
            store,
            analyzer,
            slots: Arc::new(Semaphore::new(capacity)),
            metrics: Arc::new(Metrics::default()),
            sequence: Arc::new(AtomicU64::new(1)),
            ticket_locks: Arc::new(Mutex::new(HashMap::new())),
            boot: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos(),
        }
    }
}

pub fn router(state: AppState) -> Router {
    Router::new()
        .route("/triage", post(triage))
        .route("/health", get(|| async { Json(json!({"status":"ok"})) }))
        .route("/metrics", get(metrics))
        .layer(DefaultBodyLimit::max(64 * 1024))
        .with_state(state)
}

async fn metrics(State(state): State<AppState>) -> impl IntoResponse {
    let evaluated = state.metrics.evaluated.load(Ordering::Relaxed);
    let degraded = state.metrics.degraded.load(Ordering::Relaxed);
    Json(json!({
        "triage_evaluated_total": evaluated,
        "triage_degraded_total": degraded,
        "triage_degraded_ratio": if evaluated == 0 { 0.0 } else { degraded as f64 / evaluated as f64 },
        "triage_cache_hits_total": state.metrics.cache_hits.load(Ordering::Relaxed),
        "triage_http_overload_total": state.metrics.overload.load(Ordering::Relaxed),
    }))
}

async fn triage(
    State(state): State<AppState>,
    payload: Result<Json<Ticket>, JsonRejection>,
) -> Response {
    let request_id = format!(
        "{:x}-{}",
        state.boot,
        state.sequence.fetch_add(1, Ordering::Relaxed)
    );
    let start = Instant::now();
    let response = handle(&state, payload, &request_id).await;
    // Deliberately no URI, input, payment/ticket identifier, headers, errors, or response text.
    let error_code = response
        .extensions()
        .get::<ErrorCode>()
        .map(|code| code.0)
        .unwrap_or("none");
    tracing::info!(
        event = "triage_request",
        request_id,
        status = response.status().as_u16(),
        error_code,
        elapsed_ms = start.elapsed().as_millis() as u64
    );
    let mut response = response;
    response.headers_mut().insert(
        "x-request-id",
        HeaderValue::from_str(&request_id).expect("generated ASCII"),
    );
    response
}

async fn handle(
    state: &AppState,
    payload: Result<Json<Ticket>, JsonRejection>,
    request_id: &str,
) -> Response {
    let ticket = match payload {
        Ok(Json(ticket)) => ticket,
        Err(rejection) => {
            let status = if rejection.status() == StatusCode::PAYLOAD_TOO_LARGE {
                StatusCode::PAYLOAD_TOO_LARGE
            } else {
                StatusCode::BAD_REQUEST
            };
            return error(status, "invalid_ticket_json");
        }
    };
    if let Err(code) = ticket.validate() {
        return error(StatusCode::BAD_REQUEST, code);
    }
    let _slot = match state.slots.clone().try_acquire_owned() {
        Ok(slot) => slot,
        Err(_) => {
            state.metrics.overload.fetch_add(1, Ordering::Relaxed);
            let mut headers = HeaderMap::new();
            headers.insert("retry-after", HeaderValue::from_static("1"));
            let mut response = (
                StatusCode::SERVICE_UNAVAILABLE,
                headers,
                Json(json!({"error":"service_busy","retryable":true})),
            )
                .into_response();
            response.extensions_mut().insert(ErrorCode("service_busy"));
            return response;
        }
    };
    let store = state.store.clone();
    let lookup_ticket = ticket.clone();
    // Share one analysis for concurrent deliveries of a ticket. A weak map
    // retains no ticket text and is pruned on acquisition, so completed tickets
    // cannot accumulate. HTTP slots bound the number of live owners/waiters.
    let ticket_lock = {
        let mut locks = state.ticket_locks.lock().expect("ticket lock registry");
        locks.retain(|_, lock| lock.strong_count() > 0);
        let key = crate::domain::hash_bytes(ticket.id.as_bytes());
        match locks.get(&key).and_then(Weak::upgrade) {
            Some(lock) => lock,
            None => {
                let lock = Arc::new(tokio::sync::Mutex::new(()));
                locks.insert(key, Arc::downgrade(&lock));
                lock
            }
        }
    };
    let _ticket_guard = ticket_lock.lock_owned().await;
    match tokio::task::spawn_blocking(move || store.lookup(&lookup_ticket)).await {
        Ok(Ok(Lookup::Found(result))) => {
            state.metrics.cache_hits.fetch_add(1, Ordering::Relaxed);
            log_decision(request_id, &result, true);
            return Json(result).into_response();
        }
        Ok(Ok(Lookup::Conflict)) => {
            return error(StatusCode::CONFLICT, "ticket_id_payload_conflict");
        }
        Ok(Ok(Lookup::Missing)) => {}
        _ => return error(StatusCode::SERVICE_UNAVAILABLE, "storage_unavailable"),
    }
    let outcome = state.analyzer.analyze(&ticket).await;
    let result = policy::evaluate(&ticket, &outcome);
    let store = state.store.clone();
    let stored = tokio::task::spawn_blocking(move || store.complete(&ticket, result)).await;
    match stored {
        Ok(Ok((Lookup::Found(result), inserted))) => {
            if inserted {
                state.metrics.evaluated.fetch_add(1, Ordering::Relaxed);
                if result.meta.source == AnalysisSource::Fallback {
                    state.metrics.degraded.fetch_add(1, Ordering::Relaxed);
                }
            } else {
                state.metrics.cache_hits.fetch_add(1, Ordering::Relaxed);
            }
            log_decision(request_id, &result, !inserted);
            Json(result).into_response()
        }
        Ok(Ok((Lookup::Conflict, _))) => error(StatusCode::CONFLICT, "ticket_id_payload_conflict"),
        _ => error(StatusCode::SERVICE_UNAVAILABLE, "storage_unavailable"),
    }
}

fn log_decision(request_id: &str, result: &TriageResult, cached: bool) {
    tracing::info!(event = "triage_decision", request_id, cached,
        category = ?result.category, decision = ?result.refund.decision,
        source = ?result.meta.source, attempts = result.meta.model_attempts,
        degraded_reason = result.meta.degraded_reason.as_deref().unwrap_or("none"),
        needs_human = result.needs_human);
}

fn error(status: StatusCode, code: &'static str) -> Response {
    let mut response = (status, Json(json!({"error":code}))).into_response();
    response.extensions_mut().insert(ErrorCode(code));
    response
}
