use axum::{
    body::Body,
    http::{Request, StatusCode},
};
use dhaba_triage::{
    model::Analyzer,
    service::{AppState, router},
    store::Store,
};
use http_body_util::BodyExt;
use serde_json::{Value, json};
use tower::ServiceExt;

fn app() -> (tempfile::TempDir, axum::Router) {
    let tmp = tempfile::tempdir().unwrap();
    let store = Store::open(tmp.path().join("store.redb")).unwrap();
    let app = router(AppState::new(store, Analyzer::replay(), 2));
    (tmp, app)
}

fn request(value: Value) -> Request<Body> {
    Request::builder()
        .method("POST")
        .uri("/triage")
        .header("content-type", "application/json")
        .body(Body::from(value.to_string()))
        .unwrap()
}

fn unknown_ticket() -> Value {
    json!({"id":"synthetic-http","received_at":"2026-09-02T12:00:00Z",
        "subject":"Unseen question","body":"Could someone help with a new issue?",
        "purchases":[],"app_opens_since_renewal":0})
}

#[tokio::test]
async fn unknown_replay_fails_safe_and_idempotency_is_visible_over_http() {
    let (_tmp, app) = app();
    let value = unknown_ticket();
    let response = app.clone().oneshot(request(value.clone())).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert!(response.headers().contains_key("x-request-id"));
    let first = response.into_body().collect().await.unwrap().to_bytes();
    let parsed: Value = serde_json::from_slice(&first).unwrap();
    assert_eq!(parsed["needs_human"], true);
    assert_eq!(parsed["refund"]["amount_inr"], 0);
    assert_eq!(parsed["meta"]["source"], "fallback");
    let repeated = app.clone().oneshot(request(value.clone())).await.unwrap();
    assert_eq!(
        first,
        repeated.into_body().collect().await.unwrap().to_bytes()
    );
    let mut changed = value;
    changed["body"] = json!("Changed text");
    let conflict = app.oneshot(request(changed)).await.unwrap();
    assert_eq!(conflict.status(), StatusCode::CONFLICT);
}

#[tokio::test]
async fn invalid_schema_and_payload_limits_return_sanitized_errors() {
    let (_tmp, app) = app();
    let mut invalid = unknown_ticket();
    invalid["purchases"] = json!([{"id":"PRIVATE-SENTINEL"}]);
    let response = app.clone().oneshot(request(invalid)).await.unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let body = response.into_body().collect().await.unwrap().to_bytes();
    assert!(!String::from_utf8_lossy(&body).contains("PRIVATE-SENTINEL"));
    let mut huge = unknown_ticket();
    huge["body"] = json!("x".repeat(70_000));
    assert_eq!(
        app.clone().oneshot(request(huge)).await.unwrap().status(),
        StatusCode::PAYLOAD_TOO_LARGE
    );
    let mut future = unknown_ticket();
    future["purchases"] = json!([{
        "id":"payment", "type":"renewal", "amount_inr":249, "status":"successful", "at":"2027-01-01T00:00:00Z"
    }]);
    assert_eq!(
        app.oneshot(request(future)).await.unwrap().status(),
        StatusCode::BAD_REQUEST
    );
}
