use axum::{
    Json, Router,
    body::Body,
    http::{Request, StatusCode},
    routing::post,
};
use dhaba_triage::{
    model::Analyzer,
    service::{AppState, router},
    store::Store,
};
use http_body_util::BodyExt;
use serde_json::{Value, json};
use std::{
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};
use tokio::sync::Notify;
use tower::ServiceExt;

fn request(value: &Value) -> Request<Body> {
    Request::post("/triage")
        .header("content-type", "application/json")
        .body(Body::from(value.to_string()))
        .unwrap()
}

#[tokio::test]
async fn duplicate_waits_for_original_analysis_and_changed_payload_conflicts() {
    let started = Arc::new(Notify::new());
    let release = Arc::new(Notify::new());
    let hits = Arc::new(AtomicUsize::new(0));
    let mock = Router::new().route(
        "/api/chat",
        post({
            let started = started.clone();
            let release = release.clone();
            let hits = hits.clone();
            move || {
                let started = started.clone();
                let release = release.clone();
                let hits = hits.clone();
                async move {
                    hits.fetch_add(1, Ordering::SeqCst);
                    started.notify_one();
                    release.notified().await;
                    Json(json!({"message":{"role":"assistant","content":
                    json!({"category":"technical","severity":"medium","language":"english",
                        "confidence":0.99,"refund_requested":false}).to_string()},
                    "done":true,"done_reason":"stop"}))
                }
            }
        }),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base = format!("http://{}", listener.local_addr().unwrap());
    let server = tokio::spawn(async move {
        axum::serve(listener, mock).await.unwrap();
    });
    let tmp = tempfile::tempdir().unwrap();
    let analyzer = Analyzer::ollama(&base, "mock", 1, Duration::from_secs(3)).unwrap();
    let app = router(AppState::new(
        Store::open(tmp.path().join("triage.redb")).unwrap(),
        analyzer,
        8,
    ));
    let input = json!({"id":"concurrent-event","received_at":"2030-01-01T12:00:00Z",
        "subject":"Synthetic app problem","body":"The app fails to start.",
        "purchases":[],"app_opens_since_renewal":0});
    let first = tokio::spawn(app.clone().oneshot(request(&input)));
    tokio::time::timeout(Duration::from_secs(1), started.notified())
        .await
        .unwrap();
    let mut duplicate = Box::pin(app.clone().oneshot(request(&input)));
    // A duplicate must not commit model_busy while the original is healthy.
    assert!(
        tokio::time::timeout(Duration::from_millis(150), &mut duplicate)
            .await
            .is_err()
    );
    let mut changed = input.clone();
    changed["body"] = json!("A different synthetic issue.");
    let conflict = tokio::spawn(app.clone().oneshot(request(&changed)));
    release.notify_one();
    let first = first.await.unwrap().unwrap();
    assert_eq!(first.status(), StatusCode::OK);
    let first = first.into_body().collect().await.unwrap().to_bytes();
    let duplicate = duplicate
        .await
        .unwrap()
        .into_body()
        .collect()
        .await
        .unwrap()
        .to_bytes();
    assert_eq!(first, duplicate);
    let result: Value = serde_json::from_slice(&first).unwrap();
    assert_eq!(result["category"], "technical");
    assert_eq!(result["meta"]["source"], "ollama");
    assert!(result["meta"]["degraded_reason"].is_null());
    assert_eq!(
        conflict.await.unwrap().unwrap().status(),
        StatusCode::CONFLICT
    );
    let replay = app
        .oneshot(request(&input))
        .await
        .unwrap()
        .into_body()
        .collect()
        .await
        .unwrap()
        .to_bytes();
    assert_eq!(first, replay);
    assert_eq!(hits.load(Ordering::SeqCst), 1);
    server.abort();
}
