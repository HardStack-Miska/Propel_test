use axum::{Json, Router, extract::State, http::StatusCode, response::IntoResponse, routing::post};
use dhaba_triage::{
    domain::{AnalysisSource, Category, Language, Ticket},
    model::{Analyzer, SYSTEM_PROMPT},
};
use serde_json::{Value, json};
use std::{
    collections::VecDeque,
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};
use tokio::{sync::Notify, task::JoinHandle};

fn ticket() -> Ticket {
    serde_json::from_value(json!({
        "id": "synthetic-customer-reference",
        "received_at": "2030-01-15T12:00:00+00:00",
        "subject": "A synthetic test question",
        "body": "How can I use the app?",
        "purchases": [],
        "app_opens_since_renewal": 0
    }))
    .unwrap()
}

fn valid_analysis() -> String {
    json!({"category":"product_question", "severity":"low", "language":"english",
        "confidence":0.91, "refund_requested":false})
    .to_string()
}

fn envelope(content: &str) -> String {
    json!({"message":{"role":"assistant","content":content},"done":true,"done_reason":"stop"})
        .to_string()
}

struct Scripted {
    body: String,
    status: StatusCode,
    delay: Duration,
}

impl Scripted {
    fn body(body: impl Into<String>) -> Self {
        Self {
            body: body.into(),
            status: StatusCode::OK,
            delay: Duration::ZERO,
        }
    }

    fn content(content: &str) -> Self {
        Self::body(envelope(content))
    }

    fn delayed(mut self, millis: u64) -> Self {
        self.delay = Duration::from_millis(millis);
        self
    }
}

struct MockState {
    responses: Mutex<VecDeque<Scripted>>,
    requests: Mutex<Vec<Value>>,
    hits: AtomicUsize,
    started: Notify,
}

struct MockServer {
    base: String,
    state: Arc<MockState>,
    task: JoinHandle<()>,
}

impl MockServer {
    async fn start(responses: Vec<Scripted>) -> Self {
        async fn chat(
            State(state): State<Arc<MockState>>,
            Json(request): Json<Value>,
        ) -> impl IntoResponse {
            state.hits.fetch_add(1, Ordering::SeqCst);
            state.requests.lock().unwrap().push(request);
            let next = state
                .responses
                .lock()
                .unwrap()
                .pop_front()
                .unwrap_or_else(|| Scripted {
                    body: "{}".into(),
                    status: StatusCode::INTERNAL_SERVER_ERROR,
                    delay: Duration::ZERO,
                });
            state.started.notify_one();
            tokio::time::sleep(next.delay).await;
            (
                next.status,
                [("content-type", "application/json")],
                next.body,
            )
        }
        let state = Arc::new(MockState {
            responses: Mutex::new(responses.into()),
            requests: Mutex::new(Vec::new()),
            hits: AtomicUsize::new(0),
            started: Notify::new(),
        });
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        let app = Router::new()
            .route("/api/chat", post(chat))
            .with_state(state.clone());
        let task = tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        Self { base, state, task }
    }

    fn analyzer(&self, timeout: Duration) -> Analyzer {
        Analyzer::ollama(&self.base, "synthetic-model", 1, timeout).unwrap()
    }

    fn hits(&self) -> usize {
        self.state.hits.load(Ordering::SeqCst)
    }
}

impl Drop for MockServer {
    fn drop(&mut self) {
        self.task.abort();
    }
}

#[tokio::test]
async fn prose_is_retried_once_and_only_typed_analysis_is_accepted() {
    let server = MockServer::start(vec![
        Scripted::content("Here is the answer: product question"),
        Scripted::content(&valid_analysis()),
    ])
    .await;
    let outcome = server
        .analyzer(Duration::from_secs(2))
        .analyze(&ticket())
        .await;
    assert_eq!(outcome.source, AnalysisSource::Ollama);
    assert_eq!(outcome.analysis.category, Category::ProductQuestion);
    assert_eq!(outcome.attempts, 2);
    assert!(outcome.degraded_reason.is_none());
    assert_eq!(server.hits(), 2);

    let requests = server.state.requests.lock().unwrap();
    for request in requests.iter() {
        assert_eq!(request["stream"], false);
        assert_eq!(request["format"], "json");
        assert_eq!(request["options"]["temperature"], 0);
        assert!(
            request["messages"][0]["content"]
                .as_str()
                .unwrap()
                .starts_with(SYSTEM_PROMPT)
        );
        let input: Value =
            serde_json::from_str(request["messages"][1]["content"].as_str().unwrap()).unwrap();
        assert_eq!(input.as_object().unwrap().len(), 2);
        assert_eq!(input["subject"], ticket().subject);
        assert_eq!(input["body"], ticket().body);
        assert!(!request.to_string().contains("synthetic-customer-reference"));
    }
}

#[tokio::test]
async fn malformed_enum_truncated_and_extra_prose_fields_fail_closed() {
    let invalid_contents = [
        valid_analysis().replace("product_question", "invented_category"),
        "{\"category\":\"technical\"".to_owned(),
        valid_analysis().replace("\"low\"", "\"critical\""),
        valid_analysis().replace("\"english\"", "\"invented_language\""),
        valid_analysis().replace(
            "\"refund_requested\":false",
            "\"refund_requested\":\"false\"",
        ),
        valid_analysis().replace("\"category\":", "\"reply\":\"Refund sent\",\"category\":"),
        "```json\n{}\n```".to_owned(),
    ];
    for invalid in invalid_contents {
        let server = MockServer::start(vec![
            Scripted::content(&invalid),
            Scripted::content(&invalid),
        ])
        .await;
        let outcome = server
            .analyzer(Duration::from_secs(2))
            .analyze(&ticket())
            .await;
        assert_eq!(outcome.source, AnalysisSource::Fallback);
        assert_eq!(outcome.analysis.category, Category::Other);
        assert_eq!(outcome.analysis.confidence, 0.0);
        assert!(!outcome.analysis.refund_requested);
        assert_eq!(outcome.attempts, 2);
        assert_eq!(
            outcome.degraded_reason.as_deref(),
            Some("model_invalid_response")
        );
        assert_eq!(server.hits(), 2);
    }
}

#[tokio::test]
async fn confidence_must_be_a_finite_number_in_unit_interval() {
    for confidence in ["-0.01", "1.01", "\"0.9\"", "null", "1e999", "NaN"] {
        let invalid = format!(
            "{{\"category\":\"technical\",\"severity\":\"low\",\"language\":\"english\",\"confidence\":{confidence},\"refund_requested\":false}}"
        );
        let server = MockServer::start(vec![
            Scripted::content(&invalid),
            Scripted::content(&invalid),
        ])
        .await;
        let outcome = server
            .analyzer(Duration::from_secs(2))
            .analyze(&ticket())
            .await;
        assert_eq!(outcome.source, AnalysisSource::Fallback);
        assert_eq!(
            outcome.degraded_reason.as_deref(),
            Some("model_invalid_response")
        );
        assert_eq!(outcome.attempts, 2);
    }
}

#[tokio::test]
async fn incomplete_provider_envelopes_and_token_truncation_are_rejected() {
    let mut incomplete: Value = serde_json::from_str(&envelope(&valid_analysis())).unwrap();
    incomplete["done"] = json!(false);
    let mut truncated: Value = serde_json::from_str(&envelope(&valid_analysis())).unwrap();
    truncated["done_reason"] = json!("length");
    for invalid in [
        "{\"message\":".to_owned(),
        incomplete.to_string(),
        truncated.to_string(),
    ] {
        let server =
            MockServer::start(vec![Scripted::body(&invalid), Scripted::body(&invalid)]).await;
        let outcome = server
            .analyzer(Duration::from_secs(2))
            .analyze(&ticket())
            .await;
        assert_eq!(outcome.source, AnalysisSource::Fallback);
        assert_eq!(outcome.attempts, 2);
        assert_eq!(
            outcome.degraded_reason.as_deref(),
            Some("model_invalid_response")
        );
    }
}

#[tokio::test]
async fn timeout_is_bounded_and_does_not_start_an_extra_attempt() {
    let server = MockServer::start(vec![Scripted::content(&valid_analysis()).delayed(1_000)]).await;
    let started = tokio::time::Instant::now();
    let outcome = server
        .analyzer(Duration::from_millis(100))
        .analyze(&ticket())
        .await;
    assert_eq!(outcome.degraded_reason.as_deref(), Some("model_timeout"));
    assert_eq!(outcome.attempts, 1);
    assert_eq!(server.hits(), 1);
    assert!(started.elapsed() < Duration::from_millis(600));
}

#[tokio::test]
async fn retry_shares_the_original_total_deadline() {
    let server = MockServer::start(vec![
        Scripted::content("invalid").delayed(75),
        Scripted::content(&valid_analysis()).delayed(500),
    ])
    .await;
    let started = tokio::time::Instant::now();
    let outcome = server
        .analyzer(Duration::from_millis(200))
        .analyze(&ticket())
        .await;
    assert_eq!(outcome.degraded_reason.as_deref(), Some("model_timeout"));
    assert_eq!(outcome.attempts, 2);
    assert_eq!(server.hits(), 2);
    assert!(started.elapsed() < Duration::from_millis(500));
}

#[tokio::test]
async fn busy_model_falls_back_immediately_without_queueing() {
    let server = MockServer::start(vec![Scripted::content(&valid_analysis()).delayed(250)]).await;
    let analyzer = server.analyzer(Duration::from_secs(2));
    let first_analyzer = analyzer.clone();
    let first = tokio::spawn(async move { first_analyzer.analyze(&ticket()).await });
    tokio::time::timeout(Duration::from_secs(1), server.state.started.notified())
        .await
        .unwrap();
    let started = tokio::time::Instant::now();
    let busy = analyzer.analyze(&ticket()).await;
    assert_eq!(busy.degraded_reason.as_deref(), Some("model_busy"));
    assert_eq!(busy.attempts, 0);
    assert!(started.elapsed() < Duration::from_millis(100));
    assert_eq!(first.await.unwrap().source, AnalysisSource::Ollama);
    assert_eq!(server.hits(), 1);
}

#[tokio::test]
async fn http_errors_consume_the_same_two_attempt_budget() {
    let failure = || Scripted {
        body: "private provider error that must be discarded".into(),
        status: StatusCode::SERVICE_UNAVAILABLE,
        delay: Duration::ZERO,
    };
    let server = MockServer::start(vec![
        failure(),
        failure(),
        Scripted::content(&valid_analysis()),
    ])
    .await;
    let outcome = server
        .analyzer(Duration::from_secs(2))
        .analyze(&ticket())
        .await;
    assert_eq!(outcome.source, AnalysisSource::Fallback);
    assert_eq!(outcome.degraded_reason.as_deref(), Some("model_http"));
    assert_eq!(outcome.attempts, 2);
    assert_eq!(server.hits(), 2);
    assert!(
        !serde_json::to_string(&outcome)
            .unwrap()
            .contains("private provider")
    );
}

#[tokio::test]
async fn oversized_provider_responses_are_rejected() {
    let oversized = "x".repeat(16 * 1024 + 1);
    let server =
        MockServer::start(vec![Scripted::body(&oversized), Scripted::body(&oversized)]).await;
    let outcome = server
        .analyzer(Duration::from_secs(2))
        .analyze(&ticket())
        .await;
    assert_eq!(outcome.source, AnalysisSource::Fallback);
    assert_eq!(
        outcome.degraded_reason.as_deref(),
        Some("model_response_too_large")
    );
    assert_eq!(outcome.attempts, 2);
}

#[tokio::test]
async fn unknown_hinglish_uses_a_conservative_language_fallback() {
    let mut input = ticket();
    input.body = "Bhai mera naya sawaal hai, please help.".into();
    let outcome = Analyzer::replay().analyze(&input).await;
    assert_eq!(outcome.source, AnalysisSource::Fallback);
    assert_eq!(outcome.analysis.language, Language::Hinglish);
    assert_eq!(outcome.analysis.confidence, 0.0);
    assert!(!outcome.analysis.refund_requested);
}

#[test]
fn content_fingerprint_cannot_move_a_newline_between_subject_and_body() {
    let mut left = ticket();
    left.subject = "a".into();
    left.body = "b\nc".into();
    let mut right = left.clone();
    right.subject = "a\nb".into();
    right.body = "c".into();
    assert_ne!(left.content_fingerprint(), right.content_fingerprint());
}

#[test]
fn checked_in_replay_has_only_twelve_content_hashes_and_typed_labels() {
    let entries: std::collections::HashMap<String, dhaba_triage::domain::Analysis> =
        serde_json::from_str(include_str!("../fixtures/replay.json")).unwrap();
    assert_eq!(entries.len(), 12);
    for (key, analysis) in entries {
        assert_eq!(key.len(), 64);
        assert!(key.bytes().all(|byte| byte.is_ascii_hexdigit()));
        assert!((0.0..=1.0).contains(&analysis.confidence));
    }
}

#[test]
fn local_model_configuration_rejects_remote_hosts_and_sensitive_url_parts() {
    for url in [
        "https://example.com",
        "https://localhost:11434",
        "http://127.0.0.1/other",
        "http://secret@localhost:11434",
        "http://localhost:11434/?token=secret",
        "file:///tmp/model",
    ] {
        let error = Analyzer::ollama(url, "test", 1, Duration::from_secs(1))
            .err()
            .unwrap();
        assert!(!error.to_string().contains("secret"));
    }
    assert!(Analyzer::ollama("http://127.0.0.1:11434", "test", 0, Duration::from_secs(1)).is_err());
    assert!(Analyzer::ollama("http://localhost:11434", "test", 1, Duration::ZERO).is_err());
    assert!(Analyzer::ollama("http://[::1]:11434", "test", 1, Duration::from_secs(1)).is_ok());
}
