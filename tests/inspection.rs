//! Independent inspection cases. These use synthetic customer text and local
//! mocks; no fixture classifications, credentials, or external API are needed.
//! A failing assertion records an unresolved service defect, not an expected pass.

use axum::{
    Json, Router,
    body::Body,
    http::{Request, StatusCode},
    routing::post,
};
use chrono::Duration as ChronoDuration;
use dhaba_triage::{
    domain::*,
    model::Analyzer,
    policy::evaluate,
    service::{AppState, router},
    store::{Lookup, Store},
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

fn ticket(id: &str, subject: &str, body: &str) -> Ticket {
    let received_at = "2030-06-03T12:00:00Z".parse().unwrap();
    Ticket {
        id: id.into(),
        received_at,
        subject: subject.into(),
        body: body.into(),
        purchases: vec![
            Purchase {
                id: format!("{id}-trial"),
                kind: PurchaseKind::Trial,
                amount_inr: 1,
                status: PurchaseStatus::Successful,
                at: received_at - ChronoDuration::days(7),
            },
            Purchase {
                id: format!("{id}-renewal"),
                kind: PurchaseKind::Renewal,
                amount_inr: 249,
                status: PurchaseStatus::Successful,
                at: received_at - ChronoDuration::hours(12),
            },
        ],
        app_opens_since_renewal: 0,
    }
}

fn analysis(category: Category, refund_requested: bool) -> AnalysisOutcome {
    AnalysisOutcome {
        analysis: Analysis {
            category,
            severity: Severity::Medium,
            language: Language::English,
            confidence: 0.99,
            refund_requested,
            details: Default::default(),
        },
        source: AnalysisSource::Deepseek,
        attempts: 1,
        degraded_reason: None,
        usage: Default::default(),
        cached: false,
    }
}

fn request(ticket: &Ticket) -> Request<Body> {
    Request::post("/triage")
        .header("content-type", "application/json")
        .body(Body::from(serde_json::to_vec(ticket).unwrap()))
        .unwrap()
}

#[test]
fn selective_trial_refund_never_approves_the_subscription_customer_wants_to_keep() {
    let ticket = ticket(
        "inspection-selective-refund",
        "Return only the trial payment",
        "Please refund only the Rs 1 trial payment. Keep my Rs 249 subscription; do not refund that subscription payment.",
    );
    let mut outcome = analysis(Category::BillingRefund, true);
    outcome.analysis.details.reported = vec![ReportedFact::RefundExplicit];
    outcome.analysis.details.refund_target = RefundTarget::Trial;
    assert!(ticket.validate().is_ok());
    assert!(outcome.analysis.validate());

    let result = evaluate(&ticket, &outcome);

    // The customer explicitly excluded the otherwise eligible renewal. The
    // policy must evaluate the trial instead of substituting another payment.
    assert_eq!(result.refund.decision, RefundDecision::NotEligible);
    assert_eq!(result.refund.amount_inr, 0);
    assert!(result.refund.purchase_id.is_none());
}

#[test]
fn negated_fraud_does_not_override_a_correct_invoice_classification() {
    let ticket = ticket(
        "inspection-negated-fraud",
        "Tax invoice for an authorized payment",
        "This is not fraud. I recognize and authorized this payment. I only need a tax invoice for it.",
    );
    let outcome = analysis(Category::Invoice, false);
    assert!(outcome.analysis.validate());

    let result = evaluate(&ticket, &outcome);

    assert_eq!(result.category, Category::Invoice);
    assert_ne!(result.severity, Severity::Urgent);
    assert_eq!(result.refund.decision, RefundDecision::NotRequested);
    let reply = result.reply_draft.to_lowercase();
    assert!(reply.contains("invoice"));
    assert!(!reply.contains("unauthorized-payment"));
    assert!(!reply.contains("contact your bank"));
}

#[test]
fn refund_cancellation_and_invoice_request_preserves_all_three_customer_goals() {
    let ticket = ticket(
        "inspection-three-goals",
        "Refund, stop renewals, and provide invoice",
        "Please refund the latest Rs 249 charge, stop all future subscription renewals, and send the invoice for that payment.",
    );
    let mut outcome = analysis(Category::BillingRefund, true);
    outcome.analysis.details.secondary_intent = Some(Category::Cancellation);
    outcome.analysis.details.additional_intents = vec![Category::Invoice];
    outcome.analysis.details.refund_target = RefundTarget::LatestRenewal;
    outcome.analysis.details.reported = vec![
        ReportedFact::RefundExplicit,
        ReportedFact::CancellationExplicit,
    ];
    assert!(outcome.analysis.validate());

    // The typed interface must preserve every extracted goal. End-to-end
    // evaluation separately measures whether a live model extracts all three.
    let result = evaluate(&ticket, &outcome);
    let reply = result.reply_draft.to_lowercase();

    assert!(reply.contains("refund"));
    assert!(reply.contains("cancellation"));
    assert!(
        reply.contains("invoice"),
        "the invoice request must not disappear behind the two-intent boundary"
    );
    assert!(!reply.contains("refund has been processed"));
    assert!(!reply.contains("subscription has been cancelled"));
    assert!(!reply.contains("invoice has been sent"));
}

#[tokio::test]
async fn http_overload_is_retryable_unrecorded_and_recovers_without_extra_provider_calls() {
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
                    if hits.fetch_add(1, Ordering::SeqCst) == 0 {
                        started.notify_one();
                        release.notified().await;
                    }
                    Json(json!({
                        "message": {
                            "role": "assistant",
                            "content": json!({
                                "category": "technical",
                                "severity": "medium",
                                "language": "english",
                                "confidence": 0.99,
                                "refund_requested": false,
                                "details": {
                                    "secondary_intent": null,
                                    "additional_intents": [],
                                    "refund_target": "unspecified",
                                    "unsupported_language": false,
                                    "reported": ["error_details_provided"],
                                    "missing": ["app_version"]
                                }
                            }).to_string()
                        },
                        "done": true,
                        "done_reason": "stop"
                    }))
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
    let store = Store::open(tmp.path().join("inspection.redb")).unwrap();
    let analyzer = Analyzer::ollama(&base, "inspection-mock", 1, Duration::from_secs(5))
        .unwrap()
        .without_cache();
    let app = router(AppState::new(store.clone(), analyzer, 1));
    let mut first_ticket = ticket(
        "inspection-overload-first",
        "Search freezes",
        "Tapping Search freezes the page.",
    );
    first_ticket.purchases.clear();
    let mut second_ticket = ticket(
        "inspection-overload-second",
        "Playback stops",
        "Tapping Play stops playback after one second.",
    );
    second_ticket.purchases.clear();

    let first = tokio::spawn(app.clone().oneshot(request(&first_ticket)));
    tokio::time::timeout(Duration::from_secs(2), started.notified())
        .await
        .expect("the first request must reach the local model mock");

    let busy = tokio::time::timeout(
        Duration::from_secs(1),
        app.clone().oneshot(request(&second_ticket)),
    )
    .await
    .expect("HTTP saturation must reject immediately")
    .unwrap();
    assert_eq!(busy.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(busy.headers().get("retry-after").unwrap(), "1");
    let busy_body: Value =
        serde_json::from_slice(&busy.into_body().collect().await.unwrap().to_bytes()).unwrap();
    assert_eq!(busy_body, json!({"error":"service_busy","retryable":true}));
    assert_eq!(hits.load(Ordering::SeqCst), 1);
    assert!(matches!(
        store.lookup(&second_ticket).unwrap(),
        Lookup::Missing
    ));

    release.notify_one();
    let first = tokio::time::timeout(Duration::from_secs(2), first)
        .await
        .expect("the first request must finish after the model is released")
        .unwrap()
        .unwrap();
    assert_eq!(first.status(), StatusCode::OK);

    let recovered = tokio::time::timeout(
        Duration::from_secs(2),
        app.clone().oneshot(request(&second_ticket)),
    )
    .await
    .expect("retry must succeed after the HTTP slot is released")
    .unwrap();
    assert_eq!(recovered.status(), StatusCode::OK);
    let recovered = recovered.into_body().collect().await.unwrap().to_bytes();
    let result: TriageResult = serde_json::from_slice(&recovered).unwrap();
    assert_eq!(result.ticket_id, second_ticket.id);
    assert_eq!(result.category, Category::Technical);
    assert_eq!(result.meta.source, AnalysisSource::Ollama);
    assert!(result.meta.degraded_reason.is_none());
    assert_eq!(hits.load(Ordering::SeqCst), 2);
    match store.lookup(&second_ticket).unwrap() {
        Lookup::Found(stored) => assert_eq!(
            serde_json::to_value(stored).unwrap(),
            serde_json::to_value(&result).unwrap()
        ),
        other => panic!("the successful retry must be durably recorded: {other:?}"),
    }

    let replay = app.oneshot(request(&second_ticket)).await.unwrap();
    assert_eq!(replay.status(), StatusCode::OK);
    assert_eq!(
        recovered,
        replay.into_body().collect().await.unwrap().to_bytes()
    );
    assert_eq!(hits.load(Ordering::SeqCst), 2);
    server.abort();
}
