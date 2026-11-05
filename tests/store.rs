use dhaba_triage::{
    domain::*,
    policy,
    store::{Lookup, Store},
};
use std::sync::{Arc, Barrier};

fn ticket() -> Ticket {
    serde_json::from_value(serde_json::json!({
        "id":"synthetic-1", "received_at":"2026-09-02T12:00:00+05:30",
        "subject":"Please refund", "body":"The renewal was unexpected. Please refund it.",
        "purchases":[{"id":"synthetic-payment-1","type":"renewal","amount_inr":249,
            "status":"successful","at":"2026-09-01T12:00:00+05:30"}],
        "app_opens_since_renewal":0
    }))
    .unwrap()
}

fn decision(ticket: &Ticket) -> TriageResult {
    policy::evaluate(
        ticket,
        &AnalysisOutcome {
            analysis: Analysis {
                category: Category::BillingRefund,
                severity: Severity::High,
                language: Language::English,
                confidence: 0.99,
                refund_requested: true,
                details: Default::default(),
            },
            source: AnalysisSource::Replay,
            attempts: 0,
            degraded_reason: None,
            usage: Default::default(),
            cached: false,
        },
    )
}

#[test]
fn restart_replays_exact_response_and_conflicting_payload_is_rejected() {
    let tmp = tempfile::tempdir().unwrap();
    let path = tmp.path().join("store.redb");
    let t = ticket();
    let expected = decision(&t);
    assert_eq!(expected.refund.decision, RefundDecision::Approved);
    {
        let store = Store::open(&path).unwrap();
        assert!(store.complete(&t, expected.clone()).unwrap().1);
    }
    let store = Store::open(&path).unwrap();
    let Lookup::Found(actual) = store.lookup(&t).unwrap() else {
        panic!("missing durable response")
    };
    assert_eq!(
        serde_json::to_value(expected).unwrap(),
        serde_json::to_value(actual).unwrap()
    );
    let mut changed = t.clone();
    changed.body.push('!');
    assert!(matches!(store.lookup(&changed).unwrap(), Lookup::Conflict));
    assert!(matches!(
        store.complete(&changed, decision(&changed)).unwrap(),
        (Lookup::Conflict, false)
    ));
}

#[test]
fn concurrent_same_ticket_has_one_commit_and_other_ticket_cannot_reuse_payment() {
    let tmp = tempfile::tempdir().unwrap();
    let store = Store::open(tmp.path().join("store.redb")).unwrap();
    let barrier = Arc::new(Barrier::new(8));
    let threads: Vec<_> = (0..8)
        .map(|_| {
            let store = store.clone();
            let barrier = barrier.clone();
            std::thread::spawn(move || {
                let t = ticket();
                barrier.wait();
                store.complete(&t, decision(&t)).unwrap()
            })
        })
        .collect();
    let results: Vec<_> = threads.into_iter().map(|t| t.join().unwrap()).collect();
    assert_eq!(results.iter().filter(|(_, inserted)| *inserted).count(), 1);
    let mut t = ticket();
    t.id = "synthetic-2".into();
    let (Lookup::Found(result), true) = store.complete(&t, decision(&t)).unwrap() else {
        panic!("not inserted")
    };
    assert_eq!(result.refund.decision, RefundDecision::AlreadyRecorded);
    assert_eq!(result.refund.amount_inr, 0);
    assert!(result.needs_human);
}
