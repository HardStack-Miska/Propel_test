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
                details: AnalysisDetails {
                    refund_target: RefundTarget::LatestRenewal,
                    ..Default::default()
                },
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

#[test]
fn duplicate_payment_keeps_refund_cancellation_and_invoice_in_the_supported_language() {
    for language in [Language::English, Language::Hinglish] {
        let tmp = tempfile::tempdir().unwrap();
        let store = Store::open(tmp.path().join("multilingual.redb")).unwrap();
        let mut first = ticket();
        first.subject = match language {
            Language::English => "Refund, stop renewals, and provide invoice",
            Language::Hinglish => "Refund, renewal band aur invoice",
        }
        .into();
        first.body = match language {
            Language::English => "Please refund my latest monthly charge, stop future renewals, and provide an invoice using my supplied billing details.",
            Language::Hinglish => "Mera latest monthly charge refund kar do, aage ke renewals band kar do aur diye hue billing details par invoice bhej do.",
        }.into();
        let outcome = AnalysisOutcome {
            analysis: Analysis {
                category: Category::BillingRefund,
                severity: Severity::Medium,
                language,
                confidence: 0.99,
                refund_requested: true,
                details: AnalysisDetails {
                    additional_intents: vec![Category::Cancellation, Category::Invoice],
                    refund_target: RefundTarget::LatestRenewal,
                    reported: vec![
                        ReportedFact::RefundExplicit,
                        ReportedFact::CancellationExplicit,
                        ReportedFact::BillingDetailsProvided,
                    ],
                    ..Default::default()
                },
            },
            source: AnalysisSource::Replay,
            attempts: 0,
            degraded_reason: None,
            usage: Default::default(),
            cached: false,
        };
        let first_result = policy::evaluate(&first, &outcome);
        assert_eq!(first_result.refund.decision, RefundDecision::Approved);
        assert_eq!(first_result.refund.amount_inr, 249);
        assert_eq!(first_result.meta.language, Some(language));
        assert!(matches!(
            store.complete(&first, first_result.clone()).unwrap(),
            (Lookup::Found(_), true)
        ));

        let mut duplicate = first.clone();
        duplicate.id = "synthetic-second-delivery-same-payment".into();
        let (Lookup::Found(recorded), true) = store
            .complete(&duplicate, policy::evaluate(&duplicate, &outcome))
            .unwrap()
        else {
            panic!("the distinct ticket should have its own durable zero-money response");
        };
        assert_eq!(recorded.refund.decision, RefundDecision::AlreadyRecorded);
        assert_eq!(recorded.refund.amount_inr, 0);
        assert_eq!(
            recorded.refund.purchase_id.as_deref(),
            Some("synthetic-payment-1")
        );
        assert_eq!(recorded.meta.language, Some(language));
        assert!(recorded.needs_human);
        match language {
            Language::English => {
                assert!(recorded.reply_draft.contains("already recorded"));
                assert!(recorded.reply_draft.contains("stopping future renewals"));
                assert!(
                    recorded
                        .reply_draft
                        .contains("before an invoice can be provided")
                );
                assert!(!recorded.reply_draft.contains("refund request is approved"));
            }
            Language::Hinglish => {
                assert!(recorded.reply_draft.contains("pehle se recorded hai"));
                assert!(
                    recorded
                        .reply_draft
                        .contains("Aage ke renewals rokne ke liye")
                );
                assert!(recorded.reply_draft.contains("Invoice dene se pehle"));
                assert!(!recorded.reply_draft.contains("refund request approved hai"));
            }
        }
        let Lookup::Found(unchanged) = store.lookup(&first).unwrap() else {
            panic!("the original response must remain available");
        };
        assert_eq!(
            serde_json::to_value(unchanged).unwrap(),
            serde_json::to_value(first_result).unwrap()
        );
    }
}
