use dhaba_triage::{
    domain::{AnalysisOutcome, RefundDecision, Ticket, TriageResult, hash_bytes},
    policy,
    store::{Lookup, Store},
};
use redb::{Database, ReadableTable, TableDefinition};
use serde_json::{Value, json};
use std::{
    path::Path,
    process::Command,
    sync::{Arc, Barrier},
};

const RESULTS: TableDefinition<&str, &str> = TableDefinition::new("triage_results_v1");
const REFUNDS: TableDefinition<&str, &str> = TableDefinition::new("refund_approvals_v1");
const REVIEWS: TableDefinition<&str, &str> = TableDefinition::new("triage_reviews_v1");

fn ticket() -> Ticket {
    serde_json::from_value(json!({
        "id": "synthetic-review-ticket",
        "received_at": "2026-09-02T12:00:00Z",
        "subject": "Please refund the renewal",
        "body": "SYNTHETIC-ORIGINAL-MESSAGE. Please refund this unexpected renewal.",
        "purchases": [{"id": "synthetic-review-payment", "type": "renewal", "amount_inr": 249,
            "status": "successful", "at": "2026-09-01T12:00:00Z"}],
        "app_opens_since_renewal": 0
    }))
    .unwrap()
}

fn decision(ticket: &Ticket, recovered: bool) -> TriageResult {
    let outcome: AnalysisOutcome = serde_json::from_value(json!({
        "analysis": {
            "category": "billing_refund", "severity": "medium", "language": "english",
            "confidence": if recovered { 0.99 } else { 0.0 }, "refund_requested": true
        },
        "source": if recovered { "replay" } else { "fallback" },
        "attempts": 0,
        "degraded_reason": if recovered { None } else { Some("provider_unavailable") }
    }))
    .unwrap();
    policy::evaluate(ticket, &outcome)
}

fn found(lookup: Lookup) -> TriageResult {
    match lookup {
        Lookup::Found(result) => result,
        other => panic!("expected stored result, got {other:?}"),
    }
}

fn value(result: &TriageResult) -> Value {
    serde_json::to_value(result).unwrap()
}

fn raw_records(path: &Path) -> (Vec<String>, Vec<String>) {
    let db = Database::open(path).unwrap();
    let tx = db.begin_read().unwrap();
    let results = tx.open_table(RESULTS).unwrap();
    let reviews = tx.open_table(REVIEWS).unwrap();
    let collect = |table: &redb::ReadOnlyTable<&str, &str>| {
        table
            .iter()
            .unwrap()
            .map(|entry| entry.unwrap().1.value().to_owned())
            .collect()
    };
    (collect(&results), collect(&reviews))
}

#[test]
fn review_is_immutable_idempotent_and_links_to_the_unchanged_original() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("reviews.redb");
    let ticket = ticket();
    let original = decision(&ticket, false);
    let expected = decision(&ticket, true);
    let store = Store::open(&path).unwrap();
    store.complete(&ticket, original.clone()).unwrap();
    assert!(matches!(
        store
            .lookup_review(&ticket, "review-1", "provider_recovery")
            .unwrap(),
        Lookup::Missing
    ));
    let (first, inserted) = store
        .review(&ticket, expected.clone(), "review-1", "provider_recovery")
        .unwrap();
    assert!(inserted);
    assert_eq!(value(&found(first)), value(&expected));
    let (repeated, inserted) = store
        .review(&ticket, original.clone(), "review-1", "provider_recovery")
        .unwrap();
    assert!(!inserted);
    assert_eq!(value(&found(repeated)), value(&expected));
    assert_eq!(
        value(&found(store.lookup(&ticket).unwrap())),
        value(&original)
    );
    assert!(matches!(
        store
            .lookup_review(&ticket, "review-1", "model_update")
            .unwrap(),
        Lookup::Conflict
    ));
    assert!(matches!(
        store
            .review(&ticket, expected, "review-1", "manual_review")
            .unwrap(),
        (Lookup::Conflict, false)
    ));
    let mut changed = ticket.clone();
    changed.app_opens_since_renewal = 1;
    assert!(matches!(
        store
            .lookup_review(&changed, "another-review", "provider_recovery")
            .unwrap(),
        Lookup::Conflict
    ));
    assert!(matches!(
        store
            .review(
                &changed,
                decision(&changed, true),
                "another-review",
                "provider_recovery"
            )
            .unwrap(),
        (Lookup::Conflict, false)
    ));
    drop(store);

    let (originals, reviews) = raw_records(&path);
    assert_eq!(originals.len(), 1);
    assert_eq!(reviews.len(), 1);
    assert!(!reviews[0].contains("SYNTHETIC-ORIGINAL-MESSAGE"));
    assert!(!reviews[0].contains("review-1"));
    let audit: Value = serde_json::from_str(&reviews[0]).unwrap();
    assert_eq!(audit["ticket_key"], hash_bytes(ticket.id.as_bytes()));
    assert_eq!(audit["ticket_fingerprint"], ticket.fingerprint());
    assert_eq!(audit["review_key"], hash_bytes(b"review-1"));
    assert_eq!(
        audit["original_result_fingerprint"],
        hash_bytes(&serde_json::to_vec(&value(&original)).unwrap())
    );
    assert_eq!(audit["reason"], "provider_recovery");
    assert!(
        audit["recorded_at"]
            .as_str()
            .is_some_and(|time| !time.is_empty())
    );
}

#[test]
fn missing_original_invalid_metadata_and_mismatched_result_are_rejected() {
    let temp = tempfile::tempdir().unwrap();
    let store = Store::open(temp.path().join("reviews.redb")).unwrap();
    let ticket = ticket();
    assert!(
        store
            .lookup_review(&ticket, "review-1", "provider_recovery")
            .is_err()
    );
    assert!(
        store
            .review(
                &ticket,
                decision(&ticket, true),
                "review-1",
                "provider_recovery"
            )
            .is_err()
    );
    store.complete(&ticket, decision(&ticket, false)).unwrap();
    for invalid in [
        "".to_owned(),
        " ".to_owned(),
        "x".repeat(129),
        "line\nbreak".to_owned(),
    ] {
        assert!(
            store
                .lookup_review(&ticket, &invalid, "provider_recovery")
                .is_err()
        );
        assert!(
            store
                .review(
                    &ticket,
                    decision(&ticket, true),
                    &invalid,
                    "provider_recovery"
                )
                .is_err()
        );
    }
    assert!(
        store
            .lookup_review(&ticket, "review-1", "arbitrary user text")
            .is_err()
    );
    assert!(
        store
            .review(
                &ticket,
                decision(&ticket, true),
                "review-1",
                "arbitrary user text"
            )
            .is_err()
    );
    let mut wrong = decision(&ticket, true);
    wrong.ticket_id = "another-ticket".into();
    assert!(
        store
            .review(&ticket, wrong, "review-1", "provider_recovery")
            .is_err()
    );
    let approved = found(
        store
            .review(
                &ticket,
                decision(&ticket, true),
                "review-1",
                "provider_recovery",
            )
            .unwrap()
            .0,
    );
    assert_eq!(approved.refund.decision, RefundDecision::Approved);
}

#[test]
fn restart_preserves_review_and_global_review_id_cannot_move_to_another_ticket() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("reviews.redb");
    let ticket = ticket();
    let mut other = ticket.clone();
    other.id = "other-synthetic-ticket".into();
    let first = {
        let store = Store::open(&path).unwrap();
        store.complete(&ticket, decision(&ticket, false)).unwrap();
        store.complete(&other, decision(&other, false)).unwrap();
        found(
            store
                .review(
                    &ticket,
                    decision(&ticket, true),
                    "global-review",
                    "manual_review",
                )
                .unwrap()
                .0,
        )
    };
    let store = Store::open(&path).unwrap();
    assert_eq!(
        value(&found(
            store
                .lookup_review(&ticket, "global-review", "manual_review")
                .unwrap()
        )),
        value(&first)
    );
    assert!(matches!(
        store
            .lookup_review(&other, "global-review", "manual_review")
            .unwrap(),
        Lookup::Conflict
    ));
    assert!(matches!(
        store
            .review(
                &other,
                decision(&other, true),
                "global-review",
                "manual_review"
            )
            .unwrap(),
        (Lookup::Conflict, false)
    ));
    let other_review = found(
        store
            .review(
                &other,
                decision(&other, true),
                "new-review",
                "manual_review",
            )
            .unwrap()
            .0,
    );
    assert_eq!(
        other_review.refund.decision,
        RefundDecision::AlreadyRecorded
    );
    assert_eq!(other_review.refund.amount_inr, 0);
}

#[test]
fn original_approval_cannot_be_approved_again_by_a_review() {
    let temp = tempfile::tempdir().unwrap();
    let store = Store::open(temp.path().join("reviews.redb")).unwrap();
    let ticket = ticket();
    let original = found(store.complete(&ticket, decision(&ticket, true)).unwrap().0);
    assert_eq!(original.refund.decision, RefundDecision::Approved);
    let review = found(
        store
            .review(&ticket, decision(&ticket, true), "review-1", "model_update")
            .unwrap()
            .0,
    );
    assert_eq!(review.refund.decision, RefundDecision::AlreadyRecorded);
    assert_eq!(review.refund.amount_inr, 0);
    assert!(review.needs_human);
    assert_eq!(
        value(&found(store.lookup(&ticket).unwrap())),
        value(&original)
    );
}

#[test]
fn simultaneous_independent_reviews_reserve_one_payment_atomically() {
    let temp = tempfile::tempdir().unwrap();
    let store = Store::open(temp.path().join("reviews.redb")).unwrap();
    let ticket = ticket();
    store.complete(&ticket, decision(&ticket, false)).unwrap();
    let barrier = Arc::new(Barrier::new(8));
    let threads: Vec<_> = (0..8)
        .map(|index| {
            let store = store.clone();
            let ticket = ticket.clone();
            let barrier = barrier.clone();
            std::thread::spawn(move || {
                barrier.wait();
                store
                    .review(
                        &ticket,
                        decision(&ticket, true),
                        &format!("review-{index}"),
                        "model_update",
                    )
                    .unwrap()
            })
        })
        .collect();
    let results: Vec<_> = threads
        .into_iter()
        .map(|thread| {
            let (lookup, inserted) = thread.join().unwrap();
            assert!(inserted);
            found(lookup)
        })
        .collect();
    assert_eq!(
        results
            .iter()
            .filter(|result| result.refund.decision == RefundDecision::Approved)
            .count(),
        1
    );
    assert_eq!(
        results
            .iter()
            .map(|result| result.refund.amount_inr)
            .sum::<u32>(),
        249
    );
    assert_eq!(
        results
            .iter()
            .filter(|result| result.refund.decision == RefundDecision::AlreadyRecorded)
            .count(),
        7
    );
    let mut another = ticket.clone();
    another.id = "later-ticket".into();
    let later = found(
        store
            .complete(&another, decision(&another, true))
            .unwrap()
            .0,
    );
    assert_eq!(later.refund.decision, RefundDecision::AlreadyRecorded);
    assert_eq!(later.refund.amount_inr, 0);
}

#[test]
fn simultaneous_same_review_has_one_insert_and_one_immutable_response() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("reviews.redb");
    let store = Store::open(&path).unwrap();
    let ticket = ticket();
    store.complete(&ticket, decision(&ticket, false)).unwrap();
    let barrier = Arc::new(Barrier::new(4));
    let threads: Vec<_> = (0..4)
        .map(|_| {
            let store = store.clone();
            let ticket = ticket.clone();
            let barrier = barrier.clone();
            std::thread::spawn(move || {
                barrier.wait();
                store
                    .review(
                        &ticket,
                        decision(&ticket, true),
                        "same-review",
                        "provider_recovery",
                    )
                    .unwrap()
            })
        })
        .collect();
    let results: Vec<_> = threads
        .into_iter()
        .map(|thread| thread.join().unwrap())
        .collect();
    assert_eq!(results.iter().filter(|(_, inserted)| *inserted).count(), 1);
    for (lookup, _) in results {
        assert_eq!(found(lookup).refund.decision, RefundDecision::Approved);
    }
    drop(store);
    assert_eq!(raw_records(&path).1.len(), 1);
}

#[test]
fn old_database_records_remain_byte_for_byte_unchanged() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("old.redb");
    let ticket = ticket();
    let mut old_result = value(&decision(&ticket, false));
    for field in ["usage", "analysis_cached", "language"] {
        old_result["meta"].as_object_mut().unwrap().remove(field);
    }
    let original = json!({"fingerprint": ticket.fingerprint(), "result": old_result}).to_string();
    {
        let db = Database::create(&path).unwrap();
        let tx = db.begin_write().unwrap();
        {
            let mut table = tx.open_table(RESULTS).unwrap();
            let key = hash_bytes(ticket.id.as_bytes());
            table.insert(key.as_str(), original.as_str()).unwrap();
            tx.open_table(REFUNDS).unwrap();
        }
        tx.commit().unwrap();
    }
    {
        let store = Store::open(&path).unwrap();
        assert!(matches!(store.lookup(&ticket).unwrap(), Lookup::Found(_)));
        let review = found(
            store
                .review(
                    &ticket,
                    decision(&ticket, true),
                    "migrated-review",
                    "provider_recovery",
                )
                .unwrap()
                .0,
        );
        assert_eq!(review.refund.decision, RefundDecision::Approved);
    }
    let (originals, reviews) = raw_records(&path);
    assert_eq!(originals, vec![original.clone()]);
    assert_eq!(reviews.len(), 1);
    let original: Value = serde_json::from_str(&original).unwrap();
    let review: Value = serde_json::from_str(&reviews[0]).unwrap();
    assert_eq!(
        review["original_result_fingerprint"],
        hash_bytes(&serde_json::to_vec(&original["result"]).unwrap())
    );
}

#[test]
fn cli_help_and_replay_work_and_cached_reviews_skip_provider_configuration() {
    let help = Command::new(env!("CARGO_BIN_EXE_rereview"))
        .arg("--help")
        .output()
        .unwrap();
    assert!(help.status.success());
    assert!(
        String::from_utf8(help.stdout)
            .unwrap()
            .contains("Stop the service")
    );
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("reviews.redb");
    let input = temp.path().join("ticket.json");
    let ticket = ticket();
    std::fs::write(&input, serde_json::to_vec(&ticket).unwrap()).unwrap();
    {
        let store = Store::open(&path).unwrap();
        store.complete(&ticket, decision(&ticket, false)).unwrap();
    }
    let run = |mode: &str, review_id: &str| {
        Command::new(env!("CARGO_BIN_EXE_rereview"))
            .args([
                path.as_os_str(),
                input.as_os_str(),
                review_id.as_ref(),
                "provider_recovery".as_ref(),
            ])
            .current_dir(temp.path())
            .env("TRIAGE_MODE", mode)
            .output()
            .unwrap()
    };
    let first = run("replay", "cli-review");
    assert!(
        first.status.success(),
        "{}",
        String::from_utf8_lossy(&first.stderr)
    );
    let first: Value = serde_json::from_slice(&first.stdout).unwrap();
    assert_eq!(first["inserted"], true);
    assert_eq!(first["result"]["refund"]["amount_inr"], 0);
    let cached = run("invalid-provider-never-configured", "cli-review");
    assert!(cached.status.success());
    let cached: Value = serde_json::from_slice(&cached.stdout).unwrap();
    assert_eq!(cached["inserted"], false);
    assert_eq!(cached["result"], first["result"]);
    let mut absent = ticket.clone();
    absent.id = "missing-original".into();
    std::fs::write(&input, serde_json::to_vec(&absent).unwrap()).unwrap();
    let missing = run("invalid-provider-never-configured", "another-review");
    assert!(!missing.status.success());
    let error = String::from_utf8(missing.stderr).unwrap();
    assert!(error.contains("review_precondition_failed"));
    assert!(!error.contains("invalid_model_configuration"));
    assert!(!error.contains("SYNTHETIC-ORIGINAL-MESSAGE"));
}
