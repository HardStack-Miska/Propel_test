use serde_json::json;
use std::{path::Path, process::Command};

fn evaluate(path: &Path, target: &str) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_evaluate"))
        .arg(path)
        .arg(target)
        .output()
        .unwrap()
}

fn assert_error(output: std::process::Output, code: &str) {
    assert_eq!(output.status.code(), Some(1));
    assert!(output.stdout.is_empty());
    assert_eq!(
        String::from_utf8(output.stderr).unwrap().trim(),
        format!("evaluation_failed: {code}")
    );
}

#[test]
fn malformed_input_values_never_reach_stderr() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("private-input.json");
    let input = json!({
        "tickets": [{
            "id": "synthetic-evaluation",
            "received_at": "2026-09-02T12:00:00Z",
            "subject": "Synthetic evaluation",
            "body": "Synthetic evaluation",
            "purchases": [{
                "id": "synthetic-payment", "type": "SYNTHETIC-PRIVATE-VALUE",
                "amount_inr": 249, "status": "successful", "at": "2026-09-01T12:00:00Z"
            }],
            "app_opens_since_renewal": 0
        }]
    });
    std::fs::write(&path, serde_json::to_vec(&input).unwrap()).unwrap();
    assert_error(
        evaluate(&path, "http://127.0.0.1:1"),
        "invalid_evaluation_schema",
    );
}

#[test]
fn input_is_limited_to_64_kib_before_parsing() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("input.json");
    let mut input = br#"{"tickets":[]}"#.to_vec();
    input.resize(65_536, b' ');
    std::fs::write(&path, &input).unwrap();
    let output = evaluate(&path, "http://127.0.0.1:1");
    assert!(output.status.success());
    assert!(output.stderr.is_empty());
    assert_eq!(String::from_utf8(output.stdout).unwrap().trim(), "[]");

    input.push(b' ');
    std::fs::write(&path, input).unwrap();
    assert_error(
        evaluate(&path, "http://127.0.0.1:1"),
        "evaluation_input_too_large",
    );
}

#[test]
fn missing_input_and_invalid_urls_do_not_echo_private_paths_or_values() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("SYNTHETIC-PRIVATE-PATH.json");
    assert_error(
        evaluate(&path, "http://127.0.0.1:1"),
        "evaluation_input_unavailable",
    );
    std::fs::write(&path, br#"{"tickets":[]}"#).unwrap();
    assert_error(
        evaluate(&path, "SYNTHETIC-PRIVATE-INVALID-URL"),
        "invalid_evaluation_target",
    );
}

#[test]
fn evaluation_rejects_external_and_non_http_targets_without_requests() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("input.json");
    std::fs::write(&path, br#"{"tickets":[]}"#).unwrap();
    for target in [
        "https://127.0.0.1:1",
        "http://example.invalid",
        "http://127.0.0.1.example.invalid",
        "http://localhost@example.invalid",
    ] {
        assert_error(
            evaluate(&path, target),
            "evaluation_target_must_be_local_http",
        );
    }
}
