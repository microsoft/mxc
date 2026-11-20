// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use super::*;
use crate::mxc_common::policy_failures::PolicyFailureResult;
use crate::v1::ErrorCode;
use serde_json::json;

#[test]
fn preparation_rejects_invalid_or_oversized_input_without_echoing_request_data() {
    let failures = PolicyFailures::default();
    for json in [
        r#"{"version":"1.0.0","process":{"commandLine":"INPUT_SECRET_MARKER"},"INPUT_SECRET_MARKER":true}"#,
        r#"{"version":"1.0.0","process":{"commandLine":"INPUT_SECRET_MARKER"},"filesystem":{"readwritePaths":["C:\\INPUT_SECRET_MARKER\u0000"]}}"#,
        r#"{"version":"999.0.0","process":{"commandLine":"INPUT_SECRET_MARKER"}}"#,
        r#"{"version":"1.0.0","phase":"start","sandboxId":"iso:INPUT_SECRET_MARKER"}"#,
    ] {
        for experimental in [false, true] {
            let error = prepare_policy_json(json, &failures, experimental).unwrap_err();
            assert_eq!(error.code, ErrorCode::MalformedRequest);
            assert!(!error.to_string().contains("INPUT_SECRET_MARKER"));
            assert!(!format!("{error:?}").contains("INPUT_SECRET_MARKER"));
        }
    }
    let oversized = json!({
        "version":"1.0.0", "process": {
            "commandLine": format!("INPUT_SECRET_MARKER{}", "x".repeat(MAX_REQUEST_BYTES)),
        }
    })
    .to_string();
    let error = prepare_policy_json(&oversized, &failures, false).unwrap_err();
    assert_eq!(error.code, ErrorCode::MalformedRequest);
    assert!(error.message.contains("byte limit"));
    assert!(!error.to_string().contains("INPUT_SECRET_MARKER"));
}

#[test]
fn preparation_returns_empty_observation_requests_unchanged_on_every_backend() {
    let failures = PolicyFailures::default();
    for json in [
        r#"{"version":"1.0.0","containment":"bubblewrap","process":{"commandLine":"must-not-run"}}"#,
        r#"{"version":"1.0.0","containment":"seatbelt","process":{"commandLine":"must-not-run"}}"#,
        r#"{ "version":"1.0.0", "process":{"commandLine":"must-not-run"} }"#,
    ] {
        let prepared = prepare_policy_json(json, &failures, false).unwrap();
        assert_eq!(prepared.request_json, json);
        assert!(prepared.changes.is_empty());
    }
}

#[test]
fn preparation_requires_the_experimental_optin_for_experimental_backends() {
    let empty = PolicyFailures::default();
    let observed = PolicyFailures {
        results: vec![PolicyFailureResult::default()],
        ..PolicyFailures::default()
    };
    for (backend, section) in [
        ("hyperlight", ""),
        (
            "microvm",
            r#","microvm":{"image":"docker.io/library/python:3.12-alpine"}"#,
        ),
        ("windows_sandbox", ""),
    ] {
        let json = format!(
            r#"{{"version":"1.1.0-alpha","containment":"{backend}","process":{{"commandLine":"must-not-run"}}{section}}}"#
        );
        for failures in [&empty, &observed] {
            let error = prepare_policy_json(&json, failures, false).unwrap_err();
            assert_eq!(error.code, ErrorCode::BackendUnavailable, "{backend}");
            assert!(error.message.contains("experimental"), "{error:?}");
        }
        let prepared = prepare_policy_json(&json, &empty, true).unwrap();
        assert_eq!(prepared.request_json, json);
        assert!(prepared.changes.is_empty());
    }
}

#[test]
fn preparation_rejects_observations_the_backend_cannot_apply() {
    let failures = PolicyFailures {
        results: vec![PolicyFailureResult::default()],
        ..PolicyFailures::default()
    };
    let mut unsupported = vec![
        r#"{"version":"1.0.0","containment":"bubblewrap","process":{"commandLine":"must-not-run"}}"#,
    ];
    if !cfg!(target_os = "windows") {
        unsupported.push(r#"{"version":"1.0.0","process":{"commandLine":"must-not-run"}}"#);
    }
    for json in unsupported {
        let error = prepare_policy_json(json, &failures, false).unwrap_err();
        assert_eq!(error.code, ErrorCode::UnsupportedContainment);
        assert!(error.message.contains("policy observations"));
    }
}
