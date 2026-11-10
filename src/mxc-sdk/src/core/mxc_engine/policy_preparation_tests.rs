// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use super::*;
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
    let unsupported = r#"{"version":"1.0.0","containment":"bubblewrap","process":{"commandLine":"must-not-run"}}"#;
    assert_eq!(
        prepare_policy_json(unsupported, &failures, false)
            .unwrap_err()
            .code,
        ErrorCode::UnsupportedContainment,
    );
}
