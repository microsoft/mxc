// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Host-independent tests for the `mxc-sdk` state-aware lifecycle surface
//! (`run_state_aware_json` / `exec_sandbox`).
//!
//! These exercise request parsing, phase routing, and error mapping without a
//! live host backend. The only in-tree state-aware backend (IsolationSession)
//! is Windows-only and needs the OS-side IsoSessionOps service, so the actual
//! provision/exec paths are covered by the executor E2E suites; here we assert
//! the SDK facade's contract (parse, reject one-shot, reject non-dry-run exec,
//! surface unsupported_phase for a backend without a state-aware impl).

use mxc_sdk::{exec_sandbox, run_state_aware_json, ErrorCode};

#[test]
fn run_state_aware_json_rejects_one_shot_config() {
    // No `phase` field => one-shot config, not a lifecycle request.
    let json = r#"{"version":"0.8.0-alpha","process":{"commandLine":"echo hi"}}"#;
    let err = run_state_aware_json(json, false).expect_err("one-shot must be rejected");
    assert_eq!(err.code, ErrorCode::MalformedRequest);
}

#[test]
fn run_state_aware_json_rejects_non_dry_run_exec() {
    // A non-dry-run exec streams; it must be routed through exec_sandbox, not
    // the envelope entry point.
    let json = r#"{"phase":"exec","sandboxId":"isolationsession:abc","process":{"commandLine":"echo hi"}}"#;
    let err = run_state_aware_json(json, false).expect_err("non-dry-run exec must be rejected");
    assert_eq!(err.code, ErrorCode::MalformedRequest);
    assert!(err.message.contains("exec"));
}

#[test]
fn run_state_aware_json_malformed_json_is_malformed_request() {
    let err = run_state_aware_json("{ not json", false).expect_err("bad JSON must be rejected");
    assert_eq!(err.code, ErrorCode::MalformedRequest);
}

#[test]
fn exec_sandbox_rejects_non_exec_phase() {
    let json = r#"{"phase":"provision","containment":"isolation_session"}"#;
    // `Sandbox` is not `Debug`, so match rather than `expect_err`.
    match exec_sandbox(json) {
        Ok(_) => panic!("a provision request is not an exec"),
        Err(err) => assert_eq!(err.code, ErrorCode::MalformedRequest),
    }
}

#[test]
fn exec_sandbox_rejects_one_shot_config() {
    let json = r#"{"version":"0.8.0-alpha","process":{"commandLine":"echo hi"}}"#;
    match exec_sandbox(json) {
        Ok(_) => panic!("one-shot must be rejected"),
        Err(err) => assert_eq!(err.code, ErrorCode::MalformedRequest),
    }
}

// The `mxc-sdk` crate does not enable the engine's optional `isolation_session`
// feature, so no state-aware backend is compiled in and an otherwise-valid
// provision request surfaces `unsupported_phase` rather than a backend call.
#[test]
fn provision_without_a_state_aware_backend_is_unsupported_phase() {
    let json = r#"{"phase":"provision","containment":"isolation_session"}"#;
    let err = run_state_aware_json(json, false)
        .expect_err("no state-aware backend is available in this build");
    assert_eq!(err.code, ErrorCode::UnsupportedPhase);
}
