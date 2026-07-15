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

// A non-provision phase resolves the backend from the `sandbox_id` prefix, so an
// unregistered prefix deterministically yields `unsupported_containment` —
// independent of build features (`isolation_session` on/off) and host
// capability, and with no backend side effects. (A real `isolation_session`
// provision is intentionally avoided here: its outcome varies by feature/host —
// unsupported_phase / backend_unavailable / an actual provisioned sandbox — so
// it is neither deterministic nor side-effect-free. Real lifecycle runs are
// covered by the host-gated executor E2E suites.)
#[test]
fn unregistered_backend_prefix_is_unsupported_containment() {
    let json = r#"{"phase":"start","sandboxId":"nosuchbackend:abc123"}"#;
    let err = run_state_aware_json(json, false)
        .expect_err("an unregistered sandbox-id prefix has no backend");
    assert_eq!(err.code, ErrorCode::UnsupportedContainment);
}
