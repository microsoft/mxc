// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Host-independent tests for the `mxc-sdk` state-aware lifecycle surface
//! (`run_state_aware_json` / `exec_sandbox`).
//!
//! These exercise request parsing, phase routing, and error mapping without a
//! live host backend. All three state-aware backends — IsolationSession, WSLc
//! and Windows Sandbox — are Windows-only, and IsolationSession additionally
//! needs the OS-side IsoSessionOps service, so the real lifecycle paths are
//! exercised by the executor E2E suites instead.
//!
//! Those suites drive the `ExecConsumer::Executor` path, **not** the
//! `ExecConsumer::Library` path [`exec_sandbox`] uses — that one has no
//! end-to-end coverage yet, as the testing-gap note on IsolationSession's `exec`
//! records. So the assertions here deliberately stop at the facade's contract:
//! parse, reject one-shot, reject non-dry-run exec, surface unsupported_phase
//! for a backend without a state-aware impl, and honour the experimental opt-in
//! — which stays host-independent because the gate runs before backend dispatch.

use mxc_sdk::{exec_sandbox, run_state_aware_json, ErrorCode};

#[test]
fn run_state_aware_json_rejects_one_shot_config() {
    // No `phase` field => one-shot config, not a lifecycle request.
    let json = r#"{"version":"0.8.0-alpha","process":{"commandLine":"echo hi"}}"#;
    let err = run_state_aware_json(json, false, false).expect_err("one-shot must be rejected");
    assert_eq!(err.code, ErrorCode::MalformedRequest);
}

#[test]
fn run_state_aware_json_rejects_non_dry_run_exec() {
    // A non-dry-run exec streams; it must be routed through exec_sandbox, not
    // the envelope entry point.
    let json = r#"{"phase":"exec","sandboxId":"isolationsession:abc","process":{"commandLine":"echo hi"}}"#;
    let err =
        run_state_aware_json(json, false, false).expect_err("non-dry-run exec must be rejected");
    assert_eq!(err.code, ErrorCode::MalformedRequest);
    assert!(err.message.contains("exec"));
}

#[test]
fn run_state_aware_json_malformed_json_is_malformed_request() {
    let err =
        run_state_aware_json("{ not json", false, false).expect_err("bad JSON must be rejected");
    assert_eq!(err.code, ErrorCode::MalformedRequest);
}

#[test]
fn exec_sandbox_rejects_non_exec_phase() {
    let json = r#"{"phase":"provision","containment":"isolation_session"}"#;
    // `Sandbox` is not `Debug`, so match rather than `expect_err`.
    match exec_sandbox(json, false) {
        Ok(_) => panic!("a provision request is not an exec"),
        Err(err) => assert_eq!(err.code, ErrorCode::MalformedRequest),
    }
}

#[test]
fn exec_sandbox_rejects_one_shot_config() {
    let json = r#"{"version":"0.8.0-alpha","process":{"commandLine":"echo hi"}}"#;
    match exec_sandbox(json, false) {
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
    let err = run_state_aware_json(json, false, false)
        .expect_err("an unregistered sandbox-id prefix has no backend");
    assert_eq!(err.code, ErrorCode::UnsupportedContainment);
}

/// Without the opt-in, an experimental backend is refused — and the refusal is
/// host- and feature-independent, because `require_experimental_optin` runs
/// before backend dispatch on every platform.
#[test]
fn experimental_backend_is_refused_without_the_optin() {
    let json = r#"{"phase":"provision","containment":"windows_sandbox"}"#;
    let err = run_state_aware_json(json, true, false)
        .expect_err("an experimental backend without the opt-in must be refused");
    assert_eq!(err.code, ErrorCode::BackendUnavailable);
    assert!(
        err.message.contains("experimental"),
        "the refusal should say what is missing, got: {}",
        err.message
    );
}

/// With the opt-in, the same request gets **past** the gate.
///
/// The assertion is deliberately "not `BackendUnavailable`" rather than a
/// specific success: what happens next varies by host and build features (a dry
/// run on Windows, `unsupported_phase` elsewhere), and pinning that would make
/// this a host test. What it discriminates is the thing this change adds — if
/// the parameter were dropped on the way down, the gate would still refuse and
/// this fails. A dry run keeps it side-effect-free.
#[test]
fn the_optin_admits_an_experimental_backend() {
    let json = r#"{"phase":"provision","containment":"windows_sandbox"}"#;
    if let Err(err) = run_state_aware_json(json, true, true) {
        assert_ne!(
            err.code,
            ErrorCode::BackendUnavailable,
            "the opt-in was passed, so the experimental gate must not refuse: {}",
            err.message
        );
    }
}

/// The gate's refusal carries no failing-API detail, because no platform API is
/// in flight when it fires — the same shape a malformed request produces.
#[test]
fn the_refusal_carries_no_api_call_detail() {
    let json = r#"{"phase":"provision","containment":"windows_sandbox"}"#;
    let err = run_state_aware_json(json, true, false).expect_err("must be refused");
    assert_eq!(err.operation, None);
    assert_eq!(err.native_code, None);
    assert_eq!(err.remediation, None);
}

/// The **streaming** entry point honours the opt-in too, not just the envelope
/// one.
///
/// Both are needed: they take separate paths to the same gate, so a change that
/// hardcoded the flag in only one of them would leave the other's tests green.
/// A `wsb:` id routes to Windows Sandbox, which has no streaming-exec arm — so
/// once past the gate it lands on `unsupported_phase`, and the two outcomes are
/// distinguishable without a host, a feature, or any backend work. (A `wslc:`
/// id would not discriminate: its feature-off arm also answers
/// `backend_unavailable`, which is the very code the gate returns.)
#[test]
fn exec_honours_the_optin_on_its_own_path() {
    let json = r#"{"phase":"exec","sandboxId":"wsb:0a1b2c3d","process":{"commandLine":"echo hi"}}"#;

    match exec_sandbox(json, false) {
        Ok(_) => panic!("without the opt-in the gate must refuse"),
        Err(err) => assert_eq!(err.code, ErrorCode::BackendUnavailable),
    }

    match exec_sandbox(json, true) {
        Ok(_) => panic!("windows_sandbox serves no streaming exec"),
        Err(err) => assert_ne!(
            err.code,
            ErrorCode::BackendUnavailable,
            "the opt-in was passed, so the gate must not refuse: {}",
            err.message
        ),
    }
}
