// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! State-aware dispatcher smoke tests.
//!
//! These tests exercise the wire-format invariant that `wxc-exec` reserves
//! stdout for a single JSON envelope on every state-aware request — even
//! when no state-aware backend implementation is present yet. They run on
//! any Windows host that can build `wxc-exec.exe`; no OS-side service
//! prerequisites are required.

use std::sync::OnceLock;

use serde_json::{json, Value};
use wxc_e2e_tests::{has_wxc_exe, run_wxc_state_aware, CommandResult};

static HAS_WXC_EXE: OnceLock<bool> = OnceLock::new();

fn cached_has_wxc_exe() -> bool {
    *HAS_WXC_EXE.get_or_init(has_wxc_exe)
}

/// Asserts that stdout is exactly one parseable JSON object with an
/// `error.code` string field, returns that code, and panics with the full
/// stdout/stderr payload on failure. Stdout content other than the envelope
/// would invalidate the SDK's stdout-as-envelope assumption.
fn assert_error_envelope_on_stdout(result: &CommandResult) -> String {
    let stdout = result.stdout.trim();
    let parsed: Value = serde_json::from_str(stdout).unwrap_or_else(|e| {
        panic!(
            "{} stdout did not parse as JSON: {}\n--- stdout ---\n{}\n--- stderr ---\n{}",
            result.label, e, result.stdout, result.stderr,
        )
    });
    let code = parsed
        .get("error")
        .and_then(|e| e.get("code"))
        .and_then(|c| c.as_str())
        .unwrap_or_else(|| {
            panic!(
                "{} envelope missing error.code\n--- stdout ---\n{}\n--- stderr ---\n{}",
                result.label, result.stdout, result.stderr,
            )
        });
    code.to_string()
}

#[test]
fn state_aware_unknown_containment_emits_error_envelope_on_stdout() {
    if !cached_has_wxc_exe() {
        return;
    }

    // The parser rejects an unrecognised `containment` string when discriminating
    // a state-aware request — exercises the parser-level rejection branch of
    // the wire-format error contract.
    let request = json!({
        "containment": "totally_made_up",
        "phase": "provision"
    });
    let result = run_wxc_state_aware("state-aware unknown containment", &request, &[]);
    let code = assert_error_envelope_on_stdout(&result);
    // Parser-level rejection surfaces as malformed_request per the design's
    // wire-format error model.
    assert_eq!(
        code, "malformed_request",
        "expected malformed_request for unknown containment, got {:?}; stdout={:?}",
        code, result.stdout
    );
    assert_ne!(result.code, Some(0), "non-zero exit expected on error");
}

#[test]
fn state_aware_non_phase_key_under_backend_block_emits_error_envelope() {
    if !cached_has_wxc_exe() {
        return;
    }

    // Per-backend config nests under a phase name (design §7.2). The one-shot
    // spelling `experimental.isolation_session.user` on a state-aware request
    // is a mis-slotted payload no code path reads — the dispatcher navigates
    // only `experimental.<backend>.<phase>` — so it must be refused rather than
    // silently provisioning a local sandbox for a caller who asked for an
    // Entra-backed one. Parser-level rejection, so no OS-side service is
    // required for this to run.
    let request = json!({
        "containment": "isolation_session",
        "phase": "provision",
        "experimental": {
            "isolation_session": {
                "user": { "upn": "alice@contoso.com", "wamToken": "tok" }
            }
        }
    });
    let result = run_wxc_state_aware("state-aware non-phase backend key", &request, &[]);
    let code = assert_error_envelope_on_stdout(&result);
    assert_eq!(
        code, "malformed_request",
        "expected malformed_request for a non-phase inner key, got {:?}; stdout={:?}",
        code, result.stdout
    );
    assert_ne!(result.code, Some(0), "non-zero exit expected on error");
}

#[test]
fn state_aware_process_on_non_exec_phase_emits_error_envelope() {
    if !cached_has_wxc_exe() {
        return;
    }

    // `process` is exec-only (design §7.1). Without the guard the parser maps
    // cwd/env/timeout into a request whose non-exec phase methods never read
    // them — a silently-ignored policy.
    let request = json!({
        "phase": "start",
        "sandboxId": "iso:abcd1234",
        "process": { "commandLine": "echo hi" }
    });
    let result = run_wxc_state_aware("state-aware process on non-exec", &request, &[]);
    let code = assert_error_envelope_on_stdout(&result);
    assert_eq!(
        code, "malformed_request",
        "expected malformed_request for `process` on a non-exec phase, got {:?}; stdout={:?}",
        code, result.stdout
    );
    assert_ne!(result.code, Some(0), "non-zero exit expected on error");
}

#[test]
fn state_aware_lone_foreign_experimental_block_emits_error_envelope() {
    if !cached_has_wxc_exe() {
        return;
    }

    // Non-provision phases carry no `containment`, but the `iso:` prefix
    // resolves the backend, so a lone `wslc` block is foreign. Previously the
    // unresolved backend let exactly one foreign key through, silently dropped.
    let request = json!({
        "phase": "start",
        "sandboxId": "iso:abcd1234",
        "experimental": { "wslc": { "image": "alpine:latest" } }
    });
    let result = run_wxc_state_aware("state-aware lone foreign experimental", &request, &[]);
    let code = assert_error_envelope_on_stdout(&result);
    assert_eq!(
        code, "malformed_request",
        "expected malformed_request for a foreign experimental block, got {:?}; stdout={:?}",
        code, result.stdout
    );
    assert_ne!(result.code, Some(0), "non-zero exit expected on error");
}

#[test]
fn state_aware_recognized_but_non_state_aware_backend_emits_unsupported_phase() {
    if !cached_has_wxc_exe() {
        return;
    }

    // `wslc` is a recognised backend but does not implement the state-aware
    // trait. The dispatcher should emit `unsupported_phase` per design §8 and
    // §10. This is the smoke-test scenario that protects the contract once
    // I-commits land state-aware impls — the assertion will keep working
    // because `wslc` will remain a non-state-aware backend.
    let request = json!({
        "containment": "wslc",
        "phase": "provision"
    });
    let result = run_wxc_state_aware("state-aware non-stateful backend", &request, &[]);
    let code = assert_error_envelope_on_stdout(&result);
    assert_eq!(
        code, "unsupported_phase",
        "expected unsupported_phase for non-stateful backend, got {:?}; stdout={:?}",
        code, result.stdout
    );
    assert_ne!(result.code, Some(0), "non-zero exit expected on error");
}
