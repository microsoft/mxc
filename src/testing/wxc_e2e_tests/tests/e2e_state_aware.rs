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
