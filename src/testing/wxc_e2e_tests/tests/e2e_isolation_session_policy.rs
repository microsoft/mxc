// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! IsolationSession policy-refusal tests.
//!
//! The backend refuses policy it cannot honor rather than accepting and
//! dropping it. Every refusal asserted here happens in a `validate_*` hook,
//! which runs *before* any OS-side service call (`ScriptRunner::run` calls
//! `validate_runner` before `execute`; the state-aware dispatcher calls
//! `validate_<phase>` before the phase method). So these tests need only a
//! `wxc-exec.exe` built with `--features isolation_session` — no host with the
//! OS-side isolation service, and nothing is ever provisioned.
//!
//! When `wxc-exec.exe` was built without the feature they skip, so the suite is
//! clean on any Windows host.

use std::sync::OnceLock;

use serde_json::{json, Value};
use wxc_e2e_tests::{has_wxc_exe, run_wxc_config, run_wxc_state_aware, CommandResult};

static HAS_WXC_EXE: OnceLock<bool> = OnceLock::new();

fn cached_has_wxc_exe() -> bool {
    *HAS_WXC_EXE.get_or_init(has_wxc_exe)
}

/// Marker in the error text emitted when the binary was built without
/// `--features isolation_session`.
const NOT_COMPILED: &str = "IsolationSession backend not compiled";

/// Parse the single JSON envelope on stdout and return `error.code`.
fn error_code_on_stdout(result: &CommandResult) -> String {
    let stdout = result.stdout.trim();
    let parsed: Value = serde_json::from_str(stdout).unwrap_or_else(|e| {
        panic!(
            "{} stdout did not parse as JSON: {}\n--- stdout ---\n{}\n--- stderr ---\n{}",
            result.label, e, result.stdout, result.stderr,
        )
    });
    parsed
        .get("error")
        .and_then(|e| e.get("code"))
        .and_then(|c| c.as_str())
        .unwrap_or_else(|| {
            panic!(
                "{} envelope missing error.code\n--- stdout ---\n{}",
                result.label, result.stdout,
            )
        })
        .to_string()
}

/// `true` when the run failed only because the feature is not compiled in.
fn skipped_not_compiled(result: &CommandResult) -> bool {
    let combined = result.combined_output_with_decoded_base64();
    if combined.contains(NOT_COMPILED) {
        println!(
            "SKIPPED: {} — wxc-exec.exe was built without --features isolation_session",
            result.label
        );
        return true;
    }
    false
}

// ---------------------------------------------------------------------------
// One-shot: refusals surface through `validate_runner`.
// ---------------------------------------------------------------------------

#[test]
fn one_shot_refuses_ui_policy() {
    if !cached_has_wxc_exe() {
        return;
    }

    // The isolation session is a separate OS session, which isolates the host's
    // UI from the contained code but does not deny it UI capabilities — window
    // creation, GDI, and the session's own clipboard all work inside it. A `ui`
    // policy therefore cannot be honored and must not be silently accepted.
    let result = run_wxc_config(
        "isolation_session_one_shot_ui_rejected.json",
        &["--experimental"],
    );
    if skipped_not_compiled(&result) {
        return;
    }
    let combined = result.combined_output_with_decoded_base64();
    assert!(
        combined.contains("UI policy is not supported"),
        "expected a UI-policy refusal, got exit {:?}\n--- stdout ---\n{}\n--- stderr ---\n{}",
        result.code,
        result.stdout,
        result.stderr,
    );
    assert_ne!(result.code, Some(0), "non-zero exit expected on refusal");
}

#[test]
fn one_shot_refuses_destroy_on_exit_false() {
    if !cached_has_wxc_exe() {
        return;
    }

    // The in-proc API exposes no session-lifetime knob: one-shot always stops
    // the session and removes the agent user before returning. `false` asks for
    // something the backend cannot deliver.
    let result = run_wxc_config(
        "isolation_session_one_shot_lifecycle_rejected.json",
        &["--experimental"],
    );
    if skipped_not_compiled(&result) {
        return;
    }
    let combined = result.combined_output_with_decoded_base64();
    assert!(
        combined.contains("lifecycle.destroyOnExit=false"),
        "expected a lifecycle refusal, got exit {:?}\n--- stdout ---\n{}\n--- stderr ---\n{}",
        result.code,
        result.stdout,
        result.stderr,
    );
    assert_ne!(result.code, Some(0), "non-zero exit expected on refusal");
}

// ---------------------------------------------------------------------------
// State-aware: refusals surface as a typed envelope on stdout.
// ---------------------------------------------------------------------------

#[test]
fn state_aware_provision_refuses_ui_policy_with_policy_validation() {
    if !cached_has_wxc_exe() {
        return;
    }

    let request = json!({
        "phase": "provision",
        "containment": "isolation_session",
        "network": { "defaultPolicy": "allow", "allowLocalNetwork": true },
        "ui": { "disable": true }
    });
    let result = run_wxc_state_aware("iso provision + ui", &request, &["--experimental"]);
    let code = error_code_on_stdout(&result);
    if code == "unsupported_phase" || code == "unsupported_containment" {
        println!("SKIPPED: wxc-exec.exe was built without --features isolation_session");
        return;
    }
    assert_eq!(
        code, "policy_validation",
        "expected policy_validation for a supplied `ui`, got {:?}; stdout={:?}",
        code, result.stdout
    );
}

#[test]
fn state_aware_provision_refuses_flat_user_bundle() {
    if !cached_has_wxc_exe() {
        return;
    }

    // The flat spelling is the one-shot shape. On a state-aware request the
    // dispatcher reads only `experimental.isolation_session.<phase>`, so this
    // used to be silently dropped — provisioning a *local* sandbox for a caller
    // who asked for an Entra-backed one. Parser-level, so it needs no backend.
    let request = json!({
        "phase": "provision",
        "containment": "isolation_session",
        "network": { "defaultPolicy": "allow", "allowLocalNetwork": true },
        "experimental": {
            "isolation_session": {
                "user": { "upn": "alice@contoso.com", "wamToken": "tok" }
            }
        }
    });
    let result = run_wxc_state_aware("iso provision + flat user", &request, &["--experimental"]);
    let code = error_code_on_stdout(&result);
    assert_eq!(
        code, "malformed_request",
        "expected malformed_request for a flat `user` bundle, got {:?}; stdout={:?}",
        code, result.stdout
    );
}

#[test]
fn state_aware_provision_accepts_canonical_request_shape() {
    if !cached_has_wxc_exe() {
        return;
    }

    // Guard against over-rejection: the canonical provision shape must still
    // get past validation. `--dry-run` stops before the backend provisions
    // anything, so this is safe on a host with the OS-side service and on one
    // without it alike.
    let request = json!({
        "phase": "provision",
        "containment": "isolation_session",
        "network": { "defaultPolicy": "allow", "allowLocalNetwork": true }
    });
    let result = run_wxc_state_aware(
        "iso provision canonical (dry-run)",
        &request,
        &["--experimental", "--dry-run"],
    );
    let stdout = result.stdout.trim();
    let parsed: Value = match serde_json::from_str(stdout) {
        Ok(v) => v,
        Err(_) => panic!("stdout did not parse as JSON: {stdout}"),
    };
    if let Some(code) = parsed
        .get("error")
        .and_then(|e| e.get("code"))
        .and_then(|c| c.as_str())
    {
        if code == "unsupported_phase" || code == "unsupported_containment" {
            println!("SKIPPED: wxc-exec.exe was built without --features isolation_session");
            return;
        }
        panic!("canonical provision was refused with {code}: {stdout}");
    }
    assert!(
        parsed.get("result").is_some(),
        "expected a result envelope, got {stdout}"
    );
}
