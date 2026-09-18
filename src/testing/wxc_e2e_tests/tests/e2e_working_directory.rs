// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! CLI classification of a refused `process.cwd`.
//!
//! A working directory MXC cannot honour is caller-fixable, so the executor's
//! JSON envelope must carry `policy_validation` — the code the native
//! streaming and state-aware paths already return for the same refusal — rather
//! than the infrastructure-failure `backend_error`.
//!
//! Every refusal asserted here happens in validation, before the backend is
//! asked to launch anything, so these tests need only the platform executor
//! binary: no host prep, no elevation, and no container is ever created.

use std::sync::OnceLock;

use serde_json::{json, Value};
use wxc_e2e_tests::{
    has_platform_exec, run_platform_config_value, run_wxc_config_value, CommandResult,
};

static HAS_PLATFORM_EXEC: OnceLock<bool> = OnceLock::new();

fn cached_has_platform_exec() -> bool {
    *HAS_PLATFORM_EXEC.get_or_init(has_platform_exec)
}

/// The marker the one-shot path emits when the binary was built without
/// `--features wslc`.
const WSLC_NOT_COMPILED: &str = "WSLC backend not compiled";

/// Find the single JSON error envelope the executor writes and return its
/// `error` object.
///
/// Scans line by line the way the Node SDK does: under a PTY the envelope is
/// interleaved with the run's other output, so it is located rather than
/// assumed to be the whole stream.
fn error_envelope(result: &CommandResult) -> Value {
    for line in result.combined_output().lines() {
        let trimmed = line.trim();
        if !trimmed.starts_with('{') {
            continue;
        }
        if let Ok(Value::Object(parsed)) = serde_json::from_str::<Value>(trimmed) {
            if let Some(error) = parsed.get("error") {
                return error.clone();
            }
        }
    }
    panic!(
        "{} emitted no error envelope\n--- stdout ---\n{}\n--- stderr ---\n{}",
        result.label, result.stdout, result.stderr,
    );
}

/// Assert the envelope classifies the refusal as caller-fixable and mentions
/// `expected_text`.
fn assert_policy_validation(result: &CommandResult, expected_text: &str) {
    let error = error_envelope(result);
    assert_eq!(
        error.get("code").and_then(Value::as_str),
        Some("policy_validation"),
        "a refused working directory must not be reported as an infrastructure \
         failure; envelope: {error}",
    );
    let message = error.get("message").and_then(Value::as_str).unwrap_or("");
    assert!(
        message.contains(expected_text),
        "expected a message mentioning {expected_text:?}, got: {message}",
    );
    assert_ne!(result.code, Some(0), "non-zero exit expected on a refusal");
}

#[test]
fn one_shot_relative_cwd_is_reported_as_policy_validation() {
    if !cached_has_platform_exec() {
        return;
    }

    // `process` selects the host's native backend, so this runs the same
    // refusal on every platform. Schema 0.9.0-alpha is where a relative value
    // became invalid.
    let config = json!({
        "version": "0.9.0-alpha",
        "containment": "process",
        "containerId": "cwd-relative",
        "process": { "commandLine": "echo unreachable", "cwd": "relative-subdir" },
    });
    let result = run_platform_config_value("one-shot relative cwd", &config, &[], None);

    assert_policy_validation(&result, "process.cwd must be an absolute path");
}

#[test]
fn one_shot_wslc_untranslatable_cwd_is_reported_as_policy_validation() {
    if !cached_has_platform_exec() || !cfg!(target_os = "windows") {
        return;
    }

    // A UNC path is absolute on Windows, so it clears the shared schema-0.9
    // check and is refused by WSLc itself: the backend reads `process.cwd` as a
    // host path it maps into the container, and a UNC path has no such
    // equivalent. That refusal is not version-gated, so it must carry the same
    // classification as the schema-driven one above.
    let config = json!({
        "version": "0.9.0-alpha",
        "containment": "wslc",
        "containerId": "cwd-wslc-unc",
        "process": { "commandLine": "echo unreachable", "cwd": "\\\\server\\share" },
        "experimental": { "wslc": { "image": "alpine:latest" } },
    });
    let result = run_wxc_config_value("wslc untranslatable cwd", &config, &["--experimental"]);

    if result.combined_output().contains(WSLC_NOT_COMPILED) {
        println!("SKIPPED: wxc-exec.exe was built without --features wslc");
        return;
    }
    assert_policy_validation(&result, "maps into the container");
}
