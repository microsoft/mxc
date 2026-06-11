// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! End-to-end tests for the `mxc` library against the host backend.
//!
//! Seatbelt-specific cases run only on macOS; the cross-platform cases
//! (config errors, unsupported backends) run everywhere.

use mxc::{spawn_sandbox_from_config, MxcErrorCode, SpawnOptions};

#[test]
fn unsupported_backend_is_rejected() {
    // A backend that is never the host default and is not supported by the
    // library should surface `unsupported_containment` rather than running.
    let config = r#"{
        "version": "0.7.0-alpha",
        "containment": "windows_sandbox",
        "process": { "commandLine": "echo hi" }
    }"#;

    let err = spawn_sandbox_from_config(config, &SpawnOptions::default())
        .expect_err("windows_sandbox must be unsupported by the mxc library");
    assert_eq!(err.code, MxcErrorCode::UnsupportedContainment);
}

#[test]
fn missing_command_is_rejected() {
    let config = r#"{
        "version": "0.7.0-alpha",
        "containment": "seatbelt",
        "process": { "commandLine": "" }
    }"#;

    let err = spawn_sandbox_from_config(config, &SpawnOptions::default())
        .expect_err("empty command must be rejected");
    // Either the parser rejects the empty command, or our own guard does;
    // both map to malformed_request.
    assert_eq!(err.code, MxcErrorCode::MalformedRequest);
}

#[cfg(target_os = "macos")]
#[test]
fn seatbelt_captures_stdout() {
    let config = r#"{
        "version": "0.7.0-alpha",
        "containment": "seatbelt",
        "process": { "commandLine": "echo hello-from-sandbox", "timeout": 10000 },
        "filesystem": { "readwritePaths": ["/tmp"] },
        "network": { "defaultPolicy": "block" },
        "seatbelt": { "mode": "exec" }
    }"#;

    let result = spawn_sandbox_from_config(config, &SpawnOptions::default())
        .expect("seatbelt run should succeed");

    assert_eq!(result.exit_code, 0, "stderr: {}", result.standard_err);
    assert!(
        result.standard_out.contains("hello-from-sandbox"),
        "stdout should be captured, got: {:?}",
        result.standard_out
    );
}

#[cfg(target_os = "macos")]
#[test]
fn seatbelt_command_override_and_captured_exit_code() {
    let config = r#"{
        "version": "0.7.0-alpha",
        "containment": "seatbelt",
        "process": { "commandLine": "true", "timeout": 10000 },
        "filesystem": { "readwritePaths": ["/tmp"] },
        "seatbelt": { "mode": "exec" }
    }"#;

    let options = SpawnOptions {
        command: Some("echo override-out && exit 3".to_string()),
        ..SpawnOptions::default()
    };

    let result = spawn_sandbox_from_config(config, &options).expect("seatbelt run should succeed");

    assert_eq!(result.exit_code, 3);
    assert!(result.standard_out.contains("override-out"));
}

#[cfg(target_os = "macos")]
#[test]
fn seatbelt_env_injection() {
    let config = r#"{
        "version": "0.7.0-alpha",
        "containment": "seatbelt",
        "process": { "commandLine": "echo $MXC_TEST_VAR", "timeout": 10000 },
        "filesystem": { "readwritePaths": ["/tmp"] },
        "seatbelt": { "mode": "exec" }
    }"#;

    let options = SpawnOptions {
        env: vec![("MXC_TEST_VAR".to_string(), "injected-value".to_string())],
        ..SpawnOptions::default()
    };

    let result = spawn_sandbox_from_config(config, &options).expect("seatbelt run should succeed");

    assert_eq!(result.exit_code, 0, "stderr: {}", result.standard_err);
    assert!(
        result.standard_out.contains("injected-value"),
        "env var should reach the sandboxed process, got: {:?}",
        result.standard_out
    );
}
