// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! End-to-end tests for the `mxc` library against the host backend.
//!
//! Seatbelt-specific cases run only on macOS; the cross-platform cases
//! (config errors, unsupported backends) run everywhere. The library exposes
//! only the streaming API, so "run to completion" here means spawn then
//! [`SandboxProcess::wait`], which drains the untaken stdout/stderr into the
//! returned [`mxc::ScriptResponse`].

use mxc::{spawn_sandbox, MxcErrorCode, ScriptResponse, SpawnOptions};

#[cfg(target_os = "macos")]
use mxc::FailurePhase;

/// Spawn a sandbox from a config and wait for it to exit, returning the
/// captured response — the streaming-API equivalent of running to completion.
fn spawn_and_wait(config: &str, options: &SpawnOptions) -> Result<ScriptResponse, mxc::MxcError> {
    spawn_sandbox(config, options).map(|mut proc| proc.wait())
}

#[test]
fn unsupported_backend_is_rejected() {
    // A backend that is never the host default and is not supported by the
    // library should surface `unsupported_containment` rather than running.
    let config = r#"{
        "version": "0.7.0-alpha",
        "containment": "windows_sandbox",
        "process": { "commandLine": "echo hi" }
    }"#;

    let err = spawn_and_wait(config, &SpawnOptions::default())
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

    let err = spawn_and_wait(config, &SpawnOptions::default())
        .expect_err("empty command must be rejected");
    // Either the parser rejects the empty command, or our own guard does;
    // both map to malformed_request.
    assert_eq!(err.code, MxcErrorCode::MalformedRequest);
}

#[test]
fn version_older_than_supported_is_rejected() {
    // Schema version below the supported floor (>=0.4) must be rejected by the
    // parser before any backend selection happens.
    let config = r#"{
        "version": "0.3.0-alpha",
        "containment": "seatbelt",
        "process": { "commandLine": "echo hi" }
    }"#;

    let err = spawn_and_wait(config, &SpawnOptions::default())
        .expect_err("an out-of-range schema version must be rejected");
    assert_eq!(err.code, MxcErrorCode::MalformedRequest);
}

#[test]
fn malformed_json_config_is_rejected() {
    // Not the empty-command case: structurally invalid JSON must fail to load
    // with malformed_request rather than panicking.
    let config = "{ this is not valid json";

    let err = spawn_and_wait(config, &SpawnOptions::default())
        .expect_err("malformed JSON must be rejected");
    assert_eq!(err.code, MxcErrorCode::MalformedRequest);
}

#[cfg(target_os = "macos")]
#[test]
fn seatbelt_does_not_leak_host_environment() {
    // A host env var the caller did NOT pass via SpawnOptions::env must not be
    // visible to the sandboxed child (the environment is cleared by default).
    std::env::set_var("MXC_HOST_SECRET", "leaked-value");

    let config = r#"{
        "version": "0.7.0-alpha",
        "containment": "seatbelt",
        "process": { "commandLine": "echo [$MXC_HOST_SECRET]", "timeout": 10000 },
        "filesystem": { "readwritePaths": ["/tmp"] },
        "seatbelt": { "mode": "exec" }
    }"#;

    let result =
        spawn_and_wait(config, &SpawnOptions::default()).expect("seatbelt run should succeed");
    std::env::remove_var("MXC_HOST_SECRET");

    assert_eq!(result.exit_code, 0, "stderr: {}", result.standard_err);
    assert!(
        !result.standard_out.contains("leaked-value"),
        "host env must not leak into the sandbox, got: {:?}",
        result.standard_out
    );
}

#[cfg(target_os = "macos")]
#[test]
fn is_base64_config_is_accepted() {
    // A caller already holding a base64 ContainerConfig sets `is_base64` and we
    // parse it straight through (no double-encoding).
    let config = r#"{
        "version": "0.7.0-alpha",
        "containment": "seatbelt",
        "process": { "commandLine": "echo from-base64", "timeout": 10000 },
        "filesystem": { "readwritePaths": ["/tmp"] },
        "seatbelt": { "mode": "exec" }
    }"#;
    let encoded = wxc_common::encoding::base64_encode(config.as_bytes());

    let options = SpawnOptions {
        is_base64: true,
        ..SpawnOptions::default()
    };

    let result = spawn_and_wait(&encoded, &options).expect("a base64-encoded config should run");
    assert_eq!(result.exit_code, 0, "stderr: {}", result.standard_err);
    assert!(
        result.standard_out.contains("from-base64"),
        "got: {:?}",
        result.standard_out
    );
}

#[cfg(target_os = "macos")]
#[test]
fn seatbelt_finite_timeout_fires() {
    // A finite scriptTimeout shorter than the command's runtime must fire and
    // terminate the process (exit_code -1, timeout noted in the response).
    let config = r#"{
        "version": "0.7.0-alpha",
        "containment": "seatbelt",
        "process": { "commandLine": "sleep 30", "timeout": 1000 },
        "filesystem": { "readwritePaths": ["/tmp"] },
        "seatbelt": { "mode": "exec" }
    }"#;

    let start = std::time::Instant::now();
    let result = spawn_and_wait(config, &SpawnOptions::default())
        .expect("seatbelt run should return a response");
    assert_ne!(result.exit_code, 0, "a timed-out run must not exit 0");
    assert!(
        result.error_message.to_lowercase().contains("timed out")
            || result.standard_err.to_lowercase().contains("timed out"),
        "timeout should be reported, msg: {:?} stderr: {:?}",
        result.error_message,
        result.standard_err
    );
    assert!(
        start.elapsed() < std::time::Duration::from_secs(20),
        "timeout must fire well before the command's own 30s runtime"
    );
}

#[cfg(target_os = "macos")]
#[test]
fn seatbelt_working_directory_override() {
    // `working_directory` overrides the default (first readwrite path). Run in a
    // unique subdir so the override is distinguishable from the default cwd.
    let unique = format!("/tmp/mxc_wd_test_{}", std::process::id());
    std::fs::create_dir_all(&unique).expect("create work dir");

    let config = r#"{
        "version": "0.7.0-alpha",
        "containment": "seatbelt",
        "process": { "commandLine": "/bin/pwd", "timeout": 10000 },
        "filesystem": { "readwritePaths": ["/tmp"] },
        "seatbelt": { "mode": "exec" }
    }"#;

    let options = SpawnOptions {
        working_directory: Some(unique.clone()),
        ..SpawnOptions::default()
    };

    let result = spawn_and_wait(config, &options).expect("seatbelt run should succeed");
    let _ = std::fs::remove_dir(&unique);

    assert_eq!(result.exit_code, 0, "stderr: {}", result.standard_err);
    assert!(
        result.standard_out.contains("mxc_wd_test"),
        "child cwd should be the override, got: {:?}",
        result.standard_out
    );
}

#[cfg(target_os = "macos")]
#[test]
fn seatbelt_env_override_replaces_config_value() {
    // An option env entry whose key already exists in `process.env` must
    // *replace* it (not duplicate), so the child sees the override.
    let config = r#"{
        "version": "0.7.0-alpha",
        "containment": "seatbelt",
        "process": {
            "commandLine": "echo $MXC_REPLACE",
            "timeout": 10000,
            "env": ["MXC_REPLACE=original"]
        },
        "filesystem": { "readwritePaths": ["/tmp"] },
        "seatbelt": { "mode": "exec" }
    }"#;

    let options = SpawnOptions {
        env: vec![("MXC_REPLACE".to_string(), "overridden".to_string())],
        ..SpawnOptions::default()
    };

    let result = spawn_and_wait(config, &options).expect("seatbelt run should succeed");
    assert_eq!(result.exit_code, 0, "stderr: {}", result.standard_err);
    assert!(
        result.standard_out.contains("overridden"),
        "override should win, got: {:?}",
        result.standard_out
    );
    assert!(
        !result.standard_out.contains("original"),
        "the config value must be replaced, got: {:?}",
        result.standard_out
    );
}

#[cfg(target_os = "macos")]
#[test]
fn seatbelt_captures_stderr_only() {
    // Output written solely to stderr must be captured on standard_err, with
    // standard_out left empty.
    let config = r#"{
        "version": "0.7.0-alpha",
        "containment": "seatbelt",
        "process": { "commandLine": "echo only-stderr 1>&2", "timeout": 10000 },
        "filesystem": { "readwritePaths": ["/tmp"] },
        "seatbelt": { "mode": "exec" }
    }"#;

    let result =
        spawn_and_wait(config, &SpawnOptions::default()).expect("seatbelt run should succeed");
    assert_eq!(result.exit_code, 0, "stderr: {}", result.standard_err);
    assert!(
        result.standard_err.contains("only-stderr"),
        "stderr should be captured, got: {:?}",
        result.standard_err
    );
    assert!(
        !result.standard_out.contains("only-stderr"),
        "stdout should be empty, got: {:?}",
        result.standard_out
    );
}

// ---------------------------------------------------------------------------
// Windows ProcessContainer (AppContainer + BaseContainer) — integration tests.
//
// These exercise the capture and timeout paths that regressed as review items
// #1 (BaseContainer ran with an already-closed process handle) and #2
// (AppContainer timeout killed only the direct child, so it never fired).
// They run a real sandbox, so they require an elevated, host-prepped Windows
// host (see docs/host-prep.md) and are therefore `#[ignore]`d — run them with
// `cargo test -p mxc -- --ignored` on such a host.
// ---------------------------------------------------------------------------

#[cfg(target_os = "windows")]
#[test]
#[ignore = "requires an elevated, host-prepped Windows host (see docs/host-prep.md)"]
fn base_container_captures_stdout() {
    // Schema >= 0.5 implies the BaseContainer fallback. Regression guard for
    // #1: a valid exit code and captured stdout prove the process handle was
    // not closed out from under the wait.
    let config = r#"{
        "version": "0.7.0-alpha",
        "containment": "processcontainer",
        "process": { "commandLine": "cmd /c echo hello-base-container", "timeout": 30000 },
        "filesystem": { "readwritePaths": ["C:\\Windows\\Temp"] }
    }"#;

    let result =
        spawn_and_wait(config, &SpawnOptions::default()).expect("BaseContainer run should succeed");
    assert_eq!(result.exit_code, 0, "stderr: {}", result.standard_err);
    assert!(
        result.standard_out.contains("hello-base-container"),
        "stdout should be captured, got: {:?}",
        result.standard_out
    );
}

#[cfg(target_os = "windows")]
#[test]
#[ignore = "requires an elevated, host-prepped Windows host (see docs/host-prep.md)"]
fn appcontainer_captures_stdout() {
    // Schema 0.4 keeps us on the AppContainer fast path (no BaseContainer).
    let config = r#"{
        "version": "0.4.0-alpha",
        "containment": "processcontainer",
        "process": { "commandLine": "cmd /c echo hello-appcontainer", "timeout": 30000 },
        "filesystem": { "readwritePaths": ["C:\\Windows\\Temp"] }
    }"#;

    let result =
        spawn_and_wait(config, &SpawnOptions::default()).expect("AppContainer run should succeed");
    assert_eq!(result.exit_code, 0, "stderr: {}", result.standard_err);
    assert!(
        result.standard_out.contains("hello-appcontainer"),
        "stdout should be captured, got: {:?}",
        result.standard_out
    );
}

#[cfg(target_os = "windows")]
#[test]
#[ignore = "requires an elevated, host-prepped Windows host (see docs/host-prep.md)"]
fn appcontainer_finite_timeout_fires() {
    // Regression guard for #2: a finite timeout must fire even when the command
    // spawns a descendant that keeps the inherited stdout write-end open. If
    // the timeout only killed the direct child, the capture reader would block
    // forever and this test would hang past the bounded wall-clock below.
    let config = r#"{
        "version": "0.4.0-alpha",
        "containment": "processcontainer",
        "process": {
            "commandLine": "cmd /c start /b ping -n 60 127.0.0.1 >nul & ping -n 60 127.0.0.1 >nul",
            "timeout": 2000
        },
        "filesystem": { "readwritePaths": ["C:\\Windows\\Temp"] }
    }"#;

    let start = std::time::Instant::now();
    let result = spawn_and_wait(config, &SpawnOptions::default())
        .expect("AppContainer run should return a response");
    assert_ne!(result.exit_code, 0, "a timed-out run must not exit 0");
    assert!(
        start.elapsed() < std::time::Duration::from_secs(30),
        "timeout must fire (and tree-kill descendants) well before the 60s pings finish"
    );
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

    let result =
        spawn_and_wait(config, &SpawnOptions::default()).expect("seatbelt run should succeed");

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

    let result = spawn_and_wait(config, &options).expect("seatbelt run should succeed");

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

    let result = spawn_and_wait(config, &options).expect("seatbelt run should succeed");

    assert_eq!(result.exit_code, 0, "stderr: {}", result.standard_err);
    assert!(
        result.standard_out.contains("injected-value"),
        "env var should reach the sandboxed process, got: {:?}",
        result.standard_out
    );
}

#[cfg(target_os = "macos")]
#[test]
fn seatbelt_failure_phase_process_exited_on_nonzero() {
    let config = r#"{
        "version": "0.7.0-alpha",
        "containment": "seatbelt",
        "process": { "commandLine": "exit 7", "timeout": 10000 },
        "filesystem": { "readwritePaths": ["/tmp"] },
        "seatbelt": { "mode": "exec" }
    }"#;

    let result =
        spawn_and_wait(config, &SpawnOptions::default()).expect("seatbelt run should succeed");

    assert_eq!(result.exit_code, 7);
    assert_eq!(
        result.failure_phase,
        FailurePhase::ProcessExited,
        "non-zero exit must report ProcessExited"
    );
}

#[cfg(target_os = "macos")]
#[test]
fn seatbelt_failure_phase_none_on_success() {
    let config = r#"{
        "version": "0.7.0-alpha",
        "containment": "seatbelt",
        "process": { "commandLine": "true", "timeout": 10000 },
        "filesystem": { "readwritePaths": ["/tmp"] },
        "seatbelt": { "mode": "exec" }
    }"#;

    let result =
        spawn_and_wait(config, &SpawnOptions::default()).expect("seatbelt run should succeed");

    assert_eq!(result.exit_code, 0);
    assert_eq!(result.failure_phase, FailurePhase::None);
}

#[cfg(target_os = "macos")]
#[test]
fn seatbelt_defaults_cwd_to_allowed_path_without_getcwd_leak() {
    // No `cwd` set: the child must run in a sandbox-allowed directory (the
    // first readwrite path) rather than inheriting a possibly-inaccessible
    // host cwd, so getcwd() does not leak a permission error to stderr.
    let config = r#"{
        "version": "0.7.0-alpha",
        "containment": "seatbelt",
        "process": { "commandLine": "/bin/pwd", "timeout": 10000 },
        "filesystem": { "readwritePaths": ["/tmp"] },
        "seatbelt": { "mode": "exec" }
    }"#;

    let result =
        spawn_and_wait(config, &SpawnOptions::default()).expect("seatbelt run should succeed");

    assert_eq!(result.exit_code, 0, "stderr: {}", result.standard_err);
    assert!(
        result.standard_out.contains("tmp"),
        "child cwd should default to the readwrite path, got: {:?}",
        result.standard_out
    );
    assert!(
        !result.standard_err.contains("getcwd")
            && !result.standard_err.contains("Operation not permitted"),
        "no getcwd leak expected, stderr: {:?}",
        result.standard_err
    );
}
