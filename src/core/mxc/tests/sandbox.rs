// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! End-to-end tests for the `mxc` library against the host backend.
//!
//! Seatbelt-specific cases run only on macOS; the cross-platform cases
//! (config errors, unsupported backends) run everywhere. The library exposes
//! only the streaming API, so "run to completion" here means spawn, read the
//! (untaken) stdout/stderr, then [`SandboxProcess::wait`] for the exit code.

use mxc::{spawn_sandbox, Config, MxcErrorCode, ProcessConfig, SpawnOptions};

/// A minimal config for the given backend and command (for the error-path
/// cases, which never actually run a process).
fn config(containment: &str, command_line: &str) -> Config {
    Config {
        version: Some("0.7.0-alpha".to_string()),
        containment: Some(containment.to_string()),
        process: Some(ProcessConfig {
            command_line: Some(command_line.to_string()),
            ..Default::default()
        }),
        ..Default::default()
    }
}

/// A Seatbelt config exposing `/tmp` read-write, with the given command and
/// timeout (ms).
#[cfg(target_os = "macos")]
fn seatbelt(command_line: &str, timeout: u32) -> Config {
    use mxc::{FilesystemConfig, SeatbeltConfig};
    Config {
        version: Some("0.7.0-alpha".to_string()),
        containment: Some("seatbelt".to_string()),
        process: Some(ProcessConfig {
            command_line: Some(command_line.to_string()),
            timeout: Some(timeout),
            ..Default::default()
        }),
        filesystem: Some(FilesystemConfig {
            readwrite_paths: Some(vec!["/tmp".to_string()]),
            ..Default::default()
        }),
        seatbelt: Some(SeatbeltConfig::default()),
        ..Default::default()
    }
}

/// A Windows ProcessContainer config exposing `C:\Windows\Temp` read-write.
#[cfg(target_os = "windows")]
fn process_container(version: &str, command_line: &str, timeout: u32) -> Config {
    use mxc::FilesystemConfig;
    Config {
        version: Some(version.to_string()),
        containment: Some("processcontainer".to_string()),
        process: Some(ProcessConfig {
            command_line: Some(command_line.to_string()),
            timeout: Some(timeout),
            ..Default::default()
        }),
        filesystem: Some(FilesystemConfig {
            readwrite_paths: Some(vec!["C:\\Windows\\Temp".to_string()]),
            ..Default::default()
        }),
        ..Default::default()
    }
}

/// Spawn a sandbox expecting the config to be rejected before it runs.
fn spawn_only(config: Config, options: &SpawnOptions) -> Result<(), mxc::MxcError> {
    spawn_sandbox(&config, options).map(|_| ())
}

/// Outcome of running a sandbox to completion via the streaming API.
#[cfg(any(target_os = "macos", target_os = "windows"))]
#[derive(Debug)]
struct RunOutcome {
    exit_code: i32,
    timed_out: bool,
    standard_out: String,
    standard_err: String,
}

/// Spawn a sandbox, read its stdout/stderr concurrently, and wait for exit —
/// the streaming-API equivalent of running to completion.
#[cfg(any(target_os = "macos", target_os = "windows"))]
fn spawn_and_wait(config: Config, options: &SpawnOptions) -> Result<RunOutcome, mxc::MxcError> {
    use std::io::Read;

    fn read_thread(
        reader: Option<Box<dyn Read + Send>>,
    ) -> Option<std::thread::JoinHandle<String>> {
        reader.map(|mut r| {
            std::thread::spawn(move || {
                let mut s = String::new();
                let _ = r.read_to_string(&mut s);
                s
            })
        })
    }

    let mut proc = spawn_sandbox(&config, options)?;
    let out_thread = read_thread(proc.take_stdout());
    let err_thread = read_thread(proc.take_stderr());
    let (exit_code, timed_out) = match proc.wait() {
        Ok(code) => (code, false),
        Err(e) if e.kind() == std::io::ErrorKind::TimedOut => (-1, true),
        Err(e) => panic!("wait failed: {e}"),
    };
    let standard_out = out_thread
        .map(|t| t.join().unwrap_or_default())
        .unwrap_or_default();
    let standard_err = err_thread
        .map(|t| t.join().unwrap_or_default())
        .unwrap_or_default();
    Ok(RunOutcome {
        exit_code,
        timed_out,
        standard_out,
        standard_err,
    })
}

#[test]
fn unsupported_backend_is_rejected() {
    // A backend that is never the host default and is not supported by the
    // library should surface `unsupported_containment` rather than running.
    let err = spawn_only(
        config("windows_sandbox", "echo hi"),
        &SpawnOptions::default(),
    )
    .expect_err("windows_sandbox must be unsupported by the mxc library");
    assert_eq!(err.code, MxcErrorCode::UnsupportedContainment);
}

#[test]
fn missing_command_is_rejected() {
    let err = spawn_only(config("seatbelt", ""), &SpawnOptions::default())
        .expect_err("empty command must be rejected");
    // Either the parser rejects the empty command, or our own guard does;
    // both map to malformed_request.
    assert_eq!(err.code, MxcErrorCode::MalformedRequest);
}

#[test]
fn version_older_than_supported_is_rejected() {
    // Schema version below the supported floor (>=0.4) must be rejected by the
    // parser before any backend selection happens.
    let mut cfg = config("seatbelt", "echo hi");
    cfg.version = Some("0.3.0-alpha".to_string());

    let err = spawn_only(cfg, &SpawnOptions::default())
        .expect_err("an out-of-range schema version must be rejected");
    assert_eq!(err.code, MxcErrorCode::MalformedRequest);
}

#[cfg(target_os = "macos")]
#[test]
fn seatbelt_does_not_leak_host_environment() {
    // A host env var the caller did NOT pass via SpawnOptions::env must not be
    // visible to the sandboxed child (the environment is cleared by default).
    std::env::set_var("MXC_HOST_SECRET", "leaked-value");

    let result = spawn_and_wait(
        seatbelt("echo [$MXC_HOST_SECRET]", 10000),
        &SpawnOptions::default(),
    )
    .expect("seatbelt run should succeed");
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
fn seatbelt_finite_timeout_fires() {
    // A finite scriptTimeout shorter than the command's runtime must fire and
    // terminate the process (exit_code -1, timeout noted in the response).
    let start = std::time::Instant::now();
    let result = spawn_and_wait(seatbelt("sleep 30", 1000), &SpawnOptions::default())
        .expect("seatbelt run should return a response");
    assert!(result.timed_out, "a timed-out run must report a timeout");
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

    let options = SpawnOptions {
        working_directory: Some(unique.clone()),
        ..SpawnOptions::default()
    };

    let result =
        spawn_and_wait(seatbelt("/bin/pwd", 10000), &options).expect("seatbelt run should succeed");
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
    let mut cfg = seatbelt("echo $MXC_REPLACE", 10000);
    cfg.process.as_mut().unwrap().env = Some(vec!["MXC_REPLACE=original".to_string()]);

    let options = SpawnOptions {
        env: vec![("MXC_REPLACE".to_string(), "overridden".to_string())],
        ..SpawnOptions::default()
    };

    let result = spawn_and_wait(cfg, &options).expect("seatbelt run should succeed");
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
    let result = spawn_and_wait(
        seatbelt("echo only-stderr 1>&2", 10000),
        &SpawnOptions::default(),
    )
    .expect("seatbelt run should succeed");
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
    let result = spawn_and_wait(
        process_container("0.7.0-alpha", "cmd /c echo hello-base-container", 30000),
        &SpawnOptions::default(),
    )
    .expect("BaseContainer run should succeed");
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
    let result = spawn_and_wait(
        process_container("0.4.0-alpha", "cmd /c echo hello-appcontainer", 30000),
        &SpawnOptions::default(),
    )
    .expect("AppContainer run should succeed");
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
    let result = spawn_and_wait(
        process_container(
            "0.4.0-alpha",
            "cmd /c start /b ping -n 60 127.0.0.1 >nul & ping -n 60 127.0.0.1 >nul",
            2000,
        ),
        &SpawnOptions::default(),
    )
    .expect("AppContainer run should return a response");
    assert!(result.timed_out, "a timed-out run must report a timeout");
    // The bounded wait is enforced by the test harness; a hang here is the
    // failure mode the regression guards against.
}

#[cfg(target_os = "macos")]
#[test]
fn seatbelt_captures_stdout() {
    use mxc::NetworkConfig;
    let mut cfg = seatbelt("echo hello-from-sandbox", 10000);
    cfg.network = Some(NetworkConfig {
        default_policy: Some("block".to_string()),
        ..Default::default()
    });

    let result =
        spawn_and_wait(cfg, &SpawnOptions::default()).expect("seatbelt run should succeed");

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
    let options = SpawnOptions {
        command: Some("echo override-out && exit 3".to_string()),
        ..SpawnOptions::default()
    };

    let result = spawn_and_wait(seatbelt("true", 10000), &options).expect("seatbelt run succeeds");

    assert_eq!(result.exit_code, 3);
    assert!(result.standard_out.contains("override-out"));
}

#[cfg(target_os = "macos")]
#[test]
fn seatbelt_env_injection() {
    let options = SpawnOptions {
        env: vec![("MXC_TEST_VAR".to_string(), "injected-value".to_string())],
        ..SpawnOptions::default()
    };

    let result = spawn_and_wait(seatbelt("echo $MXC_TEST_VAR", 10000), &options)
        .expect("seatbelt run should succeed");

    assert_eq!(result.exit_code, 0, "stderr: {}", result.standard_err);
    assert!(
        result.standard_out.contains("injected-value"),
        "env var should reach the sandboxed process, got: {:?}",
        result.standard_out
    );
}

#[cfg(target_os = "macos")]
#[test]
fn seatbelt_reports_nonzero_exit_code() {
    let result = spawn_and_wait(seatbelt("exit 7", 10000), &SpawnOptions::default())
        .expect("seatbelt run should succeed");

    assert_eq!(result.exit_code, 7);
    assert!(
        !result.timed_out,
        "a clean non-zero exit must not be reported as a timeout"
    );
}

#[cfg(target_os = "macos")]
#[test]
fn seatbelt_reports_zero_exit_code() {
    let result = spawn_and_wait(seatbelt("true", 10000), &SpawnOptions::default())
        .expect("seatbelt run should succeed");

    assert_eq!(result.exit_code, 0);
    assert!(!result.timed_out);
}

#[cfg(target_os = "macos")]
#[test]
fn seatbelt_defaults_cwd_to_allowed_path_without_getcwd_leak() {
    // No `cwd` set: the child must run in a sandbox-allowed directory (the
    // first readwrite path) rather than inheriting a possibly-inaccessible
    // host cwd, so getcwd() does not leak a permission error to stderr.
    let result = spawn_and_wait(seatbelt("/bin/pwd", 10000), &SpawnOptions::default())
        .expect("seatbelt run should succeed");

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
