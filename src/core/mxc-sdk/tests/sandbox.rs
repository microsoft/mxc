// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! End-to-end tests for the `mxc-sdk` library against the host backend.
//!
//! Seatbelt-specific cases run only on macOS. The library exposes only the
//! streaming API, so "run to completion" here means build a request via
//! [`build_request`], `spawn_sandbox`, read the (untaken)
//! stdout/stderr, then [`wait`](mxc_sdk::Sandbox::wait) for the exit code —
//! the same path the consumer drives.

use mxc_sdk::{build_request, ErrorCode, SandboxPolicy};
#[cfg(any(target_os = "macos", target_os = "windows"))]
use mxc_sdk::{spawn_sandbox, SandboxRequest, WaitOutcome};

/// A Seatbelt request exposing `/tmp` read-write, with the given command and
/// timeout (ms; `0` == run until exit).
#[cfg(target_os = "macos")]
fn seatbelt_request(command: &str, timeout_ms: u32) -> SandboxRequest {
    let policy = SandboxPolicy {
        version: "0.7.0-alpha".to_string(),
        filesystem: Some(mxc_sdk::policy::FilesystemSection {
            readwrite_paths: vec!["/tmp".to_string()],
            readonly_paths: vec![],
            denied_paths: vec![],
            clear_policy_on_exit: None,
        }),
        network: None,
        ui: None,
        timeout_ms: if timeout_ms == 0 {
            None
        } else {
            Some(timeout_ms)
        },
    };
    let mut request = build_request(&policy, None).expect("build_request should succeed");
    request.set_script(command);
    request
}

/// A Windows ProcessContainer request exposing `C:\Windows\Temp` read-write.
/// `version` is the schema version stamped on the policy, not a backend selector.
#[cfg(target_os = "windows")]
fn process_container_request(version: &str, command: &str, timeout_ms: u32) -> SandboxRequest {
    let policy = SandboxPolicy {
        version: version.to_string(),
        filesystem: Some(mxc_sdk::policy::FilesystemSection {
            readwrite_paths: vec!["C:\\Windows\\Temp".to_string()],
            readonly_paths: vec![],
            denied_paths: vec![],
            clear_policy_on_exit: None,
        }),
        network: None,
        ui: None,
        timeout_ms: if timeout_ms == 0 {
            None
        } else {
            Some(timeout_ms)
        },
    };
    let mut request = build_request(&policy, None).expect("build_request should succeed");
    request.set_script(command);
    request
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

/// Spawn a request, read its stdout/stderr concurrently, and wait for exit —
/// the streaming-API equivalent of running to completion.
#[cfg(any(target_os = "macos", target_os = "windows"))]
fn spawn_and_wait(request: SandboxRequest) -> Result<RunOutcome, mxc_sdk::Error> {
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

    let mut proc = spawn_sandbox(request)?;
    let out_thread = read_thread(proc.take_stdout());
    let err_thread = read_thread(proc.take_stderr());
    let (exit_code, timed_out) = match proc.wait() {
        Ok(WaitOutcome::Exited(code)) => (code, false),
        Ok(WaitOutcome::TimedOut) => (-1, true),
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
fn version_older_than_supported_is_rejected() {
    // Schema version below the supported floor (>=0.4) must be rejected by the
    // parser before any backend selection happens.
    let policy = SandboxPolicy {
        version: "0.3.0-alpha".to_string(),
        filesystem: None,
        network: None,
        ui: None,
        timeout_ms: None,
    };

    let err =
        build_request(&policy, None).expect_err("an out-of-range schema version must be rejected");
    assert_eq!(err.code, ErrorCode::MalformedRequest);
}

#[cfg(target_os = "macos")]
#[test]
fn seatbelt_does_not_leak_host_environment() {
    // A host env var must not be visible to the sandboxed child (the request's
    // env is the only source; the host environment is cleared).
    std::env::set_var("MXC_HOST_SECRET", "leaked-value");

    let result = spawn_and_wait(seatbelt_request("echo [$MXC_HOST_SECRET]", 10000))
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
fn seatbelt_env_reaches_sandboxed_process() {
    // An env entry set on the request must reach the sandboxed child.
    let mut request = seatbelt_request("echo $MXC_TEST_VAR", 10000);
    request.set_env([("MXC_TEST_VAR", "injected-value")]);

    let result = spawn_and_wait(request).expect("seatbelt run should succeed");

    assert_eq!(result.exit_code, 0, "stderr: {}", result.standard_err);
    assert!(
        result.standard_out.contains("injected-value"),
        "env var should reach the sandboxed process, got: {:?}",
        result.standard_out
    );
}

#[cfg(target_os = "macos")]
#[test]
fn seatbelt_finite_timeout_fires() {
    // A finite scriptTimeout shorter than the command's runtime must fire and
    // terminate the process.
    let start = std::time::Instant::now();
    let result = spawn_and_wait(seatbelt_request("sleep 30", 1000))
        .expect("seatbelt run should return a response");
    assert!(result.timed_out, "a timed-out run must report a timeout");
    assert!(
        start.elapsed() < std::time::Duration::from_secs(20),
        "timeout must fire well before the command's own 30s runtime"
    );
}

#[cfg(target_os = "macos")]
#[test]
fn seatbelt_captures_stderr_only() {
    // Output written solely to stderr must be captured on standard_err, with
    // standard_out left empty.
    let result = spawn_and_wait(seatbelt_request("echo only-stderr 1>&2", 10000))
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

#[cfg(target_os = "macos")]
#[test]
fn seatbelt_reports_nonzero_exit_code() {
    let result =
        spawn_and_wait(seatbelt_request("exit 7", 10000)).expect("seatbelt run should succeed");

    assert_eq!(result.exit_code, 7);
    assert!(
        !result.timed_out,
        "a clean non-zero exit must not be reported as a timeout"
    );
}

#[cfg(target_os = "macos")]
#[test]
fn seatbelt_defaults_cwd_to_allowed_path_without_getcwd_leak() {
    // No `cwd` set: the child must run in a sandbox-allowed directory (the
    // first readwrite path) rather than inheriting a possibly-inaccessible
    // host cwd, so getcwd() does not leak a permission error to stderr.
    let result =
        spawn_and_wait(seatbelt_request("/bin/pwd", 10000)).expect("seatbelt run should succeed");

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

// ---------------------------------------------------------------------------
// Windows ProcessContainer (AppContainer + BaseContainer) — integration tests.
//
// These exercise two capture/timeout regressions: the process handle being
// closed before the wait completed, and a finite timeout killing only the
// direct child so it never fired. ProcessContainer resolves to BaseContainer or
// AppContainer by host capability; these guards hold for whichever backend the
// host selects.
// They run a real sandbox, so they require an elevated, host-prepped Windows
// host (see docs/host-prep.md) and are therefore `#[ignore]`d — run them with
// `cargo test -p mxc-sdk -- --ignored` on such a host.
// ---------------------------------------------------------------------------

#[cfg(target_os = "windows")]
#[test]
#[ignore = "requires an elevated, host-prepped Windows host (see docs/host-prep.md)"]
fn process_container_captures_stdout() {
    // Regression guard: a valid exit code and captured stdout prove the
    // process handle was not closed out from under the wait.
    let result = spawn_and_wait(process_container_request(
        "0.7.0-alpha",
        "cmd /c echo hello-process-container",
        30000,
    ))
    .expect("ProcessContainer run should succeed");
    assert_eq!(result.exit_code, 0, "stderr: {}", result.standard_err);
    assert!(
        result.standard_out.contains("hello-process-container"),
        "stdout should be captured, got: {:?}",
        result.standard_out
    );
}

#[cfg(target_os = "windows")]
#[test]
#[ignore = "requires an elevated, host-prepped Windows host (see docs/host-prep.md)"]
fn process_container_finite_timeout_fires() {
    // Regression guard: a finite timeout must fire even when the command
    // spawns a descendant that keeps the inherited stdout write-end open. If
    // the timeout only killed the direct child, the capture reader would block
    // forever and this test would hang past the bounded wall-clock below.
    let result = spawn_and_wait(process_container_request(
        "0.7.0-alpha",
        "cmd /c start /b ping -n 60 127.0.0.1 >nul & ping -n 60 127.0.0.1 >nul",
        2000,
    ))
    .expect("ProcessContainer run should return a response");
    assert!(result.timed_out, "a timed-out run must report a timeout");
    // The bounded wait is enforced by the test harness; a hang here is the
    // failure mode the regression guards against.
}

// ---------------------------------------------------------------------------
// `run` — the run-to-completion convenience (spawn + wait_with_output).
// ---------------------------------------------------------------------------

#[cfg(target_os = "macos")]
#[test]
fn run_captures_stdout_seatbelt() {
    // `run` spawns, waits, and returns captured stdout/stderr in one call.
    let output = mxc_sdk::run(seatbelt_request("echo hello-run", 10000))
        .expect("seatbelt run should succeed");
    assert_eq!(output.outcome, WaitOutcome::Exited(0));
    assert!(
        String::from_utf8_lossy(&output.stdout).contains("hello-run"),
        "stdout should be captured, got: {:?}",
        String::from_utf8_lossy(&output.stdout)
    );
}

#[cfg(target_os = "macos")]
#[test]
fn run_reports_timeout_seatbelt() {
    // A finite scriptTimeout shorter than the command must surface as
    // `WaitOutcome::TimedOut` rather than an error.
    let output =
        mxc_sdk::run(seatbelt_request("sleep 30", 1000)).expect("run should return an outcome");
    assert_eq!(output.outcome, WaitOutcome::TimedOut);
}

#[cfg(target_os = "windows")]
#[test]
#[ignore = "requires an elevated, host-prepped Windows host (see docs/host-prep.md)"]
fn run_captures_stdout_process_container() {
    // `run` spawns, waits, and returns captured stdout/stderr in one call.
    let output = mxc_sdk::run(process_container_request(
        "0.7.0-alpha",
        "cmd /c echo hello-run",
        30000,
    ))
    .expect("ProcessContainer run should succeed");
    assert_eq!(output.outcome, WaitOutcome::Exited(0));
    assert!(
        String::from_utf8_lossy(&output.stdout).contains("hello-run"),
        "stdout should be captured, got: {:?}",
        String::from_utf8_lossy(&output.stdout)
    );
}
