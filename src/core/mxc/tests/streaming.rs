// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Streaming (handle-based) API tests: live stdio, kill, and wait.
//! Seatbelt-specific cases run only on macOS.
//!
//! These drive the real consumer path: build an [`ExecutionRequest`] from a
//! [`SandboxPolicy`] via `build_request`, fill in the command, then
//! `spawn_sandbox`.

use mxc::{build_request, spawn_sandbox, ExecutionRequest, MxcErrorCode, SandboxPolicy};

/// A minimal request for the cross-platform error-path cases (never actually
/// runs a process). `build_request` resolves the host's default backend.
fn minimal_request(command: &str) -> ExecutionRequest {
    let policy = SandboxPolicy {
        version: "0.7.0-alpha".to_string(),
        filesystem: None,
        network: None,
        ui: None,
        timeout_ms: None,
    };
    let mut request = build_request(&policy, None).expect("build_request should succeed");
    request.script_code = command.to_string();
    request
}

/// A Seatbelt streaming request (`/tmp` read-write) with the given command and
/// timeout (ms; `0` == run until exit, required for interactive/long cases).
#[cfg(target_os = "macos")]
fn seatbelt_request(command: &str, timeout_ms: u32) -> ExecutionRequest {
    let policy = SandboxPolicy {
        version: "0.7.0-alpha".to_string(),
        filesystem: Some(mxc::policy::FilesystemSection {
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
    request.script_code = command.to_string();
    request
}

#[test]
fn streaming_rejects_dry_run() {
    let mut request = minimal_request("echo hi");
    request.dry_run = true;
    let err = match spawn_sandbox(request) {
        Ok(_) => panic!("dry_run streaming must be rejected"),
        Err(e) => e,
    };
    assert_eq!(err.code, MxcErrorCode::MalformedRequest);
}

#[cfg(target_os = "macos")]
#[test]
fn streaming_rejects_gui_access() {
    // A windowed (guiAccess) app needs inherited stdio, so it cannot be streamed
    // over pipes; the library path must reject it rather than silently drop the
    // GUI capability.
    let mut request = seatbelt_request("echo hi", 0);
    request
        .seatbelt
        .as_mut()
        .expect("seatbelt config on macOS")
        .gui_access = true;
    let err = match spawn_sandbox(request) {
        Ok(_) => panic!("guiAccess streaming must be rejected"),
        Err(e) => e,
    };
    assert!(
        err.message.contains("guiAccess"),
        "expected a guiAccess rejection, got: {}",
        err.message
    );
}

#[cfg(target_os = "macos")]
#[test]
fn streaming_double_take_returns_none() {
    let mut proc = spawn_sandbox(seatbelt_request("cat", 0)).expect("spawn");

    assert!(
        proc.take_stdin().is_some(),
        "first take_stdin yields the pipe"
    );
    assert!(proc.take_stdin().is_none(), "second take_stdin yields None");
    assert!(
        proc.take_stdout().is_some(),
        "first take_stdout yields the pipe"
    );
    assert!(
        proc.take_stdout().is_none(),
        "second take_stdout yields None"
    );
    assert!(
        proc.take_stderr().is_some(),
        "first take_stderr yields the pipe"
    );
    assert!(
        proc.take_stderr().is_none(),
        "second take_stderr yields None"
    );

    proc.kill().expect("kill");
    let _ = proc.wait();
}

#[cfg(target_os = "macos")]
#[test]
fn streaming_try_wait_reports_exit_after_completion() {
    let mut proc = spawn_sandbox(seatbelt_request("true", 0)).expect("spawn");

    // Poll try_wait until the quick command exits; it must then report Some.
    let mut code = None;
    for _ in 0..100 {
        if let Some(c) = proc.try_wait().expect("try_wait") {
            code = Some(c);
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(50));
    }
    let code = code.expect("process should exit and try_wait report it");
    assert_eq!(code, 0, "quick command should exit 0");
}

#[cfg(target_os = "macos")]
#[test]
fn streaming_stdout_closer_unblocks_parked_read_without_killing() {
    use std::io::Read;

    // `sleep` produces no output yet holds its stdout pipe write-end open, so a
    // read parks indefinitely (mirroring a backgrounded descendant that keeps a
    // pipe open past the foreground command's exit). The stdout closer must EOF
    // that read promptly *without* terminating the still-running child — a plain
    // `kill()` would defeat the point.
    let mut proc = spawn_sandbox(seatbelt_request("sleep 30", 0)).expect("spawn");

    let mut stdout = proc.take_stdout().expect("stdout available");
    // The closer is valid even though stdout has already been taken.
    let closer = proc.stdout_closer().expect("stdout closer available");
    assert!(
        proc.stderr_closer().is_some(),
        "stderr closer should also be available in pipes mode"
    );

    // Park a blocking read on a worker thread; with the writer held open it
    // cannot return on its own.
    let reader = std::thread::spawn(move || {
        let mut buf = [0u8; 64];
        let start = std::time::Instant::now();
        let n = stdout.read(&mut buf).expect("read returns");
        (n, start.elapsed())
    });

    // Let the read park, confirm the child is still running, then close.
    std::thread::sleep(std::time::Duration::from_millis(200));
    assert!(
        proc.try_wait().expect("try_wait").is_none(),
        "child should still be running while the read is parked"
    );
    closer.close();

    let (n, elapsed) = reader.join().expect("reader thread");
    assert_eq!(n, 0, "closed stream reports EOF");
    assert!(
        elapsed < std::time::Duration::from_secs(10),
        "read should return promptly after close (elapsed: {elapsed:?})"
    );

    // The closer must not have terminated the child.
    assert!(
        proc.try_wait().expect("try_wait").is_none(),
        "stdout_closer must not terminate the child"
    );

    // A second close is a harmless no-op.
    closer.close();

    proc.kill().expect("kill");
    let _ = proc.wait();
}

// ---------------------------------------------------------------------------
// Windows ProcessContainer streaming — integration test. Requires an elevated,
// host-prepped Windows host (see docs/host-prep.md), so it is `#[ignore]`d.
// ---------------------------------------------------------------------------

#[cfg(target_os = "windows")]
#[test]
#[ignore = "requires an elevated, host-prepped Windows host (see docs/host-prep.md)"]
fn streaming_processcontainer_bidirectional_stdio() {
    use std::io::{Read, Write};

    let policy = SandboxPolicy {
        version: "0.7.0-alpha".to_string(),
        filesystem: Some(mxc::policy::FilesystemSection {
            readwrite_paths: vec!["C:\\Windows\\Temp".to_string()],
            readonly_paths: vec![],
            denied_paths: vec![],
            clear_policy_on_exit: None,
        }),
        network: None,
        ui: None,
        timeout_ms: None,
    };
    let mut request = build_request(&policy, None).expect("build_request");
    // `cmd /c more` echoes stdin to stdout until EOF, then exits.
    request.script_code = "cmd /c more".to_string();
    let mut proc = spawn_sandbox(request).expect("spawn");

    let mut stdin = proc.take_stdin().expect("stdin available");
    let mut stdout = proc.take_stdout().expect("stdout available");

    stdin.write_all(b"ping-pong\r\n").expect("write stdin");
    drop(stdin);

    let mut out = String::new();
    stdout.read_to_string(&mut out).expect("read stdout");
    assert!(out.contains("ping-pong"), "got: {:?}", out);

    let code = proc.wait().expect("wait");
    assert_eq!(code, 0);
}

#[cfg(target_os = "macos")]
#[test]
fn streaming_wait_discards_untaken_streams() {
    let mut proc =
        spawn_sandbox(seatbelt_request("echo streamed-out", 0)).expect("spawn should succeed");
    // Take nothing -> wait() drains and discards the output, returning only
    // the exit code.
    let code = proc.wait().expect("wait should succeed");
    assert_eq!(code, 0);
}

#[cfg(target_os = "macos")]
#[test]
fn streaming_bidirectional_stdio() {
    use std::io::{Read, Write};

    // `cat` echoes stdin to stdout until EOF, then exits.
    let mut proc = spawn_sandbox(seatbelt_request("cat", 0)).expect("spawn");

    let mut stdin = proc.take_stdin().expect("stdin available");
    let mut stdout = proc.take_stdout().expect("stdout available");

    stdin.write_all(b"ping-pong\n").expect("write stdin");
    drop(stdin); // close -> cat sees EOF and exits

    let mut out = String::new();
    stdout.read_to_string(&mut out).expect("read stdout");
    assert!(out.contains("ping-pong"), "got: {:?}", out);

    let code = proc.wait().expect("wait");
    assert_eq!(code, 0);
}

#[cfg(target_os = "macos")]
#[test]
fn streaming_kill_terminates_process() {
    let mut proc = spawn_sandbox(seatbelt_request("sleep 30", 0)).expect("spawn");

    // Still running shortly after spawn.
    assert!(proc.try_wait().expect("try_wait").is_none());

    proc.kill().expect("kill should succeed");

    // After kill, the process must be reapable and not report success.
    let code = proc.wait().expect("wait after kill");
    assert_ne!(code, 0, "killed process should not exit 0");
}

#[cfg(target_os = "macos")]
#[test]
fn streaming_kill_terminates_forked_descendant_quickly() {
    // Regression for the early-kill race: when the shell *forks* the inner
    // command (`echo` then `sleep`), an early `kill()` could SIGTERM the shell
    // (which dies) before the just-forked `sleep` joined the group — leaving
    // `sleep` alive and the follow-up `wait()` blocking for its full runtime.
    // The whole tree must die promptly regardless.
    let mut proc = spawn_sandbox(seatbelt_request("echo hi; sleep 30", 0)).expect("spawn");

    proc.kill().expect("kill should succeed");

    let start = std::time::Instant::now();
    let _ = proc.wait();
    assert!(
        start.elapsed() < std::time::Duration::from_secs(10),
        "wait() must return promptly after kill(), not wait out the child's \
         30s runtime (elapsed: {:?})",
        start.elapsed()
    );
}

#[cfg(target_os = "macos")]
fn pid_alive(pid: u32) -> bool {
    // Signal 0 probes existence without delivering a signal — no PID-reuse
    // race from spawning `ps`, and no false "dead" if the probe itself fails.
    let rc = unsafe { libc::kill(pid as libc::pid_t, 0) };
    if rc == 0 {
        return true;
    }
    // ESRCH => no such process (dead). Any other errno (e.g. EPERM: the pid
    // exists but we may not signal it) means it is still alive.
    std::io::Error::last_os_error().raw_os_error() != Some(libc::ESRCH)
}

#[cfg(target_os = "macos")]
#[test]
fn streaming_kill_terminates_process_tree() {
    use std::io::{BufRead, BufReader};

    // The sandboxed shell backgrounds a `sleep` (a descendant), prints its
    // pid, then blocks. `kill()` must take the whole process group down,
    // including that descendant.
    let mut proc =
        spawn_sandbox(seatbelt_request("sleep 300 & echo CHILD=$!; sleep 300", 0)).expect("spawn");

    assert!(proc.id() > 0, "id() should expose the child pid");

    let stdout = proc.take_stdout().expect("stdout");
    let mut reader = BufReader::new(stdout);
    let mut line = String::new();
    reader.read_line(&mut line).expect("read descendant pid");
    let descendant: u32 = line
        .trim()
        .strip_prefix("CHILD=")
        .expect("CHILD= prefix")
        .parse()
        .expect("descendant pid");

    assert!(
        pid_alive(descendant),
        "descendant {descendant} should be running before kill"
    );

    proc.kill().expect("kill");
    let _ = proc.wait();

    let mut gone = false;
    for _ in 0..60 {
        if !pid_alive(descendant) {
            gone = true;
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(50));
    }
    assert!(
        gone,
        "descendant {descendant} should be killed with the process tree"
    );
}

#[cfg(target_os = "macos")]
#[test]
fn streaming_timeout_kills_process_tree() {
    use std::io::{BufRead, BufReader};

    // 1s timeout; the shell backgrounds a long sleep (descendant), prints its
    // pid, then blocks past the timeout. wait()'s timeout branch must group-
    // kill, taking the descendant down too.
    let mut proc = spawn_sandbox(seatbelt_request(
        "sleep 300 & echo CHILD=$!; sleep 300",
        1000,
    ))
    .expect("spawn");

    let stdout = proc.take_stdout().expect("stdout");
    let mut reader = BufReader::new(stdout);
    let mut line = String::new();
    reader.read_line(&mut line).expect("read descendant pid");
    let descendant: u32 = line
        .trim()
        .strip_prefix("CHILD=")
        .expect("CHILD= prefix")
        .parse()
        .expect("descendant pid");

    let err = proc
        .wait()
        .expect_err("timed-out process should report a timeout");
    assert_eq!(err.kind(), std::io::ErrorKind::TimedOut);

    let mut gone = false;
    for _ in 0..60 {
        if !pid_alive(descendant) {
            gone = true;
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(50));
    }
    assert!(gone, "descendant {descendant} should be killed on timeout");
}
