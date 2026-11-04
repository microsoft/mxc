// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Streaming (handle-based) API tests: live stdio, kill, and wait.
//! Seatbelt-specific cases run only on macOS.
//!
//! These drive the real consumer path by constructing a [`ContainerRequest`]
//! and passing it to `mxc_sdk::v1::spawn`.

#![cfg(target_os = "macos")]

mod unix_pty_contract;

use mxc_sdk::v1::{
    spawn, spawn_with_pty, ContainerRequest, FilesystemPolicy, SpawnWithPtyOptions, WaitResult,
};

/// A Seatbelt streaming request (`/tmp` read-write) with the given command and
/// timeout (ms; `0` == run until exit, required for interactive/long cases).
#[cfg(target_os = "macos")]
fn seatbelt_request(command: &str, timeout_ms: u32) -> ContainerRequest {
    ContainerRequest {
        filesystem: Some(FilesystemPolicy {
            readwrite_paths: vec!["/tmp".to_string()],
            readonly_paths: vec![],
            denied_paths: vec![],
            clear_policy_on_exit: None,
        }),
        timeout_ms: (timeout_ms != 0).then_some(timeout_ms),
        ..ContainerRequest::new(command)
    }
}

#[cfg(target_os = "macos")]
#[test]
fn streaming_double_take_returns_none() {
    let mut proc = spawn(seatbelt_request("cat", 0), Default::default()).expect("spawn");

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

#[test]
fn seatbelt_pty_supports_io_resize_and_merged_output() {
    unix_pty_contract::assert_round_trip(seatbelt_request(
        unix_pty_contract::ROUND_TRIP_COMMAND,
        30_000,
    ));
}

#[test]
fn seatbelt_pty_enforces_script_timeout() {
    unix_pty_contract::assert_timeout(
        seatbelt_request(unix_pty_contract::TIMEOUT_COMMAND, 1_000),
        std::time::Duration::from_secs(15),
    );
}

#[test]
fn seatbelt_pty_preserves_explicit_timeout_kill() {
    unix_pty_contract::assert_explicit_timeout_kill(seatbelt_request(
        unix_pty_contract::TIMEOUT_COMMAND,
        30_000,
    ));
}

#[test]
fn seatbelt_pty_transfers_native_stdio() {
    unix_pty_contract::assert_native_stdio(seatbelt_request(
        unix_pty_contract::NATIVE_STDIO_COMMAND,
        30_000,
    ));
}

#[cfg(target_os = "macos")]
#[test]
fn streaming_try_wait_reports_exit_after_completion() {
    let mut proc = spawn(seatbelt_request("true", 0), Default::default()).expect("spawn");

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

#[test]
fn streaming_kill_after_reap_is_a_noop() {
    // Regression: once the child has exited and been reaped (here via `wait`),
    // `kill()` must not signal its pid/pgid again — a recycled pid could belong
    // to an unrelated process (group). The post-reap `kill()` is a clean no-op.
    let mut proc = spawn(seatbelt_request("true", 0), Default::default()).expect("spawn");
    assert_eq!(
        proc.wait().expect("wait"),
        WaitResult::Exited(0),
        "quick command should exit 0"
    );
    proc.kill().expect("kill after reap is a no-op Ok");
    proc.kill().expect("repeat kill after reap stays Ok");
}

#[test]
fn streaming_kill_after_try_wait_reap_is_a_noop() {
    // The exact race the review flagged: `try_wait()` reaps the exited child, so
    // a later `kill()` must not signal the now-recycled pid/pgid. Poll try_wait
    // to completion, then `kill()` must stay a clean no-op.
    let mut proc = spawn(seatbelt_request("true", 0), Default::default()).expect("spawn");
    let mut reaped = false;
    for _ in 0..100 {
        if proc.try_wait().expect("try_wait").is_some() {
            reaped = true;
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(50));
    }
    assert!(
        reaped,
        "quick command should exit and try_wait should reap it"
    );
    proc.kill().expect("kill after try_wait reap is a no-op Ok");
    proc.kill().expect("repeat kill stays Ok");
}

#[test]
fn streaming_double_kill_before_wait_completes_promptly() {
    // Calling `kill()` twice before `wait()` must be stable (both Ok), and
    // `wait()` must then complete promptly rather than hang.
    let mut proc = spawn(seatbelt_request("sleep 30", 0), Default::default()).expect("spawn");
    proc.kill().expect("first kill");
    proc.kill().expect("second kill stays Ok");
    let start = std::time::Instant::now();
    let _ = proc.wait();
    assert!(
        start.elapsed() < std::time::Duration::from_secs(5),
        "wait() after a double kill should complete promptly, took {:?}",
        start.elapsed()
    );
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
    let mut proc = spawn(seatbelt_request("sleep 30", 0), Default::default()).expect("spawn");

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

#[cfg(target_os = "macos")]
#[test]
fn streaming_wait_discards_untaken_streams() {
    let mut proc = spawn(seatbelt_request("echo streamed-out", 0), Default::default())
        .expect("spawn should succeed");
    // Take nothing -> wait() drains and discards the output, returning only
    // the exit code.
    assert_eq!(
        proc.wait().expect("wait should succeed"),
        WaitResult::Exited(0)
    );
}

#[cfg(target_os = "macos")]
#[test]
fn streaming_wait_with_output_captures_both_streams() {
    // wait_with_output drains stdout and stderr concurrently, so a child that
    // writes to both is captured without the take-both deadlock foot-gun.
    let proc = spawn(
        seatbelt_request("echo to-out; echo to-err 1>&2", 0),
        Default::default(),
    )
    .expect("spawn should succeed");
    let output = proc
        .wait_with_output()
        .expect("wait_with_output should succeed");
    assert_eq!(output.outcome, WaitResult::Exited(0));
    assert!(
        String::from_utf8_lossy(&output.stdout).contains("to-out"),
        "stdout: {:?}",
        String::from_utf8_lossy(&output.stdout)
    );
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("to-err"),
        "stderr: {:?}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[cfg(target_os = "macos")]
#[test]
fn streaming_bidirectional_stdio() {
    use std::io::{Read, Write};

    // `cat` echoes stdin to stdout until EOF, then exits.
    let mut proc = spawn(seatbelt_request("cat", 0), Default::default()).expect("spawn");

    let mut stdin = proc.take_stdin().expect("stdin available");
    let mut stdout = proc.take_stdout().expect("stdout available");

    stdin.write_all(b"ping-pong\n").expect("write stdin");
    drop(stdin); // close -> cat sees EOF and exits

    let mut out = String::new();
    stdout.read_to_string(&mut out).expect("read stdout");
    assert!(out.contains("ping-pong"), "got: {:?}", out);

    assert_eq!(proc.wait().expect("wait"), WaitResult::Exited(0));
}

#[cfg(target_os = "macos")]
#[test]
fn streaming_kill_terminates_process() {
    let mut proc = spawn(seatbelt_request("sleep 30", 0), Default::default()).expect("spawn");

    // Still running shortly after spawn.
    assert!(proc.try_wait().expect("try_wait").is_none());

    proc.kill().expect("kill should succeed");

    // After kill, the process must be reapable and not report success.
    assert_ne!(
        proc.wait().expect("wait after kill"),
        WaitResult::Exited(0),
        "killed process should not exit 0"
    );
}

#[cfg(target_os = "macos")]
#[test]
fn streaming_kill_terminates_forked_descendant_quickly() {
    // Regression for the early-kill race: when the shell *forks* the inner
    // command (`echo` then `sleep`), an early `kill()` could SIGTERM the shell
    // (which dies) before the just-forked `sleep` joined the group — leaving
    // `sleep` alive and the follow-up `wait()` blocking for its full runtime.
    // The whole tree must die promptly regardless.
    let mut proc =
        spawn(seatbelt_request("echo hi; sleep 30", 0), Default::default()).expect("spawn");

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
fn assert_pty_job_control_tree_is_killed(timeout_ms: u32, explicit_kill: bool) {
    use std::io::{BufRead, BufReader};

    let terminal = spawn_with_pty(
        seatbelt_request(
            "exec /bin/bash -c 'set -m; trap \"\" HUP; sleep 300 & echo CHILD=$!; wait'",
            timeout_ms,
        ),
        SpawnWithPtyOptions::default(),
    )
    .expect("spawn PTY job-control shell");
    let reader = terminal.try_clone_reader().expect("PTY reader");
    let closer = terminal.stdout_closer().expect("PTY reader closer");
    let (sender, receiver) = std::sync::mpsc::sync_channel(1);
    let reader_thread = std::thread::spawn(move || {
        let mut reader = BufReader::new(reader);
        let mut line = String::new();
        let mut readiness_sent = false;
        loop {
            line.clear();
            match reader.read_line(&mut line) {
                Ok(0) => {
                    if !readiness_sent {
                        let _ = sender.send(Err("PTY output ended before CHILD=<pid>".to_string()));
                    }
                    return;
                }
                Ok(_) => {
                    if !readiness_sent {
                        if let Some(value) = line.trim().strip_prefix("CHILD=") {
                            let _ = sender.send(
                                value
                                    .parse::<u32>()
                                    .map_err(|error| format!("invalid descendant pid: {error}")),
                            );
                            readiness_sent = true;
                        }
                    }
                }
                Err(error) => {
                    if !readiness_sent {
                        let _ = sender.send(Err(format!("failed to read descendant pid: {error}")));
                    }
                    return;
                }
            }
        }
    });
    let descendant = match receiver.recv_timeout(std::time::Duration::from_secs(10)) {
        Ok(Ok(descendant)) => descendant,
        Ok(Err(error)) => {
            closer.close();
            let _ = terminal.kill();
            reader_thread.join().expect("PTY reader thread");
            panic!("{error}");
        }
        Err(error) => {
            closer.close();
            let _ = terminal.kill();
            reader_thread.join().expect("PTY reader thread");
            panic!("timed out waiting for PTY job-control readiness: {error}");
        }
    };
    // SAFETY: `getpgid` only queries the process identified by `descendant`.
    let descendant_group = unsafe { libc::getpgid(descendant as libc::pid_t) };
    assert!(descendant_group > 0, "descendant process group");
    assert_ne!(
        descendant_group as u32,
        terminal.id(),
        "job control must place the descendant outside the shell's process group"
    );
    let terminal = std::sync::Arc::new(terminal);
    let leader = terminal.id();
    let waiter = {
        let terminal = std::sync::Arc::clone(&terminal);
        std::thread::spawn(move || {
            if explicit_kill {
                terminal.kill().expect("kill PTY session");
            }
            terminal.wait()
        })
    };
    let (sender, receiver) = std::sync::mpsc::sync_channel(1);
    std::thread::spawn(move || {
        let _ = sender.send(waiter.join());
    });
    let outcome = match receiver.recv_timeout(std::time::Duration::from_secs(20)) {
        Ok(Ok(Ok(outcome))) => outcome,
        Ok(Ok(Err(error))) => {
            closer.close();
            reader_thread.join().expect("PTY reader thread");
            panic!("PTY termination failed: {error}");
        }
        Ok(Err(_)) => {
            closer.close();
            let _ = terminal.kill();
            reader_thread.join().expect("PTY reader thread");
            panic!("PTY termination thread panicked");
        }
        Err(error) => {
            closer.close();
            // SAFETY: these are the two process IDs created and observed by this test.
            unsafe {
                libc::kill(descendant as libc::pid_t, libc::SIGKILL);
                libc::kill(leader as libc::pid_t, libc::SIGKILL);
            }
            reader_thread.join().expect("PTY reader thread");
            panic!("PTY termination did not complete within 20 seconds: {error}");
        }
    };
    closer.close();
    reader_thread.join().expect("PTY reader thread");
    if explicit_kill {
        assert_ne!(outcome, WaitResult::Exited(0));
    } else {
        assert_eq!(outcome, WaitResult::TimedOut);
    }

    for _ in 0..60 {
        if !pid_alive(leader) && !pid_alive(descendant) {
            return;
        }
        std::thread::sleep(std::time::Duration::from_millis(50));
    }
    panic!(
        "PTY termination left processes alive: leader={leader} alive={}, descendant={descendant} \
         alive={}",
        pid_alive(leader),
        pid_alive(descendant)
    );
}

#[cfg(target_os = "macos")]
#[test]
fn seatbelt_pty_kill_terminates_job_control_groups() {
    assert_pty_job_control_tree_is_killed(0, true);
}

#[cfg(target_os = "macos")]
#[test]
fn seatbelt_pty_timeout_terminates_job_control_groups() {
    assert_pty_job_control_tree_is_killed(1_000, false);
}

#[cfg(target_os = "macos")]
#[test]
fn seatbelt_pty_kill_sweeps_session_after_leader_exit() {
    use std::io::{BufRead, BufReader};

    let terminal = spawn_with_pty(
        seatbelt_request(
            "exec /bin/bash -c 'set -m; trap \"\" HUP; sleep 300 & echo CHILD=$!; exit 0'",
            0,
        ),
        SpawnWithPtyOptions::default(),
    )
    .expect("spawn PTY job-control shell");
    let mut reader = BufReader::new(terminal.try_clone_reader().expect("PTY reader"));
    let mut line = String::new();
    let descendant = loop {
        line.clear();
        reader.read_line(&mut line).expect("read descendant pid");
        if let Some(value) = line.trim().strip_prefix("CHILD=") {
            break value.parse::<u32>().expect("descendant pid");
        }
    };
    for _ in 0..100 {
        if terminal.try_wait().expect("poll leader").is_some() {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
    assert!(
        terminal.try_wait().expect("confirm leader exit").is_some(),
        "PTY leader did not exit"
    );

    terminal.kill().expect("sweep surviving PTY session");
    for _ in 0..60 {
        if !pid_alive(descendant) {
            return;
        }
        std::thread::sleep(std::time::Duration::from_millis(50));
    }
    panic!("job-control descendant {descendant} survived leader exit and kill");
}

#[cfg(target_os = "macos")]
#[test]
fn streaming_kill_terminates_process_tree() {
    use std::io::{BufRead, BufReader};

    // The sandboxed shell backgrounds a `sleep` (a descendant), prints its
    // pid, then blocks. `kill()` must take the whole process group down,
    // including that descendant.
    let mut proc = spawn(
        seatbelt_request("sleep 300 & echo CHILD=$!; sleep 300", 0),
        Default::default(),
    )
    .expect("spawn");

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
    let mut proc = spawn(
        seatbelt_request("sleep 300 & echo CHILD=$!; sleep 300", 1000),
        Default::default(),
    )
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

    assert_eq!(
        proc.wait().expect("wait yields an outcome"),
        WaitResult::TimedOut,
        "timed-out process should report a timeout"
    );

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

#[cfg(target_os = "macos")]
#[test]
fn streaming_wait_returns_when_descendant_holds_not_taken_stream_open() {
    // The foreground command exits immediately, but a backgrounded `sleep`
    // inherits and holds stdout's write end open. We take NOTHING, so `wait()`
    // drains stdout/stderr itself; with no timeout (wait-forever) it must still
    // return promptly once the foreground child exits — the held-open descendant
    // pipe must not wedge the discard drain (cr-002 regression).
    let mut proc = spawn(seatbelt_request("sleep 30 & exit 0", 0), Default::default())
        .expect("spawn should succeed");

    let start = std::time::Instant::now();
    assert_eq!(
        proc.wait().expect("wait should return"),
        WaitResult::Exited(0),
        "foreground command exits 0"
    );
    assert!(
        start.elapsed() < std::time::Duration::from_secs(10),
        "wait() must return promptly, not block on the descendant's 30s pipe hold \
         (elapsed: {:?})",
        start.elapsed()
    );
}

#[cfg(target_os = "macos")]
#[test]
fn streaming_honors_sub_500ms_timeout() {
    // A sub-500ms timeout used to be rejected outright; it must now be accepted
    // and enforced (cr-011), and fire with low latency (cr-016). `sleep 30`
    // exceeds it, so wait() reports a timeout promptly.
    let mut proc = spawn(seatbelt_request("sleep 30", 200), Default::default()).expect("spawn");
    let start = std::time::Instant::now();
    assert_eq!(
        proc.wait().expect("wait yields an outcome"),
        WaitResult::TimedOut,
        "sub-500ms timeout should fire"
    );
    assert!(
        start.elapsed() < std::time::Duration::from_secs(5),
        "timeout should fire near 200ms, not wait out the 30s sleep (elapsed: {:?})",
        start.elapsed()
    );
}

// Process lifetime: nothing the workload starts may outlive the run, including
// a process that leaves MXC's session (`detached: true` calls `setsid()`).

/// The `node` on `PATH` and the directory the sandbox must be able to read for
/// it to start. Homebrew builds link Homebrew dylibs, so that whole root is
/// granted for them.
#[cfg(target_os = "macos")]
fn node_install() -> (std::path::PathBuf, std::path::PathBuf) {
    let path = std::env::var_os("PATH").unwrap_or_default();
    let node = std::env::split_paths(&path)
        .map(|dir| dir.join("node"))
        .find(|candidate| candidate.is_file())
        .expect("node must be on PATH for the Seatbelt process-lifetime tests");
    let resolved = std::fs::canonicalize(&node).expect("resolve node");
    let root = if resolved.starts_with("/opt/homebrew") {
        std::path::PathBuf::from("/opt/homebrew")
    } else if resolved.starts_with("/usr/local/Cellar") {
        std::path::PathBuf::from("/usr/local")
    } else {
        resolved
            .ancestors()
            .nth(2)
            .expect("node install prefix")
            .to_path_buf()
    };
    (resolved, root)
}

/// A per-test directory under `/tmp`, which the sandbox can write.
#[cfg(target_os = "macos")]
struct Scratch(std::path::PathBuf);

#[cfg(target_os = "macos")]
impl Scratch {
    fn new(tag: &str) -> Self {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock")
            .as_nanos();
        let dir = std::path::PathBuf::from(format!(
            "/private/tmp/mxc-lifetime-{tag}-{}-{nanos}",
            std::process::id()
        ));
        std::fs::create_dir_all(&dir).expect("create scratch dir");
        Self(dir)
    }

    fn path(&self, name: &str) -> String {
        self.0.join(name).display().to_string()
    }
}

#[cfg(target_os = "macos")]
impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// SIGKILLs a leaked descendant when its test fails, so a failing run does not
/// leave it on the host. Not done on success: the pid may have been reused.
#[cfg(target_os = "macos")]
struct KillIfFailing(u32);

#[cfg(target_os = "macos")]
impl Drop for KillIfFailing {
    fn drop(&mut self) {
        if std::thread::panicking() && pid_alive(self.0) {
            // SAFETY: this pid was just observed alive as this test's leaked descendant.
            unsafe { libc::kill(self.0 as libc::pid_t, libc::SIGKILL) };
        }
    }
}

#[cfg(target_os = "macos")]
fn lifetime_request(
    command: String,
    timeout_ms: Option<u32>,
    node_root: &std::path::Path,
) -> ContainerRequest {
    ContainerRequest {
        filesystem: Some(FilesystemPolicy {
            readwrite_paths: vec!["/private/tmp".to_string()],
            readonly_paths: vec![node_root.display().to_string()],
            denied_paths: vec![],
            clear_policy_on_exit: None,
        }),
        timeout_ms,
        ..ContainerRequest::new(command)
    }
}

/// A shell command that uses Node to start `sleep 300` with
/// `spawn(..., { detached: true, stdio: 'ignore' })`, prints `DETACHED=<pid>`,
/// waits until that process has started, then runs `tail`.
#[cfg(target_os = "macos")]
fn detached_descendant_command(scratch: &Scratch, tail: &str) -> (String, std::path::PathBuf) {
    let (node, root) = node_install();
    let script = scratch.path("detach.js");
    std::fs::write(
        &script,
        r#"const { spawn } = require('child_process');
const child = spawn('/bin/sh', ['-c', 'echo started > "$0"; exec /bin/sleep 300', process.argv[2]], {
  detached: true,
  stdio: 'ignore',
});
child.unref();
console.log(`DETACHED=${child.pid}`);
"#,
    )
    .expect("write detach.js");
    let marker = scratch.path("started");
    let command = format!(
        "'{node}' '{script}' '{marker}' || exit 96; i=0; \
         while [ ! -s '{marker}' ] && [ $i -lt 200 ]; do sleep 0.05; i=$((i+1)); done; \
         [ -s '{marker}' ] || {{ echo DETACHED_NOT_STARTED; exit 97; }}; {tail}",
        node = node.display()
    );
    (command, root)
}

#[cfg(target_os = "macos")]
fn detached_pid(output: &str) -> u32 {
    output
        .lines()
        .find_map(|line| line.trim().strip_prefix("DETACHED="))
        .unwrap_or_else(|| panic!("no DETACHED=<pid> in output: {output}"))
        .parse()
        .expect("detached pid")
}

/// Reads stdout until `READY`, returning the detached descendant's pid.
#[cfg(target_os = "macos")]
fn read_detached_pid_until_ready(proc: &mut mxc_sdk::v1::MxcProcess) -> u32 {
    use std::io::{BufRead, BufReader};

    let mut reader = BufReader::new(proc.take_stdout().expect("stdout"));
    let mut output = String::new();
    loop {
        let mut line = String::new();
        let read = reader.read_line(&mut line).expect("read stdout");
        assert!(read != 0, "stdout ended before READY: {output}");
        output.push_str(&line);
        if line.trim() == "READY" {
            return detached_pid(&output);
        }
    }
}

/// Waits for the run and returns its outcome, stdout, and stderr. Unlike
/// `run()`, it keeps the handle, so the caller can check what `wait()` alone
/// cleaned up before dropping the handle cleans up again.
#[cfg(target_os = "macos")]
fn wait_keeping_handle(proc: &mut mxc_sdk::v1::MxcProcess) -> (WaitResult, String, String) {
    use std::io::Read;

    fn capture(stream: Option<Box<dyn Read + Send>>) -> std::thread::JoinHandle<String> {
        std::thread::spawn(move || {
            let mut text = String::new();
            if let Some(mut stream) = stream {
                let _ = stream.read_to_string(&mut text);
            }
            text
        })
    }

    let stdout = capture(proc.take_stdout());
    let stderr = capture(proc.take_stderr());
    let outcome = proc.wait().expect("wait");
    (
        outcome,
        stdout.join().expect("stdout reader"),
        stderr.join().expect("stderr reader"),
    )
}

#[cfg(target_os = "macos")]
fn assert_descendant_gone(pid: u32, when: &str) {
    for _ in 0..100 {
        if !pid_alive(pid) {
            return;
        }
        std::thread::sleep(std::time::Duration::from_millis(50));
    }
    panic!("detached descendant {pid} is still running {when}");
}

#[cfg(target_os = "macos")]
#[test]
fn wait_kills_detached_descendant_after_normal_exit() {
    let scratch = Scratch::new("normal");
    let (command, node_root) = detached_descendant_command(&scratch, "exit 0");
    let mut proc = spawn(
        lifetime_request(command, None, &node_root),
        Default::default(),
    )
    .expect("spawn");

    let (outcome, stdout, stderr) = wait_keeping_handle(&mut proc);
    assert_eq!(
        outcome,
        WaitResult::Exited(0),
        "stdout: {stdout}\nstderr: {stderr}"
    );
    let descendant = detached_pid(&stdout);
    let _guard = KillIfFailing(descendant);

    assert_descendant_gone(descendant, "after wait() returned");
    drop(proc);
}

#[cfg(target_os = "macos")]
#[test]
fn dropping_handle_kills_detached_descendant() {
    let scratch = Scratch::new("drop");
    let (command, node_root) = detached_descendant_command(&scratch, "echo READY; sleep 300");
    let mut proc = spawn(
        lifetime_request(command, None, &node_root),
        Default::default(),
    )
    .expect("spawn");
    let descendant = read_detached_pid_until_ready(&mut proc);
    let _guard = KillIfFailing(descendant);
    assert!(pid_alive(descendant), "descendant should run before drop");

    drop(proc);

    assert_descendant_gone(descendant, "after the handle was dropped");
}

#[cfg(target_os = "macos")]
#[test]
fn streaming_kill_terminates_detached_descendant() {
    let scratch = Scratch::new("kill");
    let (command, node_root) = detached_descendant_command(&scratch, "echo READY; sleep 300");
    let mut proc = spawn(
        lifetime_request(command, None, &node_root),
        Default::default(),
    )
    .expect("spawn");
    let descendant = read_detached_pid_until_ready(&mut proc);
    let _guard = KillIfFailing(descendant);
    assert!(pid_alive(descendant), "descendant should run before kill");

    proc.kill().expect("kill");

    assert_descendant_gone(descendant, "after kill()");
    let _ = proc.wait();
}

#[cfg(target_os = "macos")]
#[test]
fn streaming_timeout_kills_detached_descendant() {
    let scratch = Scratch::new("timeout");
    let (command, node_root) = detached_descendant_command(&scratch, "echo READY; sleep 300");
    let mut proc = spawn(
        lifetime_request(command, Some(5_000), &node_root),
        Default::default(),
    )
    .expect("spawn");
    let descendant = read_detached_pid_until_ready(&mut proc);
    let _guard = KillIfFailing(descendant);
    assert!(
        pid_alive(descendant),
        "descendant should run before the timeout"
    );

    assert_eq!(proc.wait().expect("wait"), WaitResult::TimedOut);

    assert_descendant_gone(descendant, "after the timeout");
}

/// Ending one run must not touch the processes of another run.
#[cfg(target_os = "macos")]
#[test]
fn streaming_kill_leaves_concurrent_run_running() {
    use std::io::{BufRead, BufReader};

    fn start() -> (mxc_sdk::v1::MxcProcess, u32) {
        let mut proc = spawn(
            seatbelt_request("sleep 300 & echo CHILD=$!; sleep 300", 0),
            Default::default(),
        )
        .expect("spawn");
        let mut line = String::new();
        BufReader::new(proc.take_stdout().expect("stdout"))
            .read_line(&mut line)
            .expect("read child pid");
        let child = line
            .trim()
            .strip_prefix("CHILD=")
            .expect("CHILD= prefix")
            .parse()
            .expect("child pid");
        (proc, child)
    }

    let (mut first, first_child) = start();
    let (mut second, second_child) = start();
    let _first_guard = KillIfFailing(first_child);
    let _second_guard = KillIfFailing(second_child);

    first.kill().expect("kill first run");
    assert_descendant_gone(first_child, "after its run was killed");
    let _ = first.wait();
    assert!(
        pid_alive(second_child),
        "killing one run also killed {second_child} from a concurrent run"
    );

    second.kill().expect("kill second run");
    assert_descendant_gone(second_child, "after its run was killed");
    let _ = second.wait();
}

/// Owns a hopping chain's scratch directory. On drop it creates the stop file,
/// waits for the chain to stop writing, and only then removes the directory;
/// a chain that keeps running keeps its directory and stop file.
#[cfg(target_os = "macos")]
struct ChainScratch(Option<Scratch>);

#[cfg(target_os = "macos")]
impl ChainScratch {
    fn path(&self, name: &str) -> String {
        self.0.as_ref().expect("scratch").path(name)
    }
}

#[cfg(target_os = "macos")]
impl Drop for ChainScratch {
    fn drop(&mut self) {
        let _ = std::fs::write(self.path("stop"), b"");
        let log = self.path("chain.log");
        let mut last = chain_length(&log);
        for _ in 0..50 {
            std::thread::sleep(std::time::Duration::from_millis(100));
            let now = chain_length(&log);
            if now == last {
                return;
            }
            last = now;
        }
        let scratch = self.0.take().expect("scratch");
        eprintln!("process chain under {} did not stop", scratch.0.display());
        std::mem::forget(scratch);
    }
}

#[cfg(target_os = "macos")]
fn chain_length(log: &str) -> usize {
    std::fs::read_to_string(log)
        .map(|text| text.lines().count())
        .unwrap_or(0)
}

/// Each process in a chain forks the next and exits at once, so a scan that
/// lists processes and then inspects them can see a process exit before it is
/// inspected while its replacement, started after the listing, is missed by
/// that scan and by the next. Several chains hop in parallel. None may outlive
/// the run.
#[cfg(target_os = "macos")]
#[test]
fn wait_kills_descendant_chain_that_outpaces_process_scans() {
    let scratch = ChainScratch(Some(Scratch::new("chain")));
    let log = scratch.path("chain.log");
    let command = format!(
        r#"LOG='{log}' STOP='{stop}' G=0
hop() {{ [ -e "$STOP" ] && exit 0; [ "$G" -ge 100000 ] && exit 0; G=$((G+1)); echo x >> "$LOG"; ( hop ) </dev/null >/dev/null 2>&1 & exit 0; }}
: > "$LOG"
for chain in 1 2 3 4 5 6 7 8; do ( hop ) </dev/null >/dev/null 2>&1 & done
i=0; while [ $(($(wc -l < "$LOG"))) -lt 200 ] && [ $i -lt 200 ]; do sleep 0.05; i=$((i+1)); done
[ $(($(wc -l < "$LOG"))) -ge 200 ] || {{ echo CHAIN_NOT_HOPPING; exit 97; }}"#,
        stop = scratch.path("stop"),
    );
    let request = ContainerRequest {
        filesystem: Some(FilesystemPolicy {
            readwrite_paths: vec!["/private/tmp".to_string()],
            readonly_paths: vec![],
            denied_paths: vec![],
            clear_policy_on_exit: None,
        }),
        ..ContainerRequest::new(command)
    };

    let mut proc = spawn(request, Default::default()).expect("spawn");

    let (outcome, stdout, stderr) = wait_keeping_handle(&mut proc);
    assert_eq!(
        outcome,
        WaitResult::Exited(0),
        "stdout: {stdout}\nstderr: {stderr}"
    );

    std::thread::sleep(std::time::Duration::from_millis(250));
    let before = chain_length(&log);
    std::thread::sleep(std::time::Duration::from_secs(1));
    let after = chain_length(&log);
    assert_eq!(
        before, after,
        "the process chain kept running after wait() returned ({before} -> {after} hops)"
    );
    drop(proc);
}
