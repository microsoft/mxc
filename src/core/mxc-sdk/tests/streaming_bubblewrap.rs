// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Bubblewrap streaming API tests: live stdio, exit-status fidelity,
//! kill/reap, and output metadata.
//!
//! Linux-gated file: the sibling `streaming.rs` is `#![cfg(macos)]` and
//! `streaming_processcontainer.rs` is `#![cfg(windows)]`, so the Linux cases
//! need a third file rather than a `#[cfg]` inside either.
//!
//! Tests skip when `bwrap` is missing or too old.

#![cfg(target_os = "linux")]

use mxc_sdk::{build_request, spawn_sandbox, SandboxPolicy, SandboxRequest, WaitOutcome};

/// Whether `bwrap` is usable. Reuses the backend's own probe so this gate
/// cannot drift from the real version check.
fn bwrap_available() -> bool {
    match bwrap_common::bwrap_version::probe_bwrap() {
        Ok(_) => true,
        Err(err) => {
            println!("SKIPPED: {err}");
            false
        }
    }
}

/// A Bubblewrap streaming request (`/tmp` read-write) with the given command
/// and timeout (ms; `0` == run until exit).
fn bwrap_request(command: &str, timeout_ms: u32) -> SandboxRequest {
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

/// Whether `pid` still has a `/proc` entry. A zombie still has one, so this
/// distinguishes "reaped" from merely "exited".
fn proc_entry_exists(pid: u32) -> bool {
    std::path::Path::new(&format!("/proc/{pid}")).exists()
}

#[test]
fn streaming_bubblewrap_bidirectional_stdio() {
    if !bwrap_available() {
        return;
    }
    use std::io::{Read, Write};

    let mut proc = spawn_sandbox(bwrap_request("cat", 0)).expect("spawn");

    let mut stdin = proc.take_stdin().expect("stdin available");
    let mut stdout = proc.take_stdout().expect("stdout available");

    stdin.write_all(b"ping-pong\n").expect("write stdin");
    drop(stdin); // close -> cat sees EOF and exits

    let mut out = String::new();
    stdout.read_to_string(&mut out).expect("read stdout");
    assert!(out.contains("ping-pong"), "got: {out:?}");

    assert_eq!(proc.wait().expect("wait"), WaitOutcome::Exited(0));
}

#[test]
fn streaming_bubblewrap_wait_with_output_captures_both_streams() {
    // Drains both streams concurrently, avoiding the take-both deadlock.
    if !bwrap_available() {
        return;
    }
    let proc = spawn_sandbox(bwrap_request("echo to-out; echo to-err 1>&2", 0)).expect("spawn");

    let output = proc.wait_with_output().expect("wait_with_output");
    assert_eq!(output.outcome, WaitOutcome::Exited(0));
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

#[test]
fn streaming_bubblewrap_stderr_is_readable_live() {
    // Pins `take_stderr` itself, which `wait_with_output` bypasses.
    if !bwrap_available() {
        return;
    }
    use std::io::Read;

    let mut proc = spawn_sandbox(bwrap_request("echo diagnostic 1>&2", 0)).expect("spawn");

    let mut stderr = proc.take_stderr().expect("stderr available");
    let mut err = String::new();
    stderr.read_to_string(&mut err).expect("read stderr");
    assert!(err.contains("diagnostic"), "got: {err:?}");

    assert_eq!(proc.wait().expect("wait"), WaitOutcome::Exited(0));
}

#[test]
fn streaming_bubblewrap_wait_reports_the_workloads_exit_code() {
    // `bwrap` sits between the SDK and the workload: pins that the workload's
    // status propagates, not bwrap's own.
    if !bwrap_available() {
        return;
    }
    for code in [0, 1, 42] {
        let mut proc = spawn_sandbox(bwrap_request(&format!("exit {code}"), 0)).expect("spawn");
        assert_eq!(
            proc.wait().expect("wait"),
            WaitOutcome::Exited(code),
            "workload exited {code}"
        );
    }
}

#[test]
fn streaming_bubblewrap_id_exposes_a_real_pid() {
    // Contrast WSLC, which documents `id() == 0` because its SDK exposes no pid.
    if !bwrap_available() {
        return;
    }
    let mut proc = spawn_sandbox(bwrap_request("sleep 30", 0)).expect("spawn");

    let pid = proc.id();
    assert!(pid > 0, "id() should expose a real pid, got {pid}");
    assert!(
        proc_entry_exists(pid),
        "pid {pid} should be live while the sandbox runs"
    );

    proc.kill().expect("kill");
    let _ = proc.wait();
}

#[test]
fn streaming_bubblewrap_kill_reaps_the_child() {
    if !bwrap_available() {
        return;
    }
    let mut proc = spawn_sandbox(bwrap_request("sleep 30", 0)).expect("spawn");
    let pid = proc.id();

    assert!(
        proc.try_wait().expect("try_wait").is_none(),
        "child should still be running shortly after spawn"
    );

    proc.kill().expect("kill");
    assert_ne!(
        proc.wait().expect("wait after kill"),
        WaitOutcome::Exited(0),
        "killed process should not report success"
    );

    let mut reaped = false;
    for _ in 0..60 {
        if !proc_entry_exists(pid) {
            reaped = true;
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(50));
    }
    assert!(reaped, "pid {pid} should be reaped, not left as a zombie");
}

#[test]
fn streaming_bubblewrap_timeout_reports_timed_out() {
    if !bwrap_available() {
        return;
    }
    let mut proc = spawn_sandbox(bwrap_request("sleep 30", 1000)).expect("spawn");

    let start = std::time::Instant::now();
    assert_eq!(
        proc.wait().expect("wait yields an outcome"),
        WaitOutcome::TimedOut,
        "a workload outliving its timeout should report a timeout"
    );
    assert!(
        start.elapsed() < std::time::Duration::from_secs(15),
        "timeout should fire near 1s, not wait out the 30s sleep (elapsed: {:?})",
        start.elapsed()
    );
}

#[test]
fn streaming_bubblewrap_reports_no_output_metadata() {
    // Pins the current contract: Bubblewrap produces no structured outputs
    // (`captureDenials` is a Windows BaseContainer feature), so the accessor is
    // callable after terminal teardown and empty. A backend that starts
    // emitting metadata should update this rather than surprise callers.
    if !bwrap_available() {
        return;
    }
    let mut proc = spawn_sandbox(bwrap_request("true", 0)).expect("spawn");
    assert_eq!(proc.wait().expect("wait"), WaitOutcome::Exited(0));
    assert!(
        proc.output_metadata().is_none(),
        "Bubblewrap should report no structured output metadata"
    );
}
