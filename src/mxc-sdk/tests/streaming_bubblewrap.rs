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

mod unix_pty_contract;

use mxc_sdk::v1::WaitResult;
use mxc_sdk::v1::{spawn, ContainerRequest, FilesystemPolicy};

/// Whether `bwrap` is usable. Reuses the backend's own probe so this gate
/// cannot drift from the real version check.
fn bwrap_available() -> bool {
    match mxc_sdk::bwrap_common::bwrap_version::probe_bwrap() {
        Ok(_) => true,
        Err(err) => {
            if std::env::var("MXC_BWRAP_TESTS_REQUIRE_EXECUTION").is_ok_and(|value| value != "0") {
                panic!("strict mode: {err}");
            }
            println!("SKIPPED: {err}");
            false
        }
    }
}

/// A Bubblewrap streaming request (`/tmp` read-write) with the given command
/// and timeout (ms; `0` == run until exit).
fn bwrap_request(command: &str, timeout_ms: u32) -> ContainerRequest {
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

/// Whether `pid` still has a `/proc` entry. An exited child stays a zombie --
/// with a live `/proc` entry -- until its parent `wait()`s and the kernel
/// releases its pid and exit status; that is "reaped". So this distinguishes a
/// child the SDK actually collected from one it merely stopped running.
fn proc_entry_exists(pid: u32) -> bool {
    std::path::Path::new(&format!("/proc/{pid}")).exists()
}

fn run_terminal_fixture(mut command: std::process::Command) {
    use std::process::Stdio;
    use std::time::Duration;

    use mxc_sdk::mxc_common::sandbox_process::{group_kill, wait_with_timeout, WaitError};
    use mxc_sdk::mxc_pty::{LivePty, PtySize};

    let log = tempfile::NamedTempFile::new().expect("fixture log");
    let _terminal = LivePty::attach(&mut command, PtySize::default(), &[]).expect("fixture PTY");
    command
        .stdout(Stdio::from(
            log.as_file().try_clone().expect("fixture stdout"),
        ))
        .stderr(Stdio::from(
            log.as_file().try_clone().expect("fixture stderr"),
        ));
    let mut child = command.spawn().expect("spawn terminal fixture");
    drop(command);

    let outcome =
        wait_with_timeout(&mut child, Some(Duration::from_secs(90))).map_err(|error| match error {
            WaitError::Timeout => "terminal fixture timed out".to_string(),
            WaitError::Io(error) => format!("waiting for terminal fixture failed: {error}"),
        });
    if outcome.is_err() {
        group_kill(&mut child).expect("terminate terminal fixture");
        child.wait().expect("reap terminal fixture");
    }
    let output = std::fs::read_to_string(log.path()).expect("read fixture log");
    assert!(
        matches!(&outcome, Ok(status) if status.success()),
        "terminal fixture failed: {outcome:?}\n{output}"
    );
}

#[test]
fn streaming_bubblewrap_bidirectional_stdio() {
    if !bwrap_available() {
        return;
    }
    use std::io::{Read, Write};

    let mut proc = spawn(bwrap_request("cat", 0), Default::default()).expect("spawn");

    let mut stdin = proc.take_stdin().expect("stdin available");
    let mut stdout = proc.take_stdout().expect("stdout available");

    stdin.write_all(b"ping-pong\n").expect("write stdin");
    drop(stdin); // close -> cat sees EOF and exits

    let mut out = String::new();
    stdout.read_to_string(&mut out).expect("read stdout");
    assert!(out.contains("ping-pong"), "got: {out:?}");

    assert_eq!(proc.wait().expect("wait"), WaitResult::Exited(0));
}

#[test]
fn streaming_bubblewrap_isolates_controlling_terminal() {
    if !bwrap_available() {
        return;
    }
    use std::process::Command;

    const FIXTURE_ENV: &str = "MXC_BWRAP_CONTROLLING_TERMINAL_FIXTURE";
    if std::env::var_os(FIXTURE_ENV).is_some() {
        let _host_terminal =
            std::fs::File::open("/dev/tty").expect("fixture must have a controlling terminal");
        let output = spawn(
            bwrap_request(
                r#"test -c /dev/tty || exit 1
read -r pid comm state ppid pgrp session tty rest < /proc/self/stat
test "$tty" = 0 || { echo "sandbox retained controlling terminal $tty" >&2; exit 1; }
if (exec 3<>/dev/tty) 2>/dev/null; then
    echo "sandbox can open the host controlling terminal" >&2
    exit 1
fi
echo NO_CONTROLLING_TERMINAL"#,
                30_000,
            ),
            Default::default(),
        )
        .expect("spawn with piped stdio")
        .wait_with_output()
        .expect("wait with piped stdio");
        assert_eq!(
            output.outcome,
            WaitResult::Exited(0),
            "stdout: {}, stderr: {}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(
            String::from_utf8_lossy(&output.stdout).contains("NO_CONTROLLING_TERMINAL"),
            "terminal isolation probe did not complete"
        );

        unix_pty_contract::assert_round_trip(bwrap_request(
            &format!(
                "stty size < /dev/tty || exit 1; {}",
                unix_pty_contract::ROUND_TRIP_COMMAND
            ),
            30_000,
        ));
        return;
    }

    let mut command = Command::new(std::env::current_exe().expect("test executable"));
    command
        .args([
            "--exact",
            "streaming_bubblewrap_isolates_controlling_terminal",
            "--nocapture",
            "--test-threads=1",
        ])
        .env(FIXTURE_ENV, "1");
    run_terminal_fixture(command);
}

#[test]
fn streaming_bubblewrap_cancels_without_parent_death_signal() {
    if !bwrap_available() {
        return;
    }
    use std::io::{BufRead, BufReader};
    use std::os::unix::fs::PermissionsExt;
    use std::process::Command;
    use std::time::{Duration, Instant};

    use nix::sys::prctl::set_child_subreaper;
    use nix::sys::signal::{kill, Signal};
    use nix::sys::wait::{waitpid, WaitPidFlag, WaitStatus};
    use nix::unistd::Pid;

    const FIXTURE_ENV: &str = "MXC_BWRAP_CANCELLATION_FIXTURE";
    if std::env::var_os(FIXTURE_ENV).is_some() {
        set_child_subreaper(true).expect("adopt namespace init after its monitor exits");

        struct NamespaceInit(Option<Pid>);

        impl NamespaceInit {
            fn wait_for_exit(&mut self) -> bool {
                let pid = self.0.expect("namespace init");
                let deadline = Instant::now() + Duration::from_secs(2);
                loop {
                    match waitpid(pid, Some(WaitPidFlag::WNOHANG)).expect("wait for namespace init")
                    {
                        WaitStatus::StillAlive if Instant::now() < deadline => {
                            std::thread::sleep(Duration::from_millis(10));
                        }
                        WaitStatus::StillAlive => return false,
                        WaitStatus::Exited(..) | WaitStatus::Signaled(..) => {
                            self.0 = None;
                            return true;
                        }
                        status => panic!("unexpected namespace init status: {status:?}"),
                    }
                }
            }
        }

        impl Drop for NamespaceInit {
            fn drop(&mut self) {
                if let Some(pid) = self.0 {
                    if let Err(error) = kill(pid, Signal::SIGKILL) {
                        eprintln!("namespace init cleanup signal failed: {error}");
                    }
                    if let Err(error) = waitpid(pid, None) {
                        eprintln!("namespace init cleanup wait failed: {error}");
                    }
                }
            }
        }

        for termination in ["kill", "timeout", "drop"] {
            let mut init = NamespaceInit(None);
            let timeout = if termination == "timeout" {
                1_000
            } else {
                30_000
            };
            let mut proc = spawn(
                bwrap_request("sleep 30 & echo CANCELLATION_READY; wait", timeout),
                Default::default(),
            )
            .expect("spawn cancellation fixture");
            let mut line = String::new();
            BufReader::new(proc.take_stdout().expect("fixture stdout"))
                .read_line(&mut line)
                .expect("read workload readiness");
            assert_eq!(line.trim(), "CANCELLATION_READY");

            let pid = proc.id();
            let children = std::fs::read_to_string(format!("/proc/{pid}/task/{pid}/children"))
                .expect("read monitor children");
            let children: Vec<_> = children
                .split_whitespace()
                .map(|pid| Pid::from_raw(pid.parse().expect("namespace init pid")))
                .collect();
            assert_eq!(
                children.len(),
                1,
                "expected one namespace init: {children:?}"
            );
            init.0 = Some(children[0]);

            match termination {
                "kill" => {
                    proc.kill().expect("cancel sandbox");
                    assert_ne!(proc.wait().expect("wait after kill"), WaitResult::Exited(0));
                }
                "timeout" => assert_eq!(proc.wait().expect("wait"), WaitResult::TimedOut),
                "drop" => drop(proc),
                _ => unreachable!(),
            }
            assert!(
                init.wait_for_exit(),
                "{termination}: namespace init survived without a parent-death signal"
            );
        }
        return;
    }

    let resolved = Command::new("/bin/sh")
        .args(["-c", "command -v bwrap"])
        .output()
        .expect("resolve bwrap");
    assert!(
        resolved.status.success(),
        "could not resolve the real bwrap"
    );
    let real_bwrap = std::fs::canonicalize(
        String::from_utf8(resolved.stdout)
            .expect("bwrap path is UTF-8")
            .trim(),
    )
    .expect("absolute bwrap path");
    let directory = tempfile::tempdir().expect("wrapper directory");
    let wrapper = directory.path().join("bwrap");

    // Omit parent-death cleanup to hold the startup condition without a timing race.
    std::fs::write(
        &wrapper,
        r#"#!/bin/sh
for arg in "$@"; do
    shift
    if [ "$arg" != "--die-with-parent" ]; then
        set -- "$@" "$arg"
    fi
done
exec "$MXC_TEST_REAL_BWRAP" "$@"
"#,
    )
    .expect("write bwrap wrapper");
    std::fs::set_permissions(&wrapper, std::fs::Permissions::from_mode(0o700))
        .expect("make wrapper executable");
    let path = std::env::var_os("PATH").expect("PATH");
    let path = std::env::join_paths(
        std::iter::once(directory.path().to_path_buf()).chain(std::env::split_paths(&path)),
    )
    .expect("fixture PATH");
    let mut command = Command::new(std::env::current_exe().expect("test executable"));
    command
        .args([
            "--exact",
            "streaming_bubblewrap_cancels_without_parent_death_signal",
            "--nocapture",
            "--test-threads=1",
        ])
        .env(FIXTURE_ENV, "1")
        .env("MXC_TEST_REAL_BWRAP", real_bwrap)
        .env("PATH", path);
    run_terminal_fixture(command);
}

#[test]
fn bubblewrap_pty_supports_io_resize_and_merged_output() {
    if !bwrap_available() {
        return;
    }
    unix_pty_contract::assert_round_trip(bwrap_request(
        unix_pty_contract::ROUND_TRIP_COMMAND,
        30_000,
    ));
}

#[test]
fn bubblewrap_pty_enforces_script_timeout() {
    if !bwrap_available() {
        return;
    }
    unix_pty_contract::assert_timeout(
        bwrap_request(unix_pty_contract::TIMEOUT_COMMAND, 1_000),
        std::time::Duration::from_secs(15),
    );
}

#[test]
fn bubblewrap_pty_preserves_explicit_timeout_kill() {
    if !bwrap_available() {
        return;
    }
    unix_pty_contract::assert_explicit_timeout_kill(bwrap_request(
        unix_pty_contract::TIMEOUT_COMMAND,
        30_000,
    ));
}

#[test]
fn bubblewrap_pty_transfers_native_stdio() {
    if !bwrap_available() {
        return;
    }
    unix_pty_contract::assert_native_stdio(bwrap_request(
        unix_pty_contract::NATIVE_STDIO_COMMAND,
        30_000,
    ));
}

#[test]
fn streaming_bubblewrap_wait_with_output_captures_both_streams() {
    // Each stream exceeds the 64 KiB pipe buffer, so a sequential drain would
    // deadlock. Bounded here rather than by the sandbox timeout, which does not
    // interrupt a blocked reader.
    if !bwrap_available() {
        return;
    }
    const BYTES: usize = 256 * 1024;
    let script = format!("yes a | head -c {BYTES}; yes b | head -c {BYTES} 1>&2");

    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let proc = spawn(bwrap_request(&script, 30_000), Default::default()).expect("spawn");
        let _ = tx.send(proc.wait_with_output());
    });

    let output = rx
        .recv_timeout(std::time::Duration::from_secs(60))
        .expect("deadlocked: streams are not drained concurrently")
        .expect("wait_with_output");

    assert_eq!(output.outcome, WaitResult::Exited(0));
    assert_eq!(output.stdout.len(), BYTES, "stdout fully drained");
    assert_eq!(output.stderr.len(), BYTES, "stderr fully drained");
    assert!(
        output.stdout.iter().all(|b| *b == b'a' || *b == b'\n'),
        "stdout carries its own stream"
    );
    assert!(
        output.stderr.iter().all(|b| *b == b'b' || *b == b'\n'),
        "stderr carries its own stream"
    );
}

#[test]
fn streaming_bubblewrap_stderr_is_readable_live() {
    // Pins `take_stderr` itself, which `wait_with_output` bypasses.
    if !bwrap_available() {
        return;
    }
    use std::io::Read;

    let mut proc =
        spawn(bwrap_request("echo diagnostic 1>&2", 0), Default::default()).expect("spawn");

    let mut stderr = proc.take_stderr().expect("stderr available");
    let mut err = String::new();
    stderr.read_to_string(&mut err).expect("read stderr");
    assert!(err.contains("diagnostic"), "got: {err:?}");

    assert_eq!(proc.wait().expect("wait"), WaitResult::Exited(0));
}

#[test]
fn streaming_bubblewrap_wait_reports_the_workloads_exit_code() {
    // `bwrap` sits between the SDK and the workload: pins that the workload's
    // status propagates, not bwrap's own.
    if !bwrap_available() {
        return;
    }
    for code in [0, 1, 42] {
        let mut proc = spawn(
            bwrap_request(&format!("exit {code}"), 0),
            Default::default(),
        )
        .expect("spawn");
        assert_eq!(
            proc.wait().expect("wait"),
            WaitResult::Exited(code),
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
    let mut proc = spawn(bwrap_request("sleep 30", 0), Default::default()).expect("spawn");

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
    let mut proc = spawn(bwrap_request("sleep 30", 0), Default::default()).expect("spawn");
    let pid = proc.id();

    assert!(
        proc.try_wait().expect("try_wait").is_none(),
        "child should still be running shortly after spawn"
    );

    proc.kill().expect("kill");
    assert_ne!(
        proc.wait().expect("wait after kill"),
        WaitResult::Exited(0),
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
    let mut proc = spawn(bwrap_request("sleep 30", 1000), Default::default()).expect("spawn");

    let start = std::time::Instant::now();
    assert_eq!(
        proc.wait().expect("wait yields an outcome"),
        WaitResult::TimedOut,
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
    let mut proc = spawn(bwrap_request("true", 0), Default::default()).expect("spawn");
    assert_eq!(proc.wait().expect("wait"), WaitResult::Exited(0));
    assert!(
        proc.output_metadata().is_none(),
        "Bubblewrap should report no structured output metadata"
    );
}
