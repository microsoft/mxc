// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Checks that SIGHUP, SIGINT and SIGTERM reach a streaming workload even when
//! the host process has them blocked, as `lxc-exec`'s cleanup watchdog does.
//! A blocked signal survives `fork` and `execve`, so unless the backend unblocks
//! them at spawn, Ctrl-C, `kill` and `timeout(1)` cannot stop the workload and
//! its `trap`s for them never run.

use std::io::Read;
use std::os::unix::process::CommandExt;
use std::process::Command;

use mxc_sdk::v1::{spawn, spawn_with_pty, ContainerRequest, WaitResult};
use nix::sys::signal::{SigSet, SigmaskHow, Signal};

/// The shell signals itself, so delivery happens before `kill` returns and
/// nothing races. A trap rather than the default action, because the shell may
/// be PID 1 in its namespace, where unhandled signals are discarded.
pub const COMMAND: &str = "for sig in HUP INT TERM; do \
                               trap \"echo CAUGHT_$sig\" \"$sig\"; \
                               kill -s \"$sig\" $$; \
                           done";

const FIXTURE_ENV: &str = "MXC_TERMINATION_SIGNALS_FIXTURE";
const FIXTURE_DONE: &str = "TERMINATION_SIGNALS_FIXTURE_DONE";

/// Runs [`COMMAND`] through `spawn` and `spawn_with_pty` in a process whose
/// every thread blocks the three signals, and asserts each trap ran.
///
/// Backends may spawn from a long-lived thread rather than the caller's, so
/// blocking only the test thread would not reliably reach the spawn. Instead
/// `test_name` re-runs as a child process started with the signals blocked,
/// which every thread it creates inherits, as with `lxc-exec`'s watchdog.
///
/// Returns `true` in the child, which ran the workloads, so the caller can
/// check their cleanup there; a failure in the child fails the parent too. The
/// parent gets `false`.
pub fn assert_delivered_despite_host_mask(
    test_name: &str,
    request: impl Fn() -> ContainerRequest,
) -> bool {
    if std::env::var_os(FIXTURE_ENV).is_some() {
        let current = SigSet::thread_get_mask().expect("read signal mask");
        for signal in [Signal::SIGHUP, Signal::SIGINT, Signal::SIGTERM] {
            assert!(
                current.contains(signal),
                "fixture must start with {signal} blocked"
            );
        }
        assert_delivered(request);
        println!("{FIXTURE_DONE}");
        return true;
    }

    let mut command = Command::new(std::env::current_exe().expect("test executable"));
    command
        .args(["--exact", test_name, "--nocapture"])
        .env(FIXTURE_ENV, "1");
    // SAFETY: `pthread_sigmask` is async-signal-safe, and the closure builds
    // its set on the stack and allocates nothing.
    unsafe {
        command.pre_exec(|| {
            let mut mask = SigSet::empty();
            mask.add(Signal::SIGHUP);
            mask.add(Signal::SIGINT);
            mask.add(Signal::SIGTERM);
            nix::sys::signal::pthread_sigmask(SigmaskHow::SIG_BLOCK, Some(&mask), None)
                .map_err(std::io::Error::from)
        });
    }
    let output = command.output().expect("run signal fixture");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        output.status.success() && stdout.contains(FIXTURE_DONE),
        "signal fixture failed ({}):\n{stdout}\n{}",
        output.status,
        String::from_utf8_lossy(&output.stderr)
    );
    false
}

fn assert_delivered(request: impl Fn() -> ContainerRequest) {
    let output = spawn(request(), Default::default())
        .expect("spawn")
        .wait_with_output()
        .expect("wait_with_output");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert_eq!(
        output.outcome,
        WaitResult::Exited(0),
        "pipes: stdout: {stdout}\nstderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_caught("pipes", &stdout);

    let terminal = spawn_with_pty(request(), Default::default()).expect("spawn_with_pty");
    let mut reader = terminal.try_clone_reader().expect("PTY reader");
    let reader_thread = std::thread::spawn(move || {
        let mut output = String::new();
        reader.read_to_string(&mut output).expect("read PTY output");
        output
    });
    let outcome = terminal.wait().expect("wait");
    let output = reader_thread.join().expect("PTY reader thread");
    assert_eq!(outcome, WaitResult::Exited(0), "pty: output: {output}");
    assert_caught("pty", &output);
}

fn assert_caught(mode: &str, output: &str) {
    for sig in ["HUP", "INT", "TERM"] {
        assert!(
            output
                .lines()
                .any(|line| line.trim_end() == format!("CAUGHT_{sig}")),
            "{mode}: SIG{sig} sent to the workload never reached its trap. Output:\n{output}"
        );
    }
}
