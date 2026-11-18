// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Checks that SIGHUP, SIGINT and SIGTERM reach a streaming workload even when
//! the host process has them blocked, as `lxc-exec`'s cleanup watchdog does.
//! A blocked signal survives `fork` and `execve`, so unless the backend unblocks
//! them at spawn, Ctrl-C, `kill` and `timeout(1)` cannot stop the workload and
//! its `trap`s for them never run.

use std::io::Read;

use mxc_sdk::v1::{spawn, spawn_with_pty, ContainerRequest, WaitResult};
use nix::sys::signal::{SigSet, SigmaskHow, Signal};

/// The shell signals itself, so delivery happens before `kill` returns and
/// nothing races. A trap rather than the default action, because the shell may
/// be PID 1 in its namespace, where unhandled signals are discarded.
pub const COMMAND: &str = "for sig in HUP INT TERM; do \
                               trap \"echo CAUGHT_$sig\" \"$sig\"; \
                               kill -s \"$sig\" $$; \
                           done";

/// Runs [`COMMAND`] through `spawn` and `spawn_with_pty` while the calling
/// thread blocks the three signals, and asserts each trap ran in both modes.
pub fn assert_delivered_despite_host_mask(request: impl Fn() -> ContainerRequest) {
    let _blocked = BlockedSignals::new();

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

/// Blocks the three signals on the calling thread until dropped.
struct BlockedSignals(SigSet);

impl BlockedSignals {
    fn new() -> Self {
        let mut mask = SigSet::empty();
        mask.add(Signal::SIGHUP);
        mask.add(Signal::SIGINT);
        mask.add(Signal::SIGTERM);
        let mut previous = SigSet::empty();
        nix::sys::signal::pthread_sigmask(SigmaskHow::SIG_BLOCK, Some(&mask), Some(&mut previous))
            .expect("block termination signals");
        Self(previous)
    }
}

impl Drop for BlockedSignals {
    fn drop(&mut self) {
        let _ = nix::sys::signal::pthread_sigmask(SigmaskHow::SIG_SETMASK, Some(&self.0), None);
    }
}
