// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! The signals that ask a process to stop, and keeping them deliverable in
//! sandboxed children.
//!
//! `lxc-exec`'s cleanup watchdog blocks these so that only it receives them,
//! and a library host may block them for its own reasons. A blocked signal
//! stays blocked across `fork` and `execve`, so every spawn of a workload, or
//! of a helper that relies on these signals, must unblock them.

use nix::sys::signal::{SigSet, Signal};

/// SIGHUP, SIGTERM and SIGINT.
pub const TERMINATION_SIGNALS: &[Signal] = &[Signal::SIGHUP, Signal::SIGTERM, Signal::SIGINT];

/// [`TERMINATION_SIGNALS`] as a signal set.
pub fn mask() -> SigSet {
    let mut mask = SigSet::empty();
    for signal in TERMINATION_SIGNALS {
        mask.add(*signal);
    }
    mask
}

/// Unblock [`TERMINATION_SIGNALS`] in `command`'s child before it execs.
///
/// Left blocked, the child and everything it spawns would keep these signals
/// pending forever: Ctrl-C, `kill` and `timeout(1)` would not stop it, and its
/// `trap`s for them would never run.
pub fn unblock_in_child(command: &mut std::process::Command) {
    use std::os::unix::process::CommandExt;

    // SAFETY: `pre_exec` runs between fork and exec, where only
    // async-signal-safe work is permitted. Building the set is plain
    // `sigemptyset`/`sigaddset` on a stack value, `pthread_sigmask` (which
    // nix's `thread_unblock` wraps) is async-signal-safe, and this closure
    // allocates nothing and captures nothing.
    unsafe {
        command.pre_exec(|| mask().thread_unblock().map_err(std::io::Error::from));
    }
}
