// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! The signals that ask a process to stop, and keeping them deliverable in
//! sandboxed children.
//!
//! `lxc-exec`'s cleanup watchdog blocks these so that only it receives them,
//! and a library host may block them for its own reasons. A blocked signal
//! stays blocked across `fork` and `execve`, so every spawn of a workload, or
//! of a helper that relies on these signals, must unblock them.

use nix::sys::signal::{sigaction, SaFlags, SigAction, SigHandler, SigSet, Signal};

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
///
/// Until it execs, the child still has the host's handlers, which must not run
/// there, so caught signals are first reset to their default action, as
/// `execve` would. Ignored signals stay ignored, as they do across `execve`.
pub fn unblock_in_child(command: &mut std::process::Command) {
    use std::os::unix::process::CommandExt;

    // SAFETY: `pre_exec` runs between fork and exec, where only
    // async-signal-safe work is permitted. `sigaction` and `pthread_sigmask`
    // (which nix's `thread_unblock` wraps) are async-signal-safe, building the
    // sets is plain `sigemptyset`/`sigaddset` on stack values, and this
    // closure allocates nothing and captures nothing.
    unsafe {
        command.pre_exec(|| {
            for signal in TERMINATION_SIGNALS {
                reset_caught_handler(*signal)?;
            }
            mask().thread_unblock().map_err(std::io::Error::from)
        });
    }
}

/// Reset `signal` to its default action unless it is ignored.
///
/// Must run while `signal` is blocked: one arriving between the two
/// `sigaction` calls then stays pending until an ignored disposition is
/// restored, which discards it as it would have been anyway.
fn reset_caught_handler(signal: Signal) -> std::io::Result<()> {
    let default = SigAction::new(SigHandler::SigDfl, SaFlags::empty(), SigSet::empty());
    // SAFETY: neither disposition installed here is a handler function, so no
    // code can run on this signal's behalf.
    let previous = unsafe { sigaction(signal, &default) }?;
    if previous.handler() == SigHandler::SigIgn {
        // SAFETY: as above; this restores `SIG_IGN`.
        unsafe { sigaction(signal, &previous) }?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::process::{CommandExt, ExitStatusExt};
    use std::process::Command;

    const HOST_HANDLER_RAN: i32 = 42;

    extern "C" fn host_handler(_: nix::libc::c_int) {
        // SAFETY: `_exit` is async-signal-safe.
        unsafe { nix::libc::_exit(HOST_HANDLER_RAN) }
    }

    /// Puts the child in the state a host leaves it in at fork: the signals
    /// blocked, a caught handler on SIGTERM and SIGINT, SIGHUP ignored. Then,
    /// if `raise_term`, a SIGTERM arrives before [`unblock_in_child`]'s hook.
    fn host_state(command: &mut Command, raise_term: bool) {
        // SAFETY: only `pthread_sigmask`, `sigaction` and `raise` run in the
        // child, all async-signal-safe, and the closure allocates nothing.
        unsafe {
            command.pre_exec(move || {
                mask().thread_block()?;
                let caught = SigAction::new(
                    SigHandler::Handler(host_handler),
                    SaFlags::empty(),
                    SigSet::empty(),
                );
                let ignored = SigAction::new(SigHandler::SigIgn, SaFlags::empty(), SigSet::empty());
                sigaction(Signal::SIGTERM, &caught)?;
                sigaction(Signal::SIGINT, &caught)?;
                sigaction(Signal::SIGHUP, &ignored)?;
                if raise_term {
                    nix::sys::signal::raise(Signal::SIGTERM)?;
                }
                Ok(())
            });
        }
        unblock_in_child(command);
    }

    #[test]
    fn a_signal_arriving_before_exec_takes_its_default_action() {
        let mut command = Command::new("true");
        host_state(&mut command, true);
        let status = command.status().expect("spawn");
        assert_eq!(
            status.signal(),
            Some(Signal::SIGTERM as i32),
            "expected the child to die of SIGTERM before exec, not run the host's handler: {status}"
        );
    }

    #[test]
    fn the_child_execs_with_the_signals_unblocked_and_ignored_ones_kept() {
        let mut command = Command::new("cat");
        command.arg("/proc/self/status");
        host_state(&mut command, false);
        let output = command.output().expect("spawn");
        assert!(output.status.success(), "{}", output.status);
        let status = String::from_utf8(output.stdout).expect("utf-8");
        let field = |name: &str| {
            let hex = status
                .lines()
                .find_map(|line| line.strip_prefix(name))
                .unwrap_or_else(|| panic!("{name} missing from:\n{status}"));
            u64::from_str_radix(hex.trim(), 16).expect("hex signal set")
        };
        let bit = |signal: Signal| 1u64 << (signal as u32 - 1);
        let (blocked, ignored) = (field("SigBlk:"), field("SigIgn:"));
        for signal in TERMINATION_SIGNALS {
            assert_eq!(blocked & bit(*signal), 0, "{signal} still blocked");
        }
        assert_ne!(ignored & bit(Signal::SIGHUP), 0, "SIGHUP no longer ignored");
        assert_eq!(ignored & bit(Signal::SIGINT), 0, "SIGINT became ignored");
        assert_eq!(ignored & bit(Signal::SIGTERM), 0, "SIGTERM became ignored");
    }
}
