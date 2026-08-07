// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! LXC host-availability probe (ports the SDK's `isLxcAvailable()`).

use std::process::{Child, Command, Stdio};
use std::sync::OnceLock;
use std::time::{Duration, Instant};

/// Upper bound on the `lxc-ls --version` probe. A version check returns almost
/// instantly; anything slower is treated as unavailable rather than allowed to
/// block discovery.
const PROBE_TIMEOUT: Duration = Duration::from_secs(3);

/// How often to poll the child while waiting for it to exit.
const POLL_INTERVAL: Duration = Duration::from_millis(25);

/// Outcome of running `lxc-ls --version`. Only `ExitedSuccess` means available;
/// the other variants are distinct for clarity but map to unavailable. The exit
/// code isn't retained — nothing reads it, and keeping it would be dead code.
#[derive(Debug, Clone, PartialEq, Eq)]
enum LxcLsOutcome {
    ExitedSuccess,
    ExitedFailure,
    SpawnFailed,
    TimedOut,
}

/// Whether the LXC backend looks usable on this host.
///
/// Runs `lxc-ls --version`; only a clean exit counts as available. A shallow
/// check — it proves `lxc-ls` is on `PATH`, not that a container can start.
/// Probed once and cached for the process lifetime.
pub fn is_lxc_available() -> bool {
    static AVAILABLE: OnceLock<bool> = OnceLock::new();
    *AVAILABLE.get_or_init(|| available_from(probe_lxc_ls()))
}

fn probe_lxc_ls() -> LxcLsOutcome {
    let child = Command::new("lxc-ls")
        .arg("--version")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn();
    match child {
        Ok(mut child) => wait_bounded(&mut child, PROBE_TIMEOUT),
        Err(_) => LxcLsOutcome::SpawnFailed,
    }
}

/// Wait up to `timeout` for `child`; if it overruns, kill and reap it so a hung
/// `lxc-ls` can't block the probe (or leak a zombie) indefinitely.
fn wait_bounded(child: &mut Child, timeout: Duration) -> LxcLsOutcome {
    let deadline = Instant::now() + timeout;
    loop {
        match child.try_wait() {
            Ok(Some(status)) if status.success() => return LxcLsOutcome::ExitedSuccess,
            Ok(Some(_)) => return LxcLsOutcome::ExitedFailure,
            Ok(None) => {
                if Instant::now() >= deadline {
                    let _ = child.kill();
                    let _ = child.wait();
                    return LxcLsOutcome::TimedOut;
                }
                std::thread::sleep(POLL_INTERVAL);
            }
            Err(_) => return LxcLsOutcome::SpawnFailed,
        }
    }
}

/// Split from the I/O half so the decision is testable without an `lxc-ls`
/// binary on the host.
fn available_from(outcome: LxcLsOutcome) -> bool {
    matches!(outcome, LxcLsOutcome::ExitedSuccess)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_a_clean_exit_means_available() {
        assert!(available_from(LxcLsOutcome::ExitedSuccess));
        assert!(!available_from(LxcLsOutcome::ExitedFailure));
        assert!(!available_from(LxcLsOutcome::SpawnFailed));
        assert!(!available_from(LxcLsOutcome::TimedOut));
    }
}
