// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use std::process::{Child, Command, Stdio};
use std::sync::OnceLock;
use std::time::{Duration, Instant};

/// A version check returns almost instantly; anything slower than this should not block discovery.
const PROBE_TIMEOUT: Duration = Duration::from_secs(3);

const POLL_INTERVAL: Duration = Duration::from_millis(25);

#[derive(Debug, Clone, PartialEq, Eq)]
enum LxcLsOutcome {
    ExitedSuccess,
    ExitedFailure,
    SpawnFailed,
    TimedOut,
}

/// Runs `lxc-ls --version`; only a clean exit counts as available.
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
