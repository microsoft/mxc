// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use std::io::ErrorKind;
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::OnceLock;
use std::time::{Duration, Instant};

/// A version check returns almost instantly; anything slower than this should not block discovery.
const PROBE_TIMEOUT: Duration = Duration::from_secs(3);

const POLL_INTERVAL: Duration = Duration::from_millis(25);

#[derive(Debug, Clone, PartialEq, Eq)]
enum LxcLsOutcome {
    ExitedSuccess,
    ExitedFailure,
    NotFound,
    SpawnFailed,
    TimedOut,
}

/// What execution should conclude from probing the LXC tooling.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LxcTooling {
    Available,
    /// `lxc-ls` is absent or reports itself broken.
    Unavailable,
    /// The probe itself failed (timeout, spawn error); worth retrying.
    ProbeFailed,
}

/// Runs `lxc-ls --version`; only a clean exit counts as available.
pub fn is_lxc_available() -> bool {
    static AVAILABLE: OnceLock<bool> = OnceLock::new();
    *AVAILABLE.get_or_init(|| available_from(probe_lxc_ls()))
}

/// The tooling verdict for execution, separate from the discovery cache.
///
/// Only success is cached: a host that gains the LXC tools later, or whose
/// probe was transiently slow, is re-probed on the next run.
pub fn lxc_tooling_for_execution() -> LxcTooling {
    static CONFIRMED: AtomicBool = AtomicBool::new(false);
    if CONFIRMED.load(Ordering::Relaxed) {
        return LxcTooling::Available;
    }
    let tooling = tooling_from(probe_lxc_ls());
    if tooling == LxcTooling::Available {
        CONFIRMED.store(true, Ordering::Relaxed);
    }
    tooling
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
        Err(error) if error.kind() == ErrorKind::NotFound => LxcLsOutcome::NotFound,
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

fn tooling_from(outcome: LxcLsOutcome) -> LxcTooling {
    match outcome {
        LxcLsOutcome::ExitedSuccess => LxcTooling::Available,
        LxcLsOutcome::NotFound | LxcLsOutcome::ExitedFailure => LxcTooling::Unavailable,
        LxcLsOutcome::SpawnFailed | LxcLsOutcome::TimedOut => LxcTooling::ProbeFailed,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_a_clean_exit_means_available() {
        assert!(available_from(LxcLsOutcome::ExitedSuccess));
        assert!(!available_from(LxcLsOutcome::ExitedFailure));
        assert!(!available_from(LxcLsOutcome::NotFound));
        assert!(!available_from(LxcLsOutcome::SpawnFailed));
        assert!(!available_from(LxcLsOutcome::TimedOut));
    }

    #[test]
    fn a_missing_tool_is_unavailable_but_a_failed_probe_is_not() {
        assert_eq!(
            tooling_from(LxcLsOutcome::ExitedSuccess),
            LxcTooling::Available
        );
        assert_eq!(
            tooling_from(LxcLsOutcome::NotFound),
            LxcTooling::Unavailable
        );
        assert_eq!(
            tooling_from(LxcLsOutcome::ExitedFailure),
            LxcTooling::Unavailable
        );
        assert_eq!(
            tooling_from(LxcLsOutcome::TimedOut),
            LxcTooling::ProbeFailed
        );
        assert_eq!(
            tooling_from(LxcLsOutcome::SpawnFailed),
            LxcTooling::ProbeFailed
        );
    }
}
