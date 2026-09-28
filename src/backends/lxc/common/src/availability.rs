// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use std::process::{Child, Command, Stdio};
use std::sync::OnceLock;
use std::time::{Duration, Instant};

/// Total caller-visible budget for the LXC availability probe.
pub const LXC_AVAILABILITY_TIMEOUT: Duration = Duration::from_secs(3);

const LXC_COMMAND_TIMEOUT: Duration = Duration::from_millis(2_750);
const LXC_REAP_TIMEOUT: Duration = Duration::from_millis(250);

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
        Ok(mut child) => wait_bounded(&mut child),
        Err(_) => LxcLsOutcome::SpawnFailed,
    }
}

fn wait_bounded(child: &mut Child) -> LxcLsOutcome {
    wait_bounded_with_deadlines(child, LXC_COMMAND_TIMEOUT, LXC_AVAILABILITY_TIMEOUT)
}

fn wait_bounded_with_deadlines(
    child: &mut Child,
    command_timeout: Duration,
    total_timeout: Duration,
) -> LxcLsOutcome {
    let started = Instant::now();
    let command_deadline = started + command_timeout;
    let total_deadline = started + total_timeout;
    loop {
        match child.try_wait() {
            Ok(Some(status)) if status.success() => return LxcLsOutcome::ExitedSuccess,
            Ok(Some(_)) => return LxcLsOutcome::ExitedFailure,
            Ok(None) => {
                if Instant::now() >= command_deadline {
                    let _ = child.kill();
                    break;
                }
                std::thread::sleep(POLL_INTERVAL);
            }
            Err(_) => return LxcLsOutcome::SpawnFailed,
        }
    }

    let reap_deadline = (Instant::now() + LXC_REAP_TIMEOUT).min(total_deadline);
    while Instant::now() < reap_deadline {
        match child.try_wait() {
            Ok(Some(_)) => return LxcLsOutcome::TimedOut,
            Ok(None) => std::thread::sleep(
                POLL_INTERVAL.min(reap_deadline.saturating_duration_since(Instant::now())),
            ),
            Err(_) => return LxcLsOutcome::TimedOut,
        }
    }
    LxcLsOutcome::TimedOut
}

fn available_from(outcome: LxcLsOutcome) -> bool {
    matches!(outcome, LxcLsOutcome::ExitedSuccess)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::process::Stdio;

    #[test]
    fn only_a_clean_exit_means_available() {
        assert!(available_from(LxcLsOutcome::ExitedSuccess));
        assert!(!available_from(LxcLsOutcome::ExitedFailure));
        assert!(!available_from(LxcLsOutcome::SpawnFailed));
        assert!(!available_from(LxcLsOutcome::TimedOut));
    }

    #[test]
    fn timeout_terminates_and_reaps_the_real_subprocess_within_the_total_budget() {
        let mut child = Command::new("sh")
            .args(["-c", "sleep 30"])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("test shell starts");
        let started = Instant::now();

        assert_eq!(
            wait_bounded_with_deadlines(
                &mut child,
                Duration::from_millis(40),
                Duration::from_millis(290),
            ),
            LxcLsOutcome::TimedOut
        );
        assert!(
            started.elapsed() < Duration::from_secs(1),
            "bounded timeout took {:?}",
            started.elapsed()
        );
        assert!(
            child
                .try_wait()
                .expect("reap status remains queryable")
                .is_some(),
            "timed-out child must already be reaped"
        );
    }
}
