// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! LXC host-availability probe (ports the SDK's `isLxcAvailable()`).

use std::process::{Command, Stdio};

/// Outcome of running `lxc-ls --version`.
#[derive(Debug, Clone, PartialEq, Eq)]
enum LxcLsOutcome {
    ExitedSuccess,
    ExitedFailure(Option<i32>),
    SpawnFailed,
}

/// Whether the LXC backend looks usable on this host.
///
/// Runs `lxc-ls --version`; only a clean exit counts as available. A shallow
/// check — it proves `lxc-ls` is on `PATH`, not that a container can start.
pub fn is_lxc_available() -> bool {
    available_from(probe_lxc_ls())
}

fn probe_lxc_ls() -> LxcLsOutcome {
    match Command::new("lxc-ls")
        .arg("--version")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
    {
        Ok(status) if status.success() => LxcLsOutcome::ExitedSuccess,
        Ok(status) => LxcLsOutcome::ExitedFailure(status.code()),
        Err(_) => LxcLsOutcome::SpawnFailed,
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
        assert!(!available_from(LxcLsOutcome::ExitedFailure(Some(1))));
        assert!(!available_from(LxcLsOutcome::ExitedFailure(None)));
        assert!(!available_from(LxcLsOutcome::SpawnFailed));
    }
}
