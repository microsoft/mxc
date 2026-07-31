// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! LXC host-availability probe.
//!
//! Ports the TypeScript SDK's `isLxcAvailable()` into Rust so backend detection
//! lives in one place (see `docs/backend-support-probe-api-plan.md`). The check
//! is deliberately shallow — a clean `lxc-ls --version` exit — matching the
//! SDK's historical behavior: it proves the `lxc-ls` CLI is on `PATH` and
//! runnable, not that liblxc is loadable or that the caller has the privileges
//! to actually start a container.
//!
//! The interpretation half is pure (no I/O), so it is unit-tested directly;
//! only [`probe_lxc_ls`] shells out.

use std::process::{Command, Stdio};

/// Outcome of running `lxc-ls --version`.
#[derive(Debug, Clone, PartialEq, Eq)]
enum LxcLsOutcome {
    /// The process ran and exited successfully (status 0).
    ExitedSuccess,
    /// The process ran but exited non-zero.
    ExitedFailure(Option<i32>),
    /// The process could not be spawned (e.g. `lxc-ls` is not on `PATH`).
    SpawnFailed,
}

/// Whether the LXC backend looks usable on this host.
///
/// Runs `lxc-ls --version`; a clean exit is treated as "available". Mirrors the
/// SDK's `isLxcAvailable()` and returns `false` on any spawn failure or
/// non-zero exit.
pub fn is_lxc_available() -> bool {
    available_from(probe_lxc_ls())
}

/// Run `lxc-ls --version`, discarding its output and classifying the result.
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

/// Map a probe outcome to availability. Split from [`probe_lxc_ls`] so the
/// decision is testable without an `lxc-ls` binary on the host.
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
