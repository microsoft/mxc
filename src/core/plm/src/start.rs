//! Port of `start_plm_logging.ps1`.
//!
//! Starts a new permissive-learning-mode trace using the
//! `AccessFailureProfile` defined in the sibling `PLM.wprp`. If a
//! pre-existing WPR session blocks our start, we cancel it and retry
//! exactly once.

use anyhow::{Context, Result};
use std::path::Path;
use std::process::{ExitStatus, Stdio};

use crate::wpr_path::wpr_command;

/// Abstraction over wpr.exe invocations so the retry-on-conflict
/// state machine in `start_plm_trace_with` is testable without
/// actually spawning processes. The production impl is `WprExe`; tests
/// supply a fake that returns canned exit codes (R5-7).
pub trait WprLauncher {
    fn start(&mut self, profile_arg: &str) -> Result<ExitStatus>;
    fn cancel(&mut self);
}

pub struct WprExe;

impl WprLauncher for WprExe {
    fn start(&mut self, profile_arg: &str) -> Result<ExitStatus> {
        wpr_command()
            .args(["-start", profile_arg, "-filemode"])
            .status()
            .context("failed to spawn wpr -start")
    }
    fn cancel(&mut self) {
        cancel_existing_wpr_trace();
    }
}

/// Discard any previous in-memory trace session before starting a new one.
/// `wpr -cancel` aborts an active trace without writing the .etl, freeing
/// the kernel session. If no session is active wpr returns non-zero --
/// that's expected, so we ignore the exit code and suppress output.
///
/// Only one NT Kernel Logger session can exist host-wide, so when this
/// runs we are necessarily terminating an existing recording (PLM's
/// previous run or an unrelated tool). We emit a warning to stderr so
/// an operator running a parallel recording sees what happened. Round-3
/// added a `wpr -status` probe gating this call; round-4 removed it
/// because the English-only stdout match defeated the scope narrowing
/// on every localized Windows install. We now invoke cancel only on
/// the retry path after `wpr -start` itself reports a conflict, which
/// is locale-invariant by construction.
pub fn cancel_existing_wpr_trace() {
    eprintln!(
        "[plm] cancelling pre-existing WPR session via `wpr -cancel`; \
         any concurrent non-PLM WPR recording on this host has just been terminated. \
         (Only one NT Kernel Logger session can exist at a time.)"
    );
    let _ = wpr_command()
        .arg("-cancel")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status();
}

/// Core try-then-cancel-then-retry state machine, parameterised on a
/// `WprLauncher` so tests can drive the conflict + retry branches
/// deterministically.
pub fn start_plm_trace_with<L: WprLauncher>(launcher: &mut L, wprp_path: &Path) -> Result<()> {
    let arg = format!("{}!AccessFailureProfile", wprp_path.display());
    let first = launcher.start(&arg)?;
    if first.success() {
        return Ok(());
    }
    launcher.cancel();
    let second = launcher.start(&arg)?;
    if !second.success() {
        anyhow::bail!(
            "wpr -start exited with {second} (also failed after retry following wpr -cancel)"
        );
    }
    Ok(())
}

pub fn start_plm_trace(wprp_path: &Path) -> Result<()> {
    start_plm_trace_with(&mut WprExe, wprp_path)
}

/// Back-compat shim: external callers (and tests) used to call
/// `stop_existing_wpr_trace` to clear any session prior to start. The
/// `start` path now handles that automatically, but the standalone
/// `cancel` is still useful from cleanup handlers (Ctrl-C, panic
/// guard). Re-export it under the legacy name as well.
pub use cancel_existing_wpr_trace as stop_existing_wpr_trace;

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::windows::process::ExitStatusExt;
    use std::path::PathBuf;

    struct FakeLauncher {
        starts: Vec<ExitStatus>,
        idx: usize,
        cancels: usize,
    }
    impl FakeLauncher {
        fn new(codes: &[u32]) -> Self {
            Self {
                starts: codes.iter().map(|c| ExitStatus::from_raw(*c)).collect(),
                idx: 0,
                cancels: 0,
            }
        }
    }
    impl WprLauncher for FakeLauncher {
        fn start(&mut self, _arg: &str) -> Result<ExitStatus> {
            let s = self.starts[self.idx];
            self.idx += 1;
            Ok(s)
        }
        fn cancel(&mut self) {
            self.cancels += 1;
        }
    }

    #[test]
    fn start_plm_trace_first_attempt_success_does_not_cancel() {
        let mut f = FakeLauncher::new(&[0]);
        start_plm_trace_with(&mut f, &PathBuf::from("plm.wprp")).unwrap();
        assert_eq!(f.idx, 1);
        assert_eq!(f.cancels, 0);
    }

    #[test]
    fn start_plm_trace_retries_once_after_conflict() {
        // First attempt fails (non-zero), cancel runs, second succeeds.
        let mut f = FakeLauncher::new(&[1, 0]);
        start_plm_trace_with(&mut f, &PathBuf::from("plm.wprp")).unwrap();
        assert_eq!(f.idx, 2);
        assert_eq!(f.cancels, 1);
    }

    #[test]
    fn start_plm_trace_propagates_when_retry_also_fails() {
        let mut f = FakeLauncher::new(&[1, 1]);
        let err = start_plm_trace_with(&mut f, &PathBuf::from("plm.wprp")).unwrap_err();
        assert!(format!("{err}").contains("failed after retry"));
        assert_eq!(f.idx, 2);
        assert_eq!(f.cancels, 1);
    }
}
