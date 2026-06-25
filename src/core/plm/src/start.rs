//! Port of `start_plm_logging.ps1`.
//!
//! Starts a new permissive-learning-mode trace using the
//! `AccessFailureProfile` defined in the sibling `PLM.wprp`. If a
//! pre-existing WPR session blocks our start, we cancel it and retry
//! exactly once.

use anyhow::{Context, Result};
use std::path::Path;
use std::process::Stdio;

use crate::wpr_path::wpr_command;

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

/// Invoke `wpr -start <profile> -filemode` once.
fn try_start(wprp_arg: &str) -> Result<std::process::ExitStatus> {
    wpr_command()
        .args(["-start", wprp_arg, "-filemode"])
        .status()
        .context("failed to spawn wpr -start")
}

pub fn start_plm_trace(wprp_path: &Path) -> Result<()> {
    let arg = format!("{}!AccessFailureProfile", wprp_path.display());
    // First attempt: try to start without disturbing any pre-existing
    // session. wpr returns non-zero (locale-invariant) when a
    // conflicting session is already active.
    let first = try_start(&arg)?;
    if first.success() {
        return Ok(());
    }
    // Conflict (or other failure): cancel whatever's running and
    // retry exactly once. If the retry also fails we propagate.
    cancel_existing_wpr_trace();
    let second = try_start(&arg)?;
    if !second.success() {
        anyhow::bail!(
            "wpr -start exited with {second} (also failed after retry following wpr -cancel)"
        );
    }
    Ok(())
}

/// Back-compat shim: external callers (and tests) used to call
/// `stop_existing_wpr_trace` to clear any session prior to start. The
/// `start` path now handles that automatically, but the standalone
/// `cancel` is still useful from cleanup handlers (Ctrl-C, panic
/// guard). Re-export it under the legacy name as well.
pub use cancel_existing_wpr_trace as stop_existing_wpr_trace;
