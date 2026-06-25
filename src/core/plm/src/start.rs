//! Port of `start_plm_logging.ps1`.
//!
//! Cancels any in-progress WPR trace (best-effort) and starts a new
//! permissive-learning-mode trace using the `AccessFailureProfile` defined
//! in the sibling `PLM.wprp`.

use anyhow::{Context, Result};
use std::path::Path;
use std::process::Command;

/// Returns true iff `wpr -status` reports a WPR session is currently
/// active. Used to scope the pre-flight cancel below to traces we
/// might actually need to cancel — round-3 review flagged the
/// unconditional `wpr -cancel` as silently terminating concurrent
/// non-PLM WPR recordings on the same host (e.g. a separately-driven
/// `wpr -start GeneralProfile` from an unrelated debugging session).
///
/// Best-effort: returns `false` on any I/O failure or missing wpr.exe.
/// The single NT Kernel Logger session that PLM wants is exclusive so
/// callers fall through to `wpr -cancel` only when one already exists.
fn wpr_session_active() -> bool {
    let output = match Command::new("wpr").arg("-status").output() {
        Ok(o) => o,
        Err(_) => return false,
    };
    // wpr exits non-zero when no session is active. The cross-platform
    // contract here is purely empirical — both Win11 24H2 and 25H2
    // ship the same status semantics — but we also defensively match
    // on the stdout text to handle locale variants.
    if !output.status.success() {
        return false;
    }
    let stdout = String::from_utf8_lossy(&output.stdout);
    // English: "WPR is not recording.". Cancel iff that line is absent.
    !stdout.contains("not recording")
}

/// Discard any previous in-memory trace session before starting a new one.
/// `wpr -cancel` aborts an active trace without writing the .etl, freeing
/// the kernel session. If no session is active wpr returns non-zero --
/// that's expected, so we ignore the exit code and suppress output.
///
/// Only one NT Kernel Logger session can exist host-wide, so if any
/// recording is in progress (PLM's previous run or an unrelated tool)
/// we have no choice but to cancel it before starting our own. The
/// `wpr -status` probe above narrows the blast radius to runs where a
/// cancel is genuinely required and emits a warning to stderr so an
/// operator running a parallel recording sees what happened.
pub fn stop_existing_wpr_trace() {
    if !wpr_session_active() {
        return;
    }
    eprintln!(
        "[plm] cancelling pre-existing WPR session via `wpr -cancel`; \
         any concurrent non-PLM WPR recording on this host has just been terminated. \
         (Only one NT Kernel Logger session can exist at a time.)"
    );
    let _ = Command::new("wpr")
        .arg("-cancel")
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status();
}

pub fn start_plm_trace(wprp_path: &Path) -> Result<()> {
    stop_existing_wpr_trace();
    let arg = format!("{}!AccessFailureProfile", wprp_path.display());
    let status = Command::new("wpr")
        .args(["-start", &arg, "-filemode"])
        .status()
        .context("failed to spawn wpr -start")?;
    if !status.success() {
        anyhow::bail!("wpr -start exited with {status}");
    }
    Ok(())
}
