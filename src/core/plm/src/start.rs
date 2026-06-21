//! Port of `start_plm_logging.ps1`.
//!
//! Cancels any in-progress WPR trace (best-effort) and starts a new
//! permissive-learning-mode trace using the `AccessFailureProfile` defined
//! in the sibling `PLM.wprp`.

use anyhow::{Context, Result};
use std::path::Path;
use std::process::Command;

/// Discard any previous in-memory trace session before starting a new one.
/// `wpr -cancel` aborts an active trace without writing the .etl, freeing
/// the kernel session. If no session is active wpr returns non-zero --
/// that's expected, so we ignore the exit code and suppress output.
pub fn stop_existing_wpr_trace() {
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
