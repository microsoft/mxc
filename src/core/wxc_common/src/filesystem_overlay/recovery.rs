// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Orphan-state recovery for the overlay enforcer.
//!
//! Peer of [`crate::filesystem_dacl::recover_orphaned_state`]. Runs
//! at `wxc-exec` startup, scans
//! `%LOCALAPPDATA%\Microsoft\MXC\overlay-state\*.json`, and reaps
//! state files whose owning process has exited (by PID + start
//! FILETIME match). Each reaped file's primitives are restored in
//! reverse application order via [`crate::filesystem_overlay::projfs::restore_branch`]
//! and [`crate::filesystem_overlay::bindflt::restore_mapping`].
//!
//! Phase A.1 ships a no-op stub. The real recovery flow lands when
//! state-file persistence lands (Phase A.3 + Phase B).

use crate::filesystem_overlay::error::OverlayError;

/// Aggregated outcome of [`recover_orphaned_state`].
#[derive(Debug, Default)]
pub struct RecoveryReport {
    /// Number of state files inspected (`*.json` under the state dir).
    pub files_processed: usize,
    /// Total primitives successfully restored across all orphan files.
    pub primitives_restored: usize,
    /// Per-file or per-primitive errors, formatted for logging.
    pub errors: Vec<String>,
}

/// Inspect the overlay state directory and reap entries owned by
/// dead processes. Idempotent; safe to call concurrently with live
/// `OverlayManager` instances (per-path serialization defends them).
///
/// Phase A.1 stub returns an empty report.
pub fn recover_orphaned_state() -> Result<RecoveryReport, OverlayError> {
    Ok(RecoveryReport::default())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn phase_a1_stub_returns_empty_report() {
        let r = recover_orphaned_state().expect("stub should succeed");
        assert_eq!(r.files_processed, 0);
        assert_eq!(r.primitives_restored, 0);
        assert!(r.errors.is_empty());
    }
}
