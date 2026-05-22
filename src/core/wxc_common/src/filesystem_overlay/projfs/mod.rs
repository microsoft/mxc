// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! ProjFS primitive (Phase A.2+ promotion of `wxc_projfs_probe::virt`).
//!
//! Phase A.1 ships type stubs only; the apply / restore code arrives
//! in Phase A.2 along with promotion of the spike's callbacks.

use std::path::PathBuf;

use crate::filesystem_overlay::error::OverlayError;
use crate::filesystem_overlay::plan::OverlayPrimitive;

/// One applied ProjFS branch — bookkeeping for restore.
#[derive(Debug, Clone)]
pub struct ProjFsApplied {
    /// The original primitive this entry resulted from.
    pub primitive: OverlayPrimitive,
    /// Projection root path created for this run (for cleanup).
    pub projection_root: PathBuf,
}

/// Apply one [`OverlayPrimitive::ProjFsBranch`] entry. Phase A.1
/// skeleton — returns `PrimitiveUnavailable` until Phase A.2 lands
/// the real implementation.
pub fn apply_branch(
    primitive: &OverlayPrimitive,
    _ac_sid: &str,
) -> Result<ProjFsApplied, OverlayError> {
    let _ = primitive;
    Err(OverlayError::PrimitiveUnavailable {
        primitive: "projfs",
        reason: "Phase A.2 promotion of wxc_projfs_probe::virt is pending".into(),
    })
}

/// Restore (stop virtualization + clean projection root). Phase A.1
/// skeleton.
pub fn restore_branch(_applied: &ProjFsApplied) -> Result<(), OverlayError> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::filesystem_overlay::plan::BranchMode;

    #[test]
    fn apply_returns_unavailable_in_phase_a1() {
        let p = OverlayPrimitive::ProjFsBranch {
            host_path: PathBuf::from(r"C:\fake"),
            branch_name: "fake".into(),
            mode: BranchMode::ReadOnly,
        };
        let err = apply_branch(&p, "S-1-15-2-test").expect_err("Phase A.1 stub should fail");
        match err {
            OverlayError::PrimitiveUnavailable { primitive, .. } => {
                assert_eq!(primitive, "projfs");
            }
            other => panic!("expected PrimitiveUnavailable, got {other:?}"),
        }
    }
}
