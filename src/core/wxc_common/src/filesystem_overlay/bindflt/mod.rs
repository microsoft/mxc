// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! BindFlt primitive (Phase B promotion of direct `BfSetupFilter*` /
//! `CreateBindLink` API access).
//!
//! Phase A.1 ships type stubs only; the apply / restore code arrives
//! in Phase B once the `BindFltApi.dll` FFI surface lands in
//! `api.rs`.

use std::path::PathBuf;

use crate::filesystem_overlay::error::OverlayError;
use crate::filesystem_overlay::plan::OverlayPrimitive;

/// One applied BindFlt mapping (tombstone, RO overlay, RW overlay)
/// — bookkeeping for restore.
#[derive(Debug, Clone)]
pub struct BindFltApplied {
    /// The original primitive this entry resulted from.
    pub primitive: OverlayPrimitive,
    /// The virtual path used as the mapping handle for `BfRemoveMapping`.
    pub virt_path: PathBuf,
}

/// Apply one BindFlt-shaped [`OverlayPrimitive`] entry. Phase A.1
/// skeleton — returns `PrimitiveUnavailable` until Phase B lands the
/// real implementation.
pub fn apply_mapping(
    primitive: &OverlayPrimitive,
    _ac_sid: &str,
) -> Result<BindFltApplied, OverlayError> {
    let _ = primitive;
    Err(OverlayError::PrimitiveUnavailable {
        primitive: "bindflt",
        reason: "Phase B direct-API integration with BindFltApi.dll is pending".into(),
    })
}

/// Restore one BindFlt mapping (`BfRemoveMapping*`). Phase A.1
/// skeleton.
pub fn restore_mapping(_applied: &BindFltApplied) -> Result<(), OverlayError> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn apply_returns_unavailable_in_phase_a1() {
        let p = OverlayPrimitive::BindFltTombstone {
            path: PathBuf::from(r"C:\fake"),
        };
        let err = apply_mapping(&p, "S-1-15-2-test").expect_err("Phase A.1 stub should fail");
        match err {
            OverlayError::PrimitiveUnavailable { primitive, .. } => {
                assert_eq!(primitive, "bindflt");
            }
            other => panic!("expected PrimitiveUnavailable, got {other:?}"),
        }
    }
}
