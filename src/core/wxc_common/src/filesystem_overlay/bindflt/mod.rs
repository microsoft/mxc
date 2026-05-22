// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! BindFlt primitive (Phase B).
//!
//! Wraps `bindfltapi.dll`'s `CreateBindLink` / `RemoveBindLink` into
//! the `OverlayPrimitive`-shaped apply / restore entry points the
//! `OverlayManager` calls.
//!
//! Phase B-1 supports `BindFltRoOverlay` and `BindFltRwOverlay`. The
//! public `bindlink.h` API has no direct "tombstone" primitive —
//! `BindFltTombstone` returns `PrimitiveUnavailable` until a Phase
//! B-2 follow-on adds the right shape (likely a no-target binding or
//! a small WCIFS interaction). The decision tree in
//! `policy::classify` already gates BindFlt usage so callers will
//! see a clear error before any partial state lands.

pub mod api;
pub mod feature_detect;
pub mod mapping;

use std::path::PathBuf;

use crate::filesystem_overlay::error::OverlayError;
use crate::filesystem_overlay::plan::OverlayPrimitive;

/// Bookkeeping for one applied BindFlt mapping.
#[derive(Debug, Clone)]
pub struct BindFltApplied {
    /// The plan primitive this entry came from.
    pub primitive: OverlayPrimitive,
    /// Virt path used as the handle for [`mapping::restore`].
    pub virt_path: PathBuf,
}

/// Apply one BindFlt-shaped [`OverlayPrimitive`]. Dispatches by
/// variant. `ac_sid` is currently unused — the public
/// `CreateBindLink` API has no per-SID scoping (the per-SID
/// `BfSetupFilterEx` variant exists internally but is a follow-on).
///
/// In production the AC inherits the mapping naturally because
/// BindFlt mappings are silo / job-scoped at the kernel layer; the
/// AC's job already lives under the orchestrator's job tree.
pub fn apply_mapping(
    primitive: &OverlayPrimitive,
    ac_sid: &str,
) -> Result<BindFltApplied, OverlayError> {
    let _ = ac_sid;
    match primitive {
        OverlayPrimitive::BindFltRoOverlay {
            virt_path,
            target_path,
        } => {
            mapping::apply_ro_overlay(virt_path, target_path)?;
            Ok(BindFltApplied {
                primitive: primitive.clone(),
                virt_path: virt_path.clone(),
            })
        }
        OverlayPrimitive::BindFltRwOverlay {
            virt_path,
            target_path,
            scratch,
        } => {
            // `scratch` (write-isolation = "private") is not yet
            // honored by the public CreateBindLink path. Phase D
            // will route this case to the internal
            // `BfSetupFilterBatched` API with a different target.
            // For now `private` mode degrades to passthrough RW
            // with a logged warning.
            if scratch.is_some() {
                eprintln!(
                    "BindFlt: writeIsolation=private not yet implemented; \
                     falling back to passthrough RW for {}",
                    virt_path.display()
                );
            }
            mapping::apply_rw_overlay(virt_path, target_path)?;
            Ok(BindFltApplied {
                primitive: primitive.clone(),
                virt_path: virt_path.clone(),
            })
        }
        OverlayPrimitive::BindFltTombstone { path } => Err(OverlayError::PrimitiveUnavailable {
            primitive: "bindflt",
            reason: format!(
                "tombstone for {} not supported via the public CreateBindLink API; \
                 Phase B-2 follow-on (likely BfSetupFilterEx with EMPTY_VIRT_ROOT)",
                path.display()
            ),
        }),
        OverlayPrimitive::ProjFsBranch { .. } => Err(OverlayError::PrimitiveUnavailable {
            primitive: "bindflt",
            reason:
                "received a ProjFsBranch primitive; caller should route via projfs::apply_branches"
                    .to_string(),
        }),
    }
}

/// Remove a previously-applied BindFlt mapping. Idempotent.
pub fn restore_mapping(applied: &BindFltApplied) -> Result<(), OverlayError> {
    mapping::restore(&applied.virt_path)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::filesystem_overlay::plan::BranchMode;

    #[test]
    fn tombstone_returns_unavailable_with_clear_reason() {
        let p = OverlayPrimitive::BindFltTombstone {
            path: PathBuf::from(r"C:\fake"),
        };
        let err = apply_mapping(&p, "S-1-15-2-test").expect_err("tombstone not supported");
        match err {
            OverlayError::PrimitiveUnavailable { primitive, reason } => {
                assert_eq!(primitive, "bindflt");
                assert!(
                    reason.contains("tombstone") && reason.contains(r"C:\fake"),
                    "got: {reason}"
                );
            }
            other => panic!("expected PrimitiveUnavailable, got {other:?}"),
        }
    }

    #[test]
    fn projfs_primitive_routed_to_bindflt_returns_unavailable() {
        let p = OverlayPrimitive::ProjFsBranch {
            host_path: PathBuf::from(r"C:\fake"),
            branch_name: "fake".into(),
            mode: BranchMode::ReadOnly,
            deny_subpaths: Vec::new(),
        };
        let err = apply_mapping(&p, "S-1-15-2-test").expect_err("misrouted primitive");
        match err {
            OverlayError::PrimitiveUnavailable { reason, .. } => {
                assert!(reason.contains("ProjFsBranch"), "got: {reason}");
            }
            other => panic!("expected PrimitiveUnavailable, got {other:?}"),
        }
    }
}
