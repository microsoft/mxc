// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Per-run handle returned by `OverlayManager::apply_policy`.
//!
//! The runner threads this through process creation so the AC's cwd
//! lands inside the projection (if any) and policy-aware env vars
//! reach the agent script.

use std::ffi::OsString;
use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use crate::filesystem_overlay::plan::OverlayPlanSummary;

/// Per-run output of `OverlayManager::apply_policy`. Owned by the
/// runner for the lifetime of the contained process.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OverlayHandle {
    /// Suggested cwd for the contained process.
    ///
    /// - If the plan contains a ProjFS branch, this is the
    ///   projection root (so relative paths resolve into projected
    ///   content).
    /// - If the plan is BindFlt-only, this is `None` and the runner
    ///   keeps the caller-supplied cwd.
    pub effective_cwd: Option<PathBuf>,

    /// Env vars to inject into the contained process. Includes at
    /// minimum `MXC_POLICY_ROOT` when a projection exists.
    pub env_injections: Vec<(String, OsString)>,

    /// Diagnostic summary of the applied plan.
    pub plan_summary: OverlayPlanSummary,
}

impl OverlayHandle {
    /// An empty handle — used when no primitives applied (policy was
    /// satisfiable purely by AC defaults / DACL augmentation).
    pub fn empty() -> Self {
        Self {
            effective_cwd: None,
            env_injections: Vec::new(),
            plan_summary: OverlayPlanSummary::default(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_handle_has_no_state() {
        let h = OverlayHandle::empty();
        assert!(h.effective_cwd.is_none());
        assert!(h.env_injections.is_empty());
        assert_eq!(h.plan_summary.projfs_branch_count, 0);
        assert_eq!(h.plan_summary.bindflt_mapping_count, 0);
    }
}
