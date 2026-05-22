// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Policy → plan lowering.
//!
//! Walks the three vectors of a [`crate::models::ContainerPolicy`]
//! and decides which primitive should enforce each entry. The
//! decision tree is in `classify`; see also `docs/proposals/
//! downlevel_support/overlay-tier.md` (Phase E.4) for the rationale
//! behind each branch.
//!
//! This module is **pure** — given the same `ContainerPolicy` and
//! `AcContext`, `classify` produces the same `OverlayPlan`. That's
//! what makes it testable on macOS / Linux CI.

use crate::filesystem_overlay::error::OverlayError;
use crate::filesystem_overlay::plan::OverlayPlan;
use crate::models::ContainerPolicy;

/// Context the classifier needs from the surrounding system.
///
/// Carries the AC's identity (so per-SID BindFlt mappings can be
/// scoped correctly) plus pre-resolved primitive availability so
/// the classifier doesn't have to re-probe.
#[derive(Debug, Clone)]
pub struct AcContext {
    /// AppContainer SID in `S-1-15-2-…` form.
    pub ac_sid: String,
    /// `true` when the `Client-ProjFS` optional feature is enabled
    /// on this host. Filled in by `fallback_detector::detect`.
    pub projfs_available: bool,
    /// `true` when `BindFltApi.dll` loaded and the entry points
    /// resolved. Filled in by `fallback_detector::detect`.
    pub bindflt_available: bool,
}

/// Classify a `ContainerPolicy` into a deterministic `OverlayPlan`.
///
/// Phase A.1 ships a stub that returns an empty plan; the real
/// classification arrives in Phase C.1.
pub fn classify(_policy: &ContainerPolicy, _ctx: &AcContext) -> Result<OverlayPlan, OverlayError> {
    // Phase A.1 skeleton: real classification ships in Phase C.1.
    // The empty plan is a valid result — it means "no primitives
    // needed; pass-through to the AC's default access rights."
    Ok(OverlayPlan::default())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn empty_ctx() -> AcContext {
        AcContext {
            ac_sid: "S-1-15-2-test".into(),
            projfs_available: true,
            bindflt_available: true,
        }
    }

    #[test]
    fn empty_policy_yields_empty_plan() {
        let p = ContainerPolicy::default();
        let plan = classify(&p, &empty_ctx()).expect("empty policy classifies cleanly");
        assert!(plan.primitives.is_empty());
    }
}
