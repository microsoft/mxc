// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Error type for the `filesystem_overlay` enforcer.
//!
//! Mirrors `filesystem_dacl::DaclError` in shape so callers can be
//! ported by changing imports and a few variant names. Maps to
//! [`crate::mxc_error::MxcErrorCode`] via [`OverlayError::error_code`]
//! for wire-format reporting.

use std::io;
use std::path::PathBuf;

use crate::mxc_error::MxcErrorCode;

/// Errors surfaced by `OverlayManager` and helpers in this module.
#[derive(Debug, thiserror::Error)]
pub enum OverlayError {
    /// Caller passed a UNC network path; only local paths are
    /// supported. Same restriction as `filesystem_dacl`.
    #[error("path is not local (network/UNC paths not supported): {0}")]
    NetworkPathRejected(PathBuf),

    /// A path in the policy could not be resolved by
    /// [`std::fs::canonicalize`].
    #[error("path does not exist: {0}")]
    PathNotFound(PathBuf),

    /// The policy refers to a path the chosen primitive cannot
    /// enforce on this host (e.g. ProjFS feature absent, BindFlt
    /// not loaded, etc.). The detector should already have caught
    /// this; surfaced here as a defense in depth.
    #[error("overlay primitive unavailable: {primitive} ({reason})")]
    PrimitiveUnavailable {
        /// Short name of the primitive: "projfs" or "bindflt".
        primitive: &'static str,
        /// Human-readable reason from the feature-detect probe.
        reason: String,
    },

    /// Win32 / NTSTATUS / HRESULT error from the underlying API.
    #[error("Win32 error on {path}: {reason}")]
    Win32 {
        /// Path involved.
        path: PathBuf,
        /// Win32 error description.
        reason: String,
    },

    /// Generic ProjFS provider error (HRESULT, callback failure, etc.).
    #[error("ProjFS error: {0}")]
    ProjFs(String),

    /// Generic BindFlt error (HRESULT from `Bf*` or `CreateBindLink`).
    #[error("BindFlt error: {0}")]
    BindFlt(String),

    /// State file IO error.
    #[error("state file I/O error: {0}")]
    StateIo(#[from] io::Error),

    /// State file parse error.
    #[error("state file parse error: {0}")]
    StateParse(String),

    /// Policy classification failed (e.g. ambiguous branch names,
    /// overlapping mappings, unsupported policy shape).
    #[error("policy classification failed: {0}")]
    Classify(String),

    /// Apply failed for one or more primitives; per-entry detail
    /// lives in `OverlayManager::warnings`.
    #[error("overlay apply failed: {0}")]
    Apply(String),

    /// Restore failed for one or more primitives; per-entry detail
    /// lives in `OverlayManager::warnings`.
    #[error("overlay restore failed: {0}")]
    Restore(String),
}

impl OverlayError {
    /// Map to the wire-format [`MxcErrorCode`] used by the
    /// state-aware dispatcher and the SDK.
    pub fn error_code(&self) -> MxcErrorCode {
        match self {
            OverlayError::NetworkPathRejected(_)
            | OverlayError::PathNotFound(_)
            | OverlayError::Classify(_) => MxcErrorCode::PolicyValidation,
            OverlayError::PrimitiveUnavailable { .. } => MxcErrorCode::BackendUnavailable,
            OverlayError::Win32 { .. }
            | OverlayError::ProjFs(_)
            | OverlayError::BindFlt(_)
            | OverlayError::StateIo(_)
            | OverlayError::StateParse(_)
            | OverlayError::Apply(_)
            | OverlayError::Restore(_) => MxcErrorCode::BackendError,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn error_code_maps_classification_to_policy_validation() {
        let e = OverlayError::Classify("ambiguous branch".into());
        assert_eq!(e.error_code(), MxcErrorCode::PolicyValidation);
    }

    #[test]
    fn error_code_maps_primitive_unavailable_to_backend_unavailable() {
        let e = OverlayError::PrimitiveUnavailable {
            primitive: "projfs",
            reason: "Client-ProjFS not enabled".into(),
        };
        assert_eq!(e.error_code(), MxcErrorCode::BackendUnavailable);
    }

    #[test]
    fn error_code_maps_apply_to_backend_error() {
        let e = OverlayError::Apply("anything".into());
        assert_eq!(e.error_code(), MxcErrorCode::BackendError);
    }
}
