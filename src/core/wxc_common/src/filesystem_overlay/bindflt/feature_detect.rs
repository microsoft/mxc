// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Feature-detect probe for the BindFlt primitive.
//!
//! Wraps [`crate::filesystem_overlay::bindflt::api::BindFltApi::get`]
//! into a yes/no signal the `fallback_detector` can use to decide
//! whether the overlay tier is selectable on this host.
//!
//! On Win11 25H2 the DLL ships with all required exports. On older
//! Win10 cohorts that predate the Bind Filter user-mode component,
//! the DLL is absent and we fall back to the DACL tier.

use crate::filesystem_overlay::bindflt::api::BindFltApi;

/// Detection outcome.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BindFltState {
    /// `bindfltapi.dll` loaded and required entry points resolved.
    Usable,
    /// DLL not present or an entry point is missing.
    Unavailable {
        /// Human-readable reason for diagnostics.
        reason: String,
    },
}

/// Probe `bindfltapi.dll`. Stateless; idempotent under the
/// `BindFltApi::get` `OnceLock`.
pub fn detect() -> BindFltState {
    match BindFltApi::get() {
        Ok(_) => BindFltState::Usable,
        Err(e) => BindFltState::Unavailable {
            reason: e.to_string(),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detect_returns_one_of_two_states() {
        match detect() {
            BindFltState::Usable => {}
            BindFltState::Unavailable { reason } => {
                assert!(!reason.is_empty());
            }
        }
    }
}
