// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! IsolationSession host-availability probe.
//!
//! Available when `IsoSessionOps` activates and reports a feature level above
//! zero for `LocalAgentUser`, which the lifecycle requires. No build number is
//! consulted.

use std::sync::OnceLock;

use isolation_session_bindings::bindings::{IsoSessionFeature, IsoSessionOps};
use windows_core::HRESULT;

use super::owned_thread;

static AVAILABLE: OnceLock<bool> = OnceLock::new();

/// The host's answer is cached for the process; never requires elevation.
pub fn is_isolation_session_available() -> bool {
    if let Some(available) = AVAILABLE.get() {
        return *available;
    }
    let probed = owned_thread::Impersonation::of_this_thread()
        .and_then(|impersonation| owned_thread::call(&impersonation, || Ok(probe_feature_level())));
    match probed {
        Ok(level) => *AVAILABLE.get_or_init(|| available_from(level)),
        // The probe did not run, so there is no answer to cache.
        Err(_) => false,
    }
}

/// Split from [`probe_feature_level`] so the decision is testable without
/// COM/WinRT. A failed probe or a zero level means not available.
fn available_from(probe: Result<i32, HRESULT>) -> bool {
    matches!(probe, Ok(level) if level > 0)
}

fn probe_feature_level() -> Result<i32, HRESULT> {
    let ops = IsoSessionOps::new().map_err(|e| e.code())?;
    ops.GetFeatureLevel(IsoSessionFeature::LocalAgentUser)
        .map_err(|e| e.code())
}

#[cfg(test)]
mod tests {
    use super::*;
    use windows::Win32::Foundation::{CLASS_E_CLASSNOTAVAILABLE, REGDB_E_CLASSNOTREG};

    #[test]
    fn availability_needs_a_positive_feature_level() {
        assert!(available_from(Ok(1)));
        assert!(!available_from(Ok(0)));
        // Pins the predicate as `> 0` rather than `!= 0`.
        assert!(!available_from(Ok(-1)));
        assert!(!available_from(Err(CLASS_E_CLASSNOTAVAILABLE)));
        assert!(!available_from(Err(REGDB_E_CLASSNOTREG)));
        assert!(!available_from(Err(HRESULT(0x8000_4005u32 as i32))));
    }
}
