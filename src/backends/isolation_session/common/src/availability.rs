// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! IsolationSession host-availability probe.
//!
//! Available when `IsoSessionOps` activates and reports a feature level above
//! zero for `LocalAgentUser`, which the lifecycle requires. No build number is
//! consulted.

use std::sync::OnceLock;

use isolation_session_bindings::bindings::{IsoSessionFeature, IsoSessionOps};
#[cfg(feature = "lifted_msi")]
use windows::Win32::Foundation::REGDB_E_CLASSNOTREG;
use windows::Win32::System::Com::{CoInitializeEx, CoUninitialize, COINIT_MULTITHREADED};
use windows_core::HRESULT;

static AVAILABLE: OnceLock<bool> = OnceLock::new();

/// Cached for the process; never requires elevation.
pub fn is_isolation_session_available() -> bool {
    *AVAILABLE.get_or_init(|| available_from(probe_feature_level()))
}

/// Split from [`probe_feature_level`] so the decision is testable without
/// COM/WinRT. A failed probe or a zero level means not available.
fn available_from(probe: Result<i32, HRESULT>) -> bool {
    matches!(probe, Ok(level) if level > 0)
}

fn probe_feature_level() -> Result<i32, HRESULT> {
    // Guard uninitializes on drop, so a panic during activation still balances
    // `CoInitializeEx`. The `ops` handle drops before `_apartment` (reverse
    // declaration order), preserving COM's create-before-uninit rule.
    let _apartment = ComApartment::enter();

    #[cfg(feature = "lifted_msi")]
    let ops = match super::regfree::activate_from_adjacent_shim::<IsoSessionOps>() {
        Some(result) => result.map_err(|error| {
            eprintln!(
                "[mxc isosession] lifted IsoSessionOps activation failed: {}",
                error
            );
            error.code()
        })?,
        None => return Err(REGDB_E_CLASSNOTREG),
    };
    #[cfg(not(feature = "lifted_msi"))]
    let ops = IsoSessionOps::new().map_err(|e| e.code())?;

    ops.GetFeatureLevel(IsoSessionFeature::LocalAgentUser)
        .map_err(|error| {
            eprintln!(
                "[mxc isosession] GetFeatureLevel(LocalAgentUser) failed: {}",
                error
            );
            error.code()
        })
}

/// Owns the COM apartment for the duration of a probe and uninitializes it on
/// drop, but only when this guard actually performed the initialization.
struct ComApartment {
    owns_com: bool,
}

impl ComApartment {
    fn enter() -> Self {
        // `is_ok()` covers S_OK and the S_FALSE "already initialized (same
        // mode)" success — both of which we own and must balance. A failure
        // (e.g. RPC_E_CHANGED_MODE) means another apartment is already active on
        // this thread: activation still works, and we must NOT uninitialize it.
        // SAFETY: standard COM init; balanced by `CoUninitialize` in `drop`.
        let owns_com = unsafe { CoInitializeEx(None, COINIT_MULTITHREADED) }.is_ok();
        Self { owns_com }
    }
}

impl Drop for ComApartment {
    fn drop(&mut self) {
        if self.owns_com {
            // SAFETY: balances the `CoInitializeEx` in `enter`; only when owned.
            unsafe { CoUninitialize() };
        }
    }
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
