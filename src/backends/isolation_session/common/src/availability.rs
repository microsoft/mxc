// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! IsolationSession host-availability probe.
//!
//! Availability is whether the in-proc `Windows.AI.IsolationSession`
//! `IsoSessionOps` WinRT class is registered on the OS (its activation factory
//! resolves), matching PR #761 rather than gating on a Windows build number.

use std::sync::OnceLock;

use isolation_session_bindings::bindings::IsoSessionOps;
use windows::Win32::System::Com::{CoInitializeEx, CoUninitialize, COINIT_MULTITHREADED};
use windows_core::HRESULT;

static AVAILABLE: OnceLock<bool> = OnceLock::new();

/// Cached for the process; never requires elevation.
pub fn is_isolation_session_available() -> bool {
    *AVAILABLE.get_or_init(|| available_from(probe_activation()))
}

/// Split from [`probe_activation`] so the decision is testable without COM/WinRT.
/// Any activation failure (class not registered, or the OS feature gate off)
/// means not available here.
fn available_from(activation: Result<(), HRESULT>) -> bool {
    activation.is_ok()
}

fn probe_activation() -> Result<(), HRESULT> {
    // Guard uninitializes on drop, so a panic in `IsoSessionOps::new()` still
    // balances `CoInitializeEx`. The `_ops` handle drops before `_apartment`
    // (reverse declaration order), preserving COM's create-before-uninit rule.
    let _apartment = ComApartment::enter();
    match IsoSessionOps::new() {
        Ok(_ops) => Ok(()),
        Err(e) => Err(e.code()),
    }
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
    fn only_successful_activation_means_available() {
        assert!(available_from(Ok(())));
        assert!(!available_from(Err(CLASS_E_CLASSNOTAVAILABLE)));
        assert!(!available_from(Err(REGDB_E_CLASSNOTREG)));
        assert!(!available_from(Err(HRESULT(0x8000_4005u32 as i32))));
    }
}
