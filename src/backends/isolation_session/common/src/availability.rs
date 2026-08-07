// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! IsolationSession host-availability probe.
//!
//! Availability is detected by whether the in-proc
//! `Windows.AI.IsolationSession` `IsoSessionOps` runtime class is **registered
//! on the OS** (its WinRT activation factory resolves), matching the approach in
//! PR #761 rather than gating on a Windows build number. Activation failing with
//! `CLASS_E_CLASSNOTAVAILABLE` / `REGDB_E_CLASSNOTREG` means the class isn't
//! registered (or its OS feature gate is off) — i.e. not available here.
//!
//! The classification half is pure (no I/O), so it is unit-tested directly; only
//! [`probe_activation`] touches COM/WinRT.

use std::sync::OnceLock;

use isolation_session_bindings::bindings::IsoSessionOps;
use windows::Win32::System::Com::{CoInitializeEx, CoUninitialize, COINIT_MULTITHREADED};
use windows_core::HRESULT;

/// Cached result — WinRT activation is comparatively expensive, so the host is
/// probed at most once per process.
static AVAILABLE: OnceLock<bool> = OnceLock::new();

/// Whether the IsolationSession backend looks available on this host.
///
/// Attempts to activate the `IsoSessionOps` WinRT class; a successful activation
/// means the API class is registered on the OS. Cached for the life of the
/// process. Never requires elevation.
pub fn is_isolation_session_available() -> bool {
    *AVAILABLE.get_or_init(|| available_from(probe_activation()))
}

/// Map an activation outcome to availability. `Ok(())` means the `IsoSessionOps`
/// class activated (registered on the OS); any `Err` means it could not be
/// activated here, for any reason (class not registered — `CLASS_E_CLASSNOTAVAILABLE`
/// / `REGDB_E_CLASSNOTREG` — or the OS feature gate is off), so the backend is not
/// available. Split from [`probe_activation`] so the decision is testable without
/// COM/WinRT.
fn available_from(activation: Result<(), HRESULT>) -> bool {
    activation.is_ok()
}

/// Attempt to activate `IsoSessionOps`, returning `Ok(())` when it resolves and
/// `Err(hresult)` otherwise. COM is initialized (multithreaded) for the call and
/// balanced with a matching uninitialize only when this call actually performed
/// the initialization; an existing apartment (`RPC_E_CHANGED_MODE`) is left
/// untouched.
fn probe_activation() -> Result<(), HRESULT> {
    // SAFETY: standard COM init/uninit pairing; `is_ok()` covers S_OK and the
    // S_FALSE "already initialized (same mode)" success, both of which we own
    // and must balance. A failure return (e.g. RPC_E_CHANGED_MODE) means another
    // apartment is already active on this thread — activation still works, and we
    // must NOT uninitialize it.
    let owns_com = unsafe { CoInitializeEx(None, COINIT_MULTITHREADED) }.is_ok();

    let result = match IsoSessionOps::new() {
        Ok(_ops) => Ok(()),
        Err(e) => Err(e.code()),
    };

    if owns_com {
        // SAFETY: balances the CoInitializeEx above; only called when we owned
        // the initialization.
        unsafe { CoUninitialize() };
    }

    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use windows::Win32::Foundation::{CLASS_E_CLASSNOTAVAILABLE, REGDB_E_CLASSNOTREG};

    #[test]
    fn only_successful_activation_means_available() {
        assert!(available_from(Ok(())));
        // Class not registered on the OS (the two registration HRESULTs).
        assert!(!available_from(Err(CLASS_E_CLASSNOTAVAILABLE)));
        assert!(!available_from(Err(REGDB_E_CLASSNOTREG)));
        // Any other activation failure is also "not available here".
        assert!(!available_from(Err(HRESULT(0x8000_4005u32 as i32))));
    }
}
