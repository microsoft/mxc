// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Reg-free classic-COM activation for the IsoSession client surface.
//!
//! By default MXC would activate `Windows.AI.IsolationSession.Preview.*`
//! through the system-installed WinRT registration (the OS image populates the
//! activation catalog, which resolves to the inbox `System32` binaries). To
//! bind the **version-pinned MSI-installed** runtime instead, MXC ships
//! `IsoSessionApp.dll` in its own nuget package (co-located with `wxc-exec.exe`)
//! and activates it through a **private classic-COM CLSID** that `wxc-exec`'s
//! fused manifest redirects (reg-free) to that DLL.
//!
//! Mechanism: [`activate_via_private_clsid`] calls
//! `CoCreateInstance(<private CLSID>, CLSCTX_INPROC_SERVER, IID_IActivationFactory)`.
//! The fused `<comClass>` redirection resolves the CLSID straight to the
//! co-located `IsoSessionApp.dll` -- there is **no `LoadLibrary` in this caller
//! and no runtime-path logic in Rust**. All knowledge of where the MSI runtime
//! lives is owned by `IsoSessionApp.dll` (C++), which resolves the runtime
//! directory and coresident-loads `IsoSessionClient.dll`, then binds the
//! matching side-by-side service instance.
//!
//! Why classic-COM and not reg-free WinRT: a classic `<comClass>` redirection
//! is honored **ahead of** HKCR and is never catalog-shadowed (a private CLSID
//! is in no inbox catalog), so it is immune to the reserved-namespace shadowing
//! that defeats a reg-free WinRT activation context on an image where the
//! `Windows.AI.IsolationSession.*` classes are already registered inbox.
//!
//! Fallback contract: when the private CLSID is not registered
//! (`REGDB_E_CLASSNOTREG`) -- i.e. the manifest was not fused, such as an
//! inbox-only build -- [`activate_via_private_clsid`] returns `None` and the
//! caller falls back to default inbox activation (`T::new()`), so hosts without
//! the fused manifest / nuget shim keep working. Any *other* activation error
//! is surfaced as `Some(Err(..))` rather than silently redirected to a
//! different binary set.
//!
//! GUID contract: the two private activator CLSIDs below are a hard contract
//! duplicated in THREE places -- change all together:
//!   * OS: `onecoreuap/windows/core/isoenvbroker/src/app/dll.cpp`
//!   * nuget manifest fragment: `.../IsoSessionApp.comClass.manifest`
//!   * this file (`backends/isolation_session/common/src/regfree.rs`)

use isolation_session_bindings::bindings::{IsoSessionOps, IsoSessionProcessOptions};
use windows::Win32::Foundation::REGDB_E_CLASSNOTREG;
use windows::Win32::System::Com::{
    CoCreateInstance, CoInitializeEx, CLSCTX_INPROC_SERVER, COINIT_MULTITHREADED,
};
use windows::Win32::System::WinRT::IActivationFactory;
use windows_core::{Interface, RuntimeName, GUID};

/// Maps a WinRT runtime class to the private classic-COM CLSID that
/// `IsoSessionApp.dll` exposes (reg-free, via the fused manifest) as its in-proc
/// activator. The CLSID is what MXC hands to `CoCreateInstance`; the shim's
/// class factory then forwards to the matching WinRT class.
///
/// See the module-level GUID contract note: these values must stay in sync with
/// the OS `dll.cpp` and the nuget `.comClass.manifest`.
pub(crate) trait ActivatorClsid {
    /// The private activator CLSID for this runtime class.
    const ACTIVATOR_CLSID: GUID;
}

impl ActivatorClsid for IsoSessionOps {
    // {6EF3155B-D1A2-4A34-BCAA-089F8A6D9916}
    const ACTIVATOR_CLSID: GUID = GUID::from_u128(0x6ef3155b_d1a2_4a34_bcaa_089f8a6d9916);
}

impl ActivatorClsid for IsoSessionProcessOptions {
    // {36B03FF1-21AA-4F3C-819D-2430EC830DD0}
    const ACTIVATOR_CLSID: GUID = GUID::from_u128(0x36b03ff1_21aa_4f3c_819d_2430ec830dd0);
}

/// Activates the WinRT runtime class `T` by resolving its private classic-COM
/// activator CLSID (reg-free, via the fused manifest) to the co-located
/// `IsoSessionApp.dll` and driving its activation factory.
///
/// Returns:
/// - `None` when the private CLSID is not registered (`REGDB_E_CLASSNOTREG`) --
///   the manifest was not fused / this is an inbox-only build. The caller falls
///   back to default inbox activation (`T::new()`).
/// - `Some(Err(..))` when activation was attempted but failed (the shim could
///   not load the client, the factory failed, an unexpected HRESULT, ...). The
///   caller must surface this rather than silently bind a different binary set.
/// - `Some(Ok(instance))` on success.
pub(crate) fn activate_via_private_clsid<T>() -> Option<windows_core::Result<T>>
where
    T: Interface + RuntimeName + ActivatorClsid,
{
    // `CoCreateInstance` requires an initialized COM apartment on this thread.
    // `wxc-exec`'s `main` already initializes an MTA, so the expected result
    // here is `S_FALSE` (already initialized); `RPC_E_CHANGED_MODE` (a
    // different apartment already in force) is likewise fine -- the existing
    // apartment is reused. We deliberately do NOT pair this with a
    // `CoUninitialize`: the one extra init-count increment is leaked for the
    // process lifetime (matching the prior implementation) and reclaimed at
    // process teardown.
    //
    // SAFETY: `CoInitializeEx` is safe to call with a null reserved pointer.
    unsafe {
        let _ = CoInitializeEx(None, COINIT_MULTITHREADED);
    }

    // SAFETY: `T::ACTIVATOR_CLSID` is a valid CLSID; the fused manifest (or, on
    // an inbox-only build, its absence) determines resolution. Requesting
    // `IActivationFactory` matches what the shim's class factory returns.
    let factory: IActivationFactory =
        match unsafe { CoCreateInstance(&T::ACTIVATOR_CLSID, None, CLSCTX_INPROC_SERVER) } {
            Ok(factory) => factory,
            // Not registered: no fused manifest / inbox-only build. Let the
            // caller fall back to inbox `T::new()`.
            Err(e) if e.code() == REGDB_E_CLASSNOTREG => return None,
            // Any other failure is a real activation error -- surface it.
            Err(e) => {
                eprintln!(
                    "[mxc isosession] CoCreateInstance(<activator for '{}'>) failed: {}",
                    <T as RuntimeName>::NAME,
                    e
                );
                return Some(Err(e));
            }
        };

    Some(activate_from_factory::<T>(factory))
}

/// Drives a resolved `IActivationFactory` to produce an instance of `T`.
fn activate_from_factory<T>(factory: IActivationFactory) -> windows_core::Result<T>
where
    T: Interface + RuntimeName,
{
    // SAFETY: `factory` came from the runtime class's own activator DLL.
    let instance = match unsafe { factory.ActivateInstance() } {
        Ok(instance) => instance,
        Err(e) => {
            eprintln!(
                "[mxc isosession] ActivateInstance('{}') failed: {}",
                <T as RuntimeName>::NAME,
                e
            );
            return Err(e);
        }
    };

    instance.cast::<T>().map_err(|e| {
        eprintln!(
            "[mxc isosession] cast to '{}' failed (IID mismatch?): {}",
            <T as RuntimeName>::NAME,
            e
        );
        e
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The two private activator CLSIDs are the hard cross-repo contract. Guard
    /// against an accidental edit that zeroes or aliases one of them.
    #[test]
    fn activator_clsids_match_contract() {
        assert_eq!(
            <IsoSessionOps as ActivatorClsid>::ACTIVATOR_CLSID,
            GUID::from_u128(0x6ef3155b_d1a2_4a34_bcaa_089f8a6d9916),
            "IsoSessionOps activator CLSID drifted from the OS dll.cpp / manifest contract"
        );
        assert_eq!(
            <IsoSessionProcessOptions as ActivatorClsid>::ACTIVATOR_CLSID,
            GUID::from_u128(0x36b03ff1_21aa_4f3c_819d_2430ec830dd0),
            "IsoSessionProcessOptions activator CLSID drifted from the OS dll.cpp / manifest contract"
        );
    }

    /// The two activators must be distinct and non-nil -- a typo collapsing them
    /// would silently activate the wrong class.
    #[test]
    fn activator_clsids_are_distinct_and_nonzero() {
        let ops = <IsoSessionOps as ActivatorClsid>::ACTIVATOR_CLSID;
        let opts = <IsoSessionProcessOptions as ActivatorClsid>::ACTIVATOR_CLSID;
        assert_ne!(ops, opts, "the two activator CLSIDs must differ");
        assert_ne!(ops, GUID::from_u128(0), "IsoSessionOps activator CLSID must be non-nil");
        assert_ne!(opts, GUID::from_u128(0), "IsoSessionProcessOptions activator CLSID must be non-nil");
    }
}
