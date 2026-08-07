// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Coresident WinRT activation for the IsoSession client surface.
//!
//! By default MXC activates `Windows.AI.IsolationSession.Preview.IsoSessionOps`
//! through the system-installed registration (the OS image populates the WinRT
//! activation catalog, which resolves to the inbox `System32` binaries). This
//! module instead loads the in-proc client (`IsoSessionApp.dll` ->
//! `IsoSessionClient.dll`) **by full path** from the folder where the paired
//! IsoSession MSI lays the runtime down, so `wxc-exec` binds the MSI-installed
//! runtime (and its matching side-by-side service instance) rather than the
//! inbox one.
//!
//! Why an explicit factory load and not a reg-free activation context: on an
//! image where the `Windows.AI.IsolationSession.*` classes are registered, a
//! dynamic reg-free activation context is *shadowed* by the system catalog, so
//! `RoGetActivationFactory` still loads the `System32` binaries. Loading the
//! activation factory directly from the MSI copy of `IsoSessionApp.dll`
//! (`LoadLibraryW` by full path + `DllGetActivationFactory`) guarantees the
//! MSI-installed binary is the one used. Its coresidency logic then
//! sibling-loads the MSI `IsoSessionClient.dll` and binds the matching service
//! instance -- no machine-wide registry mutation is involved.
//!
//! Coupling to the install path: [`runtime_dir`] returns the
//! [`RUNTIME_DIR_ENV`] override when set, otherwise the hardcoded
//! [`DEFAULT_RUNTIME_DIR`] (the fixed MSI install location the openclaw
//! packager targets). When neither the override nor the default folder
//! contains a loadable `IsoSessionApp.dll`, activation cleanly falls back to
//! the default system activation, so hosts without the MSI keep working.

use core::ffi::c_void;
use std::sync::OnceLock;

use windows::Win32::Foundation::{E_NOINTERFACE, HMODULE};
use windows::Win32::System::Com::{CoInitializeEx, COINIT_MULTITHREADED};
use windows::Win32::System::LibraryLoader::{GetProcAddress, LoadLibraryW};
use windows::Win32::System::WinRT::IActivationFactory;
use windows_core::{Interface, RuntimeName, HSTRING, PCSTR, PCWSTR};

/// Environment variable that points MXC at the folder holding the coresident
/// IsoSession runtime binaries (`IsoSessionApp.dll`, `IsoSessionClient.dll`,
/// `IsoSession.manifest`, ...). Overrides [`DEFAULT_RUNTIME_DIR`] when set.
pub const RUNTIME_DIR_ENV: &str = "MXC_ISOSESSION_RUNTIME_DIR";

/// The fixed location the paired IsoSession MSI installs its runtime to, and
/// therefore the path this build of `wxc-exec` is hardcoded to bind. The
/// openclaw packager installs the MSI here; MXC needs no configuration to find
/// it. An override via [`RUNTIME_DIR_ENV`] takes precedence (used by tests and
/// side-by-side validation).
pub const DEFAULT_RUNTIME_DIR: &str = r"C:\Program Files\Microsoft\Agentic Runtime\2026.08";

/// Name of the WinRT activation DLL inside the runtime folder.
const APP_DLL_NAME: &str = "IsoSessionApp.dll";

/// Standard WinRT in-proc activation entrypoint exported by `IsoSessionApp.dll`.
const ACTIVATION_FACTORY_EXPORT: &[u8] = b"DllGetActivationFactory\0";

/// Signature of `DllGetActivationFactory`. The first parameter is an `HSTRING`
/// activatable class id (passed by value as its pointer-sized handle); the
/// second receives an `IActivationFactory*`.
type PfnDllGetActivationFactory =
    unsafe extern "system" fn(*mut c_void, *mut *mut c_void) -> windows_core::HRESULT;

/// Cached `HMODULE` of the explicitly-loaded `IsoSessionApp.dll`, stored as a
/// `usize` so the static is `Send + Sync`. `None` means no runtime folder held
/// a loadable `IsoSessionApp.dll`.
static APP_DLL: OnceLock<Option<usize>> = OnceLock::new();

/// Resolves the coresident runtime folder: the [`RUNTIME_DIR_ENV`] override
/// when set and non-empty, otherwise the hardcoded [`DEFAULT_RUNTIME_DIR`].
fn runtime_dir() -> String {
    match std::env::var(RUNTIME_DIR_ENV) {
        Ok(value) if !value.trim().is_empty() => value.trim().to_string(),
        _ => DEFAULT_RUNTIME_DIR.to_string(),
    }
}

/// Loads `<runtime_dir>\IsoSessionApp.dll` by full path exactly once and
/// returns its module handle. Returns `None` when the DLL is absent or cannot
/// be loaded (caller then falls back to default system activation).
fn app_dll_handle() -> Option<HMODULE> {
    let cached = APP_DLL.get_or_init(|| {
        let dir = runtime_dir();
        let path = format!("{}\\{}", dir.trim_end_matches('\\'), APP_DLL_NAME);

        if !std::path::Path::new(&path).exists() {
            eprintln!(
                "[mxc isosession] {} not found at '{}'; using system activation.",
                APP_DLL_NAME, path
            );
            return None;
        }

        let path_w = HSTRING::from(path.as_str());

        // SAFETY: `path_w` is a valid NUL-terminated wide string that outlives
        // the call. Loading by full path makes the MSI-installed copy of the
        // DLL the one mapped regardless of any inbox WinRT catalog
        // registration.
        match unsafe { LoadLibraryW(PCWSTR(path_w.as_ptr())) } {
            Ok(hmod) if !hmod.is_invalid() => {
                eprintln!(
                    "[mxc isosession] explicitly loaded {} from '{}'",
                    APP_DLL_NAME, path
                );
                Some(hmod.0 as usize)
            }
            Ok(_) => None,
            Err(e) => {
                eprintln!(
                    "[mxc isosession] LoadLibraryW('{}') failed: {}; \
                     using system activation.",
                    path, e
                );
                None
            }
        }
    });

    cached.map(|raw| HMODULE(raw as *mut c_void))
}

/// Activates the WinRT runtime class `T` by obtaining its activation factory
/// **directly** from the coresident `IsoSessionApp.dll`, bypassing the WinRT
/// activation catalog.
///
/// Returns `None` when no coresident `IsoSessionApp.dll` was loadable (caller
/// falls back to the default `T::new()` system activation). Returns
/// `Some(Err(..))` when the DLL loaded but the explicit activation failed --
/// the caller should surface that rather than silently fall back to a
/// different binary set.
pub(crate) fn activate_from_runtime_dir<T>() -> Option<windows_core::Result<T>>
where
    T: Interface + RuntimeName,
{
    let hmod = app_dll_handle()?;

    // Unlike the inbox `RoActivateInstance` path (which implicitly initializes
    // the WinRT/COM apartment), obtaining the factory via
    // `DllGetActivationFactory` and calling `IActivationFactory::ActivateInstance`
    // directly does NOT. The factory's activation internally performs COM
    // activation (coresident client -> service), which requires an initialized
    // apartment, so ensure one exists first. Best-effort: `S_FALSE`
    // (already initialized) and `RPC_E_CHANGED_MODE` (a different apartment
    // model is already in force, which is fine to reuse) are both ignored.
    //
    // SAFETY: `CoInitializeEx` is safe to call with a null reserved pointer;
    // its refcount is balanced by process teardown (the runtime lives for the
    // process lifetime, matching the leaked module handle above).
    unsafe {
        let _ = CoInitializeEx(None, COINIT_MULTITHREADED);
    }

    Some(activate_via_factory::<T>(hmod))
}

fn activate_via_factory<T>(hmod: HMODULE) -> windows_core::Result<T>
where
    T: Interface + RuntimeName,
{
    // SAFETY: `hmod` is a valid module handle and the export name is a static
    // NUL-terminated byte string.
    let proc = unsafe { GetProcAddress(hmod, PCSTR(ACTIVATION_FACTORY_EXPORT.as_ptr())) }
        .ok_or_else(|| windows_core::Error::from(E_NOINTERFACE))?;

    // SAFETY: `DllGetActivationFactory` matches `PfnDllGetActivationFactory`.
    let factory_fn: PfnDllGetActivationFactory = unsafe { core::mem::transmute(proc) };

    let class_id = HSTRING::from(<T as RuntimeName>::NAME);

    // SAFETY: `HSTRING` is a transparent, pointer-sized handle. `transmute_copy`
    // reads the handle without taking ownership, so `class_id` remains valid
    // and is freed at end of scope -- after the call. The callee borrows, not
    // owns.
    let class_id_raw: *mut c_void = unsafe { core::mem::transmute_copy(&class_id) };

    let mut factory_raw: *mut c_void = core::ptr::null_mut();

    // SAFETY: out-param receives a valid `IActivationFactory*` on success.
    let hr = unsafe { factory_fn(class_id_raw, &mut factory_raw) };
    if let Err(e) = hr.ok() {
        eprintln!(
            "[mxc isosession] DllGetActivationFactory('{}') failed: {}",
            <T as RuntimeName>::NAME,
            e
        );
        return Err(e);
    }

    // SAFETY: on success `factory_raw` is a valid, owned `IActivationFactory`.
    let factory = unsafe { IActivationFactory::from_raw(factory_raw) };

    // SAFETY: factory came from the runtime class's own DLL.
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
