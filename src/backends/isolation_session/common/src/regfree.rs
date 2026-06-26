// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Registration-free WinRT activation for the IsoSession client surface.
//!
//! By default MXC activates `Windows.AI.IsolationSession.IsoSessionOps`
//! through the system-installed registration (the OS image populates the
//! WinRT activation catalog). This module lets MXC instead load the in-proc
//! client (`IsoSessionApp.dll` -> `IsoSessionClient.dll`) from a known
//! relocatable location -- the same idea as the DevBypass inner loop, but
//! pointed at the folder a nuget package would lay down.
//!
//! Contract: when the environment variable [`RUNTIME_DIR_ENV`] is set, this
//! module loads `IsoSession.manifest` from that folder via a side-by-side
//! activation context before the first `IsoSessionOps` activation. The
//! manifest's `<file name="IsoSessionApp.dll">` therefore resolves to that
//! folder rather than `System32`. The activation context is intentionally
//! leaked (never deactivated) so it stays active for the process lifetime.
//!
//! COM/DCOM routing to the matching side-by-side *service* is handled by the
//! OS client via **coresidency**: IsoSessionClient.dll (loaded from this same
//! folder) reads the coresident `IsoSessionInstance.txt` descriptor (or the
//! leaf folder name) to pick the service instance CLSID. No per-EXE registry
//! routing key is involved -- the MSI's service/CLSID registration plus the
//! coresident files are sufficient.

use core::ffi::c_void;
use std::sync::OnceLock;

use windows::Win32::Foundation::{E_NOINTERFACE, HANDLE, HMODULE};
use windows::Win32::System::ApplicationInstallationAndServicing::{
    ActivateActCtx, CreateActCtxW, ACTCTXW,
};
use windows::Win32::System::LibraryLoader::{GetProcAddress, LoadLibraryW};
use windows::Win32::System::WinRT::IActivationFactory;
use windows_core::{Interface, RuntimeName, HSTRING, PCSTR, PCWSTR};

/// Environment variable that points MXC at the folder holding the
/// side-by-side IsoSession runtime binaries and `IsoSession.manifest`.
/// A future nuget package / manifest sets this. When unset, MXC uses the
/// default system activation (no behavior change).
pub const RUNTIME_DIR_ENV: &str = "MXC_ISOSESSION_RUNTIME_DIR";

const MANIFEST_NAME: &str = "IsoSession.manifest";

/// Wrapper so the raw activation-context `HANDLE` can be cached in a static.
/// The handle is owned for the process lifetime and never released.
struct ActCtxHandle(HANDLE);

// SAFETY: the activation-context handle is an opaque, process-wide kernel
// handle; sharing it across threads to call ActivateActCtx is sound.
unsafe impl Send for ActCtxHandle {}
unsafe impl Sync for ActCtxHandle {}

static ACTCTX: OnceLock<Option<ActCtxHandle>> = OnceLock::new();

/// Idempotently establishes reg-free WinRT activation from
/// [`RUNTIME_DIR_ENV`], then activates the context on the calling thread.
///
/// Call this immediately before activating `IsoSessionOps`. It is a no-op
/// (system activation) when the env var is unset or the manifest is missing.
/// Activation is per-thread, so this is re-applied on every call to cover
/// callers that activate from more than one thread.
pub(crate) fn ensure_regfree_activation() {
    let handle = ACTCTX.get_or_init(create_actctx_from_env);

    if let Some(actctx) = handle {
        let mut cookie: usize = 0;

        // SAFETY: `actctx.0` is a valid activation context returned by
        // CreateActCtxW. We intentionally never call DeactivateActCtx -- the
        // context must remain active for this thread's WinRT activation.
        if let Err(e) = unsafe { ActivateActCtx(Some(actctx.0), &mut cookie) } {
            eprintln!("[mxc isosession] ActivateActCtx failed: {}", e);
        }
    }
}

/// Reads [`RUNTIME_DIR_ENV`] and, if set, creates an activation context from
/// the manifest in that folder. Returns `None` (system activation) on any
/// failure or when the var is unset.
fn create_actctx_from_env() -> Option<ActCtxHandle> {
    let dir = match std::env::var(RUNTIME_DIR_ENV) {
        Ok(value) if !value.trim().is_empty() => value.trim().to_string(),
        _ => return None,
    };

    let manifest = format!("{}\\{}", dir.trim_end_matches('\\'), MANIFEST_NAME);
    if !std::path::Path::new(&manifest).exists() {
        eprintln!(
            "[mxc isosession] {} = '{}' but '{}' not found; \
             using system activation.",
            RUNTIME_DIR_ENV, dir, manifest
        );
        return None;
    }

    let manifest_w = HSTRING::from(manifest.as_str());
    let mut ctx = ACTCTXW {
        cbSize: std::mem::size_of::<ACTCTXW>() as u32,
        lpSource: PCWSTR(manifest_w.as_ptr()),
        ..Default::default()
    };

    // SAFETY: `ctx` is a fully-initialised ACTCTXW and `manifest_w` outlives
    // the call, keeping `lpSource` valid.
    let handle = match unsafe { CreateActCtxW(&mut ctx) } {
        Ok(handle) => handle,
        Err(e) => {
            eprintln!(
                "[mxc isosession] CreateActCtxW failed for '{}': {}; \
                 using system activation.",
                manifest, e
            );
            return None;
        }
    };

    eprintln!(
        "[mxc isosession] reg-free WinRT activation active from '{}'",
        dir
    );

    Some(ActCtxHandle(handle))
}

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
/// `usize` so the static is `Send + Sync`. `None` means the runtime dir is
/// unset or the DLL could not be loaded.
static APP_DLL: OnceLock<Option<usize>> = OnceLock::new();

/// Loads `<RUNTIME_DIR_ENV>\IsoSessionApp.dll` by full path exactly once and
/// returns its module handle. Returns `None` when the env var is unset/empty.
fn app_dll_handle() -> Option<HMODULE> {
    let cached = APP_DLL.get_or_init(|| {
        let dir = match std::env::var(RUNTIME_DIR_ENV) {
            Ok(value) if !value.trim().is_empty() => value.trim().to_string(),
            _ => return None,
        };

        let path = format!("{}\\{}", dir.trim_end_matches('\\'), APP_DLL_NAME);
        let path_w = HSTRING::from(path.as_str());

        // SAFETY: `path_w` is a valid NUL-terminated wide string that outlives
        // the call. Loading by full path makes the 2606 copy of the DLL the one
        // mapped regardless of any inbox WinRT catalog registration.
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
/// **directly** from the coresident `IsoSessionApp.dll` in [`RUNTIME_DIR_ENV`],
/// bypassing the WinRT activation catalog.
///
/// This is required on machines where the inbox `Windows.AI.IsolationSession.*`
/// classes are registered: there, a dynamic reg-free activation context is
/// shadowed by the system catalog, so `RoGetActivationFactory` would load the
/// `System32` binaries and bind the stable service instead of the side-by-side
/// 2606 build. Loading the factory by full DLL path guarantees the 2606
/// `IsoSessionApp.dll` is the one used; its coresidency logic then sibling-loads
/// the 2606 `IsoSessionClient.dll` and binds the matching service instance.
///
/// Returns `None` when [`RUNTIME_DIR_ENV`] is unset (caller falls back to the
/// default `T::new()` system activation). Returns `Some(Err(..))` when the
/// folder is configured but the explicit activation failed -- the caller should
/// surface that rather than silently fall back to a different binary set.
pub(crate) fn activate_from_runtime_dir<T>() -> Option<windows_core::Result<T>>
where
    T: Interface + RuntimeName,
{
    let hmod = app_dll_handle()?;
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
    // reads the handle without taking ownership, so `class_id` remains valid and
    // is freed at end of scope -- after the call. The callee borrows, not owns.
    let class_id_raw: *mut c_void = unsafe { core::mem::transmute_copy(&class_id) };

    let mut factory_raw: *mut c_void = core::ptr::null_mut();
    // SAFETY: out-param receives a valid `IActivationFactory*` on success.
    let hr = unsafe { factory_fn(class_id_raw, &mut factory_raw) };
    hr.ok()?;

    // SAFETY: on success `factory_raw` is a valid, owned `IActivationFactory`.
    let factory = unsafe { IActivationFactory::from_raw(factory_raw) };

    // SAFETY: factory came from the runtime class's own DLL.
    let instance = unsafe { factory.ActivateInstance()? };

    instance.cast::<T>()
}
