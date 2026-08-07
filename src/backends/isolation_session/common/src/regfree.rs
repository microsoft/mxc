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
//! (`LoadLibraryExW` by full path + `DllGetActivationFactory`) guarantees the
//! MSI-installed binary is the one used. Its coresidency logic then
//! sibling-loads the MSI `IsoSessionClient.dll` and binds the matching service
//! instance -- no machine-wide registry mutation is involved.
//!
//! Search-order safety: a full-path `LoadLibrary*` pins only the top-level
//! module; that module's own imports are otherwise resolved through the
//! default search order (the `wxc-exec.exe` directory, System32, the current
//! directory, and `PATH`) -- none of which is the MSI runtime folder, and one
//! of which (CWD) is caller-controlled via the SDK `workingDirectory`. To
//! defeat DLL-planting and to keep coresidency honest, the App DLL is loaded
//! with `LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR | LOAD_LIBRARY_SEARCH_SYSTEM32`, so
//! its dependencies (including the sibling MSI `IsoSessionClient.dll`, whether
//! resolved as a static/delay import or by the App DLL's own path-relative
//! load) are searched only in the MSI runtime folder and System32 -- never the
//! app dir, CWD, or `PATH`. This mirrors the anti-hijack loads in
//! `base_container_runner.rs`, `learning_mode/.../ffi.rs`, and `secenv.rs`,
//! and satisfies the search-order-hijacking guidance recorded in
//! `fallback_detector.rs`.
//!
//! Coupling to the install path: [`resolve_runtime_dir`] returns the
//! [`RUNTIME_DIR_ENV`] override when set, non-empty, **and absolute**,
//! otherwise the hardcoded [`DEFAULT_RUNTIME_DIR`] (the fixed MSI install
//! location the openclaw packager targets). A non-absolute override is
//! rejected (it would make even the top-level DLL path CWD-relative). When
//! neither the override nor the default folder contains a loadable
//! `IsoSessionApp.dll`, activation cleanly falls back to the default system
//! activation, so hosts without the MSI keep working.

use core::ffi::c_void;
use std::sync::OnceLock;

use windows::Win32::Foundation::{GetLastError, ERROR_FILE_NOT_FOUND, E_FAIL, E_POINTER, HMODULE};
use windows::Win32::System::Com::{CoInitializeEx, COINIT_MULTITHREADED};
use windows::Win32::System::LibraryLoader::{
    GetProcAddress, LoadLibraryExW, LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR, LOAD_LIBRARY_SEARCH_SYSTEM32,
};
use windows::Win32::System::WinRT::IActivationFactory;
use windows_core::{Interface, RuntimeName, HRESULT, HSTRING, PCSTR, PCWSTR};

/// Environment variable that points MXC at the folder holding the coresident
/// IsoSession runtime binaries (`IsoSessionApp.dll`, `IsoSessionClient.dll`,
/// `IsoSession.manifest`, ...). Overrides [`DEFAULT_RUNTIME_DIR`] when set to a
/// non-empty **absolute** path; a relative value is rejected (see
/// [`runtime_dir`]).
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

/// Human-readable form of [`ACTIVATION_FACTORY_EXPORT`] for diagnostics.
const ACTIVATION_FACTORY_EXPORT_NAME: &str = "DllGetActivationFactory";

/// Signature of `DllGetActivationFactory`. The first parameter is an `HSTRING`
/// activatable class id (passed by value as its pointer-sized handle); the
/// second receives an `IActivationFactory*`.
type PfnDllGetActivationFactory =
    unsafe extern "system" fn(*mut c_void, *mut *mut c_void) -> windows_core::HRESULT;

/// Outcome of resolving + loading the coresident `IsoSessionApp.dll`, computed
/// once per process.
enum RuntimeLoad {
    /// The default runtime folder holds no `IsoSessionApp.dll` (a host without
    /// the paired MSI). Activation cleanly falls back to default system
    /// activation, so such hosts keep working.
    Absent,
    /// `IsoSessionApp.dll` loaded from `path`. `raw` is its `HMODULE` as a
    /// `usize` so the cache is `Send + Sync`.
    Loaded { raw: usize, path: String },
    /// The DLL is present (or an explicit [`RUNTIME_DIR_ENV`] override was
    /// configured) but could not be resolved or loaded. This is a
    /// broken-runtime condition that must be surfaced to the caller, never
    /// silently redirected to the inbox binaries -- doing so would bind a
    /// *different* binary set under the guise of success. `code`/`detail` carry
    /// the failure.
    Unloadable { code: HRESULT, detail: String },
}

/// Cached load outcome, computed once per process.
static APP_DLL: OnceLock<RuntimeLoad> = OnceLock::new();

/// Pure resolution of the runtime folder from a raw [`RUNTIME_DIR_ENV`] value.
///
/// Returns `(dir, explicit)`:
/// - `explicit == true` only when an **absolute** override was honored; such a
///   value is authoritative -- a load failure under it is surfaced rather than
///   silently ignored (see [`load_app_dll`]).
/// - An unset, empty/whitespace, or **non-absolute** override yields
///   [`DEFAULT_RUNTIME_DIR`] with `explicit == false`. A relative value is
///   rejected because it is used both to build the top-level DLL path and as
///   the dependency search root, so honoring it would make both CWD-relative --
///   a DLL-planting surface.
///
/// Kept free of environment access so every branch is unit-testable without
/// mutating process-global state.
fn resolve_runtime_dir(raw: Option<&str>) -> (String, bool) {
    match raw {
        Some(value) if !value.trim().is_empty() => {
            let trimmed = value.trim();
            if std::path::Path::new(trimmed).is_absolute() {
                (trimmed.to_string(), true)
            } else {
                (DEFAULT_RUNTIME_DIR.to_string(), false)
            }
        }
        _ => (DEFAULT_RUNTIME_DIR.to_string(), false),
    }
}

/// Builds the full `IsoSessionApp.dll` path for a runtime folder, collapsing any
/// trailing backslashes so the join never produces a doubled separator.
fn app_dll_path(dir: &str) -> String {
    format!("{}\\{}", dir.trim_end_matches('\\'), APP_DLL_NAME)
}

/// Whether success-path diagnostics should print. Gated on the crate's existing
/// diagnostic switch (`MXC_DIAG_CONSOLE`) so that normal operation -- notably a
/// host without the paired MSI -- stays silent and does not contaminate the
/// output stream the SDK consumer sees. Error-path messages are emitted
/// unconditionally.
fn success_diag_enabled() -> bool {
    wxc_common::diagnostic::DiagnosticConfig::from_environment().console_enabled
}

/// Loads `<runtime_dir>\IsoSessionApp.dll` by full path exactly once and
/// returns its module handle. Returns `None` when the DLL is absent or cannot
/// be loaded (caller then falls back to default system activation).
/// Resolves and loads `<runtime_dir>\IsoSessionApp.dll`, classifying the result
/// into [`RuntimeLoad`]. Invoked exactly once via the [`APP_DLL`] `OnceLock`.
///
/// A non-absolute [`RUNTIME_DIR_ENV`] override is rejected up front (with a
/// warning) and treated as unset. An **explicit** absolute override is
/// authoritative: if its DLL is absent or fails to load, that is reported as
/// `Unloadable` rather than falling back to the inbox runtime. The default
/// folder being empty, by contrast, is the normal "no MSI on this host" case
/// and yields `Absent`. A DLL that is present but fails to load (wrong
/// architecture, missing dependency, corrupt image, ...) is likewise
/// `Unloadable` -- surfaced, never silently redirected to a different binary
/// set.
fn load_app_dll() -> RuntimeLoad {
    let raw = std::env::var(RUNTIME_DIR_ENV).ok();

    // Warn once if an override was supplied but rejected for being relative.
    if let Some(value) = raw.as_deref() {
        let trimmed = value.trim();
        if !trimmed.is_empty() && !std::path::Path::new(trimmed).is_absolute() {
            eprintln!(
                "[mxc isosession] ignoring non-absolute {}='{}'; using default \
                 runtime dir '{}'.",
                RUNTIME_DIR_ENV, trimmed, DEFAULT_RUNTIME_DIR
            );
        }
    }

    let (dir, explicit) = resolve_runtime_dir(raw.as_deref());
    let path = app_dll_path(&dir);

    if !std::path::Path::new(&path).exists() {
        if explicit {
            // An explicit override that does not resolve is authoritative: the
            // operator asked for a specific runtime and it is not there. Surface
            // it instead of silently binding the inbox binaries. Emit an
            // (ungated) diagnostic -- this is a misconfiguration, not
            // success-path spam, matching the ungated `LoadLibraryExW failed`
            // path below; a silent fail-closed gives the operator nothing to
            // act on.
            let detail = format!(
                "{}='{}' but {} does not exist at '{}'",
                RUNTIME_DIR_ENV, dir, APP_DLL_NAME, path
            );
            eprintln!("[mxc isosession] {}; refusing inbox fallback.", detail);

            return RuntimeLoad::Unloadable {
                code: HRESULT::from_win32(ERROR_FILE_NOT_FOUND.0),
                detail,
            };
        }
        if success_diag_enabled() {
            eprintln!(
                "[mxc isosession] {} not found at '{}'; using system activation.",
                APP_DLL_NAME, path
            );
        }
        return RuntimeLoad::Absent;
    }

    let path_w = HSTRING::from(path.as_str());

    // SAFETY: `path_w` is a valid NUL-terminated wide string that outlives
    // the call. Loading by full path makes the MSI-installed copy of the
    // DLL the one mapped regardless of any inbox WinRT catalog
    // registration. `LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR` (valid because the
    // path is absolute -- guaranteed by `resolve_runtime_dir`) makes the MSI
    // runtime folder the search root for the App DLL's own dependencies,
    // and `LOAD_LIBRARY_SEARCH_SYSTEM32` permits genuine system imports;
    // together they exclude the `wxc-exec.exe` directory, the current
    // directory, and `PATH` from dependency resolution, so a planted DLL
    // cannot hijack the coresident client/service load.
    match unsafe {
        LoadLibraryExW(
            PCWSTR(path_w.as_ptr()),
            None,
            LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR | LOAD_LIBRARY_SEARCH_SYSTEM32,
        )
    } {
        Ok(hmod) if !hmod.is_invalid() => {
            if success_diag_enabled() {
                eprintln!(
                    "[mxc isosession] explicitly loaded {} from '{}'",
                    APP_DLL_NAME, path
                );
            }
            RuntimeLoad::Loaded {
                raw: hmod.0 as usize,
                path,
            }
        }
        // Present but did not load: a broken runtime, not an absent one. Surface
        // it rather than falling back to the inbox binaries.
        Ok(_) => RuntimeLoad::Unloadable {
            code: E_FAIL,
            detail: format!("LoadLibraryExW('{}') returned an invalid handle", path),
        },
        Err(e) => {
            eprintln!("[mxc isosession] LoadLibraryExW('{}') failed: {}", path, e);
            RuntimeLoad::Unloadable {
                code: e.code(),
                detail: format!("LoadLibraryExW('{}') failed: {}", path, e),
            }
        }
    }
}

/// Activates the WinRT runtime class `T` by obtaining its activation factory
/// **directly** from the coresident `IsoSessionApp.dll`, bypassing the WinRT
/// activation catalog.
///
/// Returns `None` only when no coresident `IsoSessionApp.dll` is present at the
/// default location (caller falls back to the default `T::new()` system
/// activation). Returns `Some(Err(..))` when a runtime folder was configured or
/// present but could not be loaded, or the explicit activation failed -- the
/// caller must surface that rather than silently fall back to a different
/// binary set.
pub(crate) fn activate_from_runtime_dir<T>() -> Option<windows_core::Result<T>>
where
    T: Interface + RuntimeName,
{
    let (raw, path) = match APP_DLL.get_or_init(load_app_dll) {
        RuntimeLoad::Absent => return None,
        RuntimeLoad::Unloadable { code, detail } => {
            return Some(Err(windows_core::Error::new(*code, detail.clone())));
        }
        RuntimeLoad::Loaded { raw, path } => (*raw, path.as_str()),
    };

    let hmod = HMODULE(raw as *mut c_void);

    // Unlike the inbox `RoActivateInstance` path (which implicitly initializes
    // the WinRT/COM apartment), obtaining the factory via
    // `DllGetActivationFactory` and calling `IActivationFactory::ActivateInstance`
    // directly does NOT. The factory's activation internally performs COM
    // activation (coresident client -> service), which requires an initialized
    // apartment, so ensure one exists first.
    //
    // SAFETY: `CoInitializeEx` is safe to call with a null reserved pointer. We
    // intentionally do NOT pair it with a `CoUninitialize`: `wxc-exec`'s `main`
    // already initializes an MTA, so the expected result here is `S_FALSE`
    // (already initialized), which still increments this thread's COM init
    // count. We deliberately leak that one increment for the process lifetime
    // (matching the leaked module handle above); process teardown reclaims the
    // resources but is not itself a balancing `CoUninitialize`.
    // `RPC_E_CHANGED_MODE` (a different apartment model already in force) is
    // likewise ignored -- the existing apartment is reused. If this backend is
    // ever compiled into the embeddable SDK (where the host owns thread
    // apartments), replace this with the `ComApartment` RAII guard used by
    // `appcontainer/common/src/network_manager.rs`.
    unsafe {
        let _ = CoInitializeEx(None, COINIT_MULTITHREADED);
    }

    Some(activate_via_factory::<T>(hmod, path))
}

fn activate_via_factory<T>(hmod: HMODULE, dll_path: &str) -> windows_core::Result<T>
where
    T: Interface + RuntimeName,
{
    // SAFETY: `hmod` is a valid module handle and the export name is a static
    // NUL-terminated byte string.
    let proc = unsafe { GetProcAddress(hmod, PCSTR(ACTIVATION_FACTORY_EXPORT.as_ptr())) }
        .ok_or_else(|| {
            // A missing export is a broken/incompatible DLL, not a
            // "no such interface" condition. Report the real Win32 failure and
            // name the export + DLL so an investigator looks at the right layer.
            // SAFETY: called immediately after the failed `GetProcAddress`, so
            // `GetLastError` still reflects that failure.
            let win32 = unsafe { GetLastError() };
            windows_core::Error::new(
                HRESULT::from_win32(win32.0),
                format!(
                    "export '{}' not found in '{}'",
                    ACTIVATION_FACTORY_EXPORT_NAME, dll_path
                ),
            )
        })?;

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
            "[mxc isosession] DllGetActivationFactory('{}') in '{}' failed: {}",
            <T as RuntimeName>::NAME,
            dll_path,
            e
        );
        return Err(e);
    }

    // A DLL that reports success while leaving the out-param null would cause a
    // null-vtable dereference at `ActivateInstance`. Since the whole point of
    // this module is loading a DLL from a path that may hold something
    // unexpected, verify the invariant rather than assume it.
    if factory_raw.is_null() {
        return Err(windows_core::Error::new(
            E_POINTER,
            format!(
                "DllGetActivationFactory('{}') in '{}' returned success but a null factory",
                <T as RuntimeName>::NAME,
                dll_path
            ),
        ));
    }

    // SAFETY: `factory_raw` is non-null (checked above) and, per the WinRT ABI,
    // a valid owned `IActivationFactory` on a success HRESULT.
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolve_runtime_dir_unset_uses_default() {
        let (dir, explicit) = resolve_runtime_dir(None);
        assert_eq!(dir, DEFAULT_RUNTIME_DIR);
        assert!(!explicit, "an unset override is not authoritative");
    }

    #[test]
    fn resolve_runtime_dir_whitespace_uses_default() {
        let (dir, explicit) = resolve_runtime_dir(Some("   "));
        assert_eq!(dir, DEFAULT_RUNTIME_DIR);
        assert!(!explicit, "a whitespace-only override is not authoritative");
    }

    #[test]
    fn resolve_runtime_dir_relative_is_rejected() {
        let (dir, explicit) = resolve_runtime_dir(Some(r"relative\runtime"));
        assert_eq!(
            dir, DEFAULT_RUNTIME_DIR,
            "a relative override must be rejected, not honored"
        );
        assert!(!explicit, "a rejected override must not be authoritative");
    }

    #[test]
    fn resolve_runtime_dir_absolute_is_honored_and_explicit() {
        let (dir, explicit) = resolve_runtime_dir(Some(r"D:\rt\iso"));
        assert_eq!(dir, r"D:\rt\iso");
        assert!(explicit, "an absolute override is authoritative");
    }

    #[test]
    fn resolve_runtime_dir_trims_surrounding_whitespace() {
        let (dir, explicit) = resolve_runtime_dir(Some("  C:\\rt  "));
        assert_eq!(dir, r"C:\rt");
        assert!(explicit);
    }

    #[test]
    fn app_dll_path_uses_single_separator() {
        assert_eq!(app_dll_path(r"C:\rt"), format!(r"C:\rt\{}", APP_DLL_NAME));
    }

    #[test]
    fn app_dll_path_collapses_trailing_backslashes() {
        let expected = format!(r"C:\rt\{}", APP_DLL_NAME);
        assert_eq!(app_dll_path(r"C:\rt\"), expected);
        assert_eq!(app_dll_path(r"C:\rt\\"), expected);
        assert_eq!(app_dll_path(r"C:\rt\\\"), expected);
    }
}
