// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Activation for the lifted IsolationSession runtime.
//!
//! The lifted SDK places `IsoSessionApp.dll` and a stamped
//! `IsoSession.manifest` beside the host module (or executable). The shim exports
//! `DllGetActivationFactory`; loading that export directly prevents the inbox
//! WinRT catalog from shadowing the lifted implementation.

#![allow(unsafe_code)]

use std::os::windows::ffi::OsStrExt;
use std::path::PathBuf;
use std::sync::OnceLock;

use windows::core::{s, HSTRING, PCSTR, PCWSTR, PWSTR};
use windows::Win32::Foundation::{GetLastError, ERROR_NOT_SUPPORTED, REGDB_E_CLASSNOTREG, S_OK};
use windows::Win32::System::Com::{CoInitializeEx, CoTaskMemFree, COINIT_MULTITHREADED};
use windows::Win32::System::LibraryLoader::{
    GetProcAddress, LoadLibraryExW, LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR, LOAD_LIBRARY_SEARCH_SYSTEM32,
};
use windows::Win32::System::WinRT::IActivationFactory;
use windows_core::{Interface, RuntimeName, HRESULT};

const SHIM_NAME: &str = "IsoSessionApp.dll";
const MANIFEST_NAME: &str = "IsoSession.manifest";

type DllGetActivationFactory =
    unsafe extern "system" fn(*mut std::ffi::c_void, *mut *mut std::ffi::c_void) -> HRESULT;

static GET_ACTIVATION_FACTORY: OnceLock<DllGetActivationFactory> = OnceLock::new();

/// Flat-C export on the staged shim that answers whether the matching
/// IsolationSession runtime is installed and loadable on this machine. The
/// out-param receives an owned, ready-to-display remediation string (which the
/// caller frees) when it is not; it is left null on success.
type VerifyIsoSessionFramework = unsafe extern "system" fn(*mut *mut u16) -> HRESULT;

/// Resolved by name, so the name is the contract.
const VERIFY_FRAMEWORK_EXPORT: PCSTR = s!("VerifyIsoSessionFramework");

/// Verified once per process: the install state cannot change under us.
static FRAMEWORK_STATUS: OnceLock<Result<(), FrameworkRefusal>> = OnceLock::new();

/// Why framework verification refused, split to match the wire error fields.
///
/// `message` is a concise problem statement (what is wrong); `remediation` is
/// the shim's own ready-to-display fix text, present only when the shim
/// supplied one. A synthetic refusal (verification unsupported, or a bare
/// failure status) carries no remediation.
#[derive(Debug, Clone)]
pub(crate) struct FrameworkRefusal {
    pub(crate) message: String,
    pub(crate) remediation: Option<String>,
}

impl FrameworkRefusal {
    /// A problem statement with no accompanying fix text.
    fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
            remediation: None,
        }
    }

    /// A problem statement paired with the shim's ready-to-display fix text.
    fn with_remediation(message: impl Into<String>, remediation: String) -> Self {
        Self {
            message: message.into(),
            remediation: Some(remediation),
        }
    }
}

/// Activates `T` through the lifted shim staged beside the current executable.
///
/// Returns `None` only when the lifted activation payload is not present.
/// Other failures are returned to the caller and must not fall back to inbox
/// activation because that would silently mix the lifted WinMD with inbox code.
pub(crate) fn activate_from_adjacent_shim<T>() -> Option<windows_core::Result<T>>
where
    T: Interface + RuntimeName,
{
    // Some callers enter through a native thread without initializing COM.
    // RPC_E_CHANGED_MODE only means another apartment model is already active.
    let _ = unsafe { CoInitializeEx(None, COINIT_MULTITHREADED) };

    let directory = adjacent_runtime_directory()?;
    let factory = match load_activation_factory::<T>(&directory.join(SHIM_NAME)) {
        Ok(factory) => factory,
        Err(error) if error.code() == REGDB_E_CLASSNOTREG => return None,
        Err(error) => return Some(Err(error)),
    };

    Some(activate_from_factory(factory))
}

/// Confirms the IsolationSession runtime is installed before any session work.
///
/// `Ok(())` means proceed; `Err(refusal)` means block, carrying the text to
/// show the user. The result is cached for the process.
///
/// Only `S_OK` from the shim proceeds; every other outcome is fail-closed. If
/// the shim itself is not staged beside the host, there is nothing to check
/// here and activation raises its own "payload missing" error, so this returns
/// `Ok(())`.
pub(crate) fn verify_framework() -> Result<(), FrameworkRefusal> {
    FRAMEWORK_STATUS.get_or_init(run_framework_check).clone()
}

fn run_framework_check() -> Result<(), FrameworkRefusal> {
    let Some(directory) = adjacent_runtime_directory() else {
        return Ok(());
    };

    // The shim is staged beside us, so it must expose the verification entry
    // point. If it cannot be loaded, the payload is broken — block.
    let shim_verify_fn = resolve_verify_framework(&directory.join(SHIM_NAME)).map_err(|error| {
        FrameworkRefusal::new(format!(
            "the IsolationSession framework verification entry point could not be loaded: {error}"
        ))
    })?;

    let mut remediation: *mut u16 = std::ptr::null_mut();
    // SAFETY: the out-param is a valid pointer; per the export's contract we
    // own any returned string and must free it with `CoTaskMemFree`.
    let hresult = unsafe { shim_verify_fn(&mut remediation) };
    classify_framework_status(hresult, take_cotaskmem_string(remediation))
}

/// Pure decision split from the FFI call so it is unit-testable without the
/// shim. When the shim supplies its own fix text, that becomes the refusal's
/// remediation and the message is a concise problem statement; otherwise the
/// message stands alone.
fn classify_framework_status(
    hresult: HRESULT,
    remediation: Option<String>,
) -> Result<(), FrameworkRefusal> {
    if hresult == S_OK {
        return Ok(());
    }
    if let Some(remediation) = remediation {
        return Err(FrameworkRefusal::with_remediation(
            "the IsolationSession framework runtime is not installed",
            remediation,
        ));
    }
    if hresult == HRESULT::from_win32(ERROR_NOT_SUPPORTED.0) {
        return Err(FrameworkRefusal::new(
            "the installed IsolationSession framework does not support runtime verification, \
             so MXC cannot confirm the required runtime is present",
        ));
    }
    Err(FrameworkRefusal::new(format!(
        "IsolationSession framework verification failed (0x{:08X})",
        hresult.0 as u32
    )))
}

fn resolve_verify_framework(
    dll_path: &std::path::Path,
) -> windows_core::Result<VerifyIsoSessionFramework> {
    let source: Vec<u16> = dll_path
        .as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();

    // Same absolute-path, constrained-search load used for activation.
    let module = unsafe {
        LoadLibraryExW(
            PCWSTR(source.as_ptr()),
            None,
            LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR | LOAD_LIBRARY_SEARCH_SYSTEM32,
        )
    }?;
    let export = unsafe { GetProcAddress(module, VERIFY_FRAMEWORK_EXPORT) }.ok_or_else(|| {
        windows_core::Error::from_hresult(HRESULT::from_win32(unsafe { GetLastError().0 }))
    })?;

    // The module intentionally stays loaded; the process only verifies once.
    let shim_verify_fn: VerifyIsoSessionFramework = unsafe { std::mem::transmute(export) };
    Ok(shim_verify_fn)
}

/// Reads a shim-allocated wide string into an owned `String`, then frees it
/// with `CoTaskMemFree` as the contract requires. A null pointer yields `None`.
fn take_cotaskmem_string(pointer: *mut u16) -> Option<String> {
    if pointer.is_null() {
        return None;
    }
    // SAFETY: the contract hands back a NUL-terminated wide string; we read it
    // and then release it with the matching allocator.
    let text = unsafe { PWSTR(pointer).to_string() }.ok();
    unsafe { CoTaskMemFree(Some(pointer as *const std::ffi::c_void)) };
    text
}

fn load_activation_factory<T>(
    dll_path: &std::path::Path,
) -> windows_core::Result<IActivationFactory>
where
    T: Interface + RuntimeName,
{
    let get_factory = resolve_get_activation_factory(dll_path)?;

    let class_name = HSTRING::from(T::NAME);
    // HSTRING is a transparent handle; pass the handle, not its UTF-16 buffer.
    let class_name_handle = unsafe { std::mem::transmute_copy(&class_name) };
    let mut factory = std::ptr::null_mut();
    unsafe { get_factory(class_name_handle, &mut factory) }.ok()?;
    if factory.is_null() {
        return Err(windows_core::Error::from_hresult(HRESULT(
            0x8000_4003u32 as i32,
        )));
    }

    // The module intentionally remains loaded so the returned vtable stays valid.
    Ok(unsafe { IActivationFactory::from_raw(factory) })
}

fn resolve_get_activation_factory(
    dll_path: &std::path::Path,
) -> windows_core::Result<DllGetActivationFactory> {
    if let Some(get_factory) = GET_ACTIVATION_FACTORY.get() {
        return Ok(*get_factory);
    }

    let source: Vec<u16> = dll_path
        .as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();

    // The absolute path plus constrained dependency search prevents DLL planting.
    let module = unsafe {
        LoadLibraryExW(
            PCWSTR(source.as_ptr()),
            None,
            LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR | LOAD_LIBRARY_SEARCH_SYSTEM32,
        )
    }?;
    let export =
        unsafe { GetProcAddress(module, s!("DllGetActivationFactory")) }.ok_or_else(|| {
            windows_core::Error::from_hresult(HRESULT::from_win32(unsafe { GetLastError().0 }))
        })?;
    let get_factory: DllGetActivationFactory = unsafe { std::mem::transmute(export) };

    // A racing activation may load the same module twice, but both handles remain
    // valid for the process lifetime and every caller uses the cached export.
    let _ = GET_ACTIVATION_FACTORY.set(get_factory);
    Ok(*GET_ACTIVATION_FACTORY.get().unwrap_or(&get_factory))
}

/// Finds the staged payload beside the module hosting this code first, so
/// in-process hosts (node.exe, dotnet) resolve it beside `mxc_ffi.dll`, then
/// beside the executable or its parent (`target\<profile>\deps` tests).
fn adjacent_runtime_directory() -> Option<PathBuf> {
    let module_directory = current_module_path().and_then(|path| path.parent().map(PathBuf::from));
    let executable_directory = std::env::current_exe()
        .ok()
        .and_then(|path| path.parent().map(PathBuf::from));
    let executable_parent = executable_directory
        .as_deref()
        .and_then(|directory| directory.parent().map(PathBuf::from));

    [module_directory, executable_directory, executable_parent]
        .into_iter()
        .flatten()
        .find(|directory| {
            directory.join(SHIM_NAME).is_file() && directory.join(MANIFEST_NAME).is_file()
        })
}

fn current_module_path() -> Option<PathBuf> {
    use std::os::windows::ffi::OsStringExt;
    use windows::Win32::Foundation::HMODULE;
    use windows::Win32::System::LibraryLoader::{
        GetModuleFileNameW, GetModuleHandleExW, GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS,
        GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
    };

    let mut module = HMODULE::default();
    let address = current_module_path as *const () as *const u16;
    unsafe {
        GetModuleHandleExW(
            GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
            PCWSTR(address),
            &mut module,
        )
    }
    .ok()?;

    let mut buffer = vec![0u16; 1024];
    loop {
        let length = unsafe { GetModuleFileNameW(Some(module), &mut buffer) } as usize;
        if length == 0 {
            return None;
        }
        if length < buffer.len() {
            buffer.truncate(length);
            return Some(PathBuf::from(std::ffi::OsString::from_wide(&buffer)));
        }
        buffer.resize(buffer.len() * 2, 0);
    }
}

fn activate_from_factory<T>(factory: IActivationFactory) -> windows_core::Result<T>
where
    T: Interface + RuntimeName,
{
    let instance = unsafe { factory.ActivateInstance() }.map_err(|error| {
        eprintln!(
            "[mxc isosession] ActivateInstance('{}') failed: {}",
            T::NAME,
            error
        );
        error
    })?;

    instance.cast::<T>().map_err(|error| {
        eprintln!(
            "[mxc isosession] cast to '{}' failed (WinMD/MSI version mismatch?): {}",
            T::NAME,
            error
        );
        error
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use windows::Win32::Foundation::ERROR_MOD_NOT_FOUND;

    #[test]
    fn ok_status_proceeds() {
        assert!(classify_framework_status(S_OK, None).is_ok());
    }

    #[test]
    fn remediation_text_is_surfaced_verbatim() {
        // The shim returns this fix text when the runtime is missing; it lands
        // in the refusal's remediation, with a concise problem statement.
        let fix = "IsoSession isn't found; download from aka.ms/foo".to_string();
        let refusal = classify_framework_status(
            HRESULT::from_win32(ERROR_MOD_NOT_FOUND.0),
            Some(fix.clone()),
        )
        .unwrap_err();
        assert_eq!(refusal.remediation.as_deref(), Some(fix.as_str()));
        assert!(refusal.message.contains("not installed"));
    }

    #[test]
    fn not_supported_is_fail_closed() {
        // No fix text accompanies this status; MXC still blocks, message-only.
        let refusal = classify_framework_status(HRESULT::from_win32(ERROR_NOT_SUPPORTED.0), None)
            .unwrap_err();
        assert!(
            refusal.message.contains("does not support"),
            "expected the verification-unsupported wording"
        );
        assert_eq!(refusal.remediation, None);
    }

    #[test]
    fn bare_failure_without_remediation_still_blocks() {
        // Any other failure with no shim text falls back to a synthetic message.
        let refusal = classify_framework_status(HRESULT(0x8000_4005u32 as i32), None).unwrap_err();
        assert!(
            refusal.message.contains("verification failed"),
            "expected the synthetic failure wording"
        );
        assert_eq!(refusal.remediation, None);
    }
}
