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

use windows::core::{s, HSTRING, PCWSTR};
use windows::Win32::Foundation::{GetLastError, REGDB_E_CLASSNOTREG};
use windows::Win32::System::Com::{CoInitializeEx, COINIT_MULTITHREADED};
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
