// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

mod abi;
mod policy;
pub mod runner;
mod runtime;
pub(crate) mod state_aware;

pub(crate) use runtime::CAPTURE_LIMIT_BYTES;

pub(crate) fn is_available() -> bool {
    runtime::agent_bundle_available() && hypervisor_available()
}

fn hypervisor_available() -> bool {
    use windows::Win32::Foundation::FreeLibrary;
    use windows::Win32::System::LibraryLoader::{
        GetProcAddress, LoadLibraryExW, LOAD_LIBRARY_SEARCH_SYSTEM32,
    };

    type GetCapability =
        unsafe extern "system" fn(u32, *mut std::ffi::c_void, u32, *mut u32) -> i32;

    // SAFETY: the search is restricted to the Windows system directory.
    let Ok(module) = (unsafe {
        LoadLibraryExW(
            windows::core::w!("WinHvPlatform.dll"),
            None,
            LOAD_LIBRARY_SEARCH_SYSTEM32,
        )
    }) else {
        return false;
    };
    let present = unsafe { GetProcAddress(module, windows::core::s!("WHvGetCapability")) }
        .is_some_and(|symbol| {
            // SAFETY: WHvGetCapability has this system ABI and the module remains loaded.
            let get: GetCapability = unsafe { std::mem::transmute(symbol) };
            let mut value = 0i32;
            let mut written = 0u32;
            // Capability zero is WHvCapabilityCodeHypervisorPresent, which returns a BOOL.
            let status = unsafe { get(0, (&raw mut value).cast(), 4, &mut written) };
            status >= 0 && written == 4 && value != 0
        });
    // SAFETY: the module was loaded above and no pointer escapes this function.
    unsafe {
        let _ = FreeLibrary(module);
    }
    present
}
