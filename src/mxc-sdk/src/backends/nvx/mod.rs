// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

mod policy;
pub mod runner;
#[path = "crate_runtime.rs"]
mod runtime;
mod signature_verification;
pub(crate) mod state_aware;

pub(crate) fn is_available() -> bool {
    runtime::agent_bundle_available() && hypervisor_available()
}

fn hypervisor_available() -> bool {
    use libloading::os::windows::{Library, LOAD_LIBRARY_SEARCH_SYSTEM32};

    type GetCapability =
        unsafe extern "system" fn(u32, *mut std::ffi::c_void, u32, *mut u32) -> i32;

    // SAFETY: the search is restricted to the Windows system directory.
    let Ok(module) =
        (unsafe { Library::load_with_flags("WinHvPlatform.dll", LOAD_LIBRARY_SEARCH_SYSTEM32) })
    else {
        return false;
    };
    // SAFETY: WHvGetCapability has this system ABI and the module remains loaded.
    unsafe { module.get::<GetCapability>(b"WHvGetCapability\0") }.is_ok_and(|get| {
        let mut value = 0i32;
        let mut written = 0u32;
        // Capability zero is WHvCapabilityCodeHypervisorPresent, which returns a BOOL.
        let status = unsafe { get(0, (&raw mut value).cast(), 4, &mut written) };
        status >= 0 && written == 4 && value != 0
    })
}
