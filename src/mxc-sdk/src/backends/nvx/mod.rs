// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

mod policy;
mod process;
pub mod runner;
mod runtime;
pub mod state_aware;
#[cfg(test)]
mod test_support;

pub(crate) fn is_available() -> bool {
    // Asset discovery must not open a host or admit persistent lifecycle state.
    aci_edge_sandboxes::agent::BundledAgent::discover().is_ok() && hypervisor_available()
}

fn hypervisor_available() -> bool {
    use windows::Win32::Foundation::FreeLibrary;
    use windows::Win32::System::LibraryLoader::{
        GetProcAddress, LoadLibraryExW, LOAD_LIBRARY_SEARCH_SYSTEM32,
    };
    type GetCapability =
        unsafe extern "system" fn(u32, *mut std::ffi::c_void, u32, *mut u32) -> i32;
    // SAFETY: only the system copy is loaded; the handle remains live until the query completes.
    let Ok(module) = (unsafe {
        LoadLibraryExW(
            windows::core::w!("WinHvPlatform.dll"),
            None,
            LOAD_LIBRARY_SEARCH_SYSTEM32,
        )
    }) else {
        return false;
    };
    let result = unsafe { GetProcAddress(module, windows::core::s!("WHvGetCapability")) }
        .is_some_and(|symbol| {
            // SAFETY: WHvGetCapability's system ABI takes a capability code, buffer and length.
            let get: GetCapability = unsafe { std::mem::transmute(symbol) };
            let mut present = 0i32;
            let mut written = 0u32;
            // Capability zero is WHvCapabilityCodeHypervisorPresent, whose output is BOOL.
            let status = unsafe { get(0, (&raw mut present).cast(), 4, &mut written) };
            status >= 0 && written == 4 && present != 0
        });
    // SAFETY: no function pointer escapes the completed capability query.
    unsafe {
        let _ = FreeLibrary(module);
    }
    result
}
