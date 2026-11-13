// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

mod policy;
pub mod runner;
#[path = "crate_runtime.rs"]
mod runtime;
pub(crate) use runtime::register_runtime_directory;
pub(crate) mod state_aware;

// Give NVX operations more stack space when the caller's remaining stack is limited.
const NVX_WORKER_STACK_SIZE_BYTES: usize = 2 * 1024 * 1024;

fn run_with_sufficient_stack<T: Send>(
    run: impl FnOnce() -> Result<T, crate::mxc_common::mxc_error::MxcError> + Send,
) -> Result<T, crate::mxc_common::mxc_error::MxcError> {
    use crate::mxc_common::mxc_error::MxcError;
    let (mut low, mut high) = (0usize, 0usize);
    // SAFETY: both output pointers refer to writable stack locals.
    unsafe { windows::Win32::System::Threading::GetCurrentThreadStackLimits(&mut low, &mut high) };
    let current: usize;
    // SAFETY: this reads the current x64 stack pointer without changing it.
    unsafe {
        std::arch::asm!("mov {}, rsp", out(reg) current, options(nomem, nostack, preserves_flags));
    }
    if stack_has_sufficient_space(low, high, current) {
        return run();
    }
    let context = crate::lifecycle_thread_context::LifecycleThreadContext::capture()
        .map_err(MxcError::backend_error)?;
    std::thread::scope(|scope| {
        let worker = std::thread::Builder::new()
            .name("mxc-nvx".to_owned())
            .stack_size(NVX_WORKER_STACK_SIZE_BYTES)
            .spawn_scoped(scope, move || context.run(run))
            .map_err(|error| {
                MxcError::backend_error(format!("could not start NVX worker: {error}"))
            })?;
        match worker.join() {
            Ok(Ok(result)) => result,
            Ok(Err(error)) => Err(MxcError::backend_error(error)),
            Err(panic) => std::panic::resume_unwind(panic),
        }
    })
}

fn stack_has_sufficient_space(low: usize, high: usize, current: usize) -> bool {
    current >= low && current < high && current - low >= 1024 * 1024
}

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
