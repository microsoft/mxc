// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use std::sync::OnceLock;

pub(crate) fn pin_current_module() -> Result<(), String> {
    static PIN: OnceLock<Result<(), String>> = OnceLock::new();
    PIN.get_or_init(pin_platform_module).clone()
}

#[cfg(windows)]
fn pin_platform_module() -> Result<(), String> {
    use windows::core::PCWSTR;
    use windows::Win32::Foundation::HMODULE;
    use windows::Win32::System::LibraryLoader::{
        GetModuleHandleExW, GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS, GET_MODULE_HANDLE_EX_FLAG_PIN,
    };

    let mut module = HMODULE::default();

    // SAFETY: FROM_ADDRESS identifies this image; PIN keeps it mapped until process exit.
    unsafe {
        GetModuleHandleExW(
            GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_PIN,
            PCWSTR(pin_platform_module as *const () as *const u16),
            &mut module,
        )
    }
    .map_err(|error| format!("could not pin the native module for detached workers: {error}"))
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn pin_platform_module() -> Result<(), String> {
    use std::ffi::CStr;
    use std::ptr;

    let address = pin_platform_module as *const () as *const libc::c_void;
    #[cfg(target_os = "linux")]
    if address_in_main_executable(address) {
        return Ok(());
    }

    let mut image = libc::Dl_info {
        dli_fname: ptr::null(),
        dli_fbase: ptr::null_mut(),
        dli_sname: ptr::null(),
        dli_saddr: ptr::null_mut(),
    };

    // SAFETY: address is in this image and image is a writable loader-info record.
    if unsafe { libc::dladdr(address, &mut image) } == 0 || image.dli_fname.is_null() {
        return Err("could not locate the native module for detached workers".to_string());
    }

    #[cfg(target_os = "macos")]
    {
        extern "C" {
            fn _dyld_get_image_header(index: u32) -> *const libc::c_void;
        }

        // SAFETY: dyld image zero is the main executable, which cannot be unloaded.
        if image.dli_fbase.cast_const() == unsafe { _dyld_get_image_header(0) } {
            return Ok(());
        }
    }

    // SAFETY: the loader owns this path; NOLOAD prevents loading a different on-disk image.
    let handle = unsafe {
        libc::dlopen(
            image.dli_fname,
            libc::RTLD_NOW | libc::RTLD_LOCAL | libc::RTLD_NOLOAD | libc::RTLD_NODELETE,
        )
    };

    // Keep the loader reference for process lifetime, including after a caller closes its handle.
    if !handle.is_null() {
        return Ok(());
    }

    // SAFETY: dlerror and its non-null string remain valid until the next loader call.
    let detail = unsafe {
        let error = libc::dlerror();
        if error.is_null() {
            "dynamic loader returned no error detail".to_string()
        } else {
            CStr::from_ptr(error).to_string_lossy().into_owned()
        }
    };
    Err(format!(
        "could not pin the native module for detached workers: {detail}"
    ))
}

#[cfg(target_os = "linux")]
fn address_in_main_executable(address: *const libc::c_void) -> bool {
    struct Search {
        address: usize,
        program_headers: usize,
        found: bool,
    }

    unsafe extern "C" fn inspect(
        info: *mut libc::dl_phdr_info,
        _size: usize,
        data: *mut libc::c_void,
    ) -> libc::c_int {
        let search = data.cast::<Search>();

        // SAFETY: the loader supplies info and forwards our live Search pointer.
        let (info, search) = unsafe { (&*info, &mut *search) };
        if info.dlpi_phdr as usize != search.program_headers {
            return 0;
        }

        // SAFETY: the loader supplies dlpi_phnum program headers for this image.
        let headers =
            unsafe { std::slice::from_raw_parts(info.dlpi_phdr, usize::from(info.dlpi_phnum)) };
        search.found = headers.iter().any(|header| {
            let start = (info.dlpi_addr as usize).wrapping_add(header.p_vaddr as usize);
            header.p_type == libc::PT_LOAD
                && search.address.wrapping_sub(start) < header.p_memsz as usize
        });
        1
    }

    // SAFETY: AT_PHDR reads the executable's program-header address from the process auxiliary vector.
    let program_headers = unsafe { libc::getauxval(libc::AT_PHDR) } as usize;
    if program_headers == 0 {
        return false;
    }
    let mut search = Search {
        address: address as usize,
        program_headers,
        found: false,
    };

    // SAFETY: inspect uses only loader records and search, which lives for the entire traversal.
    unsafe { libc::dl_iterate_phdr(Some(inspect), std::ptr::from_mut(&mut search).cast()) };
    search.found
}

#[cfg(not(any(windows, target_os = "linux", target_os = "macos")))]
fn pin_platform_module() -> Result<(), String> {
    Err("native module lifetime protection is unavailable on this platform".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn main_executable_accepts_repeated_pinning() {
        pin_current_module().unwrap();
        pin_current_module().unwrap();
    }
}
