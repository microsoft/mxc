// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use crate::error::WxcError;
use crate::string_util;

use windows::Win32::Foundation::{
    CloseHandle, LocalFree, SetHandleInformation, BOOL, HANDLE, HANDLE_FLAGS, HANDLE_FLAG_INHERIT,
    HLOCAL,
};
use windows::Win32::Security::{DeriveCapabilitySidsFromName, PSID, SECURITY_ATTRIBUTES};
use windows::Win32::Storage::FileSystem::ReadFile;
use windows::Win32::System::Pipes::CreatePipe;
use windows_core::PCWSTR;

const BUFFER_SIZE: u32 = 4096;
const MAX_OUTPUT_CHARS: usize = 1024 * 1024;

/// Thread-safe owned handle wrapper that transfers HANDLE ownership across thread boundaries.
/// After construction the source `OwnedHandle` is invalidated, and this wrapper is
/// responsible for closing the handle on drop.
///
/// SAFETY: Windows HANDLEs are process-wide and safe to use from any thread.
pub struct SendOwnedHandle(isize);
unsafe impl Send for SendOwnedHandle {}

impl SendOwnedHandle {
    /// Takes ownership of the handle from an `OwnedHandle`.
    /// The original `OwnedHandle` is invalidated and will not close the handle.
    pub fn take(handle: &mut OwnedHandle) -> Self {
        Self(handle.take().0 as isize)
    }

    pub fn get(&self) -> HANDLE {
        HANDLE(self.0 as *mut core::ffi::c_void)
    }
}

impl Drop for SendOwnedHandle {
    fn drop(&mut self) {
        let h = HANDLE(self.0 as *mut core::ffi::c_void);
        if !h.is_invalid() && h != HANDLE::default() {
            unsafe {
                let _ = CloseHandle(h);
            }
        }
    }
}

/// RAII wrapper for a Windows HANDLE that calls CloseHandle on drop.
pub struct OwnedHandle(HANDLE);

impl OwnedHandle {
    pub fn new(h: HANDLE) -> Self {
        Self(h)
    }

    pub fn get(&self) -> HANDLE {
        self.0
    }

    pub fn take(&mut self) -> HANDLE {
        let h = self.0;
        self.0 = HANDLE::default();
        h
    }

    pub fn is_valid(&self) -> bool {
        !self.0.is_invalid() && self.0 != HANDLE::default()
    }
}

impl Drop for OwnedHandle {
    fn drop(&mut self) {
        if self.is_valid() {
            unsafe {
                let _ = CloseHandle(self.0);
            }
        }
    }
}

/// Read all data from a pipe as UTF-8 text, capped at 1MB of characters.
pub fn read_from_pipe(pipe: HANDLE) -> String {
    let mut result = String::with_capacity(BUFFER_SIZE as usize);
    let mut buffer = [0u8; BUFFER_SIZE as usize];
    loop {
        let mut bytes_read = 0u32;
        let ok = unsafe { ReadFile(pipe, Some(&mut buffer), Some(&mut bytes_read), None) };
        if ok.is_err() || bytes_read == 0 {
            break;
        }
        let chunk = String::from_utf8_lossy(&buffer[..bytes_read as usize]);
        let remaining = MAX_OUTPUT_CHARS.saturating_sub(result.len());
        if remaining == 0 {
            break;
        }
        if chunk.len() > remaining {
            // Take only up to `remaining` chars
            let truncated: String = chunk.chars().take(remaining).collect();
            result.push_str(&truncated);
            break;
        }
        result.push_str(&chunk);
    }
    result
}

/// Create a pair of pipe handles (read, write) with appropriate inheritance.
/// If `no_inherit_read` is true, the read end is made non-inheritable;
/// otherwise the write end is made non-inheritable.
pub fn create_std_pipes(no_inherit_read: bool) -> Result<(OwnedHandle, OwnedHandle), WxcError> {
    let sa = SECURITY_ATTRIBUTES {
        nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
        bInheritHandle: BOOL::from(true),
        lpSecurityDescriptor: std::ptr::null_mut(),
    };
    let mut h_read = HANDLE::default();
    let mut h_write = HANDLE::default();

    unsafe {
        CreatePipe(&mut h_read, &mut h_write, Some(&sa), 0)
            .map_err(|_| WxcError::Process("Failed to create pipe".into()))?;

        let h_dup = if no_inherit_read { h_read } else { h_write };
        SetHandleInformation(h_dup, HANDLE_FLAG_INHERIT.0, HANDLE_FLAGS(0)).map_err(|_| {
            let _ = CloseHandle(h_read);
            let _ = CloseHandle(h_write);
            WxcError::Process("Failed to set handle information on pipe".into())
        })?;
    }

    Ok((OwnedHandle::new(h_read), OwnedHandle::new(h_write)))
}

/// Remove a specific Python "Failed to find real location of ..." line from stderr.
pub fn suppress_python_location_error(stderr: &mut String) {
    let needle = "Failed to find real location of ";
    if let Some(pos) = stderr.find(needle) {
        if let Some(nl) = stderr[pos..].find('\n') {
            stderr.replace_range(pos..pos + nl + 1, "");
        } else {
            stderr.truncate(pos);
        }
    }
}

/// Derive the capability SID for a given capability name.
/// Returns the raw SID pointer. The caller is responsible for freeing it with `LocalFree`.
pub fn get_capability_sid_from_name(name: &str) -> Result<*mut core::ffi::c_void, WxcError> {
    let wide_name = string_util::to_wide(name);
    let pcwstr = PCWSTR(wide_name.as_ptr());

    let mut capability_sids: *mut PSID = std::ptr::null_mut();
    let mut capability_sid_count: u32 = 0;
    let mut group_sids: *mut PSID = std::ptr::null_mut();
    let mut group_sid_count: u32 = 0;

    unsafe {
        DeriveCapabilitySidsFromName(
            pcwstr,
            &mut group_sids,
            &mut group_sid_count,
            &mut capability_sids,
            &mut capability_sid_count,
        )
        .map_err(|_| WxcError::Process(format!("DeriveCapabilitySidsFromName({}) failed", name)))?;

        // Free group SIDs
        for i in 0..group_sid_count {
            let sid = *group_sids.add(i as usize);
            let _ = LocalFree(HLOCAL(sid.0));
        }
        let _ = LocalFree(HLOCAL(group_sids as *mut _));

        if capability_sid_count == 0 {
            let _ = LocalFree(HLOCAL(capability_sids as *mut _));
            return Err(WxcError::Process(format!(
                "No capability SID returned for {}",
                name
            )));
        }

        // Take the first capability SID
        let result_sid = (*capability_sids).0;

        // Free remaining capability SIDs (index 1+)
        for i in 1..capability_sid_count {
            let sid = *capability_sids.add(i as usize);
            let _ = LocalFree(HLOCAL(sid.0));
        }
        let _ = LocalFree(HLOCAL(capability_sids as *mut _));

        Ok(result_sid)
    }
}
