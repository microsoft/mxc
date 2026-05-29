// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Open `\Device\Null` with the rights needed for SD read/write.

use windows::core::PCWSTR;
use windows::Win32::Foundation::{CloseHandle, GENERIC_READ, HANDLE};
use windows::Win32::Storage::FileSystem::{
    CreateFileW, FILE_ATTRIBUTE_NORMAL, FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE,
    OPEN_EXISTING,
};

use super::NullDeviceError;

/// `READ_CONTROL` is the standard right needed to read the DACL/owner/
/// group of a kernel object. Defined here rather than pulled in from
/// the windows crate because the constant in question is more discoverable
/// inline at the use site.
const READ_CONTROL: u32 = 0x0002_0000;
/// `WRITE_DAC` — required to change the DACL via `SetKernelObjectSecurity`.
const WRITE_DAC: u32 = 0x0004_0000;
/// `WRITE_OWNER` — required to change the owner via `SetKernelObjectSecurity`.
const WRITE_OWNER: u32 = 0x0008_0000;
/// `ACCESS_SYSTEM_SECURITY` — required to read/write the SACL.
const ACCESS_SYSTEM_SECURITY: u32 = 0x0100_0000;

/// RAII wrapper around the `HANDLE` returned by [`open_null`]. Closes
/// the handle on drop.
pub struct NullHandle(HANDLE);

impl NullHandle {
    pub fn as_handle(&self) -> HANDLE {
        self.0
    }
}

impl Drop for NullHandle {
    fn drop(&mut self) {
        if !self.0.is_invalid() {
            // SAFETY: handle came from a successful CreateFileW above.
            unsafe {
                let _ = CloseHandle(self.0);
            }
        }
    }
}

/// Open `\\.\NUL` (which the I/O manager resolves to the `\Device\Null`
/// kernel object) with the rights needed to read and optionally
/// rewrite its security descriptor.
///
/// When `want_sacl` is true the open additionally requests
/// `ACCESS_SYSTEM_SECURITY`, which the kernel enforces against
/// `SeSecurityPrivilege` on the caller's token. Callers that lack the
/// privilege should pass `want_sacl=false`; this is the
/// `prepare-null-device --no-sacl` mode (DACL/owner/group only).
pub fn open_null(want_sacl: bool) -> Result<NullHandle, NullDeviceError> {
    // `GENERIC_READ` is included to keep us symmetric with the
    // capability set the kernel default grants — many drivers reject
    // an open with only the security-class rights.
    let mut desired_access = GENERIC_READ.0 | READ_CONTROL | WRITE_DAC | WRITE_OWNER;
    if want_sacl {
        desired_access |= ACCESS_SYSTEM_SECURITY;
    }

    // `\\.\NUL` is the canonical Win32 path for the null device. It
    // resolves through the I/O manager to `\Device\Null` (verified by
    // `WinObj`).
    let path: Vec<u16> = "\\\\.\\NUL\0".encode_utf16().collect();
    let share = FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE;

    // SAFETY: standard CreateFileW invocation; all parameters are
    // either local data, well-defined constants, or NULL.
    let result = unsafe {
        CreateFileW(
            PCWSTR(path.as_ptr()),
            desired_access,
            share,
            None,
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL,
            None,
        )
    };

    match result {
        Ok(h) if !h.is_invalid() => Ok(NullHandle(h)),
        Ok(_) => Err(NullDeviceError::OpenFailed(
            "CreateFileW returned an invalid handle without setting an error".to_string(),
        )),
        Err(e) => {
            // If the open failed and we asked for ACCESS_SYSTEM_SECURITY,
            // that's the most likely cause (token didn't carry
            // SeSecurityPrivilege at open time). Surface a clearer error
            // so the caller knows to retry with `--no-sacl`.
            if want_sacl {
                Err(NullDeviceError::OpenFailed(format!(
                    "CreateFileW(\\\\.\\NUL, ACCESS_SYSTEM_SECURITY): {e}. \
                     Retry with `--no-sacl` if the calling token lacks SeSecurityPrivilege."
                )))
            } else {
                Err(NullDeviceError::OpenFailed(format!(
                    "CreateFileW(\\\\.\\NUL): {e}"
                )))
            }
        }
    }
}
