// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Enable `SeSecurityPrivilege` on the current process token.
//!
//! Required for both reading and writing the SACL of a kernel object.
//! Administrators hold the privilege but it's disabled by default —
//! it must be explicitly enabled per token.

use windows::core::PCWSTR;
use windows::Win32::Foundation::{CloseHandle, GetLastError, ERROR_NOT_ALL_ASSIGNED, HANDLE, LUID};
use windows::Win32::Security::{
    AdjustTokenPrivileges, LookupPrivilegeValueW, LUID_AND_ATTRIBUTES, SE_PRIVILEGE_ENABLED,
    TOKEN_ADJUST_PRIVILEGES, TOKEN_PRIVILEGES, TOKEN_QUERY,
};
use windows::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

use super::NullDeviceError;

/// Enable `SeSecurityPrivilege` on the current process token.
///
/// Returns [`NullDeviceError::PrivilegeMissing`] when the privilege is
/// not held by the token (the `ERROR_NOT_ALL_ASSIGNED` case from
/// `AdjustTokenPrivileges`) — the documented signal that the right
/// isn't merely disabled but absent.
pub fn enable_se_security_privilege() -> Result<(), NullDeviceError> {
    enable_privilege("SeSecurityPrivilege")
}

fn enable_privilege(name: &str) -> Result<(), NullDeviceError> {
    let mut wname: Vec<u16> = name.encode_utf16().collect();
    wname.push(0);

    let mut luid = LUID::default();
    unsafe {
        LookupPrivilegeValueW(PCWSTR::null(), PCWSTR(wname.as_ptr()), &mut luid).map_err(|e| {
            NullDeviceError::PrivilegeMissing(format!("LookupPrivilegeValueW({name}): {e}"))
        })?;
    }

    let mut token = HANDLE::default();
    unsafe {
        OpenProcessToken(
            GetCurrentProcess(),
            TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY,
            &mut token,
        )
        .map_err(|e| NullDeviceError::PrivilegeMissing(format!("OpenProcessToken: {e}")))?;
    }

    let privs = TOKEN_PRIVILEGES {
        PrivilegeCount: 1,
        Privileges: [LUID_AND_ATTRIBUTES {
            Luid: luid,
            Attributes: SE_PRIVILEGE_ENABLED,
        }],
    };

    let adjust = unsafe { AdjustTokenPrivileges(token, false, Some(&privs), 0, None, None) };
    // `AdjustTokenPrivileges` returns success even when the privilege
    // isn't held by the token (the documented quirk). The real signal
    // is the post-call GetLastError().
    let last = unsafe { GetLastError() };

    unsafe {
        let _ = CloseHandle(token);
    }

    if let Err(e) = adjust {
        return Err(NullDeviceError::PrivilegeMissing(format!(
            "AdjustTokenPrivileges({name}): {e}"
        )));
    }
    if last == ERROR_NOT_ALL_ASSIGNED {
        return Err(NullDeviceError::PrivilegeMissing(format!(
            "the calling token does not hold {name}; \
             run elevated, or pass `--no-sacl` to skip SACL operations"
        )));
    }
    Ok(())
}
