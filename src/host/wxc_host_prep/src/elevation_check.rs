// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Defence-in-depth elevation check.
//!
//! The application manifest declares `requireAdministrator`, so the OS
//! loader guarantees the process is elevated before `main` runs. This
//! check exists for the corner case where someone strips the manifest
//! or invokes the binary via an unusual launcher that bypasses the
//! manifest contract. If we ever lose the elevation invariant the
//! Win32 ACL calls would fail anyway, but failing early with a clear
//! exit code is friendlier than letting `SetKernelObjectSecurity`
//! return `ERROR_ACCESS_DENIED` deep inside an operation.

use windows::Win32::Foundation::{CloseHandle, HANDLE};
use windows::Win32::Security::{GetTokenInformation, TokenElevation, TOKEN_ELEVATION, TOKEN_QUERY};
use windows::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

#[derive(Debug, thiserror::Error)]
pub enum ElevationError {
    #[error("could not query process token: {0}")]
    TokenQuery(String),
    #[error(
        "wxc-host-prep was launched without an elevated token. The embedded application \
         manifest should normally prevent this; if you stripped or replaced the manifest, \
         relaunch from an elevated shell."
    )]
    NotElevated,
}

/// Returns `Ok(())` when the process is running with an elevated
/// token (`TokenIsElevated != 0`). Returns
/// [`ElevationError::NotElevated`] otherwise.
pub fn require_elevated() -> Result<(), ElevationError> {
    if is_token_elevated()? {
        Ok(())
    } else {
        Err(ElevationError::NotElevated)
    }
}

fn is_token_elevated() -> Result<bool, ElevationError> {
    let mut token: HANDLE = HANDLE::default();
    unsafe {
        OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token)
            .map_err(|e| ElevationError::TokenQuery(format!("OpenProcessToken: {e}")))?;
    }
    let mut info = TOKEN_ELEVATION::default();
    let mut size = 0u32;
    let result = unsafe {
        GetTokenInformation(
            token,
            TokenElevation,
            Some(&mut info as *mut _ as *mut std::ffi::c_void),
            std::mem::size_of::<TOKEN_ELEVATION>() as u32,
            &mut size,
        )
    };
    unsafe {
        let _ = CloseHandle(token);
    }
    result.map_err(|e| ElevationError::TokenQuery(format!("GetTokenInformation: {e}")))?;
    Ok(info.TokenIsElevated != 0)
}
