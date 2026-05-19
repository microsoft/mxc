// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Step 1b — create / derive a test AppContainer profile, look up its
//! per-user folder, and convert the SID to a string.
//!
//! This is the minimum logic needed to set up the virtualization root in
//! step 1c. It is intentionally *not* shared with `appcontainer_runner` in
//! `wxc_common` — keeping the probe a leaf crate makes the spike easier to
//! reason about and avoids accidental coupling to runtime code we may end
//! up replacing.

use std::fmt;
use std::path::PathBuf;

use serde::Serialize;

use windows::core::{PCWSTR, PWSTR};
use windows::Win32::Foundation::{LocalFree, HLOCAL};
use windows::Win32::Security::Authorization::ConvertSidToStringSidW;
use windows::Win32::Security::Isolation::{
    CreateAppContainerProfile, DeriveAppContainerSidFromAppContainerName,
    GetAppContainerFolderPath,
};
use windows::Win32::Security::PSID;
use windows::Win32::System::Com::CoTaskMemFree;

const HRESULT_ERROR_ALREADY_EXISTS: i32 = 0x8007_00B7u32 as i32;

/// Resolved AppContainer profile metadata for the probe.
#[derive(Debug, Clone, Serialize)]
pub(crate) struct AcProfile {
    /// Profile name passed to `CreateAppContainerProfile`.
    pub profile_name: String,
    /// SID in `S-1-15-...` form.
    pub sid_string: String,
    /// Per-user folder Windows assigns to the profile —
    /// `%LOCALAPPDATA%\Packages\<container-id>\AC\`-style path.
    pub folder_path: PathBuf,
}

/// Create the profile if missing, otherwise derive its SID. Either way,
/// return the metadata our later steps need.
pub(crate) fn ensure_profile(name: &str) -> Result<AcProfile, ProfileError> {
    let wide_name = to_wide(name);
    let pcwstr_name = PCWSTR(wide_name.as_ptr());

    let display = to_wide("MXC ProjFS spike");
    let desc = to_wide("Throwaway profile for ProjFS-T3 architecture probe");

    let create_result = unsafe {
        CreateAppContainerProfile(
            pcwstr_name,
            PCWSTR(display.as_ptr()),
            PCWSTR(desc.as_ptr()),
            None,
        )
    };

    let psid: PSID = match create_result {
        Ok(sid) => sid,
        Err(e) if e.code().0 == HRESULT_ERROR_ALREADY_EXISTS => {
            unsafe { DeriveAppContainerSidFromAppContainerName(pcwstr_name) }
                .map_err(|e| ProfileError::DeriveSid(format!("{e}")))?
        }
        Err(e) => return Err(ProfileError::CreateProfile(format!("{e}"))),
    };

    let sid_string = sid_to_string(psid)?;
    let folder_path = folder_path_for_sid(&sid_string)?;

    // CreateAppContainerProfile / DeriveAppContainerSidFromAppContainerName
    // allocate via the LocalAlloc family; the documented free is FreeSid.
    // We do not need the binary SID past this point.
    unsafe {
        let _ = FreeSid(psid);
    }

    Ok(AcProfile {
        profile_name: name.to_string(),
        sid_string,
        folder_path,
    })
}

/// Resolve the profile's per-user folder given the SID string.
pub(crate) fn folder_path_for_sid(sid_string: &str) -> Result<PathBuf, ProfileError> {
    let wide_sid = to_wide(sid_string);
    let pcwstr = PCWSTR(wide_sid.as_ptr());

    // GetAppContainerFolderPath returns a CoTaskMemAlloc'd PWSTR via Result.
    let raw: PWSTR = unsafe {
        GetAppContainerFolderPath(pcwstr)
            .map_err(|e| ProfileError::FolderPath(format!("{e}")))?
    };

    let path = unsafe { pwstr_to_string(raw)? };
    unsafe {
        CoTaskMemFree(Some(raw.as_ptr() as *const _));
    }
    Ok(PathBuf::from(path))
}

unsafe fn pwstr_to_string(p: PWSTR) -> Result<String, ProfileError> {
    if p.is_null() {
        return Err(ProfileError::Internal(
            "received null PWSTR".to_string(),
        ));
    }
    let mut len = 0usize;
    while *p.as_ptr().add(len) != 0 {
        len += 1;
        if len > 32_768 {
            return Err(ProfileError::Internal(
                "PWSTR absurdly long".to_string(),
            ));
        }
    }
    let slice = std::slice::from_raw_parts(p.as_ptr(), len);
    String::from_utf16(slice).map_err(|e| ProfileError::Internal(format!("utf16 decode: {e}")))
}

fn sid_to_string(psid: PSID) -> Result<String, ProfileError> {
    let mut out: PWSTR = PWSTR::null();
    unsafe {
        ConvertSidToStringSidW(psid, &mut out as *mut _)
            .map_err(|e| ProfileError::SidToString(format!("{e}")))?;
    }
    let s = unsafe { pwstr_to_string(out)? };
    unsafe {
        let _ = LocalFree(Some(HLOCAL(out.as_ptr() as *mut _)));
    }
    Ok(s)
}

fn to_wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

#[derive(Debug)]
pub(crate) enum ProfileError {
    CreateProfile(String),
    DeriveSid(String),
    SidToString(String),
    FolderPath(String),
    Internal(String),
}

impl fmt::Display for ProfileError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ProfileError::CreateProfile(s) => write!(f, "CreateAppContainerProfile failed: {s}"),
            ProfileError::DeriveSid(s) => {
                write!(f, "DeriveAppContainerSidFromAppContainerName failed: {s}")
            }
            ProfileError::SidToString(s) => write!(f, "ConvertSidToStringSidW failed: {s}"),
            ProfileError::FolderPath(s) => write!(f, "GetAppContainerFolderPath failed: {s}"),
            ProfileError::Internal(s) => write!(f, "internal: {s}"),
        }
    }
}

impl std::error::Error for ProfileError {}

// FreeSid lives in advapi32.dll. The windows crate exposes it via
// `Win32::Security::Authorization::FreeSid` in some feature combinations,
// but declaring the extern keeps this module dependency-light and feature-
// flag-independent.
#[link(name = "advapi32")]
extern "system" {
    fn FreeSid(psid: PSID) -> *mut core::ffi::c_void;
}
