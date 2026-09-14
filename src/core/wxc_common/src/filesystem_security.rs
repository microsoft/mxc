// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Owner-only ACL helpers for MXC-managed files and directories.

use std::ffi::c_void;
use std::os::windows::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::ptr;

use windows::core::{PCWSTR, PWSTR};
use windows::Win32::Foundation::{LocalFree, ERROR_SUCCESS, HANDLE, HLOCAL, WIN32_ERROR};
use windows::Win32::Security::Authorization::{
    ConvertSidToStringSidW, ConvertStringSidToSidW, GetNamedSecurityInfoW, SetEntriesInAclW,
    SetNamedSecurityInfoW, EXPLICIT_ACCESS_W, GRANT_ACCESS, SE_FILE_OBJECT, TRUSTEE_IS_SID,
    TRUSTEE_IS_UNKNOWN, TRUSTEE_W,
};
use windows::Win32::Security::{
    EqualSid, GetTokenInformation, IsValidSid, TokenOwner, TokenUser, ACE_FLAGS, ACL,
    CONTAINER_INHERIT_ACE, DACL_SECURITY_INFORMATION, OBJECT_INHERIT_ACE,
    OBJECT_SECURITY_INFORMATION, OWNER_SECURITY_INFORMATION, PROTECTED_DACL_SECURITY_INFORMATION,
    PSECURITY_DESCRIPTOR, PSID, TOKEN_INFORMATION_CLASS, TOKEN_OWNER, TOKEN_QUERY, TOKEN_USER,
};
use windows::Win32::Storage::FileSystem::FILE_ALL_ACCESS;
use windows::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

/// Failure to inspect or secure an MXC-owned filesystem object.
#[derive(Debug, thiserror::Error)]
pub enum FilesystemSecurityError {
    /// A Windows security API failed.
    #[error("{reason} for '{path}'")]
    Win32 { path: PathBuf, reason: String },
    /// The filesystem object is not owned by this process identity.
    #[error("refusing to secure foreign-owned path '{0}'")]
    ForeignOwner(PathBuf),
    /// A SID returned by Windows was invalid.
    #[error("invalid SID: {0}")]
    InvalidSid(String),
}

struct OwnedSid(PSID);

struct OwnedToken(HANDLE);

impl Drop for OwnedToken {
    fn drop(&mut self) {
        if !self.0.is_invalid() {
            unsafe {
                let _ = windows::Win32::Foundation::CloseHandle(self.0);
            }
        }
    }
}

impl OwnedSid {
    fn parse(value: &str) -> Result<Self, FilesystemSecurityError> {
        let wide: Vec<u16> = value.encode_utf16().chain(std::iter::once(0)).collect();
        let mut sid = PSID(ptr::null_mut());
        unsafe {
            ConvertStringSidToSidW(PCWSTR(wide.as_ptr()), &mut sid)
                .map_err(|error| FilesystemSecurityError::InvalidSid(error.to_string()))?;
            if sid.0.is_null() || !IsValidSid(sid).as_bool() {
                if !sid.0.is_null() {
                    let _ = LocalFree(Some(HLOCAL(sid.0)));
                }
                return Err(FilesystemSecurityError::InvalidSid(value.to_string()));
            }
        }
        Ok(Self(sid))
    }

    fn as_psid(&self) -> PSID {
        self.0
    }
}

impl Drop for OwnedSid {
    fn drop(&mut self) {
        if !self.0 .0.is_null() {
            unsafe {
                let _ = LocalFree(Some(HLOCAL(self.0 .0)));
            }
        }
    }
}

fn wide(path: &Path) -> Vec<u16> {
    path.as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect()
}

fn win32_error(path: &Path, operation: &str, error: WIN32_ERROR) -> FilesystemSecurityError {
    FilesystemSecurityError::Win32 {
        path: path.to_path_buf(),
        reason: format!("{operation}: {error:?}"),
    }
}

fn message_error(path: &Path, message: impl Into<String>) -> FilesystemSecurityError {
    FilesystemSecurityError::Win32 {
        path: path.to_path_buf(),
        reason: message.into(),
    }
}

fn trustee(sid: &OwnedSid) -> TRUSTEE_W {
    TRUSTEE_W {
        pMultipleTrustee: ptr::null_mut(),
        MultipleTrusteeOperation: windows::Win32::Security::Authorization::NO_MULTIPLE_TRUSTEE,
        TrusteeForm: TRUSTEE_IS_SID,
        TrusteeType: TRUSTEE_IS_UNKNOWN,
        ptstrName: PWSTR(sid.as_psid().0.cast()),
    }
}

fn owned_sid_from_psid(
    sid: PSID,
    path: &Path,
    context: &str,
) -> Result<OwnedSid, FilesystemSecurityError> {
    let mut string_sid = PWSTR::null();
    unsafe {
        ConvertSidToStringSidW(sid, &mut string_sid)
            .map_err(|error| message_error(path, format!("{context}: {error}")))?;
    }
    let sid_string = unsafe { string_sid.to_string() }
        .map_err(|error| FilesystemSecurityError::InvalidSid(error.to_string()));
    if !string_sid.is_null() {
        unsafe {
            let _ = LocalFree(Some(HLOCAL(string_sid.0.cast())));
        }
    }
    OwnedSid::parse(&sid_string?)
}

fn token_sid(
    information_class: TOKEN_INFORMATION_CLASS,
    label: &str,
    extract: impl FnOnce(&[u8]) -> PSID,
) -> Result<OwnedSid, FilesystemSecurityError> {
    let path = Path::new("<process token>");
    unsafe {
        let mut token = HANDLE::default();
        OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token)
            .map_err(|error| message_error(path, format!("OpenProcessToken: {error}")))?;
        let _token = OwnedToken(token);

        let mut length = 0;
        let probe = GetTokenInformation(token, information_class, None, 0, &mut length);
        if probe.is_ok() || length == 0 {
            return Err(message_error(
                path,
                format!("GetTokenInformation({label}) size probe failed"),
            ));
        }

        let mut buffer = vec![0u8; length as usize];
        GetTokenInformation(
            token,
            information_class,
            Some(buffer.as_mut_ptr().cast()),
            length,
            &mut length,
        )
        .map_err(|error| message_error(path, format!("GetTokenInformation({label}): {error}")))?;
        owned_sid_from_psid(extract(&buffer), path, label)
    }
}

fn current_user_sid() -> Result<OwnedSid, FilesystemSecurityError> {
    token_sid(TokenUser, "TokenUser", |buffer| unsafe {
        (*(buffer.as_ptr() as *const TOKEN_USER)).User.Sid
    })
}

fn current_token_owner_sid() -> Result<OwnedSid, FilesystemSecurityError> {
    token_sid(TokenOwner, "TokenOwner", |buffer| unsafe {
        (*(buffer.as_ptr() as *const TOKEN_OWNER)).Owner
    })
}

/// Whether `path` is owned by the current process's user or token owner.
pub fn owner_is_self(path: &Path) -> Result<bool, FilesystemSecurityError> {
    let mut accepted = vec![current_user_sid()?];
    if let Ok(owner) = current_token_owner_sid() {
        accepted.push(owner);
    }

    let path_wide = wide(path);
    let mut owner = PSID(ptr::null_mut());
    let mut descriptor = PSECURITY_DESCRIPTOR(ptr::null_mut());
    let result = unsafe {
        GetNamedSecurityInfoW(
            PCWSTR(path_wide.as_ptr()),
            SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION,
            Some(&mut owner),
            None,
            None,
            None,
            &mut descriptor,
        )
    };
    if result != ERROR_SUCCESS {
        return Err(win32_error(path, "GetNamedSecurityInfoW(owner)", result));
    }

    let matches = !owner.0.is_null()
        && accepted
            .iter()
            .any(|candidate| unsafe { EqualSid(owner, candidate.as_psid()).is_ok() });
    unsafe {
        let _ = LocalFree(Some(HLOCAL(descriptor.0)));
    }
    Ok(matches)
}

/// Replace the target DACL with protected full-control entries for the current
/// user and Local SYSTEM.
pub fn set_owner_only_dacl(path: &Path, inheritable: bool) -> Result<(), FilesystemSecurityError> {
    if !owner_is_self(path)? {
        return Err(FilesystemSecurityError::ForeignOwner(path.to_path_buf()));
    }

    let user = current_user_sid()?;
    let system = OwnedSid::parse("S-1-5-18")?;
    let inheritance = if inheritable {
        OBJECT_INHERIT_ACE.0 | CONTAINER_INHERIT_ACE.0
    } else {
        0
    };
    let grant = |sid: &OwnedSid| EXPLICIT_ACCESS_W {
        grfAccessPermissions: FILE_ALL_ACCESS.0,
        grfAccessMode: GRANT_ACCESS,
        grfInheritance: ACE_FLAGS(inheritance),
        Trustee: trustee(sid),
    };
    let entries = [grant(&user), grant(&system)];
    let mut dacl: *mut ACL = ptr::null_mut();
    let result = unsafe { SetEntriesInAclW(Some(&entries), None, &mut dacl) };
    if result != ERROR_SUCCESS {
        return Err(win32_error(path, "SetEntriesInAclW", result));
    }

    let path_wide = wide(path);
    let information = OBJECT_SECURITY_INFORMATION(
        DACL_SECURITY_INFORMATION.0 | PROTECTED_DACL_SECURITY_INFORMATION.0,
    );
    let result = unsafe {
        SetNamedSecurityInfoW(
            PCWSTR(path_wide.as_ptr()),
            SE_FILE_OBJECT,
            information,
            None,
            None,
            Some(dacl.cast_const()),
            None,
        )
    };
    unsafe {
        if !dacl.is_null() {
            let _ = LocalFree(Some(HLOCAL(dacl.cast::<c_void>())));
        }
    }
    if result != ERROR_SUCCESS {
        return Err(win32_error(path, "SetNamedSecurityInfoW", result));
    }
    Ok(())
}
