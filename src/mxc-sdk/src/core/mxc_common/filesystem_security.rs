// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Owner-only ACL helpers for MXC-managed files and directories.

use std::ffi::c_void;
use std::os::windows::ffi::OsStrExt;
use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};
use std::path::{Component, Prefix};
use std::path::{Path, PathBuf};
use std::ptr::{self, NonNull};

use windows::core::{PCWSTR, PWSTR};
use windows::Win32::Foundation::{
    LocalFree, ERROR_SUCCESS, HANDLE, HLOCAL, INVALID_HANDLE_VALUE, WIN32_ERROR,
};
use windows::Win32::Security::Authorization::{
    ConvertSidToStringSidW, ConvertStringSecurityDescriptorToSecurityDescriptorW,
    ConvertStringSidToSidW, GetNamedSecurityInfoW, GetSecurityInfo, SetEntriesInAclW,
    SetNamedSecurityInfoW, EXPLICIT_ACCESS_W, GRANT_ACCESS, SDDL_REVISION_1, SE_FILE_OBJECT,
    TRUSTEE_IS_SID, TRUSTEE_IS_UNKNOWN, TRUSTEE_W,
};
use windows::Win32::Security::{
    AclSizeInformation, EqualSid, GetAce, GetAclInformation, GetSecurityDescriptorControl,
    GetTokenInformation, IsValidSid, TokenOwner, TokenUser, ACCESS_ALLOWED_ACE, ACE_FLAGS,
    ACE_HEADER, ACL, ACL_SIZE_INFORMATION, CONTAINER_INHERIT_ACE, DACL_SECURITY_INFORMATION,
    OBJECT_INHERIT_ACE, OBJECT_SECURITY_INFORMATION, OWNER_SECURITY_INFORMATION,
    PROTECTED_DACL_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR, PSID, SE_DACL_PROTECTED,
    TOKEN_INFORMATION_CLASS, TOKEN_OWNER, TOKEN_QUERY, TOKEN_USER,
};
use windows::Win32::Storage::FileSystem::{
    CreateFileW, GetFileInformationByHandle, BY_HANDLE_FILE_INFORMATION, FILE_ALL_ACCESS,
    FILE_ATTRIBUTE_DIRECTORY, FILE_ATTRIBUTE_NORMAL, FILE_ATTRIBUTE_REPARSE_POINT,
    FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT, FILE_LIST_DIRECTORY,
    FILE_READ_ATTRIBUTES, FILE_SHARE_READ, FILE_SHARE_WRITE, OPEN_EXISTING, READ_CONTROL,
    SYNCHRONIZE,
};
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

/// An absolute directory path whose existing components are held open without
/// delete sharing, preventing replacement while the guard is alive.
#[derive(Debug)]
pub struct LockedDirectoryPath {
    path: PathBuf,
    _handles: Vec<OwnedHandle>,
}

impl LockedDirectoryPath {
    pub fn path(&self) -> &Path {
        &self.path
    }
}

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

fn sid_string(sid: PSID, path: &Path) -> Result<String, FilesystemSecurityError> {
    let mut string_sid = PWSTR::null();
    unsafe {
        ConvertSidToStringSidW(sid, &mut string_sid)
            .map_err(|error| message_error(path, format!("ConvertSidToStringSidW: {error}")))?;
    }
    let result = unsafe { string_sid.to_string() }
        .map_err(|error| FilesystemSecurityError::InvalidSid(error.to_string()));
    if !string_sid.is_null() {
        unsafe {
            let _ = LocalFree(Some(HLOCAL(string_sid.0.cast())));
        }
    }
    result
}

struct OwnedSecurityDescriptor(PSECURITY_DESCRIPTOR);

impl Drop for OwnedSecurityDescriptor {
    fn drop(&mut self) {
        if !self.0 .0.is_null() {
            unsafe {
                let _ = LocalFree(Some(HLOCAL(self.0 .0)));
            }
        }
    }
}

fn owner_only_security_descriptor(
    path: &Path,
) -> Result<OwnedSecurityDescriptor, FilesystemSecurityError> {
    let user = current_user_sid()?;
    owner_only_security_descriptor_for_user(user.as_psid(), path)
}

fn owner_only_security_descriptor_for_user(
    user: PSID,
    path: &Path,
) -> Result<OwnedSecurityDescriptor, FilesystemSecurityError> {
    let system = OwnedSid::parse("S-1-5-18")?;
    let sddl = if unsafe { EqualSid(user, system.as_psid()).is_ok() } {
        "D:P(A;OICI;FA;;;SY)".to_owned()
    } else {
        let user = sid_string(user, path)?;
        format!("D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;{user})")
    };
    let wide: Vec<u16> = sddl.encode_utf16().chain(std::iter::once(0)).collect();
    let mut descriptor = PSECURITY_DESCRIPTOR::default();
    unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            PCWSTR(wide.as_ptr()),
            SDDL_REVISION_1,
            &mut descriptor,
            None,
        )
        .map_err(|error| {
            message_error(
                path,
                format!("ConvertStringSecurityDescriptorToSecurityDescriptorW: {error}"),
            )
        })?;
    }
    Ok(OwnedSecurityDescriptor(descriptor))
}

#[repr(C)]
struct UnicodeString {
    length: u16,
    maximum_length: u16,
    buffer: *mut u16,
}

#[repr(C)]
struct ObjectAttributes {
    length: u32,
    root_directory: HANDLE,
    object_name: *mut UnicodeString,
    attributes: u32,
    security_descriptor: *mut c_void,
    security_quality_of_service: *mut c_void,
}

#[repr(C)]
struct IoStatusBlock {
    status: isize,
    information: usize,
}

#[link(name = "ntdll")]
unsafe extern "system" {
    fn NtCreateFile(
        file_handle: *mut HANDLE,
        desired_access: u32,
        object_attributes: *const ObjectAttributes,
        io_status_block: *mut IoStatusBlock,
        allocation_size: *const i64,
        file_attributes: u32,
        share_access: u32,
        create_disposition: u32,
        create_options: u32,
        ea_buffer: *const c_void,
        ea_length: u32,
    ) -> i32;
}

const OBJ_CASE_INSENSITIVE: u32 = 0x40;
const FILE_OPEN: u32 = 1;
const FILE_OPEN_IF: u32 = 3;
const FILE_DIRECTORY_FILE: u32 = 0x1;
const FILE_SYNCHRONOUS_IO_NONALERT: u32 = 0x20;
const FILE_OPEN_REPARSE_POINT_NT: u32 = 0x0020_0000;

fn owned_handle(handle: HANDLE, path: &Path) -> Result<OwnedHandle, FilesystemSecurityError> {
    if handle.is_invalid() {
        return Err(message_error(
            path,
            "Windows returned an invalid directory handle",
        ));
    }
    Ok(unsafe { OwnedHandle::from_raw_handle(handle.0) })
}

fn open_volume_root(path: &Path) -> Result<OwnedHandle, FilesystemSecurityError> {
    let wide = wide(path);
    let handle = unsafe {
        CreateFileW(
            PCWSTR(wide.as_ptr()),
            FILE_LIST_DIRECTORY.0 | FILE_READ_ATTRIBUTES.0 | READ_CONTROL.0 | SYNCHRONIZE.0,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            None,
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL | FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT,
            None,
        )
    }
    .map_err(|error| message_error(path, format!("CreateFileW(directory): {error}")))?;
    if handle == INVALID_HANDLE_VALUE {
        return Err(message_error(
            path,
            "CreateFileW returned INVALID_HANDLE_VALUE",
        ));
    }
    owned_handle(handle, path)
}

fn open_relative_directory(
    parent: &OwnedHandle,
    name: &std::ffi::OsStr,
    path: &Path,
    create: bool,
    descriptor: Option<&OwnedSecurityDescriptor>,
) -> Result<OwnedHandle, FilesystemSecurityError> {
    let mut name: Vec<u16> = name.encode_wide().collect();
    let byte_length = name
        .len()
        .checked_mul(std::mem::size_of::<u16>())
        .and_then(|length| u16::try_from(length).ok())
        .ok_or_else(|| message_error(path, "directory component is too long"))?;
    let mut unicode = UnicodeString {
        length: byte_length,
        maximum_length: byte_length,
        buffer: name.as_mut_ptr(),
    };
    let attributes = ObjectAttributes {
        length: std::mem::size_of::<ObjectAttributes>() as u32,
        root_directory: HANDLE(parent.as_raw_handle()),
        object_name: &mut unicode,
        attributes: OBJ_CASE_INSENSITIVE,
        security_descriptor: descriptor.map_or(ptr::null_mut(), |value| value.0 .0),
        security_quality_of_service: ptr::null_mut(),
    };
    let mut handle = HANDLE::default();
    let mut io_status = IoStatusBlock {
        status: 0,
        information: 0,
    };
    let status = unsafe {
        NtCreateFile(
            &mut handle,
            FILE_LIST_DIRECTORY.0 | FILE_READ_ATTRIBUTES.0 | READ_CONTROL.0 | SYNCHRONIZE.0,
            &attributes,
            &mut io_status,
            ptr::null(),
            FILE_ATTRIBUTE_NORMAL.0,
            (FILE_SHARE_READ | FILE_SHARE_WRITE).0,
            if create { FILE_OPEN_IF } else { FILE_OPEN },
            FILE_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT | FILE_OPEN_REPARSE_POINT_NT,
            ptr::null(),
            0,
        )
    };
    if status < 0 {
        return Err(message_error(
            path,
            format!("NtCreateFile(directory) failed with NTSTATUS 0x{status:08x}"),
        ));
    }
    owned_handle(handle, path)
}

fn validate_directory_handle(
    handle: &OwnedHandle,
    path: &Path,
) -> Result<(), FilesystemSecurityError> {
    let mut information = BY_HANDLE_FILE_INFORMATION::default();
    unsafe { GetFileInformationByHandle(HANDLE(handle.as_raw_handle()), &mut information) }
        .map_err(|error| message_error(path, format!("GetFileInformationByHandle: {error}")))?;
    if information.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY.0 == 0
        || information.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT.0 != 0
    {
        return Err(message_error(
            path,
            "expected a directory without a reparse point",
        ));
    }
    Ok(())
}

fn owner_only_directory_handle(
    handle: &OwnedHandle,
    path: &Path,
) -> Result<bool, FilesystemSecurityError> {
    let mut owner = PSID(ptr::null_mut());
    let mut dacl: *mut ACL = ptr::null_mut();
    let mut descriptor = PSECURITY_DESCRIPTOR::default();
    let result = unsafe {
        GetSecurityInfo(
            HANDLE(handle.as_raw_handle()),
            SE_FILE_OBJECT,
            OBJECT_SECURITY_INFORMATION(OWNER_SECURITY_INFORMATION.0 | DACL_SECURITY_INFORMATION.0),
            Some(&mut owner),
            None,
            Some(&mut dacl),
            None,
            Some(&mut descriptor),
        )
    };
    if result != ERROR_SUCCESS {
        return Err(win32_error(path, "GetSecurityInfo", result));
    }
    let validation = validate_owner_only_acl(owner, dacl, descriptor, path);
    unsafe {
        let _ = LocalFree(Some(HLOCAL(descriptor.0)));
    }
    validation
}

/// Atomically creates or opens `components` below `base`, applies the protected
/// owner/SYSTEM DACL at creation, validates private components by handle, and
/// holds every path component open without delete sharing.
/// Non-verbatim components ending in a dot or space are rejected before setup.
pub fn lock_owner_only_directory_path(
    base: &Path,
    components: &[&std::ffi::OsStr],
    private_from: usize,
) -> Result<LockedDirectoryPath, FilesystemSecurityError> {
    let mut base_components = base.components();
    let Some(Component::Prefix(prefix)) = base_components.next() else {
        return Err(message_error(base, "expected an absolute drive path"));
    };
    if !matches!(base_components.next(), Some(Component::RootDir)) {
        return Err(message_error(base, "expected an absolute drive path"));
    }
    if !prefix.kind().is_verbatim() {
        let ambiguous =
            |name: &std::ffi::OsStr| matches!(name.encode_wide().last(), Some(0x2e | 0x20));
        let supplied_components = components
            .iter()
            .flat_map(|name| Path::new(name).components());
        // Relative NT opens preserve names that non-verbatim native setup may trim.
        if base
            .components()
            .chain(supplied_components)
            .any(|component| match component {
                Component::Normal(name) => ambiguous(name),
                Component::Prefix(prefix) => match prefix.kind() {
                    Prefix::UNC(server, share) => ambiguous(server) || ambiguous(share),
                    _ => false,
                },
                _ => false,
            })
        {
            return Err(message_error(
                base,
                "ambiguous non-verbatim directory component ends in a dot or space; \
                 use names without trailing dots or spaces, or an explicit verbatim path",
            ));
        }
    }
    let mut root = prefix.as_os_str().to_os_string();
    root.push("\\");
    let root = PathBuf::from(root);
    let mut handles = vec![open_volume_root(&root)?];
    let mut current = root;
    for component in base_components {
        let Component::Normal(name) = component else {
            return Err(message_error(
                base,
                "path contains an unsupported component",
            ));
        };
        current.push(name);
        let handle = open_relative_directory(
            handles.last().expect("volume root handle"),
            name,
            &current,
            false,
            None,
        )?;
        validate_directory_handle(&handle, &current)?;
        handles.push(handle);
    }

    let descriptor = owner_only_security_descriptor(base)?;
    for (index, name) in components.iter().enumerate() {
        current.push(name);
        let handle = open_relative_directory(
            handles.last().expect("base directory handle"),
            name,
            &current,
            true,
            Some(&descriptor),
        )?;
        validate_directory_handle(&handle, &current)?;
        if index >= private_from && !owner_only_directory_handle(&handle, &current)? {
            return Err(message_error(
                &current,
                "owner or ACL is not the protected current-user and Local SYSTEM DACL",
            ));
        }
        handles.push(handle);
    }
    Ok(LockedDirectoryPath {
        path: current,
        _handles: handles,
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

/// Whether a directory has the exact protected owner-only DACL written by
/// [`set_owner_only_dacl`].
pub fn is_owner_only_directory(path: &Path) -> Result<bool, FilesystemSecurityError> {
    let path_wide = wide(path);
    let mut owner = PSID(ptr::null_mut());
    let mut dacl: *mut ACL = ptr::null_mut();
    let mut descriptor = PSECURITY_DESCRIPTOR::default();
    let result = unsafe {
        GetNamedSecurityInfoW(
            PCWSTR(path_wide.as_ptr()),
            SE_FILE_OBJECT,
            OBJECT_SECURITY_INFORMATION(OWNER_SECURITY_INFORMATION.0 | DACL_SECURITY_INFORMATION.0),
            Some(&mut owner),
            None,
            Some(&mut dacl),
            None,
            &mut descriptor,
        )
    };
    if result != ERROR_SUCCESS {
        return Err(win32_error(path, "GetNamedSecurityInfoW(DACL)", result));
    }

    let validation = validate_owner_only_acl(owner, dacl, descriptor, path);
    unsafe {
        let _ = LocalFree(Some(HLOCAL(descriptor.0)));
    }
    validation
}

fn validate_owner_only_acl(
    owner: PSID,
    dacl: *mut ACL,
    descriptor: PSECURITY_DESCRIPTOR,
    path: &Path,
) -> Result<bool, FilesystemSecurityError> {
    let user = current_user_sid()?;
    let token_owner = current_token_owner_sid().ok();
    validate_owner_only_acl_for_user(
        owner,
        dacl,
        descriptor,
        path,
        user.as_psid(),
        token_owner.as_ref().map(OwnedSid::as_psid),
    )
}

fn validate_owner_only_acl_for_user(
    owner: PSID,
    dacl: *mut ACL,
    descriptor: PSECURITY_DESCRIPTOR,
    path: &Path,
    user: PSID,
    token_owner: Option<PSID>,
) -> Result<bool, FilesystemSecurityError> {
    let system = OwnedSid::parse("S-1-5-18")?;
    let same_identity = unsafe { EqualSid(user, system.as_psid()).is_ok() };
    if owner.0.is_null()
        || (!unsafe { EqualSid(owner, user).is_ok() }
            && !token_owner
                .as_ref()
                .is_some_and(|candidate| unsafe { EqualSid(owner, *candidate).is_ok() }))
    {
        return Ok(false);
    }

    (|| {
        if dacl.is_null() {
            return Ok(false);
        }
        let mut control = 0u16;
        let mut revision = 0u32;
        unsafe { GetSecurityDescriptorControl(descriptor, &mut control, &mut revision) }.map_err(
            |error| message_error(path, format!("GetSecurityDescriptorControl: {error}")),
        )?;
        if control & SE_DACL_PROTECTED.0 == 0 {
            return Ok(false);
        }

        let mut information = ACL_SIZE_INFORMATION::default();
        unsafe {
            GetAclInformation(
                dacl,
                (&mut information as *mut ACL_SIZE_INFORMATION).cast(),
                std::mem::size_of::<ACL_SIZE_INFORMATION>() as u32,
                AclSizeInformation,
            )
        }
        .map_err(|error| message_error(path, format!("GetAclInformation: {error}")))?;
        if information.AceCount != if same_identity { 1 } else { 2 } {
            return Ok(false);
        }

        let expected_flags = (OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE).0 as u8;
        let mut user_grant = false;
        let mut system_grant = false;
        for index in 0..information.AceCount {
            let mut ace = ptr::null_mut();
            unsafe { GetAce(dacl, index, &mut ace) }
                .map_err(|error| message_error(path, format!("GetAce: {error}")))?;
            let Some(ace) = NonNull::new(ace) else {
                return Ok(false);
            };
            let header = unsafe { ace.cast::<ACE_HEADER>().as_ref() };
            if header.AceType != 0
                || header.AceFlags != expected_flags
                || header.AceSize < std::mem::size_of::<ACCESS_ALLOWED_ACE>() as u16
            {
                return Ok(false);
            }
            let allowed = unsafe { ace.cast::<ACCESS_ALLOWED_ACE>().as_ref() };
            if allowed.Mask != FILE_ALL_ACCESS.0 {
                return Ok(false);
            }
            let sid = PSID((&raw const allowed.SidStart).cast_mut().cast());
            if unsafe { EqualSid(sid, user).is_ok() } {
                if user_grant {
                    return Ok(false);
                }
                user_grant = true;
                if same_identity {
                    system_grant = true;
                }
            } else if unsafe { EqualSid(sid, system.as_psid()).is_ok() } {
                if system_grant {
                    return Ok(false);
                }
                system_grant = true;
            } else {
                return Ok(false);
            }
        }
        Ok(user_grant && system_grant)
    })()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ptr::NonNull;
    use windows::Win32::Security::{
        AclSizeInformation, GetAce, GetAclInformation, ACCESS_ALLOWED_ACE, ACE_HEADER,
        ACL_SIZE_INFORMATION, INHERITED_ACE,
    };

    #[test]
    fn owner_is_self_true_for_dir_we_create() {
        let directory = tempfile::tempdir().expect("create directory");
        assert!(owner_is_self(directory.path()).expect("read owner"));
    }

    #[test]
    fn owner_is_self_true_after_owner_only_stamp() {
        let directory = tempfile::tempdir().expect("create directory");
        set_owner_only_dacl(directory.path(), true).expect("secure directory");
        assert!(owner_is_self(directory.path()).expect("read owner"));
    }

    #[test]
    fn set_owner_only_dacl_strips_inheritance_and_grants_owner() {
        let parent = tempfile::tempdir().expect("create parent");
        set_owner_only_dacl(parent.path(), true).expect("secure inheritable parent");
        let child = parent.path().join("child");
        std::fs::create_dir(&child).expect("create child");
        assert_owner_acl(&child, true);
        set_owner_only_dacl(&child, true).expect("secure child");
        assert_owner_acl(&child, false);
    }

    fn assert_owner_acl(path: &Path, inherited: bool) {
        let user = current_user_sid().expect("current user");
        let system = OwnedSid::parse("S-1-5-18").expect("SYSTEM");
        let mut dacl = ptr::null_mut();
        let mut descriptor = PSECURITY_DESCRIPTOR::default();
        let result = unsafe {
            GetNamedSecurityInfoW(
                PCWSTR(wide(path).as_ptr()),
                SE_FILE_OBJECT,
                DACL_SECURITY_INFORMATION,
                None,
                None,
                Some(&mut dacl),
                None,
                &mut descriptor,
            )
        };
        assert_eq!(result, ERROR_SUCCESS);
        let mut information = ACL_SIZE_INFORMATION::default();
        unsafe {
            GetAclInformation(
                dacl,
                (&mut information as *mut ACL_SIZE_INFORMATION).cast(),
                std::mem::size_of::<ACL_SIZE_INFORMATION>() as u32,
                AclSizeInformation,
            )
            .expect("ACL size");
            let same_identity = EqualSid(user.as_psid(), system.as_psid()).is_ok();
            assert_eq!(information.AceCount, if same_identity { 1 } else { 2 });
            for index in 0..information.AceCount {
                let mut raw = ptr::null_mut();
                GetAce(dacl, index, &mut raw).expect("read ACE");
                let raw = NonNull::new(raw).expect("GetAce returned a null ACE");
                // SAFETY: GetAce succeeded; the ACE belongs to the live descriptor.
                let header = raw.cast::<ACE_HEADER>().as_ref();
                assert_eq!(header.AceType, 0, "only access-allowed ACEs");
                let ace = raw.cast::<ACCESS_ALLOWED_ACE>().as_ref();
                assert_eq!(ace.Mask, FILE_ALL_ACCESS.0);
                assert_eq!(
                    (u32::from(ace.Header.AceFlags) & INHERITED_ACE.0) != 0,
                    inherited
                );
                let sid = PSID((&ace.SidStart as *const u32).cast_mut().cast());
                assert!(
                    EqualSid(sid, user.as_psid()).is_ok()
                        || EqualSid(sid, system.as_psid()).is_ok()
                );
            }
            let _ = LocalFree(Some(HLOCAL(descriptor.0)));
        }
    }
}
