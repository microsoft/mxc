// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Secure elevated scratch storage for the embedded WPR profile and ETL.

use anyhow::{bail, Context, Result};
use std::ffi::OsStr;
use std::fmt;
use std::io::{Read, Write};
use std::os::windows::ffi::OsStrExt;
use std::os::windows::io::{AsRawHandle, FromRawHandle};
use std::path::{Component, Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};

use windows::core::{HRESULT, PCWSTR, PWSTR};
use windows::Win32::Foundation::{
    CloseHandle, LocalFree, ERROR_ALREADY_EXISTS, ERROR_FILE_EXISTS, ERROR_FILE_NOT_FOUND,
    ERROR_PATH_NOT_FOUND, HANDLE, HLOCAL,
};
use windows::Win32::Security::Authorization::{
    ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1,
};
use windows::Win32::Security::{
    SetKernelObjectSecurity, DACL_SECURITY_INFORMATION, LABEL_SECURITY_INFORMATION,
    PSECURITY_DESCRIPTOR, SECURITY_ATTRIBUTES,
};
use windows::Win32::Storage::FileSystem::{
    CreateDirectoryW, CreateFileW, DeleteFileW, FileAttributeTagInfo, FileIdInfo, FlushFileBuffers,
    GetDriveTypeW, GetFileInformationByHandleEx, GetFileSizeEx, GetVolumeInformationW,
    RemoveDirectoryW, CREATE_NEW, FILE_ATTRIBUTE_DIRECTORY, FILE_ATTRIBUTE_REPARSE_POINT,
    FILE_ATTRIBUTE_TAG_INFO, FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT,
    FILE_GENERIC_READ, FILE_GENERIC_WRITE, FILE_ID_INFO, FILE_READ_ATTRIBUTES, FILE_SHARE_MODE,
    FILE_SHARE_READ, FILE_SHARE_WRITE, OPEN_EXISTING, READ_CONTROL, WRITE_DAC, WRITE_OWNER,
};
use windows::Win32::System::Com::CoTaskMemFree;
use windows::Win32::System::SystemServices::FILE_PERSISTENT_ACLS;
use windows::Win32::System::WindowsProgramming::DRIVE_FIXED;
use windows::Win32::UI::Shell::{FOLDERID_ProgramData, SHGetKnownFolderPath, KF_FLAG_DEFAULT};

const DIRECTORY_PREFIX: &str = "mxc-plm-elevated-";
const PROFILE_FILE: &str = "embedded.wprp";
const TRACE_FILE: &str = "trace.etl";
const RECOVERY_STATE_PARENT: &str = "Microsoft";
const RECOVERY_STATE_COMPONENTS: [&str; 2] = ["MXC", "PLM"];
const RECOVERY_MARKER_FILE: &str = "active.marker";
const PROTECTED_SDDL: &str = "D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)S:(ML;OICI;NW;;;HI)";
const MARKER_SDDL: &str = "O:BAG:BAD:P(A;;FA;;;SY)(A;;FA;;;BA)S:(ML;;NW;;;HI)";
const PIN_SHARE: FILE_SHARE_MODE = FILE_SHARE_MODE(FILE_SHARE_READ.0 | FILE_SHARE_WRITE.0);
const PROTECTOR_SHARE: FILE_SHARE_MODE = FILE_SHARE_READ;
const RANDOM_NAME_ATTEMPTS: usize = 32;

/// A pinned, access-controlled scratch directory under ProgramData.
pub struct SecureScratch {
    directory: PathBuf,
    profile: PathBuf,
    trace: PathBuf,
    _ancestor_handles: Vec<OwnedHandle>,
    directory_handle: Option<OwnedHandle>,
    trace_opened: AtomicBool,
}

impl fmt::Debug for SecureScratch {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SecureScratch")
            .field("directory", &self.directory)
            .field("profile", &self.profile)
            .field("trace", &self.trace)
            .finish_non_exhaustive()
    }
}

/// Keeps the embedded profile protected against write, delete, and rename.
pub struct ProfileGuard {
    _protector: OwnedHandle,
}

/// Protected durable signal that a guardian may have left WPR armed.
pub struct RecoveryMarker {
    path: PathBuf,
    file: Option<std::fs::File>,
    _ancestor_handles: Vec<OwnedHandle>,
    stale: bool,
    delete_on_drop: bool,
}

impl fmt::Debug for ProfileGuard {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ProfileGuard")
            .finish_non_exhaustive()
    }
}

impl SecureScratch {
    /// Creates and pins a secure random directory directly under ProgramData.
    pub fn new() -> Result<Self> {
        let program_data = program_data_path()?;
        let root = validate_program_data_path(&program_data)?;
        validate_volume(&root)?;
        let ancestor_handles = pin_program_data_components(&program_data, &root)?;
        let security = OwnedSecurityDescriptor::from_sddl(PROTECTED_SDDL)?;

        for _ in 0..RANDOM_NAME_ATTEMPTS {
            let mut random = [0u8; 16];
            getrandom::getrandom(&mut random).map_err(|error| {
                anyhow::anyhow!("failed to generate secure PLM scratch directory name: {error}")
            })?;
            let directory = program_data.join(scratch_name(&random));
            let wide = wide_path(&directory);
            let attributes = security.attributes();

            // SAFETY: `wide` is NUL-terminated and `attributes` points to a
            // valid descriptor for the duration of the call.
            match unsafe { CreateDirectoryW(PCWSTR(wide.as_ptr()), Some(&attributes)) } {
                Ok(()) => {
                    let directory_handle = match open_pinned_directory(&directory) {
                        Ok(handle) => handle,
                        Err(error) => {
                            // SAFETY: `wide` names only the directory created by
                            // the immediately preceding CreateDirectoryW call.
                            let _ = unsafe { RemoveDirectoryW(PCWSTR(wide.as_ptr())) };
                            return Err(error).with_context(|| {
                                format!(
                                    "failed to pin newly created PLM scratch directory {}",
                                    directory.display()
                                )
                            });
                        }
                    };
                    return Ok(Self {
                        profile: directory.join(PROFILE_FILE),
                        trace: directory.join(TRACE_FILE),
                        directory,
                        _ancestor_handles: ancestor_handles,
                        directory_handle: Some(directory_handle),
                        trace_opened: AtomicBool::new(false),
                    });
                }
                Err(error)
                    if error.code() == HRESULT::from_win32(ERROR_ALREADY_EXISTS.0)
                        || error.code() == HRESULT::from_win32(ERROR_FILE_EXISTS.0) =>
                {
                    continue;
                }
                Err(error) => {
                    return Err(error).context("failed to create secure PLM scratch directory");
                }
            }
        }

        bail!(
            "failed to create a unique secure PLM scratch directory after {RANDOM_NAME_ATTEMPTS} attempts"
        )
    }

    /// Returns the path reserved for the embedded WPR profile.
    pub fn profile_path(&self) -> &Path {
        &self.profile
    }

    /// Returns the path WPR must use for the ETL output.
    pub fn trace_path(&self) -> &Path {
        &self.trace
    }

    /// Creates, flushes, verifies, and seals the embedded WPR profile.
    pub fn write_and_seal_profile(&self, contents: &[u8]) -> Result<ProfileGuard> {
        let security = OwnedSecurityDescriptor::from_sddl(PROTECTED_SDDL)?;
        let attributes = security.attributes();
        let wide = wide_path(&self.profile);

        // SAFETY: `wide` is NUL-terminated and `attributes` remains valid
        // while CreateFileW consumes it.
        let handle = unsafe {
            CreateFileW(
                PCWSTR(wide.as_ptr()),
                (FILE_GENERIC_WRITE | FILE_READ_ATTRIBUTES).0,
                FILE_SHARE_READ,
                Some(&attributes),
                CREATE_NEW,
                FILE_FLAG_OPEN_REPARSE_POINT,
                None,
            )
        }
        .with_context(|| {
            format!(
                "failed to create secure embedded WPR profile {}",
                self.profile.display()
            )
        })?;

        // SAFETY: ownership of the valid CreateFileW handle transfers to File.
        let mut file = unsafe { std::fs::File::from_raw_handle(handle.0) };
        file.write_all(contents)
            .context("failed to write embedded WPR profile")?;
        // SAFETY: the File still owns a valid handle.
        unsafe { FlushFileBuffers(HANDLE(file.as_raw_handle())) }
            .context("failed to flush embedded WPR profile")?;
        let identity = file_identity(HANDLE(file.as_raw_handle()))
            .context("failed to record embedded WPR profile identity")?;
        verify_file_kind(HANDLE(file.as_raw_handle()), false)
            .context("new embedded WPR profile has an unsafe file type")?;
        drop(file);

        let protector = open_handle(
            &self.profile,
            FILE_READ_ATTRIBUTES.0,
            PROTECTOR_SHARE,
            FILE_FLAG_OPEN_REPARSE_POINT,
        )
        .context("failed to seal embedded WPR profile")?;
        verify_file_kind(protector.0, false)
            .context("sealed embedded WPR profile has an unsafe file type")?;
        if file_identity(protector.0)? != identity {
            bail!("embedded WPR profile identity changed while it was being sealed");
        }

        let actual = read_protected_file(&self.profile)?;
        if actual != contents {
            bail!("embedded WPR profile contents changed while it was being sealed");
        }

        Ok(ProfileGuard {
            _protector: protector,
        })
    }

    /// Opens the WPR-created ETL once, hardens it, and returns its exact size.
    pub fn open_trace(&self) -> Result<(std::fs::File, u64)> {
        if self
            .trace_opened
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            bail!("secure PLM trace has already been opened");
        }

        let result = self.open_trace_inner();
        if result.is_err() {
            self.trace_opened.store(false, Ordering::Release);
        }
        result
    }

    fn open_trace_inner(&self) -> Result<(std::fs::File, u64)> {
        let access = FILE_GENERIC_READ.0
            | READ_CONTROL.0
            | WRITE_DAC.0
            | WRITE_OWNER.0
            | FILE_READ_ATTRIBUTES.0;
        let handle = open_handle(
            &self.trace,
            access,
            PROTECTOR_SHARE,
            FILE_FLAG_OPEN_REPARSE_POINT,
        )
        .with_context(|| format!("failed to open secure PLM trace {}", self.trace.display()))?;
        verify_file_kind(handle.0, false).context("PLM trace has an unsafe file type")?;

        let security = OwnedSecurityDescriptor::from_sddl(PROTECTED_SDDL)?;
        // SAFETY: `handle` is valid and the parsed descriptor remains alive
        // through SetKernelObjectSecurity.
        unsafe {
            SetKernelObjectSecurity(
                handle.0,
                DACL_SECURITY_INFORMATION | LABEL_SECURITY_INFORMATION,
                security.as_ptr(),
            )
        }
        .context("failed to harden PLM trace security")?;

        let mut size = 0i64;
        // SAFETY: `handle` is valid and `size` is a correctly sized out-param.
        unsafe { GetFileSizeEx(handle.0, &mut size) }.context("failed to read PLM trace size")?;
        let size = u64::try_from(size).context("PLM trace reported a negative size")?;

        // Transfer ownership from the RAII handle to File.
        let raw = handle.into_raw();
        // SAFETY: `raw` is a valid owned file handle and is no longer managed
        // by OwnedHandle.
        let file = unsafe { std::fs::File::from_raw_handle(raw.0) };
        Ok((file, size))
    }

    fn cleanup(&mut self) {
        delete_known_leaf(&self.profile);
        delete_known_leaf(&self.trace);
        self.directory_handle.take();
        let wide = wide_path(&self.directory);
        // SAFETY: `wide` is a NUL-terminated path to the one known directory.
        if let Err(error) = unsafe { RemoveDirectoryW(PCWSTR(wide.as_ptr())) } {
            let raw = (error.code().0 as u32) & 0xffff;
            if raw != ERROR_FILE_NOT_FOUND.0 && raw != ERROR_PATH_NOT_FOUND.0 {
                eprintln!(
                    "[plm] failed to remove secure scratch directory {}: {error}",
                    self.directory.display()
                );
            }
        }
    }
}

impl RecoveryMarker {
    pub fn acquire() -> Result<Self> {
        use windows::Win32::Storage::FileSystem::DELETE;

        let program_data = program_data_path()?;
        let root = validate_program_data_path(&program_data)?;
        validate_volume(&root)?;
        let (state_directory, ancestor_handles) =
            open_protected_recovery_directory(&program_data, &root)?;
        let path = state_directory.join(RECOVERY_MARKER_FILE);
        let wide = wide_path(&path);
        let security = OwnedSecurityDescriptor::from_sddl(MARKER_SDDL)?;
        let attributes = security.attributes();
        let access = (FILE_READ_ATTRIBUTES | READ_CONTROL | DELETE).0;

        let (handle, stale) = match unsafe {
            CreateFileW(
                PCWSTR(wide.as_ptr()),
                access,
                FILE_SHARE_READ,
                Some(&attributes),
                CREATE_NEW,
                FILE_FLAG_OPEN_REPARSE_POINT,
                None,
            )
        } {
            Ok(handle) => (handle, false),
            Err(error)
                if error.code() == HRESULT::from_win32(ERROR_ALREADY_EXISTS.0)
                    || error.code() == HRESULT::from_win32(ERROR_FILE_EXISTS.0) =>
            {
                let handle = unsafe {
                    CreateFileW(
                        PCWSTR(wide.as_ptr()),
                        access,
                        FILE_SHARE_READ,
                        None,
                        OPEN_EXISTING,
                        FILE_FLAG_OPEN_REPARSE_POINT,
                        None,
                    )
                }
                .context("failed to open existing PLM recovery marker")?;
                (handle, true)
            }
            Err(error) => return Err(error).context("failed to create PLM recovery marker"),
        };
        verify_file_kind(handle, false)?;
        if stale && !has_trusted_owner(handle)? {
            unsafe {
                let _ = CloseHandle(handle);
            }
            bail!("existing PLM recovery marker has an untrusted owner");
        }
        let file = unsafe { std::fs::File::from_raw_handle(handle.0) };
        Ok(Self {
            path,
            file: Some(file),
            _ancestor_handles: ancestor_handles,
            stale,
            delete_on_drop: !stale,
        })
    }

    pub fn is_stale(&self) -> bool {
        self.stale
    }

    pub fn preserve(&mut self) {
        self.delete_on_drop = false;
    }

    pub fn recovered(&mut self) {
        self.stale = false;
        self.delete_on_drop = true;
    }
}

impl Drop for RecoveryMarker {
    fn drop(&mut self) {
        self.file.take();
        if self.delete_on_drop {
            let wide = wide_path(&self.path);
            unsafe {
                let _ = DeleteFileW(PCWSTR(wide.as_ptr()));
            }
        }
    }
}

fn open_protected_recovery_directory(
    program_data: &Path,
    root: &Path,
) -> Result<(PathBuf, Vec<OwnedHandle>)> {
    let mut handles = pin_program_data_components(program_data, root)?;
    let parent = program_data.join(RECOVERY_STATE_PARENT);
    let parent_handle = open_handle(
        &parent,
        (FILE_READ_ATTRIBUTES | READ_CONTROL).0,
        PIN_SHARE,
        FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT,
    )
    .with_context(|| format!("failed to pin PLM recovery parent {}", parent.display()))?;
    verify_file_kind(parent_handle.0, true)?;
    if !has_trusted_owner(parent_handle.0)? {
        bail!("PLM recovery parent has an untrusted owner");
    }
    handles.push(parent_handle);

    let security = OwnedSecurityDescriptor::from_sddl(PROTECTED_SDDL)?;
    let mut current = parent;
    for component in RECOVERY_STATE_COMPONENTS {
        current.push(component);
        create_or_open_protected_directory(&current, &security, &mut handles)?;
    }
    Ok((current, handles))
}

fn create_or_open_protected_directory(
    path: &Path,
    security: &OwnedSecurityDescriptor,
    handles: &mut Vec<OwnedHandle>,
) -> Result<()> {
    let wide = wide_path(path);
    let attributes = security.attributes();
    match unsafe { CreateDirectoryW(PCWSTR(wide.as_ptr()), Some(&attributes)) } {
        Ok(()) => {}
        Err(error)
            if error.code() == HRESULT::from_win32(ERROR_ALREADY_EXISTS.0)
                || error.code() == HRESULT::from_win32(ERROR_FILE_EXISTS.0) => {}
        Err(error) => {
            return Err(error).with_context(|| {
                format!("failed to create PLM recovery directory {}", path.display())
            });
        }
    }

    let access = FILE_READ_ATTRIBUTES.0 | READ_CONTROL.0 | WRITE_DAC.0 | WRITE_OWNER.0;
    let handle = open_handle(
        path,
        access,
        PIN_SHARE,
        FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT,
    )
    .with_context(|| format!("failed to pin PLM recovery directory {}", path.display()))?;
    verify_file_kind(handle.0, true)?;
    if !has_trusted_owner(handle.0)? {
        bail!(
            "PLM recovery directory {} has an untrusted owner",
            path.display()
        );
    }
    unsafe {
        SetKernelObjectSecurity(
            handle.0,
            DACL_SECURITY_INFORMATION | LABEL_SECURITY_INFORMATION,
            security.as_ptr(),
        )
    }
    .with_context(|| {
        format!(
            "failed to protect PLM recovery directory {}",
            path.display()
        )
    })?;
    handles.push(handle);
    Ok(())
}

impl Drop for SecureScratch {
    fn drop(&mut self) {
        self.cleanup();
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct FileIdentity {
    volume_serial: u64,
    file_id: [u8; 16],
}

struct OwnedHandle(HANDLE);

impl OwnedHandle {
    fn into_raw(mut self) -> HANDLE {
        let handle = self.0;
        self.0 = HANDLE::default();
        handle
    }
}

impl Drop for OwnedHandle {
    fn drop(&mut self) {
        if !self.0.is_invalid() {
            // SAFETY: OwnedHandle is created only from successful CreateFileW
            // calls and closes each handle at most once.
            unsafe {
                let _ = CloseHandle(self.0);
            }
        }
    }
}

struct OwnedSecurityDescriptor(PSECURITY_DESCRIPTOR);

impl OwnedSecurityDescriptor {
    fn from_sddl(sddl: &str) -> Result<Self> {
        let wide = wide_str(sddl);
        let mut descriptor = PSECURITY_DESCRIPTOR::default();
        // SAFETY: `wide` is NUL-terminated and `descriptor` is a valid
        // out-param. The returned allocation is owned by LocalFree.
        unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                PCWSTR(wide.as_ptr()),
                SDDL_REVISION_1,
                &mut descriptor,
                None,
            )
        }
        .context("failed to parse secure PLM scratch security descriptor")?;
        if descriptor.0.is_null() {
            bail!("security descriptor parser returned a null descriptor");
        }
        Ok(Self(descriptor))
    }

    fn attributes(&self) -> SECURITY_ATTRIBUTES {
        SECURITY_ATTRIBUTES {
            nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: self.0 .0,
            bInheritHandle: false.into(),
        }
    }

    fn as_ptr(&self) -> PSECURITY_DESCRIPTOR {
        self.0
    }
}

impl Drop for OwnedSecurityDescriptor {
    fn drop(&mut self) {
        if !self.0 .0.is_null() {
            // SAFETY: this descriptor was allocated by the SDDL conversion
            // routine, whose contract requires LocalFree.
            unsafe {
                let _ = LocalFree(Some(HLOCAL(self.0 .0)));
            }
        }
    }
}

struct KnownFolderAllocation(PWSTR);

impl Drop for KnownFolderAllocation {
    fn drop(&mut self) {
        if !self.0.is_null() {
            // SAFETY: SHGetKnownFolderPath allocates this string with the COM
            // task allocator.
            unsafe { CoTaskMemFree(Some(self.0 .0.cast())) };
        }
    }
}

fn program_data_path() -> Result<PathBuf> {
    // SAFETY: the known-folder GUID is static and no token override is used.
    let allocation = unsafe { SHGetKnownFolderPath(&FOLDERID_ProgramData, KF_FLAG_DEFAULT, None) }
        .context("SHGetKnownFolderPath(FOLDERID_ProgramData) failed")?;
    let allocation = KnownFolderAllocation(allocation);
    // SAFETY: SHGetKnownFolderPath returned a valid NUL-terminated string
    // owned by `allocation`.
    let path = unsafe { PCWSTR(allocation.0 .0).to_string() }
        .context("ProgramData path was not valid UTF-16")?;
    Ok(PathBuf::from(path))
}

fn validate_program_data_path(path: &Path) -> Result<PathBuf> {
    let mut components = path.components();
    let drive = match components.next() {
        Some(Component::Prefix(prefix)) => match prefix.kind() {
            std::path::Prefix::Disk(letter) => letter,
            _ => bail!("ProgramData must use an absolute local drive path"),
        },
        _ => bail!("ProgramData must use an absolute local drive path"),
    };
    if components.next() != Some(Component::RootDir) {
        bail!("ProgramData must be an absolute path");
    }
    if components
        .clone()
        .any(|component| !matches!(component, Component::Normal(_)))
    {
        bail!("ProgramData contains an unsafe path component");
    }

    Ok(PathBuf::from(format!("{}:\\", char::from(drive))))
}

fn validate_volume(root: &Path) -> Result<()> {
    let wide = wide_path(root);
    // SAFETY: `wide` is the NUL-terminated drive-root path.
    let drive_type = unsafe { GetDriveTypeW(PCWSTR(wide.as_ptr())) };
    if drive_type != DRIVE_FIXED {
        bail!("ProgramData must reside on a local fixed-volume drive");
    }

    let mut flags = 0u32;
    // SAFETY: `wide` is a valid drive root and `flags` is a valid out-param;
    // all optional text and numeric outputs are intentionally omitted.
    unsafe {
        GetVolumeInformationW(
            PCWSTR(wide.as_ptr()),
            None,
            None,
            None,
            Some(&mut flags),
            None,
        )
    }
    .context("failed to query ProgramData volume capabilities")?;
    if flags & FILE_PERSISTENT_ACLS == 0 {
        bail!("ProgramData volume does not support persistent ACLs");
    }
    Ok(())
}

fn pin_program_data_components(program_data: &Path, root: &Path) -> Result<Vec<OwnedHandle>> {
    let mut handles = vec![open_pinned_directory(root)
        .with_context(|| format!("failed to pin ProgramData drive root {}", root.display()))?];
    let mut current = root.to_path_buf();

    for component in program_data.components().skip(2) {
        let Component::Normal(name) = component else {
            bail!("ProgramData contains an unsafe path component");
        };
        current.push(name);
        handles.push(open_pinned_directory(&current).with_context(|| {
            format!("failed to pin ProgramData component {}", current.display())
        })?);
    }
    Ok(handles)
}

fn open_pinned_directory(path: &Path) -> Result<OwnedHandle> {
    let handle = open_handle(
        path,
        FILE_READ_ATTRIBUTES.0,
        PIN_SHARE,
        FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT,
    )?;
    verify_file_kind(handle.0, true)?;
    Ok(handle)
}

fn open_handle(
    path: &Path,
    access: u32,
    share: FILE_SHARE_MODE,
    flags: windows::Win32::Storage::FileSystem::FILE_FLAGS_AND_ATTRIBUTES,
) -> Result<OwnedHandle> {
    let wide = wide_path(path);
    // SAFETY: `wide` is NUL-terminated; no security attributes or template
    // handles are supplied.
    let handle = unsafe {
        CreateFileW(
            PCWSTR(wide.as_ptr()),
            access,
            share,
            None,
            OPEN_EXISTING,
            flags,
            None,
        )
    }
    .with_context(|| format!("CreateFileW failed for {}", path.display()))?;
    Ok(OwnedHandle(handle))
}

fn verify_file_kind(handle: HANDLE, directory_expected: bool) -> Result<()> {
    let mut info = FILE_ATTRIBUTE_TAG_INFO::default();
    // SAFETY: `handle` is valid and `info` is a correctly sized out-param.
    unsafe {
        GetFileInformationByHandleEx(
            handle,
            FileAttributeTagInfo,
            &mut info as *mut FILE_ATTRIBUTE_TAG_INFO as *mut _,
            std::mem::size_of::<FILE_ATTRIBUTE_TAG_INFO>() as u32,
        )
    }
    .context("GetFileInformationByHandleEx(FileAttributeTagInfo) failed")?;

    if info.FileAttributes & FILE_ATTRIBUTE_REPARSE_POINT.0 != 0 {
        bail!("secure PLM path resolved to a reparse point");
    }
    let is_directory = info.FileAttributes & FILE_ATTRIBUTE_DIRECTORY.0 != 0;
    if is_directory != directory_expected {
        bail!("secure PLM path has an unexpected file type");
    }
    Ok(())
}

fn has_trusted_owner(handle: HANDLE) -> Result<bool> {
    use windows::Win32::Foundation::{ERROR_SUCCESS, HLOCAL};
    use windows::Win32::Security::Authorization::{GetSecurityInfo, SE_KERNEL_OBJECT};
    use windows::Win32::Security::{
        IsWellKnownSid, WinBuiltinAdministratorsSid, WinLocalSystemSid, OWNER_SECURITY_INFORMATION,
        PSECURITY_DESCRIPTOR, PSID,
    };

    let mut owner = PSID::default();
    let mut descriptor = PSECURITY_DESCRIPTOR::default();
    let result = unsafe {
        GetSecurityInfo(
            handle,
            SE_KERNEL_OBJECT,
            OWNER_SECURITY_INFORMATION,
            Some(&mut owner),
            None,
            None,
            None,
            Some(&mut descriptor),
        )
    };
    if result != ERROR_SUCCESS {
        bail!("GetSecurityInfo failed for PLM recovery marker: {result:?}");
    }
    let trusted = unsafe {
        bool::from(IsWellKnownSid(owner, WinBuiltinAdministratorsSid))
            || bool::from(IsWellKnownSid(owner, WinLocalSystemSid))
    };
    unsafe {
        let _ = LocalFree(Some(HLOCAL(descriptor.0)));
    }
    Ok(trusted)
}

fn file_identity(handle: HANDLE) -> Result<FileIdentity> {
    let mut info = FILE_ID_INFO::default();
    // SAFETY: `handle` is valid and `info` is a correctly sized out-param.
    unsafe {
        GetFileInformationByHandleEx(
            handle,
            FileIdInfo,
            &mut info as *mut FILE_ID_INFO as *mut _,
            std::mem::size_of::<FILE_ID_INFO>() as u32,
        )
    }
    .context("GetFileInformationByHandleEx(FileIdInfo) failed")?;
    Ok(FileIdentity {
        volume_serial: info.VolumeSerialNumber,
        file_id: info.FileId.Identifier,
    })
}

fn read_protected_file(path: &Path) -> Result<Vec<u8>> {
    let reader = open_handle(
        path,
        FILE_GENERIC_READ.0,
        PROTECTOR_SHARE,
        FILE_FLAG_OPEN_REPARSE_POINT,
    )?;
    verify_file_kind(reader.0, false)?;
    let raw = reader.into_raw();
    // SAFETY: `raw` is a valid owned file handle no longer managed by
    // OwnedHandle.
    let mut file = unsafe { std::fs::File::from_raw_handle(raw.0) };
    let mut contents = Vec::new();
    file.read_to_end(&mut contents)
        .context("failed to verify embedded WPR profile contents")?;
    Ok(contents)
}

fn delete_known_leaf(path: &Path) {
    let wide = wide_path(path);
    // SAFETY: `wide` is a NUL-terminated path to one known leaf file.
    if let Err(error) = unsafe { DeleteFileW(PCWSTR(wide.as_ptr())) } {
        let raw = (error.code().0 as u32) & 0xffff;
        if raw != ERROR_FILE_NOT_FOUND.0 && raw != ERROR_PATH_NOT_FOUND.0 {
            eprintln!(
                "[plm] failed to remove secure scratch file {}: {error}",
                path.display()
            );
        }
    }
}

fn scratch_name(random: &[u8; 16]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut name = String::with_capacity(DIRECTORY_PREFIX.len() + 32);
    name.push_str(DIRECTORY_PREFIX);
    for byte in random {
        name.push(char::from(HEX[(byte >> 4) as usize]));
        name.push(char::from(HEX[(byte & 0x0f) as usize]));
    }
    name
}

fn wide_path(path: &Path) -> Vec<u16> {
    wide_os(path.as_os_str())
}

fn wide_str(value: &str) -> Vec<u16> {
    wide_os(OsStr::new(value))
}

fn wide_os(value: &OsStr) -> Vec<u16> {
    value.encode_wide().chain(std::iter::once(0)).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn random_name_is_exact_lowercase_hex() {
        let bytes = [
            0x00, 0x01, 0x0f, 0x10, 0x2a, 0x3b, 0x4c, 0x5d, 0x6e, 0x7f, 0x80, 0x91, 0xa2, 0xb3,
            0xc4, 0xff,
        ];
        assert_eq!(
            scratch_name(&bytes),
            "mxc-plm-elevated-00010f102a3b4c5d6e7f8091a2b3c4ff"
        );
    }

    #[test]
    fn program_data_path_accepts_only_absolute_drive_paths() {
        assert_eq!(
            validate_program_data_path(Path::new(r"C:\ProgramData")).unwrap(),
            PathBuf::from(r"C:\")
        );
        assert!(validate_program_data_path(Path::new(r"\\server\share")).is_err());
        assert!(validate_program_data_path(Path::new(r"\\?\C:\ProgramData")).is_err());
        assert!(validate_program_data_path(Path::new(r"C:ProgramData")).is_err());
        assert!(validate_program_data_path(Path::new(r"C:\safe\..\ProgramData")).is_err());
    }

    #[test]
    fn security_policy_is_protected_high_integrity_and_non_delete_sharing() {
        assert!(PROTECTED_SDDL.starts_with("D:P"));
        assert!(PROTECTED_SDDL.contains(";;;SY"));
        assert!(PROTECTED_SDDL.contains(";;;BA"));
        assert!(PROTECTED_SDDL.ends_with("S:(ML;OICI;NW;;;HI)"));
        assert_eq!(PROTECTOR_SHARE, FILE_SHARE_READ);
        assert_eq!(
            PIN_SHARE,
            FILE_SHARE_MODE(FILE_SHARE_READ.0 | FILE_SHARE_WRITE.0)
        );
    }

    #[test]
    fn recovery_marker_is_admin_owned_and_durable_until_recovered() {
        assert!(MARKER_SDDL.starts_with("O:BAG:BAD:P"));
        assert!(MARKER_SDDL.contains(";;;SY"));
        assert!(MARKER_SDDL.contains(";;;BA"));
        assert!(MARKER_SDDL.ends_with("S:(ML;;NW;;;HI)"));
        assert_eq!(RECOVERY_STATE_PARENT, "Microsoft");
        assert_eq!(RECOVERY_STATE_COMPONENTS, ["MXC", "PLM"]);
        assert_eq!(RECOVERY_MARKER_FILE, "active.marker");

        let mut marker = RecoveryMarker {
            path: PathBuf::new(),
            file: None,
            _ancestor_handles: Vec::new(),
            stale: true,
            delete_on_drop: false,
        };
        assert!(marker.is_stale());
        marker.recovered();
        assert!(!marker.is_stale());
        assert!(marker.delete_on_drop);
        marker.preserve();
        assert!(!marker.delete_on_drop);
    }
}
