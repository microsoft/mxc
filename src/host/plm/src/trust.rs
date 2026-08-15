// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Pre-launch trust gate for the elevated `plm.exe` guardian.
//!
//! `plm.exe` self-elevates via `ShellExecuteExW("runas")`, so before that
//! launch we must prove the binary about to run as administrator is genuinely
//! Microsoft's and cannot be swapped underneath us. This module enforces, and
//! fails closed on, **all** of:
//!
//! 1. **Authenticode trust** — [`WinVerifyTrust`] with the generic
//!    verify-v2 policy (chains to a trusted root, honoring revocation policy).
//! 2. **Microsoft signer identity** — the embedded PKCS#7 signer certificate's
//!    Organization (`O`) name must be Microsoft. This is deliberately keyed on
//!    the organization name rather than a fixed thumbprint so it survives
//!    certificate rollover.
//! 3. **Directory integrity** — the containing directory's DACL must not grant
//!    any non-privileged principal rights that would let them replace the
//!    binary (create/delete files, delete-child, `WRITE_DAC`, `WRITE_OWNER`,
//!    generic write/all). Only SYSTEM, Administrators, and TrustedInstaller may
//!    hold such rights.
//!
//! To close the check-then-launch (TOCTOU) window, [`verify_and_pin_launch_binary`]
//! opens the file **first** with a share mode that denies write and delete, and
//! returns a [`LaunchIntegrityGuard`] that keeps that handle open. The caller
//! holds the guard across `ShellExecuteExW`, so the exact bytes verified are the
//! bytes the loader maps — the file cannot be renamed, deleted, or overwritten
//! in between.
//!
//! The signer/ACL *classification* is factored into pure functions so it is
//! unit-testable without a locally signed binary.

use anyhow::{bail, Context, Result};
use std::ffi::c_void;
use std::os::windows::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::ptr;

use windows::core::{Error as WinError, PCSTR, PCWSTR, PWSTR};
use windows::Win32::Foundation::{CloseHandle, LocalFree, ERROR_SUCCESS, HANDLE, HLOCAL, HWND};
use windows::Win32::Security::Authorization::{
    ConvertSidToStringSidW, GetNamedSecurityInfoW, SE_FILE_OBJECT,
};
use windows::Win32::Security::Cryptography::{
    CertCloseStore, CertFindCertificateInStore, CertFreeCertificateContext, CertGetNameStringW,
    CryptMsgClose, CryptMsgGetParam, CryptQueryObject, CERT_CONTEXT, CERT_FIND_SUBJECT_CERT,
    CERT_INFO, CERT_NAME_ATTR_TYPE, CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED_EMBED,
    CERT_QUERY_ENCODING_TYPE, CERT_QUERY_FORMAT_FLAG_BINARY, CERT_QUERY_OBJECT_FILE,
    CMSG_SIGNER_INFO, CMSG_SIGNER_INFO_PARAM, CRYPT_INTEGER_BLOB, HCERTSTORE, PKCS_7_ASN_ENCODING,
    X509_ASN_ENCODING,
};
use windows::Win32::Security::WinTrust::{
    WinVerifyTrust, WINTRUST_ACTION_GENERIC_VERIFY_V2, WINTRUST_DATA, WINTRUST_DATA_0,
    WINTRUST_DATA_PROVIDER_FLAGS, WINTRUST_DATA_REVOCATION_CHECKS, WINTRUST_FILE_INFO,
    WTD_CHOICE_FILE, WTD_REVOCATION_CHECK_CHAIN_EXCLUDE_ROOT, WTD_REVOKE_WHOLECHAIN,
    WTD_STATEACTION_CLOSE, WTD_STATEACTION_VERIFY, WTD_UI_NONE,
};
use windows::Win32::Security::{
    AclSizeInformation, GetAce, GetAclInformation, ACCESS_ALLOWED_ACE, ACE_HEADER, ACL,
    ACL_SIZE_INFORMATION, DACL_SECURITY_INFORMATION, OWNER_SECURITY_INFORMATION,
    PSECURITY_DESCRIPTOR, PSID,
};
use windows::Win32::Storage::FileSystem::{
    CreateFileW, GetFinalPathNameByHandleW, FILE_ATTRIBUTE_NORMAL, FILE_GENERIC_READ,
    FILE_NAME_NORMALIZED, FILE_SHARE_READ, GETFINALPATHNAMEBYHANDLE_FLAGS, OPEN_EXISTING,
    VOLUME_NAME_DOS,
};
use windows::Win32::System::LibraryLoader::{
    SetDefaultDllDirectories, LOAD_LIBRARY_SEARCH_SYSTEM32,
};

/// Authenticode revocation policy: check revocation across the whole chain, but
/// exclude the (self-signed) root — the standard, network-robust policy used by
/// signing tools. Kept as named constants so code and docs stay consistent.
///
/// This is an intentional **fail-closed trust posture**, not a correctness
/// tweak: if revocation status cannot be determined (offline, no cached
/// CRL/OCSP, or an unreachable responder), `WinVerifyTrust` returns a non-zero
/// status and the launch is refused. Signed end-to-end runs therefore require
/// revocation availability or a valid cached revocation status; unknown
/// revocation is never silently accepted.
const REVOCATION_CHECKS: WINTRUST_DATA_REVOCATION_CHECKS = WTD_REVOKE_WHOLECHAIN;
const REVOCATION_PROVIDER_FLAGS: WINTRUST_DATA_PROVIDER_FLAGS =
    WTD_REVOCATION_CHECK_CHAIN_EXCLUDE_ROOT;

/// `INHERIT_ONLY_ACE` — the ACE does not apply to the object itself, only to
/// children, so it does not affect who can modify this directory.
const INHERIT_ONLY_ACE: u8 = 0x08;
const ACCESS_ALLOWED_ACE_TYPE: u8 = 0x00;
const ACCESS_DENIED_ACE_TYPE: u8 = 0x01;

// Access-mask bits relevant to replacing or side-loading around `plm.exe`.
const FILE_ADD_FILE: u32 = 0x0002; // create a file in the directory
const FILE_ADD_SUBDIRECTORY: u32 = 0x0004; // create a subdirectory
const FILE_DELETE_CHILD: u32 = 0x0040; // delete/rename an entry in the directory
const DELETE: u32 = 0x0001_0000; // delete/rename this directory itself
const WRITE_DAC: u32 = 0x0004_0000; // rewrite this directory's DACL
const WRITE_OWNER: u32 = 0x0008_0000; // take ownership (implies WRITE_DAC)
const GENERIC_WRITE: u32 = 0x4000_0000;
const GENERIC_ALL: u32 = 0x1000_0000;

/// Rights that make the **leaf** directory (the one holding `plm.exe`) unsafe:
/// creating a file there could side-load a DLL or drop a replacement binary,
/// and any delete/rename/DACL/owner right enables a swap. This is the strict
/// set.
const LEAF_DANGEROUS_MASK: u32 = FILE_ADD_FILE
    | FILE_ADD_SUBDIRECTORY
    | FILE_DELETE_CHILD
    | DELETE
    | WRITE_DAC
    | WRITE_OWNER
    | GENERIC_WRITE
    | GENERIC_ALL;

/// Rights that make an **ancestor** directory unsafe. An ancestor's harmless
/// "create a sibling" rights (`FILE_ADD_FILE` / `FILE_ADD_SUBDIRECTORY` /
/// `GENERIC_WRITE`) are deliberately NOT rejected — e.g. a drive root commonly
/// lets standard users create folders, which cannot compromise the protected
/// subtree. But rights that let an unprivileged principal delete/rename an
/// entry in the chain (`FILE_DELETE_CHILD`), delete/rename the ancestor itself
/// (`DELETE`), or rewrite its ownership/DACL (`WRITE_DAC` / `WRITE_OWNER` /
/// `GENERIC_ALL`) would let them displace or re-secure the subtree that holds
/// `plm.exe`, so those are rejected on every ancestor.
const ANCESTOR_DANGEROUS_MASK: u32 =
    FILE_DELETE_CHILD | DELETE | WRITE_DAC | WRITE_OWNER | GENERIC_ALL;

/// A directory's role in the chain from `plm.exe` up to the volume root.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum DirRole {
    /// The directory that directly contains `plm.exe`.
    Leaf,
    /// A directory above the leaf, up to and including the volume root.
    Ancestor,
}

impl DirRole {
    fn dangerous_mask(self) -> u32 {
        match self {
            DirRole::Leaf => LEAF_DANGEROUS_MASK,
            DirRole::Ancestor => ANCESTOR_DANGEROUS_MASK,
        }
    }
}

/// Principals permitted to hold replacement rights on `plm.exe`'s directory.
/// Any *other* principal holding such rights means an unprivileged user could
/// swap the binary, so the gate fails closed.
const PRIVILEGED_SIDS: &[&str] = &[
    "S-1-5-18",     // NT AUTHORITY\SYSTEM
    "S-1-5-32-544", // BUILTIN\Administrators
    // NT SERVICE\TrustedInstaller
    "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464",
];

/// Well-known broad principals, retained for actionable diagnostics.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum BroadPrincipal {
    Everyone,
    AuthenticatedUsers,
    BuiltinUsers,
    Interactive,
}

/// Labels a SID string as a well-known broad principal, if it is one.
pub(crate) fn broad_principal_from_sid(sid: &str) -> Option<BroadPrincipal> {
    match sid.to_ascii_uppercase().as_str() {
        "S-1-1-0" => Some(BroadPrincipal::Everyone),
        "S-1-5-11" => Some(BroadPrincipal::AuthenticatedUsers),
        "S-1-5-32-545" => Some(BroadPrincipal::BuiltinUsers),
        "S-1-5-4" => Some(BroadPrincipal::Interactive),
        _ => None,
    }
}

/// Whether `sid` is one of the privileged principals allowed to hold
/// replacement rights on the guarded directory.
pub(crate) fn is_privileged_sid(sid: &str) -> bool {
    PRIVILEGED_SIDS
        .iter()
        .any(|privileged| sid.eq_ignore_ascii_case(privileged))
}

/// Whether an access `mask` intersects the `dangerous` set for a directory's
/// role.
pub(crate) fn mask_permits(mask: u32, dangerous: u32) -> bool {
    mask & dangerous != 0
}

/// Interprets a raw ACE type byte. `Some(true)` = a standard allow ACE,
/// `Some(false)` = a standard deny ACE, `None` = any other type (object,
/// callback, conditional, audit, …). Callers **fail closed** on `None` rather
/// than skip it, since an unparsed ACE could grant access we cannot see.
pub(crate) fn ace_type_kind(ace_type: u8) -> Option<bool> {
    match ace_type {
        ACCESS_ALLOWED_ACE_TYPE => Some(true),
        ACCESS_DENIED_ACE_TYPE => Some(false),
        _ => None,
    }
}

/// Fail-closed presence check for a directory's DACL. A NULL DACL grants
/// everyone full control, so its absence is a rejection.
pub(crate) fn require_present_dacl(present: bool) -> Result<()> {
    if present {
        Ok(())
    } else {
        bail!("the directory has a NULL DACL, which grants unrestricted access")
    }
}

/// One directory DACL entry reduced to what the classifier needs.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct DaclEntry {
    pub sid: String,
    pub mask: u32,
    pub allow: bool,
}

/// Fail-closed classification: returns the first `(sid, mask)` for an **allow**
/// ACE that grants any of `dangerous` to a **non-privileged** principal — i.e.
/// evidence that someone who is not SYSTEM/Administrators/TrustedInstaller could
/// compromise the directory. Deny ACEs are conservatively ignored (their
/// presence cannot make an unexpected allow safe).
pub(crate) fn replaceable_by(entries: &[DaclEntry], dangerous: u32) -> Option<(String, u32)> {
    entries.iter().find_map(|entry| {
        if !entry.allow || is_privileged_sid(&entry.sid) {
            return None;
        }
        if mask_permits(entry.mask, dangerous) {
            Some((entry.sid.clone(), entry.mask))
        } else {
            None
        }
    })
}

/// Whether a signer certificate's Organization (`O`) name is Microsoft's.
/// Keyed on the organization name — stable across certificate rollover — rather
/// than a fixed thumbprint.
pub(crate) fn is_trusted_microsoft_org(org: &str) -> bool {
    org.trim().eq_ignore_ascii_case("Microsoft Corporation")
}

/// Keeps `plm.exe` open with a write/delete-denying share mode for its lifetime,
/// so the verified file cannot be swapped before/while `ShellExecuteExW` maps
/// it, and carries the **resolved** canonical launch path. Dropping the guard
/// closes the handle.
pub struct LaunchIntegrityGuard {
    handle: HANDLE,
    launch_path: PathBuf,
}

// SAFETY: a Windows file HANDLE has no thread affinity; the guard uniquely owns
// it and only closes it on drop.
unsafe impl Send for LaunchIntegrityGuard {}

impl LaunchIntegrityGuard {
    /// The resolved, canonical **local DOS** path of the pinned binary. Callers
    /// MUST launch this path (e.g. via `ShellExecuteExW`), never the original,
    /// possibly aliased, path they passed to [`verify_and_pin_launch_binary`].
    /// It was resolved from the pinned handle, so SUBST / DOS-device / junction
    /// / symlink aliases have already been collapsed to the underlying object.
    pub fn launch_path(&self) -> &Path {
        &self.launch_path
    }
}

impl Drop for LaunchIntegrityGuard {
    fn drop(&mut self) {
        if !self.handle.is_invalid() {
            // SAFETY: `handle` was returned by `CreateFileW` and is owned here.
            unsafe {
                let _ = CloseHandle(self.handle);
            }
        }
    }
}

fn to_wide(path: &Path) -> Vec<u16> {
    path.as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect()
}

/// Verify `plm.exe` is Authenticode-trusted, Microsoft-signed, and located in a
/// directory chain unprivileged users cannot modify; return a guard that pins
/// the file (deny write/delete) and carries the **resolved** launch path.
///
/// The critical ordering: the file is pinned **first** (following any alias to
/// the underlying object), then its exact object is resolved with
/// `GetFinalPathNameByHandleW`. Every subsequent path-based operation — signer
/// extraction, the ancestor-chain check, and ultimately `ShellExecuteExW`
/// (through [`LaunchIntegrityGuard::launch_path`]) — uses that resolved path,
/// never the caller's original string. This defeats SUBST / DOS-device
/// remapping / junction / symlink substitution between check and launch:
/// whatever alias the caller passed, we verify and launch the same stable
/// object we pinned.
///
/// Fails closed with actionable errors.
pub fn verify_and_pin_launch_binary(path: &Path) -> Result<LaunchIntegrityGuard> {
    // 1. Pin the object. `CreateFileW` follows any alias in `path` to the real
    //    underlying file; the deny-write/delete share mode then freezes it.
    let handle = open_pinned_handle(path).with_context(|| {
        format!(
            "failed to open the guarded PLM binary {} with a write/delete-denying share mode \
             before verification",
            path.display()
        )
    })?;
    // Own the handle immediately so any early return closes it. `launch_path`
    // is filled in once resolved.
    let mut guard = LaunchIntegrityGuard {
        handle,
        launch_path: PathBuf::new(),
    };

    // 2. Resolve the pinned object's canonical local DOS path.
    let resolved = resolve_pinned_local_path(handle).with_context(|| {
        format!(
            "failed to resolve the stable local path of the guarded PLM binary {}",
            path.display()
        )
    })?;
    guard.launch_path = resolved.clone();

    // 3. Authenticode over the PINNED HANDLE (not a re-open by path), so trust
    //    is verified against the exact object we hold.
    verify_authenticode(&resolved, handle).with_context(|| {
        format!(
            "Authenticode verification failed for {}",
            resolved.display()
        )
    })?;

    // 4. Signer identity from the resolved path (the object is pinned, so a
    //    re-open by that path cannot land on a different file).
    let org = signer_organization(&resolved).with_context(|| {
        format!(
            "failed to read the signer identity of {} before elevating it",
            resolved.display()
        )
    })?;
    if !is_trusted_microsoft_org(&org) {
        bail!(
            "refusing to elevate {}: it is signed by an untrusted publisher (organization {org:?}, \
             not Microsoft Corporation)",
            resolved.display()
        );
    }

    // 5. Ancestor chain of the RESOLVED path. The original alias chain need not
    //    stay trusted, since ShellExecuteExW launches the resolved stable path.
    let dir = resolved.parent().with_context(|| {
        format!(
            "resolved guarded PLM path {} has no parent directory",
            resolved.display()
        )
    })?;
    verify_directory_chain(dir)?;

    Ok(guard)
}

/// Resolves the canonical local DOS path of the object behind a pinned handle
/// via `GetFinalPathNameByHandleW`, collapsing SUBST / DOS-device / junction /
/// symlink aliases. Rejects UNC/remote or non-DOS (device / GUID-volume) paths
/// that cannot be normalized to a stable local path.
fn resolve_pinned_local_path(handle: HANDLE) -> Result<PathBuf> {
    let mut buffer = vec![0u16; 512];
    // FILE_NAME_NORMALIZED | VOLUME_NAME_DOS (both are 0, but express intent):
    // a normalized, drive-letter path for the pinned object.
    let flags = GETFINALPATHNAMEBYHANDLE_FLAGS(FILE_NAME_NORMALIZED.0 | VOLUME_NAME_DOS.0);
    let raw = loop {
        // SAFETY: `handle` is a valid open file handle; `buffer` is writable.
        let len = unsafe { GetFinalPathNameByHandleW(handle, &mut buffer, flags) } as usize;
        if len == 0 {
            return Err(WinError::from_thread())
                .context("GetFinalPathNameByHandleW failed for the pinned PLM binary");
        }
        if len < buffer.len() {
            break String::from_utf16_lossy(&buffer[..len]);
        }
        // Too small: `len` is the required size including the NUL. Grow + retry.
        buffer = vec![0u16; len + 1];
    };
    normalize_local_dos_path(&raw)
}

/// Normalizes a `GetFinalPathNameByHandleW(VOLUME_NAME_DOS)` result (a
/// `\\?\`-prefixed path) into a plain local DOS `PathBuf`, or fails closed for
/// UNC/remote and non-drive-letter (device / GUID-volume) paths.
pub(crate) fn normalize_local_dos_path(raw: &str) -> Result<PathBuf> {
    let stripped = raw.strip_prefix(r"\\?\").unwrap_or(raw);
    if stripped.len() >= 4 && stripped[..4].eq_ignore_ascii_case("UNC\\") {
        bail!(
            "the guarded PLM binary resolved to a UNC/remote path ({raw}); refusing to elevate a \
             non-local binary"
        );
    }
    let bytes = stripped.as_bytes();
    let is_local_dos = bytes.len() >= 3
        && bytes[0].is_ascii_alphabetic()
        && bytes[1] == b':'
        && (bytes[2] == b'\\' || bytes[2] == b'/');
    if !is_local_dos {
        bail!(
            "the guarded PLM binary resolved to a non-DOS/device path ({raw}); refusing because it \
             cannot be normalized to a stable local drive-letter path"
        );
    }
    Ok(PathBuf::from(stripped))
}

/// Hardens the process's DLL search order to System32 only, so subsequent
/// `LoadLibrary` calls for a bare DLL name cannot resolve to an adjacent
/// (potentially attacker-planted) DLL. `plm.exe` is a self-contained Rust/MSVC
/// binary that links only system DLLs (kernel32, advapi32, ntdll, the UCRT/
/// vcruntime, crypt32/wintrust) — all resolved from `System32` — and ships no
/// private adjacent DLLs, so this never removes a search path it needs. It is
/// defense-in-depth atop the directory/ancestor integrity checks, which already
/// guarantee an unprivileged user cannot drop a DLL beside `plm.exe`.
///
/// Called at the start of the elevated child so it applies before any runtime
/// `LoadLibrary`. (Static imports are resolved by the loader before `main`, but
/// the verified, non-user-writable install directory already protects those.)
pub fn harden_dll_search_path() -> Result<()> {
    // SAFETY: a process-global search-policy tweak with no unsafe preconditions.
    unsafe { SetDefaultDllDirectories(LOAD_LIBRARY_SEARCH_SYSTEM32) }
        .context("failed to restrict the elevated PLM DLL search path to System32")
}

fn open_pinned_handle(path: &Path) -> Result<HANDLE> {
    let wide = to_wide(path);
    // GENERIC_READ + share READ only: others may still read/execute the image,
    // but no one can open it for write, and it cannot be renamed or deleted
    // while this handle is held — the swap window is closed. `CreateFileW`
    // follows any SUBST/junction/symlink alias to the underlying object.
    let handle = unsafe {
        CreateFileW(
            PCWSTR(wide.as_ptr()),
            FILE_GENERIC_READ.0,
            FILE_SHARE_READ,
            None,
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL,
            None,
        )
    }?;
    Ok(handle)
}

fn verify_authenticode(path: &Path, pinned: HANDLE) -> Result<()> {
    let wide = to_wide(path);
    let mut file_info = WINTRUST_FILE_INFO {
        cbStruct: std::mem::size_of::<WINTRUST_FILE_INFO>() as u32,
        pcwszFilePath: PCWSTR(wide.as_ptr()),
        // Verify the exact pinned object rather than re-reading by path.
        hFile: pinned,
        pgKnownSubject: ptr::null_mut(),
    };
    let mut data = WINTRUST_DATA {
        cbStruct: std::mem::size_of::<WINTRUST_DATA>() as u32,
        dwUIChoice: WTD_UI_NONE,
        // Revocation checking is enabled across the whole chain, excluding the
        // (self-signed) root — see `REVOCATION_CHECKS` / `REVOCATION_PROVIDER_FLAGS`.
        fdwRevocationChecks: REVOCATION_CHECKS,
        dwUnionChoice: WTD_CHOICE_FILE,
        Anonymous: WINTRUST_DATA_0 {
            pFile: &mut file_info,
        },
        dwStateAction: WTD_STATEACTION_VERIFY,
        dwProvFlags: REVOCATION_PROVIDER_FLAGS,
        ..Default::default()
    };
    let mut action = WINTRUST_ACTION_GENERIC_VERIFY_V2;
    // SAFETY: `action` and `data` are valid and outlive the call. A null hwnd
    // with WTD_UI_NONE performs a non-interactive verification.
    let status = unsafe {
        WinVerifyTrust(
            HWND::default(),
            &mut action,
            &mut data as *mut _ as *mut c_void,
        )
    };

    // Always release the per-call trust state, regardless of the result.
    data.dwStateAction = WTD_STATEACTION_CLOSE;
    unsafe {
        let _ = WinVerifyTrust(
            HWND::default(),
            &mut action,
            &mut data as *mut _ as *mut c_void,
        );
    }

    if status != 0 {
        bail!(
            "the binary is not Authenticode-trusted (WinVerifyTrust status {:#010x}); it is \
             unsigned, tampered, chains to an untrusted root, or its certificate is revoked. \
             Whole-chain revocation checking is enabled and fails closed: if revocation status \
             cannot be determined (offline, no cached CRL/OCSP, or an unreachable responder), \
             launch is refused. Signed end-to-end runs therefore require revocation availability \
             or a valid cached revocation status.",
            status as u32
        );
    }
    Ok(())
}

/// RAII closers for the crypto handles returned by `CryptQueryObject`.
struct MsgGuard(*const c_void);
impl Drop for MsgGuard {
    fn drop(&mut self) {
        if !self.0.is_null() {
            unsafe {
                let _ = CryptMsgClose(Some(self.0));
            }
        }
    }
}
struct StoreGuard(HCERTSTORE);
impl Drop for StoreGuard {
    fn drop(&mut self) {
        if !self.0 .0.is_null() {
            unsafe {
                let _ = CertCloseStore(Some(self.0), 0);
            }
        }
    }
}
struct CertGuard(*const CERT_CONTEXT);
impl Drop for CertGuard {
    fn drop(&mut self) {
        if !self.0.is_null() {
            unsafe {
                let _ = CertFreeCertificateContext(Some(self.0));
            }
        }
    }
}

fn signer_organization(path: &Path) -> Result<String> {
    let wide = to_wide(path);
    let mut store = HCERTSTORE::default();
    let mut msg: *mut c_void = ptr::null_mut();
    // SAFETY: `wide` is a valid NUL-terminated path; out-params are valid.
    unsafe {
        CryptQueryObject(
            CERT_QUERY_OBJECT_FILE,
            wide.as_ptr() as *const c_void,
            CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED_EMBED,
            CERT_QUERY_FORMAT_FLAG_BINARY,
            0,
            None,
            None,
            None,
            Some(&mut store),
            Some(&mut msg),
            None,
        )
    }
    .context("CryptQueryObject failed (the binary has no embedded PKCS#7 signature)")?;
    let _store_guard = StoreGuard(store);
    let _msg_guard = MsgGuard(msg);

    // Fetch the first signer info (Issuer + SerialNumber identify its cert).
    let mut signer_len = 0u32;
    unsafe { CryptMsgGetParam(msg, CMSG_SIGNER_INFO_PARAM, 0, None, &mut signer_len) }
        .context("CryptMsgGetParam(size) failed")?;
    let mut signer_buf = vec![0u8; signer_len as usize];
    unsafe {
        CryptMsgGetParam(
            msg,
            CMSG_SIGNER_INFO_PARAM,
            0,
            Some(signer_buf.as_mut_ptr() as *mut c_void),
            &mut signer_len,
        )
    }
    .context("CryptMsgGetParam failed")?;
    // SAFETY: the buffer holds a CMSG_SIGNER_INFO as populated above. The Vec is
    // only 1-byte aligned, so read the struct with `read_unaligned` rather than
    // forming a misaligned reference (which would be UB).
    let signer = unsafe { ptr::read_unaligned(signer_buf.as_ptr() as *const CMSG_SIGNER_INFO) };

    // Deep-copy the Issuer and SerialNumber blobs into owned buffers, so the
    // CERT_INFO used for the certificate lookup does not rely on pointers into
    // `signer_buf` (nor into the just-read `signer` copy) remaining valid.
    let issuer_bytes = copy_blob(signer.Issuer.pbData, signer.Issuer.cbData);
    let serial_bytes = copy_blob(signer.SerialNumber.pbData, signer.SerialNumber.cbData);
    let cert_info = CERT_INFO {
        Issuer: CRYPT_INTEGER_BLOB {
            cbData: issuer_bytes.len() as u32,
            pbData: issuer_bytes.as_ptr() as *mut u8,
        },
        SerialNumber: CRYPT_INTEGER_BLOB {
            cbData: serial_bytes.len() as u32,
            pbData: serial_bytes.as_ptr() as *mut u8,
        },
        ..Default::default()
    };
    // SAFETY: `store` is valid; `cert_info` (and the owned blob buffers it
    // points at) outlive the call.
    let cert = unsafe {
        CertFindCertificateInStore(
            store,
            CERT_QUERY_ENCODING_TYPE(X509_ASN_ENCODING.0 | PKCS_7_ASN_ENCODING.0),
            0,
            CERT_FIND_SUBJECT_CERT,
            Some(&cert_info as *const _ as *const c_void),
            None,
        )
    };
    // Keep the owned blob buffers alive until after the lookup.
    drop(issuer_bytes);
    drop(serial_bytes);
    if cert.is_null() {
        bail!("could not locate the signer certificate in the embedded PKCS#7 store");
    }
    let _cert_guard = CertGuard(cert);

    cert_organization_name(cert)
}

/// Copies a `cbData`/`pbData` crypto blob into an owned `Vec<u8>`. An empty or
/// null blob yields an empty vector.
fn copy_blob(pb_data: *const u8, cb_data: u32) -> Vec<u8> {
    if pb_data.is_null() || cb_data == 0 {
        return Vec::new();
    }
    // SAFETY: `pb_data` points to `cb_data` valid bytes in the signer buffer.
    unsafe { std::slice::from_raw_parts(pb_data, cb_data as usize) }.to_vec()
}

fn cert_organization_name(cert: *const CERT_CONTEXT) -> Result<String> {
    // szOID_ORGANIZATION_NAME. Passed as the type parameter for
    // CERT_NAME_ATTR_TYPE.
    let oid = PCSTR(c"2.5.4.10".as_ptr() as *const u8);
    let type_para = oid.0 as *const c_void;

    // First call: required length (in wide chars, including the NUL).
    let len = unsafe { CertGetNameStringW(cert, CERT_NAME_ATTR_TYPE, 0, Some(type_para), None) };
    if len <= 1 {
        bail!("the signer certificate has no Organization (O) name");
    }
    let mut buf = vec![0u16; len as usize];
    let written = unsafe {
        CertGetNameStringW(
            cert,
            CERT_NAME_ATTR_TYPE,
            0,
            Some(type_para),
            Some(&mut buf),
        )
    };
    if written == 0 {
        bail!("failed to read the signer certificate Organization name");
    }
    // `written` includes the terminating NUL.
    let end = (written as usize).saturating_sub(1).min(buf.len());
    Ok(String::from_utf16_lossy(&buf[..end]))
}

/// The DACL and owner of a directory, reduced to what the gate needs.
struct DirectorySecurity {
    owner: String,
    dacl: Vec<DaclEntry>,
}

/// Verify the whole ancestry chain from the directory that holds `plm.exe`
/// (the leaf) up through the volume root. The leaf must reject any side-load /
/// create / replace right; each ancestor must reject rights that would let a
/// non-privileged principal delete, rename, or re-secure the protected subtree
/// (but not harmless create-a-sibling rights). Every directory in the chain
/// must additionally be **owned** by a privileged principal, because an owner
/// has implicit `WRITE_DAC` and could grant itself anything.
fn verify_directory_chain(leaf: &Path) -> Result<()> {
    verify_one_directory(leaf, DirRole::Leaf)?;
    let mut current = leaf.to_path_buf();
    while let Some(parent) = current.parent().map(Path::to_path_buf) {
        if parent == current {
            break;
        }
        verify_one_directory(&parent, DirRole::Ancestor)?;
        current = parent;
    }
    Ok(())
}

fn verify_one_directory(dir: &Path, role: DirRole) -> Result<()> {
    let security = read_directory_security(dir)
        .with_context(|| format!("failed to read the security of {}", dir.display()))?;

    if !is_privileged_sid(&security.owner) {
        bail!(
            "refusing to elevate: {} ({role:?}) is owned by non-privileged principal {} — an \
             owner has implicit WRITE_DAC and can grant itself replacement rights. It must be \
             owned by SYSTEM, Administrators, or TrustedInstaller.",
            dir.display(),
            security.owner
        );
    }

    if let Some((sid, mask)) = replaceable_by(&security.dacl, role.dangerous_mask()) {
        let label = broad_principal_from_sid(&sid)
            .map(|principal| format!("{principal:?} ({sid})"))
            .unwrap_or_else(|| sid.clone());
        bail!(
            "refusing to elevate: {} ({role:?}) grants rights (access mask {mask:#010x}) to \
             non-privileged principal {label} that could replace or displace plm.exe. Install it \
             under a subtree writable only by SYSTEM, Administrators, or TrustedInstaller.",
            dir.display()
        );
    }
    Ok(())
}

/// Reads the owner SID and effective DACL of `dir`. Includes inherited ACEs
/// (they apply to this object); skips inherit-only ACEs (they do not). Fails
/// closed on a NULL DACL, a missing owner, or any ACE type that is not a
/// standard allow/deny.
fn read_directory_security(dir: &Path) -> Result<DirectorySecurity> {
    let wide = to_wide(dir);
    let mut owner_psid = PSID::default();
    let mut dacl: *mut ACL = ptr::null_mut();
    let mut sd = PSECURITY_DESCRIPTOR::default();
    // SAFETY: `wide` is a valid NUL-terminated path; out-params are valid.
    let rc = unsafe {
        GetNamedSecurityInfoW(
            PCWSTR(wide.as_ptr()),
            SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
            Some(&mut owner_psid),
            None,
            Some(&mut dacl),
            None,
            &mut sd,
        )
    };
    if rc != ERROR_SUCCESS {
        bail!(
            "GetNamedSecurityInfoW failed for {} (error {})",
            dir.display(),
            rc.0
        );
    }
    let _sd_guard = SecurityDescriptorGuard(sd);

    if owner_psid.0.is_null() {
        bail!("the directory {} has no owner", dir.display());
    }
    let owner = sid_to_string(owner_psid)?;

    require_present_dacl(!dacl.is_null())
        .with_context(|| format!("the guarded PLM directory {}", dir.display()))?;

    let dacl = parse_dacl(dacl)
        .with_context(|| format!("failed to parse the DACL of {}", dir.display()))?;
    Ok(DirectorySecurity { owner, dacl })
}

/// Walks a non-NULL DACL into `(sid, mask, allow)` entries, failing closed on
/// any ACE we do not fully understand.
fn parse_dacl(dacl: *const ACL) -> Result<Vec<DaclEntry>> {
    if dacl.is_null() {
        bail!("cannot parse a NULL DACL");
    }
    let mut info = ACL_SIZE_INFORMATION::default();
    // SAFETY: `dacl` is a valid non-NULL ACL pointer.
    unsafe {
        GetAclInformation(
            dacl,
            &mut info as *mut _ as *mut c_void,
            std::mem::size_of::<ACL_SIZE_INFORMATION>() as u32,
            AclSizeInformation,
        )
    }
    .context("GetAclInformation failed")?;

    let acl_start = dacl as usize;
    let acl_len = info.AclBytesInUse as usize;
    if acl_len < std::mem::size_of::<ACL>() {
        bail!("the DACL is shorter than its fixed header");
    }
    let acl_end = acl_start
        .checked_add(acl_len)
        .context("the DACL address range overflowed")?;

    let mut entries = Vec::with_capacity(info.AceCount as usize);
    for index in 0..info.AceCount {
        let mut ace_ptr: *mut c_void = ptr::null_mut();
        // A failure to read any ACE is treated as fail-closed corruption.
        unsafe { GetAce(dacl, index, &mut ace_ptr) }
            .with_context(|| format!("GetAce({index}) failed"))?;
        if ace_ptr.is_null() {
            bail!("GetAce({index}) succeeded without returning an ACE pointer");
        }
        let ace_start = ace_ptr as usize;
        let header_end = ace_start
            .checked_add(std::mem::size_of::<ACE_HEADER>())
            .context("the ACE header address range overflowed")?;
        if ace_start < acl_start || header_end > acl_end {
            bail!("ACE {index} has a header outside the DACL bounds");
        }
        // SAFETY: the fixed-size header range was proven to lie within the DACL.
        let header = unsafe { ptr::read_unaligned(ace_ptr as *const ACE_HEADER) };
        let ace_len = header.AceSize as usize;
        let ace_end = ace_start
            .checked_add(ace_len)
            .context("the ACE address range overflowed")?;
        if ace_len < std::mem::size_of::<ACE_HEADER>() || ace_end > acl_end {
            bail!("ACE {index} has an invalid size ({ace_len} bytes)");
        }
        if header.AceFlags & INHERIT_ONLY_ACE != 0 {
            // Inherit-only ACEs do not apply to this directory.
            continue;
        }
        let allow = match ace_type_kind(header.AceType) {
            Some(kind) => kind,
            None => bail!(
                "the DACL contains an unsupported ACE type {:#04x} (object/callback/conditional); \
                 failing closed because its effect cannot be classified",
                header.AceType
            ),
        };
        // ACCESS_ALLOWED_ACE and ACCESS_DENIED_ACE share layout through SidStart.
        let mask_offset = std::mem::offset_of!(ACCESS_ALLOWED_ACE, Mask);
        let sid_offset = std::mem::offset_of!(ACCESS_ALLOWED_ACE, SidStart);
        const SID_FIXED_HEADER_LEN: usize = 8;
        let minimum_len = sid_offset
            .checked_add(SID_FIXED_HEADER_LEN)
            .context("the minimum ACE size overflowed")?;
        if ace_len < minimum_len {
            bail!("ACE {index} is too short to contain a SID");
        }
        // SAFETY: the complete mask and fixed SID header lie within the
        // validated ACE range.
        let mask = unsafe { ptr::read_unaligned((ace_start + mask_offset) as *const u32) };
        let sid_start = (ace_start + sid_offset) as *const u8;
        let subauthority_count = unsafe { ptr::read(sid_start.add(1)) } as usize;
        let sid_len = SID_FIXED_HEADER_LEN
            .checked_add(
                subauthority_count
                    .checked_mul(std::mem::size_of::<u32>())
                    .context("the SID subauthority length overflowed")?,
            )
            .context("the SID length overflowed")?;
        if sid_offset
            .checked_add(sid_len)
            .is_none_or(|required_len| required_len > ace_len)
        {
            bail!("ACE {index} contains a SID that extends beyond the ACE bounds");
        }
        let sid = PSID(sid_start as *mut c_void);
        let sid_string = sid_to_string(sid)?;
        entries.push(DaclEntry {
            sid: sid_string,
            mask,
            allow,
        });
    }
    Ok(entries)
}

struct SecurityDescriptorGuard(PSECURITY_DESCRIPTOR);
impl Drop for SecurityDescriptorGuard {
    fn drop(&mut self) {
        if !self.0 .0.is_null() {
            unsafe {
                let _ = LocalFree(Some(HLOCAL(self.0 .0)));
            }
        }
    }
}

fn sid_to_string(sid: PSID) -> Result<String> {
    let mut string_sid = PWSTR::null();
    unsafe { ConvertSidToStringSidW(sid, &mut string_sid) }
        .context("ConvertSidToStringSidW failed")?;
    // SAFETY: `string_sid` is a valid NUL-terminated wide string allocated by
    // the call; freed below.
    let value = unsafe { string_sid.to_string() }.unwrap_or_default();
    unsafe {
        let _ = LocalFree(Some(HLOCAL(string_sid.0 as *mut c_void)));
    }
    Ok(value)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn microsoft_organization_is_trusted_case_insensitively() {
        assert!(is_trusted_microsoft_org("Microsoft Corporation"));
        assert!(is_trusted_microsoft_org("  microsoft corporation  "));
        assert!(!is_trusted_microsoft_org("Microsoft"));
        assert!(!is_trusted_microsoft_org("Contoso Corporation"));
        assert!(!is_trusted_microsoft_org(""));
    }

    #[test]
    fn broad_principals_are_labelled() {
        assert_eq!(
            broad_principal_from_sid("S-1-1-0"),
            Some(BroadPrincipal::Everyone)
        );
        assert_eq!(
            broad_principal_from_sid("s-1-5-11"),
            Some(BroadPrincipal::AuthenticatedUsers)
        );
        assert_eq!(
            broad_principal_from_sid("S-1-5-32-545"),
            Some(BroadPrincipal::BuiltinUsers)
        );
        assert_eq!(broad_principal_from_sid("S-1-5-21-1-2-3-1001"), None);
    }

    #[test]
    fn privileged_sids_are_recognized() {
        assert!(is_privileged_sid("S-1-5-18"));
        assert!(is_privileged_sid("s-1-5-32-544"));
        assert!(is_privileged_sid(
            "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464"
        ));
        assert!(!is_privileged_sid("S-1-5-32-545")); // BUILTIN\Users
        assert!(!is_privileged_sid("S-1-1-0")); // Everyone
        assert!(!is_privileged_sid("S-1-5-21-1-2-3-1001")); // a normal user
    }

    #[test]
    fn ace_types_fail_closed_on_anything_but_standard_allow_deny() {
        assert_eq!(ace_type_kind(ACCESS_ALLOWED_ACE_TYPE), Some(true));
        assert_eq!(ace_type_kind(ACCESS_DENIED_ACE_TYPE), Some(false));
        // Object, callback, conditional (0x0c-0x0f), and audit ACE types are
        // unsupported and must classify as `None` (the caller then fails
        // closed).
        for unsupported in [0x02u8, 0x05, 0x06, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f] {
            assert_eq!(ace_type_kind(unsupported), None, "type {unsupported:#04x}");
        }
    }

    #[test]
    fn null_dacl_fails_closed() {
        assert!(require_present_dacl(true).is_ok());
        let error = require_present_dacl(false).expect_err("a NULL DACL must be rejected");
        assert!(error.to_string().contains("NULL DACL"), "got: {error}");
    }

    #[test]
    fn leaf_and_ancestor_masks_differ_for_create_rights() {
        let leaf = DirRole::Leaf.dangerous_mask();
        let ancestor = DirRole::Ancestor.dangerous_mask();
        // Creating a file/subdir is dangerous in the leaf (side-load / drop a
        // replacement) but harmless "create a sibling" for an ancestor.
        assert!(mask_permits(FILE_ADD_FILE, leaf));
        assert!(mask_permits(FILE_ADD_SUBDIRECTORY, leaf));
        assert!(mask_permits(GENERIC_WRITE, leaf));
        assert!(!mask_permits(FILE_ADD_FILE, ancestor));
        assert!(!mask_permits(FILE_ADD_SUBDIRECTORY, ancestor));
        assert!(!mask_permits(GENERIC_WRITE, ancestor));
        // Delete/rename/replace and DACL/owner rewrites are dangerous for both.
        for right in [
            FILE_DELETE_CHILD,
            DELETE,
            WRITE_DAC,
            WRITE_OWNER,
            GENERIC_ALL,
        ] {
            assert!(mask_permits(right, leaf), "leaf {right:#010x}");
            assert!(mask_permits(right, ancestor), "ancestor {right:#010x}");
        }
        // Read/execute-only is safe for both.
        assert!(!mask_permits(0x0020 /* FILE_EXECUTE */, leaf));
        assert!(!mask_permits(0x0001 /* FILE_READ_DATA */, ancestor));
    }

    fn entry(sid: &str, mask: u32, allow: bool) -> DaclEntry {
        DaclEntry {
            sid: sid.to_string(),
            mask,
            allow,
        }
    }

    #[test]
    fn directory_with_only_privileged_writers_is_accepted() {
        let entries = vec![
            entry("S-1-5-18", GENERIC_ALL, true),         // SYSTEM
            entry("S-1-5-32-544", GENERIC_ALL, true),     // Administrators
            entry("S-1-5-32-545", 0x0020 | 0x0001, true), // Users: read/execute
            entry("S-1-5-11", 0x0020 | 0x0001, true),     // Authenticated Users: R/X
        ];
        assert!(replaceable_by(&entries, LEAF_DANGEROUS_MASK).is_none());
        assert!(replaceable_by(&entries, ANCESTOR_DANGEROUS_MASK).is_none());
    }

    #[test]
    fn directory_writable_by_broad_principal_is_rejected() {
        let entries = vec![
            entry("S-1-5-18", GENERIC_ALL, true),
            entry("S-1-1-0", FILE_ADD_FILE, true), // Everyone can create files
        ];
        let (sid, mask) = replaceable_by(&entries, LEAF_DANGEROUS_MASK).expect("must reject");
        assert_eq!(sid, "S-1-1-0");
        assert_eq!(mask, FILE_ADD_FILE);
    }

    #[test]
    fn create_sibling_at_ancestor_is_allowed_but_delete_child_is_not() {
        // An ancestor (e.g. a drive root) that lets Users create folders is
        // fine; one that lets them delete children is not.
        let create_only = vec![entry("S-1-5-32-545", FILE_ADD_SUBDIRECTORY, true)];
        assert!(replaceable_by(&create_only, ANCESTOR_DANGEROUS_MASK).is_none());
        // The same right on the LEAF is rejected.
        assert!(replaceable_by(&create_only, LEAF_DANGEROUS_MASK).is_some());

        let delete_child = vec![entry("S-1-5-32-545", FILE_DELETE_CHILD, true)];
        assert!(replaceable_by(&delete_child, ANCESTOR_DANGEROUS_MASK).is_some());
    }

    #[test]
    fn directory_writable_by_a_normal_user_is_rejected() {
        let entries = vec![
            entry("S-1-5-18", GENERIC_ALL, true),
            entry("S-1-5-21-1-2-3-1001", GENERIC_WRITE, true), // a specific user
        ];
        assert!(replaceable_by(&entries, LEAF_DANGEROUS_MASK).is_some());
    }

    #[test]
    fn deny_aces_do_not_trigger_rejection() {
        // A deny ACE, even to a broad principal with dangerous rights, is not
        // itself evidence of write access.
        let entries = vec![entry("S-1-1-0", GENERIC_ALL, false)];
        assert!(replaceable_by(&entries, LEAF_DANGEROUS_MASK).is_none());
    }

    #[test]
    fn a_user_writable_temp_directory_is_rejected() {
        // Deterministic, requires no signed binary: a freshly created temp
        // directory under the user profile is either owned by the current
        // (unprivileged) user or grants that user replacement rights, so the
        // chain gate must reject it.
        let dir = tempfile::tempdir().expect("temp dir");
        let error = verify_one_directory(dir.path(), DirRole::Leaf)
            .expect_err("a user-writable temp directory must be rejected");
        let message = error.to_string();
        assert!(
            message.contains("non-privileged") || message.contains("owned by"),
            "unexpected error: {message}"
        );
    }

    #[test]
    fn a_protected_leaf_under_a_user_controlled_ancestor_is_rejected() {
        // The leaf itself is a temp dir (user-controlled), so the chain walk
        // must reject it — exercising ancestor/owner enforcement on a real
        // path. (A leaf under System32 would pass; we cannot create such a
        // fixture without privileges, so we assert the rejection direction.)
        let dir = tempfile::tempdir().expect("temp dir");
        let child = dir.path().join("MXC");
        std::fs::create_dir(&child).expect("create child dir");
        assert!(verify_directory_chain(&child).is_err());
    }

    #[test]
    fn read_directory_security_reads_a_real_directory() {
        // System32 must be readable and owned by a privileged principal — a
        // real end-to-end exercise of owner + DACL retrieval and the ACE
        // fail-closed parser against a production directory.
        let system32 = std::path::Path::new(r"C:\Windows\System32");
        if !system32.is_dir() {
            eprintln!("skipping: {} not present", system32.display());
            return;
        }
        let security =
            read_directory_security(system32).expect("System32 security must be readable");
        assert!(
            is_privileged_sid(&security.owner),
            "System32 owner should be privileged, got {}",
            security.owner
        );
        assert!(!security.dacl.is_empty());
    }

    #[test]
    fn pin_file_denies_write_and_delete_while_held() {
        // Deterministic, no signing required: while the integrity guard lives,
        // the file cannot be opened for write, deleted, or renamed; after the
        // guard drops, those succeed.
        let dir = tempfile::tempdir().expect("temp dir");
        let path = dir.path().join("pinned.bin");
        std::fs::write(&path, b"payload").expect("write file");

        let handle = open_pinned_handle(&path).expect("pin the file");
        let guard = LaunchIntegrityGuard {
            handle,
            launch_path: path.clone(),
        };
        assert!(
            std::fs::OpenOptions::new().write(true).open(&path).is_err(),
            "opening the pinned file for write must fail"
        );
        assert!(
            std::fs::remove_file(&path).is_err(),
            "deleting the pinned file must fail"
        );
        assert!(
            std::fs::rename(&path, dir.path().join("renamed.bin")).is_err(),
            "renaming the pinned file must fail"
        );

        drop(guard);
        // After the guard is released, the file can be replaced/removed.
        std::fs::OpenOptions::new()
            .write(true)
            .open(&path)
            .expect("write must succeed after the guard drops");
        std::fs::remove_file(&path).expect("delete must succeed after the guard drops");
    }

    #[test]
    fn pin_file_rejects_a_missing_path() {
        let dir = tempfile::tempdir().expect("temp dir");
        let missing = dir.path().join("does-not-exist.exe");
        assert!(
            open_pinned_handle(&missing).is_err(),
            "a missing file must be rejected"
        );
        assert!(
            verify_and_pin_launch_binary(&missing).is_err(),
            "verify_and_pin must reject a missing binary"
        );
    }

    #[test]
    fn normalize_local_dos_path_accepts_drive_letters_and_rejects_non_local() {
        assert_eq!(
            normalize_local_dos_path(r"\\?\C:\Program Files\MXC\plm.exe").unwrap(),
            PathBuf::from(r"C:\Program Files\MXC\plm.exe")
        );
        // Lowercase drive and a path with no verbatim prefix both normalize.
        assert_eq!(
            normalize_local_dos_path(r"\\?\d:\x\plm.exe").unwrap(),
            PathBuf::from(r"d:\x\plm.exe")
        );
        assert_eq!(
            normalize_local_dos_path(r"C:\already\plain.exe").unwrap(),
            PathBuf::from(r"C:\already\plain.exe")
        );
        // UNC/remote and device / GUID-volume forms fail closed.
        assert!(normalize_local_dos_path(r"\\?\UNC\server\share\plm.exe").is_err());
        assert!(normalize_local_dos_path(r"\\?\unc\server\share\plm.exe").is_err());
        assert!(
            normalize_local_dos_path(r"\\?\Volume{12345678-0000-0000-0000-000000000000}\x")
                .is_err()
        );
        assert!(normalize_local_dos_path(r"\\server\share\plm.exe").is_err());
        assert!(normalize_local_dos_path(r"\Device\HarddiskVolume3\x").is_err());
    }

    #[test]
    fn resolve_pinned_local_path_returns_the_stable_local_object() {
        // Deterministic: resolving a pinned temp file yields a local DOS path
        // that names the same file (its final component matches).
        let dir = tempfile::tempdir().expect("temp dir");
        let path = dir.path().join("resolve-me.bin");
        std::fs::write(&path, b"x").expect("write file");

        let handle = open_pinned_handle(&path).expect("pin");
        let guard = LaunchIntegrityGuard {
            handle,
            launch_path: PathBuf::new(),
        };
        let resolved = resolve_pinned_local_path(guard.handle).expect("resolve");
        assert_eq!(
            resolved.file_name().and_then(|n| n.to_str()),
            Some("resolve-me.bin"),
            "resolved: {}",
            resolved.display()
        );
        // It is a local drive-letter path and refers to the same file.
        let s = resolved.to_string_lossy();
        assert!(
            s.as_bytes().get(1) == Some(&b':'),
            "expected a drive-letter path, got {s}"
        );
        assert!(resolved.is_file());
    }

    #[test]
    fn resolve_defeats_a_symlink_alias_if_symlinks_can_be_created() {
        // If the environment permits symlink creation (admin or Developer
        // Mode), opening through a symlink and resolving must yield the
        // underlying target, never the alias path. Skips otherwise.
        let dir = tempfile::tempdir().expect("temp dir");
        let target = dir.path().join("target.bin");
        std::fs::write(&target, b"payload").expect("write target");
        let link = dir.path().join("alias.bin");
        if std::os::windows::fs::symlink_file(&target, &link).is_err() {
            eprintln!("skipping: symlink creation not permitted on this host");
            return;
        }

        let handle = open_pinned_handle(&link).expect("pin via symlink");
        let guard = LaunchIntegrityGuard {
            handle,
            launch_path: PathBuf::new(),
        };
        let resolved = resolve_pinned_local_path(guard.handle).expect("resolve");
        assert_eq!(
            resolved.file_name().and_then(|n| n.to_str()),
            Some("target.bin"),
            "the resolved launch path must be the target, not the alias: {}",
            resolved.display()
        );
        assert!(
            !resolved
                .to_string_lossy()
                .to_ascii_lowercase()
                .contains("alias.bin"),
            "resolution must never return the original alias: {}",
            resolved.display()
        );
    }

    #[test]
    fn unsigned_binary_fails_authenticode_and_signer_read() {
        // An unsigned file deterministically fails both the Authenticode check
        // and the signer-identity read — no signed fixture required.
        let dir = tempfile::tempdir().expect("temp dir");
        let path = dir.path().join("unsigned.exe");
        std::fs::write(&path, b"MZ not a real signed PE").expect("write file");

        let handle = open_pinned_handle(&path).expect("pin the unsigned file");
        let guard = LaunchIntegrityGuard {
            handle,
            launch_path: path.clone(),
        };
        assert!(
            verify_authenticode(&path, guard.handle).is_err(),
            "an unsigned file must fail Authenticode verification"
        );
        assert!(
            signer_organization(&path).is_err(),
            "an unsigned file has no signer organization"
        );
    }

    #[test]
    fn a_microsoft_signed_system_binary_is_recognized_if_available() {
        // Best-effort positive check: if an embedded-signed Microsoft binary is
        // present, its Authenticode chain must verify and its signer
        // organization must be Microsoft. Many system binaries are catalog-
        // signed (no embedded signature), so this test skips when no suitable
        // fixture verifies — it never fails on such environments.
        let candidates = [
            r"C:\Windows\System32\wpr.exe",
            r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
            r"C:\Windows\System32\dpnsvr.exe",
        ];
        for candidate in candidates {
            let path = std::path::Path::new(candidate);
            if !path.is_file() {
                continue;
            }
            let Ok(handle) = open_pinned_handle(path) else {
                continue;
            };
            let guard = LaunchIntegrityGuard {
                handle,
                launch_path: path.to_path_buf(),
            };
            if verify_authenticode(path, guard.handle).is_err() {
                // Likely catalog-signed on this build; try the next candidate.
                continue;
            }
            match signer_organization(path) {
                Ok(org) => {
                    assert!(
                        is_trusted_microsoft_org(&org),
                        "{candidate} is Microsoft-signed but org was {org:?}"
                    );
                    return;
                }
                Err(_) => continue,
            }
        }
        eprintln!("skipping: no embedded-signed Microsoft fixture available on this host");
    }

    #[test]
    fn revocation_policy_is_whole_chain_excluding_root() {
        // Pure policy assertion (the runtime WinVerifyTrust result is
        // environment-dependent): revocation is checked across the whole chain,
        // excluding the self-signed root.
        assert_eq!(REVOCATION_CHECKS, WTD_REVOKE_WHOLECHAIN);
        assert_eq!(
            REVOCATION_PROVIDER_FLAGS,
            WTD_REVOCATION_CHECK_CHAIN_EXCLUDE_ROOT
        );
    }
}
