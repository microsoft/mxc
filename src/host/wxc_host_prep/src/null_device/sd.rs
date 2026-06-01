// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Read, diff, and write security descriptors on a kernel object.
//!
//! The shape of the work:
//!
//! * **Read** — `GetKernelObjectSecurity` two-call dance into a
//!   self-relative buffer; wrap in [`OwnedSecurityDescriptor`].
//! * **Diff** — extract `(SidString, AccessMask, AceType, AceFlags)`
//!   tuples from the DACL/SACL and from the parsed target, compare as
//!   *sets* (order-insensitive); compare owner/group via `EqualSid`.
//! * **Write** — `SetKernelObjectSecurity` with whichever
//!   `SECURITY_INFORMATION` bits we have authority for.
//!
//! The diff returns a [`Drift`] variant naming the first component
//! that differs (owner > group > DACL > SACL), so the apply log line
//! describes *why* we wrote. A full structural compare would be
//! over-engineered for our purpose — once any component differs we
//! write the whole target, because writing components piecemeal
//! creates failure-recovery edge cases.

use windows::Win32::Foundation::{GetLastError, ERROR_INSUFFICIENT_BUFFER, HANDLE};
use windows::Win32::Security::Authorization::{
    ConvertSecurityDescriptorToStringSecurityDescriptorW, ConvertSidToStringSidW, SDDL_REVISION_1,
};
use windows::Win32::Security::{
    EqualSid, GetKernelObjectSecurity, GetSecurityDescriptorDacl, GetSecurityDescriptorGroup,
    GetSecurityDescriptorOwner, GetSecurityDescriptorSacl, MapGenericMask, SetKernelObjectSecurity,
    ACE_HEADER, ACL, DACL_SECURITY_INFORMATION, GENERIC_MAPPING, GROUP_SECURITY_INFORMATION,
    LABEL_SECURITY_INFORMATION, OBJECT_SECURITY_INFORMATION, OWNER_SECURITY_INFORMATION,
    PSECURITY_DESCRIPTOR, PSID, SACL_SECURITY_INFORMATION,
};
use windows::Win32::System::SystemServices::{
    ACCESS_ALLOWED_ACE_TYPE, ACCESS_DENIED_ACE_TYPE, SYSTEM_AUDIT_ACE_TYPE,
    SYSTEM_MANDATORY_LABEL_ACE_TYPE,
};
use windows_core::{BOOL, PWSTR};

use super::sddl::local_free_sd;
use super::NullDeviceError;

/// Owns a `PSECURITY_DESCRIPTOR` allocation. The construction
/// callsites determine which deallocator runs on drop.
pub struct OwnedSecurityDescriptor {
    psd: PSECURITY_DESCRIPTOR,
    storage: SdStorage,
}

enum SdStorage {
    /// Allocated by `LocalAlloc` (e.g. the SDDL parser); free with `LocalFree`.
    LocalAlloc,
    /// Allocated by us as a `Vec<u8>` backing buffer. The vec drops
    /// normally; its bytes back the `PSECURITY_DESCRIPTOR` in
    /// [`OwnedSecurityDescriptor::psd`] for the lifetime of the
    /// struct.
    Vec(#[allow(dead_code)] Vec<u8>),
}

impl OwnedSecurityDescriptor {
    /// SAFETY: caller asserts the descriptor was returned by an API
    /// that requires `LocalFree`.
    pub unsafe fn from_local_alloc(psd: PSECURITY_DESCRIPTOR) -> Self {
        Self {
            psd,
            storage: SdStorage::LocalAlloc,
        }
    }

    fn from_vec(mut buf: Vec<u8>) -> Self {
        let psd = PSECURITY_DESCRIPTOR(buf.as_mut_ptr() as *mut _);
        Self {
            psd,
            storage: SdStorage::Vec(buf),
        }
    }

    pub fn as_psecurity_descriptor(&self) -> PSECURITY_DESCRIPTOR {
        self.psd
    }
}

impl Drop for OwnedSecurityDescriptor {
    fn drop(&mut self) {
        match &mut self.storage {
            SdStorage::LocalAlloc => unsafe { local_free_sd(self.psd) },
            SdStorage::Vec(_) => { /* Vec drops normally */ }
        }
    }
}

/// Outcome of [`diff`]. Reports the first differing component; the
/// apply path treats anything that isn't `Match` as "rewrite the
/// whole SD" — partial writes are not worth the failure-recovery
/// complexity.
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum Drift {
    Match,
    OwnerDiffers,
    GroupDiffers,
    DaclDiffers,
    SaclDiffers,
}

impl Drift {
    pub fn label(self) -> &'static str {
        match self {
            Drift::Match => "match",
            Drift::OwnerDiffers => "owner-differs",
            Drift::GroupDiffers => "group-differs",
            Drift::DaclDiffers => "dacl-differs",
            Drift::SaclDiffers => "sacl-differs",
        }
    }
}

/// Read the security descriptor of `handle` into a self-relative
/// buffer we own. `want_sacl` controls whether SACL coverage is
/// requested — callers without `SeSecurityPrivilege` must pass false.
pub fn read_current_sd(
    handle: HANDLE,
    want_sacl: bool,
) -> Result<OwnedSecurityDescriptor, NullDeviceError> {
    // The mandatory integrity label is part of the SACL on disk, but
    // its in-API info bit is separate (`LABEL_SECURITY_INFORMATION`)
    // and reading / writing it requires no extra privilege. Always
    // include it so we round-trip the label even when the caller
    // declined to read the full SACL (e.g. running unelevated for the
    // DACL-only configuration).
    let mut info: OBJECT_SECURITY_INFORMATION = OWNER_SECURITY_INFORMATION
        | GROUP_SECURITY_INFORMATION
        | DACL_SECURITY_INFORMATION
        | LABEL_SECURITY_INFORMATION;
    if want_sacl {
        info |= SACL_SECURITY_INFORMATION;
    }

    // First call: probe for the required size.
    let mut needed: u32 = 0;
    let probe = unsafe { GetKernelObjectSecurity(handle, info.0, None, 0, &mut needed) };
    match probe {
        Ok(()) => {
            // A zero-length SD is suspicious but not impossible; treat
            // it as success with an empty buffer.
            if needed == 0 {
                return Ok(OwnedSecurityDescriptor::from_vec(Vec::new()));
            }
        }
        Err(_) => {
            let last = unsafe { GetLastError() };
            if last != ERROR_INSUFFICIENT_BUFFER {
                return Err(NullDeviceError::ReadFailed(format!(
                    "GetKernelObjectSecurity probe: Win32 error {}",
                    last.0
                )));
            }
        }
    }

    // Second call: read into a right-sized buffer.
    let mut buf = vec![0u8; needed as usize];
    let mut written: u32 = 0;
    let result = unsafe {
        GetKernelObjectSecurity(
            handle,
            info.0,
            Some(PSECURITY_DESCRIPTOR(buf.as_mut_ptr() as *mut _)),
            needed,
            &mut written,
        )
    };
    if let Err(e) = result {
        return Err(NullDeviceError::ReadFailed(format!(
            "GetKernelObjectSecurity: {e}"
        )));
    }
    buf.truncate(written as usize);
    Ok(OwnedSecurityDescriptor::from_vec(buf))
}

/// Write `target` to `handle`. The `SECURITY_INFORMATION` bits we set
/// depend on whether `want_sacl` is true.
pub fn write_target_sd(
    handle: HANDLE,
    target: &OwnedSecurityDescriptor,
    want_sacl: bool,
) -> Result<(), NullDeviceError> {
    // See `read_current_sd` — `LABEL_SECURITY_INFORMATION` is always
    // safe to include and is required to install the mandatory
    // integrity label even when SACL writes are skipped.
    let mut info: OBJECT_SECURITY_INFORMATION = OWNER_SECURITY_INFORMATION
        | GROUP_SECURITY_INFORMATION
        | DACL_SECURITY_INFORMATION
        | LABEL_SECURITY_INFORMATION;
    if want_sacl {
        info |= SACL_SECURITY_INFORMATION;
    }

    unsafe {
        SetKernelObjectSecurity(handle, info, target.as_psecurity_descriptor())
            .map_err(|e| NullDeviceError::WriteFailed(format!("SetKernelObjectSecurity: {e}")))?;
    }
    Ok(())
}

/// Serialise an SD to SDDL for human-readable output (`dump`).
pub fn sd_to_sddl(sd: &OwnedSecurityDescriptor) -> Result<String, NullDeviceError> {
    let info: OBJECT_SECURITY_INFORMATION = OWNER_SECURITY_INFORMATION
        | GROUP_SECURITY_INFORMATION
        | DACL_SECURITY_INFORMATION
        | SACL_SECURITY_INFORMATION
        | LABEL_SECURITY_INFORMATION;

    let mut out_str = PWSTR::null();
    let mut out_len: u32 = 0;
    let result = unsafe {
        ConvertSecurityDescriptorToStringSecurityDescriptorW(
            sd.as_psecurity_descriptor(),
            SDDL_REVISION_1,
            info,
            &mut out_str,
            Some(&mut out_len),
        )
    };
    if let Err(e) = result {
        return Err(NullDeviceError::SddlSerializeFailed(format!(
            "ConvertSecurityDescriptorToStringSecurityDescriptorW: {e}"
        )));
    }
    if out_str.is_null() {
        return Err(NullDeviceError::SddlSerializeFailed(
            "ConvertSecurityDescriptorToStringSecurityDescriptorW returned NULL".to_string(),
        ));
    }

    // SAFETY: the API documents the buffer is null-terminated and
    // `out_len` excludes the terminator; either path is fine for
    // String reconstruction.
    let slice = unsafe { std::slice::from_raw_parts(out_str.as_ptr(), out_len as usize) };
    let s = String::from_utf16_lossy(slice);

    // SAFETY: the API documents the caller is responsible for
    // LocalFree'ing the returned buffer.
    unsafe {
        local_free_sd(PSECURITY_DESCRIPTOR(out_str.as_ptr() as *mut _));
    }
    Ok(s)
}

/// Generic mapping for `IoFileObjectType`, i.e. the mapping the kernel
/// applies at write time when `\Device\Null` (a `FILE_DEVICE_NULL`
/// kernel object) is the target. Defined by the I/O manager as:
///
/// ```c
/// GENERIC_MAPPING IoFileObjectType_GenericMapping = {
///     FILE_GENERIC_READ,    // 0x00120089
///     FILE_GENERIC_WRITE,   // 0x00120116
///     FILE_GENERIC_EXECUTE, // 0x001200A0
///     FILE_ALL_ACCESS,      // 0x001F01FF
/// };
/// ```
///
/// We need this on the *read* side of [`diff`]: the target SD we
/// parse from SDDL still has `GENERIC_READ | GENERIC_WRITE |
/// GENERIC_EXECUTE` bits set (`0xE0000000`), but after we hand the
/// SD to `SetKernelObjectSecurity` the kernel maps those generics
/// to file-specific bits (`0x001201BF`) before persisting. So a
/// naive byte-for-byte mask compare always reports `dacl-differs`
/// even when the SD was written this boot.
const FILE_GENERIC_MAPPING: GENERIC_MAPPING = GENERIC_MAPPING {
    GenericRead: 0x0012_0089,
    GenericWrite: 0x0012_0116,
    GenericExecute: 0x0012_00A0,
    GenericAll: 0x001F_01FF,
};

/// Expand any `GENERIC_*` bits in `mask` using the file generic
/// mapping, matching what the kernel does at write time. A no-op
/// when `mask` is already specific (e.g. `FILE_ALL_ACCESS = 0x1F01FF`
/// from the `FA` rights letter) or carries no access bits at all
/// (e.g. `SYSTEM_MANDATORY_LABEL_NO_WRITE_UP = 0x1` on the integrity
/// ACE).
fn normalize_access_mask(mask: u32) -> u32 {
    let mut m = mask;
    // SAFETY: `m` is a stack-local writable u32; mapping is a const
    // table that lives for the program's lifetime.
    unsafe {
        MapGenericMask(&mut m, &FILE_GENERIC_MAPPING);
    }
    m
}

/// Compare `current` against `target` and return the first differing
/// component. When `want_sacl` is false the SACL comparison is
/// skipped (because we don't have authority to even read the current
/// SACL).
pub fn diff(
    current: &OwnedSecurityDescriptor,
    target: &OwnedSecurityDescriptor,
    want_sacl: bool,
) -> Drift {
    // Compare in priority order. Stop at first difference.
    match (
        sid_of(current, SdComponent::Owner),
        sid_of(target, SdComponent::Owner),
    ) {
        (Some(c), Some(t)) if !sids_equal(&c, &t) => return Drift::OwnerDiffers,
        (None, Some(_)) | (Some(_), None) => return Drift::OwnerDiffers,
        _ => {}
    }
    match (
        sid_of(current, SdComponent::Group),
        sid_of(target, SdComponent::Group),
    ) {
        (Some(c), Some(t)) if !sids_equal(&c, &t) => return Drift::GroupDiffers,
        (None, Some(_)) | (Some(_), None) => return Drift::GroupDiffers,
        _ => {}
    }

    let current_dacl = extract_aces(current, AclKind::Dacl);
    let target_dacl = extract_aces(target, AclKind::Dacl);
    if !ace_sets_equal(&current_dacl, &target_dacl) {
        return Drift::DaclDiffers;
    }

    if want_sacl {
        let current_sacl = extract_aces(current, AclKind::Sacl);
        let target_sacl = extract_aces(target, AclKind::Sacl);
        if !ace_sets_equal(&current_sacl, &target_sacl) {
            return Drift::SaclDiffers;
        }
    }

    Drift::Match
}

#[derive(Debug, Clone, Eq)]
struct AceTuple {
    sid: String,
    ace_type: u8,
    ace_flags: u8,
    access_mask: u32,
}

// Hash + PartialEq deliberately ignore ordering so we can compare ACEs
// as sets. `(sid, type, flags, mask)` is the canonical identity.
impl PartialEq for AceTuple {
    fn eq(&self, other: &Self) -> bool {
        self.sid == other.sid
            && self.ace_type == other.ace_type
            && self.ace_flags == other.ace_flags
            && self.access_mask == other.access_mask
    }
}

#[derive(Copy, Clone)]
enum SdComponent {
    Owner,
    Group,
}

#[derive(Copy, Clone)]
enum AclKind {
    Dacl,
    Sacl,
}

/// Wrap a raw `PSID` so we can compare via `EqualSid` without copying.
struct PsidRef(PSID);

fn sids_equal(a: &PsidRef, b: &PsidRef) -> bool {
    if a.0.is_invalid() || b.0.is_invalid() {
        return a.0.is_invalid() == b.0.is_invalid();
    }
    // SAFETY: both pointers are non-null SIDs supplied by the OS
    // (`GetSecurityDescriptorOwner` / `GetSecurityDescriptorGroup`).
    unsafe { EqualSid(a.0, b.0).is_ok() }
}

fn sid_of(sd: &OwnedSecurityDescriptor, which: SdComponent) -> Option<PsidRef> {
    let mut psid = PSID::default();
    let mut defaulted = BOOL(0);
    let result = match which {
        SdComponent::Owner => unsafe {
            GetSecurityDescriptorOwner(sd.as_psecurity_descriptor(), &mut psid, &mut defaulted)
        },
        SdComponent::Group => unsafe {
            GetSecurityDescriptorGroup(sd.as_psecurity_descriptor(), &mut psid, &mut defaulted)
        },
    };
    if result.is_err() || psid.is_invalid() {
        None
    } else {
        Some(PsidRef(psid))
    }
}

fn extract_aces(sd: &OwnedSecurityDescriptor, kind: AclKind) -> Vec<AceTuple> {
    // Pull the (present, acl_ptr, defaulted) triple from the SD.
    let mut present = BOOL(0);
    let mut acl_ptr: *mut ACL = std::ptr::null_mut();
    let mut defaulted = BOOL(0);

    let ok = match kind {
        AclKind::Dacl => unsafe {
            GetSecurityDescriptorDacl(
                sd.as_psecurity_descriptor(),
                &mut present,
                &mut acl_ptr,
                &mut defaulted,
            )
        },
        AclKind::Sacl => unsafe {
            GetSecurityDescriptorSacl(
                sd.as_psecurity_descriptor(),
                &mut present,
                &mut acl_ptr,
                &mut defaulted,
            )
        },
    };
    if ok.is_err() || !present.as_bool() || acl_ptr.is_null() {
        return Vec::new();
    }

    // Walk the ACE list. The ACL header gives us the count and total
    // size; each ACE starts with an `ACE_HEADER` whose `AceSize` tells
    // us how to advance.
    let acl: &ACL = unsafe { &*acl_ptr };
    let ace_count = acl.AceCount as usize;
    let mut result = Vec::with_capacity(ace_count);

    // Skip the ACL header to reach the first ACE.
    let mut cursor: *const u8 = (acl_ptr as *const u8).wrapping_add(std::mem::size_of::<ACL>());

    for _ in 0..ace_count {
        let header: &ACE_HEADER = unsafe { &*(cursor as *const ACE_HEADER) };
        let ace_size = header.AceSize as usize;

        // The interior layout of an ACE depends on its type, but for
        // every fixed-header ACE (access-allowed, access-denied,
        // system-audit, system-mandatory-label) the body is:
        //
        //   ACE_HEADER
        //   ACCESS_MASK (u32)
        //   SID (variable)
        //
        // We support exactly those types — they cover everything the
        // target SDDL produces and everything we expect to find in
        // the current SD.
        let body = cursor.wrapping_add(std::mem::size_of::<ACE_HEADER>());
        let access_mask = unsafe { *(body as *const u32) };
        let access_mask = normalize_access_mask(access_mask);
        let sid_ptr = body.wrapping_add(4) as *const _;

        let recognised = matches!(
            header.AceType,
            t if t == ACCESS_ALLOWED_ACE_TYPE as u8
                || t == ACCESS_DENIED_ACE_TYPE as u8
                || t == SYSTEM_AUDIT_ACE_TYPE as u8
                || t == SYSTEM_MANDATORY_LABEL_ACE_TYPE as u8
        );
        if recognised {
            let sid_str = sid_to_string(PSID(sid_ptr as *mut _));
            if let Some(s) = sid_str {
                result.push(AceTuple {
                    sid: s,
                    ace_type: header.AceType,
                    ace_flags: header.AceFlags,
                    access_mask,
                });
            }
        }

        cursor = cursor.wrapping_add(ace_size);
    }

    // Force the `ACL_SIZE_INFORMATION` / `ACL_REVISION_INFORMATION`
    // imports to compile-prove the dependency, even if unused. Avoids
    // a dead-code lint while documenting intent.
    let _ = ACL {
        AclRevision: 0,
        Sbz1: 0,
        AclSize: 0,
        AceCount: 0,
        Sbz2: 0,
    };

    result
}

fn sid_to_string(sid: PSID) -> Option<String> {
    if sid.is_invalid() {
        return None;
    }
    let mut out = PWSTR::null();
    // SAFETY: `sid` was extracted from a valid SD via the documented
    // accessors above; the API allocates a wide string we must LocalFree.
    let res = unsafe { ConvertSidToStringSidW(sid, &mut out) };
    if res.is_err() || out.is_null() {
        return None;
    }
    let s = unsafe { out.to_string().ok() };
    // SAFETY: API contract — caller must LocalFree the buffer.
    unsafe {
        let _ = windows::Win32::Foundation::LocalFree(Some(windows::Win32::Foundation::HLOCAL(
            out.as_ptr() as *mut _,
        )));
    }
    s
}

fn ace_sets_equal(a: &[AceTuple], b: &[AceTuple]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    // O(n²) is fine: n is small (the target has 6 DACL ACEs + 1 SACL
    // ACE; production SDs on `\Device\Null` have similar order of
    // magnitude). Using a HashSet would require `AceTuple: Hash`
    // which is not free given the `String` field — n² wins on
    // simplicity here.
    a.iter().all(|x| b.iter().any(|y| x == y)) && b.iter().all(|y| a.iter().any(|x| x == y))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalize_expands_file_generics() {
        // GR|GW|GX (0xE0000000) -> FILE_GENERIC_READ|WRITE|EXECUTE (0x1201BF).
        // This is what the kernel does at `SetKernelObjectSecurity` time
        // for any `IoFileObjectType`-typed object (including `\Device\Null`).
        // If this regresses, `prepare-null-device` reports "applied" every
        // run and `verify-null-device` reports "dacl-differs" forever.
        assert_eq!(normalize_access_mask(0xE000_0000), 0x0012_01BF);
        // GR|GX (0xA0000000) -> FILE_GENERIC_READ|FILE_GENERIC_EXECUTE.
        assert_eq!(normalize_access_mask(0xA000_0000), 0x0012_00A9);
        // GENERIC_ALL alone -> FILE_ALL_ACCESS.
        assert_eq!(normalize_access_mask(0x1000_0000), 0x001F_01FF);
    }

    #[test]
    fn normalize_is_idempotent_for_specific_masks() {
        // FA (FILE_ALL_ACCESS) and explicit hex masks have no generic
        // bits set; mapping must leave them untouched.
        assert_eq!(normalize_access_mask(0x001F_01FF), 0x001F_01FF);
        assert_eq!(normalize_access_mask(0x0012_01BF), 0x0012_01BF);
        // SYSTEM_MANDATORY_LABEL_NO_WRITE_UP on the integrity ACE.
        assert_eq!(normalize_access_mask(0x0000_0001), 0x0000_0001);
        // Empty mask round-trips.
        assert_eq!(normalize_access_mask(0), 0);
    }
}
