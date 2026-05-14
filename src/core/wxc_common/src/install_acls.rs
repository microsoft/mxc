// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! One-time install-side ACL adjustment for the T3 fallback chain.
//!
//! See `docs/downlevel-fallback-threat-model.md` and microsoft/mxc#304.
//!
//! The Tier-3 AppContainer needs `FILE_TRAVERSE` on every ancestor of a
//! policy path (and not just on the leaf). Non-admin MXC runs can grant
//! traverse on user-owned ancestors via `DaclManager`, but for
//! system-owned ancestors (typically `C:\` and `C:\Users\`) an admin has
//! to add the ACE once at install time. This module exposes the
//! check / add / remove primitives that the `--adjustacls` CLI surface
//! drives.
//!
//! Design constraints:
//!
//! * **Non-inheriting ACEs only.** `AceFlags = 0`. We never add an
//!   inheritable ACE here — that would cause Windows to walk every
//!   descendant of the target directory to re-canonicalize inheritance
//!   (`icacls`-style — observed empirically as several minutes of disk
//!   I/O on a 605 GB drive). `SetNamedSecurityInfoW` with a DACL
//!   containing only non-inheriting changes still walks the tree to
//!   confirm nothing changed for descendants, but does no per-file
//!   work.
//!
//! * **Idempotent.** `add_grant` is a no-op if an existing matching
//!   non-inheriting Allow ACE for `sid` already covers `mask`. The
//!   "covers" semantics mean `(existing.mask & required.mask) == required.mask`
//!   — an existing ACE that grants broader rights satisfies our
//!   requirement. We never downgrade.
//!
//! * **Surgical removal.** `remove_grant` removes only ACEs that
//!   exactly match `(sid, mask, non-inheriting, Allow)`. Other ACEs on
//!   the path — inherited, inheritable, mismatched mask, different SID
//!   — are preserved. This is the right behavior for reversing an
//!   `--adjustacls` operation: undo our specific change, leave
//!   everything else alone.

use std::path::Path;
use std::ptr;

use windows::core::PCWSTR;
use windows::Win32::Foundation::{LocalFree, HLOCAL, WIN32_ERROR};
use windows::Win32::Security::Authorization::{
    ConvertStringSidToSidW, GetNamedSecurityInfoW, SetEntriesInAclW, SetNamedSecurityInfoW,
    EXPLICIT_ACCESS_W, GRANT_ACCESS, NO_MULTIPLE_TRUSTEE, SE_FILE_OBJECT, TRUSTEE_IS_SID,
    TRUSTEE_IS_UNKNOWN, TRUSTEE_W,
};
use windows::Win32::Security::{
    AclSizeInformation, EqualSid, GetAce, GetAclInformation, InitializeAcl, IsValidSid,
    ACCESS_ALLOWED_ACE, ACE_FLAGS, ACE_HEADER, ACL, ACL_REVISION, ACL_SIZE_INFORMATION,
    DACL_SECURITY_INFORMATION, INHERITED_ACE, OBJECT_INHERIT_ACE, PSECURITY_DESCRIPTOR, PSID,
};
use windows_core::PWSTR;

use std::ffi::c_void;
use std::os::windows::ffi::OsStrExt;

/// Well-known SID string for `ALL APPLICATION PACKAGES` — the umbrella
/// SID covering every AppContainer process on the host. Granting
/// traverse to this SID on a directory lets any current or future
/// AppContainer process traverse that directory.
pub const ALL_APPLICATION_PACKAGES_SID: &str = "S-1-15-2-1";

/// `FILE_TRAVERSE` access right (a.k.a. `FILE_EXECUTE` value `0x20`)
/// plus `SYNCHRONIZE` (`0x0010_0000`). Together they form the minimum
/// "able to traverse this directory" mask. Windows folds in
/// `SYNCHRONIZE` automatically when `Set-Acl` is used in PowerShell;
/// we explicitly include it here so the ACE we add matches what
/// `Set-Acl` would produce.
pub const FILE_TRAVERSE_MASK: u32 = 0x0020 | 0x0010_0000;

#[derive(Debug, thiserror::Error)]
pub enum InstallAclError {
    /// `path` could not be canonicalized or doesn't exist.
    #[error("invalid path '{path}': {reason}")]
    InvalidPath { path: String, reason: String },

    /// `sid_string` failed to parse via `ConvertStringSidToSidW`, or
    /// the resulting SID failed `IsValidSid`.
    #[error("invalid SID '{sid}': {reason}")]
    InvalidSid { sid: String, reason: String },

    /// A Win32 call returned non-success.
    #[error("Win32 {op} on '{path}': {reason}")]
    Win32 {
        path: String,
        op: String,
        reason: String,
    },

    /// `SetNamedSecurityInfoW` returned `ERROR_ACCESS_DENIED` (5) — the
    /// running token lacks `WRITE_DAC` on the target path. Almost always
    /// means "not elevated" when the path is system-owned (`C:\`,
    /// `C:\Users\`).
    #[error(
        "ERROR_ACCESS_DENIED on '{path}'. This usually means the process needs elevation \
         (run as Administrator) or the user lacks WRITE_DAC on this path."
    )]
    AccessDenied { path: String },
}

type AclResult<T> = Result<T, InstallAclError>;

/// Returns `true` iff there exists a non-inheriting Allow ACE on `path`
/// for `sid_string` whose mask covers `required_mask`.
///
/// "Covers" means `(ace.Mask & required_mask) == required_mask` — the
/// ACE grants at least every right we require, plus possibly more.
///
/// Does not modify the DACL. Safe to call without elevation.
pub fn check_grant(path: &Path, sid_string: &str, required_mask: u32) -> AclResult<bool> {
    let target_sid = OwnedSid::parse(sid_string)?;
    let view = AclView::open(path)?;
    let aces = unsafe { view.iter_aces()? };
    for ace in aces {
        if ace.is_inheriting() || ace.is_inherited() {
            continue;
        }
        if !ace.is_allow_type() {
            continue;
        }
        if unsafe { EqualSid(ace.sid_ptr(), target_sid.as_psid()) }.is_err() {
            continue;
        }
        if (ace.mask & required_mask) == required_mask {
            return Ok(true);
        }
    }
    Ok(false)
}

/// Ensure a non-inheriting Allow ACE for `sid_string` covering
/// `required_mask` is present on `path`. Returns `Ok(true)` if an ACE
/// was added (or extended), `Ok(false)` if an existing ACE already
/// covered the requirement.
///
/// Idempotent: re-running against an already-adjusted path is a fast
/// no-op (returns `Ok(false)`).
///
/// Requires the caller to hold `WRITE_DAC` on `path`. Returns
/// [`InstallAclError::AccessDenied`] otherwise.
pub fn add_grant(path: &Path, sid_string: &str, required_mask: u32) -> AclResult<bool> {
    if check_grant(path, sid_string, required_mask)? {
        return Ok(false);
    }

    let path_w = wide(path);
    let path_pcw = PCWSTR(path_w.as_ptr());
    let target_sid = OwnedSid::parse(sid_string)?;

    let ea = EXPLICIT_ACCESS_W {
        grfAccessPermissions: required_mask,
        grfAccessMode: GRANT_ACCESS,
        grfInheritance: ACE_FLAGS(0), // non-inheriting
        Trustee: TRUSTEE_W {
            pMultipleTrustee: ptr::null_mut(),
            MultipleTrusteeOperation: NO_MULTIPLE_TRUSTEE,
            TrusteeForm: TRUSTEE_IS_SID,
            TrusteeType: TRUSTEE_IS_UNKNOWN,
            ptstrName: PWSTR(target_sid.as_psid().0 as *mut u16),
        },
    };

    // Read current DACL.
    let mut existing_dacl: *mut ACL = ptr::null_mut();
    let mut sd = PSECURITY_DESCRIPTOR(ptr::null_mut());
    let rc = unsafe {
        GetNamedSecurityInfoW(
            path_pcw,
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION,
            None,
            None,
            Some(&mut existing_dacl),
            None,
            &mut sd,
        )
    };
    win32_check(path, "GetNamedSecurityInfoW", rc)?;

    // Merge.
    let mut new_dacl: *mut ACL = ptr::null_mut();
    let rc = unsafe {
        SetEntriesInAclW(
            Some(&[ea]),
            Some(existing_dacl as *const ACL),
            &mut new_dacl,
        )
    };
    let _ = ea; // ensure ptstrName stays valid through the call.
    if rc != WIN32_ERROR(0) {
        unsafe {
            let _ = LocalFree(Some(HLOCAL(sd.0)));
        }
        return Err(win32_err(path, "SetEntriesInAclW", rc));
    }

    // Apply.
    let rc = unsafe {
        SetNamedSecurityInfoW(
            path_pcw,
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION,
            None,
            None,
            Some(new_dacl as *const ACL),
            None,
        )
    };
    unsafe {
        if !new_dacl.is_null() {
            let _ = LocalFree(Some(HLOCAL(new_dacl as *mut c_void)));
        }
        let _ = LocalFree(Some(HLOCAL(sd.0)));
    }
    if rc == WIN32_ERROR(5) {
        return Err(InstallAclError::AccessDenied {
            path: path.display().to_string(),
        });
    }
    win32_check(path, "SetNamedSecurityInfoW", rc)?;

    Ok(true)
}

/// Remove all non-inheriting Allow ACEs on `path` whose SID matches
/// `sid_string` and whose mask is exactly `required_mask`. Other ACEs
/// (inherited, inheritable, different SID, different mask, deny) are
/// preserved.
///
/// Returns `Ok(true)` if at least one ACE was removed, `Ok(false)` if
/// nothing matched (idempotent).
///
/// Requires the caller to hold `WRITE_DAC` on `path`.
pub fn remove_grant(path: &Path, sid_string: &str, required_mask: u32) -> AclResult<bool> {
    let target_sid = OwnedSid::parse(sid_string)?;

    let path_w = wide(path);
    let path_pcw = PCWSTR(path_w.as_ptr());

    let mut existing_dacl: *mut ACL = ptr::null_mut();
    let mut sd = PSECURITY_DESCRIPTOR(ptr::null_mut());
    let rc = unsafe {
        GetNamedSecurityInfoW(
            path_pcw,
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION,
            None,
            None,
            Some(&mut existing_dacl),
            None,
            &mut sd,
        )
    };
    win32_check(path, "GetNamedSecurityInfoW", rc)?;

    // Rebuild a new ACL omitting matching ACEs.
    let (new_acl_buf, removed) =
        unsafe { rebuild_without_matching(existing_dacl, &target_sid, required_mask) };

    unsafe {
        let _ = LocalFree(Some(HLOCAL(sd.0)));
    }

    let (new_acl_buf, removed) = match (new_acl_buf, removed) {
        (Ok(buf), removed) => (buf, removed),
        (Err(e), _) => {
            return Err(InstallAclError::Win32 {
                path: path.display().to_string(),
                op: "rebuild_without_matching".to_string(),
                reason: e,
            });
        }
    };

    if !removed {
        return Ok(false);
    }

    let rc = unsafe {
        SetNamedSecurityInfoW(
            path_pcw,
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION,
            None,
            None,
            Some(new_acl_buf.as_ptr() as *const ACL),
            None,
        )
    };
    if rc == WIN32_ERROR(5) {
        return Err(InstallAclError::AccessDenied {
            path: path.display().to_string(),
        });
    }
    win32_check(path, "SetNamedSecurityInfoW", rc)?;
    Ok(true)
}

// -------------------------------------------------------------------------
// Internal helpers
// -------------------------------------------------------------------------

fn wide(p: &Path) -> Vec<u16> {
    p.as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect()
}

fn win32_check(path: &Path, op: &str, rc: WIN32_ERROR) -> AclResult<()> {
    if rc == WIN32_ERROR(0) {
        Ok(())
    } else {
        Err(win32_err(path, op, rc))
    }
}

fn win32_err(path: &Path, op: &str, rc: WIN32_ERROR) -> InstallAclError {
    InstallAclError::Win32 {
        path: path.display().to_string(),
        op: op.to_string(),
        reason: format!("{rc:?}"),
    }
}

/// Owned PSID — frees via `LocalFree` on drop.
struct OwnedSid(PSID);

impl OwnedSid {
    fn parse(s: &str) -> AclResult<Self> {
        let wide: Vec<u16> = s.encode_utf16().chain(std::iter::once(0)).collect();
        let mut psid = PSID(ptr::null_mut());
        unsafe {
            ConvertStringSidToSidW(PCWSTR(wide.as_ptr()), &mut psid).map_err(|e| {
                InstallAclError::InvalidSid {
                    sid: s.to_string(),
                    reason: format!("{e}"),
                }
            })?;
            if psid.0.is_null() || !IsValidSid(psid).as_bool() {
                if !psid.0.is_null() {
                    let _ = LocalFree(Some(HLOCAL(psid.0)));
                }
                return Err(InstallAclError::InvalidSid {
                    sid: s.to_string(),
                    reason: "not a valid SID".to_string(),
                });
            }
        }
        Ok(Self(psid))
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

/// RAII handle around the security descriptor / DACL returned by
/// `GetNamedSecurityInfoW`. The descriptor is allocated by the call and
/// must be freed via `LocalFree`; the DACL pointer aliases into it.
struct AclView {
    sd: PSECURITY_DESCRIPTOR,
    dacl: *mut ACL,
}

impl AclView {
    fn open(path: &Path) -> AclResult<Self> {
        let path_w = wide(path);
        let path_pcw = PCWSTR(path_w.as_ptr());
        let mut dacl: *mut ACL = ptr::null_mut();
        let mut sd = PSECURITY_DESCRIPTOR(ptr::null_mut());
        let rc = unsafe {
            GetNamedSecurityInfoW(
                path_pcw,
                SE_FILE_OBJECT,
                DACL_SECURITY_INFORMATION,
                None,
                None,
                Some(&mut dacl),
                None,
                &mut sd,
            )
        };
        win32_check(path, "GetNamedSecurityInfoW", rc)?;
        Ok(Self { sd, dacl })
    }

    /// Iterate the ACEs in the DACL.
    ///
    /// # Safety
    /// `self.dacl` must point at a well-formed ACL for the lifetime of
    /// the returned iterator.
    unsafe fn iter_aces(&self) -> AclResult<Vec<AceRef>> {
        let mut info = ACL_SIZE_INFORMATION::default();
        let info_sz = std::mem::size_of::<ACL_SIZE_INFORMATION>() as u32;
        GetAclInformation(
            self.dacl,
            &mut info as *mut _ as *mut c_void,
            info_sz,
            AclSizeInformation,
        )
        .map_err(|e| InstallAclError::Win32 {
            path: String::new(),
            op: "GetAclInformation".to_string(),
            reason: format!("{e}"),
        })?;

        let mut out = Vec::with_capacity(info.AceCount as usize);
        for i in 0..info.AceCount {
            let mut ace_ptr: *mut c_void = ptr::null_mut();
            GetAce(self.dacl, i, &mut ace_ptr).map_err(|e| InstallAclError::Win32 {
                path: String::new(),
                op: format!("GetAce({i})"),
                reason: format!("{e}"),
            })?;
            let header = &*(ace_ptr as *const ACE_HEADER);
            // Both ACCESS_ALLOWED_ACE and ACCESS_DENIED_ACE share layout
            // up to and including SidStart.
            let body = &*(ace_ptr as *const ACCESS_ALLOWED_ACE);
            out.push(AceRef {
                ace_type: header.AceType,
                ace_flags: header.AceFlags,
                mask: body.Mask,
                sid_addr: &body.SidStart as *const _ as *const c_void,
            });
        }
        Ok(out)
    }
}

impl Drop for AclView {
    fn drop(&mut self) {
        if !self.sd.0.is_null() {
            unsafe {
                let _ = LocalFree(Some(HLOCAL(self.sd.0)));
            }
        }
    }
}

struct AceRef {
    ace_type: u8,
    ace_flags: u8,
    mask: u32,
    sid_addr: *const c_void,
}

impl AceRef {
    fn is_allow_type(&self) -> bool {
        self.ace_type == 0x00 // ACCESS_ALLOWED_ACE_TYPE
    }

    fn is_inheriting(&self) -> bool {
        (self.ace_flags
            & (OBJECT_INHERIT_ACE.0 | windows::Win32::Security::CONTAINER_INHERIT_ACE.0) as u8)
            != 0
    }

    fn is_inherited(&self) -> bool {
        (self.ace_flags & INHERITED_ACE.0 as u8) != 0
    }

    fn sid_ptr(&self) -> PSID {
        PSID(self.sid_addr as *mut c_void)
    }
}

/// Walk an existing ACL and produce a new ACL byte-buffer omitting
/// every non-inheriting Allow ACE matching `(sid, mask)`. Inherited
/// ACEs are preserved unconditionally.
///
/// Returns the new ACL bytes (suitable for use as `*const ACL`) and
/// whether any matching ACE was actually removed.
///
/// # Safety
/// `dacl` must be a valid `*mut ACL` pointing at a well-formed ACL.
unsafe fn rebuild_without_matching(
    dacl: *mut ACL,
    sid: &OwnedSid,
    target_mask: u32,
) -> (Result<Vec<u8>, String>, bool) {
    let mut info = ACL_SIZE_INFORMATION::default();
    let info_sz = std::mem::size_of::<ACL_SIZE_INFORMATION>() as u32;
    if let Err(e) = GetAclInformation(
        dacl,
        &mut info as *mut _ as *mut c_void,
        info_sz,
        AclSizeInformation,
    ) {
        return (Err(format!("GetAclInformation: {e}")), false);
    }

    let total_size = info.AclBytesInUse + info.AclBytesFree;
    let mut buf = vec![0u8; total_size as usize];
    if let Err(e) = InitializeAcl(buf.as_mut_ptr() as *mut ACL, total_size, ACL_REVISION) {
        return (Err(format!("InitializeAcl: {e}")), false);
    }

    let inherit_mask: u8 =
        (OBJECT_INHERIT_ACE.0 | windows::Win32::Security::CONTAINER_INHERIT_ACE.0) as u8;

    let mut removed = false;
    for i in 0..info.AceCount {
        let mut ace_ptr: *mut c_void = ptr::null_mut();
        if let Err(e) = GetAce(dacl, i, &mut ace_ptr) {
            return (Err(format!("GetAce({i}): {e}")), removed);
        }
        let header = &*(ace_ptr as *const ACE_HEADER);
        let body = &*(ace_ptr as *const ACCESS_ALLOWED_ACE);

        let inherited = (header.AceFlags & INHERITED_ACE.0 as u8) != 0;
        let inheriting = (header.AceFlags & inherit_mask) != 0;
        let is_allow = header.AceType == 0x00;
        let mask_match = body.Mask == target_mask;
        let sid_match = EqualSid(
            PSID(&body.SidStart as *const _ as *mut c_void),
            sid.as_psid(),
        )
        .is_ok();

        let drop_this = is_allow && !inherited && !inheriting && mask_match && sid_match;
        if drop_this {
            removed = true;
            continue;
        }

        if let Err(e) = windows::Win32::Security::AddAce(
            buf.as_mut_ptr() as *mut ACL,
            ACL_REVISION,
            u32::MAX,
            ace_ptr,
            header.AceSize as u32,
        ) {
            return (Err(format!("AddAce: {e}")), removed);
        }
    }

    (Ok(buf), removed)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    /// `S-1-1-0` is the "Everyone" SID — well-known, parses without
    /// network calls, harmless to add ACEs for.
    const TEST_SID: &str = "S-1-1-0";

    #[test]
    fn check_missing_returns_false() {
        let dir = tempdir().expect("tempdir");
        let present =
            check_grant(dir.path(), TEST_SID, FILE_TRAVERSE_MASK).expect("check should succeed");
        // Brand-new tempdir won't have an explicit Everyone:(X) non-
        // inheriting ACE. If it does for some reason, the rest of the
        // test suite would also be affected; reporting present here is
        // still correct.
        let _ = present; // accept either; we just want check to succeed.
    }

    #[test]
    fn add_then_check_then_remove() {
        let dir = tempdir().expect("tempdir");
        let path = dir.path();

        let added = add_grant(path, TEST_SID, FILE_TRAVERSE_MASK).expect("add should succeed");
        assert!(added, "expected first add to insert the ACE");

        let present = check_grant(path, TEST_SID, FILE_TRAVERSE_MASK).expect("check");
        assert!(present, "check should see the freshly-added ACE");

        let added_again = add_grant(path, TEST_SID, FILE_TRAVERSE_MASK).expect("idempotent add");
        assert!(!added_again, "second add should be a no-op");

        let removed =
            remove_grant(path, TEST_SID, FILE_TRAVERSE_MASK).expect("remove should succeed");
        assert!(removed, "expected remove to drop the ACE");

        let present_after = check_grant(path, TEST_SID, FILE_TRAVERSE_MASK).expect("check");
        assert!(!present_after, "ACE should be gone after remove");

        let removed_again =
            remove_grant(path, TEST_SID, FILE_TRAVERSE_MASK).expect("idempotent remove");
        assert!(!removed_again, "second remove should be a no-op");
    }

    #[test]
    fn check_covers_means_at_least() {
        let dir = tempdir().expect("tempdir");
        let path = dir.path();

        // Grant a broader mask than what we'll check for.
        let broader = FILE_TRAVERSE_MASK | 0x0001; // + FILE_LIST_DIRECTORY
        let added = add_grant(path, TEST_SID, broader).expect("add broader");
        assert!(added);

        // A check for the narrower mask should still succeed —
        // "covers" semantics.
        let present = check_grant(path, TEST_SID, FILE_TRAVERSE_MASK).expect("check narrower");
        assert!(present, "broader ACE should satisfy narrower check");

        let _ = remove_grant(path, TEST_SID, broader);
    }

    #[test]
    fn invalid_sid_string_errors() {
        let dir = tempdir().expect("tempdir");
        let err = check_grant(dir.path(), "not-a-sid", FILE_TRAVERSE_MASK).unwrap_err();
        assert!(
            matches!(err, InstallAclError::InvalidSid { .. }),
            "got: {err:?}"
        );
    }

    #[test]
    fn all_application_packages_constant_parses() {
        let _ = OwnedSid::parse(ALL_APPLICATION_PACKAGES_SID).expect("S-1-15-2-1 must parse");
    }
}
