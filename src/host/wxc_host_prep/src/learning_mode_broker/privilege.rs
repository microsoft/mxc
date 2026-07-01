// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! LSA privilege management for the denial broker.
//!
//! `mxc-learning-mode-broker` runs as `LocalService` (least-privilege account)
//! but needs `SeSystemProfilePrivilege` to call `StartTraceW`. The
//! built-in `LocalService` SID does **not** carry this privilege by
//! default — we have to grant it explicitly via the LSA Account Rights
//! API at install time.
//!
//! Grants persist across reboots. We do not revoke on uninstall: a
//! manual cleanup is fine to leave to the operator, and over-eagerly
//! revoking could clobber another tool on the box that also granted
//! the same privilege to `LocalService`. The leftover grant is small
//! (one extra privilege on one well-known account that already runs
//! plenty of MS-shipped services) and harmless without the broker
//! binary to use it.
//!
//! Idempotent: `LsaAddAccountRights` is a no-op when the account
//! already has the requested privilege.

use std::ptr;

use windows::core::PWSTR;
use windows::Win32::Foundation::{LocalFree, HLOCAL, NTSTATUS};
use windows::Win32::Security::Authentication::Identity::{
    LsaAddAccountRights, LsaClose, LsaNtStatusToWinError, LsaOpenPolicy, LSA_HANDLE,
    LSA_OBJECT_ATTRIBUTES, LSA_UNICODE_STRING, POLICY_CREATE_ACCOUNT, POLICY_LOOKUP_NAMES,
};
use windows::Win32::Security::{CreateWellKnownSid, WinLocalServiceSid, PSID, WELL_KNOWN_SID_TYPE};

/// Grants `SeSystemProfilePrivilege` to `NT AUTHORITY\LocalService`.
///
/// Returns `Ok(())` on success or when the account already has the
/// privilege. Returns `Err` with a human-readable message on any LSA
/// failure.
pub fn grant_se_system_profile_to_local_service() -> Result<(), String> {
    grant_privilege_to_well_known(WinLocalServiceSid, "SeSystemProfilePrivilege")
}

fn grant_privilege_to_well_known(
    sid_type: WELL_KNOWN_SID_TYPE,
    privilege_name: &str,
) -> Result<(), String> {
    // 1. Build the SID for the target well-known account.
    let mut sid_buf = [0u8; 64]; // SECURITY_MAX_SID_SIZE = 68; 64 fits LocalService comfortably.
    let mut sid_size = sid_buf.len() as u32;

    // SAFETY: `sid_buf` is a valid mutable buffer; `sid_size` is its
    // capacity. CreateWellKnownSid writes the SID and updates `sid_size`
    // to the actual size used.
    unsafe {
        CreateWellKnownSid(
            sid_type,
            None,
            Some(PSID(sid_buf.as_mut_ptr() as *mut _)),
            &mut sid_size,
        )
        .map_err(|e| format!("CreateWellKnownSid({sid_type:?}) failed: {e}"))?;
    }

    let sid = PSID(sid_buf.as_mut_ptr() as *mut _);

    // 2. Open the local LSA policy with rights to add account rights
    //    + look up SIDs.
    let attrs = LSA_OBJECT_ATTRIBUTES::default();
    let mut policy: LSA_HANDLE = LSA_HANDLE::default();

    // SAFETY: `attrs` is a valid zero-initialized structure (LSA's
    // documentation explicitly accepts this). `policy` is a valid out
    // pointer.
    let status = unsafe {
        LsaOpenPolicy(
            None,
            &attrs,
            (POLICY_CREATE_ACCOUNT | POLICY_LOOKUP_NAMES) as u32,
            &mut policy,
        )
    };
    nt_check(status, "LsaOpenPolicy")?;

    // 3. Build an LSA_UNICODE_STRING for the privilege name. The buffer
    //    is borrowed for the duration of the LsaAddAccountRights call
    //    only, so a Vec on the stack is fine.
    let mut wide: Vec<u16> = privilege_name.encode_utf16().collect();
    let len_bytes = (wide.len() * 2) as u16;
    let rights = [LSA_UNICODE_STRING {
        Length: len_bytes,
        MaximumLength: len_bytes,
        Buffer: PWSTR(wide.as_mut_ptr()),
    }];

    // SAFETY: `policy` is a valid LSA handle from LsaOpenPolicy. `sid`
    // points into `sid_buf` which outlives the call. `rights` points to
    // valid LSA_UNICODE_STRING entries whose Buffer fields point into
    // `wide` (also outlives the call).
    let status = unsafe { LsaAddAccountRights(policy, sid, &rights) };

    // 4. Close the policy handle whether the grant succeeded or not.
    //    Failure to close is logged but not surfaced (the grant result
    //    is what matters).
    unsafe {
        let close_status = LsaClose(policy);
        if close_status.0 != 0 {
            eprintln!(
                "[learning-mode-broker] warning: LsaClose returned NTSTATUS {:#X}",
                close_status.0
            );
        }
    }

    nt_check(status, "LsaAddAccountRights")
}

fn nt_check(status: NTSTATUS, op: &str) -> Result<(), String> {
    if status.0 == 0 {
        return Ok(());
    }
    // SAFETY: pure conversion call.
    let win_err = unsafe { LsaNtStatusToWinError(status) };
    Err(format!(
        "{op} failed: NTSTATUS={:#X} -> Win32 error {win_err}",
        status.0
    ))
}

// LocalFree wrapper kept here to keep usage local should we ever
// allocate an LSA-side buffer (e.g. via LsaEnumerateAccountRights for
// a future audit/revoke path). Currently unused — guarded with
// #[allow(dead_code)] to satisfy `-D warnings` while documenting
// intent.
#[allow(dead_code)]
fn local_free_if_set(p: *mut core::ffi::c_void) {
    if !p.is_null() {
        // SAFETY: caller asserts `p` was returned by LsaAlloc-family or
        // LocalAlloc and has not been freed yet.
        unsafe {
            let _ = LocalFree(Some(HLOCAL(p)));
        }
    }
}

// Silence the unused-import warning for `ptr` when local_free_if_set is
// gated out — keep the wrapper above for future revoke support.
#[allow(dead_code)]
const _: *mut core::ffi::c_void = ptr::null_mut();
