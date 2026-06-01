// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Target SDDL constant + parser.

use windows::core::PCWSTR;
use windows::Win32::Foundation::LocalFree;
use windows::Win32::Foundation::HLOCAL;
use windows::Win32::Security::Authorization::ConvertStringSecurityDescriptorToSecurityDescriptorW;
use windows::Win32::Security::Authorization::SDDL_REVISION_1;
use windows::Win32::Security::PSECURITY_DESCRIPTOR;

use super::sd::OwnedSecurityDescriptor;
use super::NullDeviceError;

/// The literal security descriptor we reapply to `\Device\Null`.
///
/// Sourced from `nls.c::NlsSetDeviceSecurity` (the OS-side code path
/// gated by `Feature_AgenticAppContainerBfsSupport`). The ACL grants:
///
/// * Everyone — `GR | GW | GX`
/// * NT AUTHORITY\SYSTEM — `FA` (full access)
/// * BUILTIN\Administrators — `FA`
/// * Restricted Code — `GR | GX`
/// * APPLICATION PACKAGE AUTHORITY\ALL APPLICATION PACKAGES (S-1-15-2-1) — `GR | GW | GX`
/// * APPLICATION PACKAGE AUTHORITY\ALL RESTRICTED APPLICATION PACKAGES (S-1-15-2-2) — `GR | GW | GX`
///
/// Plus a mandatory-label SACL with No-Write-Up at Low integrity.
///
/// Order matters cosmetically (the SDDL parser preserves order on
/// parse, and `SetKernelObjectSecurity` writes whatever order we give
/// it). The runtime comparison in `sd::diff` ignores order — we
/// compare ACE *sets*, not sequences.
pub const TARGET_SDDL: &str = "O:BAG:SYD:(A;;GRGWGX;;;WD)(A;;FA;;;SY)(A;;FA;;;BA)(A;;GRGX;;;RC)(A;;GRGWGX;;;AC)(A;;GRGWGX;;;S-1-15-2-2)S:(ML;;NW;;;LW)";

/// Parse [`TARGET_SDDL`] into a self-relative security descriptor.
pub fn parse_target_sd() -> Result<OwnedSecurityDescriptor, NullDeviceError> {
    // Convert the SDDL constant into UTF-16, then call the Win32
    // parser. The returned `PSECURITY_DESCRIPTOR` is allocated via
    // `LocalAlloc` and must be freed with `LocalFree` — we wrap it in
    // `OwnedSecurityDescriptor::FromLocalFree` to make that automatic.
    let mut wide: Vec<u16> = TARGET_SDDL.encode_utf16().collect();
    wide.push(0);

    let mut psd = PSECURITY_DESCRIPTOR(std::ptr::null_mut());
    let result = unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            PCWSTR(wide.as_ptr()),
            SDDL_REVISION_1,
            &mut psd,
            None,
        )
    };
    if let Err(e) = result {
        return Err(NullDeviceError::SddlParseFailed(format!(
            "ConvertStringSecurityDescriptorToSecurityDescriptorW: {e}"
        )));
    }
    if psd.0.is_null() {
        return Err(NullDeviceError::SddlParseFailed(
            "ConvertStringSecurityDescriptorToSecurityDescriptorW returned NULL".to_string(),
        ));
    }
    // SAFETY: `psd` is the LocalAlloc'd PSECURITY_DESCRIPTOR returned
    // by the parser; ownership transfers to OwnedSecurityDescriptor,
    // which calls LocalFree on drop.
    Ok(unsafe { OwnedSecurityDescriptor::from_local_alloc(psd) })
}

/// `LocalFree` wrapper used by [`OwnedSecurityDescriptor`].
///
/// SAFETY: the caller must guarantee `psd` was allocated via
/// `LocalAlloc` (or returned by an API documented to require
/// `LocalFree`, e.g. `ConvertStringSecurityDescriptorToSecurityDescriptorW`).
pub(super) unsafe fn local_free_sd(psd: PSECURITY_DESCRIPTOR) {
    if !psd.0.is_null() {
        let _ = unsafe { LocalFree(Some(HLOCAL(psd.0))) };
    }
}
