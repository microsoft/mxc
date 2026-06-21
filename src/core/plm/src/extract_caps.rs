//! Port of `extract_caps.ps1`.
//!
//! Walks a hex-encoded blob of concatenated ACEs from a permissive
//! learning-mode event's DACL, resolves each ACE's SID to a known
//! capability name (via `DeriveCapabilitySidsFromName`), and returns the
//! set of matched capability names.
//!
//! Each ACE in the buffer is laid out as:
//! - `[0]`     ACE type        (1 byte)
//! - `[1..3]`  Padding          (3 bytes)
//! - `[4..7]`  ACE flags        (4 bytes, only low byte meaningful)
//! - `[8..11]` Access mask      (4 bytes, little-endian)
//! - `[12..]`  SID:
//!     - `[0]`    Revision           (1 byte)
//!     - `[1]`    SubAuthorityCount  (1 byte)
//!     - `[2..7]` IdentifierAuthority (6 bytes)
//!     - `[8..]`  SubAuthorities      (4 bytes each)

use anyhow::{anyhow, Result};
use std::collections::HashSet;

use windows::core::{PCWSTR, PWSTR};
use windows::Win32::Foundation::{LocalFree, HLOCAL};
use windows::Win32::Security::Authorization::ConvertSidToStringSidW;
use windows::Win32::Security::{
    DeriveCapabilitySidsFromName, GetLengthSid, IsValidSid, LookupAccountSidW, PSID, SID_NAME_USE,
};

const ACE_HEADER_SIZE: usize = 1 + 3 + 4 + 4; // type + 3 padding + 4 flags + 4 mask
const SID_FIXED_HEADER_SIZE: usize = 1 + 1 + 6; // revision + subauth count + id auth

/// Capability names we want to recognize when their SID appears in an ACE.
/// Mirrors the `$knownCapabilities` list from `extract_caps.ps1`. Sourced
/// from the public MSDN "App capability declarations" + restricted
/// capability + device capability lists. Names rejected by
/// `DeriveCapabilitySidsFromName` on this OS are silently skipped at
/// table-build time.
const KNOWN_CAPABILITIES: &[&str] = &[
    // General-use capabilities
    "internetClient",
    "internetClientServer",
    "privateNetworkClientServer",
    "documentsLibrary",
    "picturesLibrary",
    "videosLibrary",
    "musicLibrary",
    "removableStorage",
    "sharedUserCertificates",
    "appointments",
    "contacts",
    "chat",
    "phoneCall",
    "voipCall",
    "objects3D",
    "userAccountInformation",
    "userPrincipalName",
    "backgroundMediaPlayback",
    "codeGeneration",
    "allowElevation",
    // Intentionally disabled in the source PS list -- left here as
    // comments so changes stay aligned across the two implementations.
    // "broadFileSystemAccess",
    // "enterpriseAuthentication",
    // "runFullTrust",
    // "packageManagement",

    // Device capabilities
    "location",
    "microphone",
    "webcam",
    "proximity",
    "bluetooth",
    "bluetooth.genericAttributeProfile",
    "bluetooth.rfcomm",
    "humaninterfacedevice",
    "lowLevelDevices",
    "pointOfService",
    "radios",
    "serialcommunication",
    "usb",
    "wiFiControl",
    "gazeInput",
    "optical",
    "activity",
    // Graphics / capture
    "graphicsCapture",
    "graphicsCaptureProgrammatic",
    "graphicsCaptureWithoutBorder",
    "screenDuplication",
    "appCaptureServices",
    "appCaptureSettings",
    // Background / extended execution
    "backgroundMediaRecording",
    "backgroundSpatialPerception",
    "backgroundVoIP",
    "extendedBackgroundTaskTime",
    "extendedExecutionBackgroundAudio",
    "extendedExecutionCritical",
    "extendedExecutionUnconstrained",
    // System / app-package management
    "accessoryManager",
    "allAppMods",
    "appBroadcastServices",
    "appLicensing",
    "audioDeviceConfiguration",
    "cellularDeviceControl",
    "cellularDeviceIdentity",
    "cellularMessaging",
    "confirmAppClose",
    "customInstallActions",
    "developmentModeNetwork",
    "dualSimTiles",
    "enterpriseCloudSSO",
    "enterpriseDataPolicy",
    "enterpriseDeviceLockdown",
    "firstSignInSettings",
    "gameBarServices",
    "gameList",
    "gameMonitor",
    "globalMediaControl",
    "inputForegroundObservation",
    "inputInjectionBrokered",
    "inputObservation",
    "inputSuppression",
    "interopServices",
    "liveIdService",
    "localSystemServices",
    "locationHistory",
    "locationSystem",
    "modifiableApp",
    "networkConnectionManagerProvisioning",
    "networkDataPlanProvisioning",
    "networkingVpnProvider",
    "oemDeploymentInfo",
    "oemPublicDirectory",
    "packagePolicySystem",
    "packageQuery",
    "packageWriteRedirectionCompatibilityShim",
    "previewInkWorkspace",
    "previewPenWorkspace",
    "previewStore",
    "previewUiComposition",
    "protectedApp",
    "secondaryAuthenticationFactor",
    "secureAssessment",
    "shellExperience",
    "shellExperienceComposer",
    "slapiQueryLicenseValue",
    "smbios",
    "smsSend",
    "startScreenManagement",
    "storeLicenseManagement",
    "systemManagement",
    "targetedContent",
    "teamEditionDeviceCredential",
    "teamEditionExperience",
    "teamEditionView",
    "uiAccess",
    "uiAutomation",
    "unvirtualizedResources",
    "walletSystem",
    "xboxAccessoryManagement",
    // User-data system capabilities
    "appointmentsSystem",
    "chatSystem",
    "contactsSystem",
    "email",
    "emailSystem",
    "phoneCallHistory",
    "phoneCallHistorySystem",
    "phoneLineTransportManagement",
    "userDataAccountsProvider",
    "userDataSystem",
    "userSystemId",
    "cortanaPermissions",
    "cortanaSpeechAccessory",
];

#[derive(Debug, Clone)]
pub struct CapabilityEntry {
    pub name: String,
    pub app_package_sid: Option<Vec<u8>>,
    pub group_sid: Option<Vec<u8>>,
}

fn to_wide_z(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

/// Copy a SID pointed to by `psid` into a managed byte vector.
unsafe fn sid_bytes_from_ptr(psid: PSID) -> Option<Vec<u8>> {
    if psid.0.is_null() {
        return None;
    }
    let len = GetLengthSid(psid);
    if len == 0 {
        return None;
    }
    let mut buf = vec![0u8; len as usize];
    std::ptr::copy_nonoverlapping(psid.0 as *const u8, buf.as_mut_ptr(), len as usize);
    Some(buf)
}

/// Free an array of SID pointers and the array itself, mirroring the
/// LocalFree-loop cleanup from the PowerShell version.
unsafe fn free_sid_array(arr: *mut PSID, count: u32) {
    if arr.is_null() {
        return;
    }
    for i in 0..count as isize {
        let p = *arr.offset(i);
        if !p.0.is_null() {
            let _ = LocalFree(HLOCAL(p.0));
        }
    }
    let _ = LocalFree(HLOCAL(arr as *mut _));
}

/// Build the table of (capability name, AppPackage SID, Group SID) tuples
/// by calling `DeriveCapabilitySidsFromName` for each known capability.
/// Capabilities the OS rejects are silently skipped.
pub fn build_capability_table() -> Vec<CapabilityEntry> {
    let mut out = Vec::with_capacity(KNOWN_CAPABILITIES.len());

    for &name in KNOWN_CAPABILITIES {
        let wide = to_wide_z(name);
        let mut group_sids: *mut PSID = std::ptr::null_mut();
        let mut group_count: u32 = 0;
        let mut cap_sids: *mut PSID = std::ptr::null_mut();
        let mut cap_count: u32 = 0;

        let ok = unsafe {
            DeriveCapabilitySidsFromName(
                PWSTR(wide.as_ptr() as *mut u16),
                &mut group_sids as *mut _,
                &mut group_count as *mut _,
                &mut cap_sids as *mut _,
                &mut cap_count as *mut _,
            )
        };
        if ok.is_err() {
            continue;
        }

        // First entry of each array is the canonical SID; alternate
        // encodings (when present) are not currently matched.
        let app_package_sid = if cap_count > 0 && !cap_sids.is_null() {
            unsafe { sid_bytes_from_ptr(*cap_sids) }
        } else {
            None
        };
        let group_sid = if group_count > 0 && !group_sids.is_null() {
            unsafe { sid_bytes_from_ptr(*group_sids) }
        } else {
            None
        };

        out.push(CapabilityEntry {
            name: name.to_string(),
            app_package_sid,
            group_sid,
        });

        unsafe {
            free_sid_array(cap_sids, cap_count);
            free_sid_array(group_sids, group_count);
        }
    }

    out
}

/// Best-effort string form of a SID for diagnostics. Returns `None` if the
/// bytes aren't a valid SID.
pub fn sid_to_string(sid_bytes: &[u8]) -> Option<String> {
    let psid = PSID(sid_bytes.as_ptr() as *mut _);
    unsafe {
        if !IsValidSid(psid).as_bool() {
            return None;
        }
        let mut out = PWSTR::null();
        if ConvertSidToStringSidW(psid, &mut out as *mut _).is_err() {
            return None;
        }
        // Walk to NUL.
        let mut len = 0usize;
        while *out.0.add(len) != 0 {
            len += 1;
        }
        let slice = std::slice::from_raw_parts(out.0, len);
        let s = String::from_utf16_lossy(slice);
        let _ = LocalFree(HLOCAL(out.0 as *mut _));
        Some(s)
    }
}

/// Try to translate a SID to an NTAccount-style "DOMAIN\Name" string.
pub fn lookup_nt_account(sid_bytes: &[u8]) -> Option<String> {
    let psid = PSID(sid_bytes.as_ptr() as *mut _);
    unsafe {
        if !IsValidSid(psid).as_bool() {
            return None;
        }
        let mut name_len: u32 = 0;
        let mut domain_len: u32 = 0;
        let mut sid_use = SID_NAME_USE(0);
        // First call queries required buffer sizes (expected to fail with
        // ERROR_INSUFFICIENT_BUFFER and populate the length out-params).
        let _ = LookupAccountSidW(
            PCWSTR::null(),
            psid,
            PWSTR::null(),
            &mut name_len as *mut _,
            PWSTR::null(),
            &mut domain_len as *mut _,
            &mut sid_use as *mut _,
        );
        if name_len == 0 {
            return None;
        }
        let mut name = vec![0u16; name_len as usize];
        let mut domain = vec![0u16; domain_len as usize];
        let ok = LookupAccountSidW(
            PCWSTR::null(),
            psid,
            PWSTR(name.as_mut_ptr()),
            &mut name_len as *mut _,
            PWSTR(domain.as_mut_ptr()),
            &mut domain_len as *mut _,
            &mut sid_use as *mut _,
        );
        if ok.is_err() {
            return None;
        }
        let nm = String::from_utf16_lossy(&name[..name_len as usize]);
        let dom = String::from_utf16_lossy(&domain[..domain_len as usize]);
        if dom.is_empty() {
            Some(nm)
        } else {
            Some(format!("{dom}\\{nm}"))
        }
    }
}

/// Result of resolving a SID against the capability table.
pub enum SidResolution<'a> {
    Capability(&'a str),
    GroupCapability(&'a str),
    NtAccount(String),
    Unknown,
}

pub fn resolve_sid<'a>(sid_bytes: &[u8], table: &'a [CapabilityEntry]) -> SidResolution<'a> {
    for entry in table {
        if let Some(s) = &entry.app_package_sid {
            if s == sid_bytes {
                return SidResolution::Capability(&entry.name);
            }
        }
        if let Some(s) = &entry.group_sid {
            if s == sid_bytes {
                return SidResolution::GroupCapability(&entry.name);
            }
        }
    }
    if let Some(nt) = lookup_nt_account(sid_bytes) {
        SidResolution::NtAccount(nt)
    } else {
        SidResolution::Unknown
    }
}

fn parse_hex_string(hex_input: &str) -> Result<Vec<u8>> {
    let cleaned: String = hex_input.chars().filter(|c| !c.is_whitespace()).collect();
    if cleaned.is_empty() || !cleaned.len().is_multiple_of(2) {
        return Err(anyhow!(
            "Hex string must be non-empty and have an even length."
        ));
    }
    if !cleaned.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(anyhow!("Hex string contains non-hex characters."));
    }
    let mut bytes = Vec::with_capacity(cleaned.len() / 2);
    for i in (0..cleaned.len()).step_by(2) {
        bytes.push(u8::from_str_radix(&cleaned[i..i + 2], 16)?);
    }
    Ok(bytes)
}

struct AceSlice<'a> {
    ace_type: u8,
    ace_flags: u8,
    access_mask: u32,
    sub_authority_count: u8,
    sid_bytes: &'a [u8],
    next_cursor: usize,
}

fn read_ace_at_offset(buf: &[u8], cursor: usize) -> Result<AceSlice<'_>> {
    let total = buf.len();
    if total - cursor < ACE_HEADER_SIZE + SID_FIXED_HEADER_SIZE {
        return Err(anyhow!(
            "Truncated ACE header at byte offset {} (need at least {} more bytes).",
            cursor,
            ACE_HEADER_SIZE + SID_FIXED_HEADER_SIZE
        ));
    }
    let ace_type = buf[cursor];
    let ace_flags = buf[cursor + 4];
    let access_mask = u32::from_le_bytes([
        buf[cursor + 8],
        buf[cursor + 9],
        buf[cursor + 10],
        buf[cursor + 11],
    ]);

    let sid_offset = cursor + ACE_HEADER_SIZE;
    let sub_authority_count = buf[sid_offset + 1];
    let sid_size = SID_FIXED_HEADER_SIZE + 4 * sub_authority_count as usize;
    if total - sid_offset < sid_size {
        return Err(anyhow!(
            "Truncated SID at byte offset {} (need {} bytes, have {}).",
            sid_offset,
            sid_size,
            total - sid_offset
        ));
    }

    Ok(AceSlice {
        ace_type,
        ace_flags,
        access_mask,
        sub_authority_count,
        sid_bytes: &buf[sid_offset..sid_offset + sid_size],
        next_cursor: sid_offset + sid_size,
    })
}

/// Walk every ACE in `buf` and return the case-insensitively-deduped set
/// of capability names matched along the way. When `verbose` is true, a
/// per-ACE diagnostic line is emitted to stdout.
pub fn invoke_ace_walk(buf: &[u8], verbose: bool) -> Result<HashSet<String>> {
    let table = build_capability_table();
    let mut found: HashSet<String> = HashSet::new();
    let mut cursor = 0usize;
    let mut ace_index = 0usize;

    while cursor < buf.len() {
        let ace = read_ace_at_offset(buf, cursor)?;
        let resolution = resolve_sid(ace.sid_bytes, &table);

        let resolved_str = match &resolution {
            SidResolution::Capability(name) => {
                found.insert(name.to_string());
                format!("capability \"{name}\"")
            }
            SidResolution::GroupCapability(name) => {
                found.insert(name.to_string());
                format!("capability \"{name}\" (group SID)")
            }
            SidResolution::NtAccount(s) => s.clone(),
            SidResolution::Unknown => "<no known capability/account matches this SID>".to_string(),
        };

        if verbose {
            let sid_str =
                sid_to_string(ace.sid_bytes).unwrap_or_else(|| "<invalid SID>".to_string());
            println!(
                "ACE {}: type=0x{:02X}, flags=0x{:02X}, mask=0x{:08X}, subAuthCount={}",
                ace_index, ace.ace_type, ace.ace_flags, ace.access_mask, ace.sub_authority_count
            );
            println!("  SID:      {sid_str}");
            println!("  Resolved: {resolved_str}");
            println!();
        }

        cursor = ace.next_cursor;
        ace_index += 1;
    }

    Ok(found)
}

/// Top-level entry point matching the script's `-HexBytes` invocation.
pub fn extract_caps(hex_bytes: &str, verbose: bool) -> Result<HashSet<String>> {
    let bytes = parse_hex_string(hex_bytes)?;
    invoke_ace_walk(&bytes, verbose)
}
