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
use std::collections::{HashMap, HashSet};

#[cfg(target_os = "windows")]
use windows::core::PWSTR;
#[cfg(target_os = "windows")]
use windows::Win32::Foundation::{LocalFree, HLOCAL};
#[cfg(target_os = "windows")]
use windows::Win32::Security::Authorization::ConvertSidToStringSidW;
#[cfg(target_os = "windows")]
use windows::Win32::Security::{DeriveCapabilitySidsFromName, GetLengthSid, IsValidSid, PSID};

const ACE_HEADER_SIZE: usize = 1 + 3 + 4 + 4; // type + 3 padding + 4 flags + 4 mask
const SID_FIXED_HEADER_SIZE: usize = 1 + 1 + 6; // revision + subauth count + id auth

/// Capability names we want to recognize when their SID appears in an
/// ACE. Mirrors the `$knownCapabilities` list from `extract_caps.ps1`
/// (sourced from MSDN's App / restricted / device capability
/// declarations). Names rejected by `DeriveCapabilitySidsFromName` on
/// this OS are silently skipped at table-build time.
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
    // userPrincipalName intentionally excluded: it is read by LSASS during
    // token/logon plumbing on behalf of arbitrary callers, so it shows up
    // in audit traces for workloads that never asked for it.
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

#[cfg(target_os = "windows")]
fn to_wide_z(s: &str) -> Vec<u16> {
    wxc_common::string_util::to_wide(s)
}

/// Copy a SID pointed to by `psid` into a managed byte vector.
#[cfg(target_os = "windows")]
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
#[cfg(target_os = "windows")]
unsafe fn free_sid_array(arr: *mut PSID, count: u32) {
    if arr.is_null() {
        return;
    }
    for i in 0..count as isize {
        let p = *arr.offset(i);
        if !p.0.is_null() {
            let _ = LocalFree(Some(HLOCAL(p.0)));
        }
    }
    let _ = LocalFree(Some(HLOCAL(arr as *mut _)));
}

/// Copy the bytes of the canonical (first) SID out of an array returned by
/// `DeriveCapabilitySidsFromName`.
///
/// `arr` points to `count` contiguous `PSID` values (or is null when
/// `count` is 0). The first element is read through a length-`count`
/// slice so the access is provably in bounds rather than a bare pointer
/// dereference; the individual SID is then null- and length-validated by
/// [`sid_bytes_from_ptr`].
#[cfg(target_os = "windows")]
unsafe fn first_sid_bytes(arr: *const PSID, count: u32) -> Option<Vec<u8>> {
    if arr.is_null() || count == 0 {
        return None;
    }
    // SAFETY: `arr`/`count` are forwarded exactly as reported by
    // `DeriveCapabilitySidsFromName`, which allocates `count` contiguous
    // `PSID` entries at `arr`. `arr` is non-null and `count > 0` (checked
    // above), so a slice of `count` elements is valid and index 0 is in
    // bounds. The bounds check on `[0]` cannot panic given `count > 0`.
    let first = unsafe { std::slice::from_raw_parts(arr, count as usize)[0] };
    // SAFETY: `first` is one of the SID pointers the OS allocated;
    // `sid_bytes_from_ptr` null-checks and length-validates it before copy.
    unsafe { sid_bytes_from_ptr(first) }
}

/// Build the table of (capability name, AppPackage SID, Group SID) tuples
/// by calling `DeriveCapabilitySidsFromName` for each known capability.
/// Capabilities the OS rejects are silently skipped. Non-Windows targets
/// get an empty table (the API has no cross-platform equivalent); pure
/// ACE/byte-parsing tests remain meaningful regardless.
#[cfg(target_os = "windows")]
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
        // encodings (when present) are not currently matched. Each is read
        // through a bounded slice (see `first_sid_bytes`) so the access is
        // tied to the count the OS reported rather than a raw dereference.
        let app_package_sid = unsafe { first_sid_bytes(cap_sids, cap_count) };
        let group_sid = unsafe { first_sid_bytes(group_sids, group_count) };

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

/// Non-Windows stub: there is no equivalent to
/// `DeriveCapabilitySidsFromName` on Linux/macOS. Returning an empty
/// table keeps the pure parts of this module (parse_hex_string, ACE
/// byte walker, CapabilityIndex) callable in cross-platform tests.
#[cfg(not(target_os = "windows"))]
pub fn build_capability_table() -> Vec<CapabilityEntry> {
    Vec::new()
}

/// Best-effort string form of a SID for diagnostics. Returns `None` if the
/// bytes aren't a valid SID.
#[cfg(target_os = "windows")]
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
        let _ = LocalFree(Some(HLOCAL(out.0 as *mut _)));
        Some(s)
    }
}

/// Non-Windows stub.
#[cfg(not(target_os = "windows"))]
pub fn sid_to_string(_sid_bytes: &[u8]) -> Option<String> {
    None
}

/// Result of resolving a SID against the capability table.
pub enum SidResolution<'a> {
    Capability(&'a str),
    GroupCapability(&'a str),
    Unknown,
}

/// Indexed view of a capability table for O(1) SID lookup. A naive
/// `resolve_sid` doing a linear scan over ~150 entries per ACE
/// dominates CPU time on traces with thousands of ACEs.
///
/// The map keys are SID byte sequences; the value pairs the matched
/// capability name with a flag distinguishing the package-SID variant
/// (`false`) from the group-SID variant (`true`). Owns its keys so it
/// can be carried alongside the table inside `ParseAccumulator` without
/// the self-referential lifetime headaches that the previous
/// borrowing form imposed on callers.
pub struct CapabilityIndex {
    by_sid: HashMap<Vec<u8>, (String, bool)>,
}

impl CapabilityIndex {
    pub fn from_table(table: &[CapabilityEntry]) -> Self {
        let mut by_sid: HashMap<Vec<u8>, (String, bool)> = HashMap::with_capacity(table.len() * 2);
        for entry in table {
            if let Some(s) = &entry.app_package_sid {
                by_sid.insert(s.clone(), (entry.name.clone(), false));
            }
            if let Some(s) = &entry.group_sid {
                // App-package SID wins on conflict (it's the canonical
                // form); only insert the group SID when no entry exists.
                by_sid
                    .entry(s.clone())
                    .or_insert((entry.name.clone(), true));
            }
        }
        Self { by_sid }
    }

    pub fn resolve<'a>(&'a self, sid_bytes: &[u8]) -> SidResolution<'a> {
        if let Some((name, is_group)) = self.by_sid.get(sid_bytes) {
            return if *is_group {
                SidResolution::GroupCapability(name.as_str())
            } else {
                SidResolution::Capability(name.as_str())
            };
        }
        SidResolution::Unknown
    }
}

/// Legacy linear-scan resolver. Kept for callers that already have a
/// `&[CapabilityEntry]` and don't want to build an index for one ACE.
/// Prefer `CapabilityIndex::resolve` for any per-ACE hot loop.
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
    SidResolution::Unknown
}

pub(crate) fn parse_hex_string(hex_input: &str) -> Result<Vec<u8>> {
    // Single-pass byte decoder: walk the input once, skip whitespace,
    // accumulate nibbles into bytes. The previous 3-pass version
    // (filter → length/charset checks → from_str_radix per pair)
    // allocated an intermediate `String` per call; with thousands of
    // ACE blobs per trace that added up.
    //
    // iterate `as_bytes()` rather than `chars()`. The
    // input is always ASCII hex emitted by the Windows event renderer
    // (`<ComplexData>` text nodes from EvtRender), so per-codepoint
    // UTF-8 decoding is pure overhead. Non-hex / non-whitespace bytes
    // still surface the same error.
    let mut bytes: Vec<u8> = Vec::with_capacity(hex_input.len() / 2);
    let mut nibble: Option<u8> = None;
    for b in hex_input.as_bytes() {
        let b = *b;
        if b.is_ascii_whitespace() {
            continue;
        }
        let v = match b {
            b'0'..=b'9' => b - b'0',
            b'a'..=b'f' => b - b'a' + 10,
            b'A'..=b'F' => b - b'A' + 10,
            _ => return Err(anyhow!("Hex string contains non-hex characters.")),
        };
        match nibble.take() {
            None => nibble = Some(v),
            Some(hi) => bytes.push((hi << 4) | v),
        }
    }
    if nibble.is_some() || bytes.is_empty() {
        return Err(anyhow!(
            "Hex string must be non-empty and have an even length."
        ));
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
///
/// Accepts a pre-built `CapabilityIndex`. Use this in any hot loop that
/// walks many ACE buffers in a row — building the index is
/// O(table_size) and you only want to do it once. Hot-loop callers
/// should prefer `invoke_ace_walk_with_index_into` to avoid the
/// throwaway `HashSet` allocation per blob.
pub fn invoke_ace_walk_with_index(
    buf: &[u8],
    index: &CapabilityIndex,
    verbose: bool,
) -> Result<HashSet<String>> {
    let mut found: HashSet<String> = HashSet::new();
    invoke_ace_walk_with_index_into(buf, index, verbose, &mut found)?;
    Ok(found)
}

/// R5-17: variant that writes directly into a caller-provided
/// `&mut HashSet<String>`. Avoids allocating + draining a throwaway
/// `HashSet` per ACE blob in the hot loop.
pub fn invoke_ace_walk_with_index_into(
    buf: &[u8],
    index: &CapabilityIndex,
    verbose: bool,
    found: &mut HashSet<String>,
) -> Result<()> {
    let mut cursor = 0usize;
    let mut ace_index = 0usize;

    while cursor < buf.len() {
        let ace = read_ace_at_offset(buf, cursor)?;
        let is_allow_ace = matches!(ace.ace_type, 0x00 | 0x09);
        let resolution = index.resolve(ace.sid_bytes);

        if is_allow_ace {
            match &resolution {
                SidResolution::Capability(name) => {
                    found.insert(name.to_string());
                }
                SidResolution::GroupCapability(name) => {
                    found.insert(name.to_string());
                }
                SidResolution::Unknown => {}
            }
        }

        if verbose {
            let resolved_str = match &resolution {
                SidResolution::Capability(name) => format!("capability \"{name}\""),
                SidResolution::GroupCapability(name) => {
                    format!("capability \"{name}\" (group SID)")
                }
                SidResolution::Unknown => {
                    "<no known capability/account matches this SID>".to_string()
                }
            };
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

    Ok(())
}

/// Convenience wrapper that builds a fresh capability table per call.
/// Prefer `invoke_ace_walk_with_index` (with a reused index) in any loop.
pub fn invoke_ace_walk(buf: &[u8], verbose: bool) -> Result<HashSet<String>> {
    let table = build_capability_table();
    let index = CapabilityIndex::from_table(&table);
    invoke_ace_walk_with_index(buf, &index, verbose)
}

/// Top-level entry point matching the script's `-HexBytes` invocation.
pub fn extract_caps(hex_bytes: &str, verbose: bool) -> Result<HashSet<String>> {
    let bytes = parse_hex_string(hex_bytes)?;
    invoke_ace_walk(&bytes, verbose)
}

/// Per-event variant that takes a pre-built `CapabilityIndex` so the
/// O(table_size) build cost is paid once per parse, not per ACE blob.
/// Prefer `extract_caps_with_index_into` (which writes into a
/// caller-owned set) for the production hot loop; this variant is kept
/// for tests and callers that want a fresh `HashSet` per blob.
pub fn extract_caps_with_index(
    hex_bytes: &str,
    index: &CapabilityIndex,
    verbose: bool,
) -> Result<HashSet<String>> {
    let bytes = parse_hex_string(hex_bytes)?;
    invoke_ace_walk_with_index(&bytes, index, verbose)
}

/// R5-17: hot-path variant that writes directly into a caller-provided
/// `&mut HashSet<String>` to skip the per-blob throwaway HashSet.
pub fn extract_caps_with_index_into(
    hex_bytes: &str,
    index: &CapabilityIndex,
    verbose: bool,
    found: &mut HashSet<String>,
) -> Result<()> {
    let bytes = parse_hex_string(hex_bytes)?;
    invoke_ace_walk_with_index_into(&bytes, index, verbose, found)
}

#[cfg(test)]
mod tests {
    use super::*;

    // ---- parse_hex_string ------------------------------------------------

    #[test]
    fn parse_hex_string_decodes_simple_bytes() {
        let v = parse_hex_string("DEADBEEF").unwrap();
        assert_eq!(v, vec![0xDE, 0xAD, 0xBE, 0xEF]);
    }

    #[test]
    fn parse_hex_string_accepts_whitespace_and_lower() {
        let v = parse_hex_string("de ad\nbe\tef").unwrap();
        assert_eq!(v, vec![0xDE, 0xAD, 0xBE, 0xEF]);
    }

    #[test]
    fn parse_hex_string_rejects_odd_length() {
        assert!(parse_hex_string("ABC").is_err());
    }

    #[test]
    fn parse_hex_string_rejects_empty() {
        assert!(parse_hex_string("").is_err());
        assert!(parse_hex_string("   \n").is_err());
    }

    #[test]
    fn parse_hex_string_rejects_non_hex() {
        assert!(parse_hex_string("DEADXYZZ").is_err());
    }

    // ---- read_ace_at_offset (defensive: bounds checks on attacker bytes) -

    fn well_world_sid() -> Vec<u8> {
        // S-1-1-0 "Everyone": revision=1, subAuthCount=1, IdAuth=...,
        // SubAuthority[0]=0.
        vec![
            1, 1, 0, 0, 0, 0, 0, 1, // header + identifier authority
            0, 0, 0, 0, // sub_authority[0]
        ]
    }

    fn build_ace(mask: u32, sid: &[u8]) -> Vec<u8> {
        let mut v = Vec::new();
        v.push(0u8); // ace_type
        v.extend_from_slice(&[0, 0, 0]); // padding
        v.extend_from_slice(&[0, 0, 0, 0]); // flags (4 bytes, low byte = ace_flags)
        v.extend_from_slice(&mask.to_le_bytes());
        v.extend_from_slice(sid);
        v
    }

    #[test]
    fn read_ace_at_offset_decodes_well_known_sid() {
        let buf = build_ace(0xDEADBEEF, &well_world_sid());
        let ace = read_ace_at_offset(&buf, 0).expect("should decode");
        assert_eq!(ace.access_mask, 0xDEADBEEF);
        assert_eq!(ace.sid_bytes, well_world_sid().as_slice());
        assert_eq!(ace.next_cursor, buf.len());
    }

    #[test]
    fn read_ace_at_offset_rejects_truncated_header() {
        // Less than ACE_HEADER_SIZE + SID_FIXED_HEADER_SIZE.
        let buf = vec![0u8; 4];
        assert!(read_ace_at_offset(&buf, 0).is_err());
    }

    #[test]
    fn read_ace_at_offset_rejects_truncated_subauthorities() {
        // Pretend SubAuthorityCount is 5 but only one slot is present.
        let mut sid = vec![1u8, 5, 0, 0, 0, 0, 0, 1]; // revision=1, count=5
        sid.extend_from_slice(&[0, 0, 0, 0]); // only one sub_authority
        let buf = build_ace(0, &sid);
        assert!(read_ace_at_offset(&buf, 0).is_err());
    }

    // ---- CapabilityIndex -------------------------------------------------

    #[test]
    fn capability_index_resolves_app_package_and_group_sids() {
        let table = vec![CapabilityEntry {
            name: "internetClient".into(),
            app_package_sid: Some(well_world_sid()),
            group_sid: None,
        }];
        let idx = CapabilityIndex::from_table(&table);
        match idx.resolve(&well_world_sid()) {
            SidResolution::Capability(n) => assert_eq!(n, "internetClient"),
            _ => panic!("expected Capability"),
        }
    }

    fn build_ace_typed(ace_type: u8, mask: u32, sid: &[u8]) -> Vec<u8> {
        let mut v = Vec::new();
        v.push(ace_type);
        v.extend_from_slice(&[0, 0, 0]);
        v.extend_from_slice(&[0, 0, 0, 0]);
        v.extend_from_slice(&mask.to_le_bytes());
        v.extend_from_slice(sid);
        v
    }

    #[test]
    fn invoke_ace_walk_with_index_collects_matched_caps() {
        let sid = well_world_sid();
        let table = vec![CapabilityEntry {
            name: "internetClient".into(),
            app_package_sid: Some(sid.clone()),
            group_sid: None,
        }];
        let idx = CapabilityIndex::from_table(&table);

        let mut buf = Vec::new();
        buf.extend_from_slice(&build_ace(0, &sid));
        buf.extend_from_slice(&build_ace(0, &sid));

        let caps = invoke_ace_walk_with_index(&buf, &idx, false).unwrap();
        assert!(caps.contains("internetClient"));
        assert_eq!(caps.len(), 1);
    }

    #[test]
    fn invoke_ace_walk_skips_access_denied_ace() {
        // R5-6: an ACCESS_DENIED ACE (type 0x01) for a capability SID
        // does NOT grant the capability and must not be promoted.
        let sid = well_world_sid();
        let table = vec![CapabilityEntry {
            name: "internetClient".into(),
            app_package_sid: Some(sid.clone()),
            group_sid: None,
        }];
        let idx = CapabilityIndex::from_table(&table);

        let buf = build_ace_typed(0x01, 0, &sid);
        let caps = invoke_ace_walk_with_index(&buf, &idx, false).unwrap();
        assert!(caps.is_empty(), "deny ACE must not produce capability");

        // Allow-callback ACE (0x09) should still grant.
        let buf = build_ace_typed(0x09, 0, &sid);
        let caps = invoke_ace_walk_with_index(&buf, &idx, false).unwrap();
        assert!(caps.contains("internetClient"));
    }

    // ---- public entry points: extract_caps* ------------------------------
    //
    // the public surface (`extract_caps`,
    // `extract_caps_with_index`, `extract_caps_with_index_into`) had
    // no direct tests. Pin the hex-decode → ACE walk → resolve glue
    // here so a regression in any of those layers fails fast rather
    // than surfacing only via the WPR-driven integration harness.

    fn hex_for_bytes(bytes: &[u8]) -> String {
        use std::fmt::Write;
        let mut s = String::with_capacity(bytes.len() * 2);
        for b in bytes {
            let _ = write!(s, "{:02X}", b);
        }
        s
    }

    #[test]
    fn extract_caps_with_index_decodes_hex_and_matches_capability() {
        let sid = well_world_sid();
        let table = vec![CapabilityEntry {
            name: "documentsLibrary".into(),
            app_package_sid: Some(sid.clone()),
            group_sid: None,
        }];
        let idx = CapabilityIndex::from_table(&table);
        let hex = hex_for_bytes(&build_ace(0, &sid));

        let caps = extract_caps_with_index(&hex, &idx, false).unwrap();
        assert!(caps.contains("documentsLibrary"));
        assert_eq!(caps.len(), 1);
    }

    #[test]
    fn extract_caps_with_index_into_writes_into_caller_set() {
        let sid = well_world_sid();
        let table = vec![CapabilityEntry {
            name: "internetClient".into(),
            app_package_sid: Some(sid.clone()),
            group_sid: None,
        }];
        let idx = CapabilityIndex::from_table(&table);
        let mut buf = Vec::new();
        buf.extend_from_slice(&build_ace(0, &sid));
        buf.extend_from_slice(&build_ace(0, &sid));
        let hex = hex_for_bytes(&buf);

        // Pre-seed with an unrelated entry — extract_caps must
        // PRESERVE existing members, not overwrite them.
        let mut found: HashSet<String> = HashSet::new();
        found.insert("preexisting".into());
        extract_caps_with_index_into(&hex, &idx, false, &mut found).unwrap();
        assert!(found.contains("preexisting"));
        assert!(found.contains("internetClient"));
    }

    #[test]
    fn extract_caps_with_index_rejects_malformed_hex() {
        let table: Vec<CapabilityEntry> = Vec::new();
        let idx = CapabilityIndex::from_table(&table);
        assert!(extract_caps_with_index("not-hex", &idx, false).is_err());
        assert!(extract_caps_with_index("ABC", &idx, false).is_err());
    }

    #[test]
    fn extract_caps_with_index_returns_empty_for_no_match() {
        // SID doesn't match any capability entry in the table.
        let sid = well_world_sid();
        let table: Vec<CapabilityEntry> = Vec::new();
        let idx = CapabilityIndex::from_table(&table);
        let hex = hex_for_bytes(&build_ace(0, &sid));
        let caps = extract_caps_with_index(&hex, &idx, false).unwrap();
        assert!(caps.is_empty());
    }
}
