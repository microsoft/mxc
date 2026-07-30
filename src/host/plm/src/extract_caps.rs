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
//!
//! # Layout provenance — read before changing the constants below
//!
//! This is the DWORD-padded shape the PowerShell script decoded, **not**
//! the packed Win32 `ACCESS_ALLOWED_ACE` (`ACE_HEADER` is 4 bytes —
//! type, flags, `AceSize` — with the mask at `[4..7]` and the SID at
//! `[8..]`). The two disagree about where the SID begins (12 vs 8), and
//! this walker also derives each ACE's length from its SID size rather
//! than reading `AceSize`.
//!
//! Every fixture in this module's tests is *built* with the same layout
//! it *asserts*, so the suite cannot tell the two encodings apart. Do
//! not "correct" these offsets to the Win32 struct on inspection alone:
//! settle it against one real captured `EventID=14` blob first, and land
//! that blob as a golden fixture (see the `TODO` on
//! `golden_fixture_needed` in the tests below).

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

// --- ACE / SID wire layout -------------------------------------------
//
// Single source of truth for the offsets the walker and the test
// fixtures both use. See the layout-provenance note in the module
// header before changing any of these.

/// Offset of the ACE type byte within an ACE.
const ACE_TYPE_OFFSET: usize = 0;
/// Offset of the ACE flags field (only the low byte is meaningful).
const ACE_FLAGS_OFFSET: usize = 4;
/// Offset of the little-endian access mask.
const ACE_ACCESS_MASK_OFFSET: usize = 8;
/// Bytes occupied by the ACE header before the embedded SID begins.
const ACE_HEADER_SIZE: usize = 1 + 3 + 4 + 4; // type + 3 padding + 4 flags + 4 mask

/// Offset of `SubAuthorityCount` within a SID.
const SID_SUB_AUTHORITY_COUNT_OFFSET: usize = 1;
/// Bytes of fixed SID header preceding the sub-authority array.
const SID_FIXED_HEADER_SIZE: usize = 1 + 1 + 6; // revision + subauth count + id auth
/// Width of a single sub-authority entry.
const SID_SUB_AUTHORITY_SIZE: usize = 4;

/// `ACCESS_ALLOWED_ACE_TYPE` — grants the access in the mask.
const ACE_TYPE_ACCESS_ALLOWED: u8 = 0x00;
/// `ACCESS_ALLOWED_CALLBACK_ACE_TYPE` — same grant, callback variant.
const ACE_TYPE_ACCESS_ALLOWED_CALLBACK: u8 = 0x09;

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

/// Case-insensitive ASCII ordering that allocates nothing.
///
/// Sorting by a `to_ascii_lowercase()` key would allocate a `String` per
/// comparison; folding each byte as it is compared avoids that. Only
/// `A-Z` are folded, so this stays a well-defined total order for
/// arbitrary (including non-ASCII) input: ties under the fold are broken
/// by length, and the relation remains transitive and antisymmetric.
///
/// Shared by the config merge and the `plm extract-caps` CLI so both
/// present capability names in the same order.
pub(crate) fn ascii_ci_cmp(a: &str, b: &str) -> std::cmp::Ordering {
    let (ab, bb) = (a.as_bytes(), b.as_bytes());
    for i in 0..ab.len().min(bb.len()) {
        let (x, y) = (ab[i].to_ascii_lowercase(), bb[i].to_ascii_lowercase());
        if x != y {
            return x.cmp(&y);
        }
    }
    ab.len().cmp(&bb.len())
}

/// Capability names in stable display order.
///
/// Extracted from the `plm extract-caps` CLI arm so the ordering is
/// testable without spawning the binary.
pub fn sorted_capability_names(caps: &HashSet<String>) -> Vec<&str> {
    let mut out: Vec<&str> = caps.iter().map(String::as_str).collect();
    out.sort_by(|a, b| ascii_ci_cmp(a, b));
    out
}

/// Number of capability names this module knows how to match. Used by
/// callers reporting how many the OS rejected at table-build time.
pub fn known_capability_count() -> usize {
    KNOWN_CAPABILITIES.len()
}

/// Outcome of building the capability table, including how many known
/// capability names the OS refused to resolve.
///
/// A silently-empty table is indistinguishable from "this workload
/// needed no capabilities": every subsequent lookup misses and the
/// generated config omits capabilities entirely. Callers use
/// `derive_failures` / an empty `entries` to warn instead.
pub struct CapabilityTable {
    pub entries: Vec<CapabilityEntry>,
    pub derive_failures: usize,
}

/// Build the table of (capability name, AppPackage SID, Group SID) tuples
/// by calling `DeriveCapabilitySidsFromName` for each known capability.
/// Capabilities the OS rejects are counted in `derive_failures` rather
/// than silently dropped.
#[cfg(target_os = "windows")]
pub fn build_capability_table_with_diagnostics() -> CapabilityTable {
    let mut out = Vec::with_capacity(KNOWN_CAPABILITIES.len());
    let mut derive_failures = 0usize;

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
            derive_failures += 1;
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

    CapabilityTable {
        entries: out,
        derive_failures,
    }
}

/// Non-Windows stub: there is no equivalent to
/// `DeriveCapabilitySidsFromName` on Linux/macOS. Returning an empty
/// table keeps the pure parts of this module (parse_hex_string, ACE
/// byte walker, CapabilityIndex) callable in cross-platform tests.
#[cfg(not(target_os = "windows"))]
pub fn build_capability_table_with_diagnostics() -> CapabilityTable {
    CapabilityTable {
        entries: Vec::new(),
        derive_failures: 0,
    }
}

/// Convenience wrapper that discards the build diagnostics.
pub fn build_capability_table() -> Vec<CapabilityEntry> {
    build_capability_table_with_diagnostics().entries
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

/// Indexed view of a capability table for O(1) SID lookup. A linear
/// scan over ~150 entries per ACE dominates CPU time on traces with
/// thousands of ACEs.
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

pub(crate) fn parse_hex_string(hex_input: &str) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    parse_hex_string_into(hex_input, &mut out)?;
    Ok(out)
}

/// Decode `hex_input` into a caller-owned buffer, reusing its existing
/// capacity.
///
/// The per-event hot path decodes one multi-KB ACE blob per
/// `EventID=14` record; allocating and freeing a fresh `Vec` for each
/// one is pure overhead on a long trace. Callers hold a single scratch
/// buffer and pass it here, so steady-state decoding allocates nothing.
/// The buffer is cleared on entry, and is left empty on error so a
/// failed decode cannot leak bytes into the next event.
pub(crate) fn parse_hex_string_into(hex_input: &str, out: &mut Vec<u8>) -> Result<()> {
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
    out.clear();
    out.reserve(hex_input.len() / 2);
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
            _ => {
                out.clear();
                return Err(anyhow!("Hex string contains non-hex characters."));
            }
        };
        match nibble.take() {
            None => nibble = Some(v),
            Some(hi) => out.push((hi << 4) | v),
        }
    }
    if nibble.is_some() || out.is_empty() {
        out.clear();
        return Err(anyhow!(
            "Hex string must be non-empty and have an even length."
        ));
    }
    Ok(())
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
    let ace_type = buf[cursor + ACE_TYPE_OFFSET];
    let ace_flags = buf[cursor + ACE_FLAGS_OFFSET];
    let access_mask = u32::from_le_bytes([
        buf[cursor + ACE_ACCESS_MASK_OFFSET],
        buf[cursor + ACE_ACCESS_MASK_OFFSET + 1],
        buf[cursor + ACE_ACCESS_MASK_OFFSET + 2],
        buf[cursor + ACE_ACCESS_MASK_OFFSET + 3],
    ]);

    let sid_offset = cursor + ACE_HEADER_SIZE;
    let sub_authority_count = buf[sid_offset + SID_SUB_AUTHORITY_COUNT_OFFSET];
    let sid_size = SID_FIXED_HEADER_SIZE + SID_SUB_AUTHORITY_SIZE * sub_authority_count as usize;
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
/// Emit a one-shot warning when a capability SID is recognized on an
/// allow ACE that grants nothing.
///
/// Fires at most once per process so a long trace cannot spam the
/// console. See the call site for why this is worth reporting.
fn warn_zero_mask_capability_once(name: &str) {
    static WARNED: std::sync::Once = std::sync::Once::new();
    WARNED.call_once(|| {
        eprintln!(
            "warning: allow ACE for capability \"{name}\" has a zero access mask and was not \
             treated as a capability request. If capabilities are missing from the generated \
             config, this filter is the first thing to check."
        );
    });
}

/// Walk every ACE in `buf`, returning the matched capability names.
/// Allocates a `HashSet` per call — hot-loop callers should prefer
/// [`invoke_ace_walk_with_index_into`].
#[cfg(test)]
pub(crate) fn invoke_ace_walk_with_index(
    buf: &[u8],
    index: &CapabilityIndex,
    verbose: bool,
) -> Result<HashSet<String>> {
    let mut found: HashSet<String> = HashSet::new();
    invoke_ace_walk_with_index_into(buf, index, verbose, &mut found)?;
    Ok(found)
}

/// Walk every ACE in `buf`, inserting matched capability names into
/// `found`. This is the shared implementation every other entry point
/// funnels through.
///
/// **Partial writes on error.** The walk inserts as it goes, so a
/// buffer that decodes cleanly up to a corrupt tail leaves the
/// already-matched names in `found` *and* returns `Err`. Callers that
/// feed a security policy must therefore treat `Err` as fail-closed:
/// pass a per-blob scratch set and discard it on error rather than
/// pointing this at their accumulated set. See
/// `access_failure::consume_access_failure`, which stages into
/// `ParseAccumulator::ace_matches` and only promotes on `Ok`.
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
        let is_allow_ace = matches!(
            ace.ace_type,
            ACE_TYPE_ACCESS_ALLOWED | ACE_TYPE_ACCESS_ALLOWED_CALLBACK
        );
        // An allow ACE that grants nothing is not evidence that the
        // workload needs the capability. Accepting zero-mask ACEs lets a
        // crafted DACL inject arbitrary capability names into the
        // generated policy, so require an actual grant.
        let grants_access = ace.access_mask != 0;
        let resolution = index.resolve(ace.sid_bytes);

        if is_allow_ace {
            let matched = match &resolution {
                SidResolution::Capability(name) | SidResolution::GroupCapability(name) => {
                    Some(*name)
                }
                SidResolution::Unknown => None,
            };
            if let Some(name) = matched {
                if grants_access {
                    // Only allocate when the name is genuinely new. The
                    // set saturates at the handful of known capabilities
                    // within the first few events, so an unconditional
                    // `to_string()` would allocate-hash-drop on
                    // essentially every remaining ACE in the trace.
                    if !found.contains(name) {
                        found.insert(name.to_string());
                    }
                } else {
                    // The zero-mask filter above is a hardening measure
                    // derived from what a grant *should* look like, not
                    // from a captured trace. If this provider really does
                    // emit capability ACEs with an empty mask, the filter
                    // would silently disable extraction entirely — so say
                    // so once rather than failing quietly.
                    warn_zero_mask_capability_once(name);
                }
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
/// Used by the one-shot `plm extract-caps` CLI path; any loop should
/// build a [`CapabilityIndex`] once and use
/// [`invoke_ace_walk_with_index_into`].
pub fn invoke_ace_walk(buf: &[u8], verbose: bool) -> Result<HashSet<String>> {
    let table = build_capability_table();
    let index = CapabilityIndex::from_table(&table);
    let mut found: HashSet<String> = HashSet::new();
    invoke_ace_walk_with_index_into(buf, &index, verbose, &mut found)?;
    Ok(found)
}

/// Top-level entry point matching the script's `-HexBytes` invocation.
pub fn extract_caps(hex_bytes: &str, verbose: bool) -> Result<HashSet<String>> {
    let bytes = parse_hex_string(hex_bytes)?;
    invoke_ace_walk(&bytes, verbose)
}

/// Per-event variant that takes a pre-built `CapabilityIndex` so the
/// O(table_size) build cost is paid once per parse, not per ACE blob.
/// Allocates a fresh `HashSet` and decode buffer per call; the
/// production hot loop uses [`extract_caps_with_index_into`] instead.
#[cfg(test)]
pub(crate) fn extract_caps_with_index(
    hex_bytes: &str,
    index: &CapabilityIndex,
    verbose: bool,
) -> Result<HashSet<String>> {
    let bytes = parse_hex_string(hex_bytes)?;
    invoke_ace_walk_with_index(&bytes, index, verbose)
}

/// Hot-path variant: writes matches into a caller-provided
/// `&mut HashSet<String>` and decodes through a caller-provided scratch
/// buffer, so a steady-state event costs no allocation at all.
pub fn extract_caps_with_index_into(
    hex_bytes: &str,
    index: &CapabilityIndex,
    verbose: bool,
    scratch: &mut Vec<u8>,
    found: &mut HashSet<String>,
) -> Result<()> {
    parse_hex_string_into(hex_bytes, scratch)?;
    invoke_ace_walk_with_index_into(scratch, index, verbose, found)
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
        build_ace_typed(ACE_TYPE_ACCESS_ALLOWED, mask, sid)
    }

    /// A realistic non-zero grant mask, for tests that care about the
    /// capability actually being requested rather than about masks.
    const GRANT: u32 = 0x0012_0089;

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
        v.extend_from_slice(&[0, 0, 0]); // padding
        v.extend_from_slice(&[0, 0, 0, 0]); // flags (low byte meaningful)
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
        buf.extend_from_slice(&build_ace(GRANT, &sid));
        buf.extend_from_slice(&build_ace(GRANT, &sid));

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

        let buf = build_ace_typed(0x01, GRANT, &sid);
        let caps = invoke_ace_walk_with_index(&buf, &idx, false).unwrap();
        assert!(caps.is_empty(), "deny ACE must not produce capability");

        // Allow-callback ACE (0x09) should still grant.
        let buf = build_ace_typed(ACE_TYPE_ACCESS_ALLOWED_CALLBACK, GRANT, &sid);
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
        let hex = hex_for_bytes(&build_ace(GRANT, &sid));

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
        buf.extend_from_slice(&build_ace(GRANT, &sid));
        buf.extend_from_slice(&build_ace(GRANT, &sid));
        let hex = hex_for_bytes(&buf);

        // Pre-seed with an unrelated entry — extract_caps must
        // PRESERVE existing members, not overwrite them.
        let mut found: HashSet<String> = HashSet::new();
        found.insert("preexisting".into());
        let mut scratch = Vec::new();
        extract_caps_with_index_into(&hex, &idx, false, &mut scratch, &mut found).unwrap();
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
        let hex = hex_for_bytes(&build_ace(GRANT, &sid));
        let caps = extract_caps_with_index(&hex, &idx, false).unwrap();
        assert!(caps.is_empty());
    }

    // ---- adversarial / malformed ACE buffers -----------------------------
    //
    // The blob is attacker-influenceable: it arrives as hex text inside
    // an ETW payload emitted while an untrusted workload runs. These
    // pin "errors, never panics, never over-reads" on the shapes a
    // hostile or truncated buffer can take.

    fn cap_index_for(sid: &[u8], name: &str) -> CapabilityIndex {
        CapabilityIndex::from_table(&[CapabilityEntry {
            name: name.into(),
            app_package_sid: Some(sid.to_vec()),
            group_sid: None,
        }])
    }

    #[test]
    fn zero_mask_allow_ace_does_not_grant_capability() {
        // An allow ACE that grants nothing is not evidence the workload
        // needs the capability; accepting it would let a crafted DACL
        // inject capability names into the generated policy.
        let sid = well_world_sid();
        let idx = cap_index_for(&sid, "internetClient");
        let caps = invoke_ace_walk_with_index(&build_ace(0, &sid), &idx, false).unwrap();
        assert!(
            caps.is_empty(),
            "zero-mask allow ACE must not produce a capability"
        );
    }

    #[test]
    fn valid_ace_followed_by_truncated_ace_is_an_error() {
        // The first ACE is well-formed; the trailing bytes are not a
        // complete ACE. The walk must fail rather than silently
        // accepting the partial trailer.
        let sid = well_world_sid();
        let idx = cap_index_for(&sid, "internetClient");
        let mut buf = build_ace(GRANT, &sid);
        buf.extend_from_slice(&[0u8; 6]); // too short for another ACE
        assert!(invoke_ace_walk_with_index(&buf, &idx, false).is_err());
    }

    #[test]
    fn truncated_tail_writes_partially_so_callers_must_stage() {
        // Pins the low-level contract that motivates fail-closed
        // staging in `consume_access_failure`: the walker DOES leave
        // matches behind on error, which is exactly why a caller must
        // not point it at an accumulated policy set.
        let sid = well_world_sid();
        let idx = cap_index_for(&sid, "internetClient");
        let mut buf = build_ace(GRANT, &sid);
        buf.extend_from_slice(&[0u8; 6]);

        let mut found = HashSet::new();
        let err = invoke_ace_walk_with_index_into(&buf, &idx, false, &mut found);

        assert!(err.is_err(), "truncated tail must still report an error");
        assert!(
            found.contains("internetClient"),
            "walker writes as it goes; callers must stage and discard on Err"
        );
    }

    #[test]
    fn maximal_sub_authority_count_without_bytes_is_an_error() {
        // SubAuthorityCount is a u8, so a hostile blob can claim 255
        // sub-authorities (1020 bytes) while supplying none. The size
        // computation must not overflow or over-read.
        let mut sid = vec![1u8, 255, 0, 0, 0, 0, 0, 1];
        sid.extend_from_slice(&[0, 0, 0, 0]);
        let buf = build_ace(GRANT, &sid);
        assert!(read_ace_at_offset(&buf, 0).is_err());
    }

    #[test]
    fn ace_exactly_at_buffer_boundary_decodes() {
        // Exact-fit buffer: the walk must terminate cleanly rather than
        // attempting to read one ACE past the end.
        let sid = well_world_sid();
        let idx = cap_index_for(&sid, "internetClient");
        let buf = build_ace(GRANT, &sid);
        let ace = read_ace_at_offset(&buf, 0).expect("exact-fit ACE should decode");
        assert_eq!(ace.next_cursor, buf.len());
        let caps = invoke_ace_walk_with_index(&buf, &idx, false).unwrap();
        assert!(caps.contains("internetClient"));
    }

    #[test]
    fn single_trailing_byte_after_valid_ace_is_an_error() {
        let sid = well_world_sid();
        let idx = cap_index_for(&sid, "internetClient");
        let mut buf = build_ace(GRANT, &sid);
        buf.push(0xFF);
        assert!(invoke_ace_walk_with_index(&buf, &idx, false).is_err());
    }

    #[test]
    fn malformed_hex_shapes_are_rejected_without_panic() {
        let idx = CapabilityIndex::from_table(&[]);
        for bad in ["ABC", "not-hex", "", "   \n", "AB CD E"] {
            let mut scratch = Vec::new();
            let mut found = HashSet::new();
            assert!(
                extract_caps_with_index_into(bad, &idx, false, &mut scratch, &mut found).is_err(),
                "expected {bad:?} to be rejected"
            );
            assert!(
                scratch.is_empty(),
                "scratch must be left clean after a failed decode"
            );
        }
    }

    #[test]
    fn scratch_buffer_is_reused_across_decodes() {
        // Regression guard for the per-event allocation fix: decoding
        // through a shared buffer must not leak bytes from the previous
        // event into the next one.
        let sid = well_world_sid();
        let idx = cap_index_for(&sid, "internetClient");
        let hex = hex_for_bytes(&build_ace(GRANT, &sid));
        let mut scratch = Vec::new();
        let mut found = HashSet::new();

        extract_caps_with_index_into(&hex, &idx, false, &mut scratch, &mut found).unwrap();
        let after_first = scratch.len();
        extract_caps_with_index_into(&hex, &idx, false, &mut scratch, &mut found).unwrap();

        assert_eq!(
            scratch.len(),
            after_first,
            "reused scratch must not accumulate across decodes"
        );
        assert_eq!(found.len(), 1);
    }

    #[test]
    fn sorted_capability_names_orders_case_insensitively() {
        // Backs the `plm extract-caps` output ordering, which is
        // otherwise only reachable by running the binary.
        let caps: HashSet<String> = ["Zebra", "apple", "Banana"]
            .iter()
            .map(|s| s.to_string())
            .collect();
        assert_eq!(
            sorted_capability_names(&caps),
            vec!["apple", "Banana", "Zebra"]
        );
    }

    #[test]
    fn sorted_capability_names_handles_empty_set() {
        let caps: HashSet<String> = HashSet::new();
        assert!(sorted_capability_names(&caps).is_empty());
    }

    /// TODO(golden-fixture): this module's ACE layout (12-byte header,
    /// SID at `[12..]`) is inherited from `extract_caps.ps1` and differs
    /// from the packed Win32 `ACCESS_ALLOWED_ACE` (SID at `[8..]`).
    /// Every fixture here is built with the same layout it asserts, so
    /// the suite cannot tell the two apart. Capture one real
    /// `EventID=14` DACL blob, paste its hex here, and assert the
    /// expected capability set — that single fixture is what makes the
    /// layout constants authoritative.
    #[test]
    #[ignore = "needs a real captured EventID=14 ACE blob; see TODO above"]
    fn golden_fixture_needed_real_ace_blob_decodes() {
        unimplemented!("paste a captured ACE blob and its expected capabilities");
    }
}

/// Exercises the Windows FFI seam (`DeriveCapabilitySidsFromName`, SID
/// copy-out, `LocalFree` cleanup) that the cross-platform tests cannot
/// reach: on non-Windows the table is an empty stub, so a green CI run
/// says nothing about whether real SID resolution works.
#[cfg(all(test, target_os = "windows"))]
mod windows_ffi_tests {
    use super::*;

    #[test]
    fn build_capability_table_derives_real_sids() {
        let built = build_capability_table_with_diagnostics();

        // Every known name is either derived or counted as a failure —
        // entries must never silently disappear.
        assert_eq!(
            built.entries.len() + built.derive_failures,
            KNOWN_CAPABILITIES.len(),
            "every known capability must be either derived or counted as a failure"
        );

        // A stock Windows host resolves at least the common capabilities.
        // If this host resolves none, the diagnostics must say so rather
        // than reporting a clean empty table.
        if built.entries.is_empty() {
            assert_eq!(built.derive_failures, KNOWN_CAPABILITIES.len());
            return;
        }

        for entry in &built.entries {
            assert!(!entry.name.is_empty());
            assert!(
                entry.app_package_sid.is_some() || entry.group_sid.is_some(),
                "derived entry {} carried no SID",
                entry.name
            );
            // Any SID the OS handed back must be structurally valid —
            // this is what proves the copy-out length arithmetic is right.
            for sid in [&entry.app_package_sid, &entry.group_sid]
                .into_iter()
                .flatten()
            {
                assert!(
                    sid_to_string(sid).is_some(),
                    "derived SID for {} did not round-trip through ConvertSidToStringSid",
                    entry.name
                );
            }
        }
    }

    #[test]
    fn real_derived_sid_resolves_through_the_index() {
        // End-to-end on real OS data: derive a capability SID, build an
        // ACE around it, and confirm the walker recovers the name.
        let built = build_capability_table_with_diagnostics();
        let Some(entry) = built
            .entries
            .iter()
            .find(|e| e.app_package_sid.is_some())
            .cloned()
        else {
            // Host derived nothing; covered by the assertion above.
            return;
        };
        let sid = entry.app_package_sid.clone().unwrap();
        let index = CapabilityIndex::from_table(&built.entries);

        let mut ace = vec![ACE_TYPE_ACCESS_ALLOWED, 0, 0, 0];
        ace.extend_from_slice(&[0, 0, 0, 0]);
        ace.extend_from_slice(&0x0012_0089u32.to_le_bytes());
        ace.extend_from_slice(&sid);

        let mut found = HashSet::new();
        invoke_ace_walk_with_index_into(&ace, &index, false, &mut found).unwrap();
        assert!(
            found.contains(&entry.name),
            "walker did not recover {} from a real derived SID",
            entry.name
        );
    }

    #[test]
    fn repeated_table_builds_are_stable_and_do_not_leak_handles() {
        // Each build does a LocalAlloc/LocalFree round-trip per name;
        // repeating it must produce identical output.
        let a = build_capability_table_with_diagnostics();
        let b = build_capability_table_with_diagnostics();
        assert_eq!(a.entries.len(), b.entries.len());
        assert_eq!(a.derive_failures, b.derive_failures);
        for (x, y) in a.entries.iter().zip(b.entries.iter()) {
            assert_eq!(x.name, y.name);
            assert_eq!(x.app_package_sid, y.app_package_sid);
            assert_eq!(x.group_sid, y.group_sid);
        }
    }
}
