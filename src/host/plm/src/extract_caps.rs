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
///
/// Recognized so the walker can reject it explicitly. A callback ACE
/// carries a conditional-expression `OpaqueData` blob after the SID, and
/// the only field that describes its length is `AceSize` — which this
/// header layout does not carry. Its framing is therefore unresolvable
/// here; see [`read_ace_at_offset`].
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
/// testable without spawning the binary. Generic over the element type
/// so it serves both the borrowed set the extractor produces and the
/// owned set carried in a `ParseResult`.
pub fn sorted_capability_names<S>(caps: &HashSet<S>) -> Vec<&str>
where
    S: std::borrow::Borrow<str> + Eq + std::hash::Hash,
{
    let mut out: Vec<&str> = caps.iter().map(|s| s.borrow()).collect();
    out.sort_by(|a, b| ascii_ci_cmp(a, b));
    out
}

/// Number of capability names this module knows how to match. Used by
/// callers reporting how many the OS rejected at table-build time.
pub fn known_capability_count() -> usize {
    KNOWN_CAPABILITIES.len()
}

/// Build the SID → capability index by calling
/// `DeriveCapabilitySidsFromName` for each known capability.
///
/// The index is built directly rather than through an intermediate
/// table: the OS is its only producer and every consumer wants the map,
/// so the extra vector was pure conversion cost. Capabilities the OS
/// rejects are counted in [`CapabilityIndex::derive_failures`] rather
/// than silently dropped — an index that resolved nothing is
/// indistinguishable from "this workload needed no capabilities",
/// because every lookup misses and the generated config omits
/// capabilities entirely.
#[cfg(target_os = "windows")]
pub fn build_capability_index() -> CapabilityIndex {
    let mut index = CapabilityIndex::with_capacity(KNOWN_CAPABILITIES.len() * 2);

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
            index.derive_failures += 1;
            continue;
        }
        index.resolved_capabilities += 1;

        // First entry of each array is the canonical SID; alternate
        // encodings (when present) are not currently matched. Each is read
        // through a bounded slice (see `first_sid_bytes`) so the access is
        // tied to the count the OS reported rather than a raw dereference.
        if let Some(sid) = unsafe { first_sid_bytes(cap_sids, cap_count) } {
            index.insert_package_sid(sid, name);
        }
        if let Some(sid) = unsafe { first_sid_bytes(group_sids, group_count) } {
            index.insert_group_sid(sid, name);
        }

        unsafe {
            free_sid_array(cap_sids, cap_count);
            free_sid_array(group_sids, group_count);
        }
    }

    index
}

/// Non-Windows stub: there is no equivalent to
/// `DeriveCapabilitySidsFromName` on Linux/macOS. Returning an empty
/// index keeps the pure parts of this module (parse_hex_string, ACE
/// byte walker, CapabilityIndex) callable in cross-platform tests.
#[cfg(not(target_os = "windows"))]
pub fn build_capability_index() -> CapabilityIndex {
    CapabilityIndex::with_capacity(0)
}

/// Build the capability index and report what this OS refused to
/// resolve.
///
/// Discovery belongs at the CLI boundary rather than inside
/// `parse_events`: querying the live OS mid-parse makes a fixed `.etl`
/// fixture yield different results across Windows versions and
/// impossible to exercise on non-Windows CI. Callers build the index
/// here and inject it, so the parser itself is deterministic.
pub fn discover_capabilities(verbose: bool) -> CapabilityIndex {
    let index = build_capability_index();
    if index.resolved_capabilities() == 0 {
        eprintln!(
            "warning: no AppContainer capability SIDs could be derived on this host \
             ({} of {} known names rejected); no capabilities will be detected.",
            index.derive_failures(),
            known_capability_count()
        );
    } else if index.derive_failures() > 0 && verbose {
        println!(
            "Note: {} of {} known capability names were rejected by this OS and will not be \
             matched.",
            index.derive_failures(),
            known_capability_count()
        );
    }
    index
}

/// Encoded length of the SID at the front of `bytes`, or `None` when
/// `bytes` is too short to hold the fixed header or the sub-authority
/// array that header declares.
///
/// This is the bounds check that must run *before* any raw pointer to
/// `bytes` reaches Win32: the SID APIs read `8 + 4 * SubAuthorityCount`
/// bytes through the pointer, and these blobs come from
/// attacker-influenceable trace data.
#[cfg(any(target_os = "windows", test))]
fn encoded_sid_len(bytes: &[u8]) -> Option<usize> {
    let sub_authority_count = *bytes.get(SID_SUB_AUTHORITY_COUNT_OFFSET)? as usize;
    let len = SID_FIXED_HEADER_SIZE + SID_SUB_AUTHORITY_SIZE * sub_authority_count;
    (bytes.len() >= len).then_some(len)
}

/// Best-effort string form of a SID for diagnostics. Returns `None` if the
/// bytes aren't a valid SID.
#[cfg(target_os = "windows")]
pub fn sid_to_string(sid_bytes: &[u8]) -> Option<String> {
    // `IsValidSid` dereferences the pointer to read the fixed header and
    // the declared sub-authority array, so prove the slice is large
    // enough first. Without this, callers passing a short slice (e.g.
    // `&[]` or `&[1]`) make Win32 read past the end of the allocation.
    encoded_sid_len(sid_bytes)?;
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

/// Indexed view of the OS capability SIDs for O(1) lookup. A linear
/// scan over ~150 entries per ACE dominates CPU time on traces with
/// thousands of ACEs.
///
/// The map keys are SID byte sequences; the value pairs the matched
/// capability name with a flag distinguishing the package-SID variant
/// (`false`) from the group-SID variant (`true`). It owns its keys so
/// it can be carried inside `ParseAccumulator` without the
/// self-referential lifetime headaches that a borrowing form imposes on
/// callers.
///
/// Names are `&'static str` borrowed straight out of
/// [`KNOWN_CAPABILITIES`], so resolving and staging a match allocates
/// nothing — a `String` is materialized only when a capability is first
/// promoted into a trace-wide result set.
pub struct CapabilityIndex {
    by_sid: HashMap<Vec<u8>, (&'static str, bool)>,
    resolved_capabilities: usize,
    derive_failures: usize,
}

/// A `(capability name, package SID, group SID)` triple, as
/// [`CapabilityIndex::for_test`] accepts them.
#[cfg(test)]
pub(crate) type TestCapabilityEntry<'a> = (&'static str, Option<&'a [u8]>, Option<&'a [u8]>);

impl CapabilityIndex {
    fn with_capacity(sids: usize) -> Self {
        Self {
            by_sid: HashMap::with_capacity(sids),
            resolved_capabilities: 0,
            derive_failures: 0,
        }
    }

    fn insert_package_sid(&mut self, sid: Vec<u8>, name: &'static str) {
        self.by_sid.insert(sid, (name, false));
    }

    fn insert_group_sid(&mut self, sid: Vec<u8>, name: &'static str) {
        // App-package SID wins on conflict (it's the canonical form);
        // only insert the group SID when no entry exists.
        self.by_sid.entry(sid).or_insert((name, true));
    }

    /// Known capability names this OS resolved.
    pub fn resolved_capabilities(&self) -> usize {
        self.resolved_capabilities
    }

    /// Known capability names this OS refused to resolve.
    pub fn derive_failures(&self) -> usize {
        self.derive_failures
    }

    /// Resolve a SID to `(capability name, matched via the group SID)`.
    ///
    /// The `is_group` flag only distinguishes verbose diagnostic text;
    /// both variants are equally strong evidence of a request, which is
    /// why this is a flag rather than a dedicated enum.
    pub fn resolve(&self, sid_bytes: &[u8]) -> Option<(&'static str, bool)> {
        self.by_sid.get(sid_bytes).copied()
    }

    /// Test seam: iterate the indexed `(SID bytes, capability name,
    /// matched via group SID)` triples. Lets the Windows FFI tests
    /// validate what the OS actually handed back without reintroducing
    /// an intermediate table on the production path.
    #[cfg(test)]
    pub(crate) fn iter_sids(&self) -> impl Iterator<Item = (&[u8], &'static str, bool)> {
        self.by_sid
            .iter()
            .map(|(sid, (name, is_group))| (sid.as_slice(), *name, *is_group))
    }

    /// Test seam: build an index without touching the OS. Mirrors the
    /// insertion order `build_capability_index` uses, so package SIDs
    /// win over group SIDs exactly as they do in production.
    #[cfg(test)]
    pub(crate) fn for_test(entries: &[TestCapabilityEntry<'_>]) -> Self {
        let mut index = Self::with_capacity(entries.len() * 2);
        for &(name, package_sid, group_sid) in entries {
            index.resolved_capabilities += 1;
            if let Some(sid) = package_sid {
                index.insert_package_sid(sid.to_vec(), name);
            }
            if let Some(sid) = group_sid {
                index.insert_group_sid(sid.to_vec(), name);
            }
        }
        index
    }
}

/// Per-trace scratch and diagnostics for the ACE walk.
///
/// Owned by the caller so one trace reuses a single hex-decode buffer
/// and a single staging set, and so the zero-mask condition is counted
/// per parse rather than once per process.
#[derive(Default)]
pub struct AceWalkState {
    /// Reusable hex-decode buffer for the per-event ACE blob.
    scratch: Vec<u8>,
    /// Per-blob staging set. Entries are borrowed, so staging a match
    /// costs no allocation no matter how many events repeat it.
    pub(crate) matches: HashSet<&'static str>,
    zero_mask_capabilities: usize,
}

impl AceWalkState {
    pub fn new() -> Self {
        Self::default()
    }

    /// Allow ACEs that named a known capability but granted nothing, and
    /// so were not treated as capability requests.
    pub fn zero_mask_capabilities(&self) -> usize {
        self.zero_mask_capabilities
    }
}

/// Decode a hex string into a fresh buffer. Test-only: production paths
/// decode through [`AceWalkState`]'s reusable scratch buffer.
#[cfg(test)]
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
    // input is ASCII hex copied from an ETW diagnostic payload, so per-codepoint
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
    // A callback ACE is followed by a conditional-expression
    // `OpaqueData` blob whose length lives in `AceSize` — a field this
    // header layout does not carry. Advancing past the SID alone would
    // read that opaque data as the next ACE header, so every ACE after
    // it (and the capabilities they grant) would be decoded from
    // attacker-influenced offsets. Refuse the blob instead: the caller
    // stages matches and drops them on `Err`, so this is fail-closed.
    // Lift this once a captured EventID=14 payload establishes the
    // framing.
    if ace_type == ACE_TYPE_ACCESS_ALLOWED_CALLBACK {
        return Err(anyhow!(
            "Unsupported callback ACE (type 0x{:02X}) at byte offset {}: its trailing OpaqueData \
             has no length field in this header layout, so the rest of the blob cannot be framed.",
            ACE_TYPE_ACCESS_ALLOWED_CALLBACK,
            cursor
        ));
    }
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

/// Walk every ACE in `buf`, staging matched capability names in
/// `found` and counting zero-mask hits in `zero_mask_capabilities`.
/// When `verbose` is true a per-ACE diagnostic line goes to stdout.
///
/// **Partial writes on error.** The walk stages as it goes, so a buffer
/// that decodes cleanly up to a corrupt tail leaves the already-matched
/// names in `found` *and* returns `Err`. Callers that feed a security
/// policy must therefore treat `Err` as fail-closed: stage per blob and
/// discard on error rather than pointing this at an accumulated set.
/// Production callers must similarly stage matches and only promote on `Ok`.
fn walk_aces(
    buf: &[u8],
    index: &CapabilityIndex,
    verbose: bool,
    found: &mut HashSet<&'static str>,
    zero_mask_capabilities: &mut usize,
) -> Result<()> {
    let mut cursor = 0usize;
    let mut ace_index = 0usize;

    while cursor < buf.len() {
        let ace = read_ace_at_offset(buf, cursor)?;
        // Callback ACEs are rejected in `read_ace_at_offset`, so only the
        // plain allow type can reach here.
        let is_allow_ace = ace.ace_type == ACE_TYPE_ACCESS_ALLOWED;
        // An allow ACE that grants nothing is not evidence that the
        // workload needs the capability. Accepting zero-mask ACEs lets a
        // crafted DACL inject arbitrary capability names into the
        // generated policy, so require an actual grant.
        let grants_access = ace.access_mask != 0;
        let resolution = index.resolve(ace.sid_bytes);

        if is_allow_ace {
            if let Some((name, _is_group)) = resolution {
                if grants_access {
                    // Staging a borrowed name never allocates, so there
                    // is no reason to test membership first.
                    found.insert(name);
                } else {
                    // The zero-mask filter above is a hardening measure
                    // derived from what a grant *should* look like, not
                    // from a captured trace. If this provider really does
                    // emit capability ACEs with an empty mask, the filter
                    // would silently disable extraction entirely — so
                    // count it and let the caller report it once per
                    // trace rather than failing quietly.
                    *zero_mask_capabilities += 1;
                }
            }
        }

        if verbose {
            let resolved_str = match resolution {
                Some((name, false)) => format!("capability \"{name}\""),
                Some((name, true)) => format!("capability \"{name}\" (group SID)"),
                None => "<no known capability/account matches this SID>".to_string(),
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

/// One-shot entry point for the `plm extract-caps` CLI: decode a hex
/// blob against a freshly built index and return what it matched.
///
/// Builds an index per call, so any loop should build a
/// [`CapabilityIndex`] once and use [`extract_caps_into`] instead.
pub fn extract_caps(hex_bytes: &str, verbose: bool) -> Result<HashSet<&'static str>> {
    let index = build_capability_index();
    let mut state = AceWalkState::new();
    extract_caps_into(hex_bytes, &index, verbose, &mut state)?;
    Ok(state.matches)
}

/// Hot-path entry point: decode `hex_bytes` through `state`'s scratch
/// buffer and stage matches in `state.matches`, so a steady-state event
/// costs no allocation at all.
///
/// `state.matches` is deliberately **not** cleared here — the staging
/// set is the caller's fail-closed boundary, so the caller clears
/// before each blob and promotes only on `Ok`.
pub fn extract_caps_into(
    hex_bytes: &str,
    index: &CapabilityIndex,
    verbose: bool,
    state: &mut AceWalkState,
) -> Result<()> {
    // Destructured so the scratch buffer and the staging set are
    // borrowed disjointly.
    let AceWalkState {
        scratch,
        matches,
        zero_mask_capabilities,
    } = state;
    parse_hex_string_into(hex_bytes, scratch)?;
    walk_aces(scratch, index, verbose, matches, zero_mask_capabilities)
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

    // ---- SID bounds checking (no raw pointer reaches Win32 unproven) -----

    #[test]
    fn encoded_sid_len_accepts_a_well_formed_sid() {
        // S-1-1-0: 8-byte fixed header + one 4-byte sub-authority.
        assert_eq!(encoded_sid_len(&well_world_sid()), Some(12));
    }

    #[test]
    fn encoded_sid_len_rejects_slices_shorter_than_the_fixed_header() {
        // Nothing at all, and a slice too short to even hold the
        // SubAuthorityCount byte, let alone the identifier authority.
        assert_eq!(encoded_sid_len(&[]), None);
        assert_eq!(encoded_sid_len(&[1]), None);
        // Declares zero sub-authorities but is still one byte short of
        // the 8-byte fixed header.
        assert_eq!(encoded_sid_len(&[1, 0, 0, 0, 0, 0, 0]), None);
    }

    #[test]
    fn encoded_sid_len_rejects_subauthority_count_beyond_the_slice() {
        // Declares 5 sub-authorities (needs 28 bytes) but carries one.
        let mut sid = vec![1u8, 5, 0, 0, 0, 0, 0, 1];
        sid.extend_from_slice(&[0, 0, 0, 0]);
        assert_eq!(encoded_sid_len(&sid), None);
        // A count of 255 must not overflow into a small length.
        let sid = vec![1u8, 255, 0, 0, 0, 0, 0, 1];
        assert_eq!(encoded_sid_len(&sid), None);
    }

    #[test]
    fn sid_to_string_rejects_undersized_slices_without_reading_out_of_bounds() {
        // These are the inputs that previously handed an unproven
        // pointer to `IsValidSid`. Each must be rejected by the Rust-side
        // bounds check before Win32 sees the slice; a regression here is
        // an out-of-bounds read rather than a failed assertion, so this
        // is most valuable under a sanitizer.
        assert_eq!(sid_to_string(&[]), None);
        assert_eq!(sid_to_string(&[1]), None);
        assert_eq!(sid_to_string(&[1, 0, 0, 0, 0, 0, 0]), None);

        // Header claims more sub-authorities than the buffer holds.
        let mut truncated = vec![1u8, 5, 0, 0, 0, 0, 0, 1];
        truncated.extend_from_slice(&[0, 0, 0, 0]);
        assert_eq!(sid_to_string(&truncated), None);
    }

    // ---- CapabilityIndex -------------------------------------------------

    #[test]
    fn capability_index_resolves_app_package_and_group_sids() {
        let sid = well_world_sid();
        let idx = CapabilityIndex::for_test(&[("internetClient", Some(&sid), None)]);
        assert_eq!(idx.resolve(&sid), Some(("internetClient", false)));

        // The group SID resolves to the same name, flagged as a group
        // match; an unknown SID resolves to nothing.
        let group = vec![1u8, 1, 0, 0, 0, 0, 0, 5, 7, 0, 0, 0];
        let idx = CapabilityIndex::for_test(&[("documentsLibrary", None, Some(&group))]);
        assert_eq!(idx.resolve(&group), Some(("documentsLibrary", true)));
        assert_eq!(idx.resolve(&sid), None);
    }

    #[test]
    fn capability_index_prefers_the_package_sid_on_conflict() {
        // Both names claim the same SID; the package variant is the
        // canonical form and must win, exactly as it does when the OS
        // builder inserts them.
        let sid = well_world_sid();
        let idx = CapabilityIndex::for_test(&[
            ("internetClient", Some(&sid), None),
            ("documentsLibrary", None, Some(&sid)),
        ]);
        assert_eq!(idx.resolve(&sid), Some(("internetClient", false)));
        assert_eq!(idx.resolved_capabilities(), 2);
        assert_eq!(idx.derive_failures(), 0);
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

    /// Explicit walk setup. Production stages through an
    /// [`AceWalkState`], so tests that only care about matched names
    /// assemble the pieces here rather than keeping a wrapper on the
    /// module's public surface that production never calls.
    fn walk_with_zero_mask(
        buf: &[u8],
        index: &CapabilityIndex,
    ) -> (Result<()>, HashSet<&'static str>, usize) {
        let mut found = HashSet::new();
        let mut zero_mask = 0usize;
        let outcome = walk_aces(buf, index, false, &mut found, &mut zero_mask);
        (outcome, found, zero_mask)
    }

    fn walk(buf: &[u8], index: &CapabilityIndex) -> Result<HashSet<&'static str>> {
        let (outcome, found, _) = walk_with_zero_mask(buf, index);
        outcome.map(|()| found)
    }

    /// Explicit hex-path setup, mirroring how the parser hot loop calls
    /// [`extract_caps_into`].
    fn extract(hex: &str, index: &CapabilityIndex) -> Result<HashSet<&'static str>> {
        let mut state = AceWalkState::new();
        extract_caps_into(hex, index, false, &mut state)?;
        Ok(state.matches)
    }

    #[test]
    fn ace_walk_collects_matched_caps() {
        let sid = well_world_sid();
        let idx = cap_index_for(&sid, "internetClient");

        let mut buf = Vec::new();
        buf.extend_from_slice(&build_ace(GRANT, &sid));
        buf.extend_from_slice(&build_ace(GRANT, &sid));

        let caps = walk(&buf, &idx).unwrap();
        assert!(caps.contains("internetClient"));
        assert_eq!(caps.len(), 1);
    }

    #[test]
    fn ace_walk_skips_access_denied_ace() {
        // R5-6: an ACCESS_DENIED ACE (type 0x01) for a capability SID
        // does NOT grant the capability and must not be promoted.
        let sid = well_world_sid();
        let idx = cap_index_for(&sid, "internetClient");

        let buf = build_ace_typed(0x01, GRANT, &sid);
        let caps = walk(&buf, &idx).unwrap();
        assert!(caps.is_empty(), "deny ACE must not produce capability");

        // A callback ACE (0x09) is followed by conditional OpaqueData
        // with no length field in this header layout, so the walk cannot
        // be framed past it. It must fail closed rather than grant.
        let buf = build_ace_typed(ACE_TYPE_ACCESS_ALLOWED_CALLBACK, GRANT, &sid);
        let err = walk(&buf, &idx)
            .expect_err("callback ACE framing is unresolvable and must be rejected");
        assert!(
            err.to_string().contains("callback ACE"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn callback_ace_aborts_the_walk_so_later_aces_are_never_misframed() {
        // The bytes trailing a callback ACE are its OpaqueData, not the
        // next ACE header. Decoding onward would resolve capabilities
        // from attacker-chosen offsets, so the whole blob is refused.
        let sid = well_world_sid();
        let idx = cap_index_for(&sid, "internetClient");

        let mut buf = build_ace(GRANT, &sid);
        buf.extend_from_slice(&build_ace_typed(
            ACE_TYPE_ACCESS_ALLOWED_CALLBACK,
            GRANT,
            &sid,
        ));

        let (outcome, found, _) = walk_with_zero_mask(&buf, &idx);
        let err = outcome.expect_err("a callback ACE must abort the walk");
        assert!(
            err.to_string().contains("callback ACE"),
            "unexpected error: {err}"
        );
        // The walk stages as it goes, so the leading ACE is already in
        // `found` when the error fires. That is the documented
        // partial-write contract which obliges callers to pass a
        // per-blob staging set and discard it on `Err` — asserted here so
        // the fail-closed duty stays visible if this test is revisited.
        assert_eq!(
            found.len(),
            1,
            "partial write expected; callers must discard this set on Err"
        );
    }

    // ---- public entry points: extract_caps_into --------------------------
    //
    // Pin the hex-decode → ACE walk → resolve glue so a regression in
    // any of those layers fails fast rather than surfacing only via the
    // WPR-driven integration harness.

    fn hex_for_bytes(bytes: &[u8]) -> String {
        use std::fmt::Write;
        let mut s = String::with_capacity(bytes.len() * 2);
        for b in bytes {
            let _ = write!(s, "{:02X}", b);
        }
        s
    }

    #[test]
    fn extract_caps_into_decodes_hex_and_matches_capability() {
        let sid = well_world_sid();
        let idx = cap_index_for(&sid, "documentsLibrary");
        let hex = hex_for_bytes(&build_ace(GRANT, &sid));

        let caps = extract(&hex, &idx).unwrap();
        assert!(caps.contains("documentsLibrary"));
        assert_eq!(caps.len(), 1);
    }

    #[test]
    fn extract_caps_into_preserves_existing_staged_entries() {
        let sid = well_world_sid();
        let idx = cap_index_for(&sid, "internetClient");
        let mut buf = Vec::new();
        buf.extend_from_slice(&build_ace(GRANT, &sid));
        buf.extend_from_slice(&build_ace(GRANT, &sid));
        let hex = hex_for_bytes(&buf);

        // Pre-seed the staging set — `extract_caps_into` deliberately
        // does not clear it, because clearing is the caller's
        // fail-closed boundary.
        let mut state = AceWalkState::new();
        state.matches.insert("preexisting");
        extract_caps_into(&hex, &idx, false, &mut state).unwrap();
        assert!(state.matches.contains("preexisting"));
        assert!(state.matches.contains("internetClient"));
    }

    #[test]
    fn extract_caps_into_rejects_malformed_hex() {
        let idx = CapabilityIndex::for_test(&[]);
        assert!(extract("not-hex", &idx).is_err());
        assert!(extract("ABC", &idx).is_err());
    }

    #[test]
    fn extract_caps_into_returns_empty_for_no_match() {
        // SID doesn't match any capability entry in the index.
        let sid = well_world_sid();
        let idx = CapabilityIndex::for_test(&[]);
        let hex = hex_for_bytes(&build_ace(GRANT, &sid));
        let caps = extract(&hex, &idx).unwrap();
        assert!(caps.is_empty());
    }

    // ---- adversarial / malformed ACE buffers -----------------------------
    //
    // The blob is attacker-influenceable: it arrives as hex text inside
    // an ETW payload emitted while an untrusted workload runs. These
    // pin "errors, never panics, never over-reads" on the shapes a
    // hostile or truncated buffer can take.

    fn cap_index_for(sid: &[u8], name: &'static str) -> CapabilityIndex {
        CapabilityIndex::for_test(&[(name, Some(sid), None)])
    }

    #[test]
    fn zero_mask_allow_ace_does_not_grant_capability() {
        // An allow ACE that grants nothing is not evidence the workload
        // needs the capability; accepting it would let a crafted DACL
        // inject capability names into the generated policy.
        let sid = well_world_sid();
        let idx = cap_index_for(&sid, "internetClient");
        let (outcome, caps, zero_mask) = walk_with_zero_mask(&build_ace(0, &sid), &idx);
        outcome.unwrap();
        assert!(
            caps.is_empty(),
            "zero-mask allow ACE must not produce a capability"
        );
        // Counted rather than warned inline, so the condition is
        // reported once per trace and is assertable here.
        assert_eq!(zero_mask, 1);
    }

    #[test]
    fn zero_mask_counter_is_per_walk_not_per_process() {
        // Regression guard for the process-global `Once` this replaced:
        // two independent walks must each observe the condition, in any
        // order, so test outcomes never depend on execution sequence.
        let sid = well_world_sid();
        let idx = cap_index_for(&sid, "internetClient");
        for _ in 0..2 {
            let (outcome, _, zero_mask) = walk_with_zero_mask(&build_ace(0, &sid), &idx);
            outcome.unwrap();
            assert_eq!(zero_mask, 1, "each walk counts independently");
        }
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
        assert!(walk(&buf, &idx).is_err());
    }

    #[test]
    fn truncated_tail_writes_partially_so_callers_must_stage() {
        // Pins the low-level contract that motivates fail-closed
        // staging in production callers: the walker DOES leave
        // matches behind on error, which is exactly why a caller must
        // not point it at an accumulated policy set.
        let sid = well_world_sid();
        let idx = cap_index_for(&sid, "internetClient");
        let mut buf = build_ace(GRANT, &sid);
        buf.extend_from_slice(&[0u8; 6]);

        let (outcome, found, _) = walk_with_zero_mask(&buf, &idx);

        assert!(
            outcome.is_err(),
            "truncated tail must still report an error"
        );
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
        let caps = walk(&buf, &idx).unwrap();
        assert!(caps.contains("internetClient"));
    }

    #[test]
    fn single_trailing_byte_after_valid_ace_is_an_error() {
        let sid = well_world_sid();
        let idx = cap_index_for(&sid, "internetClient");
        let mut buf = build_ace(GRANT, &sid);
        buf.push(0xFF);
        assert!(walk(&buf, &idx).is_err());
    }

    #[test]
    fn malformed_hex_shapes_are_rejected_without_panic() {
        let idx = CapabilityIndex::for_test(&[]);
        for bad in ["ABC", "not-hex", "", "   \n", "AB CD E"] {
            let mut state = AceWalkState::new();
            assert!(
                extract_caps_into(bad, &idx, false, &mut state).is_err(),
                "expected {bad:?} to be rejected"
            );
            assert!(
                state.scratch.is_empty(),
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
        let mut state = AceWalkState::new();

        extract_caps_into(&hex, &idx, false, &mut state).unwrap();
        let after_first = state.scratch.len();
        extract_caps_into(&hex, &idx, false, &mut state).unwrap();

        assert_eq!(
            state.scratch.len(),
            after_first,
            "reused scratch must not accumulate across decodes"
        );
        assert_eq!(state.matches.len(), 1);
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
    fn build_capability_index_derives_real_sids() {
        let index = build_capability_index();

        // Every known name is either resolved or counted as a failure —
        // capabilities must never silently disappear.
        assert_eq!(
            index.resolved_capabilities() + index.derive_failures(),
            KNOWN_CAPABILITIES.len(),
            "every known capability must be either derived or counted as a failure"
        );

        // A stock Windows host resolves at least the common capabilities.
        // If this host resolves none, the diagnostics must say so rather
        // than reporting a clean empty index.
        if index.resolved_capabilities() == 0 {
            assert_eq!(index.derive_failures(), KNOWN_CAPABILITIES.len());
            return;
        }

        for (sid, name, _is_group) in index.iter_sids() {
            assert!(!name.is_empty());
            // Any SID the OS handed back must be structurally valid —
            // this is what proves the copy-out length arithmetic is right.
            assert!(
                sid_to_string(sid).is_some(),
                "derived SID for {name} did not round-trip through ConvertSidToStringSid"
            );
        }
    }

    #[test]
    fn real_derived_sid_resolves_through_the_index() {
        // End-to-end on real OS data: derive a capability SID, build an
        // ACE around it, and confirm the walker recovers the name.
        let index = build_capability_index();
        let Some((sid, name)) = index.iter_sids().next().map(|(s, n, _)| (s.to_vec(), n)) else {
            // Host derived nothing; covered by the assertion above.
            return;
        };

        let mut ace = vec![ACE_TYPE_ACCESS_ALLOWED, 0, 0, 0];
        ace.extend_from_slice(&[0, 0, 0, 0]);
        ace.extend_from_slice(&0x0012_0089u32.to_le_bytes());
        ace.extend_from_slice(&sid);

        let mut found = HashSet::new();
        let mut zero_mask = 0usize;
        walk_aces(&ace, &index, false, &mut found, &mut zero_mask).unwrap();
        assert!(
            found.contains(name),
            "walker did not recover {name} from a real derived SID"
        );
    }

    #[test]
    fn repeated_index_builds_are_stable_and_do_not_leak_handles() {
        // Each build does a LocalAlloc/LocalFree round-trip per name;
        // repeating it must produce identical output.
        let a = build_capability_index();
        let b = build_capability_index();
        assert_eq!(a.resolved_capabilities(), b.resolved_capabilities());
        assert_eq!(a.derive_failures(), b.derive_failures());

        let mut a_pairs: Vec<(Vec<u8>, &str, bool)> =
            a.iter_sids().map(|(s, n, g)| (s.to_vec(), n, g)).collect();
        let mut b_pairs: Vec<(Vec<u8>, &str, bool)> =
            b.iter_sids().map(|(s, n, g)| (s.to_vec(), n, g)).collect();
        a_pairs.sort();
        b_pairs.sort();
        assert_eq!(a_pairs, b_pairs);
    }
}
