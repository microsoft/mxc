// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Capability recovery from permissive Event 14 DACL data.
//!
//! Some permissive capability events leave `ObjectName` empty and expose the
//! requested capability only through a hex-encoded list of ACEs. This module
//! matches those ACE SIDs against a catalog derived with
//! `DeriveCapabilitySidsFromName`.

use std::collections::{HashMap, HashSet};
use std::sync::OnceLock;

use learning_mode_core::{AccessType, ResourceType};
use windows::core::PWSTR;
use windows::Win32::Foundation::{LocalFree, HLOCAL};
use windows::Win32::Security::{DeriveCapabilitySidsFromName, GetLengthSid, PSID};

use crate::extractors::{
    DecodedEventParts, RawDenial, ACCESS_CHECK_EVENT_ID, KERNEL_GENERAL_PROVIDER,
    PRIVACY_ACCESS_CHECK_EVENT_ID, PRIVACY_LEARNING_MODE_PROVIDER,
};

const ACE_TYPE_ACCESS_ALLOWED: u8 = 0;
const ACE_TYPE_ACCESS_ALLOWED_CALLBACK: u8 = 9;
const ACE_TYPE_OFFSET: usize = 0;
#[cfg(test)]
const ACE_FLAGS_SIZE: usize = 4;
const STANDARD_ACE_SIZE_OFFSET: usize = 2;
const STANDARD_ACE_ACCESS_MASK_OFFSET: usize = 4;
const STANDARD_ACE_HEADER_SIZE: usize = 8;
const LEGACY_ACE_ACCESS_MASK_OFFSET: usize = 8;
const LEGACY_ACE_HEADER_SIZE: usize = 12;
const SID_FIXED_HEADER_SIZE: usize = 8;
const SID_SUB_AUTHORITY_SIZE: usize = 4;
const MAX_DACL_HEX_CHARS: usize = 256 * 1024;

const KNOWN_CAPABILITIES: &[&str] = &[
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
    // `userPrincipalName` is intentionally excluded because LSASS can
    // generate it during token plumbing for workloads that never request it.
    "backgroundMediaPlayback",
    "codeGeneration",
    "allowElevation",
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
    "graphicsCapture",
    "graphicsCaptureProgrammatic",
    "graphicsCaptureWithoutBorder",
    "screenDuplication",
    "appCaptureServices",
    "appCaptureSettings",
    "backgroundMediaRecording",
    "backgroundSpatialPerception",
    "backgroundVoIP",
    "extendedBackgroundTaskTime",
    "extendedExecutionBackgroundAudio",
    "extendedExecutionCritical",
    "extendedExecutionUnconstrained",
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

// ID_CAP_LOCATION predates the manifest capability named `location` and has
// fixed app/group SIDs that DeriveCapabilitySidsFromName does not reproduce.
const LEGACY_CAPABILITY_SIDS: &[(&str, &str)] = &[
    (
        "location",
        "S-1-15-3-1024-2158456844-3754929254-744589270-3611187126-2481208986-30837703-3416168463-2437063433",
    ),
    (
        "location",
        "S-1-5-32-2158456844-3754929254-744589270-3611187126-2481208986-30837703-3416168463-2437063433",
    ),
];

#[derive(Debug, thiserror::Error)]
enum DaclDecodeError {
    #[error("DACL property is not valid hexadecimal")]
    InvalidHex,
    #[error("DACL property exceeds the {MAX_DACL_HEX_CHARS}-character decode limit")]
    InputTooLarge,
    #[error("DACL ACE at offset {0} is truncated")]
    TruncatedAce(usize),
    #[error("DACL contains an unsupported callback ACE at offset {0}")]
    CallbackAce(usize),
}

struct CapabilityIndex {
    by_sid: HashMap<Vec<u8>, &'static str>,
    by_sid_string: HashMap<String, &'static str>,
}

impl CapabilityIndex {
    fn with_capacity(capacity: usize) -> Self {
        Self {
            by_sid: HashMap::with_capacity(capacity),
            by_sid_string: HashMap::with_capacity(capacity),
        }
    }

    fn insert(&mut self, sid: Vec<u8>, name: &'static str, overwrite: bool) {
        let sid_string = format_sid(&sid);
        if overwrite {
            self.by_sid.insert(sid, name);
            if let Some(sid_string) = sid_string {
                self.by_sid_string.insert(sid_string, name);
            }
        } else {
            self.by_sid.entry(sid).or_insert(name);
            if let Some(sid_string) = sid_string {
                self.by_sid_string.entry(sid_string).or_insert(name);
            }
        }
    }

    fn resolve(&self, sid: &[u8]) -> Option<&'static str> {
        self.by_sid.get(sid).copied()
    }

    fn resolve_string(&self, sid: &str) -> Option<&'static str> {
        self.by_sid_string.get(sid).copied()
    }

    #[cfg(test)]
    fn for_test(entries: &[(&'static str, &[u8])]) -> Self {
        let mut index = Self::with_capacity(entries.len());
        for &(name, sid) in entries {
            index.insert(sid.to_vec(), name, true);
        }
        index
    }
}

static CAPABILITY_INDEX: OnceLock<CapabilityIndex> = OnceLock::new();

pub(crate) fn extract_denials(
    parts: &DecodedEventParts,
    pid: u32,
    filetime: u64,
) -> Vec<RawDenial> {
    let is_supported_event = (parts.provider == KERNEL_GENERAL_PROVIDER
        && parts.event_id == ACCESS_CHECK_EVENT_ID)
        || (parts.provider == PRIVACY_LEARNING_MODE_PROVIDER
            && matches!(
                parts.event_id,
                ACCESS_CHECK_EVENT_ID | PRIVACY_ACCESS_CHECK_EVENT_ID
            ));
    if !is_supported_event {
        return Vec::new();
    }

    let names = extract_names(parts, CAPABILITY_INDEX.get_or_init(build_capability_index));
    names
        .into_iter()
        .map(|name| RawDenial {
            pid,
            resource_type: ResourceType::Capability,
            object_name: name.to_string(),
            access_type: AccessType::Unknown,
            filetime,
            event_id: parts.event_id,
        })
        .collect()
}

fn extract_names<'a>(parts: &DecodedEventParts, index: &'a CapabilityIndex) -> HashSet<&'a str> {
    let mut names = extract_flattened_dacl_names(parts, index);
    let mut explicit: Vec<&str> = parts
        .props
        .iter()
        .filter(|(name, _)| is_dacl_property(name))
        .filter_map(|(_, value)| value.strip_prefix("hex:"))
        .collect();
    if let Some(value) = parts
        .props
        .iter()
        .filter(|(name, _)| name.eq_ignore_ascii_case("ComplexData"))
        .nth(4)
        .and_then(|(_, value)| value.strip_prefix("hex:"))
    {
        explicit.push(value);
    }

    let unidentified_capability =
        property_is_empty(parts, "ObjectType") && property_is_empty(parts, "ObjectName");
    let candidates: Vec<&str> = if explicit.is_empty() && unidentified_capability {
        parts
            .props
            .iter()
            .filter(|(name, _)| name.eq_ignore_ascii_case("ComplexData"))
            .filter_map(|(_, value)| value.strip_prefix("hex:"))
            .collect()
    } else {
        explicit
    };

    for candidate in candidates {
        let Ok(decoded) = decode_hex(candidate) else {
            continue;
        };
        let Ok(found) = walk_aces(&decoded, index) else {
            continue;
        };
        names.extend(found);
    }
    names
}

fn extract_flattened_dacl_names<'a>(
    parts: &DecodedEventParts,
    index: &'a CapabilityIndex,
) -> HashSet<&'a str> {
    let mut names = HashSet::new();
    let mut in_dacl = false;
    let mut ace_type = None;
    let mut access_mask = None;

    for (property, value) in &parts.props {
        if property.eq_ignore_ascii_case("DaclAce") {
            in_dacl = true;
            ace_type = None;
            access_mask = None;
            continue;
        }
        if !in_dacl {
            continue;
        }
        if property.eq_ignore_ascii_case("SaclRevision") || property.eq_ignore_ascii_case("SaclAce")
        {
            break;
        }

        if property.eq_ignore_ascii_case("AceType") {
            ace_type = parse_u32(value);
        } else if property.eq_ignore_ascii_case("AccessMask") {
            access_mask = parse_u32(value);
        } else if property.eq_ignore_ascii_case("Sid") {
            if ace_type == Some(ACE_TYPE_ACCESS_ALLOWED as u32)
                && access_mask.is_some_and(|mask| mask != 0)
            {
                if let Some(name) = index.resolve_string(value.trim_matches('"')) {
                    names.insert(name);
                }
            }
            ace_type = None;
            access_mask = None;
        }
    }
    names
}

fn property_is_empty(parts: &DecodedEventParts, property: &str) -> bool {
    parts
        .props
        .iter()
        .find(|(name, _)| name.eq_ignore_ascii_case(property))
        .is_some_and(|(_, value)| value.trim_matches('"').is_empty())
}

fn is_dacl_property(name: &str) -> bool {
    contains_ascii_case_insensitive(name, "dacl")
        || contains_ascii_case_insensitive(name, "securitydescriptor")
        || contains_ascii_case_insensitive(name, "security_descriptor")
        || contains_ascii_case_insensitive(name, "ace")
}

fn contains_ascii_case_insensitive(value: &str, needle: &str) -> bool {
    value
        .as_bytes()
        .windows(needle.len())
        .any(|window| window.eq_ignore_ascii_case(needle.as_bytes()))
}

fn decode_hex(value: &str) -> Result<Vec<u8>, DaclDecodeError> {
    if value.len() > MAX_DACL_HEX_CHARS {
        return Err(DaclDecodeError::InputTooLarge);
    }
    let mut bytes = Vec::with_capacity(value.len() / 2);
    let mut high = None;
    for byte in value.bytes().filter(|byte| !byte.is_ascii_whitespace()) {
        let nibble = match byte {
            b'0'..=b'9' => byte - b'0',
            b'a'..=b'f' => byte - b'a' + 10,
            b'A'..=b'F' => byte - b'A' + 10,
            _ => return Err(DaclDecodeError::InvalidHex),
        };
        match high.take() {
            Some(high) => bytes.push((high << 4) | nibble),
            None => high = Some(nibble),
        }
    }
    if high.is_some() || bytes.is_empty() {
        return Err(DaclDecodeError::InvalidHex);
    }
    Ok(bytes)
}

fn parse_u32(value: &str) -> Option<u32> {
    let value = value.trim().trim_matches('"');
    value
        .strip_prefix("0x")
        .or_else(|| value.strip_prefix("0X"))
        .and_then(|hex| u32::from_str_radix(hex, 16).ok())
        .or_else(|| value.parse().ok())
}

fn format_sid(bytes: &[u8]) -> Option<String> {
    if bytes.len() < SID_FIXED_HEADER_SIZE || bytes[0] != 1 {
        return None;
    }
    let sub_authority_count = bytes[1] as usize;
    let expected = SID_FIXED_HEADER_SIZE + SID_SUB_AUTHORITY_SIZE * sub_authority_count;
    if bytes.len() != expected {
        return None;
    }
    let authority = bytes[2..8]
        .iter()
        .fold(0u64, |value, byte| (value << 8) | u64::from(*byte));
    let mut sid = format!("S-1-{authority}");
    for chunk in bytes[8..].chunks_exact(4) {
        let sub_authority = u32::from_le_bytes(chunk.try_into().ok()?);
        sid.push('-');
        sid.push_str(&sub_authority.to_string());
    }
    Some(sid)
}

fn parse_sid(value: &str) -> Option<Vec<u8>> {
    let mut parts = value.split('-');
    if parts.next()? != "S" {
        return None;
    }
    let revision: u8 = parts.next()?.parse().ok()?;
    if revision != 1 {
        return None;
    }
    let authority: u64 = parts.next()?.parse().ok()?;
    if authority > 0x0000_ffff_ffff_ffff {
        return None;
    }
    let sub_authorities: Vec<u32> = parts.map(str::parse).collect::<Result<_, _>>().ok()?;
    let count: u8 = sub_authorities.len().try_into().ok()?;

    let mut bytes =
        Vec::with_capacity(SID_FIXED_HEADER_SIZE + SID_SUB_AUTHORITY_SIZE * count as usize);
    bytes.push(revision);
    bytes.push(count);
    bytes.extend_from_slice(&authority.to_be_bytes()[2..]);
    for sub_authority in sub_authorities {
        bytes.extend_from_slice(&sub_authority.to_le_bytes());
    }
    Some(bytes)
}

fn walk_aces<'a>(
    bytes: &[u8],
    index: &'a CapabilityIndex,
) -> Result<HashSet<&'a str>, DaclDecodeError> {
    let mut names = HashSet::new();
    let mut cursor = 0;
    while cursor < bytes.len() {
        if bytes.len() - cursor < STANDARD_ACE_HEADER_SIZE + SID_FIXED_HEADER_SIZE {
            return Err(DaclDecodeError::TruncatedAce(cursor));
        }
        let ace_type = bytes[cursor + ACE_TYPE_OFFSET];
        if ace_type == ACE_TYPE_ACCESS_ALLOWED_CALLBACK {
            return Err(DaclDecodeError::CallbackAce(cursor));
        }

        // EvtRender historically exposed this provider's ComplexData in a
        // DWORD-padded shape. TDH may expose the native ACCESS_ALLOWED_ACE
        // shape, so accept both and prefer the self-framing native form.
        let declared_ace_size =
            u16::from_le_bytes([bytes[cursor + STANDARD_ACE_SIZE_OFFSET], bytes[cursor + 3]])
                as usize;
        let (mask_offset, sid_offset, declared_end) = if declared_ace_size == 0 {
            (
                cursor + LEGACY_ACE_ACCESS_MASK_OFFSET,
                cursor + LEGACY_ACE_HEADER_SIZE,
                None,
            )
        } else {
            let end = cursor
                .checked_add(declared_ace_size)
                .filter(|end| {
                    *end <= bytes.len()
                        && declared_ace_size >= STANDARD_ACE_HEADER_SIZE + SID_FIXED_HEADER_SIZE
                })
                .ok_or(DaclDecodeError::TruncatedAce(cursor))?;
            (
                cursor + STANDARD_ACE_ACCESS_MASK_OFFSET,
                cursor + STANDARD_ACE_HEADER_SIZE,
                Some(end),
            )
        };
        let mask = u32::from_le_bytes(
            bytes[mask_offset..mask_offset + 4]
                .try_into()
                .map_err(|_| DaclDecodeError::TruncatedAce(cursor))?,
        );
        let sub_authorities = bytes[sid_offset + 1] as usize;
        let sid_size = SID_FIXED_HEADER_SIZE + SID_SUB_AUTHORITY_SIZE * sub_authorities;
        let sid_end = sid_offset
            .checked_add(sid_size)
            .filter(|next| *next <= bytes.len())
            .ok_or(DaclDecodeError::TruncatedAce(cursor))?;
        let next = match declared_end {
            Some(end) if sid_end <= end => end,
            Some(_) => return Err(DaclDecodeError::TruncatedAce(cursor)),
            None => sid_end,
        };

        if ace_type == ACE_TYPE_ACCESS_ALLOWED && mask != 0 {
            if let Some(name) = index.resolve(&bytes[sid_offset..sid_end]) {
                names.insert(name);
            }
        }
        cursor = next;
    }
    Ok(names)
}

fn build_capability_index() -> CapabilityIndex {
    let mut index =
        CapabilityIndex::with_capacity(KNOWN_CAPABILITIES.len() * 2 + LEGACY_CAPABILITY_SIDS.len());
    for &name in KNOWN_CAPABILITIES {
        let wide: Vec<u16> = name.encode_utf16().chain(std::iter::once(0)).collect();
        let mut group_sids: *mut PSID = std::ptr::null_mut();
        let mut group_count = 0;
        let mut capability_sids: *mut PSID = std::ptr::null_mut();
        let mut capability_count = 0;

        let result = unsafe {
            DeriveCapabilitySidsFromName(
                PWSTR(wide.as_ptr().cast_mut()),
                &mut group_sids,
                &mut group_count,
                &mut capability_sids,
                &mut capability_count,
            )
        };
        if result.is_ok() {
            if let Some(sid) = unsafe { first_sid(capability_sids, capability_count) } {
                index.insert(sid, name, true);
            }
            if let Some(sid) = unsafe { first_sid(group_sids, group_count) } {
                index.insert(sid, name, false);
            }
        }

        unsafe {
            free_sid_array(capability_sids, capability_count);
            free_sid_array(group_sids, group_count);
        }
    }
    for &(name, sid) in LEGACY_CAPABILITY_SIDS {
        if let Some(sid) = parse_sid(sid) {
            index.insert(sid, name, true);
        }
    }
    index
}

unsafe fn first_sid(array: *const PSID, count: u32) -> Option<Vec<u8>> {
    if array.is_null() || count == 0 {
        return None;
    }
    let sid = unsafe { *array };
    if sid.0.is_null() {
        return None;
    }
    let length = unsafe { GetLengthSid(sid) };
    if length == 0 {
        return None;
    }
    let bytes = unsafe { std::slice::from_raw_parts(sid.0.cast::<u8>(), length as usize) };
    Some(bytes.to_vec())
}

unsafe fn free_sid_array(array: *mut PSID, count: u32) {
    if array.is_null() {
        return;
    }
    for index in 0..count as isize {
        let sid = unsafe { *array.offset(index) };
        if !sid.0.is_null() {
            let _ = unsafe { LocalFree(Some(HLOCAL(sid.0))) };
        }
    }
    let _ = unsafe { LocalFree(Some(HLOCAL(array.cast()))) };
}

#[cfg(test)]
mod tests {
    use super::*;
    use windows::core::GUID;

    fn sid() -> Vec<u8> {
        vec![1, 1, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0]
    }

    fn internet_client_sid() -> Vec<u8> {
        vec![
            1, 2, 0, 0, 0, 0, 0, 15, // revision, count, authority
            3, 0, 0, 0, // capability domain
            1, 0, 0, 0, // internetClient RID
        ]
    }

    fn legacy_ace(mask: u32, sid: &[u8]) -> Vec<u8> {
        let mut bytes = vec![ACE_TYPE_ACCESS_ALLOWED, 0, 0, 0];
        bytes.extend_from_slice(&[0; ACE_FLAGS_SIZE]);
        bytes.extend_from_slice(&mask.to_le_bytes());
        bytes.extend_from_slice(sid);
        bytes
    }

    fn standard_ace(mask: u32, sid: &[u8]) -> Vec<u8> {
        let size = (STANDARD_ACE_HEADER_SIZE + sid.len()) as u16;
        let mut bytes = vec![ACE_TYPE_ACCESS_ALLOWED, 0];
        bytes.extend_from_slice(&size.to_le_bytes());
        bytes.extend_from_slice(&mask.to_le_bytes());
        bytes.extend_from_slice(sid);
        bytes
    }

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|byte| format!("{byte:02X}")).collect()
    }

    fn parts(name: &str, value: String) -> DecodedEventParts {
        DecodedEventParts {
            provider: PRIVACY_LEARNING_MODE_PROVIDER,
            event_id: ACCESS_CHECK_EVENT_ID,
            props: vec![
                ("ObjectType".to_string(), "\"\"".to_string()),
                ("ObjectName".to_string(), "\"\"".to_string()),
                (name.to_string(), format!("hex:{value}")),
            ],
        }
    }

    #[test]
    fn extracts_capability_from_named_dacl_property() {
        let sid = sid();
        let index = CapabilityIndex::for_test(&[("internetClient", &sid)]);
        let names = extract_names(&parts("Dacl", hex(&legacy_ace(1, &sid))), &index);
        assert_eq!(names, HashSet::from(["internetClient"]));
    }

    #[test]
    fn accepts_native_access_allowed_ace_layout() {
        let sid = sid();
        let index = CapabilityIndex::for_test(&[("internetClient", &sid)]);
        let names = extract_names(&parts("Dacl", hex(&standard_ace(1, &sid))), &index);
        assert_eq!(names, HashSet::from(["internetClient"]));
    }

    #[test]
    fn extracts_capability_from_tdh_flattened_dacl() {
        let sid = sid();
        let index = CapabilityIndex::for_test(&[("internetClient", &sid)]);
        let mut event = parts("DaclAce", "<struct>".to_string());
        event.props.extend([
            ("AceType".to_string(), "0".to_string()),
            ("AceFlags".to_string(), "0x0".to_string()),
            ("AccessMask".to_string(), "0x1".to_string()),
            ("Sid".to_string(), "S-1-1-0".to_string()),
            ("SaclRevision".to_string(), "0".to_string()),
        ]);
        let names = extract_names(&event, &index);
        assert_eq!(names, HashSet::from(["internetClient"]));
    }

    #[test]
    fn ignores_token_capability_sid_outside_dacl() {
        let sid = sid();
        let index = CapabilityIndex::for_test(&[("internetClient", &sid)]);
        let mut event = parts("TokenCapabilities", "<struct>".to_string());
        event
            .props
            .push(("CapabilitySid".to_string(), "S-1-1-0".to_string()));
        assert!(extract_names(&event, &index).is_empty());
    }

    #[test]
    fn unidentified_capability_falls_back_to_unnamed_binary_property() {
        let sid = sid();
        let index = CapabilityIndex::for_test(&[("internetClient", &sid)]);
        let names = extract_names(&parts("ComplexData", hex(&legacy_ace(1, &sid))), &index);
        assert_eq!(names, HashSet::from(["internetClient"]));
    }

    #[test]
    fn unidentified_capability_does_not_scan_unrelated_binary_property() {
        let sid = sid();
        let index = CapabilityIndex::for_test(&[("internetClient", &sid)]);
        let names = extract_names(&parts("Payload", hex(&legacy_ace(1, &sid))), &index);
        assert!(names.is_empty());
    }

    #[test]
    fn named_file_event_does_not_scan_unrelated_binary_property() {
        let sid = sid();
        let index = CapabilityIndex::for_test(&[("internetClient", &sid)]);
        let mut event = parts("ComplexData", hex(&legacy_ace(1, &sid)));
        event.props[0].1 = "\"File\"".to_string();
        event.props[1].1 = "\"C:\\data\\file.txt\"".to_string();
        assert!(extract_names(&event, &index).is_empty());
    }

    #[test]
    fn file_event_reads_fifth_complex_data_property_like_legacy_parser() {
        let sid = sid();
        let index = CapabilityIndex::for_test(&[("internetClient", &sid)]);
        let mut event = parts("ComplexData", "00".to_string());
        event.props[0].1 = "\"File\"".to_string();
        event.props[1].1 = "\"C:\\data\\file.txt\"".to_string();
        for _ in 0..3 {
            event
                .props
                .push(("ComplexData".to_string(), "hex:00".to_string()));
        }
        event.props.push((
            "ComplexData".to_string(),
            format!("hex:{}", hex(&legacy_ace(1, &sid))),
        ));
        let names = extract_names(&event, &index);
        assert_eq!(names, HashSet::from(["internetClient"]));
    }

    #[test]
    fn rejects_zero_mask_and_malformed_ace_data() {
        let sid = sid();
        let index = CapabilityIndex::for_test(&[("internetClient", &sid)]);
        assert!(extract_names(&parts("Dacl", hex(&legacy_ace(0, &sid))), &index).is_empty());
        assert!(extract_names(&parts("Dacl", "00".to_string()), &index).is_empty());
    }

    #[test]
    fn rejects_oversized_dacl_property_before_decoding() {
        let value = "00".repeat(MAX_DACL_HEX_CHARS / 2 + 1);
        assert!(matches!(
            decode_hex(&value),
            Err(DaclDecodeError::InputTooLarge)
        ));
    }

    #[test]
    fn dacl_property_matching_is_ascii_case_insensitive() {
        assert!(is_dacl_property("Security_DESCRIPTOR"));
        assert!(is_dacl_property("dAcLaCe"));
        assert!(!is_dacl_property("Payload"));
    }

    #[test]
    fn ignores_non_permissive_provider() {
        let event = DecodedEventParts {
            provider: GUID::zeroed(),
            event_id: ACCESS_CHECK_EVENT_ID,
            props: Vec::new(),
        };
        assert!(extract_denials(&event, 1, 2).is_empty());
    }

    #[test]
    fn production_index_recovers_empty_object_name_capability() {
        let sid = internet_client_sid();
        let event = parts("Dacl", hex(&legacy_ace(1, &sid)));
        let denials = extract_denials(&event, 5900, 42);
        assert_eq!(denials.len(), 1);
        assert_eq!(denials[0].resource_type, ResourceType::Capability);
        assert_eq!(denials[0].object_name, "internetClient");
        assert_eq!(denials[0].pid, 5900);
    }

    #[test]
    fn kernel_general_event_recovers_legacy_location_capability() {
        let mut event = parts("DaclAce", "<struct>".to_string());
        event.provider = KERNEL_GENERAL_PROVIDER;
        event.props.extend([
            ("AceType".to_string(), "0".to_string()),
            ("AceFlags".to_string(), "0x0".to_string()),
            ("AccessMask".to_string(), "0x20a10".to_string()),
            ("Sid".to_string(), LEGACY_CAPABILITY_SIDS[0].1.to_string()),
            ("SaclRevision".to_string(), "0".to_string()),
        ]);

        let denials = extract_denials(&event, 1264, 42);
        assert_eq!(denials.len(), 1);
        assert_eq!(denials[0].resource_type, ResourceType::Capability);
        assert_eq!(denials[0].object_name, "location");
    }

    #[test]
    fn formats_sid_bytes_for_flattened_lookup() {
        assert_eq!(
            format_sid(&internet_client_sid()).as_deref(),
            Some("S-1-15-3-1")
        );
        assert!(format_sid(&[1, 2, 0]).is_none());
    }

    #[test]
    fn resolves_legacy_location_sid() {
        let index = build_capability_index();
        let sid = LEGACY_CAPABILITY_SIDS[0].1;
        assert_eq!(index.resolve_string(sid), Some("location"));
        assert_eq!(
            parse_sid(sid).and_then(|sid| index.resolve(&sid)),
            Some("location")
        );
    }
}
