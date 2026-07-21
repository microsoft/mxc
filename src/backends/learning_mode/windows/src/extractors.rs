// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! ETW event -> [`RawDenial`] extractors.
//!
//! These operate on the generic [`DecodedEventParts`] shape produced by
//! [`crate::tdh_decode`], so they can be unit-tested with hand-built
//! fixtures without a live/sealed ETW trace. A [`RawDenial`] still carries
//! the *kernel-form* object path; [`crate::etl_decode`] path-normalises and
//! de-duplicates them into the public
//! [`learning_mode_core::DeniedResource`].
//!
//! ## Event vocabulary
//!
//! The learning-mode ETL carries a set of event IDs that map onto the
//! resource types we surface. This list grows as more denial sources are
//! decoded; unknown event IDs are discarded. The IDs handled today:
//!
//! - **14 / 4907 — access check** — the primary denial event
//!   (`ObjectType` / `ObjectName` / `AccessMask`). `ObjectType` selects the
//!   resource type: `File` → [`ResourceType::File`], `Key` →
//!   [`ResourceType::Other`] (registry), and an **empty** `ObjectType` is a
//!   brokered-capability check → [`ResourceType::Capability`]. Any other
//!   object type (Section, Process, Thread, ...) is dropped (not actionable
//!   via sandbox policy). The [`AccessType`] is derived from the
//!   `AccessMask` field (see [`access_type_from_mask`]). Emitted under both
//!   learning modes (`block-and-log` → `Mode="Normal"`, `allow-and-log` →
//!   `Mode="Permissive"`).
//! - **27 — `LearningModeViolation`** — UI-surface denials →
//!   [`ResourceType::Ui`]. Carries no usable access mask, so the access type
//!   stays [`AccessType::Unknown`].
//! - **28 — capability denial** — a compact capability-access-manager
//!   record (`Denied` / `PackageSid` / `ProcessId`), emitted under
//!   `block-and-log`; `allow-and-log` folds the same information into the
//!   empty-`ObjectType` event 14 above. Mapped to [`ResourceType::Capability`].
//!   The capability *name* is carried in the `PackageSid` blob and is not
//!   yet decoded, so the resource path is left empty for now (see the crate
//!   mode caveat).

use learning_mode_core::{AccessType, ResourceType};

/// Pre-decoded event payload handed to the extractors.
///
/// The trace consumer decodes each raw `EVENT_RECORD` into this shape via
/// [`crate::tdh_decode::decode_event_parts`] before routing it here. The
/// extractors take only this representation so they stay unit-testable.
#[derive(Debug, Clone)]
pub struct DecodedEventParts {
    /// Originating ETW event ID.
    pub event_id: u16,
    /// `(name, value)` pairs from the decoded payload. String values are
    /// often TDH-quoted; extractors trim the surrounding quotes.
    pub props: Vec<(String, String)>,
}

/// A denial extracted from one ETW event, before path normalisation and
/// de-duplication.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RawDenial {
    /// Process ID that triggered the denial.
    pub pid: u32,
    /// Classified resource type.
    pub resource_type: ResourceType,
    /// Object name in kernel form (e.g. `\Device\HarddiskVolumeN\...`) or,
    /// for non-file resources, the raw identifier the event carried. Empty
    /// when the event carries no resolvable name (e.g. a capability denial
    /// whose name is still encoded in an undecoded SID blob).
    pub object_name: String,
    /// Access the workload was attempting.
    pub access_type: AccessType,
    /// Kernel `FILETIME` of the event.
    pub filetime: u64,
    /// Originating ETW event ID (kept for diagnostics).
    pub event_id: u16,
}

/// Routes a decoded event to the matching extractor by its event ID.
///
/// Returns `None` for events that are not learning-mode denials or that
/// carry an object type we don't surface.
pub fn extract_denial(parts: &DecodedEventParts, pid: u32, filetime: u64) -> Option<RawDenial> {
    match parts.event_id {
        14 | 4907 => build_denial_from_access_check(parts, pid, filetime),
        27 => build_denial_from_learning_mode(parts, pid, filetime),
        28 => build_denial_from_capability(parts, pid, filetime),
        _ => None,
    }
}

/// Builds a [`RawDenial`] from an access-check (event 14 / 4907) payload.
///
/// The `ObjectType` field selects the resource type: `File` and `Key`
/// (registry) map to concrete resources, an **empty** `ObjectType` is a
/// brokered-capability check, and any other object type (Section, Process,
/// Thread, ...) is dropped as not actionable via sandbox policy. An absent
/// `ObjectType` field drops the event.
///
/// For file/registry resources the [`AccessType`] is derived from the
/// event's `AccessMask` field (the desired access the caller was denied;
/// see [`access_type_from_mask`]); when the field is absent or unparseable
/// the type falls back to [`AccessType::Unknown`] so a decode gap never
/// drops the denial itself. Capability checks carry a mask that is not a
/// read/write/execute verb, so their access type is left `Unknown`.
pub fn build_denial_from_access_check(
    parts: &DecodedEventParts,
    pid: u32,
    filetime: u64,
) -> Option<RawDenial> {
    let object_type = find_prop(&parts.props, "ObjectType")?;
    let object_type_str = object_type.trim_matches('"');

    let resource_type = match object_type_str {
        "File" => ResourceType::File,
        "Key" => ResourceType::Other,
        // A present-but-empty object type is a brokered-capability check.
        "" => ResourceType::Capability,
        _ => return None,
    };

    let object_name = find_prop(&parts.props, "ObjectName")
        .map(|v| v.trim_matches('"').to_string())
        .unwrap_or_default();

    let access_type = if resource_type == ResourceType::Capability {
        // Capability checks report a mask (often 0x1) that is not a
        // read/write/execute verb, so don't run the file/registry
        // classifier over it.
        AccessType::Unknown
    } else {
        // Registry keys and files share the standard/generic mask bits but
        // assign different meanings to the object-specific low bits, so the
        // classifier needs to know which vocabulary applies.
        let is_registry = object_type_str == "Key";
        find_prop(&parts.props, "AccessMask")
            .and_then(|v| parse_u32(v))
            .map(|mask| access_type_from_mask(mask, is_registry))
            .unwrap_or(AccessType::Unknown)
    };

    Some(RawDenial {
        pid,
        resource_type,
        object_name,
        access_type,
        filetime,
        event_id: parts.event_id,
    })
}

/// Builds a [`RawDenial`] from a `LearningModeViolation` (event 27) payload.
///
/// These represent UI-surface denials; the resource identifier is taken
/// from the first UI-ish field present. The event carries no usable access
/// mask, so the access type stays [`AccessType::Unknown`].
pub fn build_denial_from_learning_mode(
    parts: &DecodedEventParts,
    pid: u32,
    filetime: u64,
) -> Option<RawDenial> {
    let object_name = find_prop(&parts.props, "ObjectName")
        .or_else(|| find_prop(&parts.props, "ResourceName"))
        .or_else(|| find_prop(&parts.props, "ProcessName"))
        .map(|v| v.trim_matches('"').to_string())
        .unwrap_or_default();

    Some(RawDenial {
        pid,
        resource_type: ResourceType::Ui,
        object_name,
        access_type: AccessType::Unknown,
        filetime,
        event_id: parts.event_id,
    })
}

/// Builds a [`RawDenial`] from a capability-denial (event 28) payload.
///
/// Emitted under `block-and-log`. The record reports a `Denied` boolean; we
/// only surface actual denials. The originating process is taken from the
/// payload `ProcessId` (which is more precise than the ETW header pid for
/// brokered checks) when present, else the header pid. The capability name
/// is carried in the `PackageSid` blob and is not yet decoded, so the
/// resource name is left empty for now.
pub fn build_denial_from_capability(
    parts: &DecodedEventParts,
    pid: u32,
    filetime: u64,
) -> Option<RawDenial> {
    // If the record explicitly reports the check as not-denied, skip it;
    // absence of the field is treated as a denial (fail open on decode gap).
    if let Some(denied) = find_prop(&parts.props, "Denied") {
        if !denied.trim_matches('"').eq_ignore_ascii_case("true") {
            return None;
        }
    }

    let pid = find_prop(&parts.props, "ProcessId")
        .and_then(|v| parse_u32(v))
        .unwrap_or(pid);

    // Prefer a decoded capability name if a future decoder surfaces one;
    // otherwise leave the name empty until the PackageSid blob is decoded.
    let object_name = find_prop(&parts.props, "CapabilityName")
        .or_else(|| find_prop(&parts.props, "Capability"))
        .map(|v| v.trim_matches('"').to_string())
        .unwrap_or_default();

    Some(RawDenial {
        pid,
        resource_type: ResourceType::Capability,
        object_name,
        access_type: AccessType::Unknown,
        filetime,
        event_id: parts.event_id,
    })
}

/// Parses a `"0x…"` / decimal / bare-hex property value into a `u32`.
///
/// The `AccessMask` and `ProcessId` templates render as `win:HexInt32`, so
/// the TDH decoder emits a `"0x…"` string (e.g. `"0x120089"`, `"0x1acc"`).
/// We accept a leading `0x`/`0X` (hex) and, defensively, a bare decimal or
/// bare-hex form in case a future decoder path formats it differently.
/// Returns `None` when the value can't be parsed as a 32-bit integer.
fn parse_u32(raw: &str) -> Option<u32> {
    let s = raw.trim().trim_matches('"').trim();
    if let Some(hex) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        return u32::from_str_radix(hex, 16).ok();
    }
    // No explicit prefix: prefer decimal, fall back to hex.
    s.parse::<u32>()
        .ok()
        .or_else(|| u32::from_str_radix(s, 16).ok())
}

/// Classifies a Windows access mask into a single [`AccessType`].
///
/// A mask often requests several rights at once (e.g. `FILE_GENERIC_READ`
/// bundles multiple read bits). Since `AccessType` is single-valued, we
/// return the highest-privilege intent present, in the order
/// **Write → Execute → Read**, so an approval that grants the reported type
/// also covers everything else the caller asked for. Mutating rights that
/// have no dedicated variant (delete, create, take-ownership, change DACL)
/// fold into `Write`. A mask with no recognised right (e.g. only
/// `SYNCHRONIZE` or `MAXIMUM_ALLOWED`) yields [`AccessType::Unknown`].
///
/// `is_registry` selects the object-specific low-bit vocabulary: files and
/// registry keys share the standard/generic bits but disagree on bits like
/// `0x10` (`FILE_WRITE_EA` vs `KEY_NOTIFY`) and `0x20` (`FILE_EXECUTE` vs
/// `KEY_CREATE_LINK`).
fn access_type_from_mask(mask: u32, is_registry: bool) -> AccessType {
    // Standard rights (object-type independent).
    const DELETE: u32 = 0x0001_0000;
    const READ_CONTROL: u32 = 0x0002_0000;
    const WRITE_DAC: u32 = 0x0004_0000;
    const WRITE_OWNER: u32 = 0x0008_0000;
    // Generic rights (object-type independent).
    const GENERIC_READ: u32 = 0x8000_0000;
    const GENERIC_WRITE: u32 = 0x4000_0000;
    const GENERIC_EXECUTE: u32 = 0x2000_0000;
    const GENERIC_ALL: u32 = 0x1000_0000;

    let standard_write = DELETE | WRITE_DAC | WRITE_OWNER;

    let (read_bits, write_bits, execute_bits) = if is_registry {
        // Registry key-specific rights (winnt.h KEY_*).
        const KEY_QUERY_VALUE: u32 = 0x0001;
        const KEY_SET_VALUE: u32 = 0x0002;
        const KEY_CREATE_SUB_KEY: u32 = 0x0004;
        const KEY_ENUMERATE_SUB_KEYS: u32 = 0x0008;
        const KEY_NOTIFY: u32 = 0x0010;
        const KEY_CREATE_LINK: u32 = 0x0020;
        (
            KEY_QUERY_VALUE | KEY_ENUMERATE_SUB_KEYS | KEY_NOTIFY | READ_CONTROL | GENERIC_READ,
            KEY_SET_VALUE
                | KEY_CREATE_SUB_KEY
                | KEY_CREATE_LINK
                | standard_write
                | GENERIC_WRITE
                | GENERIC_ALL,
            // Registry has no execute concept (KEY_EXECUTE aliases KEY_READ).
            GENERIC_EXECUTE,
        )
    } else {
        // File/directory-specific rights (winnt.h FILE_*).
        const FILE_READ_DATA: u32 = 0x0001; // a.k.a. FILE_LIST_DIRECTORY
        const FILE_WRITE_DATA: u32 = 0x0002; // a.k.a. FILE_ADD_FILE
        const FILE_APPEND_DATA: u32 = 0x0004; // a.k.a. FILE_ADD_SUBDIRECTORY
        const FILE_READ_EA: u32 = 0x0008;
        const FILE_WRITE_EA: u32 = 0x0010;
        const FILE_EXECUTE: u32 = 0x0020; // a.k.a. FILE_TRAVERSE
        const FILE_READ_ATTRIBUTES: u32 = 0x0080;
        const FILE_WRITE_ATTRIBUTES: u32 = 0x0100;
        (
            FILE_READ_DATA | FILE_READ_EA | FILE_READ_ATTRIBUTES | READ_CONTROL | GENERIC_READ,
            FILE_WRITE_DATA
                | FILE_APPEND_DATA
                | FILE_WRITE_EA
                | FILE_WRITE_ATTRIBUTES
                | standard_write
                | GENERIC_WRITE
                | GENERIC_ALL,
            FILE_EXECUTE | GENERIC_EXECUTE,
        )
    };

    if mask & write_bits != 0 {
        AccessType::Write
    } else if mask & execute_bits != 0 {
        AccessType::Execute
    } else if mask & read_bits != 0 {
        AccessType::Read
    } else {
        AccessType::Unknown
    }
}

fn find_prop<'a>(props: &'a [(String, String)], name: &str) -> Option<&'a String> {
    props.iter().find(|(k, _)| k == name).map(|(_, v)| v)
}

#[cfg(test)]
mod tests {
    use super::*;

    const FIXED_FILETIME: u64 = 132_847_890_123_456_789;

    fn parts(event_id: u16, kv: &[(&str, &str)]) -> DecodedEventParts {
        DecodedEventParts {
            event_id,
            props: kv
                .iter()
                .map(|(k, v)| ((*k).to_string(), (*v).to_string()))
                .collect(),
        }
    }

    // ---- event 14 / 4907 access check -------------------------------------

    #[test]
    fn access_check_file_denial_read_mask() {
        let p = parts(
            14,
            &[
                ("Mode", "\"Normal\""),
                ("ObjectType", "\"File\""),
                (
                    "ObjectName",
                    "\"\\Device\\HarddiskVolume3\\Users\\x\\f.txt\"",
                ),
                // FILE_GENERIC_READ (0x120089).
                ("AccessMask", "0x120089"),
            ],
        );
        let ev = extract_denial(&p, 7777, FIXED_FILETIME).expect("should extract");
        assert_eq!(ev.event_id, 14);
        assert_eq!(ev.pid, 7777);
        assert_eq!(ev.resource_type, ResourceType::File);
        assert_eq!(ev.object_name, r"\Device\HarddiskVolume3\Users\x\f.txt");
        assert_eq!(ev.access_type, AccessType::Read);
        assert_eq!(ev.filetime, FIXED_FILETIME);
    }

    #[test]
    fn access_check_event_4907_still_routed() {
        let p = parts(
            4907,
            &[
                ("ObjectType", "\"File\""),
                ("ObjectName", "\"c:\\x\""),
                ("AccessMask", "0x1"),
            ],
        );
        let ev = extract_denial(&p, 1, FIXED_FILETIME).expect("should extract");
        assert_eq!(ev.resource_type, ResourceType::File);
        assert_eq!(ev.access_type, AccessType::Read);
    }

    #[test]
    fn access_check_write_mask_classified_write() {
        let p = parts(
            14,
            &[
                ("ObjectType", "\"File\""),
                ("ObjectName", "\"c:\\x\""),
                // DELETE | FILE_READ_DATA (0x10001) — write wins.
                ("AccessMask", "0x10001"),
            ],
        );
        let ev = extract_denial(&p, 1, FIXED_FILETIME).unwrap();
        assert_eq!(ev.access_type, AccessType::Write);
    }

    #[test]
    fn access_check_key_denial_uses_registry_vocabulary() {
        let p = parts(
            14,
            &[
                ("ObjectType", "\"Key\""),
                ("ObjectName", "\"\\REGISTRY\\USER\\.DEFAULT\\Console\""),
                // KEY_READ (0x20019): READ_CONTROL | KEY_QUERY_VALUE |
                // KEY_ENUMERATE_SUB_KEYS | KEY_NOTIFY -> Read.
                ("AccessMask", "0x20019"),
            ],
        );
        let ev = extract_denial(&p, 1, FIXED_FILETIME).expect("should extract");
        assert_eq!(ev.resource_type, ResourceType::Other);
        assert_eq!(ev.access_type, AccessType::Read);
    }

    #[test]
    fn access_check_empty_object_type_is_capability() {
        // Permissive-mode capability check: present-but-empty ObjectType,
        // empty ObjectName, mask 0x1 (not a file read verb here).
        let p = parts(
            14,
            &[
                ("Mode", "\"Permissive\""),
                ("ObjectType", "\"\""),
                ("ObjectName", "\"\""),
                ("AccessMask", "0x1"),
            ],
        );
        let ev = extract_denial(&p, 5900, FIXED_FILETIME).expect("should extract");
        assert_eq!(ev.resource_type, ResourceType::Capability);
        assert_eq!(ev.access_type, AccessType::Unknown);
        assert_eq!(ev.object_name, "");
    }

    #[test]
    fn access_check_missing_mask_defaults_to_unknown() {
        let p = parts(
            4907,
            &[("ObjectType", "\"File\""), ("ObjectName", "\"c:\\x\"")],
        );
        let ev = extract_denial(&p, 1, FIXED_FILETIME).unwrap();
        assert_eq!(ev.access_type, AccessType::Unknown);
    }

    #[test]
    fn access_check_unknown_object_type_dropped() {
        let p = parts(14, &[("ObjectType", "\"Section\"")]);
        assert!(extract_denial(&p, 1, FIXED_FILETIME).is_none());
    }

    #[test]
    fn access_check_absent_object_type_dropped() {
        let p = parts(14, &[("ObjectName", "\"x\"")]);
        assert!(extract_denial(&p, 1, FIXED_FILETIME).is_none());
    }

    // ---- event 27 UI ------------------------------------------------------

    #[test]
    fn learning_mode_violation_extracted_as_ui() {
        let p = parts(27, &[("ObjectName", "\"Clipboard\"")]);
        let ev = extract_denial(&p, 9999, FIXED_FILETIME).expect("should extract");
        assert_eq!(ev.event_id, 27);
        assert_eq!(ev.resource_type, ResourceType::Ui);
        assert_eq!(ev.access_type, AccessType::Unknown);
        assert_eq!(ev.object_name, "Clipboard");
    }

    // ---- event 28 capability denial ---------------------------------------

    #[test]
    fn capability_denial_event_28_extracted() {
        // Real block-and-log shape: image name + hex ProcessId + Denied.
        let p = parts(
            28,
            &[
                ("ProcessName", "\"conhost.exe\""),
                ("ProcessId", "0x1acc"),
                ("Category", "1"),
                ("Denied", "true"),
            ],
        );
        let ev = extract_denial(&p, 42, FIXED_FILETIME).expect("should extract");
        assert_eq!(ev.resource_type, ResourceType::Capability);
        assert_eq!(ev.access_type, AccessType::Unknown);
        // pid comes from the payload ProcessId (0x1acc), not the header.
        assert_eq!(ev.pid, 0x1acc);
        assert_eq!(ev.object_name, "");
    }

    #[test]
    fn capability_denial_not_denied_is_dropped() {
        let p = parts(28, &[("ProcessId", "0x10"), ("Denied", "false")]);
        assert!(extract_denial(&p, 1, FIXED_FILETIME).is_none());
    }

    #[test]
    fn capability_denial_falls_back_to_header_pid() {
        let p = parts(28, &[("Denied", "true")]);
        let ev = extract_denial(&p, 555, FIXED_FILETIME).unwrap();
        assert_eq!(ev.pid, 555);
    }

    #[test]
    fn unrelated_event_ignored() {
        let p = parts(9999, &[("Foo", "\"bar\"")]);
        assert!(extract_denial(&p, 1, FIXED_FILETIME).is_none());
    }

    // ---- parse_u32 --------------------------------------------------------

    #[test]
    fn parse_u32_reads_hex_prefixed() {
        assert_eq!(parse_u32("0x120089"), Some(0x0012_0089));
        assert_eq!(parse_u32("0X1"), Some(1));
        assert_eq!(parse_u32("0x1acc"), Some(0x1acc));
        // TDH could conceivably wrap or pad the value; be tolerant.
        assert_eq!(parse_u32(" \"0x2\" "), Some(2));
    }

    #[test]
    fn parse_u32_reads_bare_forms_and_rejects_garbage() {
        assert_eq!(parse_u32("32"), Some(32));
        // Bare hex fallback (no 0x prefix, not valid decimal).
        assert_eq!(parse_u32("ff"), Some(0xff));
        assert_eq!(parse_u32(""), None);
        assert_eq!(parse_u32("<no data>"), None);
        // Larger than u32.
        assert_eq!(parse_u32("0x100000000"), None);
    }

    // ---- access_type_from_mask (files) ------------------------------------

    #[test]
    fn file_mask_read_write_execute_priority() {
        // Pure reads.
        assert_eq!(access_type_from_mask(0x0001, false), AccessType::Read); // FILE_READ_DATA
        assert_eq!(access_type_from_mask(0x0012_0089, false), AccessType::Read); // FILE_GENERIC_READ
                                                                                 // Pure execute / traverse.
        assert_eq!(access_type_from_mask(0x0020, false), AccessType::Execute); // FILE_EXECUTE
        assert_eq!(
            access_type_from_mask(0x2000_0000, false),
            AccessType::Execute
        ); // GENERIC_EXECUTE
           // Writes (incl. delete / take-ownership fold into Write).
        assert_eq!(access_type_from_mask(0x0002, false), AccessType::Write); // FILE_WRITE_DATA
        assert_eq!(access_type_from_mask(0x0001_0000, false), AccessType::Write); // DELETE
        assert_eq!(access_type_from_mask(0x4000_0000, false), AccessType::Write); // GENERIC_WRITE
        assert_eq!(access_type_from_mask(0x1000_0000, false), AccessType::Write); // GENERIC_ALL
                                                                                  // Priority: write beats execute beats read when several are set.
        assert_eq!(
            access_type_from_mask(0x0001 | 0x0020 | 0x0002, false),
            AccessType::Write
        );
        assert_eq!(
            access_type_from_mask(0x0001 | 0x0020, false),
            AccessType::Execute
        );
    }

    #[test]
    fn file_mask_no_recognised_right_is_unknown() {
        // SYNCHRONIZE (0x100000) alone and MAXIMUM_ALLOWED (0x02000000) alone.
        assert_eq!(
            access_type_from_mask(0x0010_0000, false),
            AccessType::Unknown
        );
        assert_eq!(
            access_type_from_mask(0x0200_0000, false),
            AccessType::Unknown
        );
        assert_eq!(access_type_from_mask(0, false), AccessType::Unknown);
    }

    // ---- access_type_from_mask (registry) ---------------------------------

    #[test]
    fn key_mask_uses_registry_vocabulary() {
        // KEY_QUERY_VALUE / ENUMERATE / NOTIFY are reads.
        assert_eq!(access_type_from_mask(0x0001, true), AccessType::Read); // KEY_QUERY_VALUE
        assert_eq!(access_type_from_mask(0x0010, true), AccessType::Read); // KEY_NOTIFY (write for files!)
                                                                           // KEY_SET_VALUE / CREATE_SUB_KEY / CREATE_LINK are writes.
        assert_eq!(access_type_from_mask(0x0002, true), AccessType::Write); // KEY_SET_VALUE
        assert_eq!(access_type_from_mask(0x0020, true), AccessType::Write); // KEY_CREATE_LINK (execute for files!)
                                                                            // Registry has no execute concept: 0x20 is a write here, not execute.
        assert_ne!(access_type_from_mask(0x0020, true), AccessType::Execute);
    }
}
