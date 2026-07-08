// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! ETW event -> `DenialEvent` extractors.
//!
//! Ported from `feature/denied-resource-capture`
//! (`src/mxc_diagnostic_console/src/etw.rs`).
//!
//! The actual ETW consumer (`ProcessTrace` worker thread) lives in the
//! Phase 3 `session` module. These extractors operate on a generic
//! `DecodedEventParts` shape so they can be unit-tested without a live
//! ETW session.

use crate::model::{AccessType, DenialEvent, ResourceType};

/// Pre-decoded event payload.
///
/// The session worker decodes raw `EVENT_RECORD` data into this shape using
/// `TdhGetEventInformation` and friends before handing it to the extractors.
/// The extractors deliberately take only this representation so they can be
/// unit-tested with hand-built fixtures.
#[derive(Debug, Clone)]
pub struct DecodedEventParts {
    /// Originating ETW event ID.
    pub event_id: u16,
    /// `(name, value)` pairs from the decoded payload. Values may be
    /// double-quoted (the ETW TDH layer often emits string values wrapped
    /// in quotes); extractors trim them.
    pub props: Vec<(String, String)>,
}

/// Builds a `DenialEvent` from an `AccessCheckLog` (event 4907) payload.
///
/// Filters to `File` / `Key` resource types - other object types
/// (Section, Process, Thread, ...) are not actionable via sandbox policy
/// and are dropped to avoid noise.
///
/// The `AccessType` is derived from the event's `AccessMask` field (the
/// desired access the caller was denied; see [`access_type_from_mask`]).
/// When the field is absent or unparseable the type falls back to
/// [`AccessType::Unknown`] so a decode gap never drops the denial itself.
pub fn build_denial_from_access_check(
    parts: &DecodedEventParts,
    pid: u32,
    filetime: u64,
) -> Option<DenialEvent> {
    let object_type = find_prop(&parts.props, "ObjectType")?;
    let object_type_str = object_type.trim_matches('"');

    match object_type_str {
        "File" | "Key" => {}
        _ => return None,
    }

    let resource_type = crate::model::resource_type_from_object_type(object_type_str);
    let object_name = find_prop(&parts.props, "ObjectName")
        .map(|v| v.trim_matches('"').to_string())
        .unwrap_or_default();
    let container_name = find_prop(&parts.props, "LowBoxNumber")
        .map(|v| v.trim_matches('"').to_string())
        .unwrap_or_else(|| "unknown".to_string());

    // Registry keys and files share the standard/generic mask bits but
    // assign different meanings to the object-specific low bits, so the
    // classifier needs to know which vocabulary applies.
    let is_registry = object_type_str == "Key";
    let access_type = find_prop(&parts.props, "AccessMask")
        .and_then(|v| parse_access_mask(v))
        .map(|mask| access_type_from_mask(mask, is_registry))
        .unwrap_or(AccessType::Unknown);

    Some(DenialEvent::new(
        container_name,
        pid,
        resource_type,
        object_name,
        access_type,
        filetime,
        parts.event_id,
    ))
}

/// Builds a `DenialEvent` from a `LearningModeViolation` (event 27) payload.
///
/// The LearningModeViolation event payload carries the violated resource
/// directly. Resource type defaults to `Other` because the event doesn't
/// carry an `ObjectType` field - the session layer can refine this based
/// on event-specific metadata in a later iteration.
pub fn build_denial_from_learning_mode(
    parts: &DecodedEventParts,
    pid: u32,
    filetime: u64,
) -> Option<DenialEvent> {
    let object_name = find_prop(&parts.props, "ProcessName")
        .map(|v| v.trim_matches('"').to_string())
        .unwrap_or_default();
    let container_name = find_prop(&parts.props, "LowBoxNumber")
        .map(|v| v.trim_matches('"').to_string())
        .unwrap_or_else(|| "unknown".to_string());

    Some(DenialEvent::new(
        container_name,
        pid,
        ResourceType::Other,
        object_name,
        AccessType::Unknown,
        filetime,
        parts.event_id,
    ))
}

fn find_prop<'a>(props: &'a [(String, String)], name: &str) -> Option<&'a String> {
    props.iter().find(|(k, _)| k == name).map(|(_, v)| v)
}

/// Parses the `AccessMask` property value into a raw 32-bit mask.
///
/// The `AccessCheckLog` template types `AccessMask` as `win:HexInt32`, so
/// the TDH decoder renders it as a `"0x…"` string (e.g. `"0x120089"`). We
/// accept a leading `0x`/`0X` (hex) and, defensively, a bare decimal or
/// bare-hex form in case a future decoder path formats it differently.
/// Returns `None` when the value can't be parsed as a 32-bit integer.
fn parse_access_mask(raw: &str) -> Option<u32> {
    let s = raw.trim().trim_matches('"').trim();
    if let Some(hex) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        return u32::from_str_radix(hex, 16).ok();
    }
    // No explicit prefix: prefer decimal, fall back to hex.
    s.parse::<u32>().ok().or_else(|| u32::from_str_radix(s, 16).ok())
}

/// Classifies a Windows access mask into a single [`AccessType`].
///
/// A mask often requests several rights at once (e.g. `FILE_GENERIC_READ`
/// bundles multiple read bits). Since `AccessType` is single-valued, we
/// return the highest-privilege intent present, in the order
/// **Write → Execute → Read**, so an approval that grants the reported
/// type also covers everything else the caller asked for. Mutating rights
/// that have no dedicated variant (delete, create, take-ownership, change
/// DACL) fold into `Write`. A mask with no recognised right (e.g. only
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
            FILE_READ_DATA
                | FILE_READ_EA
                | FILE_READ_ATTRIBUTES
                | READ_CONTROL
                | GENERIC_READ,
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

    #[test]
    fn access_check_file_denial_extracted() {
        let p = parts(
            4907,
            &[
                ("ObjectType", "\"File\""),
                (
                    "ObjectName",
                    "\"\\Device\\HarddiskVolume3\\Users\\x\\f.txt\"",
                ),
                ("LowBoxNumber", "\"123\""),
                // FILE_GENERIC_READ (0x120089): the classifier should read this.
                ("AccessMask", "0x120089"),
            ],
        );
        let ev = build_denial_from_access_check(&p, 7777, FIXED_FILETIME).expect("should extract");
        assert_eq!(ev.event_id, 4907);
        assert_eq!(ev.pid, 7777);
        assert_eq!(ev.resource_type, ResourceType::File);
        assert_eq!(ev.object_name, r"\Device\HarddiskVolume3\Users\x\f.txt");
        assert_eq!(ev.container_name, "123");
        assert_eq!(ev.filetime, FIXED_FILETIME);
        assert_eq!(ev.access_requested, AccessType::Read);
    }

    #[test]
    fn access_check_missing_mask_defaults_to_unknown_access() {
        let p = parts(
            4907,
            &[("ObjectType", "\"File\""), ("ObjectName", "\"c:\\x\"")],
        );
        let ev = build_denial_from_access_check(&p, 1, FIXED_FILETIME).unwrap();
        assert_eq!(ev.access_requested, AccessType::Unknown);
    }

    #[test]
    fn access_check_write_mask_classified_as_write() {
        let p = parts(
            4907,
            &[
                ("ObjectType", "\"File\""),
                ("ObjectName", "\"c:\\x\""),
                // FILE_GENERIC_WRITE (0x120116).
                ("AccessMask", "0x120116"),
            ],
        );
        let ev = build_denial_from_access_check(&p, 1, FIXED_FILETIME).unwrap();
        assert_eq!(ev.access_requested, AccessType::Write);
    }

    #[test]
    fn access_check_key_denial_extracted_as_other() {
        let p = parts(4907, &[("ObjectType", "\"Key\"")]);
        let ev = build_denial_from_access_check(&p, 1, FIXED_FILETIME).expect("should extract");
        assert_eq!(ev.resource_type, ResourceType::Other);
    }

    #[test]
    fn access_check_unknown_object_type_dropped() {
        let p = parts(4907, &[("ObjectType", "\"Section\"")]);
        assert!(build_denial_from_access_check(&p, 1, FIXED_FILETIME).is_none());
    }

    #[test]
    fn access_check_missing_object_type_dropped() {
        let p = parts(4907, &[("ObjectName", "\"x\"")]);
        assert!(build_denial_from_access_check(&p, 1, FIXED_FILETIME).is_none());
    }

    #[test]
    fn access_check_missing_container_defaults_to_unknown() {
        let p = parts(
            4907,
            &[("ObjectType", "\"File\""), ("ObjectName", "\"c:\\x\"")],
        );
        let ev = build_denial_from_access_check(&p, 1, FIXED_FILETIME).unwrap();
        assert_eq!(ev.container_name, "unknown");
    }

    #[test]
    fn learning_mode_extracted() {
        let p = parts(
            27,
            &[
                ("ProcessName", "\"python.exe\""),
                ("LowBoxNumber", "\"42\""),
            ],
        );
        let ev = build_denial_from_learning_mode(&p, 9999, FIXED_FILETIME).expect("should extract");
        assert_eq!(ev.event_id, 27);
        assert_eq!(ev.pid, 9999);
        assert_eq!(ev.resource_type, ResourceType::Other);
        assert_eq!(ev.object_name, "python.exe");
        assert_eq!(ev.container_name, "42");
        assert_eq!(ev.filetime, FIXED_FILETIME);
    }

    // ---- parse_access_mask ------------------------------------------------

    #[test]
    fn parse_access_mask_reads_hex_prefixed() {
        assert_eq!(parse_access_mask("0x120089"), Some(0x0012_0089));
        assert_eq!(parse_access_mask("0X1"), Some(1));
        // TDH could conceivably wrap or pad the value; be tolerant.
        assert_eq!(parse_access_mask(" \"0x2\" "), Some(2));
    }

    #[test]
    fn parse_access_mask_reads_bare_forms_and_rejects_garbage() {
        // Bare decimal.
        assert_eq!(parse_access_mask("32"), Some(32));
        // Bare hex fallback (no 0x prefix, not valid decimal).
        assert_eq!(parse_access_mask("ff"), Some(0xff));
        assert_eq!(parse_access_mask(""), None);
        assert_eq!(parse_access_mask("<no data>"), None);
        // Larger than u32.
        assert_eq!(parse_access_mask("0x100000000"), None);
    }

    // ---- access_type_from_mask (files) ------------------------------------

    #[test]
    fn file_mask_read_write_execute_priority() {
        // Pure reads.
        assert_eq!(access_type_from_mask(0x0001, false), AccessType::Read); // FILE_READ_DATA
        assert_eq!(access_type_from_mask(0x0012_0089, false), AccessType::Read); // FILE_GENERIC_READ
        // Pure execute / traverse.
        assert_eq!(access_type_from_mask(0x0020, false), AccessType::Execute); // FILE_EXECUTE
        assert_eq!(access_type_from_mask(0x2000_0000, false), AccessType::Execute); // GENERIC_EXECUTE
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
        assert_eq!(access_type_from_mask(0x0010_0000, false), AccessType::Unknown);
        assert_eq!(access_type_from_mask(0x0200_0000, false), AccessType::Unknown);
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
