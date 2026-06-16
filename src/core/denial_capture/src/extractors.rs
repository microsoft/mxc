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

    let resource_type = ResourceType::from_object_type(object_type_str);
    let object_name = find_prop(&parts.props, "ObjectName")
        .map(|v| v.trim_matches('"').to_string())
        .unwrap_or_default();
    let container_name = find_prop(&parts.props, "LowBoxNumber")
        .map(|v| v.trim_matches('"').to_string())
        .unwrap_or_else(|| "unknown".to_string());

    Some(DenialEvent::new(
        container_name,
        pid,
        resource_type,
        object_name,
        AccessType::Unknown,
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
            ],
        );
        let ev = build_denial_from_access_check(&p, 7777, FIXED_FILETIME).expect("should extract");
        assert_eq!(ev.event_id, 4907);
        assert_eq!(ev.pid, 7777);
        assert_eq!(ev.resource_type, ResourceType::File);
        assert_eq!(ev.object_name, r"\Device\HarddiskVolume3\Users\x\f.txt");
        assert_eq!(ev.container_name, "123");
        assert_eq!(ev.filetime, FIXED_FILETIME);
    }

    #[test]
    fn access_check_key_denial_extracted_as_other() {
        let p = parts(
            4907,
            &[
                ("ObjectType", "\"Key\""),
                ("ObjectName", "\"\\Registry\\Machine\\SOFTWARE\\Foo\""),
            ],
        );
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
}
