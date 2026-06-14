// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Structured denial event captured from ETW AccessCheckLog events.
//!
//! This is the wire format between the diagnostic service and SDK clients.
//! Events are serialized as newline-delimited JSON over a named pipe.

use serde::{Deserialize, Serialize};

/// The type of resource that was denied access.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ResourceType {
    /// Filesystem path denied.
    File,
    /// Network connection denied.
    Network,
    /// Unclassified denial.
    Other,
}

impl ResourceType {
    /// Maps an ETW ObjectType string to a [`ResourceType`].
    ///
    /// Known mappings:
    /// - `"File"` → [`ResourceType::File`]
    /// - `"Key"` → [`ResourceType::Other`] (registry not actionable via policy)
    /// - Empty string → [`ResourceType::Network`]
    /// - Anything else → [`ResourceType::Other`]
    pub fn from_object_type(obj_type: &str) -> Self {
        match obj_type {
            "File" => Self::File,
            "" => Self::Network,
            _ => Self::Other,
        }
    }
}

/// The type of access that was requested and denied.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AccessType {
    /// Read access.
    Read,
    /// Write access.
    Write,
    /// Execute access.
    Execute,
    /// Unknown or unclassified access type.
    Unknown,
}

/// A structured access denial event captured from ETW.
///
/// Represents a single denied access attempt within a sandboxed container.
/// Serialized as camelCase JSON for transmission over the named pipe.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DenialEvent {
    /// Best-effort AppContainer profile name. May be an empty string when the
    /// profile name cannot be resolved from the ETW event. Consumers must treat
    /// [`DenialEvent::pid`] as the primary correlation key; `container_name` is
    /// only an optional secondary label/filter.
    pub container_name: String,
    /// Process ID that triggered the denial.
    pub pid: u32,
    /// Type of resource that was denied.
    pub resource_type: ResourceType,
    /// Full path/name of the denied resource.
    #[serde(rename = "path")]
    pub object_name: String,
    /// Type of access that was requested.
    #[serde(rename = "accessType")]
    pub access_requested: AccessType,
    /// Timestamp in ISO 8601 format.
    pub timestamp: String,
    /// Original ETW event ID.
    pub event_id: u16,
}

impl DenialEvent {
    /// Creates a new [`DenialEvent`].
    pub fn new(
        container_name: String,
        pid: u32,
        resource_type: ResourceType,
        object_name: String,
        access_requested: AccessType,
        timestamp: String,
        event_id: u16,
    ) -> Self {
        Self {
            container_name,
            pid,
            resource_type,
            object_name,
            access_requested,
            timestamp,
            event_id,
        }
    }

    /// Returns `true` if this event matches the given query filters.
    ///
    /// Matching follows the wire contract where **`pid` is the primary key**:
    /// - If `query.pid` is `Some`, the event's PID must match exactly.
    /// - If `query.container_name` is `Some` **and non-empty**, it must match
    ///   exactly. An empty container-name filter matches all events (the
    ///   producer may emit empty container names — see [`DenialEvent`]).
    /// - The optional `since` filter is applied as a lexicographic comparison
    ///   on the fixed-width ISO 8601 timestamp.
    pub fn matches_query(&self, query: &DenialQuery) -> bool {
        if let Some(pid) = query.pid {
            if self.pid != pid {
                return false;
            }
        }
        if let Some(ref name) = query.container_name {
            if !name.is_empty() && self.container_name != *name {
                return false;
            }
        }
        if let Some(ref since) = query.since {
            // ISO 8601 timestamps in canonical fixed-width form compare
            // correctly as strings.
            if self.timestamp.as_str() < since.as_str() {
                return false;
            }
        }
        true
    }
}

/// The requested mode for a denial pipe request.
///
/// Selects between a one-shot snapshot of buffered events and a live stream.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum RequestMode {
    /// Return all currently buffered matching events, then disconnect.
    Snapshot,
    /// Stream matching events as newline-delimited JSON until disconnect.
    Stream,
}

/// A unified request from an SDK client over the denial pipe.
///
/// This single struct replaces the previous snapshot/subscribe split. The
/// `mode` field selects between snapshot and stream behavior; for backward
/// compatibility a missing `mode` is treated as [`RequestMode::Snapshot`], and
/// a legacy `{"subscribe": true}` is honored as [`RequestMode::Stream`].
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DenialQuery {
    /// Requested mode. `None` is treated as [`RequestMode::Snapshot`] unless the
    /// legacy `subscribe` field selects streaming.
    #[serde(default)]
    pub mode: Option<RequestMode>,
    /// Filter by container name. `None` (or an empty string) matches all
    /// containers.
    #[serde(default)]
    pub container_name: Option<String>,
    /// Filter by process ID — the primary correlation key. `None` matches all
    /// PIDs.
    #[serde(default)]
    pub pid: Option<u32>,
    /// Only return events with a timestamp greater than or equal to this
    /// timestamp. `None` matches all timestamps.
    ///
    /// The value **must** use the fixed-width ISO 8601 form
    /// `YYYY-MM-DDTHH:MM:SSZ` (e.g. `2026-05-23T16:30:01Z`). Comparison is
    /// purely lexicographic, which is only correct for that exact format;
    /// variable-width or fractional-second timestamps are not supported.
    #[serde(default)]
    pub since: Option<String>,
    /// Legacy field: `Some(true)` requests streaming mode. Superseded by
    /// `mode`, retained for backward compatibility.
    #[serde(default)]
    pub subscribe: Option<bool>,
}

impl DenialQuery {
    /// Resolves the effective [`RequestMode`] for this request.
    ///
    /// Precedence: an explicit `mode` wins; otherwise a legacy
    /// `subscribe: true` selects [`RequestMode::Stream`]; otherwise the default
    /// is [`RequestMode::Snapshot`].
    pub fn resolved_mode(&self) -> RequestMode {
        if let Some(mode) = self.mode {
            return mode;
        }
        if self.subscribe == Some(true) {
            return RequestMode::Stream;
        }
        RequestMode::Snapshot
    }
}

/// Response sent back to SDK clients over the named pipe.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DenialResponse {
    /// The denial events matching the query.
    pub events: Vec<DenialEvent>,
    /// Version of the diagnostic service.
    pub service_version: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn serialization_round_trip() {
        let event = DenialEvent::new(
            "test-container".to_string(),
            1234,
            ResourceType::File,
            r"C:\Users\test\file.txt".to_string(),
            AccessType::Read,
            "2026-01-15T10:30:00Z".to_string(),
            4907,
        );

        let json = serde_json::to_string(&event).expect("serialize");
        let deserialized: DenialEvent = serde_json::from_str(&json).expect("deserialize");

        assert_eq!(event, deserialized);
    }

    #[test]
    fn resource_type_from_object_type() {
        assert_eq!(ResourceType::from_object_type("File"), ResourceType::File);
        assert_eq!(ResourceType::from_object_type("Key"), ResourceType::Other);
        assert_eq!(ResourceType::from_object_type(""), ResourceType::Network);
        assert_eq!(
            ResourceType::from_object_type("Something"),
            ResourceType::Other
        );
    }

    /// Test helper to build a [`DenialQuery`] with only the filter fields set.
    fn query(container_name: Option<&str>, pid: Option<u32>, since: Option<&str>) -> DenialQuery {
        DenialQuery {
            mode: None,
            container_name: container_name.map(str::to_string),
            pid,
            since: since.map(str::to_string),
            subscribe: None,
        }
    }

    #[test]
    fn matches_query_filters_correctly() {
        let event = DenialEvent::new(
            "my-container".to_string(),
            42,
            ResourceType::Other,
            r"HKLM\Software\Test".to_string(),
            AccessType::Write,
            "2026-01-15T10:30:00Z".to_string(),
            4907,
        );

        // No filters — matches everything.
        assert!(event.matches_query(&query(None, None, None)));

        // Matching container name.
        assert!(event.matches_query(&query(Some("my-container"), None, None)));

        // Non-matching container name.
        assert!(!event.matches_query(&query(Some("other-container"), None, None)));

        // Empty container name filter matches all.
        assert!(event.matches_query(&query(Some(""), None, None)));

        // Matching PID.
        assert!(event.matches_query(&query(None, Some(42), None)));

        // Non-matching PID.
        assert!(!event.matches_query(&query(None, Some(99), None)));
    }

    #[test]
    fn matches_query_filters_by_since() {
        let event = DenialEvent::new(
            "my-container".to_string(),
            42,
            ResourceType::File,
            r"C:\file.txt".to_string(),
            AccessType::Read,
            "2026-01-15T10:30:00Z".to_string(),
            4907,
        );

        // since before the event timestamp — matches.
        assert!(event.matches_query(&query(None, None, Some("2026-01-15T10:00:00Z"))));

        // since equal to the event timestamp — matches (inclusive).
        assert!(event.matches_query(&query(None, None, Some("2026-01-15T10:30:00Z"))));

        // since after the event timestamp — does not match.
        assert!(!event.matches_query(&query(None, None, Some("2026-01-15T11:00:00Z"))));
    }

    #[test]
    fn resolved_mode_precedence() {
        // Explicit mode wins.
        assert_eq!(
            DenialQuery {
                mode: Some(RequestMode::Stream),
                container_name: None,
                pid: None,
                since: None,
                subscribe: Some(false),
            }
            .resolved_mode(),
            RequestMode::Stream
        );
        // Legacy subscribe selects stream when mode is absent.
        assert_eq!(
            DenialQuery {
                mode: None,
                container_name: None,
                pid: None,
                since: None,
                subscribe: Some(true),
            }
            .resolved_mode(),
            RequestMode::Stream
        );
        // Default is snapshot.
        assert_eq!(
            query(None, None, None).resolved_mode(),
            RequestMode::Snapshot
        );
    }

    #[test]
    fn json_uses_camel_case_field_names() {
        let event = DenialEvent::new(
            "container".to_string(),
            10,
            ResourceType::Network,
            "10.0.0.1:443".to_string(),
            AccessType::Execute,
            "2026-01-15T10:30:00Z".to_string(),
            5000,
        );

        let json = serde_json::to_string(&event).expect("serialize");

        assert!(json.contains("\"containerName\""));
        assert!(json.contains("\"pid\""));
        assert!(json.contains("\"resourceType\""));
        assert!(json.contains("\"path\""));
        assert!(json.contains("\"accessType\""));
        assert!(json.contains("\"timestamp\""));
        assert!(json.contains("\"eventId\""));

        // Verify enum values are lowercase.
        assert!(json.contains("\"network\""));
        assert!(json.contains("\"execute\""));
    }
}
