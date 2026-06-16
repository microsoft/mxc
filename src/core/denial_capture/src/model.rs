// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Public + internal data model for denial capture.
//!
//! - `DenialEvent` is the **internal** form produced by the ETW extractors.
//!   It carries the kernel-form path (`\Device\HarddiskVolumeN\…`) and ETW
//!   metadata such as the originating event ID.
//! - `DeniedResource` is the **public** form the SDK surfaces to callers.
//!   It carries the user-visible drive-letter path and stripped-down fields.
//!
//! Ported from `feature/denied-resource-capture`
//! (`src/mxc_diagnostic_console/src/denial_event.rs`) and slimmed down: the
//! cross-process `DenialQuery` / `DenialResponse` types are removed because
//! the scoped-session design captures in-process and surfaces via
//! `ScriptResponse` rather than over a named pipe.

use serde::{Deserialize, Serialize};

/// The type of resource that was denied access.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ResourceType {
    /// Filesystem path denied.
    File,
    /// Network endpoint denied.
    Network,
    /// Unclassified denial (registry, COM, etc.).
    Other,
}

impl ResourceType {
    /// Maps an ETW `ObjectType` string to a `ResourceType`.
    ///
    /// Known mappings (from Vicente's branch):
    /// - `"File"` -> `File`
    /// - `""` (empty) -> `Network`
    /// - anything else -> `Other`
    pub fn from_object_type(obj_type: &str) -> Self {
        match obj_type {
            "File" => Self::File,
            "" => Self::Network,
            _ => Self::Other,
        }
    }
}

/// The type of access that was requested and denied.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AccessType {
    Read,
    Write,
    Execute,
    Unknown,
}

/// A structured access denial event captured from ETW.
///
/// Internal form. The public form surfaced to the SDK is `DeniedResource`,
/// produced via `From<DenialEvent>`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DenialEvent {
    /// AppContainer LowBoxNumber (kernel form). Used for dedup across
    /// concurrent sandboxes when the kernel doesn't honor PID filters.
    pub container_name: String,
    /// Process ID that triggered the denial.
    pub pid: u32,
    /// Type of resource that was denied.
    pub resource_type: ResourceType,
    /// Kernel-form path / object name (e.g. `\Device\HarddiskVolume3\Users\...`).
    pub object_name: String,
    /// Access type the workload was attempting.
    pub access_requested: AccessType,
    /// Kernel FILETIME copied from `EVENT_RECORD.EventHeader.TimeStamp`:
    /// 100-nanosecond intervals since 1601-01-01 UTC.
    ///
    /// Stored as `u64` rather than a formatted string to (1) skip a
    /// time-crate dependency, (2) avoid losing precision in transit,
    /// (3) defer all locale/format choices to the SDK consumer. The
    /// SDK side can convert to a JS `Date` via the standard
    /// `(filetime / 10000) - 11644473600000` formula. Values exceed
    /// `Number.MAX_SAFE_INTEGER` (~9e15) by roughly 15× as of 2026,
    /// so consumers that need sub-microsecond precision should
    /// deserialize as a string or BigInt; ordering at microsecond
    /// granularity round-trips through a JS double fine.
    pub filetime: u64,
    /// Originating ETW event ID (4907 = AccessCheckLog, 27 = LearningModeViolation).
    pub event_id: u16,
}

/// Public denial shape surfaced via `ScriptResponse.denied_resources`.
///
/// Compared to `DenialEvent` we:
/// - canonicalize the path (drive-letter form);
/// - drop ETW-specific fields the SDK doesn't need (`event_id`,
///   `container_name`);
/// - keep `pid` so a caller can correlate denials with the workload's
///   own process tree if it spawned helpers.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DeniedResource {
    /// User-visible canonicalized path (drive-letter form) for files, host
    /// for network, etc.
    pub path: String,
    /// Type of resource.
    pub resource_type: ResourceType,
    /// Access type the workload was attempting.
    pub access_type: AccessType,
    /// Process ID that triggered the denial.
    pub pid: u32,
    /// Kernel FILETIME of the denial (100ns intervals since 1601-01-01 UTC).
    /// See `DenialEvent::filetime` for SDK-side conversion notes.
    pub filetime: u64,
}

impl DenialEvent {
    /// Constructs an event with the given fields.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        container_name: String,
        pid: u32,
        resource_type: ResourceType,
        object_name: String,
        access_requested: AccessType,
        filetime: u64,
        event_id: u16,
    ) -> Self {
        Self {
            container_name,
            pid,
            resource_type,
            object_name,
            access_requested,
            filetime,
            event_id,
        }
    }

    /// Converts this event into the public `DeniedResource` shape.
    ///
    /// On Windows the path is canonicalized from kernel form to drive-letter
    /// form via `path_norm::to_user_visible`. On other platforms (or when
    /// canonicalization fails) the kernel form is preserved as-is.
    pub fn into_resource(self) -> DeniedResource {
        #[cfg(target_os = "windows")]
        let path = crate::path_norm::to_user_visible(&self.object_name)
            .unwrap_or_else(|| self.object_name.clone());

        #[cfg(not(target_os = "windows"))]
        let path = self.object_name.clone();

        DeniedResource {
            path,
            resource_type: self.resource_type,
            access_type: self.access_requested,
            pid: self.pid,
            filetime: self.filetime,
        }
    }
}

impl From<DenialEvent> for DeniedResource {
    fn from(ev: DenialEvent) -> Self {
        ev.into_resource()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn denial_event_serde_round_trip() {
        let event = DenialEvent::new(
            "test-container".to_string(),
            1234,
            ResourceType::File,
            r"\Device\HarddiskVolume3\Users\test\file.txt".to_string(),
            AccessType::Read,
            132_847_890_123_456_789,
            4907,
        );

        let json = serde_json::to_string(&event).expect("serialize");
        let parsed: DenialEvent = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(event, parsed);
    }

    #[test]
    fn resource_type_from_object_type_known_values() {
        assert_eq!(ResourceType::from_object_type("File"), ResourceType::File);
        assert_eq!(ResourceType::from_object_type(""), ResourceType::Network);
        assert_eq!(ResourceType::from_object_type("Key"), ResourceType::Other);
        assert_eq!(
            ResourceType::from_object_type("Section"),
            ResourceType::Other
        );
    }

    #[test]
    fn denied_resource_serializes_camel_case() {
        let r = DeniedResource {
            path: r"C:\Users\test\file.txt".to_string(),
            resource_type: ResourceType::File,
            access_type: AccessType::Read,
            pid: 1234,
            filetime: 132_847_890_123_456_789,
        };
        let json = serde_json::to_string(&r).unwrap();
        assert!(json.contains("\"resourceType\":\"file\""), "got {json}");
        assert!(json.contains("\"accessType\":\"read\""), "got {json}");
        assert!(
            json.contains("\"filetime\":132847890123456789"),
            "got {json}"
        );
    }

    #[test]
    fn denial_event_to_denied_resource_preserves_fields() {
        let event = DenialEvent::new(
            "lb-123".to_string(),
            4321,
            ResourceType::File,
            r"\Device\HarddiskVolumeFake999\not\a\real\path".to_string(),
            AccessType::Write,
            999_888_777,
            4907,
        );

        let resource: DeniedResource = event.clone().into();
        assert_eq!(resource.pid, 4321);
        assert_eq!(resource.resource_type, ResourceType::File);
        assert_eq!(resource.access_type, AccessType::Write);
        assert_eq!(resource.filetime, 999_888_777);
        assert!(!resource.path.is_empty());
    }
}
