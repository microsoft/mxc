// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! ETW-intermediate denial type for the Windows learning-mode backend.
//!
//! ## What lives here
//!
//! [`DenialEvent`] is the **internal** form produced by the Windows ETW
//! extractors before per-PID dedup. It carries kernel-form path
//! (`\Device\HarddiskVolumeN\...`), the originating ETW event ID, and
//! the AppContainer LowBoxNumber so the extractor side can deduplicate
//! across concurrent sandboxes when the kernel doesn't honor PID filters.
//!
//! ## What used to live here
//!
//! The cross-platform [`DeniedResource`], [`ResourceType`], and
//! [`AccessType`] types moved into the `denial_channel` crate as part of
//! the learning_mode rearchitecture. They are re-exported from
//! `learning_mode_windows`'s root for back-compat.
//!
//! [`DeniedResource`]: denial_channel::DeniedResource
//! [`ResourceType`]: denial_channel::ResourceType
//! [`AccessType`]: denial_channel::AccessType

use serde::{Deserialize, Serialize};

pub use denial_channel::{AccessType, DeniedResource, ResourceType};

/// A structured access denial event captured from ETW.
///
/// Internal form. The public form surfaced over the channel is
/// [`DeniedResource`] (from `denial_channel`), produced via
/// `From<DenialEvent>` / `DenialEvent::into_resource`.
///
/// This type stays in the Windows learning-mode backend rather than
/// the cross-platform `denial_channel` crate because everything it
/// carries (kernel-form `object_name`, ETW `event_id`, AppContainer
/// `container_name`) is Windows-specific. A future Linux backend
/// would have its own equivalent intermediate type and the same
/// `into_resource()` conversion to the shared public shape.
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
    pub filetime: u64,
    /// Originating ETW event ID (4907 = AccessCheckLog, 27 = LearningModeViolation).
    pub event_id: u16,
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

/// Maps an ETW `ObjectType` string to a `denial_channel::ResourceType`.
///
/// Lives here (in the Windows backend's intermediate type module)
/// rather than in `denial_channel` because the mapping is Windows-
/// specific -- ETW's `ObjectType` vocabulary doesn't generalise.
/// A future Linux backend will have its own classifier producing
/// the same `ResourceType` enum from native sources.
///
/// Known mappings (from Vicente's branch):
/// - `"File"` -> `File`
/// - `""` (empty) -> `Network`
/// - anything else -> `Other`
///
/// TODO(ui-denials): the `ResourceType::Ui` variant exists in the wire
/// taxonomy but is intentionally left unmapped here, mirroring `Network`.
/// UI restrictions are enforced via Job Object UI limits
/// (`JOB_OBJECT_UILIMIT_*`) at the Win32k layer, which do not surface
/// through this ETW access-check path. Once a confirmed UI-violation
/// event source is identified, add the mapping (e.g. the relevant
/// `ObjectType` strings, or a dedicated extractor) -> `ResourceType::Ui`.
pub fn resource_type_from_object_type(obj_type: &str) -> ResourceType {
    match obj_type {
        "File" => ResourceType::File,
        "" => ResourceType::Network,
        _ => ResourceType::Other,
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
        assert_eq!(resource_type_from_object_type("File"), ResourceType::File);
        assert_eq!(resource_type_from_object_type(""), ResourceType::Network);
        assert_eq!(resource_type_from_object_type("Key"), ResourceType::Other);
        assert_eq!(
            resource_type_from_object_type("Section"),
            ResourceType::Other
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
