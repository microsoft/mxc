// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Public data model for the captureDenials / learning-mode pipeline.
//!
//! [`DeniedResource`] is the shape every backend decoder emits, every
//! transport carries, and every SDK consumer parses. New OS backends
//! produce it from their native sources (Windows ETW today; Linux/macOS
//! later); the JSON output file (see [`crate::emit`]) is just an array of
//! these records plus a trailing [`crate::summary::DenialSummary`].
//!
//! The types stay tiny and cross-platform so the wire format never
//! accidentally encodes a Windows-only assumption. The Windows ETL
//! decoder lives in the `learning_mode_windows` backend crate and maps
//! its ETW-intermediate events into these types.

use serde::{Deserialize, Serialize};

/// The kind of resource an access denial was recorded against.
///
/// The variant set is deliberately closed and cross-platform. The
/// Windows decoder classifies ETW events into these buckets; other
/// backends map their native sources onto the same vocabulary.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ResourceType {
    /// Filesystem path (file or directory).
    File,
    /// User-interface resource (clipboard, window handle, input, etc.).
    Ui,
    /// Network endpoint. Reserved for future network/WFP capture; the
    /// current Windows backend does not yet produce this variant.
    Network,
    /// A named OS capability (AppContainer / brokered capability) the
    /// workload was denied. Only produced under permissive learning
    /// mode today — see the mode caveat in the crate docs.
    Capability,
    /// Unclassified denial (registry, COM, IPC, section object, etc.).
    Other,
}

/// The kind of access that was attempted and denied.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AccessType {
    /// Read / query access.
    Read,
    /// Write / create / modify / delete access.
    Write,
    /// Execute / traverse access.
    Execute,
    /// Access kind could not be determined from the source event.
    Unknown,
}

/// One denied `(resource, accessType)` observation surfaced to consumers.
///
/// A `DeniedResource` describes a single resource the sandboxed workload
/// was denied access to. Per-`(resource, accessType)` de-duplication happens
/// in the decoder, so consumers can treat the emitted stream as already
/// unique.
///
/// # Examples
///
/// ```
/// use learning_mode_core::{AccessType, DeniedResource, ResourceType};
///
/// let denial = DeniedResource {
///     resource: r"C:\Users\test\secret.txt".to_string(),
///     resource_type: ResourceType::File,
///     access_type: AccessType::Read,
///     pid: 1234,
///     filetime: 132_847_890_123_456_789,
/// };
/// let json = serde_json::to_string(&denial)?;
/// assert!(json.contains("\"resourceType\":\"file\""));
/// # Ok::<(), serde_json::Error>(())
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DeniedResource {
    /// User-visible identifier for the denied resource, interpreted per
    /// [`resource_type`](Self::resource_type):
    /// - [`File`](ResourceType::File): canonicalised drive-letter path
    ///   (`C:\Users\...`) with NT-device-namespace prefixes (`\??\`,
    ///   `\Device\HarddiskVolumeN\`) already stripped by the decoder.
    /// - [`Capability`](ResourceType::Capability): the AppContainer
    ///   capability name (e.g. `internetClient`), resolved from the
    ///   capability SID; unresolved custom capabilities fall back to the
    ///   `S-1-15-3-…` SID string.
    /// - [`Network`](ResourceType::Network) (when implemented): `host:port`.
    /// - [`Ui`](ResourceType::Ui) / [`Other`](ResourceType::Other): the raw
    ///   resource identifier the source event carried (may be empty).
    pub resource: String,

    /// Type of resource (see [`ResourceType`]).
    pub resource_type: ResourceType,

    /// Access type the workload was attempting (see [`AccessType`]).
    pub access_type: AccessType,

    /// Process ID inside the sandbox that triggered the denial.
    pub pid: u32,

    /// Kernel timestamp of the denial. On Windows this is `FILETIME`
    /// (100-nanosecond intervals since 1601-01-01 UTC), copied from
    /// `EVENT_RECORD.EventHeader.TimeStamp`. Other backends normalise
    /// their native clocks onto the same epoch so consumers can treat
    /// the field uniformly.
    pub filetime: u64,
}

/// De-duplication key for a denial: the `(resource, accessType)` pair.
///
/// Decoders collapse the many raw kernel access-check events a workload
/// generates (locale code re-reading the same key on every `printf`,
/// etc.) down to one record per unique pair.
pub type DedupKey = (String, AccessType);

impl DeniedResource {
    /// Returns the `(resource, accessType)` de-duplication key for this
    /// denial. Cloning the resource is intentional so the key can outlive a
    /// borrow of `self` while a decoder accumulates into a set.
    #[must_use]
    pub fn dedup_key(&self) -> DedupKey {
        (self.resource.clone(), self.access_type)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn denied_resource_serialises_camel_case() {
        // Guards the wire-format contract: SDK consumers depend on the
        // camelCase keys and lowercased enum strings. A future serde
        // rename would silently break every downstream parser.
        let r = DeniedResource {
            resource: r"C:\Users\test\file.txt".to_string(),
            resource_type: ResourceType::File,
            access_type: AccessType::Read,
            pid: 1234,
            filetime: 132_847_890_123_456_789,
        };
        let json = serde_json::to_string(&r).unwrap();
        assert!(json.contains("\"resource\":\"C:"), "got {json}");
        assert!(json.contains("\"resourceType\":\"file\""), "got {json}");
        assert!(json.contains("\"accessType\":\"read\""), "got {json}");
        assert!(
            json.contains("\"filetime\":132847890123456789"),
            "got {json}"
        );
    }

    #[test]
    fn denied_resource_round_trips_through_json() {
        let r = DeniedResource {
            resource: r"C:\foo\bar.txt".to_string(),
            resource_type: ResourceType::Capability,
            access_type: AccessType::Write,
            pid: 9999,
            filetime: 42,
        };
        let json = serde_json::to_string(&r).unwrap();
        let parsed: DeniedResource = serde_json::from_str(&json).unwrap();
        assert_eq!(r, parsed);
    }

    #[test]
    fn resource_type_serialises_each_variant_to_lowercase() {
        for (variant, expected) in [
            (ResourceType::File, "\"file\""),
            (ResourceType::Ui, "\"ui\""),
            (ResourceType::Network, "\"network\""),
            (ResourceType::Capability, "\"capability\""),
            (ResourceType::Other, "\"other\""),
        ] {
            assert_eq!(serde_json::to_string(&variant).unwrap(), expected);
        }
    }

    #[test]
    fn access_type_serialises_each_variant_to_lowercase() {
        for (variant, expected) in [
            (AccessType::Read, "\"read\""),
            (AccessType::Write, "\"write\""),
            (AccessType::Execute, "\"execute\""),
            (AccessType::Unknown, "\"unknown\""),
        ] {
            assert_eq!(serde_json::to_string(&variant).unwrap(), expected);
        }
    }

    #[test]
    fn dedup_key_pairs_path_and_access_type() {
        let r = DeniedResource {
            resource: r"C:\a".to_string(),
            resource_type: ResourceType::File,
            access_type: AccessType::Read,
            pid: 1,
            filetime: 1,
        };
        assert_eq!(r.dedup_key(), (r"C:\a".to_string(), AccessType::Read));
    }
}
