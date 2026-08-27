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

mod decimal_u64 {
    use serde::{Deserialize, Deserializer, Serializer};

    #[derive(Deserialize)]
    #[serde(untagged)]
    enum Repr {
        Decimal(String),
        LegacyNumber(u64),
    }

    pub fn serialize<S: Serializer>(value: &u64, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&value.to_string())
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<u64, D::Error> {
        match Repr::deserialize(deserializer)? {
            Repr::Decimal(value) => value.parse().map_err(serde::de::Error::custom),
            Repr::LegacyNumber(value) => Ok(value),
        }
    }
}

/// The kind of resource an access denial was recorded against.
///
/// The variant set is deliberately closed and cross-platform. The
/// Windows decoder classifies ETW events into these buckets; other
/// backends map their native sources onto the same vocabulary.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ResourceType {
    /// Filesystem path (file or directory).
    File,
    /// User-interface resource (clipboard, window handle, input, etc.).
    Ui,
    /// Network endpoint reported by a supported backend source.
    Network,
    /// A named OS capability (AppContainer / brokered capability) the
    /// workload was denied. Capability records may be produced under either
    /// learning mode when the source event contains a decoded identifier.
    Capability,
    /// Unclassified denial (registry, COM, IPC, section object, etc.).
    Other,
}

/// The kind of access that was attempted and denied.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
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

/// Source component that produced an actionable network denial.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum NetworkDenialSource {
    /// Tessera/processmodel schema 0.8 WFP enforcement.
    Tessera,
}

/// Stable policy reason for an actionable network denial.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum NetworkDenialReason {
    /// A direct-egress attempt matched Tessera's default-deny baseline.
    DirectDefaultDeny,
}

/// Direction of a denied network operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum NetworkDirection {
    /// Inbound traffic.
    Inbound,
    /// Outbound traffic.
    Outbound,
    /// Forwarded traffic.
    Forward,
    /// The source supplied an unrecognized direction value.
    Unknown,
}

/// Additional structured data carried by an actionable network denial.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct NetworkDenialDetails {
    /// Enforcement component that produced the denial.
    pub source: NetworkDenialSource,
    /// Stable policy reason assigned by the source adapter.
    pub reason: NetworkDenialReason,
    /// Traffic direction reported by WFP.
    pub direction: NetworkDirection,
    /// IP protocol number when the source supplied one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub protocol: Option<u8>,
    /// Local numeric IP address when available.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub local_address: Option<String>,
    /// Local host-order port when available.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub local_port: Option<u16>,
    /// Remote numeric IP address.
    pub remote_address: String,
    /// Remote host-order port when available.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub remote_port: Option<u16>,
    /// Application identifier supplied by the WFP NetEvent.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub application_id: Option<String>,
    /// Runtime WFP filter identifier used to correlate the event to its live filter.
    #[serde(with = "decimal_u64")]
    pub filter_id: u64,
}

/// Resource-family-specific metadata attached to a denial.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "lowercase")]
pub enum DenialDetails {
    /// Structured WFP network-denial metadata.
    Network(NetworkDenialDetails),
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
///     details: None,
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
    /// the field uniformly. The JSON wire format uses a decimal string so
    /// JavaScript consumers do not lose precision.
    #[serde(with = "decimal_u64")]
    pub filetime: u64,

    /// Optional resource-family-specific metadata. Existing non-network
    /// records omit this field, preserving their JSON shape.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub details: Option<DenialDetails>,
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
            details: None,
        };
        let json = serde_json::to_string(&r).unwrap();
        assert!(json.contains("\"resource\":\"C:"), "got {json}");
        assert!(json.contains("\"resourceType\":\"file\""), "got {json}");
        assert!(json.contains("\"accessType\":\"read\""), "got {json}");
        assert!(
            json.contains("\"filetime\":\"132847890123456789\""),
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
            details: None,
        };
        let json = serde_json::to_string(&r).unwrap();
        let parsed: DeniedResource = serde_json::from_str(&json).unwrap();
        assert_eq!(r, parsed);
    }

    #[test]
    fn denied_resource_accepts_legacy_numeric_filetime() {
        let parsed: DeniedResource = serde_json::from_str(
            r#"{"resource":"C:\\foo","resourceType":"file","accessType":"read","pid":1,"filetime":42}"#,
        )
        .unwrap();
        assert_eq!(parsed.filetime, 42);
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
            details: None,
        };
        assert_eq!(r.dedup_key(), (r"C:\a".to_string(), AccessType::Read));
    }

    #[test]
    fn network_details_are_additive_and_preserve_u64_filter_id() {
        let r = DeniedResource {
            resource: "tcp://203.0.113.10:443".to_string(),
            resource_type: ResourceType::Network,
            access_type: AccessType::Unknown,
            pid: 0,
            filetime: 42,
            details: Some(DenialDetails::Network(NetworkDenialDetails {
                source: NetworkDenialSource::Tessera,
                reason: NetworkDenialReason::DirectDefaultDeny,
                direction: NetworkDirection::Outbound,
                protocol: Some(6),
                local_address: None,
                local_port: None,
                remote_address: "203.0.113.10".to_string(),
                remote_port: Some(443),
                application_id: Some(r"\device\harddiskvolume3\app.exe".to_string()),
                filter_id: u64::MAX,
            })),
        };

        let json = serde_json::to_value(&r).unwrap();
        assert_eq!(json["details"]["kind"], "network");
        assert_eq!(json["details"]["filterId"], u64::MAX.to_string());
        assert_eq!(json["details"]["reason"], "directDefaultDeny");
        assert!(json["details"].get("localAddress").is_none());
        assert_eq!(serde_json::from_value::<DeniedResource>(json).unwrap(), r);
    }
}
