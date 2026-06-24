// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Public data model for the captureDenials/learning-mode pipeline.
//!
//! `DeniedResource` is the shape every backend emits, every transport
//! carries, and every SDK consumer parses. New OS backends produce
//! it from their native sources; new transports just move it across
//! a channel. The types stay tiny and cross-platform so the wire
//! format never accidentally encodes a Windows assumption.

use serde::{Deserialize, Serialize};

/// The type of resource that was denied access.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ResourceType {
    /// Filesystem path denied.
    File,
    /// Network endpoint denied. Reserved for future network/WFP
    /// capture; not produced by the current Windows file-only
    /// backend.
    Network,
    /// Unclassified denial (registry on Windows, COM, IPC, etc.).
    Other,
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

/// Public denial shape surfaced on the wire and via
/// `ScriptResponse.denied_resources` in the SDK.
///
/// One `DeniedResource` describes one (path, accessType) pair the
/// sandboxed workload was denied access to. Per-PID dedup happens
/// upstream in the writer thread, so callers can treat the stream
/// as already-unique.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DeniedResource {
    /// User-visible canonicalised path. On Windows: drive-letter form
    /// (`C:\Users\...`) with NT-device-namespace prefixes (`\??\`,
    /// `\Device\HarddiskVolumeN\`) already stripped. On Linux/macOS:
    /// the posix path. Network endpoints (when implemented) use a
    /// `host:port` form.
    pub path: String,

    /// Type of resource (see [`ResourceType`]).
    pub resource_type: ResourceType,

    /// Access type the workload was attempting (see [`AccessType`]).
    pub access_type: AccessType,

    /// Process ID inside the sandbox that triggered the denial.
    pub pid: u32,

    /// Kernel timestamp of the denial. On Windows this is `FILETIME`
    /// (100-nanosecond intervals since 1601-01-01 UTC) copied from
    /// `EVENT_RECORD.EventHeader.TimeStamp`. Linux/macOS backends
    /// will normalise their native clocks into the same epoch on
    /// emit so consumers can treat the field uniformly.
    ///
    /// Serialised as a decimal **string** on the wire: FILETIME values
    /// (~1.3e17 today) exceed JavaScript's safe-integer range (2^53-1),
    /// so a JSON number would silently lose precision in JS consumers.
    /// The string form round-trips exactly to a `bigint` in the SDK.
    #[serde(with = "filetime_str")]
    pub filetime: u64,
}

/// Serialises [`DeniedResource::filetime`] as a decimal string and
/// parses it back to `u64`, so cross-language consumers (notably the
/// JS/TypeScript SDK) can round-trip the full 64-bit value without
/// the precision loss a JSON number would incur past 2^53-1.
mod filetime_str {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(value: &u64, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&value.to_string())
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<u64, D::Error> {
        let s = String::deserialize(deserializer)?;
        s.parse::<u64>().map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn denied_resource_serializes_camel_case() {
        // Guards the wire-format contract: SDK consumers depend on
        // `resourceType` / `accessType` / `filetime` keys (camelCase)
        // and the lowercased enum strings. `filetime` is a decimal
        // string (not a JSON number) so 64-bit values round-trip
        // without precision loss in JS. A future serde rename would
        // break every downstream parser silently.
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
            json.contains("\"filetime\":\"132847890123456789\""),
            "got {json}"
        );
    }

    #[test]
    fn denied_resource_round_trips_through_json() {
        let r = DeniedResource {
            path: r"C:\foo\bar.txt".to_string(),
            resource_type: ResourceType::File,
            access_type: AccessType::Write,
            pid: 9999,
            // A value past 2^53 to exercise the decimal-string codec.
            filetime: 132_847_890_123_456_789,
        };
        let json = serde_json::to_string(&r).unwrap();
        let parsed: DeniedResource = serde_json::from_str(&json).unwrap();
        assert_eq!(r, parsed);
    }

    #[test]
    fn resource_type_serialises_each_variant_to_expected_lowercase() {
        assert_eq!(
            serde_json::to_string(&ResourceType::File).unwrap(),
            "\"file\""
        );
        assert_eq!(
            serde_json::to_string(&ResourceType::Network).unwrap(),
            "\"network\""
        );
        assert_eq!(
            serde_json::to_string(&ResourceType::Other).unwrap(),
            "\"other\""
        );
    }

    #[test]
    fn access_type_serialises_each_variant_to_expected_lowercase() {
        assert_eq!(
            serde_json::to_string(&AccessType::Read).unwrap(),
            "\"read\""
        );
        assert_eq!(
            serde_json::to_string(&AccessType::Write).unwrap(),
            "\"write\""
        );
        assert_eq!(
            serde_json::to_string(&AccessType::Execute).unwrap(),
            "\"execute\""
        );
        assert_eq!(
            serde_json::to_string(&AccessType::Unknown).unwrap(),
            "\"unknown\""
        );
    }

    #[test]
    fn access_type_is_hashable_and_copy() {
        // Used as part of the `(path, accessType)` dedup key in
        // the writer thread. Removing Hash or Copy would silently
        // break that path.
        fn assert_hashable<T: std::hash::Hash + Copy>() {}
        assert_hashable::<AccessType>();
    }
}
