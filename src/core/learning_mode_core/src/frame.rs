// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! The self-describing wire records that make up a captureDenials output
//! stream.
//!
//! A captureDenials output file is a sequence of JSON records, each
//! tagged with a `type` discriminator so a consumer can dispatch without
//! positional assumptions:
//!
//! ```text
//! {"type":"denial","path":"...","resourceType":"file","accessType":"read","pid":123,"filetime":...}
//! {"type":"denial", ...}
//! {"type":"summary","exitCode":0,"totalDenials":2,"deniedResourcesTruncated":false}
//! ```
//!
//! [`DenialFrame`] is an internally-tagged enum over the two record
//! kinds, so `serde` handles the `type` field and consumers get an
//! exhaustive match. The framing bytes (RFC 7464 record separators) are
//! added by [`crate::emit`]; this module only defines the JSON objects.

use serde::{Deserialize, Serialize};

use crate::model::DeniedResource;
use crate::summary::DenialSummary;

/// One record in a captureDenials output stream.
///
/// Serialises with an internal `type` tag (`"denial"` / `"summary"`)
/// flattened alongside the payload fields, matching the on-disk NDJSON
/// contract consumers parse.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "lowercase")]
pub enum DenialFrame {
    /// A single denied resource observation.
    Denial(DeniedResource),
    /// The terminating summary; exactly one per stream, written last.
    Summary(DenialSummary),
}

impl From<DeniedResource> for DenialFrame {
    fn from(resource: DeniedResource) -> Self {
        DenialFrame::Denial(resource)
    }
}

impl From<DenialSummary> for DenialFrame {
    fn from(summary: DenialSummary) -> Self {
        DenialFrame::Summary(summary)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{AccessType, ResourceType};

    #[test]
    fn denial_frame_carries_type_tag() {
        let frame = DenialFrame::from(DeniedResource {
            path: r"C:\x".to_string(),
            resource_type: ResourceType::File,
            access_type: AccessType::Read,
            pid: 7,
            filetime: 9,
        });
        let json = serde_json::to_string(&frame).unwrap();
        assert!(json.starts_with("{\"type\":\"denial\""), "got {json}");
        assert!(json.contains("\"path\":\"C:\\\\x\""), "got {json}");
    }

    #[test]
    fn summary_frame_carries_type_tag() {
        let frame = DenialFrame::from(DenialSummary::new(0, 1, false));
        let json = serde_json::to_string(&frame).unwrap();
        assert!(json.starts_with("{\"type\":\"summary\""), "got {json}");
        assert!(json.contains("\"totalDenials\":1"), "got {json}");
    }

    #[test]
    fn frame_round_trips_through_json() {
        let denial = DenialFrame::from(DeniedResource {
            path: r"C:\y".to_string(),
            resource_type: ResourceType::Capability,
            access_type: AccessType::Unknown,
            pid: 3,
            filetime: 4,
        });
        let parsed: DenialFrame =
            serde_json::from_str(&serde_json::to_string(&denial).unwrap()).unwrap();
        assert_eq!(denial, parsed);

        let summary = DenialFrame::from(DenialSummary::new(2, 5, true));
        let parsed: DenialFrame =
            serde_json::from_str(&serde_json::to_string(&summary).unwrap()).unwrap();
        assert_eq!(summary, parsed);
    }
}
