// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Terminating summary for a captureDenials output document.
//!
//! Exactly one [`DenialSummary`] accompanies the
//! [`crate::model::DeniedResource`] array in a JSON output file. It gives
//! consumers the child's exit code, the count of unique denials, and a
//! flag indicating whether the decoder had to truncate the set (so a UX
//! can tell the user "showing N of many").

use serde::{Deserialize, Serialize};

/// The terminating summary of a captureDenials output document.
///
/// `total_denials` is the number of *unique* `(resource, accessType)` pairs,
/// which matches the length of the document's `denials` array.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DenialSummary {
    /// Exit code of the sandboxed child process.
    pub exit_code: i32,

    /// Count of unique `(resource, accessType)` denials emitted (equals the
    /// length of the document's `denials` array).
    pub total_denials: usize,

    /// `true` when the decoder capped the emitted set and additional
    /// denials were observed but not written. Consumers should surface
    /// this so the user knows the list is partial.
    pub denied_resources_truncated: bool,
}

impl DenialSummary {
    /// Builds a summary for a completed capture.
    #[must_use]
    pub fn new(exit_code: i32, total_denials: usize, denied_resources_truncated: bool) -> Self {
        Self {
            exit_code,
            total_denials,
            denied_resources_truncated,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn summary_serialises_camel_case() {
        let s = DenialSummary::new(0, 3, false);
        let json = serde_json::to_string(&s).unwrap();
        assert!(json.contains("\"exitCode\":0"), "got {json}");
        assert!(json.contains("\"totalDenials\":3"), "got {json}");
        assert!(
            json.contains("\"deniedResourcesTruncated\":false"),
            "got {json}"
        );
    }

    #[test]
    fn summary_round_trips_through_json() {
        let s = DenialSummary::new(255, 42, true);
        let json = serde_json::to_string(&s).unwrap();
        let parsed: DenialSummary = serde_json::from_str(&json).unwrap();
        assert_eq!(s, parsed);
    }
}
