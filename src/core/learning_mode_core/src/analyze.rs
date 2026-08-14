// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! The decode abstraction: turn a platform-native capture source into the
//! cross-platform [`DeniedResource`] model.
//!
//! Each backend implements [`DenialAnalyzer`] over its own capture format.
//! The Windows backend (`learning_mode_windows`) implements it over a
//! sealed ETW trace (`.etl`); a future Linux backend would implement it
//! over its own source. Keeping the trait in this cross-platform crate
//! lets the runner and tests depend on the abstraction rather than any
//! one OS decoder, and lets tests substitute a fake.

use std::path::Path;

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::data_loop::DataLoopSummary;
use crate::model::DeniedResource;

/// Result of decoding a capture source into bounded, de-duplicated denials.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AnalysisResult {
    /// Unique denials retained by the analyzer in first-seen order.
    pub denials: Vec<DeniedResource>,
    /// Whether additional unique denials were observed after the result bound
    /// was reached.
    pub denied_resources_truncated: bool,
    /// Username-redacted signatures for outcomes omitted from canonical denials.
    #[serde(default)]
    pub data_loop: DataLoopSummary,
}

/// Inclusive process-lifetime window used to scope a host-wide capture.
///
/// Windows WPR fallback capture observes a host-wide provider stream. The
/// elevated analyzer accepts only denial events whose PID and timestamp fall
/// within one of these job-observed lifetimes, preventing unrelated host
/// activity and PID reuse from entering the caller's output.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ProcessLifetime {
    /// Process identifier assigned by the OS.
    pub pid: u32,
    /// Process creation time in the normalized capture clock.
    pub start_filetime: u64,
    /// Process exit time in the normalized capture clock.
    pub end_filetime: u64,
}

impl ProcessLifetime {
    /// Returns whether the event belongs to this exact process lifetime.
    #[must_use]
    pub fn contains(self, pid: u32, filetime: u64) -> bool {
        self.pid == pid && filetime >= self.start_filetime && filetime <= self.end_filetime
    }
}

impl AnalysisResult {
    /// Creates a complete, non-truncated result.
    #[must_use]
    pub fn complete(denials: Vec<DeniedResource>) -> Self {
        Self {
            denials,
            denied_resources_truncated: false,
            data_loop: DataLoopSummary::default(),
        }
    }

    /// Trims Data Loop signatures so the complete compact JSON result fits.
    ///
    /// Returns `false` when the canonical denials and empty Data Loop envelope
    /// alone exceed `max_bytes`; canonical denials are never discarded.
    pub fn fit_data_loop_within_serialized_bytes(
        &mut self,
        max_bytes: usize,
    ) -> Result<bool, serde_json::Error> {
        if serde_json::to_vec(self)?.len() <= max_bytes {
            return Ok(true);
        }

        let original = std::mem::take(&mut self.data_loop.signatures);
        let mut retained_bytes = 0usize;
        const ENVELOPE_HEADROOM: usize = 4 * 1024;
        let base_len = serde_json::to_vec(self)?.len();
        if base_len > max_bytes {
            return Ok(false);
        }
        let signature_budget = max_bytes
            .saturating_sub(base_len)
            .saturating_sub(ENVELOPE_HEADROOM);
        let mut original = original;
        original.sort_by_key(|aggregate| !aggregate.signature.reason.is_canonical_denial());
        for aggregate in original {
            let aggregate_len = serde_json::to_vec(&aggregate)?.len().saturating_add(1);
            if retained_bytes.saturating_add(aggregate_len) <= signature_budget {
                retained_bytes += aggregate_len;
                self.data_loop.signatures.push(aggregate);
            } else {
                self.data_loop.move_to_overflow(aggregate);
            }
        }
        self.data_loop
            .signatures
            .sort_by(|left, right| left.signature.cmp(&right.signature));

        while serde_json::to_vec(self)?.len() > max_bytes {
            let index = self
                .data_loop
                .signatures
                .iter()
                .rposition(|aggregate| !aggregate.signature.reason.is_canonical_denial())
                .or_else(|| self.data_loop.signatures.len().checked_sub(1));
            let Some(index) = index else {
                return Ok(false);
            };
            let aggregate = self.data_loop.signatures.remove(index);
            self.data_loop.move_to_overflow(aggregate);
        }
        Ok(true)
    }
}

/// Failure modes when analysing a capture source into denials.
#[derive(Debug, Error)]
pub enum AnalyzeError {
    /// The capture source could not be opened (missing file, permissions).
    #[error("failed to open capture source '{path}': {source}")]
    Open {
        /// The source path that could not be opened.
        path: String,
        /// The underlying I/O error.
        source: std::io::Error,
    },

    /// The source was opened but could not be decoded into denials.
    #[error("failed to decode capture source: {0}")]
    Decode(String),

    /// Analysis is not available on this platform / build (e.g. the
    /// decoder is Windows-only and this is a non-Windows target).
    #[error("capture analysis is not supported on this platform")]
    Unsupported,
}

/// Decodes a platform-native capture source into de-duplicated denials.
///
/// Implementors return bounded unique `(resource, accessType)` observations and
/// whether additional unique records were truncated; the caller wraps them with a
/// [`crate::summary::DenialSummary`] and writes the JSON output document via
/// [`crate::emit`].
pub trait DenialAnalyzer {
    /// Analyses the capture at `source_path`, returning its bounded denial
    /// result.
    ///
    /// # Errors
    ///
    /// Returns [`AnalyzeError`] if the source cannot be opened, cannot be
    /// decoded, or analysis is unsupported on this platform.
    fn analyze(&self, source_path: &Path) -> Result<AnalysisResult, AnalyzeError>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::data_loop::{
        DataLoopAggregate, DataLoopExclusionReason, DataLoopProvider, DataLoopSignature,
    };
    use crate::model::{AccessType, ResourceType};

    /// A trivial analyzer returning a fixed set, proving the trait is
    /// object-safe and usable behind a `dyn` reference.
    struct FakeAnalyzer(Vec<DeniedResource>);

    impl DenialAnalyzer for FakeAnalyzer {
        fn analyze(&self, _source_path: &Path) -> Result<AnalysisResult, AnalyzeError> {
            Ok(AnalysisResult::complete(self.0.clone()))
        }
    }

    #[test]
    fn analyzer_is_object_safe_and_returns_denials() {
        let denials = vec![DeniedResource {
            resource: r"C:\a".to_string(),
            resource_type: ResourceType::File,
            access_type: AccessType::Read,
            pid: 1,
            filetime: 2,
        }];
        let analyzer: Box<dyn DenialAnalyzer> = Box::new(FakeAnalyzer(denials.clone()));
        let got = analyzer.analyze(Path::new("ignored.etl")).unwrap();
        assert_eq!(got.denials, denials);
        assert!(!got.denied_resources_truncated);
        assert!(got.data_loop.is_empty());
    }

    #[test]
    fn legacy_guarded_payload_defaults_data_loop_summary() {
        let payload = br#"{"denials":[],"deniedResourcesTruncated":false}"#;
        let result: AnalysisResult = serde_json::from_slice(payload).unwrap();
        assert!(result.data_loop.is_empty());
    }

    #[test]
    fn analyze_error_messages_are_meaningful() {
        let err = AnalyzeError::Open {
            path: "x.etl".to_string(),
            source: std::io::Error::new(std::io::ErrorKind::NotFound, "nope"),
        };
        assert!(err.to_string().contains("x.etl"));
        assert!(AnalyzeError::Unsupported
            .to_string()
            .contains("not supported"));
    }

    #[test]
    fn process_lifetime_is_inclusive_and_pid_specific() {
        let lifetime = ProcessLifetime {
            pid: 42,
            start_filetime: 100,
            end_filetime: 200,
        };

        assert!(lifetime.contains(42, 100));
        assert!(lifetime.contains(42, 200));
        assert!(!lifetime.contains(42, 99));
        assert!(!lifetime.contains(42, 201));
        assert!(!lifetime.contains(43, 150));
    }

    #[test]
    fn serialized_size_limit_moves_data_loop_groups_to_overflow() {
        let signature = |pid| DataLoopAggregate {
            signature: DataLoopSignature {
                provider: DataLoopProvider::KernelGeneral,
                provider_guid: "provider".to_string(),
                event_id: 14,
                reason: DataLoopExclusionReason::CanonicalDenial,
                pid,
                access_type: Some(AccessType::Read),
                resource_type: Some(ResourceType::File),
                properties: vec![("ObjectName".to_string(), "x".repeat(4_096))],
            },
            count: 3,
        };
        let mut result = AnalysisResult {
            denials: vec![DeniedResource {
                resource: "canonical".repeat(512),
                resource_type: ResourceType::File,
                access_type: AccessType::Read,
                pid: 1,
                filetime: 2,
            }],
            denied_resources_truncated: false,
            data_loop: DataLoopSummary {
                signatures: vec![signature(1), signature(2)],
                total_occurrences: 6,
                ..Default::default()
            },
        };
        let original_len = serde_json::to_vec(&result).unwrap().len();

        assert!(result
            .fit_data_loop_within_serialized_bytes(original_len - 1)
            .unwrap());
        assert!(serde_json::to_vec(&result).unwrap().len() < original_len);
        assert!(result.data_loop.aggregate_groups_truncated);
        assert_eq!(result.data_loop.total_occurrences, 6);
        assert!(result.data_loop.overflow_occurrences > 0);
    }

    #[test]
    fn serialized_size_limit_never_discards_canonical_denials() {
        let mut result = AnalysisResult::complete(vec![DeniedResource {
            resource: "canonical".repeat(512),
            resource_type: ResourceType::File,
            access_type: AccessType::Read,
            pid: 1,
            filetime: 2,
        }]);

        assert!(!result.fit_data_loop_within_serialized_bytes(1).unwrap());
        assert_eq!(result.denials.len(), 1);
    }
}
