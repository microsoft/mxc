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

use crate::model::DeniedResource;
use crate::verbose_logging::{VerboseLoggingAggregate, VerboseLoggingSummary};

/// Result of decoding a capture source into bounded, de-duplicated denials.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AnalysisResult {
    /// Unique denials retained by the analyzer in first-seen order.
    pub denials: Vec<DeniedResource>,
    /// Whether additional unique denials were observed after the result bound
    /// was reached.
    pub denied_resources_truncated: bool,
    /// Username-redacted signatures for actionable and diagnostic outcomes.
    #[serde(default)]
    pub verbose_logging: VerboseLoggingSummary,
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
            verbose_logging: VerboseLoggingSummary::default(),
        }
    }

    /// Trims verbose logging signatures so the complete compact JSON
    /// serialization is no larger than `max_bytes`.
    ///
    /// Returns `false` when the actionable denials and empty verbose logging
    /// envelope alone exceed `max_bytes`; actionable denials are never discarded.
    pub fn fit_verbose_logging_within_serialized_bytes(
        &mut self,
        max_bytes: usize,
    ) -> Result<bool, serde_json::Error> {
        if serde_json::to_vec(self)?.len() <= max_bytes {
            return Ok(true);
        }

        let base_len =
            serialized_analysis_len(self, &[], self.verbose_logging.signatures.as_slice())?;
        if base_len > max_bytes {
            return Ok(false);
        }

        let original = std::mem::take(&mut self.verbose_logging.signatures);
        let mut retained_bytes = 0usize;
        const ENVELOPE_HEADROOM: usize = 4 * 1024;
        let signature_budget = max_bytes
            .saturating_sub(base_len)
            .saturating_sub(ENVELOPE_HEADROOM);
        let mut original = original;
        original.sort_by_key(|aggregate| !aggregate.signature.reason.is_actionable());
        for aggregate in original {
            let aggregate_len = serde_json::to_vec(&aggregate)?.len().saturating_add(1);
            if retained_bytes.saturating_add(aggregate_len) <= signature_budget {
                retained_bytes += aggregate_len;
                self.verbose_logging.signatures.push(aggregate);
            } else {
                self.verbose_logging.move_to_overflow(aggregate);
            }
        }

        let mut retained = std::mem::take(&mut self.verbose_logging.signatures);
        let serialized_len = |retained_count: usize| {
            serialized_analysis_len(
                self,
                &retained[..retained_count],
                &retained[retained_count..],
            )
        };
        let mut low = 0usize;
        let mut high = retained.len();
        while low < high {
            let middle = low + (high - low).div_ceil(2);
            if serialized_len(middle)? <= max_bytes {
                low = middle;
            } else {
                high = middle - 1;
            }
        }
        let removed = retained.split_off(low);
        self.verbose_logging.signatures = retained;
        for aggregate in removed {
            self.verbose_logging.move_to_overflow(aggregate);
        }
        self.verbose_logging
            .signatures
            .sort_by(|left, right| left.signature.cmp(&right.signature));
        Ok(serde_json::to_vec(self)?.len() <= max_bytes)
    }
}

fn serialized_analysis_len(
    analysis: &AnalysisResult,
    retained: &[VerboseLoggingAggregate],
    removed: &[VerboseLoggingAggregate],
) -> Result<usize, serde_json::Error> {
    #[derive(Serialize)]
    #[serde(rename_all = "camelCase")]
    struct AnalysisView<'a> {
        denials: &'a [DeniedResource],
        denied_resources_truncated: bool,
        verbose_logging: VerboseLoggingView<'a>,
    }

    #[derive(Serialize)]
    #[serde(rename_all = "camelCase")]
    struct VerboseLoggingView<'a> {
        signatures: &'a [VerboseLoggingAggregate],
        total_occurrences: u64,
        overflow_occurrences: u64,
        actionable_overflow_occurrences: u64,
        aggregate_groups_truncated: bool,
        processed_events_truncated: bool,
        actionable_limit_reached: bool,
    }

    let removed_occurrences = removed.iter().fold(0u64, |total, aggregate| {
        total.saturating_add(aggregate.count)
    });
    let removed_actionable_occurrences = removed
        .iter()
        .filter(|aggregate| aggregate.signature.reason.is_actionable())
        .fold(0u64, |total, aggregate| {
            total.saturating_add(aggregate.count)
        });
    let view = AnalysisView {
        denials: &analysis.denials,
        denied_resources_truncated: analysis.denied_resources_truncated,
        verbose_logging: VerboseLoggingView {
            signatures: retained,
            total_occurrences: analysis.verbose_logging.total_occurrences,
            overflow_occurrences: analysis
                .verbose_logging
                .overflow_occurrences
                .saturating_add(removed_occurrences),
            actionable_overflow_occurrences: analysis
                .verbose_logging
                .actionable_overflow_occurrences
                .saturating_add(removed_actionable_occurrences),
            aggregate_groups_truncated: analysis.verbose_logging.aggregate_groups_truncated
                || !removed.is_empty(),
            processed_events_truncated: analysis.verbose_logging.processed_events_truncated,
            actionable_limit_reached: analysis.verbose_logging.actionable_limit_reached,
        },
    };
    serde_json::to_vec(&view).map(|bytes| bytes.len())
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
    use crate::model::{AccessType, ResourceType};
    use crate::verbose_logging::{
        VerboseLoggingAggregate, VerboseLoggingOutcomeReason, VerboseLoggingProvider,
        VerboseLoggingSignature,
    };

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
        assert!(got.verbose_logging.is_empty());
    }

    #[test]
    fn analysis_payload_without_verbose_logging_defaults_summary() {
        let payload = br#"{"denials":[],"deniedResourcesTruncated":false}"#;
        let result: AnalysisResult = serde_json::from_slice(payload).unwrap();
        assert!(result.verbose_logging.is_empty());
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
    fn serialized_size_limit_moves_verbose_logging_groups_to_overflow() {
        let signature = |pid| VerboseLoggingAggregate {
            signature: VerboseLoggingSignature {
                provider: VerboseLoggingProvider::KernelGeneral,
                provider_guid: "provider".to_string(),
                event_id: 14,
                reason: VerboseLoggingOutcomeReason::Actionable,
                pid,
                access_type: Some(AccessType::Read),
                resource_type: Some(ResourceType::File),
                properties: vec![("ObjectName".to_string(), "x".repeat(4_096))],
            },
            count: 3,
        };
        let mut result = AnalysisResult {
            denials: vec![DeniedResource {
                resource: "actionable".repeat(512),
                resource_type: ResourceType::File,
                access_type: AccessType::Read,
                pid: 1,
                filetime: 2,
            }],
            denied_resources_truncated: false,
            verbose_logging: VerboseLoggingSummary {
                signatures: vec![signature(1), signature(2)],
                total_occurrences: 6,
                ..Default::default()
            },
        };
        let original_len = serde_json::to_vec(&result).unwrap().len();

        assert!(result
            .fit_verbose_logging_within_serialized_bytes(original_len - 1)
            .unwrap());
        assert!(serde_json::to_vec(&result).unwrap().len() < original_len);
        assert!(result.verbose_logging.aggregate_groups_truncated);
        assert_eq!(result.verbose_logging.total_occurrences, 6);
        assert!(result.verbose_logging.overflow_occurrences > 0);
    }

    #[test]
    fn serialized_size_limit_saturates_overflow_counters() {
        let mut result = AnalysisResult {
            denials: Vec::new(),
            denied_resources_truncated: false,
            verbose_logging: VerboseLoggingSummary {
                signatures: vec![VerboseLoggingAggregate {
                    signature: VerboseLoggingSignature {
                        provider: VerboseLoggingProvider::KernelGeneral,
                        provider_guid: "provider".to_string(),
                        event_id: 14,
                        reason: VerboseLoggingOutcomeReason::Actionable,
                        pid: 1,
                        access_type: Some(AccessType::Read),
                        resource_type: Some(ResourceType::File),
                        properties: vec![("ObjectName".to_string(), "x".repeat(4_096))],
                    },
                    count: 3,
                }],
                total_occurrences: u64::MAX,
                overflow_occurrences: u64::MAX - 1,
                actionable_overflow_occurrences: u64::MAX - 1,
                ..Default::default()
            },
        };
        let original_len = serde_json::to_vec(&result).unwrap().len();

        assert!(result
            .fit_verbose_logging_within_serialized_bytes(original_len - 1)
            .unwrap());
        assert_eq!(result.verbose_logging.overflow_occurrences, u64::MAX);
        assert_eq!(
            result.verbose_logging.actionable_overflow_occurrences,
            u64::MAX
        );
    }

    #[test]
    fn serialized_size_limit_never_discards_actionable_denials() {
        let mut result = AnalysisResult {
            denials: vec![DeniedResource {
                resource: "actionable".repeat(512),
                resource_type: ResourceType::File,
                access_type: AccessType::Read,
                pid: 1,
                filetime: 2,
            }],
            denied_resources_truncated: false,
            verbose_logging: VerboseLoggingSummary {
                signatures: vec![VerboseLoggingAggregate {
                    signature: VerboseLoggingSignature {
                        provider: VerboseLoggingProvider::KernelGeneral,
                        provider_guid: "provider".to_string(),
                        event_id: 14,
                        reason: VerboseLoggingOutcomeReason::Actionable,
                        pid: 1,
                        access_type: Some(AccessType::Read),
                        resource_type: Some(ResourceType::File),
                        properties: vec![("ObjectName".to_string(), "value".to_string())],
                    },
                    count: 1,
                }],
                total_occurrences: 1,
                ..Default::default()
            },
        };
        let original = result.clone();

        assert!(!result
            .fit_verbose_logging_within_serialized_bytes(1)
            .unwrap());
        assert_eq!(result, original);
        assert!(result
            .fit_verbose_logging_within_serialized_bytes(
                serde_json::to_vec(&original).unwrap().len()
            )
            .unwrap());
        assert_eq!(result, original);
    }

    #[test]
    fn serialized_size_limit_handles_maximum_signature_count() {
        let signatures = (0..crate::verbose_logging::MAX_VERBOSE_LOGGING_GROUPS)
            .map(|pid| VerboseLoggingAggregate {
                signature: VerboseLoggingSignature {
                    provider: VerboseLoggingProvider::KernelGeneral,
                    provider_guid: "provider".to_string(),
                    event_id: 14,
                    reason: VerboseLoggingOutcomeReason::MissingObjectName,
                    pid: u32::try_from(pid).unwrap(),
                    access_type: Some(AccessType::Read),
                    resource_type: Some(ResourceType::File),
                    properties: vec![("ObjectName".to_string(), "x".repeat(256))],
                },
                count: 1,
            })
            .collect();
        let mut result = AnalysisResult {
            denials: Vec::new(),
            denied_resources_truncated: false,
            verbose_logging: VerboseLoggingSummary {
                signatures,
                total_occurrences: crate::verbose_logging::MAX_VERBOSE_LOGGING_GROUPS as u64,
                ..Default::default()
            },
        };

        assert!(result
            .fit_verbose_logging_within_serialized_bytes(64 * 1024)
            .unwrap());
        assert!(serde_json::to_vec(&result).unwrap().len() <= 64 * 1024);
        assert!(!result.verbose_logging.signatures.is_empty());
        assert_eq!(
            result.verbose_logging.signatures.len() as u64
                + result.verbose_logging.overflow_occurrences,
            crate::verbose_logging::MAX_VERBOSE_LOGGING_GROUPS as u64
        );
    }
}
