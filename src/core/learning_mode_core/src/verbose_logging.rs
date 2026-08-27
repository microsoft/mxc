// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Sensitive-value-redacted, deduplicated diagnostics for Learning Mode events,
//! including every canonical denial occurrence.

use std::io::{self, Write};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

/// Maximum number of distinct aggregate groups retained in one analysis.
pub const MAX_VERBOSE_LOGGING_GROUPS: usize = 4_096;
/// Maximum compact-JSON bytes retained across distinct serialized signatures.
///
/// This leaves substantial headroom under the guarded WPR analysis protocol's
/// 64 MiB frame limit for canonical denials and envelope overhead.
pub const MAX_VERBOSE_LOGGING_SIGNATURE_BYTES: usize = 16 * 1024 * 1024;

/// Stable category for a known Learning Mode ETW provider.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum VerboseLoggingProvider {
    /// Microsoft-Windows-Kernel-General.
    KernelGeneral,
    /// Microsoft-Windows-Privacy-Auditing-PermissiveLearningMode.
    PrivacyAuditingPermissiveLearningMode,
    /// Microsoft-Windows-LearningMode-NetworkDecision.
    LearningModeNetworkDecision,
}

/// Closed reason why a decoder outcome was omitted from canonical denials.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum VerboseLoggingExclusionReason {
    /// The event produced a valid canonical denial candidate.
    CanonicalDenial,
    /// The provider is known, but the event ID is not a supported denial schema.
    UnsupportedEventSchema,
    /// The event payload conflicted with its declared TDH schema.
    EventPayloadMalformed,
    /// A decoder safety bound prevented full payload processing.
    DecoderLimitReached,
    /// The payload uses a property encoding the decoder cannot consume.
    UnsupportedPropertyEncoding,
    /// A required object-type property was absent or empty.
    MissingObjectType,
    /// A required object/resource-name property was absent or empty.
    MissingObjectName,
    /// The event described an object category the canonical model cannot represent.
    UnsupportedObjectType,
    /// A resource value could not be converted to a safe user-visible resource.
    UnusableResourcePath,
    /// A capability event did not contain a usable capability denial.
    UnresolvedCapability,
    /// The event was valid but did not describe an actionable denial.
    NotActionable,
    /// The source reported an intentional explicit deny or allow-rule exclusion.
    IntentionalNetworkPolicyDeny,
    /// The source reported a direct connection blocked by proxy containment.
    ProxyContainment,
    /// The network event carried an unknown or unsupported stable reason.
    UnknownNetworkReason,
    /// The network event omitted endpoint data required for policy guidance.
    IncompleteNetworkEndpoint,
}

impl VerboseLoggingExclusionReason {
    /// Returns whether this outcome represents a valid denial candidate.
    #[must_use]
    pub fn is_canonical_denial(self) -> bool {
        self == Self::CanonicalDenial
    }
}

/// One sanitized event signature used as a verbose logging deduplication key.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct VerboseLoggingSignature {
    /// Symbolic provider category.
    pub provider: VerboseLoggingProvider,
    /// Stable ETW provider GUID.
    pub provider_guid: String,
    /// Provider-scoped ETW schema identifier.
    pub event_id: u16,
    /// Closed exclusion category.
    pub reason: VerboseLoggingExclusionReason,
    /// Process identifier from the event header.
    pub pid: u32,
    /// Classified access type when the event produced a denial candidate.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub access_type: Option<crate::AccessType>,
    /// Classified resource type when the event produced a denial candidate.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resource_type: Option<crate::ResourceType>,
    /// Sorted, bounded, sensitive-value-redacted event properties.
    pub properties: Vec<(String, String)>,
}

/// One deduplicated verbose logging signature and its occurrence count.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct VerboseLoggingAggregate {
    /// Sanitized signature shared by all counted occurrences.
    pub signature: VerboseLoggingSignature,
    /// Number of matching exclusion outcomes.
    pub count: u64,
}

/// Bounded aggregate state produced by one decoder pass.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct VerboseLoggingSummary {
    /// Sorted sanitized signatures retained within [`MAX_VERBOSE_LOGGING_GROUPS`].
    pub signatures: Vec<VerboseLoggingAggregate>,
    /// Total recorded event outcomes, including groups collapsed into overflow.
    pub total_occurrences: u64,
    /// Outcomes whose new aggregate key could not be retained at the group bound.
    pub overflow_occurrences: u64,
    /// Canonical-denial occurrences whose signatures could not be retained.
    pub canonical_overflow_occurrences: u64,
    /// Whether aggregate keys were omitted at the group bound.
    pub aggregate_groups_truncated: bool,
    /// Whether the ETL processed-event bound prevented complete accounting.
    pub processed_events_truncated: bool,
    /// Whether the canonical unique-denial bound was reached.
    pub canonical_denial_limit_reached: bool,
}

impl VerboseLoggingSummary {
    /// Records one event outcome while preserving deterministic group order.
    pub fn record(&mut self, signature: VerboseLoggingSignature) {
        self.total_occurrences = self.total_occurrences.saturating_add(1);
        match self
            .signatures
            .binary_search_by(|group| group.signature.cmp(&signature))
        {
            Ok(index) => {
                self.signatures[index].count = self.signatures[index].count.saturating_add(1);
            }
            Err(index) if self.signatures.len() < MAX_VERBOSE_LOGGING_GROUPS => {
                self.signatures.insert(
                    index,
                    VerboseLoggingAggregate {
                        signature,
                        count: 1,
                    },
                );
            }
            Err(_) => {
                if signature.reason.is_canonical_denial() && self.evict_one_noncanonical_group(None)
                {
                    let index = self
                        .signatures
                        .binary_search_by(|group| group.signature.cmp(&signature))
                        .unwrap_err();
                    self.signatures.insert(
                        index,
                        VerboseLoggingAggregate {
                            signature,
                            count: 1,
                        },
                    );
                } else {
                    self.record_overflow(signature.reason.is_canonical_denial());
                    self.total_occurrences = self.total_occurrences.saturating_sub(1);
                }
            }
        }
    }

    /// Records an outcome while bounding compact serialized signature bytes.
    pub fn record_with_byte_budget(
        &mut self,
        signature: VerboseLoggingSignature,
        retained_bytes: &mut usize,
        max_bytes: usize,
    ) {
        if let Ok(index) = self
            .signatures
            .binary_search_by(|group| group.signature.cmp(&signature))
        {
            self.total_occurrences = self.total_occurrences.saturating_add(1);
            self.signatures[index].count = self.signatures[index].count.saturating_add(1);
            return;
        }

        let serialized_len = Self::serialized_signature_len(&signature);
        while self.signatures.len() >= MAX_VERBOSE_LOGGING_GROUPS
            || retained_bytes.saturating_add(serialized_len) > max_bytes
        {
            if !signature.reason.is_canonical_denial()
                || !self.evict_one_noncanonical_group(Some(retained_bytes))
            {
                self.record_overflow(signature.reason.is_canonical_denial());
                return;
            }
        }

        let index = self
            .signatures
            .binary_search_by(|group| group.signature.cmp(&signature))
            .unwrap_err();
        self.signatures.insert(
            index,
            VerboseLoggingAggregate {
                signature,
                count: 1,
            },
        );
        self.total_occurrences = self.total_occurrences.saturating_add(1);
        *retained_bytes = retained_bytes.saturating_add(serialized_len);
    }

    /// Counts an outcome whose new signature could not be retained at a bound.
    pub fn record_overflow(&mut self, canonical: bool) {
        self.total_occurrences = self.total_occurrences.saturating_add(1);
        self.overflow_occurrences = self.overflow_occurrences.saturating_add(1);
        if canonical {
            self.canonical_overflow_occurrences =
                self.canonical_overflow_occurrences.saturating_add(1);
        }
        self.aggregate_groups_truncated = true;
    }

    /// Moves a retained aggregate into overflow accounting.
    pub(crate) fn move_to_overflow(&mut self, aggregate: VerboseLoggingAggregate) {
        self.overflow_occurrences = self.overflow_occurrences.saturating_add(aggregate.count);
        if aggregate.signature.reason.is_canonical_denial() {
            self.canonical_overflow_occurrences = self
                .canonical_overflow_occurrences
                .saturating_add(aggregate.count);
        }
        self.aggregate_groups_truncated = true;
    }

    fn evict_one_noncanonical_group(&mut self, retained_bytes: Option<&mut usize>) -> bool {
        let Some(index) = self
            .signatures
            .iter()
            .rposition(|group| !group.signature.reason.is_canonical_denial())
        else {
            return false;
        };
        let aggregate = self.signatures.remove(index);
        if let Some(retained_bytes) = retained_bytes {
            *retained_bytes =
                retained_bytes.saturating_sub(Self::serialized_signature_len(&aggregate.signature));
        }
        self.move_to_overflow(aggregate);
        true
    }

    /// Marks accounting incomplete because the processed-event bound was reached.
    pub fn mark_processed_events_truncated(&mut self) {
        self.processed_events_truncated = true;
    }

    /// Marks that otherwise-valid candidates exceeded the canonical result bound.
    pub fn mark_canonical_denial_limit_reached(&mut self) {
        self.canonical_denial_limit_reached = true;
    }

    /// Returns whether this analysis observed no excluded outcomes or truncation.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.signatures.is_empty()
            && self.total_occurrences == 0
            && self.overflow_occurrences == 0
            && self.canonical_overflow_occurrences == 0
            && !self.aggregate_groups_truncated
            && !self.processed_events_truncated
            && !self.canonical_denial_limit_reached
    }

    fn serialized_signature_len(signature: &VerboseLoggingSignature) -> usize {
        serde_json::to_vec(&VerboseLoggingAggregate {
            signature: signature.clone(),
            count: 1,
        })
        .map_or(usize::MAX, |bytes| bytes.len())
    }
}

/// Versioned on-disk verbose logging document.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct VerboseLoggingDocument {
    /// Verbose logging schema version.
    pub version: u32,
    /// Sorted deduplicated sanitized signatures.
    pub signatures: Vec<VerboseLoggingAggregate>,
    /// Aggregate summary and bounds state.
    pub summary: VerboseLoggingDocumentSummary,
}

/// Bounds and count summary for a [`VerboseLoggingDocument`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct VerboseLoggingDocumentSummary {
    /// Total recorded event outcomes, including overflow.
    pub total_occurrences: u64,
    /// Outcomes collapsed because the group bound was reached.
    pub overflow_occurrences: u64,
    /// Canonical-denial occurrences collapsed into overflow.
    pub canonical_overflow_occurrences: u64,
    /// Whether aggregate keys were omitted.
    pub aggregate_groups_truncated: bool,
    /// Whether the processed-event limit prevented complete accounting.
    pub processed_events_truncated: bool,
    /// Whether the canonical unique-denial limit was reached.
    pub canonical_denial_limit_reached: bool,
}

impl VerboseLoggingDocument {
    /// Current verbose logging document schema version.
    pub const VERSION: u32 = 1;

    /// Builds an on-disk document from decoder aggregate state.
    #[must_use]
    pub fn new(summary: &VerboseLoggingSummary) -> Self {
        Self {
            version: Self::VERSION,
            signatures: summary.signatures.clone(),
            summary: VerboseLoggingDocumentSummary {
                total_occurrences: summary.total_occurrences,
                overflow_occurrences: summary.overflow_occurrences,
                canonical_overflow_occurrences: summary.canonical_overflow_occurrences,
                aggregate_groups_truncated: summary.aggregate_groups_truncated,
                processed_events_truncated: summary.processed_events_truncated,
                canonical_denial_limit_reached: summary.canonical_denial_limit_reached,
            },
        }
    }
}

/// Derives the deterministic verbose logging sibling for a canonical denials path.
///
/// # Errors
///
/// Returns an error when `output_path` has no usable file name.
pub fn verbose_logging_sibling_path(output_path: &Path) -> io::Result<PathBuf> {
    let file_name = output_path
        .file_name()
        .and_then(|value| value.to_str())
        .ok_or_else(|| {
            io::Error::other(format!(
                "denials output path has no usable file name: {}",
                output_path.display()
            ))
        })?;
    let stem = output_path
        .file_stem()
        .and_then(|value| value.to_str())
        .unwrap_or(file_name);
    let sibling = format!("{stem}.verbose.json");
    Ok(match output_path.parent() {
        Some(parent) if !parent.as_os_str().is_empty() => parent.join(sibling),
        _ => PathBuf::from(sibling),
    })
}

/// Writes a pretty-printed verbose logging JSON document and trailing newline.
///
/// # Errors
///
/// Returns serialization or underlying writer failures.
pub fn write_verbose_logging_document<W: Write>(
    writer: &mut W,
    document: &VerboseLoggingDocument,
) -> io::Result<()> {
    serde_json::to_writer_pretty(&mut *writer, document).map_err(io::Error::other)?;
    writer.write_all(b"\n")?;
    writer.flush()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn aggregates_and_sorts_sanitized_signatures() {
        let mut summary = VerboseLoggingSummary::default();
        let signature = VerboseLoggingSignature {
            provider: VerboseLoggingProvider::KernelGeneral,
            provider_guid: "{A68CA8B7-004F-D7B6-A698-07E2DE0F1F5D}".to_string(),
            event_id: 14,
            reason: VerboseLoggingExclusionReason::MissingObjectName,
            pid: 42,
            access_type: None,
            resource_type: None,
            properties: vec![
                ("ObjectName".to_string(), "<REDACTED>".to_string()),
                ("Sid".to_string(), "S-1-15-3-1".to_string()),
            ],
        };
        summary.record(signature.clone());
        summary.record(signature);

        assert_eq!(summary.total_occurrences, 2);
        assert_eq!(summary.signatures.len(), 1);
        assert_eq!(summary.signatures[0].count, 2);

        let mut bytes = Vec::new();
        write_verbose_logging_document(&mut bytes, &VerboseLoggingDocument::new(&summary)).unwrap();
        let text = String::from_utf8(bytes).unwrap();
        assert!(text.contains("S-1-15-3-1"));
        assert!(text.contains("<REDACTED>"));
        assert!(text.contains("providerGuid"));
        assert!(text.contains("\"pid\": 42"));
        assert!(!text.contains("accessType"));
        assert!(!text.contains("resourceType"));
    }

    #[test]
    fn group_bound_collapses_new_keys_into_overflow() {
        let mut summary = VerboseLoggingSummary::default();
        for event_id in 0..MAX_VERBOSE_LOGGING_GROUPS as u16 {
            summary.record(VerboseLoggingSignature {
                provider: VerboseLoggingProvider::KernelGeneral,
                provider_guid: "kernel".to_string(),
                event_id,
                reason: VerboseLoggingExclusionReason::UnsupportedEventSchema,
                pid: 1,
                access_type: None,
                resource_type: None,
                properties: Vec::new(),
            });
        }
        summary.record(VerboseLoggingSignature {
            provider: VerboseLoggingProvider::PrivacyAuditingPermissiveLearningMode,
            provider_guid: "privacy".to_string(),
            event_id: u16::MAX,
            reason: VerboseLoggingExclusionReason::UnsupportedEventSchema,
            pid: 1,
            access_type: None,
            resource_type: None,
            properties: Vec::new(),
        });

        assert_eq!(summary.signatures.len(), MAX_VERBOSE_LOGGING_GROUPS);
        assert_eq!(summary.overflow_occurrences, 1);
        assert!(summary.aggregate_groups_truncated);
    }

    #[test]
    fn canonical_signature_evicts_noncanonical_signature_at_group_bound() {
        let mut summary = VerboseLoggingSummary::default();
        for event_id in 0..MAX_VERBOSE_LOGGING_GROUPS as u16 {
            summary.record(VerboseLoggingSignature {
                provider: VerboseLoggingProvider::KernelGeneral,
                provider_guid: "kernel".to_string(),
                event_id,
                reason: VerboseLoggingExclusionReason::UnsupportedEventSchema,
                pid: 1,
                access_type: None,
                resource_type: None,
                properties: Vec::new(),
            });
        }
        summary.record(VerboseLoggingSignature {
            provider: VerboseLoggingProvider::KernelGeneral,
            provider_guid: "kernel".to_string(),
            event_id: u16::MAX,
            reason: VerboseLoggingExclusionReason::CanonicalDenial,
            pid: 1,
            access_type: Some(crate::AccessType::Read),
            resource_type: Some(crate::ResourceType::File),
            properties: Vec::new(),
        });

        assert!(summary
            .signatures
            .iter()
            .any(|group| group.signature.reason == VerboseLoggingExclusionReason::CanonicalDenial));
        assert_eq!(summary.overflow_occurrences, 1);
        assert_eq!(summary.canonical_overflow_occurrences, 0);
    }

    #[test]
    fn byte_budget_leaves_guarded_analysis_protocol_headroom() {
        let mut summary = VerboseLoggingSummary::default();
        let mut retained_bytes = 0;
        let properties = (0..24)
            .map(|index| (format!("Property{index:02}"), "x".repeat(256)))
            .collect::<Vec<_>>();
        for pid in 0..MAX_VERBOSE_LOGGING_GROUPS as u32 {
            summary.record_with_byte_budget(
                VerboseLoggingSignature {
                    provider: VerboseLoggingProvider::KernelGeneral,
                    provider_guid: "{A68CA8B7-004F-D7B6-A698-07E2DE0F1F5D}".to_string(),
                    event_id: 14,
                    reason: VerboseLoggingExclusionReason::CanonicalDenial,
                    pid,
                    access_type: Some(crate::AccessType::Read),
                    resource_type: Some(crate::ResourceType::File),
                    properties: properties.clone(),
                },
                &mut retained_bytes,
                MAX_VERBOSE_LOGGING_SIGNATURE_BYTES,
            );
        }

        assert!(summary.aggregate_groups_truncated);
        assert!(summary.overflow_occurrences > 0);
        assert!(retained_bytes <= MAX_VERBOSE_LOGGING_SIGNATURE_BYTES);
        let payload = serde_json::to_vec(&crate::AnalysisResult {
            denials: Vec::new(),
            denied_resources_truncated: false,
            verbose_logging: summary,
        })
        .unwrap();
        assert!(payload.len() < 64 * 1024 * 1024);
    }

    #[test]
    fn document_round_trips() {
        let mut summary = VerboseLoggingSummary::default();
        summary.mark_canonical_denial_limit_reached();
        summary.mark_processed_events_truncated();
        let document = VerboseLoggingDocument::new(&summary);
        let mut bytes = Vec::new();
        write_verbose_logging_document(&mut bytes, &document).unwrap();
        let parsed: VerboseLoggingDocument = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(parsed, document);
    }

    #[test]
    fn sibling_path_replaces_the_canonical_extension() {
        assert_eq!(
            verbose_logging_sibling_path(Path::new(r"C:\out\denials.123.json")).unwrap(),
            PathBuf::from(r"C:\out\denials.123.verbose.json")
        );
        assert_eq!(
            verbose_logging_sibling_path(Path::new("denials")).unwrap(),
            PathBuf::from("denials.verbose.json")
        );
    }
}
