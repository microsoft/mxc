// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Crate-internal diagnostics used by MXC capture paths.

use std::io::{self, Write};

use serde::{Deserialize, Serialize};

use super::{
    AccessType, AnalysisResult, ResourceType, VerboseLoggingAggregate, VerboseLoggingOutcomeReason,
    VerboseLoggingProvider, VerboseLoggingSummary, MAX_VERBOSE_LOGGING_GROUPS,
    MAX_VERBOSE_LOGGING_SIGNATURE_BYTES,
};

/// Verbose document version owned by the WFP diagnostic extension.
pub(crate) const CAPTURE_VERBOSE_LOGGING_VERSION: u32 = 5;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) enum CaptureVerboseLoggingProvider {
    Other,
    KernelGeneral,
    PrivacyAuditingPermissiveLearningMode,
    LearningModeNetworkDecision,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) enum CaptureVerboseLoggingOutcomeReason {
    Actionable,
    UnsupportedEventSchema,
    SchemaUnavailable,
    EventPayloadMalformed,
    DecoderLimitReached,
    UnsupportedPropertyEncoding,
    MissingObjectType,
    MissingObjectName,
    UnsupportedObjectType,
    UnusableResourcePath,
    UnresolvedCapability,
    ComActivation,
    ComInterfaceCall,
    NotActionable,
    IntentionalNetworkPolicyDeny,
    ProxyContainment,
    UnknownNetworkReason,
    IncompleteNetworkEndpoint,
}

impl CaptureVerboseLoggingOutcomeReason {
    pub(crate) fn is_actionable(self) -> bool {
        self == Self::Actionable
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) enum NetworkDecisionReason {
    AppIsolationMissingCapability,
    DirectDefaultDeny,
    AuthoredExplicitDeny,
    AllowExclusion,
    ProxyContainment,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) enum ConfigurationRecommendation {
    AddCapability,
    AddEgressAllow,
    ReviewEgressDeny,
    ReviewAllowExclusion,
    UseConfiguredProxy,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct NetworkEndpoint {
    pub(crate) protocol: String,
    pub(crate) remote_address: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) remote_port: Option<u16>,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct CaptureVerboseLoggingSignature {
    pub(crate) provider: CaptureVerboseLoggingProvider,
    pub(crate) provider_guid: String,
    pub(crate) event_id: u16,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) event_name: Option<String>,
    pub(crate) reason: CaptureVerboseLoggingOutcomeReason,
    pub(crate) pid: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) access_type: Option<AccessType>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) resource_type: Option<ResourceType>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) network_decision_reason: Option<NetworkDecisionReason>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) configuration_recommendation: Option<ConfigurationRecommendation>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) network_endpoint: Option<NetworkEndpoint>,
    pub(crate) properties: Vec<(String, String)>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct CaptureVerboseLoggingAggregate {
    pub(crate) signature: CaptureVerboseLoggingSignature,
    pub(crate) count: u64,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct CaptureVerboseLoggingSummary {
    pub(crate) signatures: Vec<CaptureVerboseLoggingAggregate>,
    pub(crate) total_occurrences: u64,
    pub(crate) overflow_occurrences: u64,
    pub(crate) actionable_overflow_occurrences: u64,
    pub(crate) aggregate_groups_truncated: bool,
    pub(crate) processed_events_truncated: bool,
    pub(crate) actionable_limit_reached: bool,
}

impl CaptureVerboseLoggingSummary {
    pub(crate) fn record_with_byte_budget(
        &mut self,
        signature: CaptureVerboseLoggingSignature,
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

        let serialized_len = serialized_signature_len(&signature);
        while self.signatures.len() >= MAX_VERBOSE_LOGGING_GROUPS
            || retained_bytes.saturating_add(serialized_len) > max_bytes
        {
            if !signature.reason.is_actionable()
                || !self.evict_one_nonactionable_group(retained_bytes)
            {
                self.record_overflow(signature.reason.is_actionable(), 1);
                return;
            }
        }

        let index = self
            .signatures
            .binary_search_by(|group| group.signature.cmp(&signature))
            .unwrap_err();
        self.signatures.insert(
            index,
            CaptureVerboseLoggingAggregate {
                signature,
                count: 1,
            },
        );
        self.total_occurrences = self.total_occurrences.saturating_add(1);
        *retained_bytes = retained_bytes.saturating_add(serialized_len);
    }

    pub(crate) fn record_actionable_after_saturation(
        &mut self,
        signature: CaptureVerboseLoggingSignature,
    ) {
        debug_assert!(signature.reason.is_actionable());
        match self
            .signatures
            .binary_search_by(|group| group.signature.cmp(&signature))
        {
            Ok(index) => {
                self.total_occurrences = self.total_occurrences.saturating_add(1);
                self.signatures[index].count = self.signatures[index].count.saturating_add(1);
            }
            Err(_) => self.record_overflow(true, 1),
        }
    }

    pub(crate) fn actionable_occurrences(&self) -> u64 {
        self.signatures
            .iter()
            .filter(|aggregate| aggregate.signature.reason.is_actionable())
            .fold(self.actionable_overflow_occurrences, |total, aggregate| {
                total.saturating_add(aggregate.count)
            })
    }

    fn record_overflow(&mut self, actionable: bool, count: u64) {
        self.total_occurrences = self.total_occurrences.saturating_add(count);
        self.overflow_occurrences = self.overflow_occurrences.saturating_add(count);
        if actionable {
            self.actionable_overflow_occurrences =
                self.actionable_overflow_occurrences.saturating_add(count);
        }
        self.aggregate_groups_truncated = true;
    }

    fn evict_one_nonactionable_group(&mut self, retained_bytes: &mut usize) -> bool {
        let Some(index) = self
            .signatures
            .iter()
            .rposition(|group| !group.signature.reason.is_actionable())
        else {
            return false;
        };
        let aggregate = self.signatures.remove(index);
        *retained_bytes =
            retained_bytes.saturating_sub(serialized_signature_len(&aggregate.signature));
        self.overflow_occurrences = self.overflow_occurrences.saturating_add(aggregate.count);
        self.aggregate_groups_truncated = true;
        true
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct CaptureVerboseLoggingDocument {
    pub(crate) version: u32,
    pub(crate) signatures: Vec<CaptureVerboseLoggingAggregate>,
    pub(crate) summary: CaptureVerboseLoggingDocumentSummary,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct CaptureVerboseLoggingDocumentSummary {
    pub(crate) total_occurrences: u64,
    pub(crate) overflow_occurrences: u64,
    pub(crate) actionable_overflow_occurrences: u64,
    pub(crate) aggregate_groups_truncated: bool,
    pub(crate) processed_events_truncated: bool,
    pub(crate) actionable_limit_reached: bool,
}

impl CaptureVerboseLoggingDocument {
    #[allow(dead_code)] // Consumed by the stacked product-output integration.
    pub(crate) fn new(
        legacy: &VerboseLoggingSummary,
        network: &CaptureVerboseLoggingSummary,
    ) -> Self {
        let mut candidates = legacy
            .signatures
            .iter()
            .map(convert_legacy_aggregate)
            .chain(network.signatures.iter().cloned())
            .collect::<Vec<_>>();
        candidates.sort_by_key(|aggregate| !aggregate.signature.reason.is_actionable());

        let mut retained = Vec::new();
        let mut retained_bytes = 0usize;
        let mut overflow_occurrences = legacy
            .overflow_occurrences
            .saturating_add(network.overflow_occurrences);
        let mut actionable_overflow_occurrences = legacy
            .actionable_overflow_occurrences
            .saturating_add(network.actionable_overflow_occurrences);
        let mut aggregate_groups_truncated =
            legacy.aggregate_groups_truncated || network.aggregate_groups_truncated;

        for aggregate in candidates {
            let serialized_len = serialized_signature_len(&aggregate.signature);
            if retained.len() < MAX_VERBOSE_LOGGING_GROUPS
                && retained_bytes.saturating_add(serialized_len)
                    <= MAX_VERBOSE_LOGGING_SIGNATURE_BYTES
            {
                retained_bytes = retained_bytes.saturating_add(serialized_len);
                retained.push(aggregate);
            } else {
                overflow_occurrences = overflow_occurrences.saturating_add(aggregate.count);
                if aggregate.signature.reason.is_actionable() {
                    actionable_overflow_occurrences =
                        actionable_overflow_occurrences.saturating_add(aggregate.count);
                }
                aggregate_groups_truncated = true;
            }
        }
        retained.sort_by(|left, right| left.signature.cmp(&right.signature));

        Self {
            version: CAPTURE_VERBOSE_LOGGING_VERSION,
            signatures: retained,
            summary: CaptureVerboseLoggingDocumentSummary {
                total_occurrences: legacy
                    .total_occurrences
                    .saturating_add(network.total_occurrences),
                overflow_occurrences,
                actionable_overflow_occurrences,
                aggregate_groups_truncated,
                processed_events_truncated: legacy.processed_events_truncated
                    || network.processed_events_truncated,
                actionable_limit_reached: legacy.actionable_limit_reached
                    || network.actionable_limit_reached,
            },
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct CaptureAnalysis {
    pub(crate) denials: Vec<super::DeniedResource>,
    pub(crate) denied_resources_truncated: bool,
    pub(crate) verbose_logging: VerboseLoggingSummary,
    pub(crate) network_verbose_logging: CaptureVerboseLoggingSummary,
}

impl CaptureAnalysis {
    pub(crate) fn into_legacy(mut self) -> AnalysisResult {
        let omitted = self.network_verbose_logging.total_occurrences;
        if omitted > 0 {
            self.verbose_logging.total_occurrences = self
                .verbose_logging
                .total_occurrences
                .saturating_add(omitted);
            self.verbose_logging.overflow_occurrences = self
                .verbose_logging
                .overflow_occurrences
                .saturating_add(omitted);
            self.verbose_logging.actionable_overflow_occurrences = self
                .verbose_logging
                .actionable_overflow_occurrences
                .saturating_add(self.network_verbose_logging.actionable_occurrences());
            self.verbose_logging.aggregate_groups_truncated = true;
            self.verbose_logging.processed_events_truncated |=
                self.network_verbose_logging.processed_events_truncated;
            self.verbose_logging.actionable_limit_reached |=
                self.network_verbose_logging.actionable_limit_reached;
        }
        AnalysisResult {
            denials: self.denials,
            denied_resources_truncated: self.denied_resources_truncated,
            verbose_logging: self.verbose_logging,
        }
    }

    #[allow(dead_code)] // Consumed by the stacked product-output integration.
    pub(crate) fn verbose_document(&self) -> CaptureVerboseLoggingDocument {
        CaptureVerboseLoggingDocument::new(&self.verbose_logging, &self.network_verbose_logging)
    }
}

#[allow(dead_code)] // Consumed by the stacked product-output integration.
pub(crate) fn write_capture_verbose_logging_document<W: Write>(
    writer: &mut W,
    document: &CaptureVerboseLoggingDocument,
) -> io::Result<()> {
    serde_json::to_writer_pretty(&mut *writer, document).map_err(io::Error::other)?;
    writer.write_all(b"\n")?;
    writer.flush()
}

pub(crate) fn parse_supported_verbose_document(
    bytes: &[u8],
) -> Result<CaptureVerboseLoggingDocument, serde_json::Error> {
    let document: CaptureVerboseLoggingDocument = serde_json::from_slice(bytes)?;
    if matches!(document.version, 3 | 4 | CAPTURE_VERBOSE_LOGGING_VERSION) {
        Ok(document)
    } else {
        Err(<serde_json::Error as serde::de::Error>::custom(
            "unsupported verbose logging document version",
        ))
    }
}

#[allow(dead_code)] // Used when the product-output integration builds v5.
fn convert_legacy_aggregate(aggregate: &VerboseLoggingAggregate) -> CaptureVerboseLoggingAggregate {
    CaptureVerboseLoggingAggregate {
        signature: CaptureVerboseLoggingSignature {
            provider: match aggregate.signature.provider {
                VerboseLoggingProvider::KernelGeneral => {
                    CaptureVerboseLoggingProvider::KernelGeneral
                }
                VerboseLoggingProvider::PrivacyAuditingPermissiveLearningMode => {
                    CaptureVerboseLoggingProvider::PrivacyAuditingPermissiveLearningMode
                }
            },
            provider_guid: aggregate.signature.provider_guid.clone(),
            event_id: aggregate.signature.event_id,
            event_name: None,
            reason: convert_legacy_reason(aggregate.signature.reason),
            pid: aggregate.signature.pid,
            access_type: aggregate.signature.access_type,
            resource_type: aggregate.signature.resource_type,
            network_decision_reason: None,
            configuration_recommendation: None,
            network_endpoint: None,
            properties: aggregate.signature.properties.clone(),
        },
        count: aggregate.count,
    }
}

#[allow(dead_code)] // Used when the product-output integration builds v5.
fn convert_legacy_reason(
    reason: VerboseLoggingOutcomeReason,
) -> CaptureVerboseLoggingOutcomeReason {
    match reason {
        VerboseLoggingOutcomeReason::Actionable => CaptureVerboseLoggingOutcomeReason::Actionable,
        VerboseLoggingOutcomeReason::UnsupportedEventSchema => {
            CaptureVerboseLoggingOutcomeReason::UnsupportedEventSchema
        }
        VerboseLoggingOutcomeReason::EventPayloadMalformed => {
            CaptureVerboseLoggingOutcomeReason::EventPayloadMalformed
        }
        VerboseLoggingOutcomeReason::DecoderLimitReached => {
            CaptureVerboseLoggingOutcomeReason::DecoderLimitReached
        }
        VerboseLoggingOutcomeReason::UnsupportedPropertyEncoding => {
            CaptureVerboseLoggingOutcomeReason::UnsupportedPropertyEncoding
        }
        VerboseLoggingOutcomeReason::MissingObjectType => {
            CaptureVerboseLoggingOutcomeReason::MissingObjectType
        }
        VerboseLoggingOutcomeReason::MissingObjectName => {
            CaptureVerboseLoggingOutcomeReason::MissingObjectName
        }
        VerboseLoggingOutcomeReason::UnsupportedObjectType => {
            CaptureVerboseLoggingOutcomeReason::UnsupportedObjectType
        }
        VerboseLoggingOutcomeReason::UnusableResourcePath => {
            CaptureVerboseLoggingOutcomeReason::UnusableResourcePath
        }
        VerboseLoggingOutcomeReason::UnresolvedCapability => {
            CaptureVerboseLoggingOutcomeReason::UnresolvedCapability
        }
        VerboseLoggingOutcomeReason::ComActivation => {
            CaptureVerboseLoggingOutcomeReason::ComActivation
        }
        VerboseLoggingOutcomeReason::ComInterfaceCall => {
            CaptureVerboseLoggingOutcomeReason::ComInterfaceCall
        }
        VerboseLoggingOutcomeReason::NotActionable => {
            CaptureVerboseLoggingOutcomeReason::NotActionable
        }
    }
}

fn serialized_signature_len(signature: &CaptureVerboseLoggingSignature) -> usize {
    serde_json::to_vec(&CaptureVerboseLoggingAggregate {
        signature: signature.clone(),
        count: 1,
    })
    .map_or(usize::MAX, |bytes| bytes.len())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::learning_mode_core::{
        DeniedResource, VerboseLoggingDocument, VerboseLoggingSignature,
    };

    fn network_signature(
        reason: CaptureVerboseLoggingOutcomeReason,
    ) -> CaptureVerboseLoggingSignature {
        CaptureVerboseLoggingSignature {
            provider: CaptureVerboseLoggingProvider::LearningModeNetworkDecision,
            provider_guid: "{71237669-21C3-4101-BD2F-FF38945D725A}".to_string(),
            event_id: 1,
            event_name: Some("NetworkDecisionV1".to_string()),
            reason,
            pid: 0,
            access_type: Some(AccessType::Unknown),
            resource_type: Some(ResourceType::Network),
            network_decision_reason: Some(NetworkDecisionReason::DirectDefaultDeny),
            configuration_recommendation: Some(ConfigurationRecommendation::AddEgressAllow),
            network_endpoint: Some(NetworkEndpoint {
                protocol: "tcp".to_string(),
                remote_address: "203.0.113.10".to_string(),
                remote_port: Some(443),
            }),
            properties: Vec::new(),
        }
    }

    #[test]
    fn legacy_projection_keeps_denial_and_counts_network_diagnostic_as_overflow() {
        let mut network = CaptureVerboseLoggingSummary::default();
        let mut bytes = 0;
        network.record_with_byte_budget(
            network_signature(CaptureVerboseLoggingOutcomeReason::Actionable),
            &mut bytes,
            MAX_VERBOSE_LOGGING_SIGNATURE_BYTES,
        );
        let analysis = CaptureAnalysis {
            denials: vec![DeniedResource {
                resource: "tcp://203.0.113.10:443".to_string(),
                resource_type: ResourceType::Network,
                access_type: AccessType::Unknown,
                pid: 0,
                filetime: 123,
            }],
            denied_resources_truncated: false,
            verbose_logging: VerboseLoggingSummary::default(),
            network_verbose_logging: network,
        };

        let legacy = analysis.into_legacy();
        assert_eq!(legacy.denials.len(), 1);
        assert!(legacy.verbose_logging.signatures.is_empty());
        assert_eq!(legacy.verbose_logging.total_occurrences, 1);
        assert_eq!(legacy.verbose_logging.overflow_occurrences, 1);
        assert_eq!(legacy.verbose_logging.actionable_overflow_occurrences, 1);
        assert!(legacy.verbose_logging.aggregate_groups_truncated);
    }

    #[test]
    fn version_five_document_merges_legacy_and_network_groups() {
        let legacy = VerboseLoggingSummary {
            signatures: vec![VerboseLoggingAggregate {
                signature: VerboseLoggingSignature {
                    provider: VerboseLoggingProvider::KernelGeneral,
                    provider_guid: "kernel".to_string(),
                    event_id: 14,
                    reason: VerboseLoggingOutcomeReason::Actionable,
                    pid: 42,
                    access_type: Some(AccessType::Read),
                    resource_type: Some(ResourceType::File),
                    properties: Vec::new(),
                },
                count: 2,
            }],
            total_occurrences: 2,
            ..Default::default()
        };
        let mut network = CaptureVerboseLoggingSummary::default();
        let mut bytes = 0;
        network.record_with_byte_budget(
            network_signature(CaptureVerboseLoggingOutcomeReason::Actionable),
            &mut bytes,
            MAX_VERBOSE_LOGGING_SIGNATURE_BYTES,
        );

        let document = CaptureVerboseLoggingDocument::new(&legacy, &network);
        assert_eq!(document.version, CAPTURE_VERBOSE_LOGGING_VERSION);
        assert_eq!(document.signatures.len(), 2);
        assert_eq!(document.summary.total_occurrences, 3);
        let network = document
            .signatures
            .iter()
            .find(|aggregate| {
                aggregate.signature.provider
                    == CaptureVerboseLoggingProvider::LearningModeNetworkDecision
            })
            .unwrap();
        assert_eq!(
            network.signature.configuration_recommendation,
            Some(ConfigurationRecommendation::AddEgressAllow)
        );
    }

    #[test]
    fn parser_accepts_legacy_and_internal_versions() {
        let legacy = VerboseLoggingDocument::new(&VerboseLoggingSummary::default());
        let legacy_bytes = serde_json::to_vec(&legacy).unwrap();
        assert_eq!(
            parse_supported_verbose_document(&legacy_bytes)
                .unwrap()
                .version,
            VerboseLoggingDocument::VERSION
        );

        let internal = CaptureVerboseLoggingDocument::new(
            &VerboseLoggingSummary::default(),
            &CaptureVerboseLoggingSummary::default(),
        );
        let internal_bytes = serde_json::to_vec(&internal).unwrap();
        assert_eq!(
            parse_supported_verbose_document(&internal_bytes)
                .unwrap()
                .version,
            CAPTURE_VERBOSE_LOGGING_VERSION
        );
    }
}
