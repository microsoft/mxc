// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Crate-internal diagnostics used by MXC capture paths.

use std::io::{self, Write};

use serde::{Deserialize, Serialize};

use super::{
    AccessType, AnalysisResult, ResourceType, VerboseLoggingAggregate, VerboseLoggingOutcomeReason,
    VerboseLoggingProvider, VerboseLoggingSignature, VerboseLoggingSummary,
    MAX_VERBOSE_LOGGING_GROUPS, MAX_VERBOSE_LOGGING_SIGNATURE_BYTES,
};

/// Verbose document version owned by the WFP diagnostic extension.
pub(crate) const CAPTURE_VERBOSE_LOGGING_VERSION: u32 = 5;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) enum CaptureVerboseLoggingProvider {
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
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct NetworkEndpoint {
    pub(crate) protocol: String,
    pub(crate) remote_address: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) remote_port: Option<u16>,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
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
#[serde(rename_all = "camelCase", deny_unknown_fields)]
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
    #[cfg_attr(not(target_os = "windows"), allow(dead_code))]
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

        let actionable = signature.reason.is_actionable();
        let can_evict = actionable
            && self
                .signatures
                .iter()
                .any(|group| !group.signature.reason.is_actionable());
        if (self.signatures.len() >= MAX_VERBOSE_LOGGING_GROUPS || *retained_bytes >= max_bytes)
            && !can_evict
        {
            self.record_overflow(actionable, 1);
            return;
        }

        let serialized_len = serialized_signature_len(&signature);
        if serialized_len > max_bytes {
            self.record_overflow(actionable, 1);
            return;
        }
        while self.signatures.len() >= MAX_VERBOSE_LOGGING_GROUPS
            || retained_bytes.saturating_add(serialized_len) > max_bytes
        {
            if !actionable || !self.evict_one_nonactionable_group(retained_bytes) {
                self.record_overflow(actionable, 1);
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

    #[cfg_attr(not(target_os = "windows"), allow(dead_code))]
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

    #[cfg_attr(not(target_os = "windows"), allow(dead_code))]
    fn record_overflow(&mut self, actionable: bool, count: u64) {
        self.total_occurrences = self.total_occurrences.saturating_add(count);
        self.overflow_occurrences = self.overflow_occurrences.saturating_add(count);
        if actionable {
            self.actionable_overflow_occurrences =
                self.actionable_overflow_occurrences.saturating_add(count);
        }
        self.aggregate_groups_truncated = true;
    }

    #[cfg_attr(not(target_os = "windows"), allow(dead_code))]
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
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct CaptureVerboseLoggingDocument {
    pub(crate) version: u32,
    pub(crate) signatures: Vec<CaptureVerboseLoggingAggregate>,
    pub(crate) summary: CaptureVerboseLoggingDocumentSummary,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
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
    #[cfg_attr(not(target_os = "windows"), allow(dead_code))]
    pub(crate) fn into_legacy(mut self) -> AnalysisResult {
        for aggregate in self.network_verbose_logging.signatures {
            if let Some(signature) = Self::capture_signature_to_legacy(&aggregate.signature) {
                Self::merge_legacy_aggregate(&mut self.verbose_logging, signature, aggregate.count);
            } else {
                self.verbose_logging.total_occurrences = self
                    .verbose_logging
                    .total_occurrences
                    .saturating_add(aggregate.count);
                self.verbose_logging.overflow_occurrences = self
                    .verbose_logging
                    .overflow_occurrences
                    .saturating_add(aggregate.count);
                if aggregate.signature.reason.is_actionable() {
                    self.verbose_logging.actionable_overflow_occurrences = self
                        .verbose_logging
                        .actionable_overflow_occurrences
                        .saturating_add(aggregate.count);
                }
                self.verbose_logging.aggregate_groups_truncated = true;
            }
        }
        self.verbose_logging.total_occurrences = self
            .verbose_logging
            .total_occurrences
            .saturating_add(self.network_verbose_logging.overflow_occurrences);
        self.verbose_logging.overflow_occurrences = self
            .verbose_logging
            .overflow_occurrences
            .saturating_add(self.network_verbose_logging.overflow_occurrences);
        self.verbose_logging.actionable_overflow_occurrences = self
            .verbose_logging
            .actionable_overflow_occurrences
            .saturating_add(self.network_verbose_logging.actionable_overflow_occurrences);
        self.verbose_logging.aggregate_groups_truncated |=
            self.network_verbose_logging.aggregate_groups_truncated;
        self.verbose_logging.processed_events_truncated |=
            self.network_verbose_logging.processed_events_truncated;
        self.verbose_logging.actionable_limit_reached |=
            self.network_verbose_logging.actionable_limit_reached;
        AnalysisResult {
            denials: self.denials,
            denied_resources_truncated: self.denied_resources_truncated,
            verbose_logging: self.verbose_logging,
        }
    }

    #[cfg_attr(not(target_os = "windows"), allow(dead_code))]
    fn capture_signature_to_legacy(
        signature: &CaptureVerboseLoggingSignature,
    ) -> Option<VerboseLoggingSignature> {
        let provider = match signature.provider {
            CaptureVerboseLoggingProvider::KernelGeneral => VerboseLoggingProvider::KernelGeneral,
            CaptureVerboseLoggingProvider::PrivacyAuditingPermissiveLearningMode => {
                VerboseLoggingProvider::PrivacyAuditingPermissiveLearningMode
            }
            CaptureVerboseLoggingProvider::LearningModeNetworkDecision => return None,
        };
        let reason = match signature.reason {
            CaptureVerboseLoggingOutcomeReason::Actionable => {
                VerboseLoggingOutcomeReason::Actionable
            }
            CaptureVerboseLoggingOutcomeReason::UnsupportedEventSchema => {
                VerboseLoggingOutcomeReason::UnsupportedEventSchema
            }
            CaptureVerboseLoggingOutcomeReason::SchemaUnavailable
            | CaptureVerboseLoggingOutcomeReason::IntentionalNetworkPolicyDeny
            | CaptureVerboseLoggingOutcomeReason::ProxyContainment
            | CaptureVerboseLoggingOutcomeReason::UnknownNetworkReason
            | CaptureVerboseLoggingOutcomeReason::IncompleteNetworkEndpoint => return None,
            CaptureVerboseLoggingOutcomeReason::EventPayloadMalformed => {
                VerboseLoggingOutcomeReason::EventPayloadMalformed
            }
            CaptureVerboseLoggingOutcomeReason::DecoderLimitReached => {
                VerboseLoggingOutcomeReason::DecoderLimitReached
            }
            CaptureVerboseLoggingOutcomeReason::UnsupportedPropertyEncoding => {
                VerboseLoggingOutcomeReason::UnsupportedPropertyEncoding
            }
            CaptureVerboseLoggingOutcomeReason::MissingObjectType => {
                VerboseLoggingOutcomeReason::MissingObjectType
            }
            CaptureVerboseLoggingOutcomeReason::MissingObjectName => {
                VerboseLoggingOutcomeReason::MissingObjectName
            }
            CaptureVerboseLoggingOutcomeReason::UnsupportedObjectType => {
                VerboseLoggingOutcomeReason::UnsupportedObjectType
            }
            CaptureVerboseLoggingOutcomeReason::UnusableResourcePath => {
                VerboseLoggingOutcomeReason::UnusableResourcePath
            }
            CaptureVerboseLoggingOutcomeReason::UnresolvedCapability => {
                VerboseLoggingOutcomeReason::UnresolvedCapability
            }
            CaptureVerboseLoggingOutcomeReason::ComActivation => {
                VerboseLoggingOutcomeReason::ComActivation
            }
            CaptureVerboseLoggingOutcomeReason::ComInterfaceCall => {
                VerboseLoggingOutcomeReason::ComInterfaceCall
            }
            CaptureVerboseLoggingOutcomeReason::NotActionable => {
                VerboseLoggingOutcomeReason::NotActionable
            }
        };
        Some(VerboseLoggingSignature {
            provider,
            provider_guid: signature.provider_guid.clone(),
            event_id: signature.event_id,
            reason,
            pid: signature.pid,
            access_type: signature.access_type,
            resource_type: signature.resource_type,
            properties: signature.properties.clone(),
        })
    }

    #[cfg_attr(not(target_os = "windows"), allow(dead_code))]
    fn merge_legacy_aggregate(
        summary: &mut VerboseLoggingSummary,
        signature: VerboseLoggingSignature,
        count: u64,
    ) {
        let total_before = summary.total_occurrences;
        let overflow_before = summary.overflow_occurrences;
        summary.record(signature.clone());
        let additional = count.saturating_sub(1);
        if summary.overflow_occurrences > overflow_before {
            summary.total_occurrences = summary.total_occurrences.saturating_add(additional);
            summary.overflow_occurrences = summary.overflow_occurrences.saturating_add(additional);
            if signature.reason.is_actionable() {
                summary.actionable_overflow_occurrences = summary
                    .actionable_overflow_occurrences
                    .saturating_add(additional);
            }
        } else if let Ok(index) = summary
            .signatures
            .binary_search_by(|group| group.signature.cmp(&signature))
        {
            summary.total_occurrences = summary.total_occurrences.saturating_add(additional);
            summary.signatures[index].count =
                summary.signatures[index].count.saturating_add(additional);
        } else {
            debug_assert_eq!(summary.total_occurrences, total_before);
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
    let envelope: VerboseDocumentVersion = serde_json::from_slice(bytes)?;
    match envelope.version {
        3 => serde_json::from_slice::<VersionedVerboseDocument<Version3Signature>>(bytes)
            .map(normalize_version3_document),
        4 => serde_json::from_slice::<VersionedVerboseDocument<Version4Signature>>(bytes)
            .map(normalize_version4_document),
        CAPTURE_VERBOSE_LOGGING_VERSION => serde_json::from_slice(bytes),
        _ => Err(<serde_json::Error as serde::de::Error>::custom(
            "unsupported verbose logging document version",
        )),
    }
}

#[derive(Deserialize)]
struct VerboseDocumentVersion {
    version: u32,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct VersionedVerboseDocument<S> {
    version: u32,
    signatures: Vec<VersionedVerboseAggregate<S>>,
    summary: CaptureVerboseLoggingDocumentSummary,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct VersionedVerboseAggregate<S> {
    signature: S,
    count: u64,
}

#[derive(Clone, Copy, Deserialize)]
#[serde(rename_all = "camelCase")]
enum Version3Provider {
    KernelGeneral,
    PrivacyAuditingPermissiveLearningMode,
}

#[derive(Clone, Copy, Deserialize)]
#[serde(rename_all = "camelCase")]
enum Version4Provider {
    KernelGeneral,
    PrivacyAuditingPermissiveLearningMode,
    LearningModeNetworkDecision,
}

#[derive(Clone, Copy, Deserialize)]
#[serde(rename_all = "camelCase")]
enum Version3Reason {
    Actionable,
    UnsupportedEventSchema,
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
}

#[derive(Clone, Copy, Deserialize)]
#[serde(rename_all = "camelCase")]
enum Version4Reason {
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
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Version3Signature {
    provider: Version3Provider,
    provider_guid: String,
    event_id: u16,
    reason: Version3Reason,
    pid: u32,
    #[serde(default)]
    access_type: Option<AccessType>,
    #[serde(default)]
    resource_type: Option<ResourceType>,
    properties: Vec<(String, String)>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Version4Signature {
    provider: Version4Provider,
    provider_guid: String,
    event_id: u16,
    #[serde(default)]
    event_name: Option<String>,
    reason: Version4Reason,
    pid: u32,
    #[serde(default)]
    access_type: Option<AccessType>,
    #[serde(default)]
    resource_type: Option<ResourceType>,
    properties: Vec<(String, String)>,
}

fn normalize_version3_document(
    document: VersionedVerboseDocument<Version3Signature>,
) -> CaptureVerboseLoggingDocument {
    CaptureVerboseLoggingDocument {
        version: document.version,
        signatures: document
            .signatures
            .into_iter()
            .map(|aggregate| CaptureVerboseLoggingAggregate {
                signature: CaptureVerboseLoggingSignature {
                    provider: match aggregate.signature.provider {
                        Version3Provider::KernelGeneral => {
                            CaptureVerboseLoggingProvider::KernelGeneral
                        }
                        Version3Provider::PrivacyAuditingPermissiveLearningMode => {
                            CaptureVerboseLoggingProvider::PrivacyAuditingPermissiveLearningMode
                        }
                    },
                    provider_guid: aggregate.signature.provider_guid,
                    event_id: aggregate.signature.event_id,
                    event_name: None,
                    reason: normalize_version3_reason(aggregate.signature.reason),
                    pid: aggregate.signature.pid,
                    access_type: aggregate.signature.access_type,
                    resource_type: aggregate.signature.resource_type,
                    network_decision_reason: None,
                    configuration_recommendation: None,
                    network_endpoint: None,
                    properties: aggregate.signature.properties,
                },
                count: aggregate.count,
            })
            .collect(),
        summary: document.summary,
    }
}

fn normalize_version4_document(
    document: VersionedVerboseDocument<Version4Signature>,
) -> CaptureVerboseLoggingDocument {
    CaptureVerboseLoggingDocument {
        version: document.version,
        signatures: document
            .signatures
            .into_iter()
            .map(|aggregate| CaptureVerboseLoggingAggregate {
                signature: CaptureVerboseLoggingSignature {
                    provider: match aggregate.signature.provider {
                        Version4Provider::KernelGeneral => {
                            CaptureVerboseLoggingProvider::KernelGeneral
                        }
                        Version4Provider::PrivacyAuditingPermissiveLearningMode => {
                            CaptureVerboseLoggingProvider::PrivacyAuditingPermissiveLearningMode
                        }
                        Version4Provider::LearningModeNetworkDecision => {
                            CaptureVerboseLoggingProvider::LearningModeNetworkDecision
                        }
                    },
                    provider_guid: aggregate.signature.provider_guid,
                    event_id: aggregate.signature.event_id,
                    event_name: aggregate.signature.event_name,
                    reason: normalize_version4_reason(aggregate.signature.reason),
                    pid: aggregate.signature.pid,
                    access_type: aggregate.signature.access_type,
                    resource_type: aggregate.signature.resource_type,
                    network_decision_reason: None,
                    configuration_recommendation: None,
                    network_endpoint: None,
                    properties: aggregate.signature.properties,
                },
                count: aggregate.count,
            })
            .collect(),
        summary: document.summary,
    }
}

fn normalize_version3_reason(reason: Version3Reason) -> CaptureVerboseLoggingOutcomeReason {
    match reason {
        Version3Reason::Actionable => CaptureVerboseLoggingOutcomeReason::Actionable,
        Version3Reason::UnsupportedEventSchema => {
            CaptureVerboseLoggingOutcomeReason::UnsupportedEventSchema
        }
        Version3Reason::EventPayloadMalformed => {
            CaptureVerboseLoggingOutcomeReason::EventPayloadMalformed
        }
        Version3Reason::DecoderLimitReached => {
            CaptureVerboseLoggingOutcomeReason::DecoderLimitReached
        }
        Version3Reason::UnsupportedPropertyEncoding => {
            CaptureVerboseLoggingOutcomeReason::UnsupportedPropertyEncoding
        }
        Version3Reason::MissingObjectType => CaptureVerboseLoggingOutcomeReason::MissingObjectType,
        Version3Reason::MissingObjectName => CaptureVerboseLoggingOutcomeReason::MissingObjectName,
        Version3Reason::UnsupportedObjectType => {
            CaptureVerboseLoggingOutcomeReason::UnsupportedObjectType
        }
        Version3Reason::UnusableResourcePath => {
            CaptureVerboseLoggingOutcomeReason::UnusableResourcePath
        }
        Version3Reason::UnresolvedCapability => {
            CaptureVerboseLoggingOutcomeReason::UnresolvedCapability
        }
        Version3Reason::ComActivation => CaptureVerboseLoggingOutcomeReason::ComActivation,
        Version3Reason::ComInterfaceCall => CaptureVerboseLoggingOutcomeReason::ComInterfaceCall,
        Version3Reason::NotActionable => CaptureVerboseLoggingOutcomeReason::NotActionable,
    }
}

fn normalize_version4_reason(reason: Version4Reason) -> CaptureVerboseLoggingOutcomeReason {
    match reason {
        Version4Reason::SchemaUnavailable => CaptureVerboseLoggingOutcomeReason::SchemaUnavailable,
        Version4Reason::Actionable => CaptureVerboseLoggingOutcomeReason::Actionable,
        Version4Reason::UnsupportedEventSchema => {
            CaptureVerboseLoggingOutcomeReason::UnsupportedEventSchema
        }
        Version4Reason::EventPayloadMalformed => {
            CaptureVerboseLoggingOutcomeReason::EventPayloadMalformed
        }
        Version4Reason::DecoderLimitReached => {
            CaptureVerboseLoggingOutcomeReason::DecoderLimitReached
        }
        Version4Reason::UnsupportedPropertyEncoding => {
            CaptureVerboseLoggingOutcomeReason::UnsupportedPropertyEncoding
        }
        Version4Reason::MissingObjectType => CaptureVerboseLoggingOutcomeReason::MissingObjectType,
        Version4Reason::MissingObjectName => CaptureVerboseLoggingOutcomeReason::MissingObjectName,
        Version4Reason::UnsupportedObjectType => {
            CaptureVerboseLoggingOutcomeReason::UnsupportedObjectType
        }
        Version4Reason::UnusableResourcePath => {
            CaptureVerboseLoggingOutcomeReason::UnusableResourcePath
        }
        Version4Reason::UnresolvedCapability => {
            CaptureVerboseLoggingOutcomeReason::UnresolvedCapability
        }
        Version4Reason::ComActivation => CaptureVerboseLoggingOutcomeReason::ComActivation,
        Version4Reason::ComInterfaceCall => CaptureVerboseLoggingOutcomeReason::ComInterfaceCall,
        Version4Reason::NotActionable => CaptureVerboseLoggingOutcomeReason::NotActionable,
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
    fn individually_oversized_actionable_signature_does_not_evict_diagnostic() {
        let mut summary = CaptureVerboseLoggingSummary::default();
        let mut bytes = 0;
        let mut diagnostic =
            network_signature(CaptureVerboseLoggingOutcomeReason::UnsupportedEventSchema);
        diagnostic.event_id = 999;
        summary.record_with_byte_budget(diagnostic, &mut bytes, 512);

        let mut oversized = network_signature(CaptureVerboseLoggingOutcomeReason::Actionable);
        oversized.properties = vec![("Large".to_string(), "x".repeat(1_024))];
        summary.record_with_byte_budget(oversized, &mut bytes, 512);

        assert_eq!(summary.signatures.len(), 1);
        assert_eq!(summary.signatures[0].signature.event_id, 999);
        assert_eq!(summary.overflow_occurrences, 1);
        assert_eq!(summary.actionable_overflow_occurrences, 1);
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

    #[test]
    fn parser_accepts_the_exact_version_four_vocabulary() {
        let document = serde_json::json!({
            "version": 4,
            "signatures": [{
                "signature": {
                    "provider": "learningModeNetworkDecision",
                    "providerGuid": "{71237669-21C3-4101-BD2F-FF38945D725A}",
                    "eventId": 1,
                    "eventName": "NetworkDecisionV1",
                    "reason": "schemaUnavailable",
                    "pid": 0,
                    "properties": []
                },
                "count": 1
            }],
            "summary": {
                "totalOccurrences": 1,
                "overflowOccurrences": 0,
                "actionableOverflowOccurrences": 0,
                "aggregateGroupsTruncated": false,
                "processedEventsTruncated": false,
                "actionableLimitReached": false
            }
        });

        let parsed = parse_supported_verbose_document(&serde_json::to_vec(&document).unwrap())
            .expect("version four document should parse");

        assert_eq!(parsed.version, 4);
        assert_eq!(
            parsed.signatures[0].signature.provider,
            CaptureVerboseLoggingProvider::LearningModeNetworkDecision
        );
        assert_eq!(
            parsed.signatures[0].signature.reason,
            CaptureVerboseLoggingOutcomeReason::SchemaUnavailable
        );
        assert_eq!(
            parsed.signatures[0].signature.event_name.as_deref(),
            Some("NetworkDecisionV1")
        );
    }

    #[test]
    fn parser_rejects_cross_version_and_unknown_vocabulary() {
        let summary = serde_json::json!({
            "totalOccurrences": 1,
            "overflowOccurrences": 0,
            "actionableOverflowOccurrences": 0,
            "aggregateGroupsTruncated": false,
            "processedEventsTruncated": false,
            "actionableLimitReached": false
        });
        let base_signature = serde_json::json!({
            "provider": "kernelGeneral",
            "providerGuid": "{A68CA8B7-004F-D7B6-A698-07E2DE0F1F5D}",
            "eventId": 14,
            "reason": "actionable",
            "pid": 42,
            "properties": []
        });
        let document = |version, signature: serde_json::Value| {
            serde_json::json!({
                "version": version,
                "signatures": [{"signature": signature, "count": 1}],
                "summary": summary
            })
        };

        let mut version3_event_name = base_signature.clone();
        version3_event_name["eventName"] = serde_json::json!("AccessCheck");
        assert!(parse_supported_verbose_document(
            &serde_json::to_vec(&document(3, version3_event_name)).unwrap()
        )
        .is_err());

        let mut version3_provider = base_signature.clone();
        version3_provider["provider"] = serde_json::json!("learningModeNetworkDecision");
        assert!(parse_supported_verbose_document(
            &serde_json::to_vec(&document(3, version3_provider)).unwrap()
        )
        .is_err());

        let mut version4_network_field = base_signature.clone();
        version4_network_field["networkDecisionReason"] = serde_json::json!("directDefaultDeny");
        assert!(parse_supported_verbose_document(
            &serde_json::to_vec(&document(4, version4_network_field)).unwrap()
        )
        .is_err());

        let mut version4_reason = base_signature.clone();
        version4_reason["reason"] = serde_json::json!("proxyContainment");
        assert!(parse_supported_verbose_document(
            &serde_json::to_vec(&document(4, version4_reason)).unwrap()
        )
        .is_err());

        let mut version5_unknown =
            network_signature(CaptureVerboseLoggingOutcomeReason::Actionable);
        version5_unknown.properties.clear();
        let mut version5 = serde_json::to_value(CaptureVerboseLoggingDocument {
            version: CAPTURE_VERBOSE_LOGGING_VERSION,
            signatures: vec![CaptureVerboseLoggingAggregate {
                signature: version5_unknown,
                count: 1,
            }],
            summary: CaptureVerboseLoggingDocumentSummary {
                total_occurrences: 1,
                overflow_occurrences: 0,
                actionable_overflow_occurrences: 0,
                aggregate_groups_truncated: false,
                processed_events_truncated: false,
                actionable_limit_reached: false,
            },
        })
        .unwrap();
        version5["signatures"][0]["signature"]["futureField"] = serde_json::json!(true);
        assert!(parse_supported_verbose_document(&serde_json::to_vec(&version5).unwrap()).is_err());
    }

    #[test]
    fn saturated_nonactionable_summary_moves_new_groups_directly_to_overflow() {
        let mut summary = CaptureVerboseLoggingSummary::default();
        let mut retained_bytes = 0;
        for event_id in 0..MAX_VERBOSE_LOGGING_GROUPS {
            let mut signature =
                network_signature(CaptureVerboseLoggingOutcomeReason::UnknownNetworkReason);
            signature.event_id = u16::try_from(event_id).unwrap();
            summary.record_with_byte_budget(
                signature,
                &mut retained_bytes,
                MAX_VERBOSE_LOGGING_SIGNATURE_BYTES,
            );
        }
        let retained_bytes_before = retained_bytes;
        let mut overflow =
            network_signature(CaptureVerboseLoggingOutcomeReason::UnknownNetworkReason);
        overflow.event_id = u16::MAX;

        summary.record_with_byte_budget(
            overflow,
            &mut retained_bytes,
            MAX_VERBOSE_LOGGING_SIGNATURE_BYTES,
        );

        assert_eq!(summary.signatures.len(), MAX_VERBOSE_LOGGING_GROUPS);
        assert_eq!(summary.overflow_occurrences, 1);
        assert_eq!(retained_bytes, retained_bytes_before);
    }
}
