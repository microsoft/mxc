// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Extractors for the OS-managed Learning Mode WFP decision event.

use crate::learning_mode_core::{
    capture_diagnostics::{
        CaptureVerboseLoggingOutcomeReason, ConfigurationRecommendation, NetworkDecisionReason,
        NetworkEndpoint,
    },
    AccessType, ResourceType,
};
use std::net::IpAddr;
use windows::core::GUID;

use super::extractors::{sanitize_properties, DecodedEventParts, RawDenial};

pub(crate) const NETWORK_DECISION_PROVIDER: GUID = GUID {
    data1: 0x7123_7669,
    data2: 0x21c3,
    data3: 0x4101,
    data4: [0xbd, 0x2f, 0xff, 0x38, 0x94, 0x5d, 0x72, 0x5a],
};
pub(crate) const NETWORK_DECISION_EVENT_ID: u16 = 1;

const SCHEMA_VERSION_V1: u16 = 1;
const SOURCE_APP_ISOLATION: u8 = 1;
const SOURCE_TESSERA: u8 = 2;
const MODE_LEARNING: u8 = 1;
const DECISION_DENY: u8 = 1;

const REASON_APP_ISOLATION_MISSING_CAPABILITY: u16 = 1;
const REASON_TESSERA_DIRECT_DEFAULT_DENY: u16 = 100;
const REASON_TESSERA_EXPLICIT_DENY: u16 = 101;
const REASON_TESSERA_ALLOW_EXCLUSION: u16 = 102;
const REASON_TESSERA_PROXY_CONTAINMENT: u16 = 103;

const FIELD_APPLICATION_ID: u32 = 1 << 0;
const FIELD_PROTOCOL: u32 = 1 << 1;
const FIELD_LOCAL_ADDRESS: u32 = 1 << 2;
const FIELD_LOCAL_PORT: u32 = 1 << 3;
const FIELD_REMOTE_ADDRESS: u32 = 1 << 4;
const FIELD_REMOTE_PORT: u32 = 1 << 5;
const FIELD_CAPABILITY_ID: u32 = 1 << 6;

const TESSERA_PROVIDER: &str = "{2F8C6D14-3B7E-4A59-9C08-1D4E7A6B2F30}";
const TESSERA_SUBLAYER: &str = "{7B1E9A2C-9D4F-4C8A-B321-5E6D2F8A1C44}";
const APP_ISOLATION_SUBLAYER: &str = "{FFE221C3-92A8-4564-A59F-DAFB70756020}";

const NETWORK_DECISION_V1_FIELDS: [&str; 24] = [
    "SchemaVersion",
    "SourceDomain",
    "Mode",
    "NormalDecision",
    "EffectiveDecision",
    "Reason",
    "FieldFlags",
    "OriginalTimestamp",
    "UserSid",
    "PackageSid",
    "ApplicationId",
    "WfpEventType",
    "FilterId",
    "ProviderGuid",
    "SublayerGuid",
    "LayerId",
    "Direction",
    "IsLoopback",
    "Protocol",
    "LocalAddress",
    "LocalPort",
    "RemoteAddress",
    "RemotePort",
    "CapabilityId",
];

pub(crate) struct NetworkDecisionAnalysis {
    pub(crate) denial: Option<RawDenial>,
    pub(crate) reason: CaptureVerboseLoggingOutcomeReason,
    pub(crate) network_decision_reason: Option<NetworkDecisionReason>,
    pub(crate) configuration_recommendation: Option<ConfigurationRecommendation>,
    pub(crate) network_endpoint: Option<NetworkEndpoint>,
    pub(crate) classification: (Option<AccessType>, Option<ResourceType>),
    pub(crate) properties: Vec<(String, String)>,
}

pub(crate) fn analyze_network_decision(parts: &DecodedEventParts) -> NetworkDecisionAnalysis {
    let properties = sanitize_properties(&parts.props);
    match analyze_network_decision_inner(parts) {
        Ok(mut analysis) => {
            analysis.properties = properties;
            analysis
        }
        Err(reason) => NetworkDecisionAnalysis {
            denial: None,
            reason,
            network_decision_reason: None,
            configuration_recommendation: None,
            network_endpoint: None,
            classification: verbose_logging_classification(parts),
            properties,
        },
    }
}

fn analyze_network_decision_inner(
    parts: &DecodedEventParts,
) -> Result<NetworkDecisionAnalysis, CaptureVerboseLoggingOutcomeReason> {
    if parts.provider != NETWORK_DECISION_PROVIDER || parts.event_id != NETWORK_DECISION_EVENT_ID {
        return Err(CaptureVerboseLoggingOutcomeReason::UnsupportedEventSchema);
    }
    if !NETWORK_DECISION_V1_FIELDS
        .iter()
        .all(|name| property(parts, name).is_some())
    {
        return Err(CaptureVerboseLoggingOutcomeReason::UnsupportedEventSchema);
    }

    let schema_version = required_u16(parts, "SchemaVersion")?;
    let source_domain = required_u8(parts, "SourceDomain")?;
    let mode = required_u8(parts, "Mode")?;
    let normal_decision = required_u8(parts, "NormalDecision")?;
    let effective_decision = required_u8(parts, "EffectiveDecision")?;
    let reason = required_u16(parts, "Reason")?;
    let field_flags = required_u32(parts, "FieldFlags")?;
    let filetime = required_u64(parts, "OriginalTimestamp")?;
    let filter_id = required_u64(parts, "FilterId")?;

    if schema_version != SCHEMA_VERSION_V1
        || mode != MODE_LEARNING
        || normal_decision != DECISION_DENY
        || effective_decision != DECISION_DENY
        || filetime == 0
        || filter_id == 0
    {
        return Err(CaptureVerboseLoggingOutcomeReason::UnsupportedEventSchema);
    }

    match source_domain {
        SOURCE_APP_ISOLATION => {
            extract_app_isolation(parts, reason, field_flags, filetime, filter_id)
        }
        SOURCE_TESSERA => extract_tessera(parts, reason, field_flags, filetime, filter_id),
        _ => Err(CaptureVerboseLoggingOutcomeReason::UnknownNetworkReason),
    }
}

pub(crate) fn verbose_logging_classification(
    parts: &DecodedEventParts,
) -> (Option<AccessType>, Option<ResourceType>) {
    let source = property(parts, "SourceDomain").and_then(parse_u8);
    let reason = property(parts, "Reason").and_then(parse_u16);
    match (source, reason) {
        (Some(SOURCE_APP_ISOLATION), Some(REASON_APP_ISOLATION_MISSING_CAPABILITY)) => {
            (Some(AccessType::Unknown), Some(ResourceType::Capability))
        }
        (Some(SOURCE_TESSERA), _) => (Some(AccessType::Unknown), Some(ResourceType::Network)),
        _ => (None, None),
    }
}

fn extract_app_isolation(
    parts: &DecodedEventParts,
    reason: u16,
    field_flags: u32,
    filetime: u64,
    _filter_id: u64,
) -> Result<NetworkDecisionAnalysis, CaptureVerboseLoggingOutcomeReason> {
    if !property_eq(parts, "SublayerGuid", APP_ISOLATION_SUBLAYER) {
        return Err(CaptureVerboseLoggingOutcomeReason::UnsupportedEventSchema);
    }
    if reason != REASON_APP_ISOLATION_MISSING_CAPABILITY {
        return Err(CaptureVerboseLoggingOutcomeReason::UnknownNetworkReason);
    }
    if field_flags & FIELD_CAPABILITY_ID == 0 {
        return Ok(network_diagnostic(
            CaptureVerboseLoggingOutcomeReason::UnresolvedCapability,
            NetworkDecisionReason::AppIsolationMissingCapability,
            None,
            None,
            ResourceType::Capability,
        ));
    }
    let capability_id = match required_u32(parts, "CapabilityId") {
        Ok(capability_id) => capability_id,
        Err(reason) => {
            return Ok(network_diagnostic(
                reason,
                NetworkDecisionReason::AppIsolationMissingCapability,
                None,
                None,
                ResourceType::Capability,
            ));
        }
    };
    let capability = match capability_id {
        0 => "internetClient",
        1 => "internetClientServer",
        2 => "privateNetworkClientServer",
        _ => {
            return Ok(network_diagnostic(
                CaptureVerboseLoggingOutcomeReason::UnresolvedCapability,
                NetworkDecisionReason::AppIsolationMissingCapability,
                None,
                None,
                ResourceType::Capability,
            ));
        }
    };

    let denial = RawDenial {
        pid: 0,
        resource_type: ResourceType::Capability,
        object_name: capability.to_string(),
        access_type: AccessType::Unknown,
        filetime,
        event_id: parts.event_id,
        provider: None,
        verbose_logging_properties: Vec::new(),
    };
    Ok(NetworkDecisionAnalysis {
        denial: Some(denial),
        reason: CaptureVerboseLoggingOutcomeReason::Actionable,
        network_decision_reason: Some(NetworkDecisionReason::AppIsolationMissingCapability),
        configuration_recommendation: Some(ConfigurationRecommendation::AddCapability),
        network_endpoint: None,
        classification: (Some(AccessType::Unknown), Some(ResourceType::Capability)),
        properties: Vec::new(),
    })
}

fn extract_tessera(
    parts: &DecodedEventParts,
    reason: u16,
    field_flags: u32,
    filetime: u64,
    _filter_id: u64,
) -> Result<NetworkDecisionAnalysis, CaptureVerboseLoggingOutcomeReason> {
    if !property_eq(parts, "ProviderGuid", TESSERA_PROVIDER)
        || !property_eq(parts, "SublayerGuid", TESSERA_SUBLAYER)
        || field_flags & FIELD_CAPABILITY_ID != 0
    {
        return Err(CaptureVerboseLoggingOutcomeReason::UnsupportedEventSchema);
    }

    let (network_decision_reason, outcome_reason, recommendation) = match reason {
        REASON_TESSERA_DIRECT_DEFAULT_DENY => (
            NetworkDecisionReason::DirectDefaultDeny,
            CaptureVerboseLoggingOutcomeReason::Actionable,
            Some(ConfigurationRecommendation::AddEgressAllow),
        ),
        REASON_TESSERA_EXPLICIT_DENY => (
            NetworkDecisionReason::AuthoredExplicitDeny,
            CaptureVerboseLoggingOutcomeReason::IntentionalNetworkPolicyDeny,
            Some(ConfigurationRecommendation::ReviewEgressDeny),
        ),
        REASON_TESSERA_ALLOW_EXCLUSION => (
            NetworkDecisionReason::AllowExclusion,
            CaptureVerboseLoggingOutcomeReason::IntentionalNetworkPolicyDeny,
            Some(ConfigurationRecommendation::ReviewAllowExclusion),
        ),
        REASON_TESSERA_PROXY_CONTAINMENT => (
            NetworkDecisionReason::ProxyContainment,
            CaptureVerboseLoggingOutcomeReason::ProxyContainment,
            Some(ConfigurationRecommendation::UseConfiguredProxy),
        ),
        _ => return Err(CaptureVerboseLoggingOutcomeReason::UnknownNetworkReason),
    };

    let endpoint = match exact_network_endpoint(parts, field_flags) {
        Ok(endpoint) => endpoint,
        Err(reason) => {
            return Ok(network_diagnostic(
                reason,
                network_decision_reason,
                (network_decision_reason != NetworkDecisionReason::DirectDefaultDeny)
                    .then_some(recommendation)
                    .flatten(),
                None,
                ResourceType::Network,
            ));
        }
    };
    if reason != REASON_TESSERA_DIRECT_DEFAULT_DENY {
        return Ok(NetworkDecisionAnalysis {
            denial: None,
            reason: outcome_reason,
            network_decision_reason: Some(network_decision_reason),
            configuration_recommendation: recommendation,
            network_endpoint: endpoint,
            classification: (Some(AccessType::Unknown), Some(ResourceType::Network)),
            properties: Vec::new(),
        });
    }

    if field_flags & FIELD_REMOTE_ADDRESS == 0 {
        return Ok(network_diagnostic(
            CaptureVerboseLoggingOutcomeReason::IncompleteNetworkEndpoint,
            network_decision_reason,
            None,
            None,
            ResourceType::Network,
        ));
    }
    let remote_address = match required_ip_string(parts, "RemoteAddress") {
        Ok(remote_address) => remote_address,
        Err(reason) => {
            return Ok(network_diagnostic(
                reason,
                network_decision_reason,
                None,
                None,
                ResourceType::Network,
            ));
        }
    };

    let denial = (|| {
        let protocol = optional_u8(parts, field_flags, FIELD_PROTOCOL, "Protocol")?;
        let _local_address =
            optional_ip_string(parts, field_flags, FIELD_LOCAL_ADDRESS, "LocalAddress")?;
        let _local_port = optional_u16(parts, field_flags, FIELD_LOCAL_PORT, "LocalPort")?;
        let remote_port = optional_u16(parts, field_flags, FIELD_REMOTE_PORT, "RemotePort")?;
        let _application_id =
            optional_string(parts, field_flags, FIELD_APPLICATION_ID, "ApplicationId")?;
        let _direction = required_u32(parts, "Direction")?;
        let resource = format_network_resource(protocol, &remote_address, remote_port);

        Ok::<_, CaptureVerboseLoggingOutcomeReason>(RawDenial {
            pid: 0,
            resource_type: ResourceType::Network,
            object_name: resource,
            access_type: AccessType::Unknown,
            filetime,
            event_id: parts.event_id,
            provider: None,
            verbose_logging_properties: Vec::new(),
        })
    })();
    let denial = match denial {
        Ok(denial) => denial,
        Err(reason) => {
            return Ok(network_diagnostic(
                reason,
                network_decision_reason,
                None,
                endpoint,
                ResourceType::Network,
            ));
        }
    };
    Ok(NetworkDecisionAnalysis {
        denial: Some(denial),
        reason: outcome_reason,
        network_decision_reason: Some(network_decision_reason),
        configuration_recommendation: recommendation.filter(|_| endpoint.is_some()),
        network_endpoint: endpoint,
        classification: (Some(AccessType::Unknown), Some(ResourceType::Network)),
        properties: Vec::new(),
    })
}

fn network_diagnostic(
    reason: CaptureVerboseLoggingOutcomeReason,
    network_decision_reason: NetworkDecisionReason,
    configuration_recommendation: Option<ConfigurationRecommendation>,
    network_endpoint: Option<NetworkEndpoint>,
    resource_type: ResourceType,
) -> NetworkDecisionAnalysis {
    NetworkDecisionAnalysis {
        denial: None,
        reason,
        network_decision_reason: Some(network_decision_reason),
        configuration_recommendation,
        network_endpoint,
        classification: (Some(AccessType::Unknown), Some(resource_type)),
        properties: Vec::new(),
    }
}

fn exact_network_endpoint(
    parts: &DecodedEventParts,
    field_flags: u32,
) -> Result<Option<NetworkEndpoint>, CaptureVerboseLoggingOutcomeReason> {
    if field_flags & FIELD_REMOTE_ADDRESS == 0 {
        return Ok(None);
    }
    let remote_address = required_ip(parts, "RemoteAddress")?;
    let protocol = optional_u8(parts, field_flags, FIELD_PROTOCOL, "Protocol")?;
    let remote_port = optional_u16(parts, field_flags, FIELD_REMOTE_PORT, "RemotePort")?;
    let (protocol, remote_port) = match protocol {
        Some(6) => match remote_port {
            Some(1..=u16::MAX) => ("tcp", remote_port),
            _ => return Ok(None),
        },
        Some(17) => match remote_port {
            Some(1..=u16::MAX) => ("udp", remote_port),
            _ => return Ok(None),
        },
        Some(1) if remote_address.is_ipv4() => ("icmp", None),
        Some(58) if remote_address.is_ipv6() => ("icmp", None),
        Some(1 | 58) => return Err(CaptureVerboseLoggingOutcomeReason::IncompleteNetworkEndpoint),
        _ => return Ok(None),
    };
    Ok(Some(NetworkEndpoint {
        protocol: protocol.to_string(),
        remote_address: remote_address.to_string(),
        remote_port,
    }))
}

fn format_network_resource(protocol: Option<u8>, address: &str, port: Option<u16>) -> String {
    let scheme = match protocol {
        Some(6) => "tcp".to_string(),
        Some(17) => "udp".to_string(),
        Some(1) => "icmp".to_string(),
        Some(58) => "icmpv6".to_string(),
        Some(value) => format!("ip-{value}"),
        None => "ip".to_string(),
    };
    let host = if address.contains(':') {
        format!("[{address}]")
    } else {
        address.to_string()
    };
    let port = match protocol {
        Some(1 | 58) => None,
        _ => port,
    };
    port.map_or_else(
        || format!("{scheme}://{host}"),
        |port| format!("{scheme}://{host}:{port}"),
    )
}

fn property<'a>(parts: &'a DecodedEventParts, name: &str) -> Option<&'a str> {
    parts
        .props
        .iter()
        .find(|(candidate, _)| candidate.eq_ignore_ascii_case(name))
        .map(|(_, value)| value.trim().trim_matches('"'))
}

fn property_eq(parts: &DecodedEventParts, name: &str, expected: &str) -> bool {
    property(parts, name).is_some_and(|value| value.eq_ignore_ascii_case(expected))
}

fn required_string(
    parts: &DecodedEventParts,
    name: &'static str,
) -> Result<String, CaptureVerboseLoggingOutcomeReason> {
    property(parts, name)
        .map(ToOwned::to_owned)
        .ok_or(CaptureVerboseLoggingOutcomeReason::EventPayloadMalformed)
}

fn required_ip_string(
    parts: &DecodedEventParts,
    name: &'static str,
) -> Result<String, CaptureVerboseLoggingOutcomeReason> {
    required_ip(parts, name).map(|address| address.to_string())
}

fn required_ip(
    parts: &DecodedEventParts,
    name: &'static str,
) -> Result<IpAddr, CaptureVerboseLoggingOutcomeReason> {
    required_string(parts, name)?
        .parse::<IpAddr>()
        .map_err(|_| CaptureVerboseLoggingOutcomeReason::IncompleteNetworkEndpoint)
}

fn required_u8(
    parts: &DecodedEventParts,
    name: &'static str,
) -> Result<u8, CaptureVerboseLoggingOutcomeReason> {
    property(parts, name)
        .and_then(parse_u8)
        .ok_or(CaptureVerboseLoggingOutcomeReason::EventPayloadMalformed)
}

fn required_u16(
    parts: &DecodedEventParts,
    name: &'static str,
) -> Result<u16, CaptureVerboseLoggingOutcomeReason> {
    property(parts, name)
        .and_then(parse_u16)
        .ok_or(CaptureVerboseLoggingOutcomeReason::EventPayloadMalformed)
}

fn required_u32(
    parts: &DecodedEventParts,
    name: &'static str,
) -> Result<u32, CaptureVerboseLoggingOutcomeReason> {
    property(parts, name)
        .and_then(parse_u32)
        .ok_or(CaptureVerboseLoggingOutcomeReason::EventPayloadMalformed)
}

fn required_u64(
    parts: &DecodedEventParts,
    name: &'static str,
) -> Result<u64, CaptureVerboseLoggingOutcomeReason> {
    property(parts, name)
        .and_then(parse_u64)
        .ok_or(CaptureVerboseLoggingOutcomeReason::EventPayloadMalformed)
}

fn optional_string(
    parts: &DecodedEventParts,
    flags: u32,
    flag: u32,
    name: &'static str,
) -> Result<Option<String>, CaptureVerboseLoggingOutcomeReason> {
    if flags & flag == 0 {
        return Ok(None);
    }
    required_string(parts, name).map(Some)
}

fn optional_ip_string(
    parts: &DecodedEventParts,
    flags: u32,
    flag: u32,
    name: &'static str,
) -> Result<Option<String>, CaptureVerboseLoggingOutcomeReason> {
    if flags & flag == 0 {
        return Ok(None);
    }
    required_ip_string(parts, name).map(Some)
}

fn optional_u8(
    parts: &DecodedEventParts,
    flags: u32,
    flag: u32,
    name: &'static str,
) -> Result<Option<u8>, CaptureVerboseLoggingOutcomeReason> {
    if flags & flag == 0 {
        return Ok(None);
    }
    required_u8(parts, name).map(Some)
}

fn optional_u16(
    parts: &DecodedEventParts,
    flags: u32,
    flag: u32,
    name: &'static str,
) -> Result<Option<u16>, CaptureVerboseLoggingOutcomeReason> {
    if flags & flag == 0 {
        return Ok(None);
    }
    required_u16(parts, name).map(Some)
}

fn parse_u8(value: &str) -> Option<u8> {
    parse_u64(value).and_then(|value| u8::try_from(value).ok())
}

fn parse_u16(value: &str) -> Option<u16> {
    parse_u64(value).and_then(|value| u16::try_from(value).ok())
}

fn parse_u32(value: &str) -> Option<u32> {
    parse_u64(value).and_then(|value| u32::try_from(value).ok())
}

fn parse_u64(value: &str) -> Option<u64> {
    let value = value.trim().trim_matches('"').trim();
    value
        .strip_prefix("0x")
        .or_else(|| value.strip_prefix("0X"))
        .map_or_else(
            || value.parse::<u64>().ok(),
            |hex| u64::from_str_radix(hex, 16).ok(),
        )
}

#[cfg(test)]
mod tests {
    use super::*;

    type VerboseLoggingExclusionReason = CaptureVerboseLoggingOutcomeReason;

    fn extract_network_denial(
        parts: &DecodedEventParts,
    ) -> Result<RawDenial, CaptureVerboseLoggingOutcomeReason> {
        let analysis = analyze_network_decision(parts);
        analysis.denial.ok_or(analysis.reason)
    }

    fn event(source: u8, reason: u16, fields: &[(&str, &str)]) -> DecodedEventParts {
        let mut props = vec![
            ("SchemaVersion".to_string(), "1".to_string()),
            ("SourceDomain".to_string(), source.to_string()),
            ("Mode".to_string(), "1".to_string()),
            ("NormalDecision".to_string(), "1".to_string()),
            ("EffectiveDecision".to_string(), "1".to_string()),
            ("Reason".to_string(), reason.to_string()),
            ("FieldFlags".to_string(), "0".to_string()),
            ("OriginalTimestamp".to_string(), "123".to_string()),
            ("UserSid".to_string(), "S-1-5-21-1".to_string()),
            ("PackageSid".to_string(), "S-1-15-2-1".to_string()),
            ("ApplicationId".to_string(), String::new()),
            ("WfpEventType".to_string(), "0".to_string()),
            ("FilterId".to_string(), "456".to_string()),
            ("ProviderGuid".to_string(), TESSERA_PROVIDER.to_string()),
            ("SublayerGuid".to_string(), TESSERA_SUBLAYER.to_string()),
            ("LayerId".to_string(), "0".to_string()),
            ("Direction".to_string(), "0".to_string()),
            ("IsLoopback".to_string(), "0".to_string()),
            ("Protocol".to_string(), "0".to_string()),
            ("LocalAddress".to_string(), String::new()),
            ("LocalPort".to_string(), "0".to_string()),
            ("RemoteAddress".to_string(), String::new()),
            ("RemotePort".to_string(), "0".to_string()),
            ("CapabilityId".to_string(), "0".to_string()),
        ];
        for (name, value) in fields {
            if let Some((_, current)) = props.iter_mut().find(|(candidate, _)| candidate == name) {
                *current = (*value).to_string();
            } else {
                props.push(((*name).to_string(), (*value).to_string()));
            }
        }
        DecodedEventParts {
            provider: NETWORK_DECISION_PROVIDER,
            event_id: NETWORK_DECISION_EVENT_ID,
            event_name: None,
            props,
        }
    }

    fn replace(parts: &mut DecodedEventParts, name: &str, value: impl Into<String>) {
        let (_, current) = parts
            .props
            .iter_mut()
            .find(|(candidate, _)| candidate == name)
            .unwrap();
        *current = value.into();
    }

    #[test]
    fn app_isolation_capability_ids_map_to_stable_names() {
        for (capability_id, expected) in [
            (0, "internetClient"),
            (1, "internetClientServer"),
            (2, "privateNetworkClientServer"),
        ] {
            let mut parts = event(
                SOURCE_APP_ISOLATION,
                REASON_APP_ISOLATION_MISSING_CAPABILITY,
                &[("CapabilityId", &capability_id.to_string())],
            );
            replace(
                &mut parts,
                "SublayerGuid",
                APP_ISOLATION_SUBLAYER.to_string(),
            );
            replace(&mut parts, "FieldFlags", FIELD_CAPABILITY_ID.to_string());

            let denial = extract_network_denial(&parts).unwrap();
            assert_eq!(denial.object_name, expected);
            assert_eq!(denial.resource_type, ResourceType::Capability);
            assert_eq!(denial.pid, 0);
            assert_eq!(denial.filetime, 123);
        }
    }

    #[test]
    fn app_isolation_unknown_capability_is_verbose_only() {
        let mut parts = event(
            SOURCE_APP_ISOLATION,
            REASON_APP_ISOLATION_MISSING_CAPABILITY,
            &[("CapabilityId", "3")],
        );
        replace(
            &mut parts,
            "SublayerGuid",
            APP_ISOLATION_SUBLAYER.to_string(),
        );
        replace(&mut parts, "FieldFlags", FIELD_CAPABILITY_ID.to_string());

        assert_eq!(
            extract_network_denial(&parts).unwrap_err(),
            VerboseLoggingExclusionReason::UnresolvedCapability
        );
    }

    #[test]
    fn tessera_direct_default_deny_builds_stable_network_resource() {
        let flags =
            FIELD_APPLICATION_ID | FIELD_PROTOCOL | FIELD_REMOTE_ADDRESS | FIELD_REMOTE_PORT;
        let mut parts = event(
            SOURCE_TESSERA,
            REASON_TESSERA_DIRECT_DEFAULT_DENY,
            &[
                ("ApplicationId", r"\Device\HarddiskVolume3\app.exe"),
                ("Protocol", "6"),
                ("RemoteAddress", "203.0.113.10"),
                ("RemotePort", "443"),
            ],
        );
        replace(&mut parts, "FieldFlags", flags.to_string());

        let denial = extract_network_denial(&parts).unwrap();
        assert_eq!(denial.object_name, "tcp://203.0.113.10:443");
        assert_eq!(denial.resource_type, ResourceType::Network);
    }

    #[test]
    fn tessera_accepts_provider_direction_values_without_exposing_a_public_enum() {
        for direction in [0, 1, u32::MAX] {
            let mut parts = event(
                SOURCE_TESSERA,
                REASON_TESSERA_DIRECT_DEFAULT_DENY,
                &[
                    ("Direction", &direction.to_string()),
                    ("RemoteAddress", "203.0.113.10"),
                ],
            );
            replace(&mut parts, "FieldFlags", FIELD_REMOTE_ADDRESS.to_string());

            let denial = extract_network_denial(&parts).unwrap();
            assert_eq!(denial.object_name, "ip://203.0.113.10");
        }
    }

    #[test]
    fn tessera_ipv6_resource_uses_brackets() {
        let flags = FIELD_PROTOCOL | FIELD_REMOTE_ADDRESS | FIELD_REMOTE_PORT;
        let mut parts = event(
            SOURCE_TESSERA,
            REASON_TESSERA_DIRECT_DEFAULT_DENY,
            &[
                ("Protocol", "17"),
                ("RemoteAddress", "2001:db8::1"),
                ("RemotePort", "53"),
            ],
        );
        replace(&mut parts, "FieldFlags", flags.to_string());

        assert_eq!(
            extract_network_denial(&parts).unwrap().object_name,
            "udp://[2001:db8::1]:53"
        );
    }

    #[test]
    fn tessera_icmp_resources_ignore_irrelevant_ports() {
        for (protocol, expected) in [(1, "icmp://203.0.113.10"), (58, "icmpv6://[2001:db8::1]")] {
            let address = if protocol == 1 {
                "203.0.113.10"
            } else {
                "2001:db8::1"
            };
            let flags = FIELD_PROTOCOL | FIELD_REMOTE_ADDRESS | FIELD_REMOTE_PORT;
            let mut parts = event(
                SOURCE_TESSERA,
                REASON_TESSERA_DIRECT_DEFAULT_DENY,
                &[
                    ("Protocol", &protocol.to_string()),
                    ("RemoteAddress", address),
                    ("RemotePort", "8"),
                ],
            );
            replace(&mut parts, "FieldFlags", flags.to_string());

            let analysis = analyze_network_decision(&parts);
            assert_eq!(analysis.denial.unwrap().object_name, expected);
            assert_eq!(
                analysis.network_endpoint.unwrap().remote_port,
                None,
                "ICMP recommendations must not carry ports"
            );
        }
    }

    #[test]
    fn tessera_icmp_recommendations_require_matching_address_family() {
        for (protocol, address) in [(1, "2001:db8::1"), (58, "203.0.113.10")] {
            let flags = FIELD_PROTOCOL | FIELD_REMOTE_ADDRESS | FIELD_REMOTE_PORT;
            let mut parts = event(
                SOURCE_TESSERA,
                REASON_TESSERA_DIRECT_DEFAULT_DENY,
                &[
                    ("Protocol", &protocol.to_string()),
                    ("RemoteAddress", address),
                    ("RemotePort", "8"),
                ],
            );
            replace(&mut parts, "FieldFlags", flags.to_string());

            let analysis = analyze_network_decision(&parts);
            assert!(analysis.denial.is_none());
            assert_eq!(
                analysis.reason,
                CaptureVerboseLoggingOutcomeReason::IncompleteNetworkEndpoint
            );
            assert!(analysis.configuration_recommendation.is_none());
            assert!(analysis.network_endpoint.is_none());
        }
    }

    #[test]
    fn intentional_and_proxy_denials_are_verbose_only() {
        for (reason, expected, policy_reason, recommendation) in [
            (
                REASON_TESSERA_EXPLICIT_DENY,
                VerboseLoggingExclusionReason::IntentionalNetworkPolicyDeny,
                NetworkDecisionReason::AuthoredExplicitDeny,
                ConfigurationRecommendation::ReviewEgressDeny,
            ),
            (
                REASON_TESSERA_ALLOW_EXCLUSION,
                VerboseLoggingExclusionReason::IntentionalNetworkPolicyDeny,
                NetworkDecisionReason::AllowExclusion,
                ConfigurationRecommendation::ReviewAllowExclusion,
            ),
            (
                REASON_TESSERA_PROXY_CONTAINMENT,
                VerboseLoggingExclusionReason::ProxyContainment,
                NetworkDecisionReason::ProxyContainment,
                ConfigurationRecommendation::UseConfiguredProxy,
            ),
        ] {
            let parts = event(SOURCE_TESSERA, reason, &[]);
            assert_eq!(extract_network_denial(&parts).unwrap_err(), expected);
            let analysis = analyze_network_decision(&parts);
            assert_eq!(analysis.network_decision_reason, Some(policy_reason));
            assert_eq!(analysis.configuration_recommendation, Some(recommendation));
        }
    }

    #[test]
    fn direct_default_deny_exposes_only_exact_allow_recommendations() {
        let flags = FIELD_PROTOCOL | FIELD_REMOTE_ADDRESS | FIELD_REMOTE_PORT;
        let mut exact = event(
            SOURCE_TESSERA,
            REASON_TESSERA_DIRECT_DEFAULT_DENY,
            &[
                ("Protocol", "6"),
                ("RemoteAddress", "203.0.113.10"),
                ("RemotePort", "443"),
            ],
        );
        replace(&mut exact, "FieldFlags", flags.to_string());
        let analysis = analyze_network_decision(&exact);
        assert_eq!(
            analysis.network_decision_reason,
            Some(NetworkDecisionReason::DirectDefaultDeny)
        );
        assert_eq!(
            analysis.configuration_recommendation,
            Some(ConfigurationRecommendation::AddEgressAllow)
        );
        assert_eq!(
            analysis.network_endpoint,
            Some(NetworkEndpoint {
                protocol: "tcp".to_string(),
                remote_address: "203.0.113.10".to_string(),
                remote_port: Some(443),
            })
        );

        let mut unknown_protocol = exact.clone();
        replace(&mut unknown_protocol, "Protocol", "132");
        let analysis = analyze_network_decision(&unknown_protocol);
        assert!(analysis.denial.is_some());
        assert_eq!(
            analysis.network_decision_reason,
            Some(NetworkDecisionReason::DirectDefaultDeny)
        );
        assert!(analysis.configuration_recommendation.is_none());
        assert!(analysis.network_endpoint.is_none());

        let mut zero_port = exact.clone();
        replace(&mut zero_port, "RemotePort", "0");
        let analysis = analyze_network_decision(&zero_port);
        assert!(analysis.denial.is_some());
        assert!(analysis.configuration_recommendation.is_none());
        assert!(analysis.network_endpoint.is_none());

        let mut missing_port = exact.clone();
        replace(
            &mut missing_port,
            "FieldFlags",
            (FIELD_PROTOCOL | FIELD_REMOTE_ADDRESS).to_string(),
        );
        let analysis = analyze_network_decision(&missing_port);
        assert!(analysis.denial.is_some());
        assert!(analysis.configuration_recommendation.is_none());
        assert!(analysis.network_endpoint.is_none());

        let mut icmp_with_port = exact.clone();
        replace(&mut icmp_with_port, "Protocol", "1");
        replace(&mut icmp_with_port, "RemotePort", "8");
        let analysis = analyze_network_decision(&icmp_with_port);
        assert_eq!(
            analysis.configuration_recommendation,
            Some(ConfigurationRecommendation::AddEgressAllow)
        );
        assert_eq!(
            analysis.network_endpoint,
            Some(NetworkEndpoint {
                protocol: "icmp".to_string(),
                remote_address: "203.0.113.10".to_string(),
                remote_port: None,
            })
        );

        let mut malformed_port = exact;
        replace(&mut malformed_port, "RemotePort", "not-a-port");
        let analysis = analyze_network_decision(&malformed_port);
        assert!(analysis.denial.is_none());
        assert!(analysis.configuration_recommendation.is_none());
        assert!(analysis.network_endpoint.is_none());
    }

    #[test]
    fn tessera_default_deny_requires_remote_address() {
        let parts = event(SOURCE_TESSERA, REASON_TESSERA_DIRECT_DEFAULT_DENY, &[]);
        assert_eq!(
            extract_network_denial(&parts).unwrap_err(),
            VerboseLoggingExclusionReason::IncompleteNetworkEndpoint
        );
    }

    #[test]
    fn tessera_default_deny_requires_numeric_addresses() {
        let mut parts = event(
            SOURCE_TESSERA,
            REASON_TESSERA_DIRECT_DEFAULT_DENY,
            &[("RemoteAddress", "example.com")],
        );
        replace(&mut parts, "FieldFlags", FIELD_REMOTE_ADDRESS.to_string());

        assert_eq!(
            extract_network_denial(&parts).unwrap_err(),
            VerboseLoggingExclusionReason::IncompleteNetworkEndpoint
        );
    }

    #[test]
    fn future_fields_and_flags_do_not_hide_a_valid_v1_event() {
        let mut parts = event(
            SOURCE_TESSERA,
            REASON_TESSERA_DIRECT_DEFAULT_DENY,
            &[("RemoteAddress", "203.0.113.10")],
        );
        replace(
            &mut parts,
            "FieldFlags",
            (FIELD_REMOTE_ADDRESS | (1 << 31)).to_string(),
        );
        parts
            .props
            .push(("FutureTrailingProperty".to_string(), "future".to_string()));

        assert_eq!(
            extract_network_denial(&parts).unwrap().object_name,
            "ip://203.0.113.10"
        );
    }

    #[test]
    fn source_identity_mismatch_fails_closed() {
        let mut parts = event(SOURCE_TESSERA, REASON_TESSERA_DIRECT_DEFAULT_DENY, &[]);
        replace(
            &mut parts,
            "ProviderGuid",
            "{00000000-0000-0000-0000-000000000000}",
        );
        assert_eq!(
            extract_network_denial(&parts).unwrap_err(),
            VerboseLoggingExclusionReason::UnsupportedEventSchema
        );
    }

    #[test]
    fn schema_and_decision_guards_fail_closed_independently() {
        for (name, value) in [
            ("SchemaVersion", "2"),
            ("Mode", "0"),
            ("NormalDecision", "0"),
            ("EffectiveDecision", "0"),
            ("OriginalTimestamp", "0"),
            ("FilterId", "0"),
        ] {
            let mut parts = event(
                SOURCE_TESSERA,
                REASON_TESSERA_DIRECT_DEFAULT_DENY,
                &[("RemoteAddress", "203.0.113.10")],
            );
            replace(&mut parts, "FieldFlags", FIELD_REMOTE_ADDRESS.to_string());
            replace(&mut parts, name, value);

            assert_eq!(
                extract_network_denial(&parts).unwrap_err(),
                VerboseLoggingExclusionReason::UnsupportedEventSchema,
                "guard {name}={value} must fail closed"
            );
        }
    }

    #[test]
    fn shipped_v1_payload_uses_the_original_24_fields() {
        let parts = event(
            SOURCE_TESSERA,
            REASON_TESSERA_DIRECT_DEFAULT_DENY,
            &[("RemoteAddress", "203.0.113.10")],
        );

        let names = parts
            .props
            .iter()
            .map(|(name, _)| name.as_str())
            .collect::<Vec<_>>();
        assert_eq!(
            names,
            [
                "SchemaVersion",
                "SourceDomain",
                "Mode",
                "NormalDecision",
                "EffectiveDecision",
                "Reason",
                "FieldFlags",
                "OriginalTimestamp",
                "UserSid",
                "PackageSid",
                "ApplicationId",
                "WfpEventType",
                "FilterId",
                "ProviderGuid",
                "SublayerGuid",
                "LayerId",
                "Direction",
                "IsLoopback",
                "Protocol",
                "LocalAddress",
                "LocalPort",
                "RemoteAddress",
                "RemotePort",
                "CapabilityId",
            ]
        );
    }

    #[test]
    fn every_original_v1_property_name_is_required() {
        for missing in NETWORK_DECISION_V1_FIELDS {
            let mut parts = event(
                SOURCE_TESSERA,
                REASON_TESSERA_DIRECT_DEFAULT_DENY,
                &[("RemoteAddress", "203.0.113.10")],
            );
            replace(&mut parts, "FieldFlags", FIELD_REMOTE_ADDRESS.to_string());
            parts.props.retain(|(name, _)| name != missing);

            assert_eq!(
                analyze_network_decision(&parts).reason,
                CaptureVerboseLoggingOutcomeReason::UnsupportedEventSchema,
                "missing base property {missing} must fail closed"
            );
        }
    }

    #[test]
    fn unknown_stable_reason_remains_verbose_only() {
        let parts = event(SOURCE_TESSERA, u16::MAX, &[]);

        assert_eq!(
            extract_network_denial(&parts).unwrap_err(),
            VerboseLoggingExclusionReason::UnknownNetworkReason
        );
    }
}
