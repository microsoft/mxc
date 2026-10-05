// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Extractors for the OS-managed Learning Mode WFP decision event.

use crate::learning_mode_core::{
    AccessType, DenialDetails, NetworkDenialDetails, NetworkDenialReason, NetworkDenialSource,
    NetworkDirection, ResourceType, VerboseLoggingOutcomeReason as VerboseLoggingExclusionReason,
    VerboseLoggingProvider,
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

pub(crate) fn extract_network_denial(
    parts: &DecodedEventParts,
) -> Result<RawDenial, VerboseLoggingExclusionReason> {
    if parts.provider != NETWORK_DECISION_PROVIDER || parts.event_id != NETWORK_DECISION_EVENT_ID {
        return Err(VerboseLoggingExclusionReason::UnsupportedEventSchema);
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
        return Err(VerboseLoggingExclusionReason::UnsupportedEventSchema);
    }

    match source_domain {
        SOURCE_APP_ISOLATION => {
            extract_app_isolation(parts, reason, field_flags, filetime, filter_id)
        }
        SOURCE_TESSERA => extract_tessera(parts, reason, field_flags, filetime, filter_id),
        _ => Err(VerboseLoggingExclusionReason::UnknownNetworkReason),
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
) -> Result<RawDenial, VerboseLoggingExclusionReason> {
    if !property_eq(parts, "SublayerGuid", APP_ISOLATION_SUBLAYER) {
        return Err(VerboseLoggingExclusionReason::UnsupportedEventSchema);
    }
    if reason != REASON_APP_ISOLATION_MISSING_CAPABILITY {
        return Err(VerboseLoggingExclusionReason::UnknownNetworkReason);
    }
    if field_flags & FIELD_CAPABILITY_ID == 0 {
        return Err(VerboseLoggingExclusionReason::UnresolvedCapability);
    }
    let capability = match required_u32(parts, "CapabilityId")? {
        0 => "internetClient",
        1 => "internetClientServer",
        2 => "privateNetworkClientServer",
        _ => return Err(VerboseLoggingExclusionReason::UnresolvedCapability),
    };

    Ok(RawDenial {
        pid: 0,
        resource_type: ResourceType::Capability,
        object_name: capability.to_string(),
        access_type: AccessType::Unknown,
        filetime,
        details: None,
        event_id: parts.event_id,
        provider: VerboseLoggingProvider::LearningModeNetworkDecision,
        verbose_logging_properties: sanitize_properties(&parts.props),
    })
}

fn extract_tessera(
    parts: &DecodedEventParts,
    reason: u16,
    field_flags: u32,
    filetime: u64,
    filter_id: u64,
) -> Result<RawDenial, VerboseLoggingExclusionReason> {
    if !property_eq(parts, "ProviderGuid", TESSERA_PROVIDER)
        || !property_eq(parts, "SublayerGuid", TESSERA_SUBLAYER)
        || field_flags & FIELD_CAPABILITY_ID != 0
    {
        return Err(VerboseLoggingExclusionReason::UnsupportedEventSchema);
    }

    match reason {
        REASON_TESSERA_EXPLICIT_DENY | REASON_TESSERA_ALLOW_EXCLUSION => {
            return Err(VerboseLoggingExclusionReason::IntentionalNetworkPolicyDeny)
        }
        REASON_TESSERA_PROXY_CONTAINMENT => {
            return Err(VerboseLoggingExclusionReason::ProxyContainment)
        }
        REASON_TESSERA_DIRECT_DEFAULT_DENY => {}
        _ => return Err(VerboseLoggingExclusionReason::UnknownNetworkReason),
    }

    if field_flags & FIELD_REMOTE_ADDRESS == 0 {
        return Err(VerboseLoggingExclusionReason::IncompleteNetworkEndpoint);
    }

    let remote_address = required_ip_string(parts, "RemoteAddress")?;

    let protocol = optional_u8(parts, field_flags, FIELD_PROTOCOL, "Protocol")?;
    let local_address =
        optional_ip_string(parts, field_flags, FIELD_LOCAL_ADDRESS, "LocalAddress")?;
    let local_port = optional_u16(parts, field_flags, FIELD_LOCAL_PORT, "LocalPort")?;
    let remote_port = optional_u16(parts, field_flags, FIELD_REMOTE_PORT, "RemotePort")?;
    let application_id =
        optional_string(parts, field_flags, FIELD_APPLICATION_ID, "ApplicationId")?;
    let direction = required_u32(parts, "Direction").map(network_direction)?;
    let resource = format_network_resource(protocol, &remote_address, remote_port);

    Ok(RawDenial {
        pid: 0,
        resource_type: ResourceType::Network,
        object_name: resource,
        access_type: AccessType::Unknown,
        filetime,
        details: Some(DenialDetails::Network(NetworkDenialDetails {
            source: NetworkDenialSource::ProcessContainerNetworkPolicy,
            reason: NetworkDenialReason::DirectDefaultDeny,
            direction,
            protocol,
            local_address,
            local_port,
            remote_address,
            remote_port,
            application_id,
            filter_id,
        })),
        event_id: parts.event_id,
        provider: VerboseLoggingProvider::LearningModeNetworkDecision,
        verbose_logging_properties: sanitize_properties(&parts.props),
    })
}

fn network_direction(value: u32) -> NetworkDirection {
    match value {
        0 => NetworkDirection::Outbound,
        1 => NetworkDirection::Inbound,
        _ => NetworkDirection::Unknown,
    }
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
) -> Result<String, VerboseLoggingExclusionReason> {
    property(parts, name)
        .map(ToOwned::to_owned)
        .ok_or(VerboseLoggingExclusionReason::EventPayloadMalformed)
}

fn required_ip_string(
    parts: &DecodedEventParts,
    name: &'static str,
) -> Result<String, VerboseLoggingExclusionReason> {
    required_string(parts, name)?
        .parse::<IpAddr>()
        .map(|address| address.to_string())
        .map_err(|_| VerboseLoggingExclusionReason::IncompleteNetworkEndpoint)
}

fn required_u8(
    parts: &DecodedEventParts,
    name: &'static str,
) -> Result<u8, VerboseLoggingExclusionReason> {
    property(parts, name)
        .and_then(parse_u8)
        .ok_or(VerboseLoggingExclusionReason::EventPayloadMalformed)
}

fn required_u16(
    parts: &DecodedEventParts,
    name: &'static str,
) -> Result<u16, VerboseLoggingExclusionReason> {
    property(parts, name)
        .and_then(parse_u16)
        .ok_or(VerboseLoggingExclusionReason::EventPayloadMalformed)
}

fn required_u32(
    parts: &DecodedEventParts,
    name: &'static str,
) -> Result<u32, VerboseLoggingExclusionReason> {
    property(parts, name)
        .and_then(parse_u32)
        .ok_or(VerboseLoggingExclusionReason::EventPayloadMalformed)
}

fn required_u64(
    parts: &DecodedEventParts,
    name: &'static str,
) -> Result<u64, VerboseLoggingExclusionReason> {
    property(parts, name)
        .and_then(parse_u64)
        .ok_or(VerboseLoggingExclusionReason::EventPayloadMalformed)
}

fn optional_string(
    parts: &DecodedEventParts,
    flags: u32,
    flag: u32,
    name: &'static str,
) -> Result<Option<String>, VerboseLoggingExclusionReason> {
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
) -> Result<Option<String>, VerboseLoggingExclusionReason> {
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
) -> Result<Option<u8>, VerboseLoggingExclusionReason> {
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
) -> Result<Option<u16>, VerboseLoggingExclusionReason> {
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
    fn app_isolation_capability_drop_maps_known_capability() {
        let mut parts = event(
            SOURCE_APP_ISOLATION,
            REASON_APP_ISOLATION_MISSING_CAPABILITY,
            &[("CapabilityId", "0")],
        );
        replace(
            &mut parts,
            "SublayerGuid",
            APP_ISOLATION_SUBLAYER.to_string(),
        );
        replace(&mut parts, "FieldFlags", FIELD_CAPABILITY_ID.to_string());

        let denial = extract_network_denial(&parts).unwrap();
        assert_eq!(denial.object_name, "internetClient");
        assert_eq!(denial.resource_type, ResourceType::Capability);
        assert_eq!(denial.pid, 0);
        assert_eq!(denial.filetime, 123);
    }

    #[test]
    fn tessera_direct_default_deny_preserves_network_details() {
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
        assert!(matches!(
            denial.details,
            Some(DenialDetails::Network(NetworkDenialDetails {
                direction: NetworkDirection::Outbound,
                protocol: Some(6),
                remote_port: Some(443),
                filter_id: 456,
                ..
            }))
        ));
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
    fn intentional_and_proxy_denials_are_verbose_only() {
        for (reason, expected) in [
            (
                REASON_TESSERA_EXPLICIT_DENY,
                VerboseLoggingExclusionReason::IntentionalNetworkPolicyDeny,
            ),
            (
                REASON_TESSERA_ALLOW_EXCLUSION,
                VerboseLoggingExclusionReason::IntentionalNetworkPolicyDeny,
            ),
            (
                REASON_TESSERA_PROXY_CONTAINMENT,
                VerboseLoggingExclusionReason::ProxyContainment,
            ),
        ] {
            let parts = event(SOURCE_TESSERA, reason, &[]);
            assert_eq!(extract_network_denial(&parts).unwrap_err(), expected);
        }
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
    fn unknown_stable_reason_remains_verbose_only() {
        let parts = event(SOURCE_TESSERA, u16::MAX, &[]);

        assert_eq!(
            extract_network_denial(&parts).unwrap_err(),
            VerboseLoggingExclusionReason::UnknownNetworkReason
        );
    }
}
