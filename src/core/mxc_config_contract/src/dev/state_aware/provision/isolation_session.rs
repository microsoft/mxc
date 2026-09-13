// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use crate::dev::state_aware::provision::ProvisionPhase;
use crate::dev::{OptionalField, Telemetry, True, Version};
use serde::Deserialize;

string_marker! {
    /// The `isolation_session` containment of the state-aware configuration contract.
    pub struct IsolationSessionContainment => "isolation_session";
}

string_marker! {
    /// The exact `allow` action required by an unrestricted network posture.
    pub struct IsolationSessionNetworkAllow => "allow";
}

string_marker! {
    /// The exact legacy `allow` default retained during the transition.
    pub struct IsolationSessionLegacyNetworkAllow => "allow";
}

/// The canonical legacy unrestricted-network posture retained for compatibility.
#[derive(Debug, Deserialize)]
#[cfg_attr(feature = "schema-gen", derive(schemars::JsonSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct IsolationSessionLegacyNetwork {
    /// Legacy unrestricted outbound posture.
    pub default_policy: IsolationSessionLegacyNetworkAllow,
    /// Legacy unrestricted inbound/local-network posture.
    pub allow_local_network: True,
}

/// Unrestricted outbound posture.
#[derive(Debug, Deserialize)]
#[cfg_attr(feature = "schema-gen", derive(schemars::JsonSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct IsolationSessionNetworkEgress {
    /// Allow outbound traffic by default.
    pub default: IsolationSessionNetworkAllow,
}

/// Unrestricted inbound and host-loopback posture.
#[derive(Debug, Deserialize)]
#[cfg_attr(feature = "schema-gen", derive(schemars::JsonSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct IsolationSessionNetworkIngress {
    /// Allow private-network inbound traffic by default.
    pub default: IsolationSessionNetworkAllow,
    /// Allow bidirectional host-loopback connectivity.
    pub host_loopback: IsolationSessionNetworkAllow,
}

/// The canonical directional unrestricted-network posture.
#[derive(Debug, Deserialize)]
#[cfg_attr(feature = "schema-gen", derive(schemars::JsonSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct IsolationSessionDirectionalNetwork {
    /// Required unrestricted outbound posture.
    pub egress: IsolationSessionNetworkEgress,
    /// Required unrestricted inbound and host-loopback posture.
    pub ingress: IsolationSessionNetworkIngress,
}

/// The two accepted unrestricted-network spellings.
#[derive(Debug, Deserialize)]
#[serde(try_from = "IsolationSessionNetworkFields")]
pub enum IsolationSessionNetwork {
    /// Canonical legacy compatibility spelling.
    Legacy(IsolationSessionLegacyNetwork),
    /// Standard directional networking spelling.
    Directional(IsolationSessionDirectionalNetwork),
}

#[derive(Debug, Deserialize)]
#[cfg_attr(feature = "schema-gen", derive(schemars::JsonSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct IsolationSessionNetworkFields {
    #[serde(default)]
    default_policy: OptionalField<IsolationSessionLegacyNetworkAllow>,
    #[serde(default)]
    allow_local_network: OptionalField<True>,
    #[serde(default)]
    egress: OptionalField<IsolationSessionNetworkEgress>,
    #[serde(default)]
    ingress: OptionalField<IsolationSessionNetworkIngress>,
}

/// The supplied network object was not exactly one accepted unrestricted form.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error(
    "IsolationSession requires either defaultPolicy='allow' with \
     allowLocalNetwork=true, or egress.default, ingress.default, and \
     ingress.hostLoopback all set to 'allow'"
)]
pub struct InvalidIsolationSessionNetwork;

impl TryFrom<IsolationSessionNetworkFields> for IsolationSessionNetwork {
    type Error = InvalidIsolationSessionNetwork;

    fn try_from(fields: IsolationSessionNetworkFields) -> Result<Self, Self::Error> {
        let IsolationSessionNetworkFields {
            default_policy,
            allow_local_network,
            egress,
            ingress,
        } = fields;
        match (
            default_policy.into_option(),
            allow_local_network.into_option(),
            egress.into_option(),
            ingress.into_option(),
        ) {
            (Some(default_policy), Some(allow_local_network), None, None) => {
                Ok(Self::Legacy(IsolationSessionLegacyNetwork {
                    default_policy,
                    allow_local_network,
                }))
            }
            (None, None, Some(egress), Some(ingress)) => {
                Ok(Self::Directional(IsolationSessionDirectionalNetwork {
                    egress,
                    ingress,
                }))
            }
            _ => Err(InvalidIsolationSessionNetwork),
        }
    }
}

#[cfg(feature = "schema-gen")]
impl schemars::JsonSchema for IsolationSessionNetwork {
    fn schema_name() -> String {
        "IsolationSessionNetwork".to_string()
    }

    fn json_schema(generator: &mut schemars::gen::SchemaGenerator) -> schemars::schema::Schema {
        use schemars::schema::{SchemaObject, SubschemaValidation};

        schemars::schema::Schema::Object(SchemaObject {
            subschemas: Some(Box::new(SubschemaValidation {
                one_of: Some(vec![
                    generator.subschema_for::<IsolationSessionLegacyNetwork>(),
                    generator.subschema_for::<IsolationSessionDirectionalNetwork>(),
                ]),
                ..Default::default()
            })),
            ..Default::default()
        })
    }
}

/// IsolationSession settings accepted during provisioning.
#[derive(Debug, Deserialize)]
#[cfg_attr(feature = "schema-gen", derive(schemars::JsonSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct IsolationSessionProvision {
    /// Optional application identifier carried by the sandbox identity.
    #[serde(default)]
    pub app_id: OptionalField<String>,
}

/// State-aware IsolationSession experimental settings.
#[derive(Debug, Deserialize)]
#[cfg_attr(feature = "schema-gen", derive(schemars::JsonSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct StateAwareIsolationSession {
    /// Optional provision-phase settings.
    #[serde(default)]
    pub provision: OptionalField<IsolationSessionProvision>,
}

/// Experimental settings accepted by an IsolationSession provision request.
#[derive(Debug, Deserialize)]
#[cfg_attr(feature = "schema-gen", derive(schemars::JsonSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct IsolationSessionProvisionExperimental {
    /// Optional IsolationSession backend settings.
    #[serde(rename = "isolation_session", default)]
    pub isolation_session: OptionalField<StateAwareIsolationSession>,
}

/// A complete state-aware `provision` request for IsolationSession.
///
/// The backend cannot restrict networking, so `network` is required and must
/// describe its actual unrestricted posture. The historical legacy pair and
/// the standard directional all-allow shape are accepted.
#[derive(Debug, Deserialize)]
#[cfg_attr(feature = "schema-gen", derive(schemars::JsonSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct IsolationSessionProvisionRequest {
    /// Optional JSON Schema reference for editor validation.
    #[serde(rename = "$schema", default)]
    pub schema: OptionalField<String>,
    /// Optional human-readable annotation ignored by the runtime.
    #[serde(rename = "_comment", default)]
    pub comment: OptionalField<serde_json::Value>,
    /// Exact development contract version.
    pub version: Version,
    /// Exact `provision` phase marker.
    pub phase: ProvisionPhase,
    /// Exact `isolation_session` containment marker.
    pub containment: IsolationSessionContainment,
    /// Required unrestricted network posture.
    pub network: IsolationSessionNetwork,
    /// Optional telemetry configuration.
    #[serde(default)]
    pub telemetry: OptionalField<Telemetry>,
    /// Optional closed experimental settings containing only `appId`.
    #[serde(default)]
    pub experimental: OptionalField<IsolationSessionProvisionExperimental>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dev::{parse_request, ProvisionRequest, Request};

    const LEGACY_NETWORK: &str = r#""network":{"defaultPolicy":"allow","allowLocalNetwork":true}"#;
    const DIRECTIONAL_NETWORK: &str = r#""network":{"egress":{"default":"allow"},"ingress":{"default":"allow","hostLoopback":"allow"}}"#;

    fn provision(fields: &str) -> String {
        format!(
            r#"{{"version":"0.9.0-alpha","phase":"provision","containment":"isolation_session"{fields}}}"#
        )
    }

    fn parse(fields: &str) -> Result<IsolationSessionProvisionRequest, String> {
        match parse_request(&provision(fields)) {
            Ok(Request::Provision(ProvisionRequest::IsolationSession(request))) => Ok(request),
            Ok(other) => panic!("expected an IsolationSession provision request: {other:?}"),
            Err(error) => Err(format!(
                "{error}: {}",
                std::error::Error::source(&error)
                    .map(ToString::to_string)
                    .unwrap_or_default()
            )),
        }
    }

    #[test]
    fn legacy_and_directional_unrestricted_postures_are_accepted() {
        assert!(matches!(
            parse(&format!(",{LEGACY_NETWORK}")).unwrap().network,
            IsolationSessionNetwork::Legacy(_)
        ));
        assert!(matches!(
            parse(&format!(",{DIRECTIONAL_NETWORK}")).unwrap().network,
            IsolationSessionNetwork::Directional(_)
        ));
    }

    #[test]
    fn network_is_required() {
        let error = parse("").unwrap_err();
        assert!(error.contains("missing field `network`"), "{error}");
    }

    #[test]
    fn partial_or_mixed_network_postures_are_rejected() {
        for network in [
            r#""network":{}"#,
            r#""network":{"defaultPolicy":"allow"}"#,
            r#""network":{"allowLocalNetwork":true}"#,
            r#""network":{"defaultPolicy":"block","allowLocalNetwork":true}"#,
            r#""network":{"egress":{"default":"allow"}}"#,
            r#""network":{"ingress":{"default":"allow","hostLoopback":"allow"}}"#,
            r#""network":{"egress":{"default":"allow"},"ingress":{"default":"allow"}}"#,
            r#""network":{"egress":{"default":"allow"},"ingress":{"default":"allow","hostLoopback":"deny"}}"#,
            r#""network":{"defaultPolicy":"allow","allowLocalNetwork":true,"egress":{"default":"allow"},"ingress":{"default":"allow","hostLoopback":"allow"}}"#,
            r#""network":null"#,
        ] {
            assert!(parse(&format!(",{network}")).is_err(), "{network}");
        }
    }

    #[test]
    fn directional_rules_and_proxy_are_rejected() {
        for network in [
            r#""network":{"egress":{"default":"allow","allow":[]},"ingress":{"default":"allow","hostLoopback":"allow"}}"#,
            r#""network":{"egress":{"default":"allow","deny":[]},"ingress":{"default":"allow","hostLoopback":"allow"}}"#,
            r#""network":{"egress":{"default":"allow"},"ingress":{"default":"allow","hostLoopback":"allow"},"proxy":{"url":"http://proxy.example:8080"}}"#,
        ] {
            assert!(parse(&format!(",{network}")).is_err(), "{network}");
        }
    }

    #[test]
    fn app_id_remains_optional_and_provision_scoped() {
        let fields = format!(
            r#",{DIRECTIONAL_NETWORK},"experimental":{{"isolation_session":{{"provision":{{"appId":"Contoso.App"}}}}}}"#
        );
        let request = parse(&fields).unwrap();
        assert_eq!(
            request
                .experimental
                .as_ref()
                .and_then(|experimental| experimental.isolation_session.as_ref())
                .and_then(|isolation_session| isolation_session.provision.as_ref())
                .and_then(|provision| provision.app_id.as_ref())
                .map(String::as_str),
            Some("Contoso.App")
        );
    }

    #[cfg(feature = "schema-gen")]
    #[test]
    fn generated_schema_requires_network_and_exposes_both_postures() {
        let schema = crate::dev::development_schema();
        let root = &schema["definitions"]["IsolationSessionProvisionRequest"];
        assert!(root["required"]
            .as_array()
            .expect("required fields")
            .contains(&serde_json::json!("network")));
        assert_eq!(
            schema["definitions"]["IsolationSessionNetwork"]["oneOf"]
                .as_array()
                .expect("network variants")
                .len(),
            2
        );
    }
}
