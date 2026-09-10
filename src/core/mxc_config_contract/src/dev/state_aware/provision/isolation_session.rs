// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use crate::dev::state_aware::provision::ProvisionPhase;
use crate::dev::{OptionalField, Telemetry, True, Version};
use serde::Deserialize;

string_marker! {
    /// The `isolation_session` containment of the state-aware configuration contract.
    pub struct IsolationSessionContainment => "isolation_session";
}

/// IsolationSession settings accepted during provisioning.
#[derive(Debug, Deserialize)]
#[cfg_attr(feature = "schema-gen", derive(schemars::JsonSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct IsolationSessionProvision {
    /// Optional application identifier carried by the sandbox identity.
    #[serde(default)]
    pub app_id: OptionalField<String>,
    /// Required acknowledgment that MXC cannot restrict the container's networking.
    /// Only the JSON value `true` is valid; later phases cannot redeclare it.
    pub acknowledge_unrestricted_network: True,
}

/// State-aware IsolationSession experimental settings.
#[derive(Debug, Deserialize)]
#[cfg_attr(feature = "schema-gen", derive(schemars::JsonSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct StateAwareIsolationSession {
    /// Required provision settings containing the unrestricted-network acknowledgment.
    pub provision: IsolationSessionProvision,
}

/// Experimental settings accepted by an IsolationSession provision request.
#[derive(Debug, Deserialize)]
#[cfg_attr(feature = "schema-gen", derive(schemars::JsonSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct IsolationSessionProvisionExperimental {
    /// Required IsolationSession backend settings.
    #[serde(rename = "isolation_session")]
    pub isolation_session: StateAwareIsolationSession,
}

/// A complete IsolationSession provision request. The container's network is
/// unrestricted: the required typed acknowledgment cannot be replaced by network
/// policy, and direct construction cannot omit it.
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
    /// Exact provision phase marker.
    pub phase: ProvisionPhase,
    /// Exact IsolationSession containment marker.
    pub containment: IsolationSessionContainment,
    /// Optional telemetry configuration.
    #[serde(default)]
    pub telemetry: OptionalField<Telemetry>,
    /// Required backend configuration with the unrestricted-network acknowledgment.
    pub experimental: IsolationSessionProvisionExperimental,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dev::{parse_request, ProvisionRequest, Request};

    fn provision(fields: &str) -> String {
        format!(
            r#"{{"version":"0.9.0-alpha","phase":"provision","containment":"isolation_session"{fields}}}"#
        )
    }

    const ACK: &str = r#","experimental":{"isolation_session":{"provision":{"acknowledgeUnrestrictedNetwork":true}}}"#;

    #[test]
    fn acknowledgment_is_required_at_every_wrapper() {
        for fields in [
            "",
            r#","experimental":{}"#,
            r#","experimental":{"isolation_session":{}}"#,
            r#","experimental":{"isolation_session":{"provision":{}}}"#,
            r#","experimental":{"isolation_session":{"provision":{"appId":"Contoso.App"}}}"#,
        ] {
            assert!(parse_request(&provision(fields)).is_err(), "{fields}");
            assert!(
                serde_json::from_str::<IsolationSessionProvisionRequest>(&provision(fields))
                    .is_err(),
                "{fields}"
            );
        }
        assert!(parse_request(&provision(ACK)).is_ok());
    }

    #[test]
    fn legacy_network_cannot_substitute_or_accompany_acknowledgment() {
        for network in [
            r#","network":{}"#,
            r#","network":{"defaultPolicy":"allow","allowLocalNetwork":true}"#,
            r#","network":{"egress":{"default":"allow"}}"#,
            r#","network":null"#,
        ] {
            assert!(parse_request(&provision(network)).is_err());
            assert!(parse_request(&provision(&format!("{network}{ACK}"))).is_err());
        }
    }

    #[test]
    fn supplied_marker_preserves_closed_source_diagnostics() {
        for value in ["false", "null", r#""true""#, "1", "{}", "[]"] {
            let source = provision(&ACK.replace(":true", &format!(":{value}")));
            assert!(parse_request(&source).is_err(), "{source}");
        }
        for source in [
            provision(&ACK.replace(":true", ":true,\"acknowledgeUnrestrictedNetwork\":true")),
            provision(&ACK.replace(":true", ":true,\"unknown\":true")),
        ] {
            assert!(parse_request(&source).is_err(), "{source}");
        }
    }

    #[test]
    fn typed_construction_carries_the_required_true_marker() {
        let request = IsolationSessionProvisionRequest {
            schema: OptionalField::default(),
            comment: OptionalField::default(),
            version: Version::V0_9_0Alpha,
            phase: ProvisionPhase,
            containment: IsolationSessionContainment,
            telemetry: OptionalField::default(),
            experimental: IsolationSessionProvisionExperimental {
                isolation_session: StateAwareIsolationSession {
                    provision: IsolationSessionProvision {
                        app_id: OptionalField::present("Contoso.App".to_string()),
                        acknowledge_unrestricted_network: True,
                    },
                },
            },
        };
        let True = request
            .experimental
            .isolation_session
            .provision
            .acknowledge_unrestricted_network;
        let Request::Provision(ProvisionRequest::IsolationSession(parsed)) =
            parse_request(&provision(ACK)).unwrap()
        else {
            panic!("expected provision");
        };
        let True = parsed
            .experimental
            .isolation_session
            .provision
            .acknowledge_unrestricted_network;
    }
}
