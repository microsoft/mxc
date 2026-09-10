// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use crate::dev::state_aware::provision::ProvisionPhase;
use crate::dev::{OptionalField, Version};
use crate::dev::{Telemetry, True};
use serde::Deserialize;

string_marker! {
    /// The `isolation_session` containment of the state-aware configuration contract.
    pub struct IsolationSessionContainment => "isolation_session";
}

string_marker! {
    /// The exact `allow` default policy required by the IsolationSession network acknowledgment.
    pub struct IsolationSessionNetworkDefaultPolicy => "allow";
}

/// IsolationSession settings accepted during provisioning.
#[derive(Debug, Deserialize)]
#[cfg_attr(feature = "schema-gen", derive(schemars::JsonSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct IsolationSessionProvision {
    /// Optional application identifier carried by the sandbox identity.
    #[serde(default)]
    pub app_id: OptionalField<String>,
    /// Affirmative acknowledgment that the container's network is unrestricted
    /// and cannot be filtered or denied. Only the JSON value `true` is valid.
    ///
    /// Provision-phase only: the posture is fixed for the sandbox's lifetime,
    /// so no later phase accepts it.
    #[serde(default)]
    pub acknowledge_unrestricted_network: OptionalField<True>,
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

/// The exact unrestricted-network acknowledgment required when provisioning an IsolationSession.
#[derive(Debug, Deserialize)]
#[cfg_attr(feature = "schema-gen", derive(schemars::JsonSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct IsolationSessionNetwork {
    /// Exact `allow` default network policy marker.
    pub default_policy: IsolationSessionNetworkDefaultPolicy,
    /// Required acknowledgment that local network access is allowed.
    pub allow_local_network: True,
}

/// The description the generated schema carries for the public provision
/// request root. Kept beside the type so the manual `JsonSchema` impl documents
/// the contract rather than the private carrier it forwards.
#[cfg(feature = "schema-gen")]
const REQUEST_SCHEMA_DESCRIPTION: &str = "A complete state-aware `provision` request for \
    isolation_session. The container's network is unrestricted and MXC cannot filter or deny it, \
    so the request must acknowledge that: supply \
    `experimental.isolation_session.provision.acknowledgeUnrestrictedNetwork: true`, the legacy \
    `network` acknowledgment, or both consistent forms. At least one is required; supplying both \
    is valid.";

/// A complete state-aware `provision` request for isolation_session
///
/// At least one of the two acknowledgment forms must be present, and both
/// together are also valid — see
/// [`validate`](IsolationSessionProvisionRequest::validate). The requirement is
/// enforced on every deserialization through the private field carrier below,
/// so no Serde entry point can produce an unvalidated value, and `validate`
/// re-checks a value a caller assembled from the public fields directly.
#[derive(Debug, Deserialize)]
#[serde(try_from = "IsolationSessionProvisionRequestFields")]
pub struct IsolationSessionProvisionRequest {
    /// Optional JSON Schema reference for editor validation.
    pub schema: OptionalField<String>,
    /// Optional human-readable annotation ignored by the runtime.
    pub comment: OptionalField<serde_json::Value>,
    /// Exact development contract version.
    pub version: Version,
    /// Exact `provision` phase marker.
    pub phase: ProvisionPhase,
    /// Exact `isolation_session` containment marker.
    pub containment: IsolationSessionContainment,
    /// Optional legacy unrestricted-network acknowledgment.
    ///
    /// Either this or the acknowledgment nested under
    /// `experimental.isolation_session.provision` must be present.
    pub network: OptionalField<IsolationSessionNetwork>,
    /// Optional telemetry configuration.
    pub telemetry: OptionalField<Telemetry>,
    /// Optional closed experimental settings.
    pub experimental: OptionalField<IsolationSessionProvisionExperimental>,
}

/// The private field carrier the public request is built from.
//
// It exists so the conditional acknowledgment requirement is part of
// *deserialization* rather than a check a caller could skip: every Serde entry
// point — including callers that deserialize this root directly instead of
// going through `parse_request` — passes through `TryFrom`. Unknown fields,
// duplicate keys, explicit `null`, and positional-sequence input all behave
// exactly as they did when the public struct was derived directly, because this
// carrier is an ordinary derived struct with the same attributes.
//
// Its doc comment is deliberately a single line: the manual `JsonSchema` impl
// below replaces the struct-level description with the public request's own, so
// no internal prose can reach the generated artifacts.
#[derive(Debug, Deserialize)]
#[cfg_attr(feature = "schema-gen", derive(schemars::JsonSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct IsolationSessionProvisionRequestFields {
    /// Optional JSON Schema reference for editor validation.
    #[serde(rename = "$schema", default)]
    schema: OptionalField<String>,
    /// Optional human-readable annotation ignored by the runtime.
    #[serde(rename = "_comment", default)]
    comment: OptionalField<serde_json::Value>,
    /// Exact development contract version.
    version: Version,
    /// Exact `provision` phase marker.
    phase: ProvisionPhase,
    /// Exact `isolation_session` containment marker.
    containment: IsolationSessionContainment,
    /// Optional legacy unrestricted-network acknowledgment.
    #[serde(default)]
    network: OptionalField<IsolationSessionNetwork>,
    /// Optional telemetry configuration.
    #[serde(default)]
    telemetry: OptionalField<Telemetry>,
    /// Optional closed experimental settings.
    #[serde(default)]
    experimental: OptionalField<IsolationSessionProvisionExperimental>,
}

/// The IsolationSession provision request carried no acknowledgment.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error(
    "an isolation_session provision request must acknowledge that the container's network is \
     unrestricted: supply `experimental.isolation_session.provision.\
     acknowledgeUnrestrictedNetwork: true`, or the legacy `network` object with \
     `defaultPolicy: \"allow\"` and `allowLocalNetwork: true`"
)]
pub struct MissingUnrestrictedNetworkAcknowledgment;

impl IsolationSessionProvisionRequest {
    /// Whether the nested experimental acknowledgment is present.
    fn acknowledges_unrestricted_network(&self) -> bool {
        self.experimental
            .as_ref()
            .and_then(|experimental| experimental.isolation_session.as_ref())
            .and_then(|isolation_session| isolation_session.provision.as_ref())
            .is_some_and(|provision| {
                provision
                    .acknowledge_unrestricted_network
                    .as_ref()
                    .is_some()
            })
    }

    /// Checks the conditional acknowledgment requirement.
    ///
    /// The backend cannot filter or deny the container's network, so a
    /// provision request must say so. Either acknowledgment form satisfies the
    /// requirement, and supplying both consistent forms is valid — the rule is
    /// "at least one", never "exactly one".
    ///
    /// Deserialization already applies this, so it only matters for a value a
    /// caller assembled from the public fields. The adapter calls it for that
    /// reason.
    ///
    /// # Errors
    ///
    /// Returns [`MissingUnrestrictedNetworkAcknowledgment`] when neither form
    /// is present.
    pub fn validate(&self) -> Result<(), MissingUnrestrictedNetworkAcknowledgment> {
        if self.network.as_ref().is_some() || self.acknowledges_unrestricted_network() {
            Ok(())
        } else {
            Err(MissingUnrestrictedNetworkAcknowledgment)
        }
    }
}

impl TryFrom<IsolationSessionProvisionRequestFields> for IsolationSessionProvisionRequest {
    type Error = MissingUnrestrictedNetworkAcknowledgment;

    fn try_from(fields: IsolationSessionProvisionRequestFields) -> Result<Self, Self::Error> {
        // Exhaustively destructured so a new contract field cannot be dropped
        // silently on its way to the public request.
        let IsolationSessionProvisionRequestFields {
            schema,
            comment,
            version,
            phase,
            containment,
            network,
            telemetry,
            experimental,
        } = fields;
        let request = Self {
            schema,
            comment,
            version,
            phase,
            containment,
            network,
            telemetry,
            experimental,
        };
        request.validate()?;
        Ok(request)
    }
}

/// Forwards the private carrier's derived schema under the public root name, so
/// the generated document keeps its historical definition name and the carrier
/// never appears in it. The conditional acknowledgment requirement is added as
/// an object-local `anyOf`: at least one form, never an exclusive choice.
#[cfg(feature = "schema-gen")]
impl schemars::JsonSchema for IsolationSessionProvisionRequest {
    fn schema_name() -> String {
        "IsolationSessionProvisionRequest".to_string()
    }

    fn json_schema(generator: &mut schemars::gen::SchemaGenerator) -> schemars::schema::Schema {
        // Generated inline rather than through `subschema_for`, so the private
        // carrier's name never reaches the definitions table.
        let schema = <IsolationSessionProvisionRequestFields as schemars::JsonSchema>::json_schema(
            generator,
        );
        let mut value =
            serde_json::to_value(schema).expect("provision request schema serializes to JSON");
        let object = value
            .as_object_mut()
            .expect("provision request schema is an object");
        // The carrier's own description documents an implementation detail;
        // replace it with the public request's contract description.
        object.insert(
            "description".to_string(),
            serde_json::Value::String(REQUEST_SCHEMA_DESCRIPTION.to_string()),
        );
        let constraints = object
            .entry("anyOf")
            .or_insert_with(|| serde_json::Value::Array(Vec::new()))
            .as_array_mut()
            .expect("anyOf constraints");
        constraints.push(serde_json::json!({ "required": ["network"] }));
        constraints.push(serde_json::json!({
            "required": ["experimental"],
            "properties": {
                "experimental": {
                    "required": ["isolation_session"],
                    "properties": {
                        "isolation_session": {
                            "required": ["provision"],
                            "properties": {
                                "provision": {
                                    "required": ["acknowledgeUnrestrictedNetwork"]
                                }
                            }
                        }
                    }
                }
            }
        }));
        serde_json::from_value(value).expect("provision request schema round-trips")
    }
}

#[cfg(test)]
mod tests {
    use crate::dev::{parse_request, ProvisionRequest, Request};

    const LEGACY_NETWORK: &str = r#""network":{"defaultPolicy":"allow","allowLocalNetwork":true}"#;
    const ACKNOWLEDGMENT: &str = r#""experimental":{"isolation_session":{"provision":{"acknowledgeUnrestrictedNetwork":true}}}"#;

    fn provision(fields: &str) -> String {
        format!(
            r#"{{"version":"0.9.0-alpha","phase":"provision","containment":"isolation_session"{fields}}}"#
        )
    }

    fn parse(fields: &str) -> Result<super::IsolationSessionProvisionRequest, String> {
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
    fn legacy_only_new_only_and_both_consistent_are_accepted() {
        let legacy = parse(&format!(",{LEGACY_NETWORK}")).unwrap();
        assert!(legacy.network.as_ref().is_some());
        assert!(!legacy.acknowledges_unrestricted_network());

        let new_only = parse(&format!(",{ACKNOWLEDGMENT}")).unwrap();
        assert!(new_only.network.as_ref().is_none());
        assert!(new_only.acknowledges_unrestricted_network());

        let both = parse(&format!(",{LEGACY_NETWORK},{ACKNOWLEDGMENT}")).unwrap();
        assert!(both.network.as_ref().is_some());
        assert!(both.acknowledges_unrestricted_network());
    }

    #[test]
    fn neither_acknowledgment_is_a_structural_rejection() {
        let error = parse("").unwrap_err();
        assert!(
            error.contains("must acknowledge that the container's network is unrestricted"),
            "{error}"
        );
        // An experimental section that stops short of the acknowledgment does
        // not satisfy the requirement either.
        for fields in [
            r#","experimental":{}"#,
            r#","experimental":{"isolation_session":{}}"#,
            r#","experimental":{"isolation_session":{"provision":{}}}"#,
            r#","experimental":{"isolation_session":{"provision":{"appId":"Contoso.App"}}}"#,
        ] {
            assert!(parse(fields).is_err(), "{fields}");
        }
    }

    #[test]
    fn an_empty_or_partial_network_object_stays_structurally_invalid() {
        for network in [
            r#""network":{}"#,
            r#""network":{"defaultPolicy":"allow"}"#,
            r#""network":{"allowLocalNetwork":true}"#,
            r#""network":{"defaultPolicy":"block","allowLocalNetwork":true}"#,
            r#""network":{"defaultPolicy":"allow","allowLocalNetwork":false}"#,
            r#""network":null"#,
        ] {
            assert!(parse(&format!(",{network}")).is_err(), "{network}");
            assert!(
                parse(&format!(",{network},{ACKNOWLEDGMENT}")).is_err(),
                "an acknowledgment must not rescue an invalid network object: {network}"
            );
        }
    }

    #[test]
    fn only_the_json_value_true_acknowledges() {
        for value in ["false", "null", r#""true""#, "1", "{}", "[]"] {
            let fields = format!(
                r#","experimental":{{"isolation_session":{{"provision":{{"acknowledgeUnrestrictedNetwork":{value}}}}}}}"#
            );
            assert!(parse(&fields).is_err(), "{fields}");
        }
    }

    #[test]
    fn misplaced_acknowledgments_are_rejected() {
        for fields in [
            // One-shot spelling (no `provision` leaf) on a state-aware request.
            r#","experimental":{"isolation_session":{"acknowledgeUnrestrictedNetwork":true}}"#,
            // Another backend's section.
            r#","experimental":{"wslc":{"provision":{"acknowledgeUnrestrictedNetwork":true}}}"#,
            // Top-level.
            r#","acknowledgeUnrestrictedNetwork":true"#,
            // Inside the legacy network object.
            r#","network":{"defaultPolicy":"allow","allowLocalNetwork":true,"acknowledgeUnrestrictedNetwork":true}"#,
        ] {
            assert!(parse(fields).is_err(), "{fields}");
        }
    }

    #[test]
    fn unknown_and_duplicate_source_diagnostics_are_preserved() {
        assert!(parse(&format!(",{ACKNOWLEDGMENT},\"unknown\":true")).is_err());
        assert!(parse(&format!(",{ACKNOWLEDGMENT},{ACKNOWLEDGMENT}")).is_err());
        assert!(parse(&format!(",{LEGACY_NETWORK},{LEGACY_NETWORK}")).is_err());
        let error = parse(&format!(",{ACKNOWLEDGMENT},\"unknown\":true")).unwrap_err();
        assert!(error.contains("unknown field `unknown`"), "{error}");
    }

    #[test]
    fn typed_construction_is_checked_by_validate() {
        // A caller assembling the public fields directly bypasses Serde, so
        // `validate` is the seam that keeps the requirement enforced.
        let mut request = parse(&format!(",{LEGACY_NETWORK}")).unwrap();
        request.validate().unwrap();
        request.network = crate::dev::OptionalField::default();
        assert_eq!(
            request.validate(),
            Err(super::MissingUnrestrictedNetworkAcknowledgment)
        );

        let acknowledged = parse(&format!(",{ACKNOWLEDGMENT}")).unwrap();
        acknowledged.validate().unwrap();
    }

    #[cfg(feature = "schema-gen")]
    #[test]
    fn the_generated_schema_requires_at_least_one_acknowledgment() {
        let schema = crate::dev::development_schema();
        let root = &schema["definitions"]["IsolationSessionProvisionRequest"];
        let required = root["required"].as_array().expect("required fields");
        assert!(
            !required.contains(&serde_json::json!("network")),
            "network must no longer be unconditionally required"
        );
        let any_of = root["anyOf"].as_array().expect("presence constraint");
        assert_eq!(any_of.len(), 2, "at least one, never an exclusive choice");
        assert_eq!(any_of[0], serde_json::json!({"required": ["network"]}));
        assert_eq!(
            any_of[1]["properties"]["experimental"]["properties"]["isolation_session"]
                ["properties"]["provision"]["required"],
            serde_json::json!(["acknowledgeUnrestrictedNetwork"])
        );
        assert!(
            root["description"]
                .as_str()
                .expect("root description")
                .contains("acknowledgeUnrestrictedNetwork"),
            "the public description documents the requirement"
        );
        assert!(
            !schema["definitions"]
                .as_object()
                .expect("definitions")
                .keys()
                .any(|name| name.contains("Fields")),
            "the private field carrier must not leak into the schema"
        );
    }
}
