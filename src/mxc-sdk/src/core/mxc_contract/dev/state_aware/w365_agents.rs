// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Development-only W365 Agents lifecycle settings. These do not enable a backend.

use crate::mxc_contract::dev::{OptionalField, ProvisionPhase, Telemetry, Version};
use serde::{Deserialize, Deserializer};

string_marker! {
    /// The development-only W365 Agents provision containment.
    pub struct W365AgentsContainment => "w365_agents";
}

string_enum! {
    /// Supported W365 user types; omission does not infer an identity.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum W365AgentsUserType {
        Local => ["Local"],
        HumanUser => ["HumanUser"],
        Agentic => ["Agentic"],
    }
}

/// A hyphenated ASCII-hex GUID, preserving the caller's spelling.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct W365AgentsGuid(String);

impl W365AgentsGuid {
    /// Consumes the GUID without changing its spelling.
    pub fn into_inner(self) -> String {
        self.0
    }
}

impl<'de> Deserialize<'de> for W365AgentsGuid {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let value = String::deserialize(deserializer)?;
        let valid = value.len() == 36
            && value.bytes().enumerate().all(|(index, byte)| {
                if matches!(index, 8 | 13 | 18 | 23) {
                    byte == b'-'
                } else {
                    byte.is_ascii_hexdigit()
                }
            });
        if !valid {
            return Err(serde::de::Error::custom(
                "expected a hyphenated ASCII-hex GUID",
            ));
        }
        Ok(Self(value))
    }
}

#[cfg(feature = "schema-gen")]
impl schemars::JsonSchema for W365AgentsGuid {
    fn schema_name() -> String {
        "W365AgentsGuid".to_owned()
    }

    fn json_schema(_: &mut schemars::gen::SchemaGenerator) -> schemars::schema::Schema {
        use schemars::schema::{InstanceType, Schema, SchemaObject, StringValidation};
        Schema::Object(SchemaObject {
            instance_type: Some(InstanceType::String.into()),
            string: Some(Box::new(StringValidation {
                min_length: Some(36),
                max_length: Some(36),
                pattern: Some(
                    "^[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}$"
                        .to_owned(),
                ),
            })),
            ..Default::default()
        })
    }
}

/// W365 checkout settings. Defaults and resolved service validation belong to the backend.
#[derive(Debug, Deserialize)]
#[cfg_attr(feature = "schema-gen", derive(schemars::JsonSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct W365AgentsProvision {
    /// Required pool identifier; no automatic pool selection.
    pub pool_id: W365AgentsGuid,
    /// Optional user type.
    #[serde(default)]
    pub user_type: OptionalField<W365AgentsUserType>,
    /// Optional user object identifier.
    #[serde(default)]
    pub user_object_id: OptionalField<W365AgentsGuid>,
}

/// A closed W365 settings object containing only checkout settings.
#[derive(Debug, Deserialize)]
#[cfg_attr(feature = "schema-gen", derive(schemars::JsonSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct StateAwareW365AgentsProvision {
    /// Optional provision settings; an empty wrapper remains distinct from omission.
    #[serde(
        default,
        deserialize_with = "crate::mxc_contract::dev::primitives::deserialize_optional_object"
    )]
    pub provision: OptionalField<W365AgentsProvision>,
}

/// The complete development W365 provision request, excluding unenforceable local policy.
#[derive(Debug, Deserialize)]
#[cfg_attr(feature = "schema-gen", derive(schemars::JsonSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct W365AgentsProvisionRequest {
    /// Optional editor schema reference.
    #[serde(rename = "$schema", default)]
    pub schema: OptionalField<String>,
    /// Optional annotation.
    #[serde(rename = "_comment", default)]
    pub comment: OptionalField<serde_json::Value>,
    /// Development contract version.
    pub version: Version,
    /// Provision phase marker.
    pub phase: ProvisionPhase,
    /// W365 containment marker.
    pub containment: W365AgentsContainment,
    /// Optional telemetry settings.
    #[serde(default)]
    pub telemetry: OptionalField<Telemetry>,
    /// Optional provision settings; missing configuration is not defaulted by parsing.
    #[serde(
        default,
        deserialize_with = "crate::mxc_contract::dev::primitives::deserialize_optional_object"
    )]
    pub w365_agents: OptionalField<StateAwareW365AgentsProvision>,
}
