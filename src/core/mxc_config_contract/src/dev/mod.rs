// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Wire types for the mutable `0.8.0-alpha` configuration contract.
//!
//! These types validate the JSON structure and value constraints of the
//! in-development contract. They preserve omitted optional fields for a later
//! adapter to default and normalize.

// Serde's default fieldless-enum deserializer also accepts externally
// tagged object forms such as {"process": null}. Published contracts accept
// only string values. This macro generates a string-only deserializer while
// supporting explicit compatibility aliases.
macro_rules! string_enum {
    (@schema_name $name:ident, $schema_name:literal) => {
        $schema_name.to_string()
    };
    (@schema_name $name:ident) => {
        stringify!($name).to_string()
    };
    (
        $(#[$enum_meta:meta])*
        $vis:vis enum $name:ident
        $(, schema_name = $schema_name:literal)?
        {
            $(
                $(#[$variant_meta:meta])*
                $variant:ident => [
                    $canonical:literal
                    $(, $alias:literal)*
                ]
            ),+ $(,)?
        }
    ) => {
        $(#[$enum_meta])*
        $vis enum $name {
            $(
                $(#[$variant_meta])*
                $variant,
            )+
        }

        #[cfg(feature = "schema-gen")]
        impl schemars::JsonSchema for $name {
            fn schema_name() -> String {
                string_enum!(@schema_name $name $(, $schema_name)?)
            }

            fn json_schema(
                _generator: &mut schemars::gen::SchemaGenerator,
            ) -> schemars::schema::Schema {
                use schemars::schema::{
                    InstanceType, Metadata, Schema, SchemaObject, SingleOrVec,
                    SubschemaValidation,
                };

                let branches = vec![
                    $(
                        Schema::Object(SchemaObject {
                            metadata: Some(Box::new(Metadata {
                                description: Some(
                                    stringify!($variant).to_string(),
                                ),
                                ..Default::default()
                            })),
                            instance_type: Some(SingleOrVec::Single(Box::new(
                                InstanceType::String,
                            ))),
                            enum_values: Some(vec![
                                serde_json::Value::String(
                                    $canonical.to_string(),
                                ),
                            ]),
                            ..Default::default()
                        }),
                        $(
                            Schema::Object(SchemaObject {
                                metadata: Some(Box::new(Metadata {
                                    description: Some(
                                        stringify!($variant).to_string(),
                                    ),
                                    ..Default::default()
                                })),
                                instance_type: Some(SingleOrVec::Single(Box::new(
                                    InstanceType::String,
                                ))),
                                enum_values: Some(vec![
                                    serde_json::Value::String(
                                        $alias.to_string(),
                                    ),
                                ]),
                                ..Default::default()
                            }),
                        )*
                    )+
                ];

                Schema::Object(SchemaObject {
                    subschemas: Some(Box::new(SubschemaValidation {
                        one_of: Some(branches),
                        ..Default::default()
                    })),
                    ..Default::default()
                })
            }
        }

        impl $name {
            const WIRE_VALUES: &'static [&'static str] = &[
                $(
                    $canonical,
                    $($alias,)*
                )+
            ];
        }

        impl<'de> serde::Deserialize<'de> for $name {
            fn deserialize<D>(
                deserializer: D,
            ) -> Result<Self, D::Error>
            where
                D: serde::Deserializer<'de>,
            {
                struct StringEnumVisitor;

                impl<'de> serde::de::Visitor<'de>
                    for StringEnumVisitor
                {
                    type Value = $name;

                    fn expecting(
                        &self,
                        formatter: &mut std::fmt::Formatter<'_>,
                    ) -> std::fmt::Result {
                        write!(
                            formatter,
                            "a valid {} string",
                            stringify!($name)
                        )
                    }

                    fn visit_str<E>(
                        self,
                        value: &str,
                    ) -> Result<Self::Value, E>
                    where
                        E: serde::de::Error,
                    {
                        match value {
                            $(
                                $canonical
                                $(| $alias)*
                                    => Ok($name::$variant),
                            )+
                            _ => Err(E::unknown_variant(
                                value,
                                $name::WIRE_VALUES,
                            )),
                        }
                    }
                }

                deserializer.deserialize_str(StringEnumVisitor)
            }
        }

        // Generate a test for each string enum variant and its aliases.
        // The test ensures that the enum deserializes from the canonical and
        // alias string values (if any), and that it rejects externally tagged
        // and non-string values. Emitted here as part of the macro to avoid
        // repeating the same test logic for each enum in a separate location
        // where the enum's private WIRE_VALUES constant is not accessible.
        #[cfg(test)]
        #[allow(non_snake_case)]
        #[test]
        fn $name() {
            $(
                for wire_value in [
                    $canonical,
                    $($alias,)*
                ] {
                    let json = serde_json::to_string(wire_value).unwrap();
                    let parsed: $name = serde_json::from_str(&json).unwrap();

                    assert!(
                        matches!(parsed, $name::$variant),
                        "{wire_value:?} did not map to {}::{}",
                        stringify!($name),
                        stringify!($variant),
                    );

                    let externally_tagged = format!("{{{json}:null}}");
                    assert!(
                        serde_json::from_str::<$name>(&externally_tagged).is_err(),
                        "{} accepted externally tagged value {externally_tagged}",
                        stringify!($name),
                    );
                }
            )+

            for json in ["null", "true", "0", "[]", "{}"] {
                assert!(
                    serde_json::from_str::<$name>(json).is_err(),
                    "{} accepted non-string value {json}",
                    stringify!($name),
                );
            }
        }
    };
}

string_enum! {
    /// The exact version marker accepted by this contract.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum Version {
        /// The development `0.8.0-alpha` contract.
        V0_8_0Alpha => ["0.8.0-alpha"],
    }
}

mod experimental;
mod network;
/// The development `0.8.0-alpha` one-shot configuration contract.
mod one_shot;
mod primitives;
mod request;
#[cfg(feature = "schema-gen")]
mod schema;
mod stable;
/// The development `0.8.0-alpha` state-aware configuration contract.
mod state_aware;

pub use experimental::{
    OneShotExperimental, OneShotWindowsSandbox, OneShotWslc, PortMapping, Telemetry, TestFeature,
    TransportProtocol,
};
pub use network::{
    DefaultNetworkPolicy, Network, NetworkAction, NetworkEgress, NetworkEnforcementMode,
    NetworkIngress, NetworkPeer, NetworkPort, NetworkProtocol, NetworkProxy, NetworkRule,
};
pub use one_shot::{Containment as OneShotContainment, Request as OneShotRequest};
pub use primitives::{NonEmptyString, OptionalField, True};
pub use request::{parse_request, Request, RequestParseError};
#[cfg(feature = "schema-gen")]
pub use schema::development_schema;
pub use stable::{
    CaptureDenials, CaptureDenialsMode, Fallback, Filesystem, LaunchMethod, Lifecycle, Lxc,
    Process, ProcessContainer, ProcessContainerCapability, ProcessContainerNetwork,
    ProcessContainerUi, ProcessContainerUiIsolation, RuntimeConfig, Seatbelt, Ui, UiClipboard,
};
pub use state_aware::{probe_containment, Containment, ContainmentProbeError};
pub use state_aware::{probe_phase, Phase, PhaseProbeError};
pub use state_aware::{DeprovisionExperimental, DeprovisionPhase, DeprovisionRequest};
pub use state_aware::{ExecExperimental, ExecPhase, ExecRequest};
pub use state_aware::{
    IsolationSessionContainment, IsolationSessionNetwork, IsolationSessionNetworkDefaultPolicy,
    IsolationSessionProvision, IsolationSessionProvisionExperimental,
    IsolationSessionProvisionRequest, StateAwareIsolationSession,
};
pub use state_aware::{ProvisionPhase, ProvisionRequest};
pub use state_aware::{StartExperimental, StartPhase, StartRequest};
pub use state_aware::{
    StateAwareWslc, WslcContainment, WslcProvision, WslcProvisionExperimental, WslcProvisionRequest,
};
pub use state_aware::{StopExperimental, StopPhase, StopRequest};
pub use state_aware::{
    WindowsSandboxContainment, WindowsSandboxExperimental, WindowsSandboxProvisionRequest,
};
