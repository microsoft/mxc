// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Wire types for the mutable `0.8.0-alpha` state-aware configuration
//! contract.

macro_rules! string_marker {
    (
        $(#[$meta:meta])*
        $vis:vis struct $name:ident => $wire_value:literal;
    ) => {
        $(#[$meta])*
        #[derive(Debug, Clone, Copy, PartialEq, Eq)]
        $vis struct $name;

        #[cfg(feature = "schema-gen")]
        impl schemars::JsonSchema for $name {
            fn schema_name() -> String {
                stringify!($name).to_string()
            }

            fn json_schema(
                _generator: &mut schemars::gen::SchemaGenerator,
            ) -> schemars::schema::Schema {
                use schemars::schema::{
                    InstanceType, Schema, SchemaObject, SingleOrVec,
                };

                Schema::Object(SchemaObject {
                    instance_type: Some(SingleOrVec::Single(Box::new(
                        InstanceType::String,
                    ))),
                    enum_values: Some(vec![serde_json::Value::String(
                        $wire_value.to_string(),
                    )]),
                    ..Default::default()
                })
            }
        }

        impl<'de> serde::Deserialize<'de> for $name {
            fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
            where
                D: serde::Deserializer<'de>,
            {
                let value = <std::borrow::Cow<'de, str> as serde::Deserialize>::deserialize(deserializer)?;

                if value == $wire_value {
                    Ok(Self)
                } else {
                    Err(serde::de::Error::unknown_variant(&value, &[$wire_value]))
                }
            }
        }
    };
}

mod deprovision;
mod exec;
mod phase;
mod provision;
mod start;
mod stop;

pub use deprovision::{DeprovisionExperimental, DeprovisionPhase, DeprovisionRequest};
pub use exec::{ExecExperimental, ExecPhase, ExecRequest};
pub use phase::{probe_phase, Phase, PhaseProbeError};
pub use provision::{probe_containment, Containment, ContainmentProbeError};
pub use provision::{
    IsolationSessionContainment, IsolationSessionNetwork, IsolationSessionNetworkDefaultPolicy,
    IsolationSessionProvision, IsolationSessionProvisionExperimental,
    IsolationSessionProvisionRequest, StateAwareIsolationSession,
};
pub use provision::{ProvisionPhase, ProvisionRequest};
pub use provision::{
    StateAwareWslc, WslcContainment, WslcProvision, WslcProvisionExperimental, WslcProvisionRequest,
};
pub use provision::{
    WindowsSandboxContainment, WindowsSandboxExperimental, WindowsSandboxProvisionRequest,
};
pub use start::{StartExperimental, StartPhase, StartRequest};
pub use stop::{StopExperimental, StopPhase, StopRequest};
