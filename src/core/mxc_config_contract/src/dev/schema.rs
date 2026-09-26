// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! JSON Schema composition for the mutable development contract.

use schemars::{gen::SchemaGenerator, JsonSchema};
use serde_json::{json, Value};

use super::{
    DeprovisionRequest, ExecRequest, IsolationSessionProvisionRequest, OneShotRequest,
    StartRequest, StopRequest, WindowsSandboxProvisionRequest, WslcProvisionRequest,
};

fn subschema<T: JsonSchema>(generator: &mut SchemaGenerator) -> Value {
    serde_json::to_value(generator.subschema_for::<T>())
        .expect("contract schema serializes to JSON")
}

fn discriminator(property: &str, value: &str) -> Value {
    let mut properties = serde_json::Map::new();
    properties.insert(property.to_string(), json!({ "const": value }));

    json!({
        "properties": properties,
        "required": [property]
    })
}

fn branch(condition: Value, selected: Value, otherwise: Value) -> Value {
    json!({
        "if": condition,
        "then": selected,
        "else": otherwise
    })
}

fn provision_dispatch(windows_sandbox: Value, isolation_session: Value, wslc: Value) -> Value {
    branch(
        discriminator("containment", "windows_sandbox"),
        windows_sandbox,
        branch(
            discriminator("containment", "isolation_session"),
            isolation_session,
            branch(
                discriminator("containment", "wslc"),
                wslc,
                Value::Bool(false),
            ),
        ),
    )
}

fn one_shot_dispatch(one_shot: Value) -> Value {
    json!({
        "allOf": [
            one_shot,
            branch(
                discriminator("containment", "isolation_session"),
                json!({
                    "required": ["network"],
                    "properties": {
                        "network": {
                            "type": "object",
                            "additionalProperties": false,
                            "required": ["egress", "ingress"],
                            "properties": {
                                "egress": {
                                    "type": "object",
                                    "additionalProperties": false,
                                    "required": ["default"],
                                    "properties": {
                                        "default": { "const": "allow" }
                                    }
                                },
                                "ingress": {
                                    "type": "object",
                                    "additionalProperties": false,
                                    "required": ["default", "hostLoopback"],
                                    "properties": {
                                        "default": { "const": "allow" },
                                        "hostLoopback": { "const": "allow" }
                                    }
                                }
                            }
                        },
                        "runtimeConfig": {
                            "not": {
                                "required": ["networkProxy"]
                            }
                        }
                    }
                }),
                Value::Bool(true)
            )
        ]
    })
}

#[allow(clippy::too_many_arguments)]
fn phase_dispatch(
    provision: Value,
    start: Value,
    exec: Value,
    stop: Value,
    deprovision: Value,
) -> Value {
    branch(
        discriminator("phase", "provision"),
        provision,
        branch(
            discriminator("phase", "start"),
            start,
            branch(
                discriminator("phase", "exec"),
                exec,
                branch(
                    discriminator("phase", "stop"),
                    stop,
                    branch(
                        discriminator("phase", "deprovision"),
                        deprovision,
                        Value::Bool(false),
                    ),
                ),
            ),
        ),
    )
}

/// Generates the unrendered JSON Schema for the mutable `1.1.0-alpha`
/// development contract.
///
/// The document selects one of eight closed request roots through nested
/// `if`/`then` discriminators. This avoids reporting validation failures from
/// unrelated lifecycle phases while retaining a shared definitions table.
pub fn development_schema() -> Value {
    let mut generator = SchemaGenerator::default();

    let one_shot = subschema::<OneShotRequest>(&mut generator);
    let windows_sandbox = subschema::<WindowsSandboxProvisionRequest>(&mut generator);
    let isolation_session = subschema::<IsolationSessionProvisionRequest>(&mut generator);
    let wslc = subschema::<WslcProvisionRequest>(&mut generator);
    let start = subschema::<StartRequest>(&mut generator);
    let exec = subschema::<ExecRequest>(&mut generator);
    let stop = subschema::<StopRequest>(&mut generator);
    let deprovision = subschema::<DeprovisionRequest>(&mut generator);

    let provision = provision_dispatch(windows_sandbox, isolation_session, wslc);
    let state_aware = phase_dispatch(provision, start, exec, stop, deprovision);
    let dispatch = branch(
        json!({ "required": ["phase"] }),
        state_aware,
        one_shot_dispatch(one_shot),
    );
    let definitions =
        serde_json::to_value(generator.take_definitions()).expect("definitions serialize to JSON");

    json!({
        "$schema": "http://json-schema.org/draft-07/schema#",
        "title": "MXC Configuration 1.1.0-alpha",
        "description": "Exact mutable MXC development configuration contract.",
        "$comment": "GENERATED FILE - DO NOT EDIT. Regenerate with: cargo run --manifest-path src/Cargo.toml -p mxc_schema_gen -- schema --version 1.1.0-alpha --out schemas/dev/mxc-config.schema.1.1.0-alpha.json. This exact contract is authoritative for declared 1.1.0-alpha requests. Request roots are selected by phase and provision containment.",
        "allOf": [dispatch],
        "definitions": definitions
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::schema_test_support::{assert_schema_invariants, SchemaExpectations};

    const ROOT_NAMES: &[&str] = &[
        "OneShotRequest",
        "WindowsSandboxProvisionRequest",
        "IsolationSessionProvisionRequest",
        "WslcProvisionRequest",
        "StartRequest",
        "ExecRequest",
        "StopRequest",
        "DeprovisionRequest",
    ];

    #[test]
    fn development_schema_satisfies_shared_invariants() {
        assert_schema_invariants(SchemaExpectations {
            version: "1.1.0-alpha",
            schema: development_schema(),
            regenerated_schema: development_schema(),
            request_roots: ROOT_NAMES,
            phase_markers: &[
                ("WindowsSandboxProvisionRequest", "provision"),
                ("IsolationSessionProvisionRequest", "provision"),
                ("WslcProvisionRequest", "provision"),
                ("StartRequest", "start"),
                ("ExecRequest", "exec"),
                ("StopRequest", "stop"),
                ("DeprovisionRequest", "deprovision"),
            ],
            containment_markers: &[
                ("WindowsSandboxProvisionRequest", "windows_sandbox"),
                ("IsolationSessionProvisionRequest", "isolation_session"),
                ("WslcProvisionRequest", "wslc"),
            ],
            compatibility_aliases: false,
            one_shot_required: &["process"],
            exec_required: &["process"],
        });
    }
}
