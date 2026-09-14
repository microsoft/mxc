// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! JSON Schema composition for the mutable development contract.

use schemars::{gen::SchemaGenerator, JsonSchema};
use serde_json::{json, Value};

use super::{
    DeprovisionRequest, ExecRequest, IsolationSessionProvisionRequest, OneShotRequest,
    PublicationProfile, StableCandidateDeprovisionRequest, StableCandidateExecRequest,
    StableCandidateIsolationSessionProvisionRequest, StableCandidateOneShotRequest,
    StableCandidateStartRequest, StableCandidateStopRequest,
    StableCandidateWindowsSandboxProvisionRequest, StableCandidateWslcProvisionRequest,
    StartRequest, StateAwareBackend, StopRequest, WindowsSandboxProvisionRequest,
    WslcProvisionRequest, V0_9_0_ALPHA_PUBLICATION_PROFILE,
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
                json!({ "required": ["network"] }),
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

fn add_property_alias(definitions: &mut Value, definition: &str, canonical: &str, alias: &str) {
    let properties = definitions[definition]["properties"]
        .as_object_mut()
        .expect("object definition properties");
    let schema = properties
        .get(canonical)
        .unwrap_or_else(|| panic!("missing canonical property {definition}.{canonical}"))
        .clone();
    properties.insert(alias.to_string(), schema);
}

fn exclude_duplicate_alias(
    definitions: &mut Value,
    definition: &str,
    canonical: &str,
    alias: &str,
) {
    let definition = definitions[definition]
        .as_object_mut()
        .expect("object definition");
    let constraints = definition
        .entry("allOf")
        .or_insert_with(|| Value::Array(Vec::new()))
        .as_array_mut()
        .expect("allOf constraints");
    constraints.push(json!({
        "not": {
            "required": [canonical, alias]
        }
    }));
}

/// Generates the unrendered JSON Schema for the mutable `0.9.0-alpha`
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
    let mut definitions =
        serde_json::to_value(generator.take_definitions()).expect("definitions serialize to JSON");
    add_property_alias(
        &mut definitions,
        "OneShotRequest",
        "processContainer",
        "appContainer",
    );
    exclude_duplicate_alias(
        &mut definitions,
        "OneShotRequest",
        "processContainer",
        "appContainer",
    );
    add_property_alias(
        &mut definitions,
        "OneShotRequest",
        "seatbelt",
        "macos_sandbox",
    );
    exclude_duplicate_alias(
        &mut definitions,
        "OneShotRequest",
        "seatbelt",
        "macos_sandbox",
    );

    json!({
        "$schema": "http://json-schema.org/draft-07/schema#",
        "title": "MXC Configuration 0.9.0-alpha",
        "description": "Exact mutable MXC development configuration contract.",
        "$comment": "GENERATED FILE - DO NOT EDIT. Regenerate with: cargo run --manifest-path src/Cargo.toml -p mxc_schema_gen -- schema --version 0.9.0-alpha --out schemas/dev/mxc-config.schema.0.9.0-alpha.json. This exact contract is authoritative for declared 0.9.0-alpha requests. Request roots are selected by phase and provision containment.",
        "allOf": [dispatch],
        "definitions": definitions
    })
}

fn publication_provision_dispatch(backends: &[(StateAwareBackend, Value)]) -> Value {
    backends
        .iter()
        .rev()
        .fold(Value::Bool(false), |otherwise, (backend, selected)| {
            branch(
                discriminator("containment", backend.as_str()),
                selected.clone(),
                otherwise,
            )
        })
}

/// Generates the narrowed schema selected by a Rust publication profile.
///
/// # Errors
///
/// Returns an error when the profile is empty, selects a backend more than
/// once, or selects a backend whose provision fields still require migration
/// from the development-only `experimental` block.
pub fn publication_schema_for_profile(profile: PublicationProfile) -> Result<Value, String> {
    let mut generator = SchemaGenerator::default();
    let one_shot = profile
        .one_shot
        .then(|| subschema::<StableCandidateOneShotRequest>(&mut generator));
    let mut selected_backends = Vec::new();
    for backend in profile.state_aware_backends {
        if selected_backends
            .iter()
            .any(|(selected, _)| selected == backend)
        {
            return Err(format!(
                "publication profile selects {backend:?} more than once"
            ));
        }
        let root = match backend {
            StateAwareBackend::WindowsSandbox => {
                subschema::<StableCandidateWindowsSandboxProvisionRequest>(&mut generator)
            }
            StateAwareBackend::IsolationSession => {
                subschema::<StableCandidateIsolationSessionProvisionRequest>(&mut generator)
            }
            StateAwareBackend::Wslc => {
                subschema::<StableCandidateWslcProvisionRequest>(&mut generator)
            }
        };
        selected_backends.push((*backend, root));
    }

    let state_aware = if selected_backends.is_empty() {
        None
    } else {
        Some(phase_dispatch(
            publication_provision_dispatch(&selected_backends),
            subschema::<StableCandidateStartRequest>(&mut generator),
            subschema::<StableCandidateExecRequest>(&mut generator),
            subschema::<StableCandidateStopRequest>(&mut generator),
            subschema::<StableCandidateDeprovisionRequest>(&mut generator),
        ))
    };
    let dispatch = match (one_shot, state_aware) {
        (Some(one_shot), Some(state_aware)) => {
            branch(json!({ "required": ["phase"] }), state_aware, one_shot)
        }
        (Some(one_shot), None) => one_shot,
        (None, Some(state_aware)) => state_aware,
        (None, None) => return Err("publication profile selects no request roots".to_string()),
    };

    let mut definitions =
        serde_json::to_value(generator.take_definitions()).expect("definitions serialize to JSON");
    if profile.one_shot {
        add_property_alias(
            &mut definitions,
            "OneShotRequest",
            "processContainer",
            "appContainer",
        );
        exclude_duplicate_alias(
            &mut definitions,
            "OneShotRequest",
            "processContainer",
            "appContainer",
        );
        add_property_alias(
            &mut definitions,
            "OneShotRequest",
            "seatbelt",
            "macos_sandbox",
        );
        exclude_duplicate_alias(
            &mut definitions,
            "OneShotRequest",
            "seatbelt",
            "macos_sandbox",
        );
    }

    Ok(json!({
        "$schema": "http://json-schema.org/draft-07/schema#",
        "title": "MXC Configuration 0.9.0-alpha",
        "description": "Immutable published MXC configuration contract.",
        "$comment": "GENERATED FILE - DO NOT EDIT. Published contracts are immutable and verified by scripts/versioning/check-contract-freeze.js.",
        "allOf": [dispatch],
        "definitions": definitions
    }))
}

/// Generates the schema selected by the checked-in v0.9 publication profile.
pub fn publication_schema() -> Result<Value, String> {
    publication_schema_for_profile(V0_9_0_ALPHA_PUBLICATION_PROFILE)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::{BTreeSet, VecDeque};

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

    fn definitions(schema: &Value) -> &serde_json::Map<String, Value> {
        schema["definitions"]
            .as_object()
            .expect("schema definitions")
    }

    fn collect_refs(value: &Value, refs: &mut BTreeSet<String>) {
        match value {
            Value::Object(object) => {
                if let Some(reference) = object.get("$ref").and_then(Value::as_str) {
                    refs.insert(reference.to_string());
                }
                for child in object.values() {
                    collect_refs(child, refs);
                }
            }
            Value::Array(array) => {
                for child in array {
                    collect_refs(child, refs);
                }
            }
            _ => {}
        }
    }

    fn resolve_definition<'a>(
        reference: &str,
        definitions: &'a serde_json::Map<String, Value>,
    ) -> &'a Value {
        let name = reference
            .strip_prefix("#/definitions/")
            .expect("local definition reference");
        definitions.get(name).expect("referenced definition exists")
    }

    fn assert_marker(
        root: &Value,
        field: &str,
        expected: &str,
        definitions: &serde_json::Map<String, Value>,
    ) {
        let reference = root["properties"][field]["$ref"]
            .as_str()
            .expect("marker reference");
        let marker = resolve_definition(reference, definitions);
        assert_eq!(marker["enum"], json!([expected]));
    }

    #[test]
    fn contains_all_eight_concrete_roots() {
        let schema = development_schema();
        let definitions = definitions(&schema);

        for name in ROOT_NAMES {
            assert!(definitions.contains_key(*name), "missing root {name}");
        }
    }

    #[test]
    fn dispatch_uses_phase_and_containment_property_names() {
        let schema = development_schema();
        let dispatch = &schema["allOf"][0];
        let serialized = serde_json::to_string(dispatch).unwrap();

        assert!(serialized.contains("\"phase\""), "{serialized}");
        assert!(serialized.contains("\"containment\""), "{serialized}");
        assert!(!serialized.contains("\"property\""), "{serialized}");
    }

    #[test]
    fn one_shot_schema_advertises_compatibility_aliases() {
        let schema = development_schema();
        let properties = &schema["definitions"]["OneShotRequest"]["properties"];

        assert_eq!(properties["appContainer"], properties["processContainer"]);
        assert_eq!(properties["macos_sandbox"], properties["seatbelt"]);
        assert_eq!(
            schema["definitions"]["OneShotRequest"]["allOf"]
                .as_array()
                .expect("alias constraints")
                .len(),
            2
        );
    }

    #[test]
    fn generation_is_deterministic() {
        assert_eq!(development_schema(), development_schema());
        assert_eq!(publication_schema().unwrap(), publication_schema().unwrap());
    }

    #[test]
    fn development_contract_has_no_experimental_json_member() {
        let serialized = serde_json::to_string(&development_schema()).unwrap();
        assert!(!serialized.contains("\"experimental\""));
    }

    #[test]
    fn current_publication_profile_contains_only_the_stable_one_shot_surface() {
        let schema = publication_schema().unwrap();
        let serialized = serde_json::to_string(&schema).unwrap();
        let root = &schema["definitions"]["OneShotRequest"];

        assert!(root["properties"].get("experimental").is_none());
        assert!(root["properties"].get("phase").is_none());
        assert!(root["properties"].get("sandboxId").is_none());
        assert!(root["properties"].get("correlationVector").is_none());
        for development_only in [
            "vm",
            "windows_sandbox",
            "microvm",
            "hyperlight",
            "wslc",
            "isolation_session",
        ] {
            assert!(!serialized.contains(&format!("\"{development_only}\"")));
        }
        for stable in [
            "process",
            "processcontainer",
            "appcontainer",
            "lxc",
            "bubblewrap",
            "seatbelt",
            "macos_sandbox",
        ] {
            assert!(serialized.contains(&format!("\"{stable}\"")));
        }
    }

    #[test]
    fn publication_profile_can_select_windows_sandbox_state_aware_roots() {
        let schema = publication_schema_for_profile(PublicationProfile {
            one_shot: true,
            state_aware_backends: &[StateAwareBackend::WindowsSandbox],
        })
        .unwrap();
        let definitions = definitions(&schema);
        for root in [
            "OneShotRequest",
            "WindowsSandboxProvisionRequest",
            "StartRequest",
            "ExecRequest",
            "StopRequest",
            "DeprovisionRequest",
        ] {
            assert!(definitions.contains_key(root), "missing root {root}");
            assert!(
                definitions[root]["properties"]
                    .get("experimental")
                    .is_none(),
                "{root} contains experimental"
            );
        }
        assert!(!definitions.contains_key("IsolationSessionProvisionRequest"));
        assert!(!definitions.contains_key("WslcProvisionRequest"));
        let serialized = serde_json::to_string(&schema["allOf"][0]).unwrap();
        assert!(serialized.contains("\"windows_sandbox\""));
        assert!(serialized.contains("\"start\""));
        assert!(serialized.contains("\"exec\""));
        assert!(serialized.contains("\"stop\""));
        assert!(serialized.contains("\"deprovision\""));
    }

    #[test]
    fn publication_profile_can_select_each_state_aware_backend_without_experimental_fields() {
        const WINDOWS_SANDBOX: &[StateAwareBackend] = &[StateAwareBackend::WindowsSandbox];
        const ISOLATION_SESSION: &[StateAwareBackend] = &[StateAwareBackend::IsolationSession];
        const WSLC: &[StateAwareBackend] = &[StateAwareBackend::Wslc];
        for (backends, expected) in [
            (WINDOWS_SANDBOX, "windows_sandbox"),
            (ISOLATION_SESSION, "isolation_session"),
            (WSLC, "wslc"),
        ] {
            let schema = publication_schema_for_profile(PublicationProfile {
                one_shot: true,
                state_aware_backends: backends,
            })
            .unwrap();
            let serialized = serde_json::to_string(&schema).unwrap();
            assert!(serialized.contains(expected), "{expected}");
            for definition in definitions(&schema).values() {
                assert!(definition["properties"].get("experimental").is_none());
            }
        }
    }

    #[test]
    fn publication_profile_rejects_empty_or_duplicate_root_selections() {
        assert!(publication_schema_for_profile(PublicationProfile {
            one_shot: false,
            state_aware_backends: &[],
        })
        .unwrap_err()
        .contains("no request roots"));

        const DUPLICATE_WINDOWS_SANDBOX: &[StateAwareBackend] = &[
            StateAwareBackend::WindowsSandbox,
            StateAwareBackend::WindowsSandbox,
        ];
        assert!(publication_schema_for_profile(PublicationProfile {
            one_shot: true,
            state_aware_backends: DUPLICATE_WINDOWS_SANDBOX,
        })
        .unwrap_err()
        .contains("more than once"));
    }

    #[test]
    fn roots_pin_version_phase_and_containment() {
        let schema = development_schema();
        let definitions = definitions(&schema);

        for name in ROOT_NAMES {
            let root = &definitions[*name];
            let version_ref = root["properties"]["version"]["$ref"]
                .as_str()
                .expect("version reference");
            let version = resolve_definition(version_ref, definitions);
            assert_eq!(version["oneOf"][0]["enum"], json!(["0.9.0-alpha"]));
        }

        let one_shot = &definitions["OneShotRequest"];
        assert!(one_shot["properties"].get("phase").is_none());
        assert!(one_shot["required"]
            .as_array()
            .expect("one-shot required fields")
            .contains(&json!("process")));

        let exec = &definitions["ExecRequest"];
        assert!(exec["required"]
            .as_array()
            .expect("exec required fields")
            .contains(&json!("process")));

        for (root, phase) in [
            ("WindowsSandboxProvisionRequest", "provision"),
            ("IsolationSessionProvisionRequest", "provision"),
            ("WslcProvisionRequest", "provision"),
            ("StartRequest", "start"),
            ("ExecRequest", "exec"),
            ("StopRequest", "stop"),
            ("DeprovisionRequest", "deprovision"),
        ] {
            assert_marker(&definitions[root], "phase", phase, definitions);
        }
        for (root, containment) in [
            ("WindowsSandboxProvisionRequest", "windows_sandbox"),
            ("IsolationSessionProvisionRequest", "isolation_session"),
            ("WslcProvisionRequest", "wslc"),
        ] {
            assert_marker(&definitions[root], "containment", containment, definitions);
        }
    }

    #[test]
    fn every_reachable_object_is_closed() {
        let schema = development_schema();
        let definitions = definitions(&schema);
        let mut pending: VecDeque<&Value> =
            ROOT_NAMES.iter().map(|name| &definitions[*name]).collect();
        let mut visited = BTreeSet::new();

        while let Some(value) = pending.pop_front() {
            if let Value::Object(object) = value {
                if object.get("type") == Some(&Value::String("object".to_string())) {
                    assert_eq!(
                        object.get("additionalProperties"),
                        Some(&Value::Bool(false)),
                        "open object schema: {value}"
                    );
                }

                if let Some(reference) = object.get("$ref").and_then(Value::as_str) {
                    if visited.insert(reference.to_string()) {
                        pending.push_back(resolve_definition(reference, definitions));
                    }
                }
                pending.extend(object.values());
            } else if let Value::Array(array) = value {
                pending.extend(array);
            }
        }
    }

    #[test]
    fn no_legacy_network_property_is_reachable_from_exact_development_request_roots() {
        let schema = development_schema();
        let definitions = definitions(&schema);
        for root in ROOT_NAMES {
            let mut pending = VecDeque::from([(&definitions[*root], false)]);
            let mut visited = BTreeSet::new();
            while let Some((node, network_object)) = pending.pop_front() {
                let Value::Object(object) = node else {
                    continue;
                };
                if let Some(reference) = object.get("$ref").and_then(Value::as_str) {
                    if visited.insert((reference, network_object)) {
                        pending.push_back((
                            resolve_definition(reference, definitions),
                            network_object,
                        ));
                    }
                }
                if let Some(properties) = object.get("properties").and_then(Value::as_object) {
                    for (name, child) in properties {
                        assert!(
                            !network_object
                                || !matches!(
                                    name.as_str(),
                                    "defaultPolicy"
                                        | "enforcementMode"
                                        | "allowedHosts"
                                        | "blockedHosts"
                                        | "allowLocalNetwork"
                                        | "proxy"
                                ),
                            "{root}: removed network property {name}"
                        );
                        pending.push_back((child, name == "network"));
                    }
                }
                for keyword in ["allOf", "anyOf", "oneOf"] {
                    if let Some(children) = object.get(keyword).and_then(Value::as_array) {
                        pending.extend(children.iter().map(|child| (child, network_object)));
                    }
                }
                for keyword in ["if", "then", "else", "not", "items", "additionalProperties"] {
                    if let Some(child) = object.get(keyword) {
                        pending.push_back((child, network_object));
                    }
                }
            }
        }
    }

    #[test]
    fn definition_names_and_references_are_consistent() {
        let schema = development_schema();
        let definitions = definitions(&schema);
        let mut references = BTreeSet::new();
        collect_refs(&schema, &mut references);

        for reference in references {
            resolve_definition(&reference, definitions);
        }
        assert_eq!(
            definitions.len(),
            definitions.keys().collect::<BTreeSet<_>>().len()
        );
    }
}
