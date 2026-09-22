// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use serde_json::{json, Map, Value};
use std::collections::{BTreeSet, VecDeque};

pub(crate) struct SchemaExpectations<'a> {
    pub(crate) version: &'a str,
    pub(crate) schema: Value,
    pub(crate) regenerated_schema: Value,
    pub(crate) request_roots: &'a [&'a str],
    pub(crate) phase_markers: &'a [(&'a str, &'a str)],
    pub(crate) containment_markers: &'a [(&'a str, &'a str)],
    pub(crate) compatibility_aliases: bool,
    pub(crate) one_shot_required: &'a [&'a str],
    pub(crate) exec_required: &'a [&'a str],
}

fn definitions(schema: &Value) -> &Map<String, Value> {
    schema["definitions"]
        .as_object()
        .expect("schema definitions")
}

fn collect_refs(value: &Value, references: &mut BTreeSet<String>) {
    match value {
        Value::Object(object) => {
            if let Some(reference) = object.get("$ref").and_then(Value::as_str) {
                references.insert(reference.to_string());
            }
            for child in object.values() {
                collect_refs(child, references);
            }
        }
        Value::Array(array) => {
            for child in array {
                collect_refs(child, references);
            }
        }
        _ => {}
    }
}

fn resolve_definition<'a>(reference: &str, definitions: &'a Map<String, Value>) -> &'a Value {
    let name = reference
        .strip_prefix("#/definitions/")
        .expect("local definition reference");
    definitions.get(name).expect("referenced definition exists")
}

fn assert_marker(root: &Value, field: &str, expected: &str, definitions: &Map<String, Value>) {
    let reference = root["properties"][field]["$ref"]
        .as_str()
        .expect("marker reference");
    let marker = resolve_definition(reference, definitions);
    assert_eq!(marker["enum"], json!([expected]));
}

fn assert_required(root: &Value, expected: &[&str], label: &str) {
    let required = root["required"]
        .as_array()
        .unwrap_or_else(|| panic!("{label} required fields"));
    for field in expected {
        assert!(
            required.contains(&json!(field)),
            "{label} does not require {field}"
        );
    }
}

fn assert_roots_are_closed(schema: &Value, request_roots: &[&str]) {
    let definitions = definitions(schema);
    let mut pending: VecDeque<&Value> = request_roots
        .iter()
        .map(|name| &definitions[*name])
        .collect();
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

fn assert_no_legacy_network_properties(schema: &Value, request_roots: &[&str]) {
    let definitions = definitions(schema);
    for root in request_roots {
        let mut pending = VecDeque::from([(&definitions[*root], false)]);
        let mut visited = BTreeSet::new();
        while let Some((node, network_object)) = pending.pop_front() {
            let Value::Object(object) = node else {
                continue;
            };
            if let Some(reference) = object.get("$ref").and_then(Value::as_str) {
                if visited.insert((reference, network_object)) {
                    pending.push_back((resolve_definition(reference, definitions), network_object));
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

fn assert_references_are_consistent(schema: &Value) {
    let definitions = definitions(schema);
    let mut references = BTreeSet::new();
    collect_refs(schema, &mut references);

    for reference in references {
        resolve_definition(&reference, definitions);
    }
    assert_eq!(
        definitions.len(),
        definitions.keys().collect::<BTreeSet<_>>().len()
    );
}

pub(crate) fn assert_schema_invariants(expectations: SchemaExpectations<'_>) {
    let SchemaExpectations {
        version,
        schema,
        regenerated_schema,
        request_roots,
        phase_markers,
        containment_markers,
        compatibility_aliases,
        one_shot_required,
        exec_required,
    } = expectations;
    let definitions = definitions(&schema);

    for name in request_roots {
        assert!(definitions.contains_key(*name), "missing root {name}");
    }

    let dispatch = &schema["allOf"][0];
    let serialized = serde_json::to_string(dispatch).expect("dispatch serializes");
    assert!(serialized.contains("\"phase\""), "{serialized}");
    assert!(serialized.contains("\"containment\""), "{serialized}");
    assert!(!serialized.contains("\"property\""), "{serialized}");

    let one_shot = &definitions["OneShotRequest"];
    let properties = &one_shot["properties"];
    if compatibility_aliases {
        assert_eq!(properties["appContainer"], properties["processContainer"]);
        assert_eq!(properties["macos_sandbox"], properties["seatbelt"]);
        assert_eq!(
            one_shot["allOf"]
                .as_array()
                .expect("alias constraints")
                .len(),
            2
        );
    } else {
        assert!(properties.get("appContainer").is_none());
        assert!(properties.get("macos_sandbox").is_none());
    }

    assert_eq!(schema, regenerated_schema);

    for name in request_roots {
        let root = &definitions[*name];
        let version_ref = root["properties"]["version"]["$ref"]
            .as_str()
            .expect("version reference");
        let version_definition = resolve_definition(version_ref, definitions);
        assert_eq!(version_definition["oneOf"][0]["enum"], json!([version]));
    }

    assert!(one_shot["properties"].get("phase").is_none());
    assert_required(one_shot, one_shot_required, "one-shot");
    assert_required(&definitions["ExecRequest"], exec_required, "exec");

    for (root, phase) in phase_markers {
        assert_marker(&definitions[*root], "phase", phase, definitions);
    }
    for (root, containment) in containment_markers {
        assert_marker(&definitions[*root], "containment", containment, definitions);
    }

    assert_roots_are_closed(&schema, request_roots);
    assert_no_legacy_network_properties(&schema, request_roots);
    assert_references_are_consistent(&schema);
}
