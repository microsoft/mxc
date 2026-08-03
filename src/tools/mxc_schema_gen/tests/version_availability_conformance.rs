// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Pins the version-availability metadata against the generated JSON Schema.
//!
//! A range is enforced by matching a JSON key against the name the derive
//! computes; a name that disagrees with what `serde` accepts would fail *open*.
//! `schemars` derives the same names through separate code, so the generated
//! schema is an independent oracle. These live here because this crate enables
//! the `schema-gen` feature, so they run under a plain `cargo test --workspace`.

use std::collections::BTreeSet;

use serde_json::Value;
use wxc_common::version_availability::{
    all_nodes, annotated_fields, NodeAvailability, VersionAvailability,
};
use wxc_common::wire::MxcConfig;

fn schema() -> Value {
    serde_json::from_str(&wxc_common::wire::generate_config_schema_json())
        .expect("the generator emits valid JSON")
}

fn root_node() -> &'static NodeAvailability {
    MxcConfig::availability().expect("MxcConfig is a struct, so it has a node")
}

/// The schema object describing `type_name`: the document root for the root
/// type, else its entry under `definitions`.
fn schema_object_for<'a>(schema: &'a Value, type_name: &str) -> Option<&'a Value> {
    if type_name == "MxcConfig" {
        Some(schema)
    } else {
        schema.pointer(&format!("/definitions/{type_name}"))
    }
}

fn schema_property_names(object: &Value) -> BTreeSet<String> {
    object
        .get("properties")
        .and_then(Value::as_object)
        .map(|props| props.keys().cloned().collect())
        .unwrap_or_default()
}

#[test]
fn every_wire_node_has_a_schema_counterpart() {
    let schema = schema();
    for node in all_nodes(root_node()) {
        assert!(
            schema_object_for(&schema, node.type_name).is_some(),
            "wire type `{}` derives VersionAvailability but has no schema definition; \
             the availability metadata and the schema disagree about which types exist",
            node.type_name
        );
    }
}

#[test]
fn derived_json_names_match_the_schema_exactly() {
    let schema = schema();
    for node in all_nodes(root_node()) {
        let object = schema_object_for(&schema, node.type_name)
            .unwrap_or_else(|| panic!("no schema object for `{}`", node.type_name));

        let from_schema = schema_property_names(object);
        let from_derive: BTreeSet<String> =
            node.fields.iter().map(|f| f.name.to_string()).collect();

        assert_eq!(
            from_derive,
            from_schema,
            "`{}`: the JSON field names derived for availability ranges disagree with the \
             generated schema. A derived name that serde would not accept makes the \
             availability range unreachable (it fails OPEN), so these must match exactly.\n  \
             only in derive: {:?}\n  only in schema: {:?}",
            node.type_name,
            from_derive.difference(&from_schema).collect::<Vec<_>>(),
            from_schema.difference(&from_derive).collect::<Vec<_>>(),
        );
    }
}

#[test]
fn serde_aliases_are_absent_from_the_schema_but_present_in_the_metadata() {
    // An alias is a spelling, not a schema property, so schemars omits it — but
    // the metadata must carry it or the alias bypasses the range.
    let schema = schema();
    let root = schema_property_names(&schema);

    let process_container = root_node()
        .field("processContainer")
        .expect("processContainer is a wire field");
    assert!(
        process_container.aliases.contains(&"appContainer"),
        "the appContainer alias must be carried in the availability metadata so a config \
         using it is still checked; aliases: {:?}",
        process_container.aliases
    );
    assert!(
        !root.contains("appContainer"),
        "the schema advertises only the canonical spelling"
    );

    let seatbelt = root_node()
        .field("seatbelt")
        .expect("seatbelt is a wire field");
    assert!(seatbelt.aliases.contains(&"macos_sandbox"));
    assert!(!root.contains("macos_sandbox"));
}

#[test]
fn every_declared_availability_is_published_in_the_schema() {
    let schema = schema();
    let declared = annotated_fields(root_node());
    assert!(
        !declared.is_empty(),
        "the wire model declares no availability ranges at all; this test would be vacuous"
    );

    for (type_name, field, availability) in declared {
        let pointer = if type_name == "MxcConfig" {
            format!("/properties/{field}")
        } else {
            format!("/definitions/{type_name}/properties/{field}")
        };
        let property = schema
            .pointer(&pointer)
            .unwrap_or_else(|| panic!("schema has no property at {pointer}"));

        match availability.since {
            Some(since) => assert_eq!(
                property.get("x-mxc-since").and_then(Value::as_str),
                Some(since.to_string().as_str()),
                "{pointer}: x-mxc-since is missing or stale"
            ),
            None => assert!(
                property.get("x-mxc-since").is_none(),
                "{pointer}: schema advertises a lower bound the wire model does not declare"
            ),
        }
        match availability.until {
            Some(until) => assert_eq!(
                property.get("x-mxc-until").and_then(Value::as_str),
                Some(until.to_string().as_str()),
                "{pointer}: x-mxc-until is missing or stale"
            ),
            None => assert!(
                property.get("x-mxc-until").is_none(),
                "{pointer}: schema advertises an upper bound the wire model does not declare"
            ),
        }
    }
}

#[test]
fn the_schema_declares_no_availability_the_wire_model_does_not() {
    // Reverse direction: a hand-edited schema cannot add an unenforced range.
    let schema = schema();
    let declared: BTreeSet<(String, String)> = annotated_fields(root_node())
        .into_iter()
        .map(|(type_name, field, _)| (type_name.to_string(), field.to_string()))
        .collect();

    let mut found = BTreeSet::new();
    collect_availability_keys(&schema, "MxcConfig", &mut found);
    if let Some(defs) = schema.get("definitions").and_then(Value::as_object) {
        for (type_name, object) in defs {
            collect_availability_keys(object, type_name, &mut found);
        }
    }

    assert_eq!(
        found, declared,
        "the schema's x-mxc-* annotations must come from the wire model and nowhere else"
    );
}

fn collect_availability_keys(
    object: &Value,
    type_name: &str,
    out: &mut BTreeSet<(String, String)>,
) {
    let Some(props) = object.get("properties").and_then(Value::as_object) else {
        return;
    };
    for (name, property) in props {
        if property.get("x-mxc-since").is_some() || property.get("x-mxc-until").is_some() {
            out.insert((type_name.to_string(), name.clone()));
        }
    }
}
