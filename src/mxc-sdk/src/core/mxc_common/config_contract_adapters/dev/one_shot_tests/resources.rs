// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use super::common::adapt;
use crate::mxc_common::models::ResourcePriority;

fn request_with_resources(resources: &str) -> String {
    format!(
        r#"{{
            "version": "1.1.0-alpha",
            "process": {{"commandLine": "echo hello"}},
            "resources": {resources}
        }}"#
    )
}

#[test]
fn resources_map_expected_wire_fields() {
    let ir = adapt(&request_with_resources(
        r#"{"cpuTimeMs": 120000, "memoryMb": 2048, "maxProcesses": 64, "priority": "low"}"#,
    ));
    let resources = ir.resources.expect("resources section");

    assert_eq!(resources.cpu_time_ms, Some(120_000));
    assert_eq!(resources.memory_mb, Some(2048));
    assert_eq!(resources.max_processes, Some(64));
    assert_eq!(resources.priority, Some(ResourcePriority::Low));
}

#[test]
fn empty_resources_map_to_a_present_empty_wire_section() {
    let ir = adapt(&request_with_resources("{}"));
    let resources = ir.resources.expect("resources section");

    assert_eq!(resources.cpu_time_ms, None);
    assert_eq!(resources.memory_mb, None);
    assert_eq!(resources.max_processes, None);
    assert_eq!(resources.priority, None);
}

#[test]
fn omitted_resources_map_to_no_wire_section() {
    let ir = adapt(
        r#"{
            "version": "1.1.0-alpha",
            "process": {"commandLine": "echo hello"}
        }"#,
    );

    assert!(ir.resources.is_none());
}

#[test]
fn every_resource_priority_maps_to_the_expected_value() {
    for (wire_value, expected) in [
        ("normal", ResourcePriority::Normal),
        ("low", ResourcePriority::Low),
        ("idle", ResourcePriority::Idle),
    ] {
        let ir = adapt(&request_with_resources(&format!(
            r#"{{"priority": "{wire_value}"}}"#
        )));

        assert_eq!(ir.resources.unwrap().priority, Some(expected));
    }
}
