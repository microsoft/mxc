// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
use crate::common::{assert_invalid, assert_valid};

fn request_with_resources(resources: &str) -> String {
    format!(
        r#"{{
            "version": "1.1.0-alpha",
            "process": {{"commandLine": "echo"}},
            "resources": {resources}
        }}"#
    )
}

#[test]
fn accepts_complete_resources_object() {
    assert_valid(&request_with_resources(
        r#"{"cpuTimeMs": 120000, "memoryMb": 2048, "maxProcesses": 64, "priority": "idle"}"#,
    ));
}

#[test]
fn accepts_every_priority() {
    for priority in ["normal", "low", "idle"] {
        assert_valid(&request_with_resources(&format!(
            r#"{{"priority": "{priority}"}}"#
        )));
    }
}

#[test]
fn rejects_unknown_priority() {
    for priority in ["\"high\"", "\"Low\"", "\"\"", "0", "true", "{}"] {
        assert_invalid(&request_with_resources(&format!(
            r#"{{"priority": {priority}}}"#
        )));
    }
}

#[test]
fn rejects_zero_limits() {
    for field in ["cpuTimeMs", "memoryMb", "maxProcesses"] {
        assert_invalid(&request_with_resources(&format!(r#"{{"{field}": 0}}"#)));
    }
}

#[test]
fn rejects_non_integer_limits() {
    for field in ["cpuTimeMs", "memoryMb", "maxProcesses"] {
        for value in ["-1", "1.5", "\"10\"", "true", "[]", "{}"] {
            assert_invalid(&request_with_resources(&format!(
                r#"{{"{field}": {value}}}"#
            )));
        }
    }
}

#[test]
fn rejects_max_processes_beyond_u32() {
    assert_invalid(&request_with_resources(r#"{"maxProcesses": 4294967296}"#));
}

#[test]
fn rejects_unknown_resource_fields() {
    assert_invalid(&request_with_resources(r#"{"cpuTime": 1000}"#));
}

#[test]
fn rejects_non_object_resources() {
    for resources in ["true", "1", "\"low\""] {
        assert_invalid(&request_with_resources(resources));
    }
}
