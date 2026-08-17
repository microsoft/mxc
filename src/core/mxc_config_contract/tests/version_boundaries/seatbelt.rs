// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use crate::common::assert_v06_rejects_v07_accepts;

#[test]
fn seatbelt_section_is_introduced_in_v07() {
    let v06_json = r#"{
        "version": "0.6.0-alpha",
        "containment": "process",
        "process": {"commandLine": "echo"},
        "seatbelt": {}
    }"#;

    let v07_json = r#"{
        "version": "0.7.0-alpha",
        "containment": "process",
        "process": {"commandLine": "echo"},
        "seatbelt": {}
    }"#;

    assert_v06_rejects_v07_accepts(v06_json, v07_json);
}

#[test]
fn seatbelt_containment_value_is_introduced_in_v07() {
    let v06_json = r#"{
        "version": "0.6.0-alpha",
        "containment": "seatbelt",
        "process": {"commandLine": "echo"},
        "seatbelt": {}
    }"#;

    let v07_json = r#"{
        "version": "0.7.0-alpha",
        "containment": "seatbelt",
        "process": {"commandLine": "echo"},
        "seatbelt": {}
    }"#;

    assert_v06_rejects_v07_accepts(v06_json, v07_json);
}

#[test]
fn macos_sandbox_section_alias_is_introduced_in_v07() {
    let v06_json = r#"{
        "version": "0.6.0-alpha",
        "containment": "process",
        "process": {"commandLine": "echo"},
        "macos_sandbox": {}
    }"#;

    let v07_json = r#"{
        "version": "0.7.0-alpha",
        "containment": "process",
        "process": {"commandLine": "echo"},
        "macos_sandbox": {}
    }"#;

    assert_v06_rejects_v07_accepts(v06_json, v07_json);
}

#[test]
fn macos_sandbox_containment_value_alias_is_introduced_in_v07() {
    let v06_json = r#"{
        "version": "0.6.0-alpha",
        "containment": "macos_sandbox",
        "process": {"commandLine": "echo"},
        "macos_sandbox": {}
    }"#;

    let v07_json = r#"{
        "version": "0.7.0-alpha",
        "containment": "macos_sandbox",
        "process": {"commandLine": "echo"},
        "macos_sandbox": {}
    }"#;

    assert_v06_rejects_v07_accepts(v06_json, v07_json);
}
