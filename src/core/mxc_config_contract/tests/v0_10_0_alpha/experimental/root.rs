// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use crate::common::{assert_invalid, assert_valid};

#[test]
fn accepts_permanent_development_fields() {
    let json = r#"{
        "version": "0.10.0-alpha",
        "process": {"commandLine": "echo"},
        "test": {"message": "this is a message"},
        "windowsSandbox": {},
        "hyperlight": {}
    }"#;

    assert_valid(json);
}

#[test]
fn rejects_legacy_experimental_section() {
    let json = r#"{
        "version": "0.10.0-alpha",
        "process": {"commandLine": "echo"},
        "experimental": {
            "test": {"message": "this is a message"}
        }
    }"#;

    assert_invalid(json);
}

#[test]
fn rejects_null_legacy_experimental_section() {
    let json = r#"{
        "version": "0.10.0-alpha",
        "process": {"commandLine": "echo"},
        "experimental": null
    }"#;

    assert_invalid(json);
}

#[test]
fn rejects_duplicate_experimental_section() {
    let json = r#"{
        "version": "0.10.0-alpha",
        "process": {"commandLine": "echo"},
        "experimental": {
            "test": {"message": "this is a message"}
        },
        "experimental": {
            "test": {"message": "this is another message"}
        }
    }"#;

    assert_invalid(json);
}

#[test]
fn rejects_moved_experimental_seatbelt_sections() {
    for field in [r#""seatbelt": {}"#, r#""macos_sandbox": {}"#] {
        let json = format!(
            r#"{{
                "version": "0.10.0-alpha",
                "process": {{"commandLine": "echo"}},
                "experimental": {{{field}}}
            }}"#
        );

        assert_invalid(&json);
    }
}
