// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use crate::common::{assert_invalid, assert_valid};

#[test]
fn accepts_experimental_section() {
    let json = r#"{
        "version": "0.9.0-alpha",
        "process": {"commandLine": "echo"},
        "experimental": {
            "test": {"message": "this is a message"}
        }
    }"#;

    assert_valid(json);
}

#[test]
fn rejects_unknown_experimental_field() {
    let json = r#"{
        "version": "0.9.0-alpha",
        "process": {"commandLine": "echo"},
        "experimental": {
            "unknown": "value"
        }
    }"#;

    assert_invalid(json);
}

#[test]
fn rejects_null_experimental_section() {
    let json = r#"{
        "version": "0.9.0-alpha",
        "process": {"commandLine": "echo"},
        "experimental": null
    }"#;

    assert_invalid(json);
}

#[test]
fn rejects_duplicate_experimental_section() {
    let json = r#"{
        "version": "0.9.0-alpha",
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
                "version": "0.9.0-alpha",
                "process": {{"commandLine": "echo"}},
                "experimental": {{{field}}}
            }}"#
        );

        assert_invalid(&json);
    }
}

#[test]
fn rejects_moved_experimental_wslc_section() {
    // `wslc` was promoted to the top-level stable surface. The closed
    // experimental block must no longer accept it under any shape.
    for field in [
        r#""wslc": {}"#,
        r#""wslc": {"image": "alpine:latest"}"#,
        r#""wslc": {"provision": {}}"#,
    ] {
        let json = format!(
            r#"{{
                "version": "0.9.0-alpha",
                "process": {{"commandLine": "echo"}},
                "experimental": {{{field}}}
            }}"#
        );

        assert_invalid(&json);
    }
}

#[test]
fn rejects_state_aware_experimental_sections() {
    let json = r#"{
        "version": "0.9.0-alpha",
        "process": {"commandLine": "echo"},
        "experimental": {"isolation_session": {"provision": {}}}
    }"#;

    assert_invalid(json);
}
