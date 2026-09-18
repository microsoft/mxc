// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use crate::common::assert_invalid;

#[test]
fn rejects_ungraduated_development_fields() {
    for field in [
        r#""test": {"message": "this is a message"}"#,
        r#""windowsSandbox": {}"#,
    ] {
        let json = format!(
            r#"{{
                "version": "0.9.0-alpha",
                "process": {{"commandLine": "echo"}},
                {field}
            }}"#
        );
        assert_invalid(&json);
    }
}

#[test]
fn rejects_legacy_experimental_section() {
    let json = r#"{
        "version": "0.9.0-alpha",
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
fn rejects_state_aware_experimental_sections() {
    let isolation_session = r#"{
        "version": "0.9.0-alpha",
        "process": {"commandLine": "echo"},
        "isolationSession": {"provision": {}}
    }"#;
    let wslc = r#"{
        "version": "0.9.0-alpha",
        "process": {"commandLine": "echo"},
        "wslc": {"provision": {}}
    }"#;

    assert_invalid(isolation_session);
    assert_invalid(wslc);
}
