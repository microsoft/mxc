// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use crate::common::{assert_invalid, assert_valid};

#[test]
fn accepts_schema_string() {
    let json = r#"{
        "$schema": "https://example.com/one-shot.schema.json",
        "version": "0.8.0-alpha",
        "process": {
            "commandLine": "echo"
        }
    }"#;

    assert_valid(json);
}

#[test]
fn accepts_empty_schema_string() {
    let json = r#"{
        "$schema": "",
        "version": "0.8.0-alpha",
        "process": {
            "commandLine": "echo"
        }
    }"#;

    assert_valid(json);
}

#[test]
fn rejects_non_string_schema_values() {
    for schema in ["null", "true", "false", "0", "1", "[]", "{}"] {
        let json = format!(
            r#"{{
                "$schema": {schema},
                "version": "0.8.0-alpha",
                "process": {{"commandLine": "echo"}}
            }}"#
        );

        assert_invalid(&json);
    }
}

#[test]
fn accepts_all_json_comment_value_types() {
    for comment in ["null", "true", "false", "0", "1", "\"string\"", "[]", "{}"] {
        let json = format!(
            r#"{{
                "_comment": {comment},
                "version": "0.8.0-alpha",
                "process": {{"commandLine": "echo"}}
            }}"#
        );

        assert_valid(&json);
    }
}

#[test]
fn accepts_schema_and_comment_together() {
    let json = r#"{
        "$schema": "https://example.com/one-shot.schema.json",
        "_comment": "This is a comment",
        "version": "0.8.0-alpha",
        "process": {
            "commandLine": "echo"
        }
    }"#;

    assert_valid(json);
}

#[test]
fn rejects_duplicate_schema_field() {
    let json = r#"{
        "$schema": "https://example.com/one-shot.schema.json",
        "$schema": "https://example.com/one-shot.schema.json",
        "version": "0.8.0-alpha",
        "process": {
            "commandLine": "echo"
        }
    }"#;

    assert_invalid(json);
}

#[test]
fn rejects_duplicate_comment_field() {
    let json = r#"{
        "_comment": "This is a comment",
        "_comment": "This is another comment",
        "version": "0.8.0-alpha",
        "process": {
            "commandLine": "echo"
        }
    }"#;

    assert_invalid(json);
}

#[test]
fn rejects_unprefixed_schema_field() {
    let json = r#"{
        "schema": "https://example.com/one-shot.schema.json",
        "version": "0.8.0-alpha",
        "process": {
            "commandLine": "echo"
        }
    }"#;

    assert_invalid(json);
}

#[test]
fn rejects_unprefixed_comment_field() {
    let json = r#"{
        "comment": "This is a comment",
        "version": "0.8.0-alpha",
        "process": {
            "commandLine": "echo"
        }
    }"#;

    assert_invalid(json);
}
