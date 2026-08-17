// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use crate::common::assert_v06_rejects_v07_accepts;

#[test]
fn schema_is_available_starting_in_v07() {
    let v06_json = r#"{
        "$schema": "https://github.com/microsoft/mxc/blob/main/schemas/stable/mxc-config.schema.0.7.0-alpha.json",
        "version": "0.6.0-alpha",
        "process": {
            "commandLine": "echo"
        }
    }"#;

    let v07_json = r#"{
        "$schema": "https://github.com/microsoft/mxc/blob/main/schemas/stable/mxc-config.schema.0.7.0-alpha.json",
        "version": "0.7.0-alpha",
        "process": {
            "commandLine": "echo"
        }
    }"#;

    assert_v06_rejects_v07_accepts(v06_json, v07_json);
}

#[test]
fn comment_is_available_starting_in_v07() {
    let v06_json = r#"{
        "_comment": "This is a comment",
        "version": "0.6.0-alpha",
        "process": {
            "commandLine": "echo"
        }
    }"#;

    let v07_json = r#"{
        "_comment": "This is a comment",
        "version": "0.7.0-alpha",
        "process": {
            "commandLine": "echo"
        }
    }"#;

    assert_v06_rejects_v07_accepts(v06_json, v07_json);
}
