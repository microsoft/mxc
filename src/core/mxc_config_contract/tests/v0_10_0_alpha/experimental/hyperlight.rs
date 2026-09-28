// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use crate::common::{assert_invalid, assert_valid};

fn hyperlight_request(fields: &str) -> String {
    format!(
        r#"{{
            "version": "0.10.0-alpha",
            "containment": "hyperlight",
            "hyperlight": {{{fields}}},
            "process": {{"commandLine": "print(1)"}}
        }}"#
    )
}

#[test]
fn accepts_empty_hyperlight_object() {
    assert_valid(&hyperlight_request(""));
}

#[test]
fn accepts_known_runtimes() {
    for runtime in [
        "agent",
        "python",
        "python-shell",
        "node",
        "bash",
        "dotnet-jit",
    ] {
        assert_valid(&hyperlight_request(&format!(r#""runtime": "{runtime}""#)));
    }
}

#[test]
fn rejects_unknown_runtime_values() {
    for value in [
        r#""Python""#,
        r#""ruby""#,
        r#""powershell""#,
        r#""c""#,
        r#""""#,
        "1",
        "true",
        "null",
        "[]",
        "{}",
    ] {
        assert_invalid(&hyperlight_request(&format!(r#""runtime": {value}"#)));
    }
}

#[test]
fn rejects_unknown_hyperlight_fields() {
    assert_invalid(&hyperlight_request(r#""image": "agent""#));
    assert_invalid(&hyperlight_request(
        r#""runtime": "node", "scratchMb": 512"#,
    ));
}
