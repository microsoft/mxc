// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use crate::common::{assert_invalid, assert_invalid_cases, assert_valid};

fn windows_sandbox_request(fields: &str) -> String {
    format!(
        r#"{{
            "version": "0.8.0-alpha",
            "experimental": {{
                "windows_sandbox": {{{fields}}}
            }},
            "process": {{"commandLine": "echo"}}
        }}"#
    )
}

#[test]
fn accepts_empty_windows_sandbox_object() {
    assert_valid(&windows_sandbox_request(""));
}

#[test]
fn accepts_windows_sandbox_fields() {
    for fields in [
        r#""idleTimeoutMs": 1000"#,
        r#""idleTimeout": 2000"#,
        r#""daemonPipeName": "test_pipe""#,
        r#""idleTimeoutMs": 1000, "idleTimeout": 2000"#,
    ] {
        assert_valid(&windows_sandbox_request(fields));
    }
}

#[test]
fn rejects_incorrect_windows_sandbox_spellings() {
    let wrong_outer_name = r#"{
        "version": "0.8.0-alpha",
        "experimental": {"windowsSandbox": {}},
        "process": {"commandLine": "echo"}
    }"#;

    assert_invalid(wrong_outer_name);
    assert_invalid(&windows_sandbox_request(r#""idle_timeout": 1000"#));
}

#[test]
fn accepts_windows_sandbox_timeout_boundaries() {
    for field in ["idleTimeoutMs", "idleTimeout"] {
        for value in [0, u32::MAX] {
            assert_valid(&windows_sandbox_request(&format!(r#""{field}": {value}"#)));
        }
    }
}

#[test]
fn rejects_invalid_windows_sandbox_timeout_values() {
    for field in ["idleTimeoutMs", "idleTimeout"] {
        for value in ["-1", "1.5", "4294967296", r#""1000""#, "true", "[]", "{}"] {
            assert_invalid(&windows_sandbox_request(&format!(r#""{field}": {value}"#)));
        }
    }
}

#[test]
fn accepts_windows_sandbox_daemon_pipe_name_values() {
    for pipe_name in ["", r"\\.\pipe\wxc-test"] {
        let pipe_name_json = serde_json::to_string(pipe_name).unwrap();
        assert_valid(&windows_sandbox_request(&format!(
            r#""daemonPipeName": {pipe_name_json}"#
        )));
    }
}

#[test]
fn rejects_non_string_windows_sandbox_daemon_pipe_name_values() {
    for value in ["123", "true", "[]", "{}"] {
        assert_invalid(&windows_sandbox_request(&format!(
            r#""daemonPipeName": {value}"#
        )));
    }
}

#[test]
fn rejects_unknown_windows_sandbox_field() {
    assert_invalid(&windows_sandbox_request(r#""unknownField": "value""#));
}

#[test]
fn rejects_duplicate_windows_sandbox_fields() {
    let version_and_process = r#""version": "0.8.0-alpha", "process": {"commandLine": "echo"}"#;

    assert_invalid_cases(
        [
            (
                "experimental.windows_sandbox",
                version_and_process,
                r#""experimental": {"windows_sandbox": {}, "windows_sandbox": {}}"#,
            ),
            (
                "experimental.windows_sandbox.idleTimeoutMs",
                version_and_process,
                r#""experimental": {"windows_sandbox": {"idleTimeoutMs": 1000, "idleTimeoutMs": 2000}}"#,
            ),
            (
                "experimental.windows_sandbox.idleTimeout",
                version_and_process,
                r#""experimental": {"windows_sandbox": {"idleTimeout": 1000, "idleTimeout": 2000}}"#,
            ),
            (
                "experimental.windows_sandbox.daemonPipeName",
                version_and_process,
                r#""experimental": {"windows_sandbox": {"daemonPipeName": "pipe1", "daemonPipeName": "pipe2"}}"#,
            ),
        ],
        "duplicate experimental field",
    );
}
