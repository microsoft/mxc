// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use crate::state_aware::common::{
    assert_invalid as assert_invalid_request, assert_valid as assert_valid_request,
};
use mxc_config_contract::published::v0_9_0_alpha::WslcProvisionRequest;

fn assert_valid(json: &str) {
    assert_valid_request::<WslcProvisionRequest>(json);
}

fn assert_invalid(json: &str) {
    assert_invalid_request::<WslcProvisionRequest>(json);
}

fn request(additional_fields: &str) -> String {
    format!(
        r#"{{
            "version": "0.9.0-alpha",
            "phase": "provision",
            "containment": "wslc"
            {additional_fields}
        }}"#
    )
}

#[test]
fn accepts_minimal_and_complete_provision_requests() {
    assert_valid(&request(""));
    assert_valid(&request(
        r#",
            "$schema": "https://example.com/provision.schema.json",
            "_comment": "WSLC provision",
            "filesystem": {
                "readwritePaths": ["C:\\rw"],
                "readonlyPaths": ["C:\\ro"],
                "deniedPaths": ["C:\\denied"]
            },
            "network": {
                "egress": {"default": "deny"},
                "ingress": {"default": "deny", "hostLoopback": "deny"}
            },
            "telemetry": {"enabled": true},
            "wslc": {
                "provision": {
                    "image": "alpine:latest",
                    "imageTarPath": "C:\\images\\alpine.tar"
                }
            }
        "#,
    ));
}

#[test]
fn accepts_empty_and_explicit_wslc_provision_settings() {
    for fields in [
        r#","wslc": {}"#,
        r#","wslc": {"provision": {}}"#,
        r#","wslc": {"provision": {"image": ""}}"#,
        r#","wslc": {"provision": {"imageTarPath": ""}}"#,
    ] {
        assert_valid(&request(fields));
    }
}

#[test]
fn rejects_wrong_version_phase_or_containment() {
    for json in [
        r#"{"phase":"provision","containment":"wslc"}"#,
        r#"{"version":"0.9.0-alpha","containment":"wslc"}"#,
        r#"{"version":"0.10.0-alpha","phase":"provision","containment":"wslc"}"#,
        r#"{"version":"0.9.0-alpha","phase":"start","containment":"wslc"}"#,
        r#"{"version":"0.9.0-alpha","phase":"provision","containment":"windows_sandbox"}"#,
        r#"{"version":"0.9.0-alpha","phase":"provision","containment":"microvm"}"#,
        r#"{"version":"0.9.0-alpha","phase":"provision","containment":"hyperlight"}"#,
        r#"{"version":"0.9.0-alpha","phase":"provision","containment":"vm"}"#,
    ] {
        assert_invalid(json);
    }
}

#[test]
fn rejects_null_unknown_and_foreign_fields() {
    for fields in [
        r#","wslc": null"#,
        r#","wslc": {"provision": null}"#,
        r#","wslc": {"provision": {"image": null}}"#,
        r#","wslc": {"provision": {"imageTarPath": true}}"#,
        r#","wslc": {"provision": {"unknown": true}}"#,
        r#","runtimeConfig": {"networkProxy": "http://localhost:8080"}"#,
        r#","sandboxId": "wslc:0123456789abcdef0123456789abcdef""#,
        r#","process": {"commandLine": "echo"}"#,
        r#","lifecycle": {}"#,
        r#","test": {}"#,
        r#","windowsSandbox": {}"#,
        r#","isolationSession": {}"#,
    ] {
        assert_invalid(&request(fields));
    }
}

#[test]
fn rejects_duplicate_wslc_provision_fields() {
    for fields in [
        r#","wslc": {}, "wslc": {}"#,
        r#","wslc": {"provision": {}, "provision": {}}"#,
        r#","wslc": {"provision": {"image": "first", "image": "second"}}"#,
        r#","wslc": {"provision": {"imageTarPath": "first", "imageTarPath": "second"}}"#,
    ] {
        assert_invalid(&request(fields));
    }
}
