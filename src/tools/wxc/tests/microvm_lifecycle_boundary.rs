// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#![cfg(windows)]

use std::process::{Command, Output, Stdio};

use mxc_sdk::v1::dev;
use serde_json::{json, Value};

fn invoke(
    request: &Value,
    operation: Option<&str>,
    id: Option<&str>,
    experimental: bool,
    dry_run: bool,
) -> Output {
    let target = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join("target");
    std::fs::create_dir_all(&target).unwrap();
    let directory = tempfile::tempdir_in(target).unwrap();
    let config = directory.path().join("request.json");
    std::fs::write(&config, request.to_string()).unwrap();
    let mut command = Command::new(env!("CARGO_BIN_EXE_wxc-exec"));
    command.arg(config).stdin(Stdio::null());
    // A regression must fail before runtime setup, never provision or start a VM.
    command.env(
        "ACI_EDGE_SANDBOXES_AGENT_ARTIFACTS_DIR",
        directory.path().join("absent-bundle"),
    );
    if let Some(operation) = operation {
        command.args(["--operation", operation]);
    }
    if let Some(id) = id {
        command.args(["--container-id", id]);
    }
    if experimental {
        command.arg("--experimental");
    }
    if dry_run {
        command.arg("--dry-run");
    }
    command.output().unwrap()
}

fn assert_error(output: Output, code: &str) -> Value {
    assert!(!output.status.success(), "{output:?}");
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    let envelope = stdout
        .lines()
        .chain(stderr.lines())
        .filter_map(|line| serde_json::from_str::<Value>(line).ok())
        .find(|value| value["error"]["code"].is_string())
        .unwrap_or_else(|| panic!("missing error envelope: {output:?}"));
    assert_eq!(envelope["error"]["code"], code, "{output:?}");
    envelope
}

fn provision() -> Value {
    json!({
        "version": "1.1.0-alpha", "containment": "microvm",
        "microvm": {"image": "mcr.microsoft.com/azurelinux/base/core:3.0"}
    })
}

#[test]
fn executor_rejects_microvm_lifecycle_including_dry_run() {
    for phase in ["provision", "start", "exec", "stop", "deprovision"] {
        let request = match phase {
            "provision" => provision(),
            "exec" => json!({
                "version": "1.1.0-alpha", "process": {"commandLine": "true"}
            }),
            _ => json!({"version": "1.1.0-alpha"}),
        };
        let id = (phase != "provision").then_some("microvm:0123456789abcdef0123456789abcdef");
        for dry_run in [false, true] {
            let error = assert_error(
                invoke(&request, Some(phase), id, true, dry_run),
                "unsupported_phase",
            );
            assert!(error["error"]["message"]
                .as_str()
                .unwrap()
                .contains("only through Rust mxc_sdk::v1::dev JSON APIs"));
        }
    }
}

#[test]
fn executor_exec_rejection_precedes_native_id_lookup() {
    let request = json!({
        "version": "1.1.0-alpha", "process": {"commandLine": "true"}
    });
    for dry_run in [false, true] {
        assert_error(
            invoke(
                &request,
                Some("exec"),
                Some("microvm:invalid"),
                true,
                dry_run,
            ),
            "unsupported_phase",
        );
    }
}

#[test]
fn executor_keeps_parsing_and_opt_in_before_surface_authorization() {
    let mut invalid = provision();
    invalid["microvm"]["provision"] = json!({"memoryMib": 0});
    for dry_run in [false, true] {
        for experimental in [false, true] {
            assert_error(
                invoke(&invalid, Some("provision"), None, experimental, dry_run),
                "malformed_request",
            );
        }
        assert_error(
            invoke(&provision(), Some("provision"), None, false, dry_run),
            "backend_unavailable",
        );
    }
}

#[test]
fn executor_preserves_non_microvm_lifecycle_validation() {
    let output = invoke(
        &json!({"version": "1.1.0-alpha"}),
        Some("start"),
        Some("wsb:deadbeef"),
        true,
        true,
    );
    assert!(output.status.success(), "{output:?}");
    let envelope: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(envelope, json!({"result": {}}));
}

#[test]
fn executor_preserves_microvm_create_and_run_capture() {
    let mut request = provision();
    request["process"] = json!({"commandLine": "true", "timeout": 3_600_001});
    let rust_error = dev::run_json(
        &request.to_string(),
        dev::JsonOptions { experimental: true },
    )
    .unwrap_err();
    assert!(matches!(
        rust_error.code,
        mxc_sdk::v1::ErrorCode::PolicyValidation | mxc_sdk::v1::ErrorCode::BackendUnavailable
    ));
    assert_error(
        invoke(&request, None, None, true, false),
        rust_error.code.as_str(),
    );
}
