// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use mxc_sdk::{
    __ffi,
    v1::{dev, ErrorCode},
};

#[cfg(all(windows, target_arch = "x86_64", feature = "microvm"))]
#[path = "nvx_e2e/network.rs"]
mod windows_network;

fn process_only_request(command: &str) -> serde_json::Value {
    serde_json::json!({
        "version": "1.1.0-alpha",
        "containment": "microvm",
        "microvm": {"image": "mcr.microsoft.com/azurelinux/base/core:3.0"},
        "process": { "commandLine": command, "timeout": 30_000 }
    })
}

#[test]
fn json_execution_requires_a_valid_contract() {
    for json in [
        "{ not json",
        r#"{"version":"999.0.0","process":{"commandLine":"echo"}}"#,
        r#"{"version":"1.0.0","process":{"commandLine":"echo"},"extra":true}"#,
        r#"{"version":"1.0.0","phase":"start","sandboxId":"iso:unused"}"#,
    ] {
        for experimental in [false, true] {
            let error = __ffi::run_json(json, experimental).unwrap_err();
            assert_eq!(error.code, ErrorCode::MalformedRequest, "{json}: {error}");
            let error = __ffi::spawn_container_json(json, experimental)
                .err()
                .expect("invalid request must not spawn");
            assert_eq!(error.code, ErrorCode::MalformedRequest, "{json}: {error}");
        }
    }
}

#[test]
fn microvm_creation_rejects_invalid_images_before_runtime() {
    for image in [
        None,
        Some(""),
        Some(" "),
        Some("\n"),
        Some("python:3.12-alpine"),
        Some("library/python:3.12-alpine"),
        Some("localhost/"),
    ] {
        let mut request = process_only_request("printf forbidden");
        request.as_object_mut().unwrap().remove("microvm");
        if let Some(image) = image {
            request["microvm"] = serde_json::json!({"image": image});
        }
        let error = __ffi::run_json(&request.to_string(), true).unwrap_err();
        assert_eq!(error.code, ErrorCode::MalformedRequest, "{error}");
        assert!(
            error.message.contains("microvm.image")
                || (image.is_none() && error.message.contains("missing field `microvm`")),
            "{error}"
        );

        request.as_object_mut().unwrap().remove("process");
        request["phase"] = serde_json::json!("provision");
        for dry_run in [false, true] {
            let error = __ffi::run_lifecycle_json(&request.to_string(), dry_run, true).unwrap_err();
            assert_eq!(error.code, ErrorCode::MalformedRequest, "{error}");
            assert!(
                error.message.contains("microvm.image")
                    || (image.is_none() && error.message.contains("missing field `microvm`")),
                "{error}"
            );
        }
    }
}

#[test]
fn zero_microvm_memory_is_malformed_in_json_sdk_creation_and_provision() {
    let mut request = process_only_request("printf forbidden");
    request["microvm"]["provision"] = serde_json::json!({"memoryMib": 0});
    for experimental in [false, true] {
        let options = dev::JsonOptions { experimental };
        let error = dev::run_json(&request.to_string(), options).unwrap_err();
        assert_eq!(error.code, ErrorCode::MalformedRequest, "{error}");
        assert!(
            error
                .message
                .contains("microvm.provision.memoryMib must be greater than zero"),
            "{error}"
        );
        let mut provision = request.clone();
        provision.as_object_mut().unwrap().remove("process");
        provision["phase"] = serde_json::json!("provision");
        for validate in [false, true] {
            let error = if validate {
                dev::validate_provision_json(&provision.to_string(), options)
            } else {
                dev::provision_container_json(&provision.to_string(), options)
            }
            .unwrap_err();
            assert_eq!(error.code, ErrorCode::MalformedRequest, "{error}");
            assert!(
                error
                    .message
                    .contains("microvm.provision.memoryMib must be greater than zero"),
                "{error}"
            );
        }
    }
}

#[test]
fn microvm_json_operations_require_explicit_optin() {
    let mut request = process_only_request("printf forbidden");
    let json = request.to_string();
    for spawn in [false, true] {
        let error = if spawn {
            __ffi::spawn_container_json(&json, false)
                .err()
                .expect("spawn must reject MicroVM without opt-in")
        } else {
            __ffi::run_json(&json, false).unwrap_err()
        };
        assert_eq!(error.code, ErrorCode::BackendUnavailable, "{error}");
        assert!(error.message.contains("experimental"), "{error}");
    }

    request.as_object_mut().unwrap().remove("process");
    request["phase"] = serde_json::json!("provision");
    for dry_run in [false, true] {
        let error = __ffi::run_lifecycle_json(&request.to_string(), dry_run, false).unwrap_err();
        assert_eq!(error.code, ErrorCode::BackendUnavailable, "{error}");
        assert!(error.message.contains("experimental"), "{error}");
    }
}

#[test]
fn sdk_json_rejects_invalid_requests_and_requires_explicit_optin() {
    let request = process_only_request("printf forbidden");
    let json = request.to_string();
    let error = dev::run_json(&json, dev::JsonOptions::default()).unwrap_err();
    assert_eq!(error.code, ErrorCode::BackendUnavailable, "{error}");
    assert!(error.message.contains("experimental"), "{error}");

    for experimental in [false, true] {
        let options = dev::JsonOptions { experimental };
        for invalid in [
            "{ not json".to_owned(),
            r#"{"version":"999.0.0","process":{"commandLine":"echo"}}"#.to_owned(),
            r#"{"version":"1.0.0","phase":"start","sandboxId":"iso:unused"}"#.to_owned(),
        ] {
            let error = dev::run_json(&invalid, options).unwrap_err();
            assert_eq!(error.code, ErrorCode::MalformedRequest, "{error}");
        }
        let mut invalid_image = request.clone();
        invalid_image["microvm"]["image"] = serde_json::json!("python:3.12-alpine");
        let error = dev::run_json(&invalid_image.to_string(), options).unwrap_err();
        assert_eq!(error.code, ErrorCode::MalformedRequest, "{error}");
    }

    #[cfg(not(all(windows, target_arch = "x86_64", feature = "microvm")))]
    {
        let error = dev::run_json(&json, dev::JsonOptions { experimental: true }).unwrap_err();
        assert_eq!(error.code, ErrorCode::BackendUnavailable, "{error}");
        assert!(error.message.contains("Windows x64"), "{error}");
    }
}

#[test]
fn sdk_json_rejects_microvm_streaming_pty_and_lifecycle() {
    let mut request = process_only_request("printf forbidden");
    let options = dev::JsonOptions { experimental: true };
    let json = request.to_string();
    let error = dev::spawn_json(&json, options)
        .err()
        .expect("MicroVM streaming must be rejected");
    assert_eq!(error.code, ErrorCode::UnsupportedContainment, "{error}");
    let error = dev::spawn_with_pty_json(
        &json,
        dev::PtyJsonOptions {
            experimental: true,
            ..Default::default()
        },
    )
    .expect_err("MicroVM PTY must be rejected");
    assert_eq!(error.code, ErrorCode::UnsupportedContainment, "{error}");

    request.as_object_mut().unwrap().remove("process");
    request["phase"] = serde_json::json!("provision");
    let json = request.to_string();
    for call in [dev::provision_container_json, dev::validate_provision_json] {
        let error = call(&json, options).unwrap_err();
        assert_eq!(error.code, ErrorCode::UnsupportedPhase, "{error}");
    }
}

#[test]
fn non_microvm_experimental_json_run_and_spawn_require_explicit_optin() {
    let json = r#"{"version":"1.1.0-alpha","containment":"windows_sandbox","process":{"commandLine":"echo forbidden"}}"#;
    for experimental in [false, true] {
        let run_error = __ffi::run_json(json, experimental).unwrap_err();
        let spawn_error = __ffi::spawn_container_json(json, experimental)
            .err()
            .expect("Windows Sandbox does not support streaming");
        for error in [run_error, spawn_error] {
            if experimental {
                assert_eq!(error.code, ErrorCode::UnsupportedContainment, "{error}");
                assert!(error.message.contains("streaming"), "{error}");
            } else {
                assert_eq!(error.code, ErrorCode::BackendUnavailable, "{error}");
                assert!(error.message.contains("experimental"), "{error}");
            }
        }
    }
}

#[test]
fn declared_microvm_streaming_and_lifecycle_fail_closed() {
    let mut request = process_only_request("printf forbidden");
    let error = __ffi::spawn_container_json(&request.to_string(), true)
        .err()
        .expect("MicroVM streaming is not implemented");
    assert_eq!(error.code, ErrorCode::UnsupportedContainment, "{error}");
    assert!(error.message.contains("streaming"), "{error}");

    request.as_object_mut().unwrap().remove("process");
    request["phase"] = serde_json::json!("provision");
    for dry_run in [false, true] {
        let error = __ffi::run_lifecycle_json(&request.to_string(), dry_run, true).unwrap_err();
        assert_eq!(error.code, ErrorCode::UnsupportedPhase, "{error}");
        assert!(error.message.contains("lifecycle"), "{error}");
    }
}

#[cfg(not(all(windows, target_arch = "x86_64", feature = "microvm")))]
#[test]
fn unsupported_platform_or_feature_is_fail_closed() {
    let json = process_only_request("printf forbidden").to_string();
    for experimental in [false, true] {
        let error = __ffi::run_json(&json, experimental).unwrap_err();
        assert_eq!(error.code, ErrorCode::BackendUnavailable, "{error}");
        if experimental {
            assert!(error.message.contains("Windows x64"), "{error}");
        } else {
            assert!(error.message.contains("experimental"), "{error}");
        }
    }
}

#[cfg(all(windows, target_arch = "x86_64", feature = "microvm"))]
mod windows_x64 {
    use std::path::{Component, Path, PathBuf, Prefix};
    use std::process::{Command, Output, Stdio};
    use std::time::{Instant, SystemTime, UNIX_EPOCH};

    use mxc_sdk::v1::{ExecutionResult, WaitResult};
    use serde_json::{json, Value};

    use super::*;

    const BUNDLE_ENV: &str = "ACI_EDGE_SANDBOXES_AGENT_ARTIFACTS_DIR";
    const CAPTURE_LIMIT: usize = 64 * 1024 * 1024;
    const CAPTURE_ERROR: &str =
        "NVX signed bundled agent: combined stdout/stderr capture limit of 67108864 bytes exceeded";
    const MIXED_BACKEND_ERROR: &str = "Configuration parse error: Multiple containment backends \
        configured: 'containment' is 'microvm' (no per-backend section is defined for this \
        backend), but the config includes backend section(s): processContainer. Only one backend \
        section is allowed; remove the unused section(s).";

    #[test]
    fn experimental_opt_in_is_required_before_backend_discovery() {
        let error =
            mxc_sdk::__ffi::run_json(&process_only_request("printf forbidden").to_string(), false)
                .unwrap_err();
        assert_eq!(error.code, ErrorCode::BackendUnavailable);
        assert!(error.message.contains("experimental"));
    }

    #[test]
    fn signed_agent_proxy_validation_withholds_credentials() {
        for proxy in [
            "http://synthetic-user:synthetic-secret@[::1]:3128",
            "http://synthetic%3Auser:synthetic%40secret@[::1]:3128",
        ] {
            let mut request = process_only_request("printf forbidden");
            request["runtimeConfig"] = json!({"networkProxy": proxy});
            let error = __ffi::run_json(&request.to_string(), true).unwrap_err();
            assert_eq!(error.code, ErrorCode::PolicyValidation, "{}", error.message);
            assert!(
                !error.message.contains("synthetic"),
                "native error leaked credentials"
            );
            assert!(
                error.message.contains("validate_provision"),
                "{}",
                error.message
            );
            assert!(error.message.contains("withheld"), "{}", error.message);
            assert_no_run_state(std::process::id());
        }

        let mut request = process_only_request("printf forbidden");
        request["runtimeConfig"] = json!({"networkProxy": "http://[::1]:3128"});
        let error = __ffi::run_json(&request.to_string(), true).unwrap_err();
        assert_eq!(error.code, ErrorCode::PolicyValidation, "{}", error.message);
        assert!(
            error.message.contains("OpenVMM reaches host loopback"),
            "{}",
            error.message
        );
        assert!(!error.message.contains("withheld"), "{}", error.message);
        assert_no_run_state(std::process::id());

        request["runtimeConfig"] =
            json!({"networkProxy": "http://synthetic-user:synthetic-secret@192.0.2.1:3128"});
        let error = __ffi::run_json(&request.to_string(), true).unwrap_err();
        assert_eq!(error.code, ErrorCode::MalformedRequest);
        assert!(error.message.contains("localhost"), "{}", error.message);
        assert!(!error.message.contains("synthetic"));
        assert_no_run_state(std::process::id());
    }

    fn rejected_requests() -> Vec<(&'static str, Value)> {
        vec![
            (
                "image-without-registry",
                json!({"microvm": {"image": "python:3.12-alpine"}}),
            ),
            (
                "ambiguous-image",
                json!({"microvm": {"image": "library/python:3.12-alpine"}}),
            ),
            (
                "image-without-repository",
                json!({"microvm": {"image": "localhost/"}}),
            ),
            ("ui", json!({"ui": {"disable": true}})),
            (
                "memory-override",
                json!({"microvm": {
                    "image": "docker.io/library/python:3.12-alpine",
                    "provision": {"memoryMib": 512}
                }}),
            ),
            (
                "capture",
                json!({"processContainer": {"captureDenials": {}}}),
            ),
            (
                "least-privilege",
                json!({"processContainer": {"leastPrivilege": false}}),
            ),
            (
                "learning-mode",
                json!({"processContainer": {"learningMode": false}}),
            ),
            (
                "capabilities",
                json!({"processContainer": {"capabilities": []}}),
            ),
            ("process-ui", json!({"processContainer": {"ui": {}}})),
            (
                "enumerate",
                json!({"processContainer": {"filesystem": {"enumeratePaths": ["C:\\work"]}}}),
            ),
            ("destroy", json!({"lifecycle": {"destroyOnExit": false}})),
            ("preserve", json!({"lifecycle": {"preservePolicy": true}})),
            ("timeout-limit", json!({"process": {"timeout": 3_600_001}})),
            ("parent-cwd", json!({"process": {"cwd": "/tmp/../escape"}})),
            ("relative-cwd", json!({"process": {"cwd": "relative"}})),
            (
                "cwd-limit",
                json!({"process": {"cwd": format!("/{}", "x".repeat(4095))}}),
            ),
            (
                "cwd-multibyte-limit",
                json!({"process": {"cwd": format!("/{}x", "\u{00e9}".repeat(2047))}}),
            ),
            (
                "env-entry-limit",
                json!({"process": {"env": vec!["KEY=value"; 257], "inheritDefaultEnv": true}}),
            ),
            (
                "replacement-env",
                json!({"process": {"env": ["KEY=value"]}}),
            ),
            (
                "proxy-env",
                json!({"process": {"env": ["hTtP_pRoXy=http://proxy"], "inheritDefaultEnv": true}}),
            ),
            (
                "large-env",
                json!({"process": {"env": [format!("KEY={}", "x".repeat(32 * 1024))], "inheritDefaultEnv": true}}),
            ),
            (
                "malformed-env",
                json!({"process": {"env": ["MISSING_EQUALS"], "inheritDefaultEnv": true}}),
            ),
            (
                "null-command",
                json!({"process": {"commandLine": "printf forbidden\0"}}),
            ),
        ]
    }

    fn request_with_patch(patch: Value) -> Value {
        let mut request = process_only_request("printf forbidden");
        for (key, value) in patch.as_object().expect("patch object") {
            if key == "process" {
                for (field, value) in value.as_object().expect("process patch object") {
                    request["process"][field] = value.clone();
                }
            } else {
                request[key] = value.clone();
            }
        }
        request
    }

    fn valid_process_boundaries() -> Vec<(&'static str, Value)> {
        vec![
            ("legacy-fallback-empty", json!({"fallback": {}})),
            (
                "legacy-fallback-true",
                json!({"fallback": {"allowDaclMutation": true}}),
            ),
            (
                "legacy-fallback-false",
                json!({"fallback": {"allowDaclMutation": false}}),
            ),
            (
                "cwd-boundary",
                json!({"process": {"cwd": format!("/{}", "x".repeat(4094))}}),
            ),
            (
                "cwd-multibyte-boundary",
                json!({"process": {"cwd": format!("/{}", "\u{00e9}".repeat(2047))}}),
            ),
            (
                "env-entry-boundary",
                json!({"process": {"env": vec!["KEY=value"; 256], "inheritDefaultEnv": true}}),
            ),
            (
                "absent-env",
                json!({"process": {"inheritDefaultEnv": true}}),
            ),
            (
                "empty-env",
                json!({"process": {"env": [], "inheritDefaultEnv": true}}),
            ),
        ]
    }

    fn process_limit_error(label: &str) -> Option<&'static str> {
        match label {
            "memory-override" => Some("NVX guest memory overrides are not available in this build"),
            "cwd-limit" | "cwd-multibyte-limit" => {
                Some("NVX process.cwd must not exceed 4095 UTF-8 bytes")
            }
            "env-entry-limit" => Some("NVX process.env must not exceed 256 entries"),
            _ => None,
        }
    }

    #[test]
    fn host_only_request_matrix_never_reaches_a_runtime() {
        // Only this isolated child sees the deliberately absent bundle. Even a policy regression
        // cannot start a VM: native discovery fails before the agent DLL can be opened.
        if std::env::var_os("MXC_NVX_MATRIX_CHILD").is_none() {
            let directory = tempfile::tempdir().expect("matrix temporary directory");
            let output = Command::new(std::env::current_exe().expect("current test executable"))
                .args([
                    "--exact",
                    "windows_x64::host_only_request_matrix_never_reaches_a_runtime",
                    "--nocapture",
                ])
                .env("MXC_NVX_MATRIX_CHILD", "1")
                .env(BUNDLE_ENV, directory.path().join("absent"))
                .output()
                .expect("host-only matrix child");
            assert!(
                output.status.success(),
                "matrix child failed\nstdout: {}\nstderr: {}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            );
            println!("{}", String::from_utf8_lossy(&output.stdout));
            return;
        }

        for (label, patch) in rejected_requests() {
            let request = request_with_patch(patch);
            let error = mxc_sdk::__ffi::run_json(&request.to_string(), true).unwrap_err();
            assert!(
                matches!(
                    error.code,
                    ErrorCode::PolicyValidation | ErrorCode::MalformedRequest
                ),
                "{label} must be rejected before bundle discovery: {error:?}"
            );
            if matches!(
                label,
                "capture"
                    | "least-privilege"
                    | "learning-mode"
                    | "capabilities"
                    | "process-ui"
                    | "enumerate"
            ) {
                assert_eq!(
                    error.code,
                    ErrorCode::MalformedRequest,
                    "{label} must use the parser error contract"
                );
                assert_eq!(error.message, MIXED_BACKEND_ERROR, "{label}");
            }
            if let Some(expected) = process_limit_error(label) {
                assert_eq!(error.code, ErrorCode::PolicyValidation, "{label}");
                assert_eq!(error.message, expected, "{label}");
            }
            println!(
                "HOST_ONLY rejected {label}: {:?}: {}",
                error.code, error.message
            );
        }

        let mut request = process_only_request("printf forbidden");
        request["microvm"]["provision"] = json!({"memoryMib": 512});
        let error = __ffi::run_json(&request.to_string(), true).unwrap_err();
        assert_eq!(error.code, ErrorCode::PolicyValidation, "{error}");
        assert_eq!(
            error.message,
            "NVX guest memory overrides are not available in this build"
        );

        for (label, patch) in valid_process_boundaries() {
            let error =
                mxc_sdk::__ffi::run_json(&request_with_patch(patch).to_string(), true).unwrap_err();
            assert_eq!(
                error.code,
                ErrorCode::BackendUnavailable,
                "{label}: {error:?}"
            );
            assert!(
                error.message.contains("holds no agent bundle"),
                "{label}: {error:?}"
            );
            assert_no_run_state(std::process::id());
            println!(
                "HOST_ONLY valid {label} reaches missing bundle: {}",
                error.message
            );
        }

        let request = process_only_request("printf forbidden").to_string();
        let error = mxc_sdk::__ffi::run_json(&request, true).unwrap_err();
        assert_eq!(error.code, ErrorCode::BackendUnavailable);
        assert!(error.message.contains("NVX"));
        println!(
            "HOST_ONLY missing official bundle fails closed: {}",
            error.message
        );
        assert_no_run_state(std::process::id());

        let streaming = mxc_sdk::__ffi::spawn_container_json(&request, true)
            .err()
            .expect("P1 must reject streaming");
        assert_eq!(streaming.code, ErrorCode::UnsupportedContainment);
        let pty =
            mxc_sdk::__ffi::spawn_with_pty_json(&request, true, Default::default()).unwrap_err();
        assert_eq!(pty.code, ErrorCode::UnsupportedContainment);
        let lifecycle = json!({
            "version": "1.1.0-alpha", "phase": "provision", "containment": "microvm"
        });
        assert!(mxc_sdk::__ffi::run_lifecycle_json(&lifecycle.to_string(), false, true).is_err());
    }

    fn executor() -> PathBuf {
        let current = std::env::current_exe().expect("current test executable");
        let directory = current.parent().expect("test executable directory");
        let beside = directory.join("wxc-exec.exe");
        let path = if beside.is_file() {
            beside
        } else {
            directory
                .parent()
                .expect("Cargo profile directory")
                .join("wxc-exec.exe")
        };
        assert!(
            path.is_file(),
            "build wxc-exec with microvm first: {}",
            path.display()
        );
        path
    }

    fn executor_output(request: &Value, missing_bundle: bool) -> Output {
        executor_output_with_mode(request, missing_bundle, false)
    }

    fn executor_output_with_mode(request: &Value, missing_bundle: bool, dry_run: bool) -> Output {
        let directory = tempfile::tempdir().expect("executor request directory");
        let path = directory.path().join("request.json");
        std::fs::write(&path, request.to_string()).expect("write executor request");
        let mut command = Command::new(executor());
        command.arg("--experimental").arg(&path);
        if dry_run {
            command.arg("--dry-run");
        }
        if missing_bundle {
            command.env(BUNDLE_ENV, directory.path().join("absent"));
        }
        let child = command
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("MXC executor process");
        let pid = child.id();
        let output = child.wait_with_output().expect("MXC executor output");
        assert_no_run_state(pid);
        output
    }

    #[test]
    #[ignore = "host-only; requires separately built wxc-exec.exe; never creates a VM"]
    fn host_only_executor_request_matrix() {
        let mut zero_memory = process_only_request("printf forbidden");
        zero_memory["microvm"]["provision"] = json!({"memoryMib": 0});
        let sdk_error = dev::run_json(
            &zero_memory.to_string(),
            dev::JsonOptions { experimental: true },
        )
        .unwrap_err();
        assert_eq!(sdk_error.code, ErrorCode::MalformedRequest);
        for dry_run in [false, true] {
            let output = executor_output_with_mode(&zero_memory, true, dry_run);
            assert_eq!(output.status.code(), Some(1), "{output:?}");
            let stderr = String::from_utf8_lossy(&output.stderr);
            assert!(stderr.contains("malformed_request"), "{stderr}");
            assert!(!stderr.contains("policy_validation"), "{stderr}");
            assert!(
                stderr.contains("microvm.provision.memoryMib must be greater than zero"),
                "{stderr}"
            );
            assert!(!String::from_utf8_lossy(&output.stdout).contains("forbidden"));
        }
        for (label, patch) in rejected_requests() {
            let output = executor_output(&request_with_patch(patch), true);
            assert!(!output.status.success(), "executor accepted {label}");
            let stderr = String::from_utf8_lossy(&output.stderr);
            assert!(
                stderr.contains("policy_validation")
                    || stderr.contains("malformed_request")
                    || stderr.contains("Configuration parse error:"),
                "{label} was not rejected before bundle discovery: {stderr}"
            );
            assert!(!String::from_utf8_lossy(&output.stdout).contains("forbidden"));
            if let Some(expected) = process_limit_error(label) {
                assert!(stderr.contains("policy_validation"), "{label}: {stderr}");
                assert!(stderr.contains(expected), "{label}: {stderr}");
            }
            println!("HOST_ONLY executor rejected {label}: {stderr}");
        }
        for (label, patch) in valid_process_boundaries() {
            let output = executor_output(&request_with_patch(patch), true);
            assert!(!output.status.success(), "missing bundle accepted {label}");
            let stderr = String::from_utf8_lossy(&output.stderr);
            assert!(stderr.contains("backend_unavailable"), "{label}: {stderr}");
            assert!(
                stderr.contains("holds no agent bundle"),
                "{label}: {stderr}"
            );
            assert!(output.stdout.is_empty());
            println!("HOST_ONLY executor valid {label} reaches missing bundle: {stderr}");
        }
    }

    #[test]
    #[ignore = "requires a signed agent bundle and separately built wxc-exec.exe"]
    fn signed_executor_proxy_validation_withholds_credentials() {
        let directory = tempfile::tempdir().expect("executor request directory");
        let request_path = directory.path().join("request.json");
        let log_path = directory.path().join("executor.log");
        let mut request = process_only_request("printf forbidden");
        request["runtimeConfig"] =
            json!({"networkProxy": "http://synthetic-user:synthetic-password@[::1]:3128"});
        std::fs::write(&request_path, request.to_string()).expect("write executor request");

        let child = Command::new(executor())
            .arg("--experimental")
            .arg("--debug")
            .arg("--log-file")
            .arg(&log_path)
            .arg(&request_path)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("MXC executor process");
        let pid = child.id();
        let output = child.wait_with_output().expect("MXC executor output");
        assert_no_run_state(pid);
        assert!(!output.status.success());
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(stderr.contains("policy_validation"), "{stderr}");
        assert!(stderr.contains("validate_provision"), "{stderr}");
        assert!(stderr.contains("withheld"), "{stderr}");
        let stdout = String::from_utf8_lossy(&output.stdout);
        let log = std::fs::read_to_string(log_path).expect("executor log");
        assert!(!log.is_empty(), "executor log should contain diagnostics");
        for text in [stdout.as_ref(), stderr.as_ref(), log.as_str()] {
            assert!(
                !text.contains("synthetic"),
                "executor diagnostics leaked credentials"
            );
        }
    }

    fn nonce() -> String {
        format!(
            "mxc-nvx-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("system clock")
                .as_nanos()
        )
    }

    pub(super) fn assert_no_run_state(pid: u32) {
        let prefix = format!("mxc-nvx-{pid}-");
        let retained: Vec<_> = std::fs::read_dir(std::env::temp_dir())
            .expect("temporary directory listing")
            .filter_map(Result::ok)
            .filter(|entry| entry.file_name().to_string_lossy().starts_with(&prefix))
            .map(|entry| entry.path())
            .collect();
        assert!(retained.is_empty(), "NVX run state leaked: {retained:?}");
    }

    fn facade_run(request: Value) -> ExecutionResult {
        let result = mxc_sdk::__ffi::run_json(&request.to_string(), true)
            .expect("real MXC signed bundled-agent create-and-run");
        assert_no_run_state(std::process::id());
        result
    }

    fn assert_host_cpu_profile(stdout: &[u8]) {
        let output = String::from_utf8_lossy(stdout);
        assert!(
            output.contains("Processor (host profile)"),
            "guest CPU does not identify a host profile: {output}"
        );
    }

    fn capture_boundary_request(stderr_bytes: usize) -> Value {
        // Finite output bounds host memory and run time even if the capture guard regresses.
        let mut request = process_only_request(&format!(
            "head -c {} /dev/zero && head -c {stderr_bytes} /dev/zero >&2",
            CAPTURE_LIMIT / 2
        ));
        request["process"]["timeout"] = json!(0);
        request
    }

    fn assert_capture_boundary(stdout: &[u8], stderr: &[u8], stderr_bytes: usize) {
        assert_eq!(stdout.len(), CAPTURE_LIMIT / 2);
        assert_eq!(stderr.len(), stderr_bytes);
        assert!(stdout.iter().chain(stderr).all(|&byte| byte == 0));
    }

    fn guest_path_for_host_directory(path: &Path) -> String {
        let canonical = path.canonicalize().expect("canonical host directory");
        let mut components = canonical.components();
        let drive = match components.next() {
            Some(Component::Prefix(prefix)) => match prefix.kind() {
                Prefix::Disk(drive) | Prefix::VerbatimDisk(drive) => drive,
                _ => panic!("host directory must have a disk prefix"),
            },
            _ => panic!("host directory must have a disk prefix"),
        };
        assert!(matches!(components.next(), Some(Component::RootDir)));
        let mut guest = format!("/mnt/{}", char::from(drive).to_ascii_lowercase());
        for component in components {
            match component {
                Component::Normal(name) => {
                    guest.push('/');
                    guest.push_str(name.to_str().expect("UTF-8 host directory"));
                }
                _ => panic!("canonical host directory has an unsupported component"),
            }
        }
        guest
    }

    #[test]
    fn guest_path_resolves_windows_case_alias() {
        let directory = tempfile::tempdir().unwrap();
        let actual = directory.path().join("PolicyAlias");
        std::fs::create_dir(&actual).unwrap();
        let alias = directory.path().join("pOLICYalias");
        let guest = guest_path_for_host_directory(&alias);
        assert_eq!(guest, guest_path_for_host_directory(&actual));
        assert!(guest.ends_with("/PolicyAlias"), "{guest}");
        assert!(!guest.contains("pOLICYalias"), "{guest}");
    }

    #[test]
    #[ignore = "VM: requires Windows x64, WHP and the exact signed official bundle"]
    fn signed_bundle_json_image_and_filesystem_policy() {
        let directory = tempfile::tempdir().unwrap();
        let actual_root = directory.path().join("PolicyAlias");
        std::fs::create_dir(&actual_root).unwrap();
        let alias_root = directory.path().join("pOLICYalias");
        assert_eq!(
            actual_root.canonicalize().unwrap(),
            alias_root.canonicalize().unwrap()
        );
        let ro = alias_root.join("ro");
        let rw = alias_root.join("rw");
        std::fs::create_dir(&ro).unwrap();
        std::fs::create_dir(&rw).unwrap();
        std::fs::write(ro.join("input"), b"read-ok").unwrap();
        std::fs::write(rw.join("secret"), b"secret").unwrap();
        let ungranted = alias_root.join("ungranted");
        std::fs::write(&ungranted, b"ungranted-sentinel").unwrap();
        assert_eq!(std::fs::read(&ungranted).unwrap(), b"ungranted-sentinel");
        let host_file = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(&ungranted)
            .expect("ungranted fixture must be readable and writable by the host");
        drop(host_file);
        let guest_root = guest_path_for_host_directory(&alias_root);
        let script = r#"python3 -c 'import errno, os, pathlib, sys
assert sys.version_info[:2] == (3, 12)
root = pathlib.Path(os.environ["MXC_NVX_POLICY_ROOT"])
assert (root / "ro" / "input").read_bytes() == b"read-ok"
try:
    (root / "ro" / "input").write_bytes(b"forbidden")
except OSError as error:
    assert error.errno in (errno.EACCES, errno.EROFS), error
else:
    raise AssertionError("read-only mapping was writable")
try:
    (root / "rw" / "secret").read_bytes()
except OSError as error:
    assert error.errno == errno.EACCES, error
else:
    raise AssertionError("denied path was readable")
try:
    descriptor = os.open(root / "rw" / "secret", os.O_WRONLY)
    try:
        os.write(descriptor, b"forbidden")
    finally:
        os.close(descriptor)
except OSError as error:
    assert error.errno == errno.EACCES, error
else:
    raise AssertionError("denied path was writable")
for operation in ("read", "write"):
    try:
        if operation == "read":
            (root / "ungranted").read_bytes()
        else:
            # Do not create a guest-local file when the host sibling is unmapped.
            with (root / "ungranted").open("r+b") as output:
                output.write(b"forbidden")
    except OSError as error:
        expected = (errno.EACCES, errno.ENOENT)
        if operation == "write":
            expected += (errno.EROFS,)
        assert error.errno in expected, error
    else:
        raise AssertionError("ungranted sibling allowed " + operation)
(root / "rw" / "result").write_bytes(b"write-ok")
print("NVX_JSON_IMAGE_AND_POLICY_OK", end="")
'"#;
        let request = json!({
            "version": "1.1.0-alpha",
            "containment": "microvm",
            "microvm": {"image": "docker.io/library/python:3.12-alpine"},
            "filesystem": {
                "readonlyPaths": [ro.to_str().unwrap()],
                "readwritePaths": [rw.to_str().unwrap()],
                "deniedPaths": [rw.join("secret").to_str().unwrap()]
            },
            "network": {},
            "process": {
                "commandLine": script,
                "env": [format!("MXC_NVX_POLICY_ROOT={guest_root}")],
                "inheritDefaultEnv": true,
                "timeout": 30000
            }
        });
        let result = __ffi::run_json(&request.to_string(), true).unwrap();
        assert_eq!(result.outcome, WaitResult::Exited(0), "{result:?}");
        assert_eq!(result.stdout, b"NVX_JSON_IMAGE_AND_POLICY_OK");
        assert_eq!(std::fs::read(ro.join("input")).unwrap(), b"read-ok");
        assert_eq!(std::fs::read(rw.join("secret")).unwrap(), b"secret");
        assert_eq!(std::fs::read(rw.join("result")).unwrap(), b"write-ok");
        assert_eq!(std::fs::read(&ungranted).unwrap(), b"ungranted-sentinel");
        assert_no_run_state(std::process::id());
        println!("VM_EXECUTED JSON selected-image filesystem read/write/deny and cleanup");
    }

    #[test]
    #[ignore = "VM: requires Windows x64, WHP and the exact signed official bundle"]
    fn signed_bundle_sdk_json_capture() {
        let options = dev::JsonOptions { experimental: true };
        let mut invalid_proxy = process_only_request("printf forbidden");
        invalid_proxy["runtimeConfig"] =
            json!({"networkProxy": "http://synthetic-user:synthetic-password@[::1]:3128"});
        let error = dev::run_json(&invalid_proxy.to_string(), options).unwrap_err();
        assert_eq!(error.code, ErrorCode::PolicyValidation);
        assert!(error.message.contains("validate_provision"), "{error}");
        assert!(error.message.contains("withheld"), "{error}");
        assert!(!format!("{error:?}").contains("synthetic"));
        assert_no_run_state(std::process::id());

        let request =
            process_only_request("printf '\\377\\000\\376'; printf '\\200\\000\\201' >&2; exit 42");
        let result = dev::run_json(&request.to_string(), options).unwrap();
        assert_eq!(result.outcome, WaitResult::Exited(42));
        assert_eq!(result.stdout, b"\xff\0\xfe");
        assert_eq!(result.stderr, b"\x80\0\x81");
        assert_no_run_state(std::process::id());

        let mut timeout =
            process_only_request("printf partial-out; printf partial-err >&2; sleep 5");
        timeout["process"]["timeout"] = json!(200);
        let result = dev::run_json(&timeout.to_string(), options).unwrap();
        assert_eq!(result.outcome, WaitResult::TimedOut);
        assert_eq!(result.stdout, b"partial-out");
        assert_eq!(result.stderr, b"partial-err");
        assert_no_run_state(std::process::id());

        let error = dev::run_json(
            &capture_boundary_request(CAPTURE_LIMIT / 2 + 1).to_string(),
            options,
        )
        .unwrap_err();
        assert_eq!(error.code, ErrorCode::BackendError);
        assert_eq!(error.message, CAPTURE_ERROR);
        assert_no_run_state(std::process::id());
        println!("VM_EXECUTED SDK JSON binary capture timeout limit and cleanup");
    }

    #[test]
    #[ignore = "VM: requires Windows x64, WHP and the exact signed official bundle"]
    fn signed_bundle_facade_create_and_run() {
        let profile = facade_run(process_only_request("cat /proc/cpuinfo"));
        assert_eq!(profile.outcome, WaitResult::Exited(0));
        assert_host_cpu_profile(&profile.stdout);

        let marker = nonce();
        for fallback in [
            None,
            Some(json!({})),
            Some(json!({"allowDaclMutation": true})),
            Some(json!({"allowDaclMutation": false})),
        ] {
            let command = format!(
                "test ! -e /tmp/{marker} || exit 99; touch /tmp/{marker}; \
                 printf '{marker}'; printf 'separate-stderr' >&2; exit 42"
            );
            let mut request = process_only_request(&command);
            if let Some(fallback) = fallback {
                request["fallback"] = fallback;
            }
            let result = facade_run(request);
            assert_eq!(result.outcome, WaitResult::Exited(42));
            assert_eq!(result.stdout, marker.as_bytes());
            assert_eq!(result.stderr, b"separate-stderr");
        }

        let mut environment = process_only_request("printf '%s:%s' \"$MXC_NVX_PROBE\" \"$PWD\"");
        environment["process"]["cwd"] = json!("/tmp");
        environment["process"]["env"] = json!([format!("MXC_NVX_PROBE={marker}")]);
        environment["process"]["inheritDefaultEnv"] = json!(true);
        let result = facade_run(environment);
        assert_eq!(result.outcome, WaitResult::Exited(0));
        assert_eq!(result.stdout, format!("{marker}:/tmp").as_bytes());

        let result = facade_run(process_only_request(
            "printf '\\377\\000\\376'; printf '\\200\\000\\201' >&2; exit 42",
        ));
        assert_eq!(result.outcome, WaitResult::Exited(42));
        assert_eq!(result.stdout, b"\xff\0\xfe");
        assert_eq!(result.stderr, b"\x80\0\x81");

        let mut timeout =
            process_only_request("printf partial-out; printf partial-err >&2; sleep 5");
        timeout["process"]["timeout"] = json!(200);
        let result = facade_run(timeout);
        assert_eq!(result.outcome, WaitResult::TimedOut);
        assert_eq!(result.stdout, b"partial-out");
        assert_eq!(result.stderr, b"partial-err");

        let result = facade_run(process_only_request("printf after-timeout"));
        assert_eq!(result.outcome, WaitResult::Exited(0));
        assert_eq!(result.stdout, b"after-timeout");

        for stderr_bytes in [CAPTURE_LIMIT / 2 - 1, CAPTURE_LIMIT / 2] {
            let result = facade_run(capture_boundary_request(stderr_bytes));
            assert_eq!(result.outcome, WaitResult::Exited(0));
            assert_capture_boundary(&result.stdout, &result.stderr, stderr_bytes);
        }
        let error = mxc_sdk::__ffi::run_json(
            &capture_boundary_request(CAPTURE_LIMIT / 2 + 1).to_string(),
            true,
        )
        .unwrap_err();
        assert_eq!(error.code, ErrorCode::BackendError);
        assert_eq!(error.message, CAPTURE_ERROR);
        assert_no_run_state(std::process::id());
        let result = facade_run(process_only_request("printf after-overflow"));
        assert_eq!(result.outcome, WaitResult::Exited(0));
        assert_eq!(result.stdout, b"after-overflow");
        println!("VM_EXECUTED facade sequential stdout/stderr/exit/env/cwd/timeout/capture-limit/cleanup");
    }

    #[test]
    #[ignore = "VM: requires separately built wxc-exec.exe, WHP and exact signed official bundle"]
    fn signed_bundle_executor_configs() {
        let valid = process_only_request("printf forbidden");
        let output = executor_output_with_mode(&valid, false, true);
        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(output.status.success(), "{output:?}");
        assert!(
            stdout.contains("Dry run completed. Result: validation passed"),
            "{stdout}"
        );
        assert!(!stdout.contains("forbidden"), "{stdout}");

        let mut invalid_proxy = valid.clone();
        invalid_proxy["runtimeConfig"] = json!({"networkProxy": "http://[::1]:3128"});
        let output = executor_output_with_mode(&invalid_proxy, false, true);
        assert!(!output.status.success(), "{output:?}");
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(stderr.contains("policy_validation"), "{stderr}");
        assert!(stderr.contains("OpenVMM reaches host loopback"), "{stderr}");
        assert!(!String::from_utf8_lossy(&output.stdout).contains("forbidden"));

        invalid_proxy["runtimeConfig"] =
            json!({"networkProxy": "http://synthetic:secret@[::1]:3128"});
        let output = executor_output_with_mode(&invalid_proxy, false, true);
        assert!(!output.status.success(), "{output:?}");
        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(stderr.contains("policy_validation"), "{stderr}");
        assert!(stderr.contains("validate_provision"), "{stderr}");
        assert!(stderr.contains("withheld"), "{stderr}");
        assert!(!stdout.contains("synthetic"));
        assert!(!stderr.contains("synthetic"));

        let output = executor_output_with_mode(&valid, true, true);
        assert!(!output.status.success(), "{output:?}");
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(stderr.contains("backend_unavailable"), "{stderr}");
        assert!(stderr.contains("holds no agent bundle"), "{stderr}");

        let cases = [
            (
                "microvm_hello.json",
                include_str!("fixtures/microvm/microvm_hello.json"),
                0,
                Some("sum=100"),
                "Hello world",
            ),
            (
                "microvm_exit_code.json",
                include_str!("fixtures/microvm/microvm_exit_code.json"),
                42,
                None,
                "Exit code propagation",
            ),
            (
                "microvm_multiline.json",
                include_str!("fixtures/microvm/microvm_multiline.json"),
                0,
                Some("fib("),
                "Shell Fibonacci program",
            ),
            (
                "microvm_stdlib.json",
                include_str!("fixtures/microvm/microvm_stdlib.json"),
                0,
                Some("shell=posix"),
                "Guest shell and OS",
            ),
            (
                "microvm_large_output.json",
                include_str!("fixtures/microvm/microvm_large_output.json"),
                0,
                Some("line 999"),
                "Large stdout (1000 lines)",
            ),
            (
                "microvm_error.json",
                include_str!("fixtures/microvm/microvm_error.json"),
                1,
                Some("intentional test error"),
                "Shell error",
            ),
            (
                "microvm_timeout.json",
                include_str!("fixtures/microvm/microvm_timeout.json"),
                -1,
                Some("NVX workload timed out"),
                "Timeout kills VM",
            ),
        ];
        let mut results = Vec::new();
        let mut failures = Vec::new();
        for (name, source, expected_exit, expected_output, description) in cases {
            let request: Value = serde_json::from_str(source).expect("MicroVM config fixture");
            let started = Instant::now();
            let output = executor_output(&request, false);
            let elapsed = started.elapsed().as_millis();
            let combined = format!(
                "{}\n{}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            );
            let passed = output.status.code() == Some(expected_exit)
                && expected_output.is_none_or(|expected| combined.contains(expected));
            let status = if passed { "PASS" } else { "FAIL" };
            println!("{status} {description} ({name}): {elapsed} ms");
            results.push(json!({
                "test": name,
                "description": description,
                "status": status,
                "exit_code": output.status.code(),
                "wall_time_ms": elapsed,
            }));
            if !passed {
                failures.push(format!(
                    "{name}: expected exit {expected_exit}, got {:?}\n{combined}",
                    output.status.code()
                ));
            }
        }
        let performance = json!({
            "commit": std::env::var("GITHUB_SHA").unwrap_or_else(|_| "local".to_owned()),
            "timestamp": chrono::Utc::now().to_rfc3339(),
            "results": results,
        });
        let path = std::env::temp_dir().join("microvm-perf-results.json");
        std::fs::write(
            &path,
            serde_json::to_vec_pretty(&performance).expect("MicroVM performance JSON"),
        )
        .expect("write MicroVM performance results");
        println!("MicroVM performance results: {}", path.display());
        assert!(failures.is_empty(), "{}", failures.join("\n"));
        println!("VM_EXECUTED executor configs all seven fixtures");
    }

    #[test]
    #[ignore = "VM: requires separately built wxc-exec.exe, WHP and exact signed official bundle"]
    fn signed_bundle_executor_console_interrupt() {
        use mxc_sdk::mxc_common::process_util::OwnedHandle;
        use std::os::windows::process::CommandExt;
        use std::time::Duration;
        use windows::Win32::Foundation::{ERROR_NO_MORE_FILES, WAIT_OBJECT_0, WAIT_TIMEOUT};
        use windows::Win32::System::Console::{
            GenerateConsoleCtrlEvent, SetConsoleCtrlHandler, CTRL_C_EVENT,
        };
        use windows::Win32::System::Diagnostics::ToolHelp::{
            CreateToolhelp32Snapshot, Process32FirstW, Process32NextW, PROCESSENTRY32W,
            TH32CS_SNAPPROCESS,
        };
        use windows::Win32::System::Threading::{
            OpenProcess, TerminateProcess, WaitForSingleObject, CREATE_NEW_CONSOLE,
            PROCESS_SYNCHRONIZE, PROCESS_TERMINATE,
        };

        const CHILD_ENV: &str = "MXC_NVX_CONSOLE_CHILD";
        if std::env::var_os(CHILD_ENV).is_none() {
            for phase in ["startup", "execution"] {
                // A separate console prevents Ctrl-C from reaching the suite or other sessions.
                let output = Command::new(std::env::current_exe().expect("test executable"))
                    .args([
                        "--exact",
                        "windows_x64::signed_bundle_executor_console_interrupt",
                        "--ignored",
                        "--nocapture",
                    ])
                    .creation_flags(CREATE_NEW_CONSOLE.0)
                    .env(CHILD_ENV, phase)
                    .output()
                    .expect("isolated console helper");
                assert!(
                    output.status.success(),
                    "{phase} helper failed\nstdout: {}\nstderr: {}",
                    String::from_utf8_lossy(&output.stdout),
                    String::from_utf8_lossy(&output.stderr)
                );
            }
            println!(
                "VM_EXECUTED executor console interruption startup/execution/owned-vmm/cleanup"
            );
            return;
        }

        unsafe extern "system" fn helper_handler(event: u32) -> windows::core::BOOL {
            windows::core::BOOL(i32::from(event == CTRL_C_EVENT))
        }
        unsafe { SetConsoleCtrlHandler(Some(helper_handler), true) }
            .expect("helper control handler");

        struct ExecutorGuard {
            child: std::process::Child,
            vmm: Option<OwnedHandle>,
        }
        impl Drop for ExecutorGuard {
            fn drop(&mut self) {
                match self.child.try_wait() {
                    Ok(Some(_)) => {}
                    _ => {
                        if let Err(error) = self.child.kill() {
                            eprintln!("failed-test executor cleanup failed: {error}");
                        }
                        if let Err(error) = self.child.wait() {
                            eprintln!("failed-test executor wait failed: {error}");
                        }
                    }
                }
                if let Some(vmm) = &self.vmm {
                    if unsafe { WaitForSingleObject(vmm.get(), 0) } == WAIT_TIMEOUT {
                        if let Err(error) = unsafe { TerminateProcess(vmm.get(), 1) } {
                            eprintln!("failed-test owned VMM cleanup failed: {error}");
                        } else if unsafe { WaitForSingleObject(vmm.get(), 30_000) } != WAIT_OBJECT_0
                        {
                            eprintln!("failed-test owned VMM cleanup did not complete");
                        }
                    }
                }
            }
        }

        fn owned_vmm(pid: u32) -> Option<OwnedHandle> {
            let snapshot = OwnedHandle::new(
                unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) }
                    .expect("process snapshot"),
            );
            let mut entry = PROCESSENTRY32W {
                dwSize: std::mem::size_of::<PROCESSENTRY32W>() as u32,
                ..Default::default()
            };
            let mut next = unsafe { Process32FirstW(snapshot.get(), &mut entry) };
            loop {
                match next {
                    Ok(()) => {}
                    Err(error) if error.code() == ERROR_NO_MORE_FILES.to_hresult() => return None,
                    Err(error) => panic!("process enumeration failed: {error}"),
                }
                let end = entry
                    .szExeFile
                    .iter()
                    .position(|&c| c == 0)
                    .unwrap_or(entry.szExeFile.len());
                let name = String::from_utf16_lossy(&entry.szExeFile[..end]);
                if entry.th32ParentProcessID == pid && name.eq_ignore_ascii_case("openvmm.exe") {
                    let handle = unsafe {
                        OpenProcess(
                            PROCESS_SYNCHRONIZE | PROCESS_TERMINATE,
                            false,
                            entry.th32ProcessID,
                        )
                    }
                    .expect("owned OpenVMM handle");
                    return Some(OwnedHandle::new(handle));
                }
                next = unsafe { Process32NextW(snapshot.get(), &mut entry) };
            }
        }

        let directory = tempfile::tempdir().expect("interruption test directory");
        let state = directory.path().join("state");
        std::fs::create_dir(&state).expect("isolated state directory");
        let request_path = directory.path().join("request.json");
        let log_path = directory.path().join("executor.log");
        let stdout_path = directory.path().join("stdout");
        let stderr_path = directory.path().join("stderr");
        let mut request = process_only_request("sleep 600");
        request["process"]["timeout"] = json!(0);
        std::fs::write(&request_path, request.to_string()).expect("interruption request");
        let mut guard = ExecutorGuard {
            child: Command::new(executor())
                .args(["--experimental", "--log-file"])
                .arg(&log_path)
                .arg(&request_path)
                .env("TEMP", &state)
                .env("TMP", &state)
                .stdin(Stdio::null())
                .stdout(std::fs::File::create(&stdout_path).expect("stdout file"))
                .stderr(std::fs::File::create(&stderr_path).expect("stderr file"))
                .spawn()
                .expect("interruptible executor"),
            vmm: None,
        };
        let phase = std::env::var(CHILD_ENV).expect("interruption phase");
        let ready_deadline = Instant::now() + Duration::from_secs(180);
        loop {
            assert!(
                guard.child.try_wait().expect("executor status").is_none(),
                "executor exited before interruption: {}",
                std::fs::read_to_string(&stderr_path).expect("executor stderr")
            );
            if guard.vmm.is_none() {
                guard.vmm = owned_vmm(guard.child.id());
            }
            let executing = match std::fs::read_to_string(&log_path) {
                Ok(log) => log.contains("NVX execution started"),
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => false,
                Err(error) => panic!("executor log read failed: {error}"),
            };
            if guard.vmm.is_some() && (phase == "startup" || executing) {
                assert!(
                    phase != "startup" || !executing,
                    "missed the startup interruption window"
                );
                break;
            }
            assert!(
                Instant::now() < ready_deadline,
                "executor never reached {phase}"
            );
            std::thread::sleep(Duration::from_millis(20));
        }
        let interrupted = Instant::now();
        unsafe { GenerateConsoleCtrlEvent(CTRL_C_EVENT, 0) }.expect("real Ctrl-C delivery");
        let exit = loop {
            if let Some(exit) = guard.child.try_wait().expect("cancelled executor status") {
                break exit;
            }
            assert!(
                interrupted.elapsed() < Duration::from_secs(180),
                "cancellation teardown hung"
            );
            std::thread::sleep(Duration::from_millis(20));
        };
        assert_eq!(
            exit.code(),
            Some(130),
            "Ctrl-C must exit through coordinated cancellation"
        );
        assert_eq!(
            unsafe { WaitForSingleObject(guard.vmm.as_ref().expect("owned VM").get(), 0) },
            WAIT_OBJECT_0,
            "owned OpenVMM is still running",
        );
        assert!(
            std::fs::read_dir(&state)
                .expect("run state listing")
                .next()
                .is_none(),
            "cancelled run state was retained"
        );
        assert!(std::fs::read(&stdout_path)
            .expect("stdout bytes")
            .is_empty());
        let stderr = std::fs::read_to_string(&stderr_path).expect("cancellation stderr");
        assert!(stderr.contains("execution cancelled"), "{stderr}");
        assert!(!stderr.contains("timed out"), "{stderr}");
        assert!(std::fs::read_to_string(&log_path)
            .expect("teardown log")
            .contains("mxc.SandboxTornDown"));
        unsafe { SetConsoleCtrlHandler(Some(helper_handler), false) }
            .expect("remove helper handler");
    }

    #[test]
    #[ignore = "VM: requires separately built wxc-exec.exe, WHP and exact signed official bundle"]
    fn signed_bundle_executor_create_and_run() {
        let profile = executor_output(&process_only_request("cat /proc/cpuinfo"), false);
        assert_eq!(profile.status.code(), Some(0));
        assert_host_cpu_profile(&profile.stdout);

        let marker = nonce();
        for fallback in [
            None,
            Some(json!({})),
            Some(json!({"allowDaclMutation": true})),
            Some(json!({"allowDaclMutation": false})),
        ] {
            let mut request = process_only_request(&format!(
                "printf '{marker}'; printf executor-stderr >&2; exit 42"
            ));
            if let Some(fallback) = fallback {
                request["fallback"] = fallback;
            }
            let output = executor_output(&request, false);
            assert_eq!(output.status.code(), Some(42));
            assert_eq!(output.stdout, marker.as_bytes());
            assert_eq!(output.stderr, b"executor-stderr");
        }
        let output = executor_output(
            &process_only_request(
                "printf '\\377\\000\\376'; printf '\\200\\000\\201' >&2; exit 42",
            ),
            false,
        );
        assert_eq!(output.status.code(), Some(42));
        assert_eq!(output.stdout, b"\xff\0\xfe");
        assert_eq!(output.stderr, b"\x80\0\x81");
        let mut timeout =
            process_only_request("printf partial-out; printf partial-err >&2; sleep 5");
        timeout["process"]["timeout"] = json!(200);
        let output = executor_output(&timeout, false);
        assert_eq!(output.status.code(), Some(-1));
        assert_eq!(output.stdout, b"partial-out");
        assert!(String::from_utf8_lossy(&output.stderr).contains("partial-err"));
        assert!(String::from_utf8_lossy(&output.stderr).contains("NVX workload timed out"));
        let output = executor_output(&process_only_request("printf after-timeout"), false);
        assert_eq!(output.status.code(), Some(0));
        assert_eq!(output.stdout, b"after-timeout");
        for stderr_bytes in [CAPTURE_LIMIT / 2 - 1, CAPTURE_LIMIT / 2] {
            let output = executor_output(&capture_boundary_request(stderr_bytes), false);
            assert_eq!(output.status.code(), Some(0));
            assert_capture_boundary(&output.stdout, &output.stderr, stderr_bytes);
        }
        let output = executor_output(&capture_boundary_request(CAPTURE_LIMIT / 2 + 1), false);
        assert_eq!(output.status.code(), Some(-1));
        assert!(
            output.stdout.is_empty(),
            "overflow must not relay partial output"
        );
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(stderr.contains(CAPTURE_ERROR), "{stderr}");
        assert!(!stderr.contains("NVX workload timed out"), "{stderr}");
        let output = executor_output(&process_only_request("printf after-overflow"), false);
        assert_eq!(output.status.code(), Some(0));
        assert_eq!(output.stdout, b"after-overflow");
        println!(
            "VM_EXECUTED executor sequential stdout/stderr/exit/timeout/capture-limit/cleanup"
        );
    }
}
