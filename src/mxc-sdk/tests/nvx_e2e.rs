// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use mxc_sdk::v1::ErrorCode;

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
fn microvm_creation_rejects_missing_and_blank_images_before_runtime() {
    for image in [None, Some(""), Some(" "), Some("\n")] {
        let mut request = process_only_request("printf forbidden");
        request.as_object_mut().unwrap().remove("microvm");
        if let Some(image) = image {
            request["microvm"] = serde_json::json!({"image": image});
        }
        let error = mxc_sdk::__ffi::run_json(&request.to_string(), true).unwrap_err();
        assert_eq!(error.code, ErrorCode::MalformedRequest, "{error}");
        assert!(error.message.contains("microvm.image"), "{error}");
    }
}

#[test]
fn microvm_typed_stable_run_and_spawn_require_optin() {
    for spawn in [false, true] {
        let mut request = mxc_sdk::v1::ContainerRequest::new("printf forbidden");
        request.containment = mxc_sdk::v1::Containment::MicroVm {
            image: "python:3.12-alpine".to_owned(),
        };
        let error = if spawn {
            mxc_sdk::v1::spawn(request, Default::default())
                .err()
                .expect("stable spawn must reject MicroVM")
        } else {
            mxc_sdk::v1::run(request, Default::default()).unwrap_err()
        };
        assert_eq!(error.code, ErrorCode::BackendUnavailable, "{error}");
        assert!(error.message.contains("experimental"), "{error}");
    }
}

#[test]
fn microvm_experimental_typed_run_rejects_blank_image_before_runtime() {
    let mut request = mxc_sdk::v1::ContainerRequest::new("printf forbidden");
    request.containment = mxc_sdk::v1::Containment::MicroVm {
        image: " ".to_owned(),
    };
    let error = mxc_sdk::v1::experimental::run(request, Default::default()).unwrap_err();
    assert_eq!(error.code, ErrorCode::MalformedRequest, "{error}");
    assert!(error.message.contains("microvm.image"), "{error}");
}

#[cfg(not(all(windows, target_arch = "x86_64", feature = "microvm")))]
#[test]
fn unsupported_platform_or_feature_is_fail_closed() {
    let error =
        mxc_sdk::__ffi::run_json(&process_only_request("printf forbidden").to_string(), true)
            .unwrap_err();
    assert_eq!(error.code, ErrorCode::BackendUnavailable);
    assert!(error.message.contains("Windows x64"));
}

#[cfg(all(windows, target_arch = "x86_64", feature = "microvm"))]
mod windows_x64 {
    use std::path::PathBuf;
    use std::process::{Command, Output, Stdio};
    use std::time::{SystemTime, UNIX_EPOCH};

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

    fn rejected_requests() -> Vec<(&'static str, Value)> {
        vec![
            ("ui", json!({"ui": {"disable": true}})),
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
            ("fallback", json!({"fallback": {}})),
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
            } else if label == "fallback" {
                assert_eq!(error.code, ErrorCode::PolicyValidation);
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
        let directory = tempfile::tempdir().expect("executor request directory");
        let path = directory.path().join("request.json");
        std::fs::write(&path, request.to_string()).expect("write executor request");
        let mut command = Command::new(executor());
        command.arg("--experimental").arg(&path);
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

    #[test]
    #[ignore = "VM: requires Windows x64, WHP and the exact signed official bundle"]
    fn signed_bundle_typed_image_and_filesystem_policy() {
        use mxc_sdk::v1::{ContainerRequest, Containment, FilesystemPolicy, NetworkPolicy};

        let directory = tempfile::tempdir().unwrap();
        let ro = directory.path().join("ro");
        let rw = directory.path().join("rw");
        std::fs::create_dir(&ro).unwrap();
        std::fs::create_dir(&rw).unwrap();
        std::fs::write(ro.join("input"), b"read-ok").unwrap();
        std::fs::write(rw.join("secret"), b"secret").unwrap();
        let host_root = directory.path().to_str().unwrap();
        assert_eq!(host_root.as_bytes()[1], b':', "drive-qualified host path");
        let guest_root = format!(
            "/mnt/{}/{}",
            host_root[..1].to_ascii_lowercase(),
            host_root[3..].replace('\\', "/")
        );
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
(root / "rw" / "result").write_bytes(b"write-ok")
print("NVX_TYPED_IMAGE_AND_POLICY_OK", end="")
'"#;
        let result = mxc_sdk::v1::experimental::run(
            ContainerRequest {
                containment: Containment::MicroVm {
                    image: "python:3.12-alpine".to_owned(),
                },
                filesystem: Some(FilesystemPolicy {
                    readonly_paths: vec![ro.to_str().unwrap().to_owned()],
                    readwrite_paths: vec![rw.to_str().unwrap().to_owned()],
                    denied_paths: vec![rw.join("secret").to_str().unwrap().to_owned()],
                    ..Default::default()
                }),
                network: Some(NetworkPolicy::default()),
                environment: Some(vec![("MXC_NVX_POLICY_ROOT".to_owned(), guest_root)]),
                inherit_default_environment: Some(true),
                timeout_ms: Some(30_000),
                ..ContainerRequest::new(script)
            },
            Default::default(),
        )
        .unwrap();
        assert_eq!(result.outcome, WaitResult::Exited(0), "{result:?}");
        assert_eq!(result.stdout, b"NVX_TYPED_IMAGE_AND_POLICY_OK");
        assert_eq!(std::fs::read(ro.join("input")).unwrap(), b"read-ok");
        assert_eq!(std::fs::read(rw.join("secret")).unwrap(), b"secret");
        assert_eq!(std::fs::read(rw.join("result")).unwrap(), b"write-ok");
        assert_no_run_state(std::process::id());
        println!("VM_EXECUTED typed selected-image filesystem read/write/deny and cleanup");
    }

    #[test]
    #[ignore = "VM: requires Windows x64, WHP and the exact signed official bundle"]
    fn signed_bundle_facade_create_and_run() {
        let marker = nonce();
        for _ in 0..2 {
            let command = format!(
                "test ! -e /tmp/{marker} || exit 99; touch /tmp/{marker}; \
                 printf '{marker}'; printf 'separate-stderr' >&2; exit 42"
            );
            let result = facade_run(process_only_request(&command));
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
    fn signed_bundle_executor_create_and_run() {
        let marker = nonce();
        for _ in 0..2 {
            let output = executor_output(
                &process_only_request(&format!(
                    "printf '{marker}'; printf executor-stderr >&2; exit 42"
                )),
                false,
            );
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
