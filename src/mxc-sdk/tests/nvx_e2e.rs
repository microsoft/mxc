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
    use std::collections::{BTreeMap, BTreeSet};
    use std::path::{Component, Path, PathBuf, Prefix};
    use std::process::{Command, Output, Stdio};
    use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

    use mxc_sdk::mxc_common::logger::{Logger, Mode};
    use mxc_sdk::v1::{ExecutionResult, WaitResult};
    use serde_json::{json, Value};

    use super::*;

    const BUNDLE_ENV: &str = "ACI_EDGE_SANDBOXES_AGENT_ARTIFACTS_DIR";
    const CAPTURE_LIMIT: usize = 64 * 1024 * 1024;
    const CAPTURE_ERROR: &str =
        "NVX signed bundled agent: combined stdout/stderr capture limit of 67108864 bytes exceeded";

    #[test]
    fn native_validation_rejects_requests_without_booting_a_vm() {
        const CHILD: &str = "MXC_NVX_PHASE3_VALIDATION_CHILD";
        if std::env::var_os(CHILD).is_some() {
            let options = dev::JsonOptions { experimental: true };
            for source in ["{ not json".to_owned(), {
                let mut request = process_only_request("printf forbidden");
                request["microvm"]["provision"] = json!({"memoryMib": 0});
                request.to_string()
            }] {
                let error = dev::run_json(&source, options).unwrap_err();
                assert_eq!(error.code, ErrorCode::MalformedRequest, "{error}");
                let error = dev::spawn_json(&source, options)
                    .err()
                    .expect("malformed request must not spawn");
                assert_eq!(error.code, ErrorCode::MalformedRequest, "{error}");
            }
            let mut credentialed = process_only_request("printf forbidden");
            credentialed["network"] = json!({"egress": {"default": "deny"}});
            credentialed["runtimeConfig"] = json!({
                "networkProxy": "http://synthetic-user:synthetic-secret@localhost:3128"
            });
            let error = dev::run_json(&credentialed.to_string(), options).unwrap_err();
            assert_eq!(error.code, ErrorCode::PolicyValidation, "{error}");
            assert!(error.message.contains("validate_provision"), "{error}");
            assert!(error.message.contains("withheld"), "{error}");
            assert!(!format!("{error:?}").contains("synthetic"));
            let mut request = process_only_request("printf forbidden");
            request["runtimeConfig"] = json!({"networkProxy": "http://[::1]:3128"});
            let error = dev::run_json(&request.to_string(), options).unwrap_err();
            assert_eq!(error.code, ErrorCode::PolicyValidation, "{error}");
            assert!(
                error.message.contains("OpenVMM reaches host loopback"),
                "{error}"
            );
            let error = dev::spawn_json(&request.to_string(), options)
                .err()
                .expect("native proxy rejection");
            assert_eq!(error.code, ErrorCode::PolicyValidation, "{error}");
            assert!(
                error.message.contains("OpenVMM reaches host loopback"),
                "{error}"
            );
            request.as_object_mut().unwrap().remove("process");
            request["phase"] = json!("provision");
            request["microvm"]["provision"] = json!({"memoryMib": 256});
            for validate in [false, true] {
                let error = if validate {
                    dev::validate_provision_json(&request.to_string(), options)
                } else {
                    dev::provision_container_json(&request.to_string(), options)
                }
                .unwrap_err();
                assert_eq!(error.code, ErrorCode::PolicyValidation, "{error}");
                assert!(
                    error.message.contains("OpenVMM reaches host loopback"),
                    "{error}"
                );
            }
            return;
        }
        let state = tempfile::tempdir().unwrap();
        let output = Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "windows_x64::native_validation_rejects_requests_without_booting_a_vm",
                "--nocapture",
            ])
            .env(CHILD, "1")
            .env("LOCALAPPDATA", state.path())
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        // Rejected requests never boot VMs, including the ones that capture templates.
        let agent_state = state.path().join(r"Microsoft\MXC\nvx");
        let template_stores: Vec<PathBuf> = std::iter::once(agent_state.clone())
            .chain(
                std::fs::read_dir(&agent_state)
                    .expect("agent state directories")
                    .map(|entry| entry.expect("agent state directory").path()),
            )
            .map(|directory| directory.join("templates"))
            .filter(|store| store.exists())
            .collect();
        assert!(template_stores.is_empty(), "{template_stores:?}");
        assert_template_captures(&String::from_utf8_lossy(&output.stderr), 0);
    }

    #[test]
    fn experimental_opt_in_is_required_before_backend_discovery() {
        let error =
            mxc_sdk::__ffi::run_json(&process_only_request("printf forbidden").to_string(), false)
                .unwrap_err();
        assert_eq!(error.code, ErrorCode::BackendUnavailable);
        assert!(error.message.contains("experimental"));
    }

    #[test]
    fn malformed_environment_is_rejected_with_host_loopback_allow() {
        let mut request = process_only_request("printf forbidden");
        request["process"]["env"] = json!(["MISSING_EQUALS"]);
        request["process"]["inheritDefaultEnv"] = json!(true);
        request["network"] = json!({
            "ingress": {"default": "deny", "hostLoopback": "allow"}
        });

        let error = __ffi::run_json(&request.to_string(), true).unwrap_err();
        assert_eq!(error.code, ErrorCode::MalformedRequest);
        assert_eq!(
            error.message,
            "NVX process.env entries must be KEY=VALUE without null bytes"
        );
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
        executor_output_with_env(request, missing_bundle, dry_run, &[])
    }

    fn executor_output_with_env(
        request: &Value,
        missing_bundle: bool,
        dry_run: bool,
        environment: &[(&str, &std::ffi::OsStr)],
    ) -> Output {
        executor_output_with_log(request, missing_bundle, dry_run, environment).0
    }

    fn executor_output_with_log(
        request: &Value,
        missing_bundle: bool,
        dry_run: bool,
        environment: &[(&str, &std::ffi::OsStr)],
    ) -> (Output, String) {
        let directory = tempfile::tempdir().expect("executor request directory");
        let path = directory.path().join("request.json");
        let log_path = directory.path().join("executor.log");
        let mut request = request.clone();
        let mut command = Command::new(executor());
        command
            .arg("--experimental")
            .arg("--log-file")
            .arg(&log_path);
        if let Some(phase) = request.as_object_mut().unwrap().remove("phase") {
            command.arg("--operation").arg(phase.as_str().unwrap());
            if let Some(id) = request.as_object_mut().unwrap().remove("sandboxId") {
                command.arg("--container-id").arg(id.as_str().unwrap());
            }
        }
        std::fs::write(&path, request.to_string()).expect("write executor request");
        command.arg(&path);
        if dry_run {
            command.arg("--dry-run");
        }
        if missing_bundle {
            command.env(BUNDLE_ENV, directory.path().join("absent"));
        }
        let child = command
            .envs(environment.iter().copied())
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("MXC executor process");
        let pid = child.id();
        let output = child.wait_with_output().expect("MXC executor output");
        assert_no_run_state(pid);
        let log = std::fs::read_to_string(log_path).expect("executor diagnostic log");
        (output, log)
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
        for executor in [false, true] {
            assert_eq!(
                clone_policy_output(&request, executor),
                b"NVX_JSON_IMAGE_AND_POLICY_OK"
            );
        }
        assert_eq!(std::fs::read(ro.join("input")).unwrap(), b"read-ok");
        assert_eq!(std::fs::read(rw.join("secret")).unwrap(), b"secret");
        assert_eq!(std::fs::read(rw.join("result")).unwrap(), b"write-ok");
        assert_eq!(std::fs::read(&ungranted).unwrap(), b"ungranted-sentinel");
        assert_no_run_state(std::process::id());
        println!(
            "VM_EXECUTED JSON selected-image filesystem read/write/deny and cleanup confirmed clones"
        );
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
        exercise_streaming_capture();
        println!("VM_EXECUTED SDK JSON binary capture timeout limit and cleanup");
    }

    fn exercise_streaming_capture() {
        let options = dev::JsonOptions { experimental: true };
        let command = "head -c 131072 /dev/zero; head -c 131072 /dev/zero >&2; exit 42";
        let process = dev::spawn_json(&process_only_request(command).to_string(), options).unwrap();
        let output = process.wait_with_output().unwrap();
        assert_eq!(output.outcome, WaitResult::Exited(42));
        assert_eq!(output.stdout, vec![0; 131072]);
        assert_eq!(output.stderr, vec![0; 131072]);
        assert_no_run_state(std::process::id());
    }

    fn lifecycle_phase(id: &str, phase: &str) -> Value {
        json!({"version": "1.1.0-alpha", "phase": phase, "sandboxId": id})
    }

    fn lifecycle_provision() -> Value {
        let mut provision = process_only_request("unused");
        provision.as_object_mut().unwrap().remove("process");
        provision["phase"] = json!("provision");
        provision
    }

    struct LifecycleContainer {
        id: String,
        local_app_data: Option<PathBuf>,
        cleaned: bool,
    }

    impl Drop for LifecycleContainer {
        fn drop(&mut self) {
            if self.cleaned {
                return;
            }
            for phase in ["stop", "deprovision"] {
                let cleanup = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    let request = lifecycle_phase(&self.id, phase);
                    if let Some(local_app_data) = &self.local_app_data {
                        let output = executor_output_with_env(
                            &request,
                            false,
                            false,
                            &[("LOCALAPPDATA", local_app_data.as_os_str())],
                        );
                        if output.status.success() {
                            Ok(())
                        } else {
                            Err(String::from_utf8_lossy(&output.stderr).into_owned())
                        }
                    } else {
                        let options = dev::JsonOptions { experimental: true };
                        let result = if phase == "stop" {
                            dev::stop_container_json(&request.to_string(), options)
                        } else {
                            dev::deprovision_container_json(&request.to_string(), options)
                        };
                        result.map(|_| ()).map_err(|error| error.to_string())
                    }
                }));
                match cleanup {
                    Ok(Ok(())) => {}
                    Ok(Err(error)) => eprintln!("lifecycle fixture {phase} failed: {error}"),
                    Err(_) => eprintln!("lifecycle fixture {phase} cleanup panicked"),
                }
            }
        }
    }

    fn exercise_sdk_lifecycle(fallback: bool, hold_owner: bool) {
        let options = dev::JsonOptions { experimental: true };
        let local_app_data = PathBuf::from(std::env::var_os("LOCALAPPDATA").unwrap());
        let root = local_app_data.join(r"Microsoft\MXC\nvx");
        let templates = root.join("templates");
        let assert_not_captured = || {
            assert_eq!(
                templates.exists(),
                fallback,
                "unexpected template store: {templates:?}"
            );
            assert!(
                !templates.is_dir(),
                "lifecycle validation or provision captured templates"
            );
        };
        let log_path = local_app_data.join("sdk-lifecycle.log");
        let mut logger = Logger::new(Mode::Buffer);
        logger
            .enable_file_sink(&log_path)
            .expect("lifecycle diagnostic sink");
        let _sink = logger.install_thread_diagnostic_sink();
        let mut provision = lifecycle_provision();
        let proxy_listener =
            std::net::TcpListener::bind("127.0.0.1:0").expect("private proxy port");
        if fallback {
            provision["network"] = json!({"egress": {"default": "deny"}});
            provision["runtimeConfig"] = json!({
                "networkProxy": format!(
                    "http://localhost:{}",
                    proxy_listener.local_addr().unwrap().port()
                )
            });
        }
        dev::validate_provision_json(&provision.to_string(), options).unwrap();
        assert_not_captured();
        let result: Value = serde_json::from_str(
            &dev::provision_container_json(&provision.to_string(), options).unwrap(),
        )
        .unwrap();
        let mut container = LifecycleContainer {
            id: result["result"]["sandboxId"].as_str().unwrap().to_owned(),
            local_app_data: None,
            cleaned: false,
        };
        assert!(container.id.starts_with("microvm:"));
        if hold_owner {
            std::fs::write(local_app_data.join("lifecycle-id"), &container.id).unwrap();
        }
        assert_not_captured();
        let start = lifecycle_phase(&container.id, "start").to_string();
        dev::validate_start_json(&start, options).unwrap();
        assert_not_captured();
        assert!(!std::fs::read_to_string(&log_path)
            .unwrap()
            .contains("NVX sandbox started:"));
        let started: Value =
            serde_json::from_str(&dev::start_container_json(&start, options).unwrap()).unwrap();
        assert!(started["result"]["metadata"].is_null(), "{started}");
        let log = std::fs::read_to_string(&log_path).unwrap();
        let binding = if fallback {
            assert!(started["result"]["warnings"].is_null(), "{started}");
            let warnings: Vec<String> = log
                .lines()
                .filter(|line| line.contains(SNAPSHOT_WARNING))
                .map(str::to_owned)
                .collect();
            assert_snapshot_warning(&warnings, true);
            assert_cold_start(&log);
            assert!(!templates.is_dir());
            assert!(!lifecycle_sandbox_directory(&root, &container.id)
                .join("clone.json")
                .exists());
            None
        } else {
            let template = clone_template(&log, "noNic");
            assert!(templates.is_dir());
            Some((
                template.clone(),
                assert_clone_binding(&root, &container.id, &template),
            ))
        };
        assert!(!log.contains("synthetic"), "{log}");

        let marker = nonce();
        let command = format!(
            "test ! -e /tmp/{marker} || exit 99; printf '{marker}' > /tmp/{marker}; \
             head -c 131072 /dev/zero; head -c 131072 /dev/zero >&2; exit 42"
        );
        let mut exec = lifecycle_phase(&container.id, "exec");
        exec["process"] = json!({"commandLine": command, "timeout": 30000});
        let process = dev::spawn_in_container_json(&exec.to_string(), options).unwrap();
        let output = process.wait_with_output().unwrap();
        assert_eq!(output.outcome, WaitResult::Exited(42));
        assert_eq!(output.stdout, vec![0; 131072]);
        assert_eq!(output.stderr, vec![0; 131072]);
        exec["process"] = json!({
            "commandLine": format!("test \"$(cat /tmp/{marker})\" = '{marker}' && printf container-reused"),
            "timeout": 30000
        });
        let output = dev::run_in_container_json(&exec.to_string(), options).unwrap();
        assert_eq!(output.outcome, WaitResult::Exited(0));
        assert_eq!(output.stdout, b"container-reused");
        assert!(output.stderr.is_empty());
        if let Some((template, binding)) = &binding {
            assert_eq!(
                assert_clone_binding(&root, &container.id, template),
                *binding
            );
        }
        if hold_owner {
            std::fs::write(
                local_app_data.join("lifecycle-ready.pending"),
                json!({"sandboxId": container.id, "marker": marker}).to_string(),
            )
            .unwrap();
            std::fs::rename(
                local_app_data.join("lifecycle-ready.pending"),
                local_app_data.join("lifecycle-ready.json"),
            )
            .unwrap();
            let deadline = Instant::now() + Duration::from_secs(180);
            while !local_app_data.join("lifecycle-release").exists() {
                assert!(
                    Instant::now() < deadline,
                    "lifecycle owner was not released"
                );
                std::thread::sleep(Duration::from_millis(20));
            }
            // Native clone ownership lasts until this process exits, not until SDK handles close.
            container.cleaned = true;
            return;
        }
        dev::stop_container_json(&lifecycle_phase(&container.id, "stop").to_string(), options)
            .unwrap();
        let sandbox = lifecycle_sandbox_directory(&root, &container.id);
        assert!(
            !sandbox.join("clone.json").exists(),
            "stop retained the template lease"
        );
        dev::deprovision_container_json(
            &lifecycle_phase(&container.id, "deprovision").to_string(),
            options,
        )
        .unwrap();
        assert!(
            !sandbox.exists(),
            "deprovision retained native sandbox state"
        );
        container.cleaned = true;
        if !fallback {
            let result: Value = serde_json::from_str(
                &dev::provision_container_json(&provision.to_string(), options).unwrap(),
            )
            .unwrap();
            let mut next = LifecycleContainer {
                id: result["result"]["sandboxId"].as_str().unwrap().to_owned(),
                local_app_data: None,
                cleaned: false,
            };
            assert_ne!(next.id, container.id);
            let offset = std::fs::read_to_string(&log_path).unwrap().len();
            dev::start_container_json(&lifecycle_phase(&next.id, "start").to_string(), options)
                .unwrap();
            let log = std::fs::read_to_string(&log_path).unwrap();
            assert!(!log[offset..].contains(SNAPSHOT_WARNING), "{log}");
            let template = clone_template(&log[offset..], "noNic");
            assert_eq!(template, binding.as_ref().unwrap().0);
            assert_clone_binding(&root, &next.id, &template);
            let mut exec = lifecycle_phase(&next.id, "exec");
            exec["process"] = json!({
                "commandLine": format!(
                    "test ! -e /tmp/{marker} && \
                     grep -qw '{PLATFORM_TEMPLATE_PARAMETER}' /proc/cmdline && printf fresh-clone"
                ),
                "timeout": 30000
            });
            let output = dev::run_in_container_json(&exec.to_string(), options).unwrap();
            assert_eq!(output.outcome, WaitResult::Exited(0), "{output:?}");
            assert_eq!(output.stdout, b"fresh-clone");
            dev::stop_container_json(&lifecycle_phase(&next.id, "stop").to_string(), options)
                .unwrap();
            let sandbox = lifecycle_sandbox_directory(&root, &next.id);
            assert!(!sandbox.join("clone.json").exists());
            dev::deprovision_container_json(
                &lifecycle_phase(&next.id, "deprovision").to_string(),
                options,
            )
            .unwrap();
            assert!(!sandbox.exists());
            next.cleaned = true;
            println!(
                "VM_EXECUTED SDK JSON lifecycle same-process clone cleanup lease release and reuse"
            );
        }
    }

    fn exercise_executor_lifecycle(local_app_data: &Path) {
        let environment = [("LOCALAPPDATA", local_app_data.as_os_str())];
        let templates = local_app_data.join(r"Microsoft\MXC\nvx\templates");
        let provision = lifecycle_provision();
        let (output, _) = executor_output_with_log(&provision, false, true, &environment);
        assert!(output.status.success(), "{output:?}");
        assert!(
            !templates.exists(),
            "CLI provision dry-run captured templates"
        );
        assert_template_captures(&String::from_utf8_lossy(&output.stderr), 0);
        let (output, _) = executor_output_with_log(&provision, false, false, &environment);
        assert!(output.status.success(), "{output:?}");
        assert!(!templates.exists(), "CLI provision captured templates");
        let result: Value = serde_json::from_slice(&output.stdout).unwrap();
        let mut container = LifecycleContainer {
            id: result["result"]["sandboxId"].as_str().unwrap().to_owned(),
            local_app_data: Some(local_app_data.to_owned()),
            cleaned: false,
        };
        let start = lifecycle_phase(&container.id, "start");
        let (output, _) = executor_output_with_log(&start, false, true, &environment);
        assert!(output.status.success(), "{output:?}");
        assert!(!templates.exists(), "CLI start dry-run captured templates");
        let (output, log) = executor_output_with_log(&start, false, false, &environment);
        assert!(output.status.success(), "{output:?}");
        let template = clone_template(&log, "noNic");
        let root = local_app_data.join(r"Microsoft\MXC\nvx");
        let binding = assert_clone_binding(&root, &container.id, &template);
        assert_template_captures(&String::from_utf8_lossy(&output.stderr), 1);
        let marker = nonce();
        for (command, expected) in [
            (format!("test ! -e /tmp/{marker} && printf '{marker}' > /tmp/{marker} && printf first-exec"), b"first-exec".as_slice()),
            (format!("test \"$(cat /tmp/{marker})\" = '{marker}' && printf later-exec"), b"later-exec".as_slice()),
        ] {
            let mut exec = lifecycle_phase(&container.id, "exec");
            exec["process"] = json!({"commandLine": command, "timeout": 30000});
            let (output, log) = executor_output_with_log(&exec, false, false, &environment);
            assert_eq!(output.status.code(), Some(0), "{output:?}");
            assert_eq!(output.stdout, expected);
            assert!(!log.contains("NVX sandbox started:"), "exec restarted the VM: {log}");
            assert_template_captures(&String::from_utf8_lossy(&output.stderr), 0);
            assert_eq!(assert_clone_binding(&root, &container.id, &template), binding);
        }
        for phase in ["stop", "deprovision"] {
            let output = executor_output_with_env(
                &lifecycle_phase(&container.id, phase),
                false,
                false,
                &environment,
            );
            assert!(output.status.success(), "{output:?}");
            assert!(!lifecycle_sandbox_directory(&root, &container.id)
                .join("clone.json")
                .exists());
        }
        assert!(!lifecycle_sandbox_directory(&root, &container.id).exists());
        container.cleaned = true;
        println!(
            "VM_EXECUTED executor lifecycle provision/dry-run clone start cross-process exec and cleanup"
        );
    }

    struct LifecycleOwner {
        child: std::process::Child,
        local_app_data: PathBuf,
        cleaned: bool,
    }

    impl Drop for LifecycleOwner {
        fn drop(&mut self) {
            if !matches!(self.child.try_wait(), Ok(Some(_))) {
                if let Err(error) = self.child.kill() {
                    eprintln!("lifecycle owner cleanup failed: {error}");
                }
                if let Err(error) = self.child.wait() {
                    eprintln!("lifecycle owner wait failed: {error}");
                }
            }
            if !self.cleaned {
                if let Ok(id) = std::fs::read_to_string(self.local_app_data.join("lifecycle-id")) {
                    let _container = LifecycleContainer {
                        id,
                        local_app_data: Some(self.local_app_data.clone()),
                        cleaned: false,
                    };
                }
            }
        }
    }

    #[test]
    #[ignore = "VM: requires separately built wxc-exec.exe, WHP and exact signed official bundle"]
    fn signed_bundle_sdk_json_lifecycle() {
        const CHILD: &str = "MXC_NVX_LIFECYCLE_OWNER_CHILD";
        match std::env::var(CHILD).ok().as_deref() {
            Some("cleanup") => {
                exercise_sdk_lifecycle(false, false);
                return;
            }
            Some("owner") => {
                exercise_sdk_lifecycle(false, true);
                return;
            }
            Some(mode) => panic!("unknown lifecycle helper mode: {mode}"),
            None => {}
        }
        let cleanup = tempfile::tempdir().expect("isolated SDK cleanup LOCALAPPDATA");
        let output = Command::new(std::env::current_exe().expect("test executable"))
            .args([
                "--exact",
                "windows_x64::signed_bundle_sdk_json_lifecycle",
                "--ignored",
                "--nocapture",
            ])
            .env(CHILD, "cleanup")
            .env("LOCALAPPDATA", cleanup.path())
            .stdin(Stdio::null())
            .output()
            .expect("same-process lifecycle cleanup helper");
        assert_helper_success(&output);
        assert_template_captures(&String::from_utf8_lossy(&output.stderr), 1);
        let marker =
            "VM_EXECUTED SDK JSON lifecycle same-process clone cleanup lease release and reuse";
        assert!(String::from_utf8_lossy(&output.stdout).contains(marker));
        println!("{marker}");
        let cli = tempfile::tempdir().expect("isolated CLI lifecycle LOCALAPPDATA");
        exercise_executor_lifecycle(cli.path());
        let local_app_data = tempfile::tempdir().expect("isolated lifecycle owner LOCALAPPDATA");
        let stdout_path = local_app_data.path().join("owner.stdout");
        let stderr_path = local_app_data.path().join("owner.stderr");
        let mut owner = LifecycleOwner {
            child: Command::new(std::env::current_exe().expect("test executable"))
                .args([
                    "--exact",
                    "windows_x64::signed_bundle_sdk_json_lifecycle",
                    "--ignored",
                    "--nocapture",
                ])
                .env(CHILD, "owner")
                .env("LOCALAPPDATA", local_app_data.path())
                .stdin(Stdio::null())
                .stdout(std::fs::File::create(&stdout_path).unwrap())
                .stderr(std::fs::File::create(&stderr_path).unwrap())
                .spawn()
                .expect("lifecycle owner helper"),
            local_app_data: local_app_data.path().to_owned(),
            cleaned: false,
        };
        let ready = local_app_data.path().join("lifecycle-ready.json");
        let deadline = Instant::now() + Duration::from_secs(180);
        while !ready.exists() {
            assert!(
                owner.child.try_wait().unwrap().is_none(),
                "lifecycle owner exited before ready\n{}\n{}",
                std::fs::read_to_string(&stdout_path).unwrap(),
                std::fs::read_to_string(&stderr_path).unwrap()
            );
            assert!(
                Instant::now() < deadline,
                "lifecycle owner never became ready"
            );
            std::thread::sleep(Duration::from_millis(20));
        }
        let ready: Value = serde_json::from_slice(&std::fs::read(ready).unwrap()).unwrap();
        let id = ready["sandboxId"].as_str().unwrap();
        let marker = ready["marker"].as_str().unwrap();
        let root = local_app_data.path().join(r"Microsoft\MXC\nvx");
        let template = clone_template(
            &std::fs::read_to_string(local_app_data.path().join("sdk-lifecycle.log")).unwrap(),
            "noNic",
        );
        let binding = assert_clone_binding(&root, id, &template);
        let environment = [("LOCALAPPDATA", local_app_data.path().as_os_str())];
        let mut exec = lifecycle_phase(id, "exec");
        exec["process"] =
            json!({"commandLine": "printf forbidden-live-adoption", "timeout": 30000});
        assert!(owner.child.try_wait().unwrap().is_none());
        let output = executor_output_with_env(&exec, false, false, &environment);
        assert!(
            !output.status.success(),
            "a live clone controller was replaced: {output:?}"
        );
        assert!(!String::from_utf8_lossy(&output.stdout).contains("forbidden-live-adoption"));
        assert!(
            owner.child.try_wait().unwrap().is_none(),
            "owner exited during rejection"
        );
        assert_eq!(assert_clone_binding(&root, id, &template), binding);
        std::fs::write(local_app_data.path().join("lifecycle-release"), b"release").unwrap();
        let deadline = Instant::now() + Duration::from_secs(180);
        let status = loop {
            if let Some(status) = owner.child.try_wait().unwrap() {
                break status;
            }
            assert!(Instant::now() < deadline, "lifecycle owner did not exit");
            std::thread::sleep(Duration::from_millis(20));
        };
        assert!(
            status.success(),
            "lifecycle owner failed\n{}\n{}",
            std::fs::read_to_string(&stdout_path).unwrap(),
            std::fs::read_to_string(&stderr_path).unwrap()
        );
        assert_template_captures(&std::fs::read_to_string(&stderr_path).unwrap(), 1);
        exec["process"] = json!({
            "commandLine": format!("test \"$(cat /tmp/{marker})\" = '{marker}' && printf adopted-after-exit"),
            "timeout": 30000
        });
        let output = executor_output_with_env(&exec, false, false, &environment);
        assert_eq!(output.status.code(), Some(0), "{output:?}");
        assert_eq!(output.stdout, b"adopted-after-exit");
        assert_eq!(assert_clone_binding(&root, id, &template), binding);
        for phase in ["stop", "deprovision"] {
            let output =
                executor_output_with_env(&lifecycle_phase(id, phase), false, false, &environment);
            assert!(output.status.success(), "{output:?}");
            assert!(!lifecycle_sandbox_directory(&root, id)
                .join("clone.json")
                .exists());
        }
        assert!(!lifecycle_sandbox_directory(&root, id).exists());
        owner.cleaned = true;
        println!(
            "VM_EXECUTED SDK JSON lifecycle clone start state reuse live-owner rejection and adoption"
        );
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
        assert!(!stdout.lines().any(|line| line == "forbidden"), "{stdout}");

        let mut invalid_proxy = valid.clone();
        invalid_proxy["runtimeConfig"] = json!({"networkProxy": "http://[::1]:3128"});
        let output = executor_output_with_mode(&invalid_proxy, false, true);
        assert!(!output.status.success(), "{output:?}");
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(stderr.contains("policy_validation"), "{stderr}");
        assert!(stderr.contains("OpenVMM reaches host loopback"), "{stderr}");
        assert!(
            !String::from_utf8_lossy(&output.stdout)
                .lines()
                .any(|line| line == "forbidden"),
            "{output:?}"
        );

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

    /// How a test asks a running executor to cancel its request.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    enum Interruption {
        /// A real Ctrl-C delivered to the executor's console.
        ConsoleControl,
        /// Closing the stdin pipe of an executor run with `--cancel-on-stdin-close`.
        StdinClose,
    }

    #[test]
    #[ignore = "VM: requires separately built wxc-exec.exe, WHP and exact signed official bundle"]
    fn signed_bundle_executor_console_interrupt() {
        use std::os::windows::process::CommandExt;
        use windows::Win32::System::Console::{SetConsoleCtrlHandler, CTRL_C_EVENT};
        use windows::Win32::System::Threading::CREATE_NEW_CONSOLE;

        const CHILD_ENV: &str = "MXC_NVX_CONSOLE_CHILD";
        if std::env::var_os(CHILD_ENV).is_none() {
            for phase in ["capture", "startup", "execution"] {
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
                "VM_EXECUTED executor console interruption capture/startup/execution/owned-vmm/cleanup"
            );
            return;
        }

        unsafe extern "system" fn helper_handler(event: u32) -> windows::core::BOOL {
            windows::core::BOOL(i32::from(event == CTRL_C_EVENT))
        }
        // An inherited ignore-Ctrl-C flag also propagates to the executor.
        unsafe { SetConsoleCtrlHandler(None, false) }.expect("enable child Ctrl-C delivery");
        unsafe { SetConsoleCtrlHandler(Some(helper_handler), true) }
            .expect("helper control handler");
        let phase = std::env::var(CHILD_ENV).expect("interruption phase");
        interrupt_executor(&phase, Interruption::ConsoleControl);
        unsafe { SetConsoleCtrlHandler(Some(helper_handler), false) }
            .expect("remove helper handler");
    }

    #[test]
    #[ignore = "VM: requires separately built wxc-exec.exe, WHP and exact signed official bundle"]
    fn signed_bundle_executor_stdin_close_cancels() {
        for phase in ["startup", "execution"] {
            interrupt_executor(phase, Interruption::StdinClose);
        }
        println!(
            "VM_EXECUTED executor stdin-close cancellation startup/execution/owned-vmm/cleanup"
        );
    }

    /// Reads a held container's events and finds the ones a test waits for.
    struct HeldEvents {
        events: std::sync::mpsc::Receiver<Value>,
        seen: Vec<Value>,
    }

    impl HeldEvents {
        fn wait_for(&mut self, found: impl Fn(&Value) -> bool) -> Value {
            let deadline = Instant::now() + std::time::Duration::from_secs(180);
            loop {
                if let Some(event) = self.seen.iter().find(|event| found(event)) {
                    return event.clone();
                }
                let remaining = deadline.saturating_duration_since(Instant::now());
                match self.events.recv_timeout(remaining) {
                    Ok(event) => self.seen.push(event),
                    Err(_) => panic!("the event never arrived; events: {:?}", self.seen),
                }
            }
        }

        fn ended(&mut self, id: &str) -> Value {
            self.wait_for(|event| {
                event["id"] == id
                    && matches!(event["type"].as_str(), Some("exit" | "timeout" | "error"))
            })
        }

        fn output(&self, id: &str, stream: &str) -> String {
            use base64::Engine as _;
            let bytes: Vec<u8> = self
                .seen
                .iter()
                .filter(|event| event["id"] == id && event["type"] == stream)
                .flat_map(|event| {
                    base64::engine::general_purpose::STANDARD
                        .decode(event["data"].as_str().expect("output data"))
                        .expect("base64 output")
                })
                .collect();
            String::from_utf8(bytes).expect("UTF-8 output")
        }
    }

    /// Holds a container with `--hold`, runs execs side by side in it, cancels one, and closes
    /// stdin, then checks that the executor stopped the container's VM and exited with 0.
    #[test]
    #[ignore = "VM: requires separately built wxc-exec.exe, WHP and exact signed official bundle"]
    fn signed_bundle_executor_holds_a_container() {
        use std::io::{BufRead, BufReader, Write};
        use std::time::Duration;
        use windows::Win32::Foundation::WAIT_OBJECT_0;
        use windows::Win32::System::Threading::WaitForSingleObject;

        let directory = tempfile::tempdir().expect("held container directory");
        let request_path = directory.path().join("provision.json");
        let stderr_path = directory.path().join("stderr");
        let mut provision = process_only_request("unused");
        provision.as_object_mut().unwrap().remove("process");
        std::fs::write(&request_path, provision.to_string()).expect("provision request");
        let mut guard = ExecutorGuard {
            child: Command::new(executor())
                .args(["--experimental", "--operation", "provision", "--hold"])
                .arg(&request_path)
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(std::fs::File::create(&stderr_path).expect("stderr file"))
                .spawn()
                .expect("held-container executor"),
            vmm: None,
        };
        let stderr = || std::fs::read_to_string(&stderr_path).expect("executor stderr");
        let mut requests = guard.child.stdin.take().expect("executor stdin");
        let stdout = guard.child.stdout.take().expect("executor stdout");
        let (sender, events) = std::sync::mpsc::channel();
        let reader = std::thread::spawn(move || {
            let mut lines = Vec::new();
            for line in BufReader::new(stdout).lines() {
                let line = line.expect("event line");
                let _ = sender.send(serde_json::from_str::<Value>(&line).expect("event JSON"));
                lines.push(line);
            }
            lines.join("\n")
        });
        let mut held = HeldEvents {
            events,
            seen: Vec::new(),
        };
        let mut send = move |request: Value| {
            writeln!(requests, "{request}").expect("held-container request");
            requests.flush().expect("flushed request");
        };
        let exec = |id: &str, command: &str| {
            json!({
                "type": "exec",
                "id": id,
                "request": {
                    "version": "1.1.0-alpha",
                    "process": { "commandLine": command, "timeout": 0 }
                }
            })
        };

        let ready = held.wait_for(|event| event["type"] == "ready" || event["type"] == "error");
        assert_eq!(ready["type"], "ready", "{ready}\n{}", stderr());
        guard.vmm = owned_vmms(guard.child.id()).into_iter().next();
        assert!(guard.vmm.is_some(), "the held container has no VM");

        // The second exec runs while the first still runs, and leaves a file for later ones.
        send(exec("long", "sleep 600"));
        send(exec("write", "printf held > /tmp/held; printf written"));
        assert_eq!(held.ended("write")["exitCode"], 0);
        assert_eq!(held.output("write", "stdout"), "written");
        send(exec("read", "cat /tmp/held; printf failed >&2; exit 3"));
        assert_eq!(held.ended("read")["exitCode"], 3);
        assert_eq!(held.output("read", "stdout"), "held");
        assert_eq!(held.output("read", "stderr"), "failed");

        // Cancelling an exec ends that exec only.
        let cancelled = Instant::now();
        send(json!({ "type": "cancel", "id": "long" }));
        assert_eq!(held.ended("long")["exitCode"], 137);
        assert!(
            cancelled.elapsed() < Duration::from_secs(30),
            "cancellation took {:?}",
            cancelled.elapsed()
        );
        send(exec("after", "cat /tmp/held"));
        assert_eq!(held.ended("after")["exitCode"], 0);
        assert_eq!(held.output("after", "stdout"), "held");

        // Closing stdin cancels what still runs, then stops and deprovisions the container.
        send(exec("orphan", "sleep 600"));
        drop(send);
        let closed = Instant::now();
        let exit = loop {
            if let Some(exit) = guard.child.try_wait().expect("held executor status") {
                break exit;
            }
            assert!(
                closed.elapsed() < Duration::from_secs(120),
                "held-container teardown hung"
            );
            std::thread::sleep(Duration::from_millis(20));
        };
        assert_eq!(exit.code(), Some(0), "{}", stderr());
        assert_eq!(held.ended("orphan")["exitCode"], 137);
        assert_eq!(
            unsafe { WaitForSingleObject(guard.vmm.as_ref().expect("held VM").get(), 0) },
            WAIT_OBJECT_0,
            "the held container's OpenVMM is still running",
        );
        for vmm in owned_vmms(guard.child.id()) {
            assert_eq!(
                unsafe { WaitForSingleObject(vmm.get(), 0) },
                WAIT_OBJECT_0,
                "an OpenVMM that the executor started is still running",
            );
        }
        // The container ID never leaves the executor.
        let events = reader.join().expect("event reader");
        assert!(!events.contains("microvm:"), "{events}");
        assert!(!stderr().contains("microvm:"), "{}", stderr());
        println!("VM_EXECUTED executor held container side-by-side execs/state/cancel/teardown");
    }

    /// Kills an executor, and the VM it started, that a failed test left running.
    struct ExecutorGuard {
        child: std::process::Child,
        vmm: Option<mxc_sdk::mxc_common::process_util::OwnedHandle>,
    }
    impl Drop for ExecutorGuard {
        fn drop(&mut self) {
            use windows::Win32::Foundation::{WAIT_OBJECT_0, WAIT_TIMEOUT};
            use windows::Win32::System::Threading::{TerminateProcess, WaitForSingleObject};

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
                    } else if unsafe { WaitForSingleObject(vmm.get(), 30_000) } != WAIT_OBJECT_0 {
                        eprintln!("failed-test owned VMM cleanup did not complete");
                    }
                }
            }
        }
    }

    /// The OpenVMM processes that process `pid` started.
    fn owned_vmms(pid: u32) -> Vec<mxc_sdk::mxc_common::process_util::OwnedHandle> {
        use mxc_sdk::mxc_common::process_util::OwnedHandle;
        use windows::Win32::Foundation::ERROR_NO_MORE_FILES;
        use windows::Win32::System::Diagnostics::ToolHelp::{
            CreateToolhelp32Snapshot, Process32FirstW, Process32NextW, PROCESSENTRY32W,
            TH32CS_SNAPPROCESS,
        };
        use windows::Win32::System::Threading::{
            OpenProcess, PROCESS_SYNCHRONIZE, PROCESS_TERMINATE,
        };

        let snapshot = OwnedHandle::new(
            unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) }.expect("process snapshot"),
        );
        let mut entry = PROCESSENTRY32W {
            dwSize: std::mem::size_of::<PROCESSENTRY32W>() as u32,
            ..Default::default()
        };
        let mut vmms = Vec::new();
        let mut next = unsafe { Process32FirstW(snapshot.get(), &mut entry) };
        loop {
            match next {
                Ok(()) => {}
                Err(error) if error.code() == ERROR_NO_MORE_FILES.to_hresult() => return vmms,
                Err(error) => panic!("process enumeration failed: {error}"),
            }
            let end = entry
                .szExeFile
                .iter()
                .position(|&c| c == 0)
                .unwrap_or(entry.szExeFile.len());
            let name = String::from_utf16_lossy(&entry.szExeFile[..end]);
            if entry.th32ParentProcessID == pid && name.eq_ignore_ascii_case("openvmm.exe") {
                // A template capture's VM can exit before it is opened.
                if let Ok(handle) = unsafe {
                    OpenProcess(
                        PROCESS_SYNCHRONIZE | PROCESS_TERMINATE,
                        false,
                        entry.th32ProcessID,
                    )
                } {
                    vmms.push(OwnedHandle::new(handle));
                }
            }
            next = unsafe { Process32NextW(snapshot.get(), &mut entry) };
        }
    }

    /// Interrupts a `sleep 600` request during template capture, VM startup, or execution, then
    /// checks that the executor stops its OpenVMM processes, exits with 130, and leaves the agent
    /// state directory usable.
    fn interrupt_executor(phase: &str, interruption: Interruption) {
        use std::time::Duration;
        use windows::Win32::Foundation::WAIT_OBJECT_0;
        use windows::Win32::System::Console::{GenerateConsoleCtrlEvent, CTRL_C_EVENT};
        use windows::Win32::System::Threading::WaitForSingleObject;

        let directory = tempfile::tempdir().expect("interruption test directory");
        let state = directory.path().join("state");
        std::fs::create_dir(&state).expect("isolated state directory");
        if phase != "capture" {
            // Capture the platform snapshot templates and register the image first, so the first
            // VM of the interrupted request is its own sandbox rather than a template capture.
            let warm = executor_output_with_env(
                &process_only_request("printf warm"),
                false,
                false,
                &[("LOCALAPPDATA", state.as_os_str())],
            );
            assert_eq!(
                warm.status.code(),
                Some(0),
                "{}",
                String::from_utf8_lossy(&warm.stderr)
            );
        }
        let request_path = directory.path().join("request.json");
        let log_path = directory.path().join("executor.log");
        let stdout_path = directory.path().join("stdout");
        let stderr_path = directory.path().join("stderr");
        let mut request = process_only_request("sleep 600");
        request["process"]["timeout"] = json!(0);
        std::fs::write(&request_path, request.to_string()).expect("interruption request");
        let mut command = Command::new(executor());
        command
            .args(["--experimental", "--log-file"])
            .arg(&log_path);
        if interruption == Interruption::StdinClose {
            command.arg("--cancel-on-stdin-close");
        }
        let mut guard = ExecutorGuard {
            child: command
                .arg(&request_path)
                .env("TEMP", &state)
                .env("TMP", &state)
                .env("LOCALAPPDATA", &state)
                .stdin(match interruption {
                    Interruption::ConsoleControl => Stdio::null(),
                    Interruption::StdinClose => Stdio::piped(),
                })
                .stdout(std::fs::File::create(&stdout_path).expect("stdout file"))
                .stderr(std::fs::File::create(&stderr_path).expect("stderr file"))
                .spawn()
                .expect("interruptible executor"),
            vmm: None,
        };
        let ready_deadline = Instant::now() + Duration::from_secs(180);
        loop {
            assert!(
                guard.child.try_wait().expect("executor status").is_none(),
                "executor exited before interruption: {}",
                std::fs::read_to_string(&stderr_path).expect("executor stderr")
            );
            if guard.vmm.is_none() {
                guard.vmm = owned_vmms(guard.child.id()).into_iter().next();
            }
            let log = match std::fs::read_to_string(&log_path) {
                Ok(log) => log,
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => String::new(),
                Err(error) => panic!("executor log read failed: {error}"),
            };
            // The request logs its sandbox's identity before starting it, so a VM that runs
            // before then captures a template.
            let provisioned = log.contains("mxc.SandboxIdentity");
            let executing = log.contains("NVX execution started");
            if guard.vmm.is_some() && (phase != "execution" || executing) {
                assert!(
                    match phase {
                        "capture" => !provisioned,
                        "startup" => !executing,
                        _ => true,
                    },
                    "missed the {phase} interruption window"
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
        match interruption {
            Interruption::ConsoleControl => {
                unsafe { GenerateConsoleCtrlEvent(CTRL_C_EVENT, 0) }.expect("real Ctrl-C delivery")
            }
            Interruption::StdinClose => drop(guard.child.stdin.take().expect("executor stdin")),
        }
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
            "{interruption:?} during {phase} must exit through coordinated cancellation"
        );
        assert_eq!(
            unsafe { WaitForSingleObject(guard.vmm.as_ref().expect("owned VM").get(), 0) },
            WAIT_OBJECT_0,
            "owned OpenVMM is still running",
        );
        for vmm in owned_vmms(guard.child.id()) {
            assert_eq!(
                unsafe { WaitForSingleObject(vmm.get(), 0) },
                WAIT_OBJECT_0,
                "an OpenVMM that the executor started is still running",
            );
        }
        // The cancelled request must leave the shared agent state directory usable.
        let after = executor_output_with_env(
            &process_only_request("printf after-interrupt"),
            false,
            false,
            &[("LOCALAPPDATA", state.as_os_str())],
        );
        assert_eq!(
            after.status.code(),
            Some(0),
            "{}",
            String::from_utf8_lossy(&after.stderr)
        );
        assert_eq!(after.stdout, b"after-interrupt");
        assert!(std::fs::read(&stdout_path)
            .expect("stdout bytes")
            .is_empty());
        let stderr = std::fs::read_to_string(&stderr_path).expect("cancellation stderr");
        assert!(stderr.contains("execution cancelled"), "{stderr}");
        assert!(!stderr.contains("timed out"), "{stderr}");
        let log = std::fs::read_to_string(&log_path).expect("teardown log");
        if phase == "capture" {
            // Cancellation during the capture ends the request before it provisions a sandbox.
            assert!(!log.contains("mxc.SandboxIdentity"), "{log}");
        } else {
            assert!(log.contains("mxc.SandboxTornDown"), "{log}");
        }
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

    #[test]
    #[ignore = "VM: requires separately built wxc-exec.exe, WHP and exact signed official bundle"]
    fn signed_bundle_executor_reuses_registered_images() {
        use std::ffi::OsStr;

        // An isolated LOCALAPPDATA starts the executor with an empty agent state directory, and
        // a proxy that refuses every connection makes any registry pull fail.
        let local_app_data = tempfile::tempdir().expect("isolated LOCALAPPDATA");
        let state = [("LOCALAPPDATA", local_app_data.path().as_os_str())];
        let offline = [
            state[0],
            ("HTTPS_PROXY", OsStr::new("http://127.0.0.1:9")),
            ("HTTP_PROXY", OsStr::new("http://127.0.0.1:9")),
        ];
        let marker = nonce();
        let request = process_only_request("printf registered");
        let image = request["microvm"]["image"]
            .as_str()
            .expect("image reference");
        let run_concurrently = |environment: &[(&str, &OsStr)]| {
            let outputs: Vec<(Output, String)> = std::thread::scope(|scope| {
                let runs: Vec<_> = (0..3)
                    .map(|index| {
                        let request = process_only_request(&format!(
                            "test ! -e /tmp/{marker} || exit 99; touch /tmp/{marker}; \
                             printf registered-{index}"
                        ));
                        scope.spawn(move || {
                            executor_output_with_log(&request, false, false, environment)
                        })
                    })
                    .collect();
                runs.into_iter()
                    .map(|run| run.join().expect("concurrent executor"))
                    .collect()
            });
            let mut identities = BTreeSet::new();
            let mut templates = Vec::new();
            let mut diagnostics = String::new();
            for (index, (output, log)) in outputs.into_iter().enumerate() {
                assert_eq!(
                    output.status.code(),
                    Some(0),
                    "{}",
                    String::from_utf8_lossy(&output.stderr)
                );
                assert_eq!(output.stdout, format!("registered-{index}").as_bytes());
                assert!(identities.insert(sandbox_identity(&log)), "{log}");
                templates.push(clone_template(&log, "noNic"));
                diagnostics.push_str(&String::from_utf8_lossy(&output.stderr));
            }
            assert!(templates.iter().all(|template| template == &templates[0]));
            assert_no_sandbox_state(&agent_state_directory(local_app_data.path()));
            (templates.remove(0), diagnostics)
        };

        // Keep the failed pull control out of the empty store used by the first-capture race.
        let unregistered = tempfile::tempdir().expect("unregistered image control");
        let output = executor_output_with_env(
            &request,
            false,
            false,
            &[
                ("LOCALAPPDATA", unregistered.path().as_os_str()),
                offline[1],
                offline[2],
            ],
        );
        assert_ne!(
            output.status.code(),
            Some(0),
            "an unregistered image needs its registry"
        );
        assert!(
            String::from_utf8_lossy(&output.stderr).contains(image),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );

        // Concurrent first requests race to register the image, and each must boot it.
        let (first, captures) = run_concurrently(&state);
        assert_template_captures(&captures, 1);
        // Later concurrent requests boot the registered image without the registry.
        let (later, captures) = run_concurrently(&offline);
        assert_template_captures(&captures, 0);
        assert_eq!(first, later, "registered-image reuse recaptured a template");
        println!(
            "VM_EXECUTED executor registered-image reuse offline concurrent first-capture clone isolation"
        );
    }

    #[test]
    #[ignore = "VM: requires separately built wxc-exec.exe, WHP and exact signed official bundle"]
    fn signed_bundle_executor_starts_sandboxes_from_platform_snapshots() {
        const CHILD: &str = "MXC_NVX_PLATFORM_SNAPSHOTS_CHILD";
        const TEST: &str =
            "windows_x64::signed_bundle_executor_starts_sandboxes_from_platform_snapshots";
        if let Some(mode) = std::env::var_os(CHILD) {
            let fallback = mode == "fallback";
            exercise_sdk_snapshot_requests(fallback);
            if fallback {
                exercise_sdk_lifecycle(true, false);
                let local_app_data = PathBuf::from(std::env::var_os("LOCALAPPDATA").unwrap());
                for root in [
                    agent_state_directory(&local_app_data),
                    local_app_data.join(r"Microsoft\MXC\nvx"),
                ] {
                    std::fs::remove_file(root.join("templates")).expect("unblock template store");
                }
                // A failed capture is not remembered after the store becomes usable.
                let output =
                    sdk_json_output(&snapshot_request(&nonce(), "recovered", false), false);
                assert_eq!(output.outcome, WaitResult::Exited(42));
                assert_snapshot_output(&output.stdout, "recovered", true);
                assert!(!output
                    .warnings
                    .iter()
                    .any(|warning| warning.contains(SNAPSHOT_WARNING)));
            }
            return;
        }

        let local_app_data = tempfile::tempdir().expect("isolated LOCALAPPDATA");
        let environment = [("LOCALAPPDATA", local_app_data.path().as_os_str())];
        let marker = nonce();
        let mut templates = BTreeMap::new();
        let mut identities = BTreeSet::new();
        for (index, nic) in [false, true, false, true].into_iter().enumerate() {
            let label = format!("cli-{index}");
            let (output, log) = executor_output_with_log(
                &snapshot_request(&marker, &label, nic),
                false,
                false,
                &environment,
            );
            assert_eq!(
                output.status.code(),
                Some(42),
                "{}",
                String::from_utf8_lossy(&output.stderr)
            );
            assert_snapshot_output(&output.stdout, &label, true);
            assert!(String::from_utf8_lossy(&output.stderr).contains("snapshot-stderr"));
            assert_template_captures(
                &String::from_utf8_lossy(&output.stderr),
                usize::from(index == 0),
            );
            let class = if nic { "nic" } else { "noNic" };
            let template = clone_template(&log, class);
            if let Some(previous) = templates.insert(class, template.clone()) {
                assert_eq!(previous, template, "fresh executor recaptured {class}");
            }
            assert!(identities.insert(sandbox_identity(&log)), "{log}");
            assert_no_sandbox_state(&agent_state_directory(local_app_data.path()));
        }
        println!(
            "VM_EXECUTED executor platform snapshot NIC/noNIC clones stable templates and isolated VMs"
        );

        let sdk = tempfile::tempdir().expect("isolated SDK LOCALAPPDATA");
        let output = Command::new(std::env::current_exe().expect("test executable"))
            .args(["--exact", TEST, "--ignored", "--nocapture"])
            .env(CHILD, "sdk")
            .env("LOCALAPPDATA", sdk.path())
            .stdin(Stdio::null())
            .output()
            .expect("SDK snapshot helper");
        assert_helper_success(&output);
        assert_template_captures(&String::from_utf8_lossy(&output.stderr), 1);
        println!(
            "VM_EXECUTED SDK JSON platform snapshot repeated capture/streaming clones and isolation"
        );

        let blocked = tempfile::tempdir().expect("isolated LOCALAPPDATA");
        let state = [("LOCALAPPDATA", blocked.path().as_os_str())];
        let valid = process_only_request("printf forbidden");
        let mut native_rejected = valid.clone();
        native_rejected["runtimeConfig"] = json!({"networkProxy": "http://[::1]:3128"});
        let mut malformed = valid.clone();
        malformed["microvm"]["provision"] = json!({"memoryMib": 0});
        for (request, succeeds) in [
            (&valid, true),
            (&native_rejected, false),
            (&malformed, false),
        ] {
            let (output, log) = executor_output_with_log(request, false, true, &state);
            assert_eq!(output.status.success(), succeeds, "{output:?}");
            assert!(
                !String::from_utf8_lossy(&output.stdout)
                    .lines()
                    .any(|line| line == "forbidden"),
                "{output:?}"
            );
            assert!(!log.contains("NVX sandbox started:"), "{log}");
            assert_template_captures(&String::from_utf8_lossy(&output.stderr), 0);
            assert_no_sandbox_state(&agent_state_directory(blocked.path()));
        }
        let templates = agent_state_directory(blocked.path()).join("templates");
        assert!(!templates.exists());
        std::fs::write(&templates, b"not a template store").expect("block the template store");
        std::fs::write(
            blocked.path().join(r"Microsoft\MXC\nvx\templates"),
            b"not a lifecycle template store",
        )
        .expect("block the lifecycle template store");
        let (output, log) =
            executor_output_with_log(&process_only_request("printf cold"), false, false, &state);
        assert_eq!(output.status.code(), Some(0), "{output:?}");
        assert_eq!(output.stdout, b"cold");
        assert!(log.contains(SNAPSHOT_WARNING), "{log}");
        assert_cold_start(&log);
        let output = Command::new(std::env::current_exe().expect("test executable"))
            .args(["--exact", TEST, "--ignored", "--nocapture"])
            .env(CHILD, "fallback")
            .env("LOCALAPPDATA", blocked.path())
            .stdin(Stdio::null())
            .output()
            .expect("SDK fallback helper");
        assert_helper_success(&output);
        assert_template_captures(&String::from_utf8_lossy(&output.stderr), 1);
        println!(
            "VM_EXECUTED SDK JSON platform snapshot cold fallback capture/streaming warnings lifecycle diagnostics and recovery"
        );
    }

    const SNAPSHOT_WARNING: &str = "NVX platform snapshots are unavailable";
    const PLATFORM_TEMPLATE_PARAMETER: &str = "nvx_snapshot_tier=platform";

    pub(super) fn clone_policy_output(request: &Value, executor: bool) -> Vec<u8> {
        let mut request = request.clone();
        request["process"]["commandLine"] = json!(format!(
            "grep -qw '{PLATFORM_TEMPLATE_PARAMETER}' /proc/cmdline || exit 94; {}",
            request["process"]["commandLine"]
                .as_str()
                .expect("policy workload command")
        ));
        if executor {
            let (output, log) = executor_output_with_log(&request, false, false, &[]);
            assert_eq!(output.status.code(), Some(0), "{output:?}");
            let metadata = start_metadata(&log);
            assert_eq!(metadata["bootMode"], "clone", "{metadata}");
            assert!(metadata["template"].is_object(), "{metadata}");
            assert!(!log.contains(SNAPSHOT_WARNING), "{log}");
            assert!(
                !String::from_utf8_lossy(&output.stderr).contains(SNAPSHOT_WARNING),
                "{output:?}"
            );
            output.stdout
        } else {
            let output = __ffi::run_json(&request.to_string(), true).unwrap();
            assert_eq!(output.outcome, WaitResult::Exited(0), "{output:?}");
            assert!(!output
                .warnings
                .iter()
                .any(|warning| warning.contains(SNAPSHOT_WARNING)));
            assert_no_run_state(std::process::id());
            output.stdout
        }
    }

    #[test]
    #[ignore = "VM: requires separately built wxc-exec.exe, WHP and exact signed official bundle"]
    fn signed_bundle_snapshot_memory_capacity() {
        let local_app_data = tempfile::tempdir().expect("isolated memory LOCALAPPDATA");
        let environment = [("LOCALAPPDATA", local_app_data.path().as_os_str())];
        for lifecycle in [false, true] {
            let mut observed = Vec::new();
            for memory_mib in [256_u64, 512] {
                let label = format!("memory-{memory_mib}");
                let command = format!(
                    "printf '{label}\\n'; cat /proc/cpuinfo; \
                     printf 'NVX_KERNEL_CMDLINE='; cat /proc/cmdline; \
                     cat /proc/meminfo"
                );
                let (output, log) = if lifecycle {
                    let mut provision = lifecycle_provision();
                    provision["microvm"]["provision"] = json!({"memoryMib": memory_mib});
                    let (output, _) =
                        executor_output_with_log(&provision, false, false, &environment);
                    assert!(output.status.success(), "{output:?}");
                    let provisioned: Value = serde_json::from_slice(&output.stdout).unwrap();
                    let mut container = LifecycleContainer {
                        id: provisioned["result"]["sandboxId"]
                            .as_str()
                            .unwrap()
                            .to_owned(),
                        local_app_data: Some(local_app_data.path().to_owned()),
                        cleaned: false,
                    };
                    let (started, log) = executor_output_with_log(
                        &lifecycle_phase(&container.id, "start"),
                        false,
                        false,
                        &environment,
                    );
                    assert!(started.status.success(), "{started:?}");
                    assert!(
                        !String::from_utf8_lossy(&started.stderr).contains(SNAPSHOT_WARNING),
                        "{started:?}"
                    );
                    let mut exec = lifecycle_phase(&container.id, "exec");
                    exec["process"] = json!({"commandLine": command, "timeout": 30000});
                    let (output, _) = executor_output_with_log(&exec, false, false, &environment);
                    for phase in ["stop", "deprovision"] {
                        let cleanup = executor_output_with_env(
                            &lifecycle_phase(&container.id, phase),
                            false,
                            false,
                            &environment,
                        );
                        assert!(cleanup.status.success(), "{cleanup:?}");
                    }
                    let root = local_app_data.path().join(r"Microsoft\MXC\nvx");
                    assert!(!lifecycle_sandbox_directory(&root, &container.id).exists());
                    container.cleaned = true;
                    (output, log)
                } else {
                    let mut request = process_only_request(&command);
                    request["microvm"]["provision"] = json!({"memoryMib": memory_mib});
                    executor_output_with_log(&request, false, false, &environment)
                };
                assert_eq!(output.status.code(), Some(0), "{output:?}");
                let cloned = memory_mib == 256;
                let metadata = start_metadata(&log);
                if cloned {
                    assert_eq!(metadata["bootMode"], "clone", "{metadata}");
                    assert!(metadata["template"].is_object(), "{metadata}");
                } else {
                    assert_cold_start(&log);
                    assert_eq!(
                        metadata["coldReason"], "memory-above-capacity",
                        "{metadata}"
                    );
                }
                assert!(!log.contains(SNAPSHOT_WARNING), "{log}");
                assert!(
                    !String::from_utf8_lossy(&output.stderr).contains(SNAPSHOT_WARNING),
                    "{output:?}"
                );
                assert_snapshot_output(&output.stdout, &label, cloned);
                let stdout = String::from_utf8_lossy(&output.stdout);
                let memory: Vec<u64> = stdout
                    .lines()
                    .filter_map(|line| line.strip_prefix("MemTotal:"))
                    .map(|value| {
                        let mut fields = value.split_whitespace();
                        let memory = fields
                            .next()
                            .expect("guest MemTotal value")
                            .parse()
                            .expect("guest MemTotal KiB");
                        assert_eq!(fields.next(), Some("kB"), "{value}");
                        assert!(fields.next().is_none(), "{value}");
                        memory
                    })
                    .collect();
                assert_eq!(memory.len(), 1, "{stdout}");
                assert!(memory[0] > 0 && memory[0] <= memory_mib * 1024, "{stdout}");
                observed.push(memory[0]);
            }
            // MemTotal excludes kernel reservations; compare the increase, not exact RAM.
            let increase = observed[1]
                .checked_sub(observed[0])
                .expect("larger guest RAM");
            assert!(increase.abs_diff(256 * 1024) <= 16 * 1024, "{observed:?}");
        }
        println!(
            "VM_EXECUTED snapshot memory explicit 256 clone and 512 resource cold boot guest sizing both modes"
        );
    }

    fn assert_helper_success(output: &Output) {
        assert!(
            output.status.success(),
            "helper failed\nstdout: {}\nstderr: {}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        for bytes in [&output.stdout, &output.stderr] {
            assert!(
                !String::from_utf8_lossy(bytes).contains("synthetic"),
                "helper leaked credentials"
            );
        }
    }

    fn assert_template_captures(stderr: &str, per_class: usize) {
        let captures: Vec<_> = stderr
            .lines()
            .filter(|line| line.contains("captured generation "))
            .collect();
        assert_eq!(captures.len(), per_class * 2, "{stderr}");
        for class in ["noNic", "nic"] {
            assert_eq!(
                captures
                    .iter()
                    .filter(|line| line.contains(&format!("of the {class} template")))
                    .count(),
                per_class,
                "{stderr}"
            );
        }
    }

    fn start_metadata(log: &str) -> Value {
        let starts: Vec<Value> = log
            .lines()
            .filter_map(|line| line.split_once("NVX sandbox started: "))
            .map(|(_, metadata)| {
                serde_json::from_str(metadata).expect("native StartResult metadata")
            })
            .collect();
        assert_eq!(starts.len(), 1, "{log}");
        let metadata = starts.into_iter().next().unwrap();
        assert!(metadata["bootMilliseconds"].is_number(), "{metadata}");
        metadata
    }

    fn clone_template(log: &str, class: &str) -> Value {
        let metadata = start_metadata(log);
        assert_eq!(metadata["bootMode"], "clone", "{metadata}");
        let template = &metadata["template"];
        assert_eq!(template["class"], class, "{metadata}");
        let key = template["key"].as_str().expect("template key");
        assert!(
            key.len() == 64
                && key
                    .bytes()
                    .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f')),
            "{metadata}"
        );
        assert!(
            template["generation"]
                .as_u64()
                .expect("template generation")
                > 0,
            "{metadata}"
        );
        json!({"key": template["key"], "generation": template["generation"]})
    }

    fn assert_cold_start(log: &str) {
        let metadata = start_metadata(log);
        assert_eq!(metadata["bootMode"], "cold", "{metadata}");
        assert!(metadata["template"].is_null(), "{metadata}");
    }

    fn lifecycle_sandbox_directory(root: &Path, id: &str) -> PathBuf {
        root.join(id.strip_prefix("microvm:").expect("MicroVM lifecycle ID"))
    }

    fn assert_clone_binding(root: &Path, id: &str, template: &Value) -> Value {
        let sandbox = lifecycle_sandbox_directory(root, id);
        let binding: Value = serde_json::from_slice(
            &std::fs::read(sandbox.join("clone.json")).expect("native clone lease binding"),
        )
        .expect("native clone lease JSON");
        assert_eq!(binding["key"], template["key"], "{binding}");
        assert_eq!(binding["generation"], template["generation"], "{binding}");
        assert!(
            !binding["lease"]
                .as_str()
                .expect("native lease ID")
                .is_empty(),
            "{binding}"
        );
        assert!(
            !binding["launch"]
                .as_str()
                .expect("native launch ID")
                .is_empty(),
            "{binding}"
        );
        assert_eq!(
            Path::new(binding["sandbox"].as_str().expect("native sandbox path"))
                .canonicalize()
                .unwrap(),
            sandbox.canonicalize().unwrap()
        );
        assert!(
            sandbox.join("runtime.json").is_file(),
            "clone has no running VM record"
        );
        assert!(
            sandbox.join("clone-holder.lock").is_file(),
            "clone has no controller record"
        );
        binding
    }

    fn sandbox_identity(log: &str) -> String {
        let identities: Vec<String> = log
            .lines()
            .filter_map(|line| line.find('{').map(|index| &line[index..]))
            .filter_map(|line| serde_json::from_str::<Value>(line).ok())
            .filter(|event| event["event"] == "mxc.SandboxIdentity")
            .map(|event| {
                event["identity"]
                    .as_str()
                    .expect("sandbox identity")
                    .to_owned()
            })
            .collect();
        assert_eq!(identities.len(), 1, "{log}");
        identities.into_iter().next().unwrap()
    }

    fn snapshot_request(marker: &str, label: &str, nic: bool) -> Value {
        let nic_test = if nic { "-e" } else { "! -e" };
        let mut request = process_only_request(&format!(
            "test ! -e /tmp/{marker} || exit 99; \
             test {nic_test} /sys/class/net/eth0 || exit 98; \
             touch /tmp/{marker}; printf '{label}\\n'; cat /proc/cpuinfo; \
             printf 'NVX_KERNEL_CMDLINE='; cat /proc/cmdline; \
             printf snapshot-stderr >&2; exit 42"
        ));
        if nic {
            request["network"] = json!({"egress": {"default": "allow"}});
        }
        request
    }

    fn assert_snapshot_output(stdout: &[u8], label: &str, cloned: bool) {
        assert!(
            stdout.starts_with(format!("{label}\n").as_bytes()),
            "{stdout:?}"
        );
        assert_host_cpu_profile(stdout);
        let output = String::from_utf8_lossy(stdout);
        let command_lines: Vec<_> = output
            .lines()
            .filter_map(|line| line.strip_prefix("NVX_KERNEL_CMDLINE="))
            .collect();
        assert_eq!(command_lines.len(), 1, "{output}");
        assert_eq!(
            command_lines[0]
                .split_whitespace()
                .any(|parameter| parameter == PLATFORM_TEMPLATE_PARAMETER),
            cloned,
            "unexpected guest boot mode: {output}"
        );
    }

    fn sdk_json_output(request: &Value, streaming: bool) -> ExecutionResult {
        let options = dev::JsonOptions { experimental: true };
        let output = if streaming {
            let process = dev::spawn_json(&request.to_string(), options).unwrap();
            let warnings = process.warnings();
            let output = process.wait_with_output().unwrap();
            assert!(warnings
                .iter()
                .all(|warning| output.warnings.contains(warning)));
            assert!(
                output
                    .warnings
                    .iter()
                    .filter(|warning| warning.contains(SNAPSHOT_WARNING))
                    .all(|warning| warnings.contains(warning)),
                "spawn lost its fallback warning"
            );
            output
        } else {
            dev::run_json(&request.to_string(), options).unwrap()
        };
        assert_no_run_state(std::process::id());
        output
    }

    fn assert_snapshot_warning(warnings: &[String], sensitive: bool) {
        assert!(
            !warnings.iter().any(|warning| warning.contains("synthetic")),
            "{warnings:?}"
        );
        let warnings: Vec<_> = warnings
            .iter()
            .filter(|warning| warning.contains(SNAPSHOT_WARNING))
            .collect();
        assert_eq!(warnings.len(), 1, "{warnings:?}");
        if sensitive {
            assert!(warnings[0].contains("withheld"), "{warnings:?}");
        }
    }

    fn exercise_sdk_snapshot_requests(fallback: bool) {
        let marker = nonce();
        let content = format!("clone-readonly-{marker}");
        let proxy_listener =
            std::net::TcpListener::bind("127.0.0.1:0").expect("private proxy port");
        let proxy = format!(
            "http://localhost:{}",
            proxy_listener.local_addr().unwrap().port()
        );
        for (index, (streaming, nic)) in
            [(true, false), (false, true), (true, true), (false, false)]
                .into_iter()
                .enumerate()
        {
            let label = format!("sdk-{index}");
            let mut request = snapshot_request(&marker, &label, nic);
            let mut command = String::new();
            if nic {
                request["network"] = json!({"egress": {"default": "deny"}});
                request["runtimeConfig"] = json!({"networkProxy": proxy.as_str()});
                command.push_str("test -n \"$HTTPS_PROXY\" || exit 97; ");
            }
            let readonly = if !fallback && index == 0 {
                let directory = tempfile::tempdir().expect("clone read-only fixture");
                std::fs::write(directory.path().join("input"), content.as_bytes()).unwrap();
                request["filesystem"] = json!({
                    "readonlyPaths": [directory.path().to_str().unwrap()]
                });
                request["process"]["env"] = json!([format!(
                    "MXC_NVX_SNAPSHOT_RO={}",
                    guest_path_for_host_directory(directory.path())
                )]);
                request["process"]["inheritDefaultEnv"] = json!(true);
                command.push_str(&format!(
                    "test \"$(cat \"$MXC_NVX_SNAPSHOT_RO/input\")\" = '{content}' || exit 96; \
                     if (printf forbidden >> \"$MXC_NVX_SNAPSHOT_RO/input\") 2>/dev/null; \
                     then exit 95; fi; "
                ));
                Some(directory)
            } else {
                None
            };
            command.push_str(request["process"]["commandLine"].as_str().unwrap());
            request["process"]["commandLine"] = json!(command);
            let output = sdk_json_output(&request, streaming);
            assert_eq!(output.outcome, WaitResult::Exited(42), "{output:?}");
            assert_snapshot_output(&output.stdout, &label, !fallback);
            assert_eq!(output.stderr, b"snapshot-stderr");
            if let Some(directory) = readonly {
                assert_eq!(
                    std::fs::read(directory.path().join("input")).unwrap(),
                    content.as_bytes()
                );
            }
            if fallback {
                assert_snapshot_warning(&output.warnings, false);
            } else {
                assert!(!output
                    .warnings
                    .iter()
                    .any(|warning| warning.contains(SNAPSHOT_WARNING)));
            }
            let local_app_data = PathBuf::from(std::env::var_os("LOCALAPPDATA").unwrap());
            assert_no_sandbox_state(&agent_state_directory(&local_app_data));
        }
        if fallback {
            let mut invalid = process_only_request("printf forbidden");
            invalid["runtimeConfig"] = json!({
                "networkProxy": "http://synthetic-user:synthetic-secret@[::1]:3128"
            });
            let error = dev::run_json(
                &invalid.to_string(),
                dev::JsonOptions { experimental: true },
            )
            .unwrap_err();
            assert_eq!(error.code, ErrorCode::PolicyValidation, "{error}");
            assert!(error.message.contains("withheld"), "{error}");
            assert!(!format!("{error:?}").contains("synthetic"));
            assert_no_run_state(std::process::id());
        }
    }

    fn agent_state_directory(local_app_data: &Path) -> PathBuf {
        let directories: Vec<PathBuf> =
            std::fs::read_dir(local_app_data.join(r"Microsoft\MXC\nvx"))
                .expect("agent state directories")
                .map(|entry| entry.expect("agent state directory").path())
                .filter(|path| {
                    path.is_dir()
                        && path.file_name().unwrap().to_str().is_some_and(|name| {
                            name.len() == 16 && name.bytes().all(|byte| byte.is_ascii_hexdigit())
                        })
                })
                .collect();
        assert_eq!(directories.len(), 1, "{directories:?}");
        directories
            .into_iter()
            .next()
            .expect("agent state directory")
    }

    fn assert_no_sandbox_state(root: &Path) {
        let sandboxes: Vec<_> = std::fs::read_dir(root)
            .expect("agent state listing")
            .map(|entry| entry.expect("agent state entry").path())
            .filter(|path| {
                path.is_dir()
                    && path.file_name().unwrap().to_str().is_some_and(|name| {
                        name.len() == 32 && name.bytes().all(|byte| byte.is_ascii_hexdigit())
                    })
            })
            .collect();
        assert!(
            sandboxes.is_empty(),
            "native sandbox state leaked: {sandboxes:?}"
        );
    }
}
