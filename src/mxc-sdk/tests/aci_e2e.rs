// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! ACI sandbox backend tests.
//!
//! The tests that need Azure are ignored by default. Run them on Windows with
//! `--features aci`, a `wxc-exec.exe` built with the same feature, Azure CLI
//! credentials (or `MXC_ACI_ARM_TOKEN`), and `MXC_ACI_E2E_SANDBOX_GROUP` set
//! to a sandbox group the account can use:
//!
//! ```text
//! cargo build -p wxc --features aci
//! cargo test -p mxc-sdk --features aci --test aci_e2e -- --include-ignored --test-threads=1
//! ```

use mxc_sdk::{
    __ffi,
    v1::{dev, ErrorCode},
};

const EXAMPLE_GROUP: &str = "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/rg/providers/Microsoft.ContainerInstance/sandboxGroups/sbg";
const DEFAULT_IMAGE: &str = "mcr.microsoft.com/mirror/docker/library/alpine:3.16";

fn request(group: &str, command: &str) -> serde_json::Value {
    serde_json::json!({
        "version": "1.1.0-alpha",
        "containment": "aci",
        "aci": {"sandboxGroup": group, "image": DEFAULT_IMAGE},
        "process": {"commandLine": command, "timeout": 60_000}
    })
}

#[test]
fn aci_requires_explicit_experimental_optin() {
    let json = request(EXAMPLE_GROUP, "echo forbidden").to_string();
    let error = __ffi::run_json(&json, false).unwrap_err();
    assert_eq!(error.code, ErrorCode::BackendUnavailable, "{error}");
    assert!(error.message.contains("experimental"), "{error}");
    let error = __ffi::spawn_container_json(&json, false)
        .err()
        .expect("ACI must require the opt-in");
    assert_eq!(error.code, ErrorCode::BackendUnavailable, "{error}");
    let error = dev::run_json(&json, dev::JsonOptions::default()).unwrap_err();
    assert_eq!(error.code, ErrorCode::BackendUnavailable, "{error}");
}

#[test]
fn aci_streaming_pty_and_lifecycle_fail_closed() {
    let mut request = request(EXAMPLE_GROUP, "echo forbidden");
    let options = dev::JsonOptions { experimental: true };
    let json = request.to_string();
    let error = dev::spawn_json(&json, options)
        .err()
        .expect("ACI streaming must be rejected");
    assert_eq!(error.code, ErrorCode::UnsupportedContainment, "{error}");
    assert!(error.message.contains("streaming"), "{error}");
    let error = dev::spawn_with_pty_json(
        &json,
        dev::PtyJsonOptions {
            experimental: true,
            ..Default::default()
        },
    )
    .expect_err("ACI PTY must be rejected");
    assert_eq!(error.code, ErrorCode::UnsupportedContainment, "{error}");

    request.as_object_mut().unwrap().remove("process");
    request["phase"] = serde_json::json!("provision");
    for dry_run in [false, true] {
        let error = __ffi::run_lifecycle_json(&request.to_string(), dry_run, true).unwrap_err();
        assert_eq!(error.code, ErrorCode::MalformedRequest, "{error}");
    }
}

#[cfg(not(all(windows, feature = "aci")))]
#[test]
fn unsupported_platform_or_feature_is_fail_closed() {
    let json = request(EXAMPLE_GROUP, "echo forbidden").to_string();
    let error = dev::run_json(&json, dev::JsonOptions { experimental: true }).unwrap_err();
    assert_eq!(error.code, ErrorCode::BackendUnavailable, "{error}");
    assert!(error.message.contains("aci feature"), "{error}");
}

#[cfg(all(windows, feature = "aci"))]
mod windows_host {
    use std::path::PathBuf;
    use std::process::{Command, Output, Stdio};
    use std::time::{Duration, Instant};

    use mxc_sdk::v1::WaitResult;
    use serde_json::{json, Value};

    use super::*;

    const GROUP_ENV: &str = "MXC_ACI_E2E_SANDBOX_GROUP";
    const IMAGE_ENV: &str = "MXC_ACI_E2E_IMAGE";

    fn run(request: &Value) -> Result<mxc_sdk::v1::ExecutionResult, mxc_sdk::v1::Error> {
        dev::run_json(
            &request.to_string(),
            dev::JsonOptions { experimental: true },
        )
    }

    /// Each case must be rejected before MXC contacts Azure, so the example
    /// group never needs to exist.
    #[test]
    fn unenforceable_or_invalid_requests_fail_before_any_azure_call() {
        let cases: Vec<(&str, Value, ErrorCode, &str)> = vec![
            (
                "readonly",
                json!({"filesystem": {"readonlyPaths": [r"C:\data"]}}),
                ErrorCode::PolicyValidation,
                "filesystem.readonlyPaths",
            ),
            (
                "readwrite",
                json!({"filesystem": {"readwritePaths": [r"C:\data"]}}),
                ErrorCode::PolicyValidation,
                "filesystem.readwritePaths",
            ),
            (
                "denied",
                json!({"filesystem": {"deniedPaths": [r"C:\data"]}}),
                ErrorCode::PolicyValidation,
                "filesystem.deniedPaths",
            ),
            (
                "network",
                json!({"network": {}}),
                ErrorCode::PolicyValidation,
                "network policy",
            ),
            (
                "egress-allow",
                json!({"network": {"egress": {"default": "allow"}}}),
                ErrorCode::PolicyValidation,
                "network policy",
            ),
            (
                "proxy",
                json!({"runtimeConfig": {"networkProxy": "http://127.0.0.1:3128"}}),
                ErrorCode::PolicyValidation,
                "runtimeConfig.networkProxy",
            ),
            (
                "ui",
                json!({"ui": {"disable": true}}),
                ErrorCode::PolicyValidation,
                "UI policy",
            ),
            (
                "destroy",
                json!({"lifecycle": {"destroyOnExit": false}}),
                ErrorCode::PolicyValidation,
                "destroyOnExit",
            ),
            (
                "preserve",
                json!({"lifecycle": {"preservePolicy": true}}),
                ErrorCode::PolicyValidation,
                "preservePolicy",
            ),
            (
                "timeout",
                json!({"process": {"commandLine": "true", "timeout": 3_600_001}}),
                ErrorCode::PolicyValidation,
                "one hour",
            ),
            (
                "relative-cwd",
                json!({"process": {"commandLine": "true", "cwd": "relative"}}),
                ErrorCode::PolicyValidation,
                "absolute POSIX",
            ),
            (
                "parent-cwd",
                json!({"process": {"commandLine": "true", "cwd": "/tmp/../etc"}}),
                ErrorCode::PolicyValidation,
                "'..'",
            ),
            (
                "replacement-env",
                json!({"process": {"commandLine": "true", "env": ["A=b"]}}),
                ErrorCode::PolicyValidation,
                "inheritDefaultEnv",
            ),
            (
                "proxy-env",
                json!({"process": {"commandLine": "true", "env": ["HTTPS_PROXY=x"], "inheritDefaultEnv": true}}),
                ErrorCode::PolicyValidation,
                "proxy environment",
            ),
            (
                "zero-cpu",
                json!({"aci": {"sandboxGroup": EXAMPLE_GROUP, "image": DEFAULT_IMAGE, "provision": {"cpu": 0}}}),
                ErrorCode::MalformedRequest,
                "aci.provision.cpu",
            ),
            (
                "zero-memory",
                json!({"aci": {"sandboxGroup": EXAMPLE_GROUP, "image": DEFAULT_IMAGE, "provision": {"memoryGb": 0}}}),
                ErrorCode::MalformedRequest,
                "aci.provision.memoryGb",
            ),
            (
                "bad-group",
                json!({"aci": {"sandboxGroup": "/subscriptions/x", "image": DEFAULT_IMAGE}}),
                ErrorCode::MalformedRequest,
                "aci.sandboxGroup",
            ),
            (
                "bad-image",
                json!({"aci": {"sandboxGroup": EXAMPLE_GROUP, "image": "alpine:3.16"}}),
                ErrorCode::MalformedRequest,
                "aci.image",
            ),
            (
                "process-container",
                json!({"processContainer": {"leastPrivilege": true}}),
                ErrorCode::MalformedRequest,
                "processContainer",
            ),
        ];
        for (label, patch, code, text) in cases {
            let mut request = request(EXAMPLE_GROUP, "echo forbidden");
            for (key, value) in patch.as_object().unwrap() {
                request[key] = value.clone();
            }
            let error = run(&request).expect_err(label);
            assert_eq!(error.code, code, "{label}: {error}");
            assert!(error.message.contains(text), "{label}: {error}");
        }
    }

    fn sandbox_group() -> String {
        std::env::var(GROUP_ENV).unwrap_or_else(|_| {
            panic!("set {GROUP_ENV} to the ARM resource ID of a sandbox group to run ACI tests")
        })
    }

    fn live_request(command: &str) -> Value {
        let image = std::env::var(IMAGE_ENV).unwrap_or_else(|_| DEFAULT_IMAGE.to_owned());
        let mut request = request(&sandbox_group(), command);
        request["aci"]["image"] = json!(image);
        request
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
            "build wxc-exec with --features aci first: {}",
            path.display()
        );
        path
    }

    /// Runs the executor and returns its output and audit log.
    fn executor_output(request: &Value, extra: &[&str]) -> (Output, String) {
        let directory = tempfile::tempdir().expect("executor request directory");
        let request_path = directory.path().join("request.json");
        let log_path = directory.path().join("executor.log");
        std::fs::write(&request_path, request.to_string()).expect("write executor request");
        let output = Command::new(executor())
            .arg("--experimental")
            .arg("--debug")
            .arg("--log-file")
            .arg(&log_path)
            .args(extra)
            .arg(&request_path)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .output()
            .expect("MXC executor process");
        let log = std::fs::read_to_string(&log_path).unwrap_or_default();
        (output, log)
    }

    #[test]
    #[ignore = "Azure: creates and deletes an ACI sandbox; needs MXC_ACI_E2E_SANDBOX_GROUP and wxc-exec.exe"]
    fn executor_runs_a_command_and_tears_down_the_sandbox() {
        let request =
            live_request("printf 'hello from %s\\n' \"$(uname -s)\"; printf 'to stderr' >&2");
        let (output, log) = executor_output(&request, &[]);
        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(output.status.success(), "{output:?}\n{log}");
        assert!(stdout.contains("hello from Linux\n"), "{stdout}");
        assert!(stderr.contains("to stderr"), "{stderr}");
        assert!(log.contains("mxc.SandboxIdentity"), "{log}");
        assert!(log.contains("/sandboxes/mxc-"), "{log}");
        assert!(
            log.lines()
                .any(|line| line.contains("mxc.SandboxTornDown")
                    && line.contains(r#""status":"ok""#)),
            "the sandbox was not deleted cleanly:\n{log}"
        );
        println!("ACI executor run: {stdout}");
    }

    #[test]
    #[ignore = "Azure: checks credentials and sandbox group access; needs MXC_ACI_E2E_SANDBOX_GROUP and wxc-exec.exe"]
    fn executor_dry_run_checks_access_without_creating_a_sandbox() {
        let (output, log) = executor_output(&live_request("echo never runs"), &["--dry-run"]);
        assert!(output.status.success(), "{output:?}");
        assert!(String::from_utf8_lossy(&output.stdout).contains("validation passed"));
        assert!(!log.contains("mxc.SandboxIdentity"), "{log}");

        let mut missing = live_request("echo never runs");
        let group = sandbox_group();
        let name = group.rsplit('/').next().unwrap();
        missing["aci"]["sandboxGroup"] = json!(group.replace(name, "mxc-e2e-missing-group"));
        let (output, _) = executor_output(&missing, &["--dry-run"]);
        assert!(!output.status.success());
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(stderr.contains("backend_unavailable"), "{stderr}");
    }

    #[test]
    #[ignore = "Azure: creates and deletes an ACI sandbox; needs MXC_ACI_E2E_SANDBOX_GROUP"]
    fn run_json_captures_streams_exit_code_environment_and_working_directory() {
        let mut request = live_request(
            "printf '%s|%s|%s' \"$MXC_ACI_PROBE\" \"$PWD\" \"$MXC_ACI_REPEATED\"; printf 'err' >&2; exit 7",
        );
        request["process"]["cwd"] = json!("/tmp");
        request["process"]["env"] = json!([
            "MXC_ACI_PROBE=marker",
            "MXC_ACI_REPEATED=first",
            "MXC_ACI_REPEATED=last"
        ]);
        request["process"]["inheritDefaultEnv"] = json!(true);
        let result = run(&request).expect("ACI run");
        assert_eq!(result.outcome, WaitResult::Exited(7));
        assert_eq!(String::from_utf8_lossy(&result.stdout), "marker|/tmp|last");
        assert_eq!(String::from_utf8_lossy(&result.stderr), "err");
    }

    #[test]
    #[ignore = "Azure: creates and deletes an ACI sandbox; needs MXC_ACI_E2E_SANDBOX_GROUP"]
    fn run_json_sizes_the_sandbox() {
        let mut request = live_request("nproc");
        request["aci"]["provision"] = json!({"cpu": 2, "memoryGb": 2});
        let result = run(&request).expect("ACI run");
        assert_eq!(result.outcome, WaitResult::Exited(0));
        assert_eq!(String::from_utf8_lossy(&result.stdout).trim(), "2");
    }

    #[test]
    #[ignore = "Azure: creates and deletes an ACI sandbox; needs MXC_ACI_E2E_SANDBOX_GROUP"]
    fn timeouts_return_promptly_and_delete_the_sandbox() {
        let mut request = live_request("sleep 120; echo late");
        request["process"]["timeout"] = json!(3_000);
        let started = Instant::now();
        let result = run(&request).expect("ACI run");
        assert_eq!(result.outcome, WaitResult::TimedOut);
        assert!(!String::from_utf8_lossy(&result.stdout).contains("late"));
        // Startup, the 3 s workload deadline, and deletion; far less than the sleep.
        assert!(
            started.elapsed() < Duration::from_secs(100),
            "{:?}",
            started.elapsed()
        );
    }

    #[test]
    #[ignore = "Azure: creates and deletes an ACI sandbox; needs MXC_ACI_E2E_SANDBOX_GROUP"]
    fn a_missing_working_directory_is_an_error_not_an_exit_code() {
        let mut request = live_request("pwd");
        request["process"]["cwd"] = json!("/mxc/does/not/exist");
        let error = run(&request).expect_err("a missing cwd cannot start");
        assert_eq!(error.code, ErrorCode::BackendError, "{error}");
        assert!(
            error.message.contains("could not start the command"),
            "{error}"
        );
        assert!(error.message.contains("/mxc/does/not/exist"), "{error}");
        assert!(!error.message.contains("cleanup failure"), "{error}");
    }

    #[test]
    #[ignore = "Azure: sends one rejected create request; needs MXC_ACI_E2E_SANDBOX_GROUP"]
    fn image_references_the_service_rejects_are_malformed_requests() {
        let mut request = live_request("true");
        request["aci"]["image"] = json!("mcr.microsoft.com/MXC/Invalid-Upper-Case:1");
        let error = run(&request).expect_err("the service must reject the reference");
        assert_eq!(error.code, ErrorCode::MalformedRequest, "{error}");
        assert!(error.message.contains("HTTP 400"), "{error}");
        assert!(!error.message.contains("cleanup failure"), "{error}");
    }

    /// Ctrl-C during startup and during execution must stop waiting, delete
    /// the sandbox, and exit with 130.
    #[test]
    #[ignore = "Azure: creates and deletes ACI sandboxes; needs MXC_ACI_E2E_SANDBOX_GROUP and wxc-exec.exe"]
    fn executor_console_interrupt_deletes_the_sandbox() {
        use std::os::windows::process::CommandExt;
        use windows::Win32::System::Console::{
            GenerateConsoleCtrlEvent, SetConsoleCtrlHandler, CTRL_C_EVENT,
        };
        use windows::Win32::System::Threading::CREATE_NEW_CONSOLE;

        const CHILD_ENV: &str = "MXC_ACI_CONSOLE_CHILD";
        let Some(phase) = std::env::var_os(CHILD_ENV) else {
            for phase in ["startup", "execution"] {
                // A separate console keeps Ctrl-C away from the suite and other sessions.
                let output = Command::new(std::env::current_exe().expect("test executable"))
                    .args([
                        "--exact",
                        "windows_host::executor_console_interrupt_deletes_the_sandbox",
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
            return;
        };

        unsafe extern "system" fn ignore_ctrl_c(event: u32) -> windows::core::BOOL {
            windows::core::BOOL(i32::from(event == CTRL_C_EVENT))
        }
        // Clear an inherited "ignore Ctrl-C" attribute, which some launchers
        // set, so the executor this helper starts receives the event.
        unsafe { SetConsoleCtrlHandler(None, false) }.expect("restore Ctrl-C processing");
        unsafe { SetConsoleCtrlHandler(Some(ignore_ctrl_c), true) }.expect("helper handler");

        let directory = tempfile::tempdir().expect("interruption test directory");
        let request_path = directory.path().join("request.json");
        let log_path = directory.path().join("executor.log");
        let mut request = live_request("sleep 600");
        request["process"]["timeout"] = json!(0);
        std::fs::write(&request_path, request.to_string()).expect("interruption request");
        let mut child = Command::new(executor())
            .args(["--experimental", "--debug", "--log-file"])
            .arg(&log_path)
            .arg(&request_path)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("interruptible executor");
        let marker = if phase == "startup" {
            "mxc.SandboxIdentity"
        } else {
            "ACI execution started"
        };
        let ready_deadline = Instant::now() + Duration::from_secs(300);
        loop {
            if let Some(status) = child.try_wait().expect("executor status") {
                panic!("executor exited with {status} before interruption");
            }
            let log = std::fs::read_to_string(&log_path).unwrap_or_default();
            if log.contains(marker) {
                if phase == "execution" {
                    // Let the request reach the guest before interrupting it.
                    std::thread::sleep(Duration::from_secs(2));
                }
                break;
            }
            assert!(
                Instant::now() < ready_deadline,
                "executor never logged {marker}"
            );
            std::thread::sleep(Duration::from_millis(20));
        }
        let interrupted = Instant::now();
        unsafe { GenerateConsoleCtrlEvent(CTRL_C_EVENT, 0) }.expect("Ctrl-C delivery");
        let status = loop {
            if let Some(status) = child.try_wait().expect("cancelled executor status") {
                break status;
            }
            if interrupted.elapsed() > Duration::from_secs(120) {
                let _ = child.kill();
                let log = std::fs::read_to_string(&log_path).unwrap_or_default();
                let tail: Vec<&str> = log.lines().rev().take(15).collect();
                panic!(
                    "executor did not stop after Ctrl-C during {phase:?}; log tail:\n{}",
                    tail.into_iter().rev().collect::<Vec<_>>().join("\n")
                );
            }
            std::thread::sleep(Duration::from_millis(50));
        };
        let log = std::fs::read_to_string(&log_path).expect("executor log");
        assert_eq!(status.code(), Some(130), "{phase:?}\n{log}");
        assert!(
            log.lines()
                .any(|line| line.contains("mxc.SandboxTornDown")
                    && line.contains(r#""status":"ok""#)),
            "{phase:?}: the sandbox was not deleted cleanly:\n{log}"
        );
        println!(
            "ACI {phase:?} interruption completed in {:?}",
            interrupted.elapsed()
        );
    }
}
