// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use mxc_sdk::v1::ErrorCode;

fn process_only_request(command: &str) -> serde_json::Value {
    serde_json::json!({
        "version": "1.1.0-alpha",
        "containment": "microvm",
        "process": { "commandLine": command, "timeout": 30_000 }
    })
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

    fn rejected_requests() -> Vec<(&'static str, Value)> {
        vec![
            (
                "readonly",
                json!({"filesystem": {"readonlyPaths": ["C:\\work"]}}),
            ),
            (
                "readwrite",
                json!({"filesystem": {"readwritePaths": ["C:\\work"]}}),
            ),
            (
                "denied",
                json!({"filesystem": {"deniedPaths": ["C:\\work"]}}),
            ),
            ("network-empty", json!({"network": {}})),
            (
                "network-deny",
                json!({"network": {"egress": {"default": "deny"}}}),
            ),
            (
                "network-allow",
                json!({"network": {"egress": {"default": "allow"}}}),
            ),
            (
                "proxy",
                json!({"runtimeConfig": {"networkProxy": "http://127.0.0.1:8080"}}),
            ),
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

    fn assert_no_run_state(pid: u32) {
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
    fn signed_bundle_facade_create_and_run() {
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
