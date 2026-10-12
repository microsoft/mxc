#![cfg(all(windows, target_arch = "x86_64", feature = "microvm"))]

use std::time::{SystemTime, UNIX_EPOCH};

use mxc_sdk::v1::{ErrorCode, WaitResult};

fn process_only_request() -> serde_json::Value {
    serde_json::json!({
        "version": "1.1.0-alpha",
        "containment": "microvm",
        "process": {
            "commandLine": "echo ok",
            "timeout": 30_000
        }
    })
}

fn shell_quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', "'\"'\"'"))
}

fn run_nonce(label: &str) {
    let nonce = format!(
        "{label}-{}-{}",
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system clock")
            .as_nanos()
    );
    let python = format!(
        "import platform; print({nonce:?}); print(platform.python_version()); print(platform.platform())"
    );
    let command = format!("python3 -c {}", shell_quote(&python));
    let request = serde_json::json!({
        "version": "1.1.0-alpha",
        "containment": "microvm",
        "process": {
            "commandLine": command,
            "timeout": 120_000
        }
    });

    let result = mxc_sdk::__ffi::run_json(&request.to_string(), true)
        .expect("exact alpha MicroVM request should run through signed NVX agent");
    assert_eq!(result.outcome, WaitResult::Exited(0));
    assert!(
        result
            .stdout
            .windows(nonce.len())
            .any(|bytes| bytes == nonce.as_bytes()),
        "stdout did not contain nonce: {}",
        String::from_utf8_lossy(&result.stdout)
    );
    let stdout = String::from_utf8_lossy(&result.stdout);
    assert!(
        stdout.contains("3.12"),
        "stdout did not identify Python 3.12: {stdout}"
    );
    assert!(
        stdout.contains("Linux"),
        "stdout did not identify a Linux guest: {stdout}"
    );
}

#[test]
fn experimental_opt_in_is_required_before_backend_discovery() {
    let error = mxc_sdk::__ffi::run_json(&process_only_request().to_string(), false).unwrap_err();
    assert_eq!(error.code, ErrorCode::BackendUnavailable);
    assert!(error.message.contains("experimental"));
}

#[test]
fn unsupported_policy_is_rejected_before_bundle_discovery() {
    let mut request = process_only_request();
    request["network"] = serde_json::json!({
        "egress": { "default": "deny" },
        "ingress": { "default": "deny", "hostLoopback": "deny" }
    });
    let error = mxc_sdk::__ffi::run_json(&request.to_string(), true).unwrap_err();
    assert_eq!(error.code, ErrorCode::PolicyValidation);
    assert_eq!(
        error.message,
        "the initial NVX integration supports process settings only; filesystem, network, UI, and capture-denials policies are not yet supported"
    );
}

#[test]
fn missing_bundle_is_backend_unavailable_at_production_boundary() {
    if std::env::var_os("MXC_NVX_MISSING_BUNDLE_CHILD").is_some() {
        let error =
            mxc_sdk::__ffi::run_json(&process_only_request().to_string(), true).unwrap_err();
        assert_eq!(error.code, ErrorCode::BackendUnavailable);
        assert!(error.message.contains("MXC_NVX_BUNDLE_DIR"));
        return;
    }

    let output = std::process::Command::new(std::env::current_exe().expect("current test binary"))
        .arg("--exact")
        .arg("missing_bundle_is_backend_unavailable_at_production_boundary")
        .arg("--nocapture")
        .env("MXC_NVX_MISSING_BUNDLE_CHILD", "1")
        .env_remove("MXC_NVX_BUNDLE_DIR")
        .output()
        .expect("launch isolated missing-bundle test");
    assert!(
        output.status.success(),
        "isolated missing-bundle test failed\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
#[ignore = "requires Windows x64, WHP, MXC_NVX_BUNDLE_DIR, and MCR access"]
fn exact_alpha_json_runs_twice_through_signed_nvx_agent() {
    run_nonce("mxc-nvx-first");
    run_nonce("mxc-nvx-second");
}
