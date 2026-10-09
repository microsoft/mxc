#![cfg(all(windows, target_arch = "x86_64", feature = "microvm"))]

use std::time::{SystemTime, UNIX_EPOCH};

use mxc_sdk::v1::WaitResult;

fn run_nonce(label: &str) {
    let nonce = format!(
        "{label}-{}-{}",
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system clock")
            .as_nanos()
    );
    let command = format!("printf '%s\\n' '{nonce}'; cat /etc/os-release");
    let request = serde_json::json!({
        "version": "1.1.0-alpha",
        "containment": "microvm",
        "process": {
            "commandLine": command,
            "timeout": 30_000
        }
    });

    let result = mxc_sdk::__ffi::run_nvx_json(&request.to_string(), true)
        .expect("exact alpha MicroVM request should run through NVX");
    assert_eq!(result.outcome, WaitResult::Exited(0));
    assert!(
        result
            .stdout
            .windows(nonce.len())
            .any(|bytes| bytes == nonce.as_bytes()),
        "stdout did not contain nonce: {}",
        String::from_utf8_lossy(&result.stdout)
    );
    assert!(
        String::from_utf8_lossy(&result.stdout).contains("Alpine Linux"),
        "stdout did not identify Alpine: {}",
        String::from_utf8_lossy(&result.stdout)
    );
}

#[test]
#[ignore = "requires Windows x64, WHP, hardware virtualization, and bundled NVX artifacts"]
fn exact_alpha_json_runs_twice_through_nvx() {
    run_nonce("mxc-nvx-first");
    run_nonce("mxc-nvx-second");
}
