// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Tests for the ported SDK helpers: policy discovery, platform support, and
//! the SandboxPolicy -> SandboxRequest builder.

use mxc_sdk::{
    available_tools_policy, build_request, platform_support, temporary_files_policy,
    user_profile_policy, SandboxPolicy,
};

#[cfg(target_os = "macos")]
use mxc_sdk::{spawn_sandbox, WaitOutcome};

fn env_pairs(pairs: &[(&str, &str)]) -> Vec<(String, String)> {
    pairs
        .iter()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect()
}

#[test]
fn platform_support_reports_host() {
    let support = platform_support();
    // Every platform this test runs on (macOS/Linux/Windows in CI) is supported.
    assert!(support.is_supported, "reason: {:?}", support.reason);
    assert!(!support.available_methods.is_empty());
}

#[cfg(target_os = "macos")]
#[test]
fn platform_support_macos_is_seatbelt() {
    let support = platform_support();
    assert_eq!(support.available_methods, vec!["seatbelt".to_string()]);
}

#[test]
fn available_tools_policy_filters_nonexistent_and_dedups() {
    // A real dir (cwd), a bogus dir, and the real dir again under a known var.
    let cwd = std::env::current_dir()
        .unwrap()
        .to_string_lossy()
        .into_owned();
    let sep = if cfg!(target_os = "windows") {
        ";"
    } else {
        ":"
    };
    let path_val = format!("{cwd}{sep}/this/does/not/exist/xyzzy");
    let env = env_pairs(&[("PATH", &path_val), ("GOROOT", &cwd)]);

    let result = available_tools_policy(Some(&env), false);

    assert!(
        result.readonly_paths.iter().any(|p| p.contains(&cwd)),
        "the full resolved cwd should be discovered: cwd={cwd:?} paths={:?}",
        result.readonly_paths
    );
    assert!(
        !result.readonly_paths.iter().any(|p| p.contains("xyzzy")),
        "non-existent dir should be filtered: {:?}",
        result.readonly_paths
    );
    // cwd appeared twice (PATH + CARGO_HOME) but must be deduplicated.
    let cwd_hits = result
        .readonly_paths
        .iter()
        .filter(|p| {
            p.ends_with(
                std::path::Path::new(&cwd)
                    .file_name()
                    .unwrap()
                    .to_str()
                    .unwrap(),
            )
        })
        .count();
    assert!(
        cwd_hits <= 1,
        "cwd should not be duplicated: {:?}",
        result.readonly_paths
    );
}

#[test]
fn temporary_files_policy_returns_existing_temp() {
    let cwd = std::env::current_dir()
        .unwrap()
        .to_string_lossy()
        .into_owned();
    let var = if cfg!(target_os = "windows") {
        "TEMP"
    } else {
        "TMPDIR"
    };
    let env = env_pairs(&[(var, &cwd)]);

    let result = temporary_files_policy(Some(&env));
    assert_eq!(result.readwrite_paths.len(), 1);
    assert!(result.readonly_paths.is_empty());
}

#[test]
fn temporary_files_policy_empty_when_missing() {
    let env = env_pairs(&[
        ("TEMP", "/no/such/temp/xyzzy"),
        ("TMPDIR", "/no/such/temp/xyzzy"),
    ]);
    let result = temporary_files_policy(Some(&env));
    assert!(result.readwrite_paths.is_empty());
}

#[test]
fn user_profile_policy_does_not_panic() {
    // Behaviour is host-dependent; assert it returns without error and never
    // populates readwrite (it is a read-only fragment).
    let result = user_profile_policy();
    assert!(result.readwrite_paths.is_empty());
}

#[test]
fn build_request_rejects_empty_version() {
    // Parity with the SDK, which throws "Policy version is required".
    let policy = SandboxPolicy {
        version: String::new(),
        filesystem: None,
        network: None,
        ui: None,
        timeout_ms: None,
    };

    let err = build_request(&policy, None).expect_err("an empty policy version must be rejected");
    assert_eq!(err.code, mxc_sdk::ErrorCode::MalformedRequest);
}

#[test]
fn build_request_host_rules_require_outbound() {
    let policy = SandboxPolicy {
        version: "0.7.0-alpha".to_string(),
        filesystem: None,
        network: Some(mxc_sdk::policy::NetworkSection {
            allow_outbound: false,
            allow_local_network: false,
            allowed_hosts: vec!["example.com".to_string()],
            blocked_hosts: vec![],
            proxy: None,
        }),
        ui: None,
        timeout_ms: None,
    };

    // Unix backends accept host rules without `allowOutbound`; only Windows
    // ProcessContainer requires it. Either way this must not panic.
    let result = build_request(&policy, None);
    if cfg!(any(target_os = "linux", target_os = "macos")) {
        assert!(
            result.is_ok(),
            "Linux/macOS accept host rules without allowOutbound (matching the SDK)"
        );
    } else {
        assert!(
            result.is_err(),
            "Windows ProcessContainer requires allowOutbound for host rules"
        );
    }
}

#[cfg(target_os = "macos")]
#[test]
fn build_request_then_run_seatbelt() {
    let policy = SandboxPolicy {
        version: "0.7.0-alpha".to_string(),
        filesystem: Some(mxc_sdk::policy::FilesystemSection {
            readwrite_paths: vec!["/tmp".to_string()],
            readonly_paths: vec![],
            denied_paths: vec![],
            clear_policy_on_exit: None,
        }),
        network: None,
        ui: None,
        timeout_ms: Some(10000),
    };

    let mut request = build_request(&policy, None).expect("build_request should succeed");
    request.set_script("echo built-from-policy");

    let mut proc = spawn_sandbox(request).expect("spawn should succeed");
    let mut out = String::new();
    if let Some(mut stdout) = proc.take_stdout() {
        let _ = std::io::Read::read_to_string(&mut stdout, &mut out);
    }
    let outcome = proc.wait().expect("wait should succeed");
    assert_eq!(outcome, WaitOutcome::Exited(0));
    assert!(out.contains("built-from-policy"), "got: {out:?}");
}

#[cfg(target_os = "linux")]
#[test]
fn platform_support_linux_methods_are_bubblewrap_only() {
    let support = platform_support();
    // The crate dispatches only Bubblewrap on Linux (LXC has no captured /
    // streaming path), so that is the only method it should ever report.
    for method in &support.available_methods {
        assert_eq!(method, "bubblewrap", "unexpected Linux method: {method}");
    }
}

#[cfg(target_os = "windows")]
#[test]
fn platform_support_windows_is_processcontainer() {
    let support = platform_support();
    assert!(support.is_supported, "reason: {:?}", support.reason);
    assert_eq!(
        support.available_methods,
        vec!["processcontainer".to_string()]
    );
}

#[test]
fn available_tools_policy_filters_system_critical() {
    // A system-critical, existing directory on PATH must be filtered out so it
    // never lands in readonly_paths.
    let critical = if cfg!(target_os = "windows") {
        format!(
            "{}\\System32",
            std::env::var("WINDIR").unwrap_or_else(|_| "C:\\Windows".to_string())
        )
    } else {
        "/usr/bin".to_string()
    };
    if !std::path::Path::new(&critical).is_dir() {
        return; // skip if the critical dir doesn't exist on this host
    }
    let env = env_pairs(&[("PATH", &critical)]);
    let result = available_tools_policy(Some(&env), false);
    assert!(
        !result
            .readonly_paths
            .iter()
            .any(|p| p.to_lowercase().contains("system32") || p == "/usr/bin"),
        "system-critical dir must be filtered: {:?}",
        result.readonly_paths
    );
}
