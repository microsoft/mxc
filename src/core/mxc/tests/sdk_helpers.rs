// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Tests for the ported SDK helpers: policy discovery, platform support, and
//! the SandboxPolicy -> ExecutionRequest builder.

use mxc::{
    available_tools_policy, build_request, platform_support, spawn_sandbox_from_request,
    temporary_files_policy, user_profile_policy, Containment, SandboxPolicy,
};

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
    let env = env_pairs(&[("PATH", &path_val), ("CARGO_HOME", &cwd)]);

    let result = available_tools_policy(Some(&env));

    assert!(
        result.readonly_paths.iter().any(|p| p.contains(
            std::path::Path::new(&cwd)
                .file_name()
                .unwrap()
                .to_str()
                .unwrap()
        )),
        "cwd should be discovered: {:?}",
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
fn build_request_maps_filesystem_and_timeout() {
    let policy = SandboxPolicy {
        version: "0.7.0-alpha".to_string(),
        filesystem: Some(mxc::policy::FilesystemSection {
            readwrite_paths: vec!["/tmp".to_string()],
            readonly_paths: vec![],
            denied_paths: vec![],
            clear_policy_on_exit: None,
        }),
        network: None,
        ui: None,
        timeout_ms: Some(5000),
    };

    let request = build_request(&policy, Containment::Process, Some("test-container"))
        .expect("build_request should succeed");

    assert_eq!(request.script_timeout, 5000);
    assert!(request.policy.readwrite_paths.contains(&"/tmp".to_string()));
    assert!(request.script_code.is_empty());
}

#[test]
fn build_request_host_rules_require_outbound() {
    let policy = SandboxPolicy {
        version: "0.7.0-alpha".to_string(),
        filesystem: None,
        network: Some(mxc::policy::NetworkSection {
            allow_outbound: false,
            allow_local_network: false,
            allowed_hosts: vec!["example.com".to_string()],
            blocked_hosts: vec![],
            proxy: None,
        }),
        ui: None,
        timeout_ms: None,
    };

    // On macOS/Linux the abstract Process backend supports host filtering, so
    // this is accepted; on Windows it must be rejected. Either way it must not
    // panic and the result must be consistent with the platform.
    let result = build_request(&policy, Containment::Process, None);
    if cfg!(target_os = "windows") {
        assert!(
            result.is_err(),
            "Windows requires allowOutbound for host rules"
        );
    } else {
        assert!(result.is_ok(), "host-filtering backends accept host rules");
    }
}

#[cfg(target_os = "macos")]
#[test]
fn build_request_then_run_seatbelt() {
    let policy = SandboxPolicy {
        version: "0.7.0-alpha".to_string(),
        filesystem: Some(mxc::policy::FilesystemSection {
            readwrite_paths: vec!["/tmp".to_string()],
            readonly_paths: vec![],
            denied_paths: vec![],
            clear_policy_on_exit: None,
        }),
        network: None,
        ui: None,
        timeout_ms: Some(10000),
    };

    let mut request =
        build_request(&policy, Containment::Process, None).expect("build_request should succeed");
    request.script_code = "echo built-from-policy".to_string();

    let result = spawn_sandbox_from_request(request).expect("run should succeed");
    assert_eq!(result.exit_code, 0, "stderr: {}", result.standard_err);
    assert!(
        result.standard_out.contains("built-from-policy"),
        "got: {:?}",
        result.standard_out
    );
}

#[test]
fn build_request_preserves_clipboard_policy() {
    use mxc::policy::ClipboardPolicy as P;
    use wxc_common::models::ClipboardPolicy as Wire;

    for (input, expected) in [
        (P::None, Wire::None),
        (P::Read, Wire::Read),
        (P::Write, Wire::Write),
        (P::All, Wire::All),
    ] {
        let policy = SandboxPolicy {
            version: "0.7.0-alpha".to_string(),
            filesystem: None,
            network: None,
            ui: Some(mxc::policy::UiSection {
                allow_windows: true,
                clipboard: input,
                allow_input_injection: false,
            }),
            timeout_ms: None,
        };
        let request = build_request(&policy, Containment::Process, None)
            .expect("build_request should succeed");
        assert_eq!(
            request.policy.ui.clipboard, expected,
            "clipboard {input:?} should map to {expected:?}"
        );
    }
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
    let result = available_tools_policy(Some(&env));
    assert!(
        !result
            .readonly_paths
            .iter()
            .any(|p| p.to_lowercase().contains("system32") || p == "/usr/bin"),
        "system-critical dir must be filtered: {:?}",
        result.readonly_paths
    );
}
