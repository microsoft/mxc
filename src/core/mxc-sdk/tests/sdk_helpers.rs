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
    let env = env_pairs(&[("PATH", &path_val), ("CARGO_HOME", &cwd)]);

    let result = available_tools_policy(Some(&env));

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
    let mut network = mxc_sdk::policy::NetworkSection::default();
    network.allowed_hosts = vec!["example.com".to_string()];

    let policy = SandboxPolicy {
        version: "0.7.0-alpha".to_string(),
        filesystem: None,
        network: Some(network),
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

#[test]
fn rust_sdk_builds_legacy_networking() {
    use mxc_sdk::policy::NetworkSection;

    let mut network = NetworkSection::default();
    network.allow_outbound = true;
    network.allow_local_network = true;
    network.allowed_hosts = vec!["allowed.example".to_string()];
    network.blocked_hosts = vec!["blocked.example".to_string()];

    let policy = SandboxPolicy {
        version: "0.7.0-alpha".to_string(),
        filesystem: None,
        network: Some(network),
        ui: None,
        timeout_ms: None,
    };

    build_request(&policy, None).expect("the Rust SDK should build legacy networking");
}

#[test]
fn rust_sdk_builds_directional_networking() {
    use mxc_sdk::policy::{
        NetworkAction, NetworkEgressSection, NetworkIngressSection, NetworkSection,
    };

    let mut egress = NetworkEgressSection::default();
    egress.default = Some(NetworkAction::Deny);
    let mut ingress = NetworkIngressSection::default();
    ingress.default = Some(NetworkAction::Deny);
    ingress.host_loopback = Some(NetworkAction::Deny);
    let mut network = NetworkSection::default();
    network.egress = Some(egress);
    network.ingress = Some(ingress);

    let policy = SandboxPolicy {
        version: "0.8.0-alpha".to_string(),
        filesystem: None,
        network: Some(network),
        ui: None,
        timeout_ms: None,
    };

    build_request(&policy, None).expect("the Rust SDK should build directional networking");
}

#[test]
fn rust_sdk_builds_directional_process_container_networking_and_capture() {
    use mxc_sdk::configs::{CaptureDenials, ProcessContainer, ProcessContainerNetwork};
    use mxc_sdk::policy::{
        NetworkAction, NetworkEgressSection, NetworkIngressSection, NetworkSection,
        RuntimeConfigSection,
    };
    use mxc_sdk::{build_request_with_containment, Containment};

    let mut egress = NetworkEgressSection::default();
    egress.default = Some(NetworkAction::Deny);
    let mut ingress = NetworkIngressSection::default();
    ingress.default = Some(NetworkAction::Allow);
    ingress.host_loopback = Some(NetworkAction::Deny);
    let mut runtime_config = RuntimeConfigSection::default();
    runtime_config.network_proxy = Some("http://127.0.0.1:8080".to_string());
    let mut network = NetworkSection::default();
    network.egress = Some(egress);
    network.ingress = Some(ingress);
    network.runtime_config = Some(runtime_config);

    let policy = SandboxPolicy {
        version: "0.8.0-alpha".to_string(),
        filesystem: None,
        network: Some(network),
        ui: None,
        timeout_ms: None,
    };
    let mut process_network = ProcessContainerNetwork::default();
    process_network.allowed_proxy_peer = Some("Contoso.Proxy_123".to_string());
    let mut process_container = ProcessContainer::default();
    process_container.capture_denials = Some(CaptureDenials::default());
    process_container.network = Some(process_network);

    build_request_with_containment(
        &policy,
        &Containment::ProcessContainer(process_container),
        None,
    )
    .expect("public re-exports should build a schema 0.8 ProcessContainer request");
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
fn platform_support_linux_reports_only_bubblewrap() {
    let support = platform_support();
    // Bubblewrap is the only SDK-launchable Linux backend; `lxc` is a
    // host-capability backend reported by `available_backends()`, not here.
    // Assert the exact set so re-advertising a non-launchable backend fails
    // (an inclusive `for` check would pass vacuously and permit `lxc`).
    assert_eq!(
        support.available_methods,
        vec!["bubblewrap".to_string()],
        "Linux platform_support must report exactly bubblewrap (lxc excluded)"
    );
}

#[cfg(target_os = "windows")]
#[test]
fn platform_support_windows_includes_processcontainer() {
    let support = platform_support();
    assert!(support.is_supported, "reason: {:?}", support.reason);
    // ProcessContainer is always available on Windows and is reported first.
    assert_eq!(
        support.available_methods.first().map(String::as_str),
        Some("processcontainer")
    );
    // Beyond processcontainer, only `wslc` may appear (SDK-launchable, opt-in).
    // `windows_sandbox` and `isolation_session` are host-capability backends
    // reported by `available_backends()`, not here — so assert they never leak
    // into this launchable set, or a regression would slip through.
    for method in &support.available_methods {
        assert!(
            matches!(method.as_str(), "processcontainer" | "wslc"),
            "unexpected Windows method (only processcontainer + optional wslc \
             are SDK-launchable): {method}"
        );
    }
}

/// Without the `wslc` feature the backend cannot run at all, so it must never be
/// advertised — regardless of whether the host happens to have the runtime.
#[cfg(all(target_os = "windows", not(feature = "wslc")))]
#[test]
fn platform_support_windows_omits_wslc_when_not_compiled_in() {
    let support = platform_support();
    assert!(
        !support.available_methods.iter().any(|m| m == "wslc"),
        "wslc must not be advertised without the feature: {:?}",
        support.available_methods
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
