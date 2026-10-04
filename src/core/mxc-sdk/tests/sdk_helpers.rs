// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Tests for SDK helpers and V1 request authoring.

use mxc_sdk::v1::platform_support;
use mxc_sdk::v1::policy::filesystem::{
    available_tools_policy, temporary_files_policy, user_profile_policy,
};
use mxc_sdk::v1::ContainerRequest;
#[cfg(target_os = "windows")]
use mxc_sdk::v1::ErrorCode;
#[cfg(target_os = "windows")]
use mxc_sdk::v1::{configs::WslcConfig, Containment};

#[cfg(target_os = "macos")]
use mxc_sdk::v1::spawn;
#[cfg(target_os = "macos")]
use mxc_sdk::v1::WaitResult;

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

    let result = available_tools_policy(Some(&env), Default::default());

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
    let result = user_profile_policy(None);
    assert!(result.readwrite_paths.is_empty());
}

#[test]
fn explicitly_empty_environment_does_not_discover_host_tools_or_profile() {
    let empty = [];
    assert!(available_tools_policy(Some(&empty), Default::default())
        .readonly_paths
        .is_empty());
    assert!(user_profile_policy(Some(&empty)).readonly_paths.is_empty());
}

#[test]
fn user_profile_policy_uses_supplied_environment() {
    let directory = std::env::temp_dir().join(format!("mxc-profile-{}", std::process::id()));
    let (key, expected) = if cfg!(target_os = "windows") {
        ("LOCALAPPDATA", directory.join("Programs").join("Tool"))
    } else {
        ("HOME", directory.join(".local").join("bin"))
    };
    std::fs::create_dir_all(&expected).unwrap();
    let environment = env_pairs(&[(key, &directory.to_string_lossy())]);
    let result = user_profile_policy(Some(&environment));
    std::fs::remove_dir_all(&directory).unwrap();
    assert_eq!(
        result.readonly_paths,
        [expected.to_string_lossy().into_owned()]
    );
    assert!(result.readwrite_paths.is_empty());
}

#[cfg(target_os = "windows")]
#[test]
fn tool_options_filter_all_application_packages_without_changing_default() {
    use mxc_sdk::v1::policy::filesystem::{ToolsPolicyContainerType, ToolsPolicyOptions};
    let directory = std::env::temp_dir().join(format!("mxc-tools-{} & paths", std::process::id()));
    std::fs::create_dir_all(&directory).unwrap();
    let grant = std::process::Command::new("icacls.exe")
        .arg(&directory)
        .args(["/grant", "*S-1-15-2-1:(OI)(CI)(RX)"])
        .output()
        .unwrap();
    assert!(grant.status.success(), "icacls failed: {:?}", grant);
    let environment = env_pairs(&[("PATH", &directory.to_string_lossy())]);
    let unfiltered = available_tools_policy(Some(&environment), Default::default());
    let filtered = available_tools_policy(
        Some(&environment),
        ToolsPolicyOptions {
            container_type: Some(ToolsPolicyContainerType::ProcessContainer),
        },
    );
    std::fs::remove_dir_all(&directory).unwrap();
    assert!(unfiltered
        .readonly_paths
        .contains(&directory.to_string_lossy().into_owned()));
    assert!(filtered.readonly_paths.is_empty());
}

#[cfg(target_os = "macos")]
#[test]
fn build_request_then_run_seatbelt() {
    let request = ContainerRequest {
        filesystem: Some(mxc_sdk::v1::FilesystemPolicy {
            readwrite_paths: vec!["/tmp".to_string()],
            readonly_paths: vec![],
            denied_paths: vec![],
            clear_policy_on_exit: None,
        }),
        timeout_ms: Some(10000),
        ..ContainerRequest::new("echo built-from-request")
    };

    let mut proc = spawn(request, Default::default()).expect("spawn should succeed");
    let mut out = String::new();
    if let Some(mut stdout) = proc.take_stdout() {
        let _ = std::io::Read::read_to_string(&mut stdout, &mut out);
    }
    let outcome = proc.wait().expect("wait should succeed");
    assert_eq!(outcome, WaitResult::Exited(0));
    assert!(out.contains("built-from-request"), "got: {out:?}");
}

#[cfg(target_os = "linux")]
#[test]
fn platform_support_linux_reports_the_backends_it_can_launch() {
    // Asserted as invariants rather than by re-running the probes: an
    // expectation rebuilt from the same calls `platform_support` makes has no
    // independent oracle and cannot fail. The LXC-only and both-present
    // matrices are pinned by the injected-probe tests in `mxc_engine`.
    let support = platform_support();

    for method in &support.available_methods {
        assert!(
            matches!(method.as_str(), "lxc" | "bubblewrap"),
            "only the two SDK-launchable Linux backends may be reported, got: {method}"
        );
    }
    assert_eq!(
        support.available_methods.len(),
        support
            .available_methods
            .iter()
            .collect::<std::collections::HashSet<_>>()
            .len(),
        "a backend must not be reported twice: {:?}",
        support.available_methods
    );
    assert_eq!(
        support.is_supported,
        !support.available_methods.is_empty(),
        "a host with a launchable backend must report itself supported, and one \
         without must not: {support:?}"
    );
    assert_eq!(
        support.bubblewrap_network.is_some(),
        support
            .available_methods
            .iter()
            .any(|method| method == "bubblewrap"),
        "the bubblewrap network capability is reported exactly when bubblewrap is: {support:?}"
    );
    if support.available_methods.len() == 2 {
        assert_eq!(
            support.available_methods,
            ["lxc", "bubblewrap"],
            "the reported order must match the TypeScript SDK's"
        );
    }
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
    // Beyond processcontainer, only the opt-in backends may appear.
    // `windows_sandbox` is a host-capability backend reported by
    // `available_backends()`, not here — so assert it never leaks into this
    // launchable set, or a regression would slip through.
    for method in &support.available_methods {
        assert!(
            matches!(
                method.as_str(),
                "processcontainer" | "wslc" | "isolation_session"
            ),
            "unexpected Windows method (only processcontainer plus the opt-in \
             wslc / isolation_session are SDK-launchable): {method}"
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

#[cfg(target_os = "windows")]
#[test]
fn request_probe_accepts_default_and_typed_requests() {
    let _: fn(
        Option<&mxc_sdk::v1::ContainerRequest>,
    ) -> Result<mxc_sdk::v1::ProbeOutput, mxc_sdk::v1::Error> = mxc_sdk::v1::probe;

    let request = ContainerRequest {
        containment: Containment::ProcessContainer(
            mxc_sdk::v1::configs::ProcessContainerConfig::default(),
        ),
        ..ContainerRequest::new("cmd /c exit 0")
    };

    for request in [None, Some(&request)] {
        let output = mxc_sdk::v1::probe(request).expect("ProcessContainer request should probe");
        let _: &mxc_sdk::v1::ProbeFacts = &output.probes;
        let _: &mxc_sdk::v1::UiCapabilitySupport = &output.probes.ui_capabilities;
        assert!(!output.warnings.iter().any(String::is_empty));
    }
}

#[cfg(target_os = "windows")]
#[test]
fn request_probe_rejects_non_process_container_requests() {
    let request = ContainerRequest {
        containment: Containment::Wslc(WslcConfig::default()),
        ..ContainerRequest::new("echo hi")
    };

    let error = mxc_sdk::v1::probe(Some(&request))
        .expect_err("request probe should reject non-ProcessContainer containment");
    assert_eq!(error.code, ErrorCode::UnsupportedContainment);
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
    let result = available_tools_policy(Some(&env), Default::default());
    assert!(
        !result
            .readonly_paths
            .iter()
            .any(|p| p.to_lowercase().contains("system32") || p == "/usr/bin"),
        "system-critical dir must be filtered: {:?}",
        result.readonly_paths
    );
}

/// The nested bubblewrap-network types must be nameable from the SDK facade
/// alone; a consumer should never need `mxc_engine` as a direct dependency.
#[test]
fn bubblewrap_network_types_are_reachable_from_the_facade() {
    use mxc_sdk::v1::{BubblewrapNetworkSupport, ProxyEnforcement};

    let network: Option<BubblewrapNetworkSupport> = platform_support().bubblewrap_network;
    if let Some(network) = network {
        assert!(
            network.proxy_enforcement == ProxyEnforcement::Supported
                || !network.warnings.is_empty(),
            "an unsupported result must carry the reason (fail-closed contract)"
        );
    }
}
