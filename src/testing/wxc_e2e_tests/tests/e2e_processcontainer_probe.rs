// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! ProcessContainer fallback-selection probe E2E tests.
//!
//! This is the Rust replacement for the `Probes` phase in
//! `WinProcessContainer-Tests.ps1`. It drives the shipped `wxc-exec.exe`
//! directly and verifies the same safety and tier-selection contract without
//! routing the assertions through PowerShell.
#![cfg(target_os = "windows")]

use std::fs;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use serde::Deserialize;
use serde_json::json;
use wxc_e2e_tests::{has_wxc_exe, run_wxc_probe, CommandResult};

const SCHEMA_VERSION: &str = "0.7.0-alpha";

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ProbeOutput {
    tier: Option<String>,
    needs_dacl_augmentation: Option<bool>,
    #[serde(default)]
    warnings: Vec<String>,
    probes: ProbeFacts,
    error: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ProbeFacts {
    base_container_api_present: bool,
    base_container_supports_deny_paths: bool,
    bfscfg_present: bool,
    bfs_compiled_in: bool,
}

struct Scratch {
    root: PathBuf,
    readwrite: PathBuf,
    denied: PathBuf,
}

impl Scratch {
    fn create() -> Self {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system clock before Unix epoch")
            .as_nanos();
        let root = std::env::temp_dir().join(format!(
            "mxc-processcontainer-probe-{}-{unique}",
            std::process::id()
        ));
        let readwrite = root.join("readwrite");
        let denied = root.join("denied");
        fs::create_dir_all(&readwrite).expect("create probe readwrite directory");
        fs::create_dir_all(&denied).expect("create probe denied directory");
        Self {
            root,
            readwrite,
            denied,
        }
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

fn config(
    label: &str,
    readwrite: Option<&Path>,
    denied: Option<&Path>,
    allow_dacl_mutation: Option<bool>,
) -> serde_json::Value {
    let mut config = json!({
        "version": SCHEMA_VERSION,
        "containerId": format!("e2e-probe-{label}"),
        "containment": "processcontainer",
        "process": { "commandLine": "cmd /c exit 0" },
        "processContainer": {
            "capabilities": [],
            "ui": {
                "isolation": "container",
                "desktopSystemControl": false,
                "systemSettings": "none",
                "ime": false,
            }
        }
    });

    if readwrite.is_some() || denied.is_some() {
        config["filesystem"] = json!({});
    }
    if let Some(path) = readwrite {
        config["filesystem"]["readwritePaths"] = json!([path]);
    }
    if let Some(path) = denied {
        config["filesystem"]["deniedPaths"] = json!([path]);
    }
    if let Some(allow) = allow_dacl_mutation {
        config["fallback"] = json!({ "allowDaclMutation": allow });
    }
    config
}

fn probe(label: &str, config: Option<&serde_json::Value>) -> ProbeOutput {
    let result = run_wxc_probe(label, config);
    assert_probe_succeeded(&result);
    serde_json::from_str(&result.stdout).unwrap_or_else(|error| {
        panic!(
            "{label} returned malformed probe JSON: {error}\nstdout: {}\nstderr: {}",
            result.stdout, result.stderr
        )
    })
}

fn assert_probe_succeeded(result: &CommandResult) {
    assert_eq!(
        result.code,
        Some(0),
        "{} failed\nstdout: {}\nstderr: {}",
        result.label,
        result.stdout,
        result.stderr
    );
}

fn resolved_tier(probe: &ProbeOutput) -> &str {
    probe.tier.as_deref().unwrap_or_else(|| {
        panic!(
            "probe returned no tier; error={:?}; warnings={:?}",
            probe.error, probe.warnings
        )
    })
}

fn expected_dacl_augmentation(tier: &str) -> bool {
    match tier {
        "appcontainer-dacl" => true,
        "base-container" => false,
        other => panic!("unexpected ProcessContainer tier: {other}"),
    }
}

fn assert_resolved_as(label: &str, probe: &ProbeOutput, expected_tier: &str) {
    assert_eq!(
        resolved_tier(probe),
        expected_tier,
        "{label} selected a different tier"
    );
    assert_eq!(
        probe.needs_dacl_augmentation,
        Some(expected_dacl_augmentation(expected_tier)),
        "{label} reported the wrong DACL-augmentation requirement"
    );
}

#[test]
fn processcontainer_probe_matrix() {
    if !has_wxc_exe() {
        return;
    }

    let scratch = Scratch::create();
    let baseline = probe("probe-no-config", None);
    let tier = resolved_tier(&baseline).to_string();

    assert!(
        matches!(tier.as_str(), "base-container" | "appcontainer-dacl"),
        "tier2_bfs-off binary selected unsupported tier {tier}"
    );
    assert!(
        !baseline.probes.bfs_compiled_in,
        "refusing to run ProcessContainer E2E with tier2_bfs compiled in"
    );
    assert!(
        !baseline.probes.bfscfg_present,
        "bfscfg must be unreachable when tier2_bfs is compiled out"
    );
    if tier == "base-container" {
        assert!(
            baseline.probes.base_container_api_present,
            "BaseContainer cannot be selected when its API is absent"
        );
    }
    assert_resolved_as("empty policy", &baseline, &tier);

    let readwrite = config("readwrite", Some(&scratch.readwrite), None, None);
    let readwrite_probe = probe("probe-readwrite", Some(&readwrite));
    assert_resolved_as("readwrite policy", &readwrite_probe, &tier);

    let denied = config("denied", None, Some(&scratch.denied), None);
    let denied_probe = probe("probe-denied", Some(&denied));
    let denied_tier =
        if tier == "base-container" && !baseline.probes.base_container_supports_deny_paths {
            "appcontainer-dacl"
        } else {
            &tier
        };
    assert_resolved_as("denied policy", &denied_probe, denied_tier);

    let refuse_dacl = config("refuse-dacl", Some(&scratch.readwrite), None, Some(false));
    let refuse_probe = probe("probe-refuse-dacl", Some(&refuse_dacl));
    if expected_dacl_augmentation(&tier) {
        assert!(
            refuse_probe.tier.is_none(),
            "DACL-dependent tier resolved despite allowDaclMutation=false"
        );
        assert!(
            refuse_probe
                .error
                .as_deref()
                .is_some_and(|error| error.contains("DACL fallback")),
            "expected DACL fallback error, got {:?}",
            refuse_probe.error
        );
    } else {
        assert_resolved_as(
            "readwrite policy with DACL mutation disabled",
            &refuse_probe,
            &tier,
        );
    }
}
