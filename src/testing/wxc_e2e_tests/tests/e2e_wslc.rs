// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! WSLC (WSL Container) E2E integration tests.
//!
//! These tests mirror the Windows MicroVM / Hyperlight E2E suites and invoke
//! `wxc-exec.exe` directly with the `wslc` containment backend. WSLC boots
//! Linux containers inside WSL2, which needs nested virtualization on the host
//! (unavailable on GitHub-hosted runners) plus the WSLC SDK (`wslcsdk.dll`, a
//! `--features wslc` build), a WSL2 runtime, and pre-pulled images. Tests skip
//! gracefully when any prerequisite is missing so the suite is a no-op on
//! machines that cannot run it, and only executes on a nested-virt-capable
//! (e.g. 1ES) runner.

use std::sync::OnceLock;
use std::time::{SystemTime, UNIX_EPOCH};

use serde::Serialize;
use wxc_e2e_tests::{
    has_wsl_runtime, has_wslc_sdk, has_wxc_exe, repo_root, run_wxc_config, run_wxc_example,
    test_configs_dir, CommandResult,
};

static HAS_WXC_EXE: OnceLock<bool> = OnceLock::new();
static HAS_WSLC_SDK: OnceLock<bool> = OnceLock::new();
static HAS_WSL_RUNTIME: OnceLock<bool> = OnceLock::new();

fn cached_has_wxc_exe() -> bool {
    *HAS_WXC_EXE.get_or_init(has_wxc_exe)
}

fn cached_has_wslc_sdk() -> bool {
    *HAS_WSLC_SDK.get_or_init(has_wslc_sdk)
}

fn cached_has_wsl_runtime() -> bool {
    *HAS_WSL_RUNTIME.get_or_init(has_wsl_runtime)
}

/// Guard: skip test unless the WSLC prerequisites are present.
fn skip_unless_ready() -> bool {
    cached_has_wxc_exe() && cached_has_wslc_sdk() && cached_has_wsl_runtime()
}

// ---------------------------------------------------------------------------
// Individual test (mirrors test_microvm_hello)
// ---------------------------------------------------------------------------

#[test]
fn test_wslc_hello() {
    if !skip_unless_ready() {
        return;
    }
    // The hello-world config lives under tests/examples/, not tests/configs/.
    let result = run_wxc_example("wslc_hello_world.json", &["--debug", "--experimental"]);
    assert_eq!(
        result.code,
        Some(0),
        "expected exit 0, got {:?}\nstdout: {}\nstderr: {}",
        result.code,
        result.stdout,
        result.stderr
    );
    assert!(
        result
            .combined_output_with_decoded_base64()
            .contains("Hello from WSL Container!"),
        "output missing greeting\nstdout: {}\nstderr: {}",
        result.stdout,
        result.stderr
    );
}

// ---------------------------------------------------------------------------
// Full WSLC smoke suite (mirrors test_microvm_suite)
// ---------------------------------------------------------------------------

#[derive(Debug)]
struct WslcCase {
    config: &'static str,
    /// When true the config lives in tests/examples/, otherwise tests/configs/.
    from_example: bool,
    expected_exit: Option<i32>,
    description: &'static str,
    output_contains: Option<&'static str>,
    expect_non_zero: bool,
}

#[derive(Debug, Serialize)]
struct WslcPerfOutput {
    commit: String,
    timestamp: String,
    results: Vec<WslcPerfEntry>,
}

#[derive(Debug, Serialize)]
struct WslcPerfEntry {
    test: String,
    description: String,
    wall_time_ms: u128,
    exit_code: Option<i32>,
    status: String,
}

#[test]
fn test_wslc_suite() {
    if !skip_unless_ready() {
        return;
    }
    wslc_suite();
}

fn wslc_suite() {
    // Core smoke set. Images required (pre-pull via scripts/setup-wslc.ps1):
    //   alpine:latest        -> hello-world, exit-code, network-isolated, large-output
    //   python:3.12-alpine   -> python-stdlib
    let cases = [
        WslcCase {
            config: "wslc_hello_world.json",
            from_example: true,
            expected_exit: Some(0),
            description: "Hello world (alpine, uname)",
            output_contains: Some("Hello from WSL Container!"),
            expect_non_zero: false,
        },
        WslcCase {
            config: "wslc_exit_code.json",
            from_example: false,
            expected_exit: Some(42),
            description: "Exit code propagation",
            output_contains: Some("About to exit with code 42"),
            expect_non_zero: false,
        },
        WslcCase {
            config: "wslc_python_stdlib.json",
            from_example: false,
            expected_exit: Some(0),
            description: "Python stdlib (json, math, hashlib)",
            output_contains: Some("pi"),
            expect_non_zero: false,
        },
        WslcCase {
            config: "wslc_network_isolated.json",
            from_example: false,
            expected_exit: Some(0),
            description: "Network isolation (block policy)",
            output_contains: Some("Network"),
            expect_non_zero: false,
        },
        WslcCase {
            config: "wslc_large_output.json",
            from_example: false,
            expected_exit: Some(0),
            description: "Large stdout (500 lines)",
            output_contains: Some("Large output test complete"),
            expect_non_zero: false,
        },
    ];

    let mut perf_entries = Vec::new();
    let mut failures = Vec::new();

    for case in cases {
        let config_path = if case.from_example {
            repo_root().join("tests").join("examples").join(case.config)
        } else {
            test_configs_dir().join(case.config)
        };
        if !config_path.exists() {
            println!("SKIPPED: config not found: {}", config_path.display());
            continue;
        }

        println!("--- {} ({}) ---", case.description, case.config);
        let result = if case.from_example {
            run_wxc_example(case.config, &["--debug", "--experimental"])
        } else {
            run_wxc_config(case.config, &["--debug", "--experimental"])
        };

        let status = if command_matches(&result, &case) {
            "PASS"
        } else {
            failures.push(format!(
                "{} expected {}, got {:?}",
                case.config,
                expected_exit_description(&case),
                result.code
            ));
            "FAIL"
        };

        perf_entries.push(WslcPerfEntry {
            test: case.config.to_string(),
            description: case.description.to_string(),
            wall_time_ms: result.wall_time_ms,
            exit_code: result.code,
            status: status.to_string(),
        });

        if status == "FAIL" {
            println!(
                "--- stdout ---\n{}\n--- stderr ---\n{}",
                result.stdout, result.stderr
            );
        } else {
            println!("  PASS ({} ms)", result.wall_time_ms);
        }
    }

    write_wslc_perf_results(perf_entries);

    if !failures.is_empty() {
        panic!("WSLC E2E failures:\n{}", failures.join("\n"));
    }
}

fn command_matches(result: &CommandResult, case: &WslcCase) -> bool {
    if case.expect_non_zero {
        if result.code == Some(0) {
            return false;
        }
    } else if result.code != case.expected_exit {
        return false;
    }

    let Some(expected) = case.output_contains else {
        return true;
    };

    result
        .combined_output_with_decoded_base64()
        .contains(expected)
}

fn expected_exit_description(case: &WslcCase) -> String {
    if case.expect_non_zero {
        "non-zero exit".to_string()
    } else {
        format!("exit {}", case.expected_exit.unwrap_or(0))
    }
}

// ---------------------------------------------------------------------------
// Perf results output
// ---------------------------------------------------------------------------

fn write_wslc_perf_results(results: Vec<WslcPerfEntry>) {
    let output = WslcPerfOutput {
        commit: std::env::var("GITHUB_SHA").unwrap_or_else(|_| "local".to_string()),
        timestamp: SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|duration| duration.as_secs().to_string())
            .unwrap_or_else(|_| "unknown".to_string()),
        results,
    };
    let json =
        serde_json::to_string_pretty(&output).expect("wslc performance results should serialize");
    let path = repo_root().join("wslc-perf-results.json");
    std::fs::write(&path, json)
        .unwrap_or_else(|error| panic!("failed to write {}: {error}", path.display()));
    println!("Performance results written to {}", path.display());
}
