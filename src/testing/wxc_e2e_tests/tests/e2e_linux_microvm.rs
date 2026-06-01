// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Linux MicroVM (NanVix/KVM) E2E integration tests.
//!
//! These tests mirror the Windows MicroVM E2E suite in `e2e_windows.rs` and
//! invoke `lxc-exec` directly with the `microvm` containment backend.
//! Tests skip gracefully when prerequisites (binaries, KVM) are missing.

use std::sync::OnceLock;
use std::time::{SystemTime, UNIX_EPOCH};

use serde::Serialize;
use wxc_e2e_tests::{
    has_kvm, has_lxc_exe, has_lxc_nanvix_binaries, repo_root, run_lxc_config, test_configs_dir,
    CommandResult,
};

static HAS_LXC_EXE: OnceLock<bool> = OnceLock::new();
static HAS_LXC_NANVIX: OnceLock<bool> = OnceLock::new();
static HAS_KVM: OnceLock<bool> = OnceLock::new();

fn cached_has_lxc_exe() -> bool {
    *HAS_LXC_EXE.get_or_init(has_lxc_exe)
}

fn cached_has_lxc_nanvix() -> bool {
    *HAS_LXC_NANVIX.get_or_init(has_lxc_nanvix_binaries)
}

fn cached_has_kvm() -> bool {
    *HAS_KVM.get_or_init(has_kvm)
}

/// Guard: skip test if prerequisites are missing.
fn skip_unless_ready() -> bool {
    if !cached_has_lxc_exe() {
        return false;
    }
    if !cached_has_lxc_nanvix() {
        return false;
    }
    if !cached_has_kvm() {
        return false;
    }
    true
}

// ---------------------------------------------------------------------------
// Individual tests (mirrors microvm_basic on Windows)
// ---------------------------------------------------------------------------

#[test]
fn test_microvm_hello() {
    if !skip_unless_ready() {
        return;
    }
    let result = run_lxc_config("microvm_hello_linux.json", &["--debug", "--experimental"]);
    assert_eq!(
        result.code,
        Some(0),
        "expected exit 0, got {:?}\nstdout: {}\nstderr: {}",
        result.code,
        result.stdout,
        result.stderr
    );
    let combined = format!("{}\n{}", result.stdout, result.stderr);
    assert!(
        combined.contains("sum=100"),
        "output missing 'sum=100'\ncombined: {}",
        combined
    );
}

// ---------------------------------------------------------------------------
// Full microvm suite (mirrors test_microvm_suite on Windows)
// ---------------------------------------------------------------------------

#[derive(Debug)]
struct MicrovmCase {
    config: &'static str,
    expected_exit: Option<i32>,
    description: &'static str,
    output_contains: Option<&'static str>,
    expect_non_zero: bool,
}

#[derive(Debug, Serialize)]
struct MicrovmPerfOutput {
    commit: String,
    timestamp: String,
    results: Vec<MicrovmPerfEntry>,
}

#[derive(Debug, Serialize)]
struct MicrovmPerfEntry {
    test: String,
    description: String,
    wall_time_ms: u128,
    exit_code: Option<i32>,
    status: String,
}

#[test]
fn test_microvm_suite() {
    if !skip_unless_ready() {
        return;
    }
    microvm_suite();
}

fn microvm_suite() {
    let cases = [
        MicrovmCase {
            config: "microvm_hello_linux.json",
            expected_exit: Some(0),
            description: "Hello world",
            output_contains: Some("sum=100"),
            expect_non_zero: false,
        },
        MicrovmCase {
            config: "microvm_exit_code_linux.json",
            expected_exit: Some(42),
            description: "Exit code propagation",
            output_contains: None,
            expect_non_zero: false,
        },
        MicrovmCase {
            config: "microvm_multiline_linux.json",
            expected_exit: Some(0),
            description: "Multi-line script (fibonacci)",
            output_contains: Some("fib("),
            expect_non_zero: false,
        },
        MicrovmCase {
            config: "microvm_stdlib_linux.json",
            expected_exit: Some(0),
            description: "Stdlib (json, math, hashlib)",
            output_contains: Some("pi"),
            expect_non_zero: false,
        },
        MicrovmCase {
            config: "microvm_large_output_linux.json",
            expected_exit: Some(0),
            description: "Large stdout (1000 lines)",
            output_contains: Some("line 999"),
            expect_non_zero: false,
        },
        MicrovmCase {
            config: "microvm_error_linux.json",
            expected_exit: Some(1),
            description: "Python exception",
            output_contains: Some("ValueError"),
            expect_non_zero: false,
        },
        MicrovmCase {
            config: "microvm_timeout_linux.json",
            expected_exit: None,
            description: "Timeout kills VM",
            output_contains: None,
            expect_non_zero: true,
        },
    ];

    let mut perf_entries = Vec::new();
    let mut failures = Vec::new();

    for case in cases {
        let config_path = test_configs_dir().join(case.config);
        if !config_path.exists() {
            println!("SKIPPED: config not found: {}", config_path.display());
            continue;
        }

        println!("--- {} ({}) ---", case.description, case.config);
        let result = run_lxc_config(case.config, &["--debug", "--experimental"]);
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

        perf_entries.push(MicrovmPerfEntry {
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

    write_microvm_perf_results(perf_entries);

    if !failures.is_empty() {
        panic!("MicroVM Linux E2E failures:\n{}", failures.join("\n"));
    }
}

fn command_matches(result: &CommandResult, case: &MicrovmCase) -> bool {
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

fn expected_exit_description(case: &MicrovmCase) -> String {
    if case.expect_non_zero {
        "non-zero exit".to_string()
    } else {
        format!("exit {}", case.expected_exit.unwrap_or(0))
    }
}

// ---------------------------------------------------------------------------
// Perf results output
// ---------------------------------------------------------------------------

fn write_microvm_perf_results(results: Vec<MicrovmPerfEntry>) {
    let output = MicrovmPerfOutput {
        commit: std::env::var("GITHUB_SHA").unwrap_or_else(|_| "local".to_string()),
        timestamp: SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|duration| duration.as_secs().to_string())
            .unwrap_or_else(|_| "unknown".to_string()),
        results,
    };
    let json = serde_json::to_string_pretty(&output)
        .expect("microvm performance results should serialize");
    let path = repo_root().join("microvm-perf-results-linux.json");
    std::fs::write(&path, json)
        .unwrap_or_else(|error| panic!("failed to write {}: {error}", path.display()));
    println!("Performance results written to {}", path.display());
}

// ---------------------------------------------------------------------------
// Stress tests (run_on_repeat — ignored by default)
// ---------------------------------------------------------------------------

#[test]
#[ignore]
fn test_microvm_run_on_repeat() {
    if !skip_unless_ready() {
        return;
    }

    const ITERATIONS: u32 = 10;
    let mut failures = Vec::new();

    for i in 0..ITERATIONS {
        let result = run_lxc_config("microvm_hello_linux.json", &["--experimental"]);
        if result.code != Some(0) {
            failures.push(format!("iteration {}: exit {:?}", i, result.code));
        }
    }

    if !failures.is_empty() {
        panic!(
            "MicroVM repeat test: {}/{} failures:\n{}",
            failures.len(),
            ITERATIONS,
            failures.join("\n")
        );
    }
}
