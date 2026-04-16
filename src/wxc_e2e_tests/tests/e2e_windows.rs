// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Windows E2E integration tests.
//!
//! Each test invokes a PowerShell script from `test_scripts/` via `pwsh`.
//! Tests skip gracefully when prerequisites (binaries, admin, features) are missing.

use std::path::{Path, PathBuf};
use std::process::Command;

/// Locate the repository root (four levels up from this file's directory at compile time,
/// but at runtime we derive from the cargo manifest dir).
fn repo_root() -> PathBuf {
    // CARGO_MANIFEST_DIR points to src/wxc_e2e_tests/ during `cargo test`
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    manifest_dir
        .parent() // src/
        .and_then(|p| p.parent()) // repo root
        .expect("could not determine repo root")
        .to_path_buf()
}

fn test_scripts_dir() -> PathBuf {
    repo_root().join("test_scripts")
}

fn wxc_exe_path() -> PathBuf {
    let src_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("could not find src/")
        .to_path_buf();

    // Prefer debug build (matches default `cargo test` without --release)
    let debug_path = src_dir.join("target").join("debug").join("wxc-exec.exe");
    if debug_path.exists() {
        return debug_path;
    }

    let release_path = src_dir.join("target").join("release").join("wxc-exec.exe");
    if release_path.exists() {
        return release_path;
    }

    // Return the debug path even if it doesn't exist — callers check and skip
    debug_path
}

fn pwsh_available() -> bool {
    Command::new("pwsh")
        .arg("--version")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

/// Run a PS1 script and assert it exits successfully.
/// Returns `None` if a prerequisite is missing (test should skip).
fn run_ps1_script(script_name: &str) -> Option<std::process::Output> {
    if !pwsh_available() {
        println!("SKIPPED: pwsh not available");
        return None;
    }

    let script_path = test_scripts_dir().join(script_name);
    if !script_path.exists() {
        println!("SKIPPED: script not found: {}", script_path.display());
        return None;
    }

    let output = Command::new("pwsh")
        .args(["-NoProfile", "-NonInteractive", "-File"])
        .arg(&script_path)
        .output()
        .expect("failed to execute pwsh");

    Some(output)
}

fn assert_ps1_success(script_name: &str) {
    let Some(output) = run_ps1_script(script_name) else {
        return;
    };

    if !output.status.success() {
        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);
        panic!(
            "{} failed with exit code {:?}\n--- stdout ---\n{}\n--- stderr ---\n{}",
            script_name,
            output.status.code(),
            stdout,
            stderr
        );
    }
}

fn skip_if_no_wxc_exe() -> bool {
    let exe = wxc_exe_path();
    if !exe.exists() {
        println!(
            "SKIPPED: wxc-exec.exe not found at {} — build first",
            exe.display()
        );
        return true;
    }
    false
}

fn skip_if_no_test_driver() -> bool {
    let src_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("could not find src/")
        .to_path_buf();

    let debug_path = src_dir
        .join("target")
        .join("debug")
        .join("wxc-test-driver.exe");
    let release_path = src_dir
        .join("target")
        .join("release")
        .join("wxc-test-driver.exe");

    if !debug_path.exists() && !release_path.exists() {
        println!("SKIPPED: wxc-test-driver.exe not found — build first");
        return true;
    }
    false
}

fn skip_if_no_daemon() -> bool {
    let src_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("could not find src/")
        .to_path_buf();

    let debug_path = src_dir
        .join("target")
        .join("debug")
        .join("wxc-windows-sandbox-daemon.exe");
    let release_path = src_dir
        .join("target")
        .join("release")
        .join("wxc-windows-sandbox-daemon.exe");

    if !debug_path.exists() && !release_path.exists() {
        println!("SKIPPED: wxc-windows-sandbox-daemon.exe not found — build first");
        return true;
    }
    false
}

fn nanvix_binaries_present() -> bool {
    let exe = wxc_exe_path();
    let bin_dir = exe.parent().unwrap_or(Path::new("."));
    ["nanvixd.exe", "kernel.elf", "python.elf", "cpython-ramfs.img"]
        .iter()
        .all(|name| bin_dir.join(name).exists())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[test]
fn test_appcontainer_basic() {
    if skip_if_no_wxc_exe() {
        return;
    }
    assert_ps1_success("run_basicac_test.ps1");
}

#[test]
fn test_appcontainer_lpac() {
    if skip_if_no_wxc_exe() {
        return;
    }
    assert_ps1_success("run_lpacac_test.ps1");
}

#[test]
fn test_filesystem_bfs() {
    if skip_if_no_wxc_exe() {
        return;
    }
    assert_ps1_success("run_filesystem_bfs_test.ps1");
}

#[test]
fn test_filesystem_bfs_readonly() {
    if skip_if_no_wxc_exe() {
        return;
    }
    assert_ps1_success("run_filesystem_bfsreadonly_test.ps1");
}

#[test]
fn test_filesystem_bfs_spaces() {
    if skip_if_no_wxc_exe() {
        return;
    }
    assert_ps1_success("run_filesystem_bfs_spaces_test.ps1");
}

#[test]
fn test_pwsh_setlocation() {
    if skip_if_no_wxc_exe() {
        return;
    }
    assert_ps1_success("run_pwsh_test.ps1");
}

#[test]
fn test_test_configs() {
    if skip_if_no_test_driver() {
        return;
    }
    assert_ps1_success("run_test_configs.ps1");
}

#[test]
fn test_examples() {
    if skip_if_no_test_driver() {
        return;
    }
    assert_ps1_success("run_examples.ps1");
}

#[test]
fn test_microvm_basic() {
    if skip_if_no_wxc_exe() {
        return;
    }
    if !nanvix_binaries_present() {
        println!("SKIPPED: NanVix binaries not found next to wxc-exec.exe");
        return;
    }
    assert_ps1_success("run_microvm_basic_test.ps1");
}

#[test]
fn test_windows_sandbox() {
    if skip_if_no_wxc_exe() {
        return;
    }
    if skip_if_no_daemon() {
        return;
    }
    assert_ps1_success("run_windows_sandbox_tests.ps1");
}

#[test]
fn test_microvm_suite() {
    if skip_if_no_wxc_exe() {
        return;
    }
    if !nanvix_binaries_present() {
        println!("SKIPPED: NanVix binaries not found next to wxc-exec.exe");
        return;
    }
    assert_ps1_success("run_microvm_tests.ps1");
}

#[test]
fn test_appcontainer_proxy() {
    if skip_if_no_wxc_exe() {
        return;
    }
    assert_ps1_success("run_appcontainer_proxy_tests.ps1");
}

#[test]
#[ignore] // Stress test — run explicitly with `cargo test -p wxc_e2e_tests -- --ignored`
fn test_on_repeat() {
    if skip_if_no_wxc_exe() {
        return;
    }
    assert_ps1_success("run_on_repeat.ps1");
}
