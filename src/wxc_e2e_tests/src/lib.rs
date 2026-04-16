// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Shared helpers for MXC end-to-end integration tests.
//!
//! Tests live in `tests/e2e_windows.rs`, `tests/e2e_sdk.rs`, and `tests/e2e_cli.rs`.

use std::path::{Path, PathBuf};
use std::process::Command;

// ---------------------------------------------------------------------------
// Path helpers
// ---------------------------------------------------------------------------

/// Locate the repository root.
/// `CARGO_MANIFEST_DIR` points to `src/wxc_e2e_tests/` during `cargo test`.
pub fn repo_root() -> PathBuf {
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    manifest_dir
        .parent() // src/
        .and_then(|p| p.parent()) // repo root
        .expect("could not determine repo root")
        .to_path_buf()
}

pub fn test_scripts_dir() -> PathBuf {
    repo_root().join("test_scripts")
}

fn src_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("could not find src/")
        .to_path_buf()
}

// ---------------------------------------------------------------------------
// Build-mode detection
// ---------------------------------------------------------------------------

/// Whether the test binary was compiled in release mode.
pub fn is_release_mode() -> bool {
    !cfg!(debug_assertions)
}

/// The target triple for the current platform (used for cross-compiled paths).
fn current_triple() -> &'static str {
    if cfg!(all(target_os = "windows", target_arch = "x86_64")) {
        "x86_64-pc-windows-msvc"
    } else if cfg!(all(target_os = "windows", target_arch = "aarch64")) {
        "aarch64-pc-windows-msvc"
    } else {
        ""
    }
}

/// Search for a binary in the target directory, checking multiple locations.
///
/// Search order prefers the profile matching the current build mode, then falls
/// back to the other profile. For each profile, the plain `target/<profile>/`
/// path is checked before the triple-prefixed `target/<triple>/<profile>/` path.
pub fn find_binary(name: &str) -> Option<PathBuf> {
    let src = src_dir();
    let (primary, fallback) = if is_release_mode() {
        ("release", "debug")
    } else {
        ("debug", "release")
    };
    let triple = current_triple();

    let mut candidates = vec![src.join("target").join(primary).join(name)];
    if !triple.is_empty() {
        candidates.push(src.join("target").join(triple).join(primary).join(name));
    }
    candidates.push(src.join("target").join(fallback).join(name));
    if !triple.is_empty() {
        candidates.push(src.join("target").join(triple).join(fallback).join(name));
    }

    candidates.into_iter().find(|p| p.exists())
}

// ---------------------------------------------------------------------------
// Prerequisite checks (has_* pattern — returns true when present)
// ---------------------------------------------------------------------------

pub fn has_wxc_exe() -> bool {
    match find_binary("wxc-exec.exe") {
        Some(p) => {
            println!("Using wxc-exec.exe at {}", p.display());
            true
        }
        None => {
            println!("SKIPPED: wxc-exec.exe not found — build first");
            false
        }
    }
}

pub fn has_test_driver() -> bool {
    match find_binary("wxc-test-driver.exe") {
        Some(p) => {
            println!("Using wxc-test-driver.exe at {}", p.display());
            true
        }
        None => {
            println!("SKIPPED: wxc-test-driver.exe not found — build first");
            false
        }
    }
}

pub fn has_daemon() -> bool {
    match find_binary("wxc-windows-sandbox-daemon.exe") {
        Some(p) => {
            println!("Using daemon at {}", p.display());
            true
        }
        None => {
            println!("SKIPPED: wxc-windows-sandbox-daemon.exe not found — build first");
            false
        }
    }
}

pub fn has_nanvix_binaries() -> bool {
    let Some(exe) = find_binary("wxc-exec.exe") else {
        return false;
    };
    let bin_dir = exe.parent().unwrap_or(Path::new("."));
    let present = ["nanvixd.exe", "kernel.elf", "python.elf", "cpython-ramfs.img"]
        .iter()
        .all(|name| bin_dir.join(name).exists());
    if !present {
        println!("SKIPPED: NanVix binaries not found next to wxc-exec.exe");
    }
    present
}

pub fn has_pwsh() -> bool {
    let available = Command::new("pwsh")
        .arg("--version")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false);
    if !available {
        println!("SKIPPED: pwsh not available");
    }
    available
}

pub fn has_node() -> bool {
    let available = Command::new("node")
        .arg("--version")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false);
    if !available {
        println!("SKIPPED: node not available");
    }
    available
}

pub fn has_npm() -> bool {
    let available = Command::new("npm")
        .arg("--version")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false);
    if !available {
        println!("SKIPPED: npm not available");
    }
    available
}

// ---------------------------------------------------------------------------
// Bin directory helper
// ---------------------------------------------------------------------------

/// Return the directory containing build output binaries.
///
/// Searches for any known binary (`wxc-exec.exe`, `wxc-test-driver.exe`,
/// `wxc-windows-sandbox-daemon.exe`) and returns the parent directory of the
/// first match. This ensures the Rust test harness and the PS1 scripts agree
/// on where binaries live — even for triple-prefixed target directories.
pub fn bin_dir() -> Option<PathBuf> {
    find_binary("wxc-exec.exe")
        .or_else(|| find_binary("wxc-test-driver.exe"))
        .or_else(|| find_binary("wxc-windows-sandbox-daemon.exe"))
        .and_then(|p| p.parent().map(|p| p.to_path_buf()))
}

// ---------------------------------------------------------------------------
// PS1 script runner
// ---------------------------------------------------------------------------

/// Run a PS1 script and return its output.
///
/// Returns `None` if pwsh is unavailable or the script doesn't exist (test
/// should skip). Automatically passes `-Release` when built in release mode
/// and `-BinDir` when a binary directory is found.
pub fn run_ps1_script(script_name: &str) -> Option<std::process::Output> {
    if !has_pwsh() {
        return None;
    }

    let script_path = test_scripts_dir().join(script_name);
    if !script_path.exists() {
        println!("SKIPPED: script not found: {}", script_path.display());
        return None;
    }

    let mut cmd = Command::new("pwsh");
    cmd.args(["-NoProfile", "-NonInteractive", "-File"])
        .arg(&script_path);

    if is_release_mode() {
        cmd.arg("-Release");
    }

    if let Some(dir) = bin_dir() {
        cmd.args(["-BinDir", &dir.to_string_lossy()]);
    }

    let output = cmd.output().expect("failed to execute pwsh");
    Some(output)
}

/// Run a PS1 script and panic if it fails.
pub fn assert_ps1_success(script_name: &str) {
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
