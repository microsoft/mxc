// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Build script for wxc — embeds Windows VersionInfo and copies NanVix binaries.

fn main() {
    mxc_build_common::embed_version_info("MXC sandbox executor", "wxc-exec.exe");

    #[cfg(windows)]
    check_test_prerequisites();

    #[cfg(all(windows, feature = "microvm"))]
    copy_nanvix_binaries();

    // Re-run prerequisite checks when PATH changes (e.g., after installing Python).
    #[cfg(windows)]
    println!("cargo:rerun-if-env-changed=PATH");
}

/// Emit build warnings when E2E test prerequisites are missing or
/// misconfigured. These are non-blocking — the build succeeds regardless.
#[cfg(windows)]
fn check_test_prerequisites() {
    use std::process::Command;

    // Check Python
    let python_ok = Command::new("where.exe")
        .arg("python.exe")
        .output()
        .ok()
        .and_then(|o| {
            if !o.status.success() {
                return None;
            }
            let stdout = String::from_utf8_lossy(&o.stdout).to_string();
            let first = stdout.lines().next().unwrap_or("").to_string();
            Some(first)
        });

    match python_ok {
        None => {
            println!(
                "cargo:warning=python.exe not found. E2E tests require a system-wide Python install."
            );
            println!(
                "cargo:warning=Fix: Run scripts\\setup-test-prereqs.ps1 (elevated) or: winget install Python.Python.3.12 --scope machine"
            );
        }
        Some(ref path) if path.to_ascii_lowercase().contains("windowsapps") => {
            println!("cargo:warning=python.exe resolves to a Store alias. Store aliases cannot be launched inside sandbox containers.");
            println!(
                "cargo:warning=Fix: Run scripts\\setup-test-prereqs.ps1 (elevated) or disable App Execution Aliases for Python"
            );
        }
        _ => {}
    }

    // Check pwsh at the expected install path (test configs use a hardcoded path)
    const PWSH_PATH: &str = r"C:\Program Files\PowerShell\7\pwsh.exe";
    if !std::path::Path::new(PWSH_PATH).exists() {
        println!(
            "cargo:warning=PowerShell 7 not found at {PWSH_PATH}. pwsh sandbox tests will fail."
        );
        println!(
            "cargo:warning=Fix: Run scripts\\setup-test-prereqs.ps1 (elevated) or install PowerShell 7"
        );
    }
}

#[cfg(all(windows, feature = "microvm"))]
fn copy_nanvix_binaries() {
    use std::path::Path;

    let nanvix_bin_dir = match std::env::var("DEP_NANVIX_BINARIES_BIN_DIR") {
        Ok(dir) => dir,
        Err(_) => {
            eprintln!("wxc build.rs: DEP_NANVIX_BINARIES_BIN_DIR not set, skipping copy");
            return;
        }
    };

    // Cargo puts the output binary in OUT_DIR/../../.. (target/<profile>/)
    let out_dir = std::env::var("OUT_DIR").unwrap();
    let target_dir = Path::new(&out_dir)
        .parent()
        .and_then(|p| p.parent())
        .and_then(|p| p.parent());

    let target_dir = match target_dir {
        Some(d) => d,
        None => {
            eprintln!("wxc build.rs: could not determine target dir from OUT_DIR");
            return;
        }
    };

    // WHP snapshots from a prefetched (externally supplied) directory are not
    // covered by checksums.json, so they must not be trusted/copied; the
    // producer reports this via `cargo:PREFETCHED`. Default to trusting
    // (online build) when the flag is absent.
    let trust_snapshots = std::env::var("DEP_NANVIX_BINARIES_PREFETCHED")
        .map(|v| v != "1")
        .unwrap_or(true);

    nanvix_common::copy_artifacts_to_target(
        Path::new(&nanvix_bin_dir),
        target_dir,
        trust_snapshots,
    );

    // Re-run when the source path changes (detected via nanvix_binaries
    // rebuild) and when the source artifacts themselves change in place (e.g.
    // an offline NANVIX_BIN prefetch dir updated at the same path).
    nanvix_common::emit_rerun_for_copied_artifacts(Path::new(&nanvix_bin_dir));
    println!("cargo:rerun-if-env-changed=DEP_NANVIX_BINARIES_BIN_DIR");
    println!("cargo:rerun-if-env-changed=DEP_NANVIX_BINARIES_PREFETCHED");
}
