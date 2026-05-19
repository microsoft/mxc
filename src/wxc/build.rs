// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Build script for wxc — copies NanVix binaries next to the output executable.

fn main() {
    #[cfg(windows)]
    check_test_prerequisites();

    #[cfg(all(windows, feature = "microvm"))]
    copy_nanvix_binaries();

    // Always emit rerun-if-changed so Cargo doesn't re-run unnecessarily.
    println!("cargo:rerun-if-changed=build.rs");
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
    use std::fs;
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

    let src_dir = Path::new(&nanvix_bin_dir);

    for name in nanvix_common::REQUIRED_BINARIES {
        let src = src_dir.join(name);
        let dst = target_dir.join(name);

        if src.exists() && (!dst.exists() || is_newer(&src, &dst)) {
            eprintln!(
                "wxc build.rs: copying {} -> {}",
                src.display(),
                dst.display()
            );
            if let Err(e) = fs::copy(&src, &dst) {
                // Remove partial copy to avoid leaving a dangling file
                let _ = fs::remove_file(&dst);
                eprintln!("wxc build.rs: WARNING: failed to copy {}: {}", name, e);
            }
        }
    }

    // Re-run when source binaries change (detected via nanvix_binaries rebuild)
    println!("cargo:rerun-if-env-changed=DEP_NANVIX_BINARIES_BIN_DIR");
}

#[cfg(all(windows, feature = "microvm"))]
fn is_newer(src: &std::path::Path, dst: &std::path::Path) -> bool {
    let src_time = src.metadata().and_then(|m| m.modified()).ok();
    let dst_time = dst.metadata().and_then(|m| m.modified()).ok();
    match (src_time, dst_time) {
        (Some(s), Some(d)) => s > d,
        _ => true,
    }
}
