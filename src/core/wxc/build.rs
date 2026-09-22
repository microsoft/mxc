// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Build script for wxc — embeds Windows VersionInfo and stages backend artifacts.

fn main() {
    mxc_build_common::embed_version_info("MXC sandbox executor", "wxc-exec.exe");

    #[cfg(windows)]
    check_test_prerequisites();

    #[cfg(feature = "microvm")]
    stage_nvx_for_target();

    // Delay-load winhvplatform.dll so WHP-less hosts don't crash before main().
    // CARGO_CFG_TARGET_* (not #[cfg]) because build.rs cfg gates are host, not target.
    #[cfg(feature = "hyperlight")]
    {
        let target_os = std::env::var("CARGO_CFG_TARGET_OS").unwrap_or_default();
        let target_arch = std::env::var("CARGO_CFG_TARGET_ARCH").unwrap_or_default();
        if target_os == "windows" && target_arch == "x86_64" {
            println!("cargo:rustc-link-arg=/DELAYLOAD:winhvplatform.dll");
            println!("cargo:rustc-link-lib=delayimp");
        }
    }

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

#[cfg(feature = "microvm")]
fn stage_nvx_for_target() {
    let target_os = std::env::var("CARGO_CFG_TARGET_OS").unwrap_or_default();
    let target_arch = std::env::var("CARGO_CFG_TARGET_ARCH").unwrap_or_default();
    let target_env = std::env::var("CARGO_CFG_TARGET_ENV").unwrap_or_default();

    let target = std::env::var("TARGET").expect("wxc build.rs: TARGET is not set by Cargo");
    let should_stage =
        nvx_build_common::should_stage_nvx(&target, &target_os, &target_arch, &target_env)
            .unwrap_or_else(|error| panic!("wxc build.rs: {error}"));
    if should_stage {
        copy_nvx_binaries();
    }
}

#[cfg(feature = "microvm")]
fn copy_nvx_binaries() {
    use std::path::Path;

    let nvx_bin_dir = std::env::var("DEP_NVX_BINARIES_BIN_DIR").unwrap_or_else(|error| {
        panic!(
            "wxc build.rs: DEP_NVX_BINARIES_BIN_DIR is required for the microvm feature: {error}"
        )
    });

    nvx_build_common::stage_artifacts_next_to_exe(Path::new(&nvx_bin_dir))
        .unwrap_or_else(|error| panic!("wxc build.rs: failed to stage NVX artifacts: {error}"));
}
