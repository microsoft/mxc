// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Build script for wxc - embeds Windows VersionInfo and stages runtime assets.

#[path = "../../mxc-sdk/build/build_mxc_build_common.rs"]
mod mxc_build_common;

fn main() {
    #[cfg(all(windows, feature = "isolation_session"))]
    stage_isolation_session_runtime();

    mxc_build_common::embed_version_info("MXC sandbox executor", "wxc-exec.exe");

    #[cfg(windows)]
    check_test_prerequisites();

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

    #[cfg(windows)]
    println!("cargo:rerun-if-env-changed=PATH");
}

#[cfg(all(windows, feature = "isolation_session"))]
fn stage_isolation_session_runtime() {
    let manifest_dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let sdk_dir = manifest_dir
        .join("..")
        .join("..")
        .join("mxc-sdk")
        .join("build")
        .join("isolation_session_bindings");
    let _ = mxc_build_common::stage_isolation_session_runtime(&sdk_dir);
}

#[cfg(windows)]
fn check_test_prerequisites() {
    use std::process::Command;

    let python_ok = Command::new("where.exe")
        .arg("python.exe")
        .output()
        .ok()
        .and_then(|output| {
            if !output.status.success() {
                return None;
            }
            let stdout = String::from_utf8_lossy(&output.stdout).to_string();
            Some(stdout.lines().next().unwrap_or("").to_string())
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
