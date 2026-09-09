//! Build script for wxc — embeds Windows VersionInfo and stages runtime assets.

fn main() {
    #[cfg(all(windows, feature = "isolation_session"))]
    reconcile_isolation_session_runtime();

    mxc_build_common::embed_version_info("MXC sandbox executor", "wxc-exec.exe");

    #[cfg(windows)]
    check_test_prerequisites();

    #[cfg(all(windows, feature = "microvm"))]
    copy_nanvix_binaries();
}

#[cfg(all(windows, feature = "isolation_session"))]
fn reconcile_isolation_session_runtime() {
    let out_dir = std::path::PathBuf::from(std::env::var("OUT_DIR").expect("OUT_DIR"));
    let target_dir = out_dir
        .parent()
        .and_then(|path| path.parent())
        .and_then(|path| path.parent())
        .expect("could not determine target directory from OUT_DIR");

    // Feature configurations share the final profile directory but have
    // separate build-script fingerprints. Force this script to reconcile the
    // shared payload whenever Cargo is invoked.
    println!(
        "cargo:rerun-if-changed={}",
        target_dir.join(".isosession-payload-state").display()
    );

    #[cfg(feature = "isolation_session_lifted")]
    mxc_build_common::isolation_session_sdk::stage_runtime()
        .unwrap_or_else(|e| panic!("IsolationSession SDK staging failed: {e}"));

    #[cfg(not(feature = "isolation_session_lifted"))]
    for file_name in [
        "IsoSessionApp.dll",
        "IsoSession.manifest",
        "IsoSessionApp.runtimeversion",
    ] {
        let path = target_dir.join(file_name);
        match std::fs::remove_file(&path) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => panic!("remove stale lifted payload {}: {error}", path.display()),
        }
    }
}

/// Emit build warnings when E2E test prerequisites are missing or
/// misconfigured. These are non-blocking — the build succeeds regardless.
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

    nanvix_build_common::stage_artifacts_next_to_exe(Path::new(&nanvix_bin_dir));
}
