// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Build script for wxc — embeds Windows VersionInfo and copies NanVix binaries.

fn main() {
    // Under the `isolation_session` feature the IsoSession reg-free COM
    // manifest is fused into wxc-exec (mapping the two private activator CLSIDs
    // to the co-located `IsoSessionApp.dll`) and `IsoSessionApp.dll` is staged
    // next to the executable. Both are extracted from the pinned SDK nupkg.
    // This MUST share a single resource compile with the version info, so the
    // manifest is resolved first and handed to `embed_version_info_with_manifest`.
    #[cfg(all(windows, feature = "isolation_session"))]
    {
        match isosession::stage_and_resolve_manifest() {
            Some(manifest_xml) => {
                mxc_build_common::embed_version_info_with_manifest(
                    "MXC sandbox executor",
                    "wxc-exec.exe",
                    Some(&manifest_xml),
                );
            }
            None => {
                // nupkg lacks the reg-free payload (e.g. an inbox-only /
                // pre-repack package): build still succeeds; the Rust caller
                // falls back to inbox activation at runtime.
                mxc_build_common::embed_version_info("MXC sandbox executor", "wxc-exec.exe");
            }
        }
    }

    #[cfg(not(all(windows, feature = "isolation_session")))]
    mxc_build_common::embed_version_info("MXC sandbox executor", "wxc-exec.exe");

    #[cfg(windows)]
    check_test_prerequisites();

    #[cfg(all(windows, feature = "microvm"))]
    copy_nanvix_binaries();

    // Re-run prerequisite checks when PATH changes (e.g., after installing Python).
    #[cfg(windows)]
    println!("cargo:rerun-if-env-changed=PATH");
}

/// IsoSession reg-free COM wiring: extract `IsoSessionApp.dll` and the
/// `.comClass.manifest` from the pinned SDK nupkg, stage the DLL next to
/// `wxc-exec.exe`, and return the manifest XML for fusing into the exe.
///
/// The whole real-design activation path (see
/// `backends/isolation_session/common/src/regfree.rs`) depends on wxc-exec's
/// fused manifest redirecting the two private CLSIDs to this co-located DLL.
#[cfg(all(windows, feature = "isolation_session"))]
mod isosession {
    use std::io::Read;
    use std::path::{Path, PathBuf};

    /// Name of the reg-free COM manifest fragment inside the nupkg `runtime`
    /// folder (fused into wxc-exec so the private activator CLSIDs resolve to
    /// the co-located `IsoSessionApp.dll`).
    const COMCLASS_MANIFEST: &str = "IsoSessionApp.comClass.manifest";
    /// The in-proc activation shim that owns knowledge of the MSI runtime dir.
    const APP_DLL: &str = "IsoSessionApp.dll";

    /// Name of the pipeline-stamped runtime-version sidecar inside the nupkg
    /// `runtime` folder. `IsoSessionApp.dll` is version-agnostic at OS build
    /// time and reads this co-located token (e.g. `2026_08`) at load time to
    /// build its MSI reg key + fallback runtime dir. Staged next to the exe
    /// alongside the DLL so the co-located read works in the fused scenario.
    const VERSION_SIDECAR: &str = "IsoSessionApp.runtimeversion";

    /// Locate the nupkg, extract the App.dll (stage next to the exe) and the
    /// manifest fragment, and return the manifest XML. Returns `None` (with a
    /// `cargo:warning`) when the nupkg does not carry the reg-free payload, so
    /// the build degrades gracefully to inbox activation instead of failing.
    pub fn stage_and_resolve_manifest() -> Option<String> {
        let manifest_dir = std::env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR");

        // This crate lives at <repo>/src/core/wxc, so three `..` segments reach
        // the repo root where `external/` lives.
        let sdk_dir = Path::new(&manifest_dir)
            .join("..")
            .join("..")
            .join("..")
            .join("external")
            .join("windows-sdk")
            .join("isolation-session");

        let nupkg = match find_nupkg(&sdk_dir) {
            Some(p) => p,
            None => {
                println!(
                    "cargo:warning=isosession: no .nupkg under {} — skipping reg-free manifest fuse",
                    sdk_dir.display()
                );
                return None;
            }
        };
        println!("cargo:rerun-if-changed={}", nupkg.display());

        // Stage IsoSessionApp.dll next to the output exe (target/<profile>/).
        // Cargo puts the binary at OUT_DIR/../../.. .
        let out_dir = std::env::var("OUT_DIR").expect("OUT_DIR");
        let target_dir = Path::new(&out_dir)
            .parent()
            .and_then(|p| p.parent())
            .and_then(|p| p.parent())
            .expect("could not determine target dir from OUT_DIR");

        let app_dll = match extract_entry(&nupkg, APP_DLL) {
            Some(bytes) => bytes,
            None => {
                println!(
                    "cargo:warning=isosession: {} not found in {} — skipping reg-free manifest fuse (inbox fallback at runtime)",
                    APP_DLL,
                    nupkg.display()
                );
                return None;
            }
        };
        let dll_dst = target_dir.join(APP_DLL);
        std::fs::write(&dll_dst, &app_dll)
            .unwrap_or_else(|e| panic!("stage {} to {}: {e}", APP_DLL, dll_dst.display()));

        // Stage the pipeline-stamped runtime-version sidecar next to the DLL.
        // Best-effort: if the nupkg predates the stamping pipeline, the shim
        // falls back to its compile-time default version, so a missing sidecar
        // is a warning, not a fatal error, and does NOT skip the manifest fuse.
        match extract_entry(&nupkg, VERSION_SIDECAR) {
            Some(bytes) => {
                let sidecar_dst = target_dir.join(VERSION_SIDECAR);
                std::fs::write(&sidecar_dst, &bytes).unwrap_or_else(|e| {
                    panic!("stage {} to {}: {e}", VERSION_SIDECAR, sidecar_dst.display())
                });
            }
            None => {
                println!(
                    "cargo:warning=isosession: {} not found in {} — IsoSessionApp.dll will use its compile-time default runtime version",
                    VERSION_SIDECAR,
                    nupkg.display()
                );
            }
        }

        let manifest_bytes = match extract_entry(&nupkg, COMCLASS_MANIFEST) {
            Some(bytes) => bytes,
            None => {
                println!(
                    "cargo:warning=isosession: {} not found in {} — skipping reg-free manifest fuse",
                    COMCLASS_MANIFEST,
                    nupkg.display()
                );
                return None;
            }
        };
        let manifest_xml = String::from_utf8(manifest_bytes)
            .expect("IsoSessionApp.comClass.manifest is valid UTF-8");

        Some(manifest_xml)
    }

    /// Returns the lexicographically-last `*.nupkg` under `dir`.
    fn find_nupkg(dir: &Path) -> Option<PathBuf> {
        let mut hits: Vec<PathBuf> = std::fs::read_dir(dir)
            .ok()?
            .filter_map(|e| e.ok().map(|e| e.path()))
            .filter(|p| {
                p.extension()
                    .map(|x| x.eq_ignore_ascii_case("nupkg"))
                    .unwrap_or(false)
            })
            .collect();
        hits.sort();
        hits.into_iter().next_back()
    }

    /// Extract the nupkg (zip) entry whose file name matches `file_name`
    /// (case-insensitive, path-separator tolerant). Returns `None` if absent.
    fn extract_entry(nupkg: &Path, file_name: &str) -> Option<Vec<u8>> {
        let file = std::fs::File::open(nupkg)
            .unwrap_or_else(|e| panic!("open {}: {e}", nupkg.display()));
        let mut archive = zip::ZipArchive::new(file)
            .unwrap_or_else(|e| panic!("read zip {}: {e}", nupkg.display()));

        let want = file_name.to_ascii_lowercase();
        let entry_name = (0..archive.len()).find_map(|i| {
            let name = archive.by_index(i).ok()?.name().to_string();
            let leaf = name.rsplit(['/', '\\']).next().unwrap_or(&name);
            if leaf.to_ascii_lowercase() == want {
                Some(name)
            } else {
                None
            }
        })?;

        let mut entry = archive
            .by_name(&entry_name)
            .unwrap_or_else(|e| panic!("open zip entry {entry_name}: {e}"));
        let mut buf = Vec::new();
        entry
            .read_to_end(&mut buf)
            .unwrap_or_else(|e| panic!("read zip entry {entry_name}: {e}"));
        Some(buf)
    }
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

    // Stage the artifacts next to the executable and emit rerun triggers. All
    // of the staging logic (target-dir derivation, snapshot trust, copy/purge,
    // rerun emission) lives in the build-only `nanvix_build_common` crate.
    nanvix_build_common::stage_artifacts_next_to_exe(Path::new(&nanvix_bin_dir));
}
