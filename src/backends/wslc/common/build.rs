// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Build script for wslc_common — downloads the WSLC SDK NuGet package and
//! copies wslcsdk.dll next to the final binary so it can be loaded at runtime.
//!
//! The SDK is resolved from:
//! 1. `WSLC_SDK_PATH` environment variable (if set, points to a directory
//!    containing `wslcsdk.dll`, or a `native/` subdirectory containing it).
//!    Use this for offline / air-gapped builds by pre-fetching the package.
//! 2. Otherwise, the `.nupkg` (pinned to `WSLC_SDK_VERSION`) is downloaded from
//!    the MxcDependencies Azure Artifacts feed and extracted into `OUT_DIR`.
//! 3. If the feed download fails, the vendored `.nupkg` checked into
//!    `external/wslc-sdk/` is used as a fallback. This vendored copy is a
//!    transitional safety net and is expected to be removed once the feed is
//!    proven in all official build environments.

use std::path::{Path, PathBuf};
use std::process::Command;

/// Pinned WSLC SDK version. Override with the `WSLC_SDK_VERSION` env var.
const WSLC_SDK_VERSION: &str = "2.9.3";

/// Direct anonymous content URL for a package version on the public
/// MxcDependencies Azure Artifacts feed (mirrors nuget.org; reachable from the
/// 1ES build pool, which does not allowlist nuget.org directly).
fn feed_url(version: &str) -> String {
    format!(
        "https://pkgs.dev.azure.com/shine-oss/mxc/_apis/packaging/feeds/MxcDependencies/\
         nuget/packages/Microsoft.WSL.Containers/versions/{version}/content?api-version=7.1-preview.1"
    )
}

fn main() {
    // Skip nupkg extraction and DLL copy unless the `link-wslcsdk` feature is
    // enabled. Without this gate, workspace builds would extract the nupkg
    // even when no binary depends on wslc_common.
    if std::env::var("CARGO_FEATURE_LINK_WSLCSDK").is_err() {
        return;
    }

    // WSLC SDK is Windows-only — skip entirely on other platforms.
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() != Ok("windows") {
        return;
    }

    let arch = match std::env::var("CARGO_CFG_TARGET_ARCH").as_deref() {
        Ok("x86_64") => "x64",
        Ok("aarch64") => "arm64",
        _ => {
            println!("cargo:warning=WSLC SDK: unsupported target architecture, skipping");
            return;
        }
    };

    let version =
        std::env::var("WSLC_SDK_VERSION").unwrap_or_else(|_| WSLC_SDK_VERSION.to_string());

    println!("cargo:rerun-if-env-changed=WSLC_SDK_PATH");
    println!("cargo:rerun-if-env-changed=WSLC_SDK_VERSION");

    let sdk_dir = if let Ok(path) = std::env::var("WSLC_SDK_PATH") {
        PathBuf::from(path)
    } else {
        // Download the nupkg from the MxcDependencies feed and extract it. If
        // the download fails (e.g. no network access to the feed), fall back to
        // the vendored copy checked into external/wslc-sdk/.
        match download_and_extract(&version, arch) {
            Ok(path) => path,
            Err(e) => {
                println!(
                    "cargo:warning=WSLC SDK: feed download failed ({e}); trying vendored copy"
                );
                match extract_vendored(&version, arch) {
                    Ok(path) => path,
                    Err(e2) => {
                        println!("cargo:warning=WSLC SDK: {e2}");
                        return;
                    }
                }
            }
        }
    };

    // The SDK is loaded at runtime via libloading — no static linking.
    // We only need to copy wslcsdk.dll next to the final binary so it
    // can be found by LoadLibrary at runtime.
    let dll_src = match find_dll(&sdk_dir) {
        Some(p) => p,
        None => {
            println!(
                "cargo:warning=WSLC SDK: wslcsdk.dll not found under {}. Runtime will fail to load.",
                sdk_dir.display()
            );
            return;
        }
    };

    let out_dir = PathBuf::from(std::env::var("OUT_DIR").unwrap());
    if let Some(profile_dir) = out_dir
        .parent()
        .and_then(|p| p.parent())
        .and_then(|p| p.parent())
    {
        let dll_dst = profile_dir.join("wslcsdk.dll");
        if let Err(e) = std::fs::copy(&dll_src, &dll_dst) {
            println!(
                "cargo:warning=WSLC SDK: failed to copy DLL to output dir: {}",
                e
            );
        }
    }
}

/// Locate `wslcsdk.dll` under `dir`, checking both a flat layout and the NuGet
/// `native/` runtime subdirectory (the 2.9.x package places the DLL under
/// `runtimes/win-<arch>/native/`).
fn find_dll(dir: &Path) -> Option<PathBuf> {
    let direct = dir.join("wslcsdk.dll");
    if direct.exists() {
        return Some(direct);
    }
    let native = dir.join("native").join("wslcsdk.dll");
    if native.exists() {
        return Some(native);
    }
    None
}

/// Download the WSLC SDK nupkg from the MxcDependencies feed and extract it,
/// returning the `runtimes/win-<arch>` directory (which contains
/// `native/wslcsdk.dll`).
fn download_and_extract(version: &str, arch: &str) -> Result<PathBuf, String> {
    let out_dir = PathBuf::from(std::env::var("OUT_DIR").unwrap());
    let extract_dir = out_dir.join("wslc-sdk").join(version);
    let runtime_dir = extract_dir.join("runtimes").join(format!("win-{}", arch));

    // Skip if a previous build already extracted this version.
    if find_dll(&runtime_dir).is_some() {
        return Ok(runtime_dir);
    }

    let nupkg_path = out_dir.join(format!("Microsoft.WSL.Containers.{}.nupkg", version));
    if !nupkg_path.exists() {
        download(&feed_url(version), &nupkg_path)?;
    }

    extract_zip(&nupkg_path, &extract_dir)?;

    if find_dll(&runtime_dir).is_some() {
        println!(
            "cargo:warning=WSLC SDK: downloaded and extracted v{} from the MxcDependencies feed",
            version
        );
        Ok(runtime_dir)
    } else {
        Err(format!(
            "wslcsdk.dll not found in nupkg at runtimes/win-{}/native/",
            arch
        ))
    }
}

/// Fallback: extract the vendored `.nupkg` checked into `external/wslc-sdk/`
/// when the feed download is unavailable (e.g. offline builds without
/// `WSLC_SDK_PATH` set). This vendored copy is a transitional safety net and is
/// expected to be removed once the feed is proven in all official build
/// environments.
fn extract_vendored(version: &str, arch: &str) -> Result<PathBuf, String> {
    let manifest_dir = PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").unwrap());
    // wslc_common lives at src/backends/wslc/common → repo root is four levels up.
    let nupkg = manifest_dir
        .join("../../../../external/wslc-sdk")
        .join(format!("Microsoft.WSL.Containers.{version}.nupkg"));
    if !nupkg.exists() {
        return Err(format!("vendored nupkg not found at {}", nupkg.display()));
    }
    println!("cargo:rerun-if-changed={}", nupkg.display());

    let out_dir = PathBuf::from(std::env::var("OUT_DIR").unwrap());
    let extract_dir = out_dir.join("wslc-sdk").join(version);
    let runtime_dir = extract_dir.join("runtimes").join(format!("win-{}", arch));
    if find_dll(&runtime_dir).is_some() {
        return Ok(runtime_dir);
    }

    extract_zip(&nupkg, &extract_dir)?;

    if find_dll(&runtime_dir).is_some() {
        println!("cargo:warning=WSLC SDK: extracted vendored v{version} from external/wslc-sdk");
        Ok(runtime_dir)
    } else {
        Err(format!(
            "wslcsdk.dll not found in vendored nupkg at runtimes/win-{}/native/",
            arch
        ))
    }
}

/// Download `url` to `dest` using `curl` (present on Windows 10+ and on the
/// build agents). For offline / air-gapped builds, set `WSLC_SDK_PATH` to a
/// pre-fetched SDK directory to bypass the download entirely.
fn download(url: &str, dest: &Path) -> Result<(), String> {
    let status = Command::new("curl")
        .args([
            "--fail",
            "--silent",
            "--show-error",
            "--location",
            "--output",
        ])
        .arg(dest)
        .arg(url)
        .status()
        .map_err(|e| {
            format!(
                "failed to invoke curl to download the WSLC SDK: {}. \
                 Set WSLC_SDK_PATH to a pre-fetched SDK directory for offline builds.",
                e
            )
        })?;
    if !status.success() {
        return Err(format!(
            "curl failed to download the WSLC SDK from {} ({}). \
             Set WSLC_SDK_PATH to a pre-fetched SDK directory for offline builds.",
            url, status
        ));
    }
    Ok(())
}

/// Extract a `.nupkg` (a zip archive) into `extract_dir`.
fn extract_zip(nupkg_path: &Path, extract_dir: &Path) -> Result<(), String> {
    let file = std::fs::File::open(nupkg_path)
        .map_err(|e| format!("Cannot open {}: {}", nupkg_path.display(), e))?;
    let mut archive =
        zip::ZipArchive::new(file).map_err(|e| format!("Cannot read nupkg as zip: {}", e))?;

    for i in 0..archive.len() {
        let mut entry = archive
            .by_index(i)
            .map_err(|e| format!("Zip entry error: {}", e))?;
        let entry_path = match entry.enclosed_name() {
            Some(p) => extract_dir.join(p),
            None => continue,
        };

        if entry.is_dir() {
            let _ = std::fs::create_dir_all(&entry_path);
        } else {
            if let Some(parent) = entry_path.parent() {
                let _ = std::fs::create_dir_all(parent);
            }
            let mut out_file = std::fs::File::create(&entry_path)
                .map_err(|e| format!("Cannot create {}: {}", entry_path.display(), e))?;
            std::io::copy(&mut entry, &mut out_file)
                .map_err(|e| format!("Cannot write {}: {}", entry_path.display(), e))?;
        }
    }

    Ok(())
}
