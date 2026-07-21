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
//!
//! Both the downloaded and vendored packages are verified against a pinned
//! SHA-256 before extraction (see `expected_sha256`). Downloads and extractions
//! are staged in temporary locations and published atomically, so an
//! interrupted transfer/unpack can never poison the `OUT_DIR` cache. When the
//! `link-wslcsdk` feature is enabled the build fails hard if the SDK cannot be
//! acquired, rather than silently producing a binary that can't load the DLL.

use sha2::{Digest, Sha256};
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
                        // The `link-wslcsdk` feature is explicitly enabled, so a
                        // missing SDK is a hard error: failing here prevents CI
                        // from publishing a green binary that cannot load the
                        // DLL at runtime. Set WSLC_SDK_PATH for offline builds.
                        panic!(
                            "WSLC SDK acquisition failed with the `link-wslcsdk` feature \
                             enabled: feed download failed ({e}) and the vendored fallback \
                             failed ({e2}). Set WSLC_SDK_PATH to a pre-fetched SDK directory \
                             for offline builds."
                        );
                    }
                }
            }
        }
    };

    // The SDK is loaded at runtime via libloading — no static linking.
    // We only need to copy wslcsdk.dll next to the final binary so it
    // can be found by LoadLibrary at runtime.
    let dll_src = find_dll(&sdk_dir).unwrap_or_else(|| {
        panic!(
            "WSLC SDK: wslcsdk.dll not found under {}. Cannot build with the \
             `link-wslcsdk` feature enabled.",
            sdk_dir.display()
        )
    });

    let out_dir = PathBuf::from(std::env::var("OUT_DIR").unwrap());
    let profile_dir = out_dir
        .parent()
        .and_then(|p| p.parent())
        .and_then(|p| p.parent())
        .unwrap_or_else(|| {
            panic!("WSLC SDK: cannot resolve the build profile output directory from OUT_DIR")
        });
    let dll_dst = profile_dir.join("wslcsdk.dll");
    if let Err(e) = std::fs::copy(&dll_src, &dll_dst) {
        panic!(
            "WSLC SDK: failed to copy wslcsdk.dll to {}: {}",
            dll_dst.display(),
            e
        );
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

    // Verify integrity before extracting: a downloaded native DLL that gets
    // loaded into the process must match a known-good hash (defends against a
    // compromised/mutated feed or a redirected download).
    verify_sha256(&nupkg_path, version)?;

    extract_zip_atomic(&nupkg_path, &extract_dir)?;

    if find_dll(&runtime_dir).is_some() {
        // Success path: keep it out of the default build output. Plain
        // `println!` only surfaces under `cargo build -vv`, so this doesn't add
        // a spurious `cargo:warning` to every clean/CI build.
        println!(
            "WSLC SDK: downloaded and extracted v{} from the MxcDependencies feed",
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

    // The vendored copy is content-reviewed in-repo, but verify it too so a
    // corrupted checkout is caught before its DLL is loaded.
    verify_sha256(&nupkg, version)?;

    extract_zip_atomic(&nupkg, &extract_dir)?;

    if find_dll(&runtime_dir).is_some() {
        // Reaching the vendored fallback means the feed download did not
        // succeed, which is worth surfacing as a real warning (not per-build
        // noise -- this branch only runs when the feed is unreachable).
        println!(
            "cargo:warning=WSLC SDK: MxcDependencies feed unavailable; \
             fell back to vendored v{version} from external/wslc-sdk"
        );
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
///
/// The transfer is staged to a temporary `.part` sibling and renamed into place
/// only on success, so an interrupted/partial/failed download never leaves a
/// truncated file at `dest` that a later build would treat as a valid cached
/// package (and thus skip re-downloading).
fn download(url: &str, dest: &Path) -> Result<(), String> {
    let tmp = dest.with_extension("part");
    let _ = std::fs::remove_file(&tmp);
    let status = Command::new("curl")
        .args([
            "--fail",
            "--silent",
            "--show-error",
            "--location",
            "--output",
        ])
        .arg(&tmp)
        .arg(url)
        .status()
        .map_err(|e| {
            let _ = std::fs::remove_file(&tmp);
            format!(
                "failed to invoke curl to download the WSLC SDK: {}. \
                 Set WSLC_SDK_PATH to a pre-fetched SDK directory for offline builds.",
                e
            )
        })?;
    if !status.success() {
        let _ = std::fs::remove_file(&tmp);
        return Err(format!(
            "curl failed to download the WSLC SDK from {} ({}). \
             Set WSLC_SDK_PATH to a pre-fetched SDK directory for offline builds.",
            url, status
        ));
    }
    std::fs::rename(&tmp, dest).map_err(|e| {
        let _ = std::fs::remove_file(&tmp);
        format!(
            "failed to finalize downloaded WSLC SDK ({} -> {}): {}",
            tmp.display(),
            dest.display(),
            e
        )
    })?;
    Ok(())
}

/// Expected lowercase-hex SHA-256 of the `.nupkg` for `version`, used to verify
/// package integrity before extraction. Returns `None` for versions without a
/// pinned hash unless `WSLC_SDK_SHA256` provides one, so a custom
/// `WSLC_SDK_VERSION` must be accompanied by its hash to be accepted.
fn expected_sha256(version: &str) -> Option<String> {
    if let Ok(h) = std::env::var("WSLC_SDK_SHA256") {
        let h = h.trim().to_ascii_lowercase();
        if !h.is_empty() {
            return Some(h);
        }
    }
    match version {
        "2.9.3" => {
            Some("d49b66796cb3b88ff513f5e65cd0333ddfed8fe998bf8ed3845ebdecf8563281".to_string())
        }
        _ => None,
    }
}

/// Verify the SHA-256 of the package at `nupkg_path` against the pinned hash for
/// `version`. On mismatch the offending file is removed (so the next build
/// re-fetches) and an error is returned. If no pinned hash is available for the
/// requested version, the build is rejected rather than trusting arbitrary bytes.
fn verify_sha256(nupkg_path: &Path, version: &str) -> Result<(), String> {
    let expected = expected_sha256(version).ok_or_else(|| {
        format!(
            "no pinned SHA-256 for WSLC SDK v{version}; set WSLC_SDK_SHA256 to the \
             expected package hash to authorize this version"
        )
    })?;
    let bytes = std::fs::read(nupkg_path)
        .map_err(|e| format!("cannot read {} for hashing: {}", nupkg_path.display(), e))?;
    let mut hasher = Sha256::new();
    hasher.update(&bytes);
    let actual = hasher
        .finalize()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<String>();
    if actual != expected {
        let _ = std::fs::remove_file(nupkg_path);
        return Err(format!(
            "WSLC SDK integrity check failed for {}: expected SHA-256 {}, got {}. \
             The package may be corrupted or tampered with; the file was removed.",
            nupkg_path.display(),
            expected,
            actual
        ));
    }
    Ok(())
}

/// Extract `nupkg` into `extract_dir` atomically: unpack into a temporary
/// sibling directory and rename it into place only after a complete extraction.
/// A partial/interrupted extraction therefore never leaves a half-populated
/// cache dir that a later build — or the vendored fallback, which shares this
/// same `extract_dir` — would mistake for a valid SDK.
fn extract_zip_atomic(nupkg: &Path, extract_dir: &Path) -> Result<(), String> {
    if let Some(parent) = extract_dir.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|e| format!("cannot create {}: {}", parent.display(), e))?;
    }
    let name = extract_dir
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("wslc-sdk");
    let tmp_dir = extract_dir.with_file_name(format!("{name}.tmp.{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&tmp_dir);

    let result = extract_zip(nupkg, &tmp_dir);
    if let Err(e) = result {
        let _ = std::fs::remove_dir_all(&tmp_dir);
        return Err(e);
    }

    // Publish atomically: drop any prior (possibly partial) dir, then rename.
    let _ = std::fs::remove_dir_all(extract_dir);
    std::fs::rename(&tmp_dir, extract_dir).map_err(|e| {
        let _ = std::fs::remove_dir_all(&tmp_dir);
        format!(
            "failed to publish extracted WSLC SDK to {}: {}",
            extract_dir.display(),
            e
        )
    })
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
