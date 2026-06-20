// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Build script for wslc_common — links against the WSLC SDK and copies
//! wslcsdk.dll next to the final binary so it can be loaded at runtime.
//!
//! The SDK lib is resolved from:
//! 1. `WSLC_SDK_PATH` environment variable (if set, points to a directory
//!    containing `wslcsdk.lib`)
//! 2. Extracted from the `.nupkg` in `external/wslc-sdk/` into the cargo
//!    build output directory (`OUT_DIR`)

use std::path::PathBuf;

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

    let sdk_path = if let Ok(path) = std::env::var("WSLC_SDK_PATH") {
        PathBuf::from(path)
    } else {
        // Extract from nupkg into OUT_DIR
        match extract_nupkg(arch) {
            Ok(path) => path,
            Err(e) => {
                println!("cargo:warning=WSLC SDK: {}", e);
                return;
            }
        }
    };

    println!("cargo:rerun-if-env-changed=WSLC_SDK_PATH");

    // The SDK is loaded at runtime via libloading — no static linking.
    // We only need to copy wslcsdk.dll next to the final binary so it
    // can be found by LoadLibrary at runtime.
    let dll_src = sdk_path.join("wslcsdk.dll");
    if !dll_src.exists() {
        println!(
            "cargo:warning=WSLC SDK: wslcsdk.dll not found at {}. Runtime will fail to load.",
            dll_src.display()
        );
    } else {
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
}

/// Extract the WSLC SDK nupkg and return the path to the runtime libs for
/// the given architecture.
fn extract_nupkg(arch: &str) -> Result<PathBuf, String> {
    let manifest_dir = std::env::var("CARGO_MANIFEST_DIR").unwrap();
    // The crate lives at <repo>/src/backends/wslc/common, so the committed nupkg
    // at <repo>/external/wslc-sdk is FOUR levels up (common -> wslc -> backends
    // -> src -> repo root). (Historically this crate sat two levels under the
    // repo root, hence the previously-too-shallow `../..`, which silently
    // resolved to a nonexistent dir and left wslcsdk.dll unbuilt.)
    let nupkg_dir = PathBuf::from(&manifest_dir)
        .join("..")
        .join("..")
        .join("..")
        .join("..")
        .join("external")
        .join("wslc-sdk");

    // Find the nupkg file
    let nupkg_path = std::fs::read_dir(&nupkg_dir)
        .map_err(|e| format!("Cannot read external/wslc-sdk/: {}", e))?
        .filter_map(|entry| entry.ok())
        .find(|entry| entry.file_name().to_string_lossy().ends_with(".nupkg"))
        .map(|entry| entry.path())
        .ok_or_else(|| "No .nupkg file found in external/wslc-sdk/".to_string())?;

    let out_dir = PathBuf::from(std::env::var("OUT_DIR").unwrap());
    let extract_dir = out_dir.join("wslc-sdk");

    // Skip extraction if already done (lib file exists)
    let runtime_dir = extract_dir.join("runtimes").join(format!("win-{}", arch));
    if runtime_dir.join("wslcsdk.lib").exists() {
        return Ok(runtime_dir);
    }

    // Extract the nupkg (it's a zip)
    let file = std::fs::File::open(&nupkg_path)
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

    if runtime_dir.join("wslcsdk.lib").exists() {
        println!(
            "cargo:warning=WSLC SDK: extracted from {}",
            nupkg_path.display()
        );
        Ok(runtime_dir)
    } else {
        Err(format!(
            "wslcsdk.lib not found in nupkg at runtimes/win-{}/",
            arch
        ))
    }
}
