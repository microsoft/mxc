// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Downloads and verifies pinned NVX artifacts at build time.

use std::collections::HashMap;
use std::fs;
use std::io::{self, Read};
use std::path::{Path, PathBuf};
use std::process::Command;

use nvx_common::{
    github_download_url, load_checksums, load_json, ReleaseConfig, WINDOWS_PLATFORM_ARTIFACTS,
    WORKLOAD_IMAGE_ARTIFACTS,
};
use sha2::{Digest, Sha256};

fn main() {
    println!("cargo:rerun-if-env-changed=CARGO_FEATURE_NVX");

    if std::env::var_os("CARGO_FEATURE_NVX").is_none() {
        emit_disabled_metadata();
        return;
    }

    let target_os = std::env::var("CARGO_CFG_TARGET_OS").unwrap_or_default();
    if target_os != "windows" {
        emit_disabled_metadata();
        return;
    }

    let out_dir = PathBuf::from(
        std::env::var_os("OUT_DIR").expect("nvx_binaries: OUT_DIR is not set by Cargo"),
    );
    let (bin_dir, prefetched) =
        nvx_build_common::resolve_bin_dir(&out_dir).unwrap_or_else(|error| {
            panic!("nvx_binaries: failed to resolve artifact directory: {error}")
        });
    let release: ReleaseConfig = load_json("versions.json");
    let checksums = load_checksums("checksums.json");
    let workload_images_available = release.workload_image_asset.is_some();

    if prefetched {
        eprintln!(
            "nvx_binaries: NVX_BIN set; using pre-fetched artifacts from '{}' (offline)",
            bin_dir.display()
        );
    } else {
        ensure_asset(
            &release,
            &release.windows_whp_asset,
            &WINDOWS_PLATFORM_ARTIFACTS,
            &bin_dir,
            &checksums,
        );

        if let Some(asset) = release.workload_image_asset.as_deref() {
            ensure_asset(
                &release,
                asset,
                &WORKLOAD_IMAGE_ARTIFACTS,
                &bin_dir,
                &checksums,
            );
        }
    }

    validate_artifacts(
        &bin_dir,
        nvx_build_common::available_artifact_rel_paths(workload_images_available),
        &checksums,
    )
    .unwrap_or_else(|error| panic!("nvx_binaries: {error}"));

    nvx_build_common::emit_rerun_for_artifacts(&bin_dir, workload_images_available);

    emit_metadata(&bin_dir, workload_images_available);
}

fn emit_disabled_metadata() {
    let out_dir = std::env::var("OUT_DIR").expect("nvx_binaries: OUT_DIR is not set by Cargo");
    println!("cargo:rustc-env=NVX_BIN_DIR={out_dir}");
    println!("cargo:rustc-env=NVX_WORKLOAD_IMAGES_AVAILABLE=0");
    println!("cargo:BIN_DIR={out_dir}");
    println!("cargo:WORKLOAD_IMAGES_AVAILABLE=0");
    println!("cargo:rerun-if-changed=build.rs");
}

fn emit_metadata(bin_dir: &Path, workload_images_available: bool) {
    let available = if workload_images_available { "1" } else { "0" };
    println!("cargo:rustc-env=NVX_BIN_DIR={}", bin_dir.display());
    println!("cargo:rustc-env=NVX_WORKLOAD_IMAGES_AVAILABLE={available}");
    println!("cargo:BIN_DIR={}", bin_dir.display());
    println!("cargo:WORKLOAD_IMAGES_AVAILABLE={available}");
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed=versions.json");
    println!("cargo:rerun-if-changed=checksums.json");
    println!("cargo:rerun-if-env-changed=NVX_BIN");
}

fn ensure_asset(
    release: &ReleaseConfig,
    asset: &str,
    relative_paths: &[&str],
    bin_dir: &Path,
    checksums: &HashMap<String, String>,
) {
    if validate_artifacts(bin_dir, relative_paths.iter().copied(), checksums).is_ok() {
        eprintln!("nvx_binaries: '{asset}' artifacts are cached and verified");
        return;
    }

    let url = github_download_url(&release.repository, &release.tag, asset);
    let archive = bin_dir.join(asset);
    download(&url, &archive).unwrap_or_else(|error| {
        let _ = fs::remove_file(&archive);
        panic!("nvx_binaries: failed to download '{asset}': {error}");
    });

    extract_and_stage(&archive, asset, relative_paths, bin_dir, checksums).unwrap_or_else(
        |error| {
            let _ = fs::remove_file(&archive);
            panic!("nvx_binaries: failed to extract '{asset}': {error}");
        },
    );
    let _ = fs::remove_file(archive);
}

fn download(url: &str, destination: &Path) -> Result<(), String> {
    let mut command = Command::new("curl");
    command.args([
        "--silent",
        "--show-error",
        "--fail",
        "--location",
        "--retry",
        "5",
        "--retry-delay",
        "5",
        "--retry-all-errors",
        "--output",
    ]);
    command.arg(destination);
    command.args(["--header", "User-Agent: mxc-nvx-build/0.1"]);

    command.arg(url);

    let output = command
        .output()
        .map_err(|error| format!("could not start curl: {error}"))?;
    if !output.status.success() {
        return Err(format!(
            "curl exited with {}\nstderr: {}",
            output.status,
            String::from_utf8_lossy(&output.stderr)
        ));
    }
    Ok(())
}

fn extract_and_stage(
    archive: &Path,
    asset: &str,
    relative_paths: &[&str],
    bin_dir: &Path,
    checksums: &HashMap<String, String>,
) -> Result<(), String> {
    let archive_root = archive_root(asset)?;
    let extraction_dir = bin_dir.join(".nvx-extract");
    if extraction_dir.exists() {
        fs::remove_dir_all(&extraction_dir).map_err(|error| {
            format!(
                "failed to clean extraction directory '{}': {error}",
                extraction_dir.display()
            )
        })?;
    }
    fs::create_dir_all(&extraction_dir).map_err(|error| {
        format!(
            "failed to create extraction directory '{}': {error}",
            extraction_dir.display()
        )
    })?;

    let archive_paths: Vec<String> = relative_paths
        .iter()
        .map(|path| format!("{archive_root}/{path}"))
        .collect();
    let mut command = Command::new("tar");
    command
        .arg("-xf")
        .arg(archive)
        .arg("-C")
        .arg(&extraction_dir);
    command.args(&archive_paths);
    let output = command
        .output()
        .map_err(|error| format!("could not start tar: {error}"))?;
    if !output.status.success() {
        let _ = fs::remove_dir_all(&extraction_dir);
        return Err(format!(
            "tar exited with {}\nstderr: {}",
            output.status,
            String::from_utf8_lossy(&output.stderr)
        ));
    }

    let extracted_root = extraction_dir.join(archive_root);
    let result = validate_artifacts(&extracted_root, relative_paths.iter().copied(), checksums)
        .and_then(|()| {
            nvx_build_common::copy_artifact_paths(
                &extracted_root,
                bin_dir,
                relative_paths.iter().copied(),
            )
            .map_err(|error| error.to_string())
        });
    let cleanup_result = fs::remove_dir_all(&extraction_dir);

    result?;
    cleanup_result.map_err(|error| {
        format!(
            "failed to remove extraction directory '{}': {error}",
            extraction_dir.display()
        )
    })
}

fn archive_root(asset: &str) -> Result<&str, String> {
    asset
        .strip_suffix(".zip")
        .or_else(|| asset.strip_suffix(".tar.gz"))
        .ok_or_else(|| format!("unsupported NVX archive name '{asset}'"))
}

fn validate_artifacts<'a>(
    root: &Path,
    relative_paths: impl IntoIterator<Item = &'a str>,
    checksums: &HashMap<String, String>,
) -> Result<(), String> {
    for relative_path in relative_paths {
        let artifact = root.join(relative_path);
        if !artifact.is_file() {
            return Err(format!(
                "required artifact '{}' is missing",
                artifact.display()
            ));
        }
        let expected = checksums.get(relative_path).ok_or_else(|| {
            format!("artifact '{relative_path}' has no checksum entry; refusing unverified input")
        })?;
        let actual = sha256(&artifact)
            .map_err(|error| format!("failed to hash '{}': {error}", artifact.display()))?;
        if actual != *expected {
            return Err(format!(
                "SHA-256 mismatch for '{relative_path}': expected {expected}, actual {actual}"
            ));
        }
    }
    Ok(())
}

fn sha256(path: &Path) -> io::Result<String> {
    let mut file = fs::File::open(path)?;
    let mut hasher = Sha256::new();
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let bytes_read = file.read(&mut buffer)?;
        if bytes_read == 0 {
            break;
        }
        hasher.update(&buffer[..bytes_read]);
    }
    Ok(format!("{:x}", hasher.finalize()))
}
