// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Stages the committed WSLC gateway image for the WSLC backend.
//!
//! Reads `assets/mxc-wslc-gateway-<arch>.tar`, checks that its image ID is
//! the SHA-256 of its config, compiles that ID in as
//! `MXC_WSLC_GATEWAY_IMAGE_ID`, and copies the tar next to the final binary
//! as `mxc-wslc-gateway.tar`. `scripts/build-wslc-gateway-image.ps1`
//! regenerates the tars.

use sha2::{Digest, Sha256};
use std::path::PathBuf;

pub(crate) const STAGED_NAME: &str = "mxc-wslc-gateway.tar";

pub(crate) fn run() -> Result<(), String> {
    if std::env::var("CARGO_FEATURE_WSLC").is_err()
        || std::env::var("CARGO_CFG_TARGET_OS").as_deref() != Ok("windows")
    {
        return Ok(());
    }
    let arch = std::env::var("CARGO_CFG_TARGET_ARCH").unwrap_or_default();
    let manifest_dir = PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").unwrap());
    let tar_path = manifest_dir
        .join("assets")
        .join(format!("mxc-wslc-gateway-{arch}.tar"));
    println!("cargo:rerun-if-changed={}", tar_path.display());

    let tar = std::fs::read(&tar_path).map_err(|e| {
        format!(
            "WSLC gateway image: cannot read {} ({e}); the WSLC backend supports \
             x86_64 and aarch64",
            tar_path.display()
        )
    })?;
    let id =
        image_id(&tar).map_err(|e| format!("WSLC gateway image {}: {e}", tar_path.display()))?;
    println!("cargo:rustc-env=MXC_WSLC_GATEWAY_IMAGE_ID=sha256:{id}");

    let out_dir = PathBuf::from(std::env::var("OUT_DIR").unwrap());
    let profile_dir = out_dir
        .ancestors()
        .nth(3)
        .ok_or("WSLC gateway image: cannot resolve the build profile directory")?;
    let staged = profile_dir.join(STAGED_NAME);
    std::fs::write(&staged, &tar)
        .map_err(|e| format!("WSLC gateway image: cannot write {}: {e}", staged.display()))
}

/// Returns the image ID from a single-image `docker save` tar, after checking
/// that it is the SHA-256 of the image config.
fn image_id(tar: &[u8]) -> Result<String, String> {
    let entries = tar_entries(tar)?;
    let find = |name: &str| {
        entries
            .iter()
            .find(|(n, _)| n == name)
            .map(|(_, d)| *d)
            .ok_or_else(|| format!("no {name}"))
    };
    let manifest: serde_json::Value = serde_json::from_slice(find("manifest.json")?)
        .map_err(|e| format!("manifest.json: {e}"))?;
    let config_name = match manifest.as_array().map(Vec::as_slice) {
        Some([image]) => image["Config"]
            .as_str()
            .ok_or("manifest.json has no Config")?,
        _ => return Err("manifest.json must list exactly one image".into()),
    };
    let id = hex(&Sha256::digest(find(config_name)?));
    if config_name != format!("{id}.json") {
        return Err(format!("config {config_name} has SHA-256 {id}"));
    }
    Ok(id)
}

/// Splits a USTAR archive into regular-file entries.
fn tar_entries(tar: &[u8]) -> Result<Vec<(String, &[u8])>, String> {
    let mut entries = Vec::new();
    let mut offset = 0;
    while let Some(header) = tar.get(offset..offset + 512) {
        if header.iter().all(|&b| b == 0) {
            return Ok(entries);
        }
        let field = |range: std::ops::Range<usize>| {
            let raw = &header[range];
            let end = raw.iter().position(|&b| b == 0).unwrap_or(raw.len());
            String::from_utf8_lossy(&raw[..end]).trim().to_string()
        };
        let name = field(0..100);
        let size = usize::from_str_radix(&field(124..136), 8)
            .map_err(|e| format!("bad size for tar entry {name}: {e}"))?;
        let start = offset + 512;
        let data = tar
            .get(start..start + size)
            .ok_or_else(|| format!("tar entry {name} is truncated"))?;
        if matches!(header[156], b'0' | 0) {
            entries.push((name, data));
        }
        offset = start + size.div_ceil(512) * 512;
    }
    Err("tar has no end-of-archive marker".into())
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
