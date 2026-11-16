// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Integrity checks the build applies to the committed WSLC gateway images.

#[allow(dead_code)]
#[path = "../build/build_wslc_gateway_image.rs"]
mod build_wslc_gateway_image;

use build_wslc_gateway_image::{image_id, tar_entries};

fn committed(arch: &str) -> Vec<u8> {
    let path = format!(
        "{}/assets/mxc-wslc-gateway-{arch}.tar",
        env!("CARGO_MANIFEST_DIR")
    );
    std::fs::read(&path).unwrap_or_else(|e| panic!("{path}: {e}"))
}

/// Offset of the first layer's data in `tar`.
fn first_layer(tar: &[u8]) -> (usize, usize) {
    let entries = tar_entries(tar).unwrap();
    let (_, data) = entries
        .iter()
        .find(|(name, _)| name.ends_with("/layer.tar"))
        .expect("a layer");
    (data.as_ptr() as usize - tar.as_ptr() as usize, data.len())
}

#[test]
fn committed_images_pass_the_build_checks() {
    for arch in ["x86_64", "aarch64"] {
        let tar = committed(arch);
        let id = image_id(&tar).unwrap_or_else(|e| panic!("{arch}: {e}"));
        assert_eq!(id.len(), 64, "{arch}");
    }
}

#[test]
fn a_modified_or_missing_layer_is_rejected() {
    let tar = committed("x86_64");
    let (offset, len) = first_layer(&tar);

    let mut flipped = tar.clone();
    flipped[offset + len / 2] ^= 1;
    let error = image_id(&flipped).unwrap_err();
    assert!(error.contains("config expects"), "{error}");

    // Renames the entry; the parser doesn't check header checksums.
    let mut missing = tar;
    missing[offset - 512] ^= 1;
    let error = image_id(&missing).unwrap_err();
    assert!(error.starts_with("no "), "{error}");
}
