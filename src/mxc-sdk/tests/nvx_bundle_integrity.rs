// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#[allow(dead_code)]
#[path = "../build/build_nvx_bundled.rs"]
mod build_nvx_bundled;

use sha2::{Digest, Sha256};

fn digest(contents: &[u8]) -> String {
    Sha256::digest(contents)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn fixture() -> (tempfile::TempDir, Vec<(&'static str, String)>) {
    let directory = tempfile::tempdir().expect("bundle fixture");
    let files = [
        ("SHA256SUMS", b"checksums".as_slice()),
        ("SOURCE-MANIFEST.json", b"source manifest".as_slice()),
        ("bin/direct-images.exe", b"image tool".as_slice()),
        ("guest/initramfs-edge.cpio.gz", b"guest".as_slice()),
    ];
    for (relative, contents) in files {
        let path = directory.path().join(relative);
        std::fs::create_dir_all(path.parent().expect("fixture parent"))
            .expect("create fixture parent");
        std::fs::write(path, contents).expect("write fixture");
    }
    let expected = files
        .into_iter()
        .map(|(path, contents)| (path, digest(contents)))
        .collect();
    (directory, expected)
}

fn verify(directory: &std::path::Path, expected: &[(&str, String)]) {
    let expected: Vec<(&str, &str)> = expected
        .iter()
        .map(|(path, digest)| (*path, digest.as_str()))
        .collect();
    build_nvx_bundled::verify_bundle_against(directory, &expected);
}

#[test]
fn accepts_complete_pinned_bundle() {
    let (directory, expected) = fixture();
    verify(directory.path(), &expected);
}

#[test]
fn rejects_modified_guest_helper_and_checksum_metadata() {
    for relative in [
        "guest/initramfs-edge.cpio.gz",
        "bin/direct-images.exe",
        "SHA256SUMS",
        "SOURCE-MANIFEST.json",
    ] {
        let (directory, expected) = fixture();
        std::fs::write(directory.path().join(relative), b"modified").expect("tamper fixture");
        let result = std::panic::catch_unwind(|| verify(directory.path(), &expected));
        assert!(result.is_err(), "modified {relative} must be rejected");
    }
}

#[test]
fn rejects_missing_or_unlisted_bundle_files() {
    let (directory, expected) = fixture();
    std::fs::remove_file(directory.path().join("guest/initramfs-edge.cpio.gz"))
        .expect("remove fixture");
    assert!(
        std::panic::catch_unwind(|| verify(directory.path(), &expected)).is_err(),
        "missing official files must be rejected"
    );

    let (directory, expected) = fixture();
    std::fs::write(directory.path().join("mutable-release.txt"), b"unexpected")
        .expect("write unexpected fixture");
    assert!(
        std::panic::catch_unwind(|| verify(directory.path(), &expected)).is_err(),
        "unlisted files must be rejected"
    );
}

fn write_zip_fixture(entries: &[(&str, &[u8])]) -> (tempfile::TempDir, std::path::PathBuf, String) {
    use std::io::Write;

    let directory = tempfile::tempdir().expect("zip fixture dir");
    let archive_path = directory.path().join("aci-edge-sandboxes.zip");
    let file = std::fs::File::create(&archive_path).expect("create zip fixture");
    let mut writer = zip::ZipWriter::new(file);
    let options = zip::write::SimpleFileOptions::default()
        .compression_method(zip::CompressionMethod::Deflated);
    for (name, contents) in entries {
        writer.start_file(*name, options).expect("start zip entry");
        writer.write_all(contents).expect("write zip entry");
    }
    writer.finish().expect("finish zip fixture");
    let archive_sha = digest(&std::fs::read(&archive_path).expect("read zip fixture"));
    (directory, archive_path, archive_sha)
}

#[test]
fn extracts_and_verifies_complete_pinned_archive() {
    let entries = [
        ("SHA256SUMS", b"checksums".as_slice()),
        ("SOURCE-MANIFEST.json", b"source manifest".as_slice()),
        ("bin/aci_edge_agent.dll", b"agent dll".as_slice()),
        ("bin/direct-images.exe", b"image tool".as_slice()),
        ("guest/initramfs-edge.cpio.gz", b"guest".as_slice()),
    ];
    let expected: Vec<(&str, String)> = entries
        .iter()
        .map(|(path, contents)| (*path, digest(contents)))
        .collect();
    let expected_refs: Vec<(&str, &str)> = expected
        .iter()
        .map(|(path, sha)| (*path, sha.as_str()))
        .collect();
    let (directory, archive_path, archive_sha) = write_zip_fixture(&entries);
    let extracted = directory.path().join("extracted");

    build_nvx_bundled::extract_verified_archive_against(
        &archive_path,
        &extracted,
        &archive_sha,
        &expected_refs,
    );
    verify(&extracted, &expected);
}

#[test]
fn rejects_archive_digest_mismatch_and_unsafe_or_unlisted_entries() {
    let entries = [
        ("SHA256SUMS", b"checksums".as_slice()),
        ("SOURCE-MANIFEST.json", b"source manifest".as_slice()),
    ];
    let expected: Vec<(&str, String)> = entries
        .iter()
        .map(|(path, contents)| (*path, digest(contents)))
        .collect();
    let expected_refs: Vec<(&str, &str)> = expected
        .iter()
        .map(|(path, sha)| (*path, sha.as_str()))
        .collect();

    let (directory, archive_path, _) = write_zip_fixture(&entries);
    let extracted = directory.path().join("extracted");
    assert!(
        std::panic::catch_unwind(|| {
            build_nvx_bundled::extract_verified_archive_against(
                &archive_path,
                &extracted,
                &"0".repeat(64),
                &expected_refs,
            );
        })
        .is_err(),
        "archive with mismatched SHA-256 must be rejected before extraction"
    );
    assert!(
        !archive_path.exists(),
        "corrupted archive must be removed on SHA-256 mismatch"
    );
    assert!(!extracted.exists());

    let (directory, traversal_archive, traversal_sha) = write_zip_fixture(&[
        ("SHA256SUMS", b"checksums".as_slice()),
        ("../escape.txt", b"escape".as_slice()),
    ]);
    let extracted = directory.path().join("extracted");
    assert!(
        std::panic::catch_unwind(|| {
            build_nvx_bundled::extract_verified_archive_against(
                &traversal_archive,
                &extracted,
                &traversal_sha,
                &expected_refs,
            );
        })
        .is_err(),
        "archive with path traversal entry must be rejected"
    );
    assert!(!extracted.exists());
}

#[test]
fn pins_official_release_url_and_hashes() {
    assert_eq!(
        build_nvx_bundled::OFFICIAL_BUNDLE_URL,
        "https://github.com/microsoft/nvx/releases/download/v0.1.0-dev.0430ce79d125/aci-edge-sandboxes.zip"
    );
    assert_eq!(
        build_nvx_bundled::OFFICIAL_BUNDLE_ZIP_SHA256,
        "98e3d6011b0664fad6fa783768370a34209639463f5ab812b7776840660ac24e"
    );
    assert_eq!(build_nvx_bundled::OFFICIAL_BUNDLE_FILES.len(), 18);
}
