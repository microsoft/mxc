// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#[cfg(any(test, feature = "microvm"))]
use std::collections::BTreeMap;
#[cfg(any(test, feature = "microvm"))]
use std::path::{Component, Path, PathBuf};
#[cfg(feature = "microvm")]
use std::process::Command;

#[cfg(any(test, feature = "microvm"))]
use sha2::{Digest, Sha256};

#[cfg(any(test, feature = "microvm"))]
pub(crate) const OFFICIAL_BUNDLE_URL: &str =
    "https://github.com/microsoft/nvx/releases/download/v0.1.0-dev.0430ce79d125/aci-edge-sandboxes.zip";
#[cfg(any(test, feature = "microvm"))]
pub(crate) const OFFICIAL_BUNDLE_ZIP_SHA256: &str =
    "98e3d6011b0664fad6fa783768370a34209639463f5ab812b7776840660ac24e";
const BUNDLE_DIR_ENV: &str = "ACI_EDGE_SANDBOXES_AGENT_BUNDLE_DIR";

#[cfg(any(test, feature = "microvm"))]
pub(crate) const OFFICIAL_BUNDLE_FILES: &[(&str, &str)] = &[
    (
        "SHA256SUMS",
        "d86b7768ca51e6ea93c40880cc027c85280e718e960e1efe3e0e80bd23727fce",
    ),
    (
        "SOURCE-MANIFEST.json",
        "d5487737b07d663d983373dec82d917bbfcab58e39fed45b6642e8885c3fb01b",
    ),
    (
        "bin/aci_edge_agent.dll",
        "a203e58b97a642bd4a68824c0387965541895b25582e18db6f55e28947f5f135",
    ),
    (
        "bin/direct-images.exe",
        "633b679a8f8f2586626b7475b1e5e3faa3d2ea7119082ffc5873191194feb6fe",
    ),
    (
        "bin/openvmm.exe",
        "697f8221e62a1ea4efb3846fefde6f595c89f4f81c0153a2609bf6fb4c81ea9e",
    ),
    (
        "bundle-manifest.json",
        "44c9c355dee41bd0cd098b9ccfb623ddb7508407c213ca3343090500348e9253",
    ),
    (
        "guest/initramfs-edge.cpio.gz",
        "5e42d4617c1508e9116df8c330c0ff72243e954d7f132091ecdecfc743d904ed",
    ),
    (
        "guest/nvx-edge-agent",
        "d29acada883da8f2977036958704516545cb295114e94999eb269094b81aaff7",
    ),
    (
        "guest/vmlinux",
        "b36ab45b22d1c14438047b24c3724f54cc71dd03601d0f3cbdca11438f40e768",
    ),
    (
        "guest/vmlinux.config",
        "89228d78a10ac9d8f151384b0adc5a155c8a1ee045732b17e236a0e28b49297d",
    ),
    (
        "provenance/edge-guest.json",
        "31512ee712657ede1884ad2ed04f86200f78f282a9fb8e6f0855a4790875507b",
    ),
    (
        "provenance/edge-windows.json",
        "21f2455e680b565dac122ac4be3cf793159e31979ccc6def3a982a4013ae209f",
    ),
    (
        "provenance/licenses/linux/COPYING-LINUX",
        "4fc360c08586ee232e17eaf34e97feae0065dc3daacb2210b754921dc587a5c5",
    ),
    (
        "provenance/licenses/nvx/LICENSE",
        "7df20dcdf9197e9945c14858d41c60f11b52b93e5b69e2b63416b874d598d322",
    ),
    (
        "provenance/licenses/nvx/THIRD_PARTY_NOTICES.md",
        "d659326442a1092e29ba2edec81ff6cb3a4ad63dbdd36a166478eb08fecd9fe0",
    ),
    (
        "provenance/licenses/openvmm/LICENSE",
        "c2cfccb812fe482101a8f04597dfc5a9991a6b2748266c47ac91b6a5aae15383",
    ),
    (
        "provenance/openvmm.provenance.json",
        "adfd57d7a7197f91604acad3eea30b583fa3f442b4b8cabd1147611c5c1b3521",
    ),
    (
        "provenance/vmlinux.provenance.json",
        "a526683d54302c87c2dacbecdfcc879817c4ba2f1e21241f0d2c9d170b17cc58",
    ),
];

pub(crate) fn run() {
    println!("cargo:rerun-if-env-changed=CARGO_FEATURE_MICROVM");
    println!("cargo:rerun-if-env-changed={BUNDLE_DIR_ENV}");
    #[cfg(feature = "microvm")]
    if std::env::var_os("CARGO_FEATURE_MICROVM").is_some()
        && std::env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("windows")
        && std::env::var("CARGO_CFG_TARGET_ARCH").as_deref() == Ok("x86_64")
    {
        stage_official_bundle();
    }
}

#[cfg(feature = "microvm")]
fn stage_official_bundle() {
    let out_dir = PathBuf::from(std::env::var_os("OUT_DIR").expect("OUT_DIR is set"));
    let source = match std::env::var_os(BUNDLE_DIR_ENV).filter(|value| !value.is_empty()) {
        Some(directory) => {
            let directory = PathBuf::from(directory);
            let archive = directory.join("aci-edge-sandboxes.zip");
            if archive.is_file() && !directory.join("SOURCE-MANIFEST.json").is_file() {
                println!("cargo:rerun-if-changed={}", archive.display());
                let extracted = out_dir.join("aci-edge-sandboxes");
                if !is_verified_bundle(&extracted, OFFICIAL_BUNDLE_FILES) {
                    extract_verified_archive_against(
                        &archive,
                        &extracted,
                        OFFICIAL_BUNDLE_ZIP_SHA256,
                        OFFICIAL_BUNDLE_FILES,
                    );
                }
                extracted
            } else {
                directory
            }
        }
        None => acquire_cached_bundle(&out_dir),
    };
    verify_bundle(&source);

    let target = out_dir
        .ancestors()
        .nth(3)
        .expect("OUT_DIR has target/profile ancestors")
        .join("aci-edge-sandboxes");
    copy_bundle(&source, &target);
    verify_bundle(&target);
}

#[cfg(feature = "microvm")]
fn acquire_cached_bundle(out_dir: &Path) -> PathBuf {
    let extracted = out_dir.join("aci-edge-sandboxes");
    if is_verified_bundle(&extracted, OFFICIAL_BUNDLE_FILES) {
        return extracted;
    }

    let archive = out_dir.join("aci-edge-sandboxes.zip");
    let archive_ok =
        archive.is_file() && sha256(&archive).eq_ignore_ascii_case(OFFICIAL_BUNDLE_ZIP_SHA256);
    if !archive_ok {
        let _ = std::fs::remove_file(&archive);
        download_archive(OFFICIAL_BUNDLE_URL, &archive);
    }
    extract_verified_archive_against(
        &archive,
        &extracted,
        OFFICIAL_BUNDLE_ZIP_SHA256,
        OFFICIAL_BUNDLE_FILES,
    );
    extracted
}

#[cfg(feature = "microvm")]
fn download_archive(url: &str, destination: &Path) {
    if let Some(parent) = destination.parent() {
        std::fs::create_dir_all(parent)
            .unwrap_or_else(|error| panic!("cannot create {}: {error}", parent.display()));
    }
    let partial = destination.with_extension("zip.part");
    let _ = std::fs::remove_file(&partial);
    let output = Command::new("curl")
        .args([
            "--fail",
            "--silent",
            "--show-error",
            "--location",
            "--retry",
            "5",
            "--retry-delay",
            "5",
            "--retry-all-errors",
            "--output",
        ])
        .arg(&partial)
        .arg(url)
        .output()
        .unwrap_or_else(|error| {
            let _ = std::fs::remove_file(&partial);
            panic!(
                "cannot invoke curl to download signed NVX bundle from {url}: {error}; \
                 set {BUNDLE_DIR_ENV} to a pre-fetched bundle directory for offline builds"
            )
        });
    if !output.status.success() {
        let _ = std::fs::remove_file(&partial);
        panic!(
            "curl failed to download signed NVX bundle from {url} ({}): {}; \
             set {BUNDLE_DIR_ENV} to a pre-fetched bundle directory for offline builds",
            output.status,
            String::from_utf8_lossy(&output.stderr).trim()
        );
    }
    std::fs::rename(&partial, destination).unwrap_or_else(|error| {
        let _ = std::fs::remove_file(&partial);
        panic!(
            "cannot finalize downloaded NVX bundle ({} -> {}): {error}",
            partial.display(),
            destination.display()
        )
    });
}

#[cfg(any(test, feature = "microvm"))]
pub(crate) fn extract_verified_archive_against(
    archive_path: &Path,
    destination: &Path,
    expected_archive_sha256: &str,
    expected_files: &[(&str, &str)],
) {
    let actual_archive_sha256 = sha256(archive_path);
    if !actual_archive_sha256.eq_ignore_ascii_case(expected_archive_sha256) {
        let _ = std::fs::remove_file(archive_path);
        panic!(
            "microvm requires the signed v0.1.0-dev.0430ce79d125 archive {}: \
             expected SHA-256 {expected_archive_sha256}, got {actual_archive_sha256}",
            archive_path.display()
        );
    }

    if let Some(parent) = destination.parent() {
        std::fs::create_dir_all(parent)
            .unwrap_or_else(|error| panic!("cannot create {}: {error}", parent.display()));
    }
    let name = destination
        .file_name()
        .and_then(|value| value.to_str())
        .unwrap_or("aci-edge-sandboxes");
    let staging = destination.with_file_name(format!("{name}.tmp.{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&staging);
    std::fs::create_dir_all(&staging)
        .unwrap_or_else(|error| panic!("cannot create {}: {error}", staging.display()));

    let unpack_result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        unpack_zip_strict(archive_path, &staging);
        verify_bundle_against(&staging, expected_files);
    }));
    if let Err(payload) = unpack_result {
        let _ = std::fs::remove_dir_all(&staging);
        std::panic::resume_unwind(payload);
    }

    let _ = std::fs::remove_dir_all(destination);
    std::fs::rename(&staging, destination).unwrap_or_else(|error| {
        let _ = std::fs::remove_dir_all(&staging);
        panic!(
            "cannot publish extracted NVX bundle to {}: {error}",
            destination.display()
        )
    });
}

#[cfg(any(test, feature = "microvm"))]
fn unpack_zip_strict(archive_path: &Path, destination: &Path) {
    let file = std::fs::File::open(archive_path)
        .unwrap_or_else(|error| panic!("cannot open {}: {error}", archive_path.display()));
    let mut archive = zip::ZipArchive::new(file).unwrap_or_else(|error| {
        panic!(
            "cannot read NVX bundle archive {}: {error}",
            archive_path.display()
        )
    });

    for index in 0..archive.len() {
        let mut entry = archive
            .by_index(index)
            .unwrap_or_else(|error| panic!("cannot read NVX zip entry {index}: {error}"));
        assert!(
            !entry.is_symlink(),
            "NVX bundle archive must not contain links: {}",
            entry.name()
        );
        let relative = entry.enclosed_name().unwrap_or_else(|| {
            panic!(
                "NVX bundle archive entry path is not safe: {}",
                entry.name()
            )
        });
        assert!(
            !relative.as_os_str().is_empty()
                && relative
                    .components()
                    .all(|component| matches!(component, Component::Normal(_))),
            "NVX bundle archive entry path is not safe: {}",
            entry.name()
        );
        let out_path = destination.join(&relative);
        if entry.is_dir() {
            std::fs::create_dir_all(&out_path)
                .unwrap_or_else(|error| panic!("cannot create {}: {error}", out_path.display()));
        } else {
            assert!(
                entry.is_file(),
                "NVX bundle archive must contain only regular files and directories: {}",
                entry.name()
            );
            if let Some(parent) = out_path.parent() {
                std::fs::create_dir_all(parent)
                    .unwrap_or_else(|error| panic!("cannot create {}: {error}", parent.display()));
            }
            assert!(
                !out_path.exists(),
                "duplicate NVX bundle archive entry: {}",
                relative.display()
            );
            let mut output = std::fs::File::create(&out_path)
                .unwrap_or_else(|error| panic!("cannot create {}: {error}", out_path.display()));
            std::io::copy(&mut entry, &mut output)
                .unwrap_or_else(|error| panic!("cannot write {}: {error}", out_path.display()));
        }
    }
}

#[cfg(feature = "microvm")]
fn is_verified_bundle(source: &Path, expected_files: &[(&str, &str)]) -> bool {
    source.is_dir()
        && std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            verify_bundle_against(source, expected_files);
        }))
        .is_ok()
}

#[cfg(any(test, feature = "microvm"))]
fn sha256(path: &Path) -> String {
    let bytes = std::fs::read(path).unwrap_or_else(|error| {
        panic!(
            "cannot read signed NVX artifact {}: {error}",
            path.display()
        )
    });
    Sha256::digest(&bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

#[cfg(feature = "microvm")]
fn verify_bundle(source: &Path) {
    verify_bundle_against(source, OFFICIAL_BUNDLE_FILES);
}

#[cfg(any(test, feature = "microvm"))]
pub(crate) fn verify_bundle_against(source: &Path, expected_files: &[(&str, &str)]) {
    let expected: BTreeMap<&str, &str> = expected_files.iter().copied().collect();
    assert_eq!(
        expected.len(),
        expected_files.len(),
        "official NVX bundle file list contains duplicate paths"
    );

    let mut actual = BTreeMap::new();
    collect_bundle_files(source, source, &mut actual);
    let actual_paths: Vec<&str> = actual.keys().map(String::as_str).collect();
    let expected_paths: Vec<&str> = expected.keys().copied().collect();
    assert_eq!(
        actual_paths, expected_paths,
        "microvm requires the complete signed v0.1.0-dev.0430ce79d125 bundle"
    );

    for (relative, path) in actual {
        let expected_sha256 = expected[relative.as_str()];
        assert_eq!(
            sha256(&path),
            expected_sha256,
            "microvm requires the signed v0.1.0-dev.0430ce79d125 artifact {relative}"
        );
    }
}

#[cfg(any(test, feature = "microvm"))]
fn collect_bundle_files(source: &Path, directory: &Path, files: &mut BTreeMap<String, PathBuf>) {
    for entry in std::fs::read_dir(directory)
        .unwrap_or_else(|error| panic!("cannot list {}: {error}", directory.display()))
    {
        let entry = entry.unwrap_or_else(|error| panic!("cannot read bundle entry: {error}"));
        let path = entry.path();
        let kind = entry
            .file_type()
            .unwrap_or_else(|error| panic!("cannot inspect {}: {error}", path.display()));
        assert!(!kind.is_symlink(), "NVX bundle must not contain links");
        if kind.is_dir() {
            collect_bundle_files(source, &path, files);
            continue;
        }
        assert!(kind.is_file(), "NVX bundle must contain only regular files");
        let relative = path
            .strip_prefix(source)
            .expect("bundle entry remains under its source");
        assert!(
            relative
                .components()
                .all(|component| matches!(component, Component::Normal(_))),
            "NVX bundle path is not safe: {}",
            relative.display()
        );
        let relative = relative
            .to_str()
            .unwrap_or_else(|| panic!("NVX bundle path is not UTF-8: {}", relative.display()))
            .replace('\\', "/");
        assert!(
            files.insert(relative.clone(), path).is_none(),
            "duplicate NVX bundle path: {relative}"
        );
    }
}

#[cfg(feature = "microvm")]
fn copy_bundle(source: &Path, target: &Path) {
    std::fs::create_dir_all(target)
        .unwrap_or_else(|error| panic!("cannot create {}: {error}", target.display()));
    for entry in std::fs::read_dir(source)
        .unwrap_or_else(|error| panic!("cannot list {}: {error}", source.display()))
    {
        let entry = entry.unwrap_or_else(|error| panic!("cannot read bundle entry: {error}"));
        let from = entry.path();
        let to = target.join(entry.file_name());
        let kind = entry
            .file_type()
            .unwrap_or_else(|error| panic!("cannot inspect {}: {error}", from.display()));
        assert!(!kind.is_symlink(), "NVX bundle must not contain links");
        if kind.is_dir() {
            copy_bundle(&from, &to);
        } else {
            assert!(kind.is_file(), "NVX bundle must contain only regular files");
            println!("cargo:rerun-if-changed={}", from.display());
            let contents = std::fs::read(&from)
                .unwrap_or_else(|error| panic!("cannot read {}: {error}", from.display()));
            if std::fs::read(&to).is_ok_and(|existing| existing == contents) {
                continue;
            }
            std::fs::copy(&from, &to).unwrap_or_else(|error| {
                panic!(
                    "cannot stage signed NVX artifact {} to {}: {error}",
                    from.display(),
                    to.display()
                )
            });
        }
    }
}
