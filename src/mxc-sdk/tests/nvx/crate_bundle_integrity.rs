// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#![cfg(all(windows, target_arch = "x86_64", feature = "microvm"))]

use aci_edge_sandboxes::agent::{AgentBackend, BundledAgent};
use aci_edge_sandboxes::ErrorCode;

#[path = "../../build/verify_nvx_runtime_signatures.rs"]
mod verify_nvx_runtime_signatures;
use verify_nvx_runtime_signatures::signature_verification;

const BUNDLE_CHILD: &str = "MXC_NVX_BUNDLE_CHILD";
const BUNDLE_FINGERPRINTS: &[signature_verification::BundleFingerprint<'static>] = {
    use signature_verification::BundleFingerprint;
    include!(concat!(env!("OUT_DIR"), "\\nvx_bundle_fingerprints.rs"))
};

fn copy_bundle(source: &std::path::Path, destination: &std::path::Path) {
    std::fs::create_dir_all(destination).unwrap();
    for entry in std::fs::read_dir(source).unwrap() {
        let entry = entry.unwrap();
        let target = destination.join(entry.file_name());
        if entry.file_type().unwrap().is_dir() {
            copy_bundle(&entry.path(), &target);
        } else {
            std::fs::copy(entry.path(), target).unwrap();
        }
    }
}

fn flip_byte(path: &std::path::Path, offset: u64) {
    use std::io::{Read, Seek, SeekFrom, Write};

    let mut file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(path)
        .unwrap();
    file.seek(SeekFrom::Start(offset)).unwrap();
    let mut byte = [0];
    file.read_exact(&mut byte).unwrap();
    file.seek(SeekFrom::Start(offset)).unwrap();
    file.write_all(&[byte[0] ^ 1]).unwrap();
}

fn rewrite_guest_checksum(directory: &std::path::Path, guest: &str) {
    use sha2::{Digest, Sha256};

    let replacement = Sha256::digest(std::fs::read(directory.join(guest)).unwrap())
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    let checksums = directory.join("SHA256SUMS");
    let updated = std::fs::read_to_string(&checksums)
        .unwrap()
        .lines()
        .map(|line| {
            if line.ends_with(&format!("  {guest}")) {
                format!("{replacement}  {guest}")
            } else {
                line.to_owned()
            }
        })
        .collect::<Vec<_>>()
        .join("\n");
    std::fs::write(checksums, updated + "\n").unwrap();
}

#[test]
fn bundle_rejects_modified_guest_with_self_declared_checksums() {
    let bundle = BundledAgent::discover().expect("crate-staged agent bundle");
    let state = tempfile::tempdir().unwrap();
    copy_bundle(bundle.directory(), state.path());
    let guest = "guest/nvx-edge-agent";
    std::fs::write(state.path().join(guest), b"unapproved guest replacement").unwrap();
    rewrite_guest_checksum(state.path(), guest);
    let error = signature_verification::verify_bundle(state.path(), None).unwrap_err();
    assert!(error.to_string().contains("checksum manifest"), "{error}");
}

#[test]
fn crate_staged_bundle_opens_and_rejects_an_unverified_library() {
    if std::env::var_os(BUNDLE_CHILD).is_some_and(|value| value == "approved-fingerprints") {
        mxc_sdk::v1::dev::validate_provision_json(
            r#"{"version":"1.1.0-alpha","phase":"provision","containment":"microvm","microvm":{"image":"mcr.microsoft.com/azurelinux/base/core:3.0"}}"#,
            mxc_sdk::v1::dev::JsonOptions { experimental: true },
        )
        .expect("public validation accepts build-generated fingerprints without starting a VM");
        return;
    }
    if std::env::var_os(BUNDLE_CHILD).is_some() {
        json_execution_and_build_reject_unapproved_bundle_before_agent_load();
        return;
    }
    let bundle = BundledAgent::discover().expect("crate-staged agent bundle");
    let _verified = signature_verification::verify_bundle(bundle.directory(), None)
        .expect("Microsoft-signed binaries");
    let state = tempfile::tempdir().expect("private test state");
    let config = bundle.config(bundle.setup(state.path()));
    let backend = AgentBackend::new(config.clone()).expect("hash-verified runtime opens");
    assert!(backend.info().runtime_digests.openvmm != [0; 32]);
    drop(backend);

    let invalid = state.path().join("invalid.dll");
    std::fs::write(&invalid, b"not the pinned library").unwrap();
    let mut invalid_config = config;
    invalid_config.library = invalid;
    let error = AgentBackend::new(invalid_config).unwrap_err();
    assert_eq!(error.code(), ErrorCode::BackendUnavailable);

    let tampered_dir = state.path().join("tampered");
    std::fs::create_dir_all(tampered_dir.join("bin")).unwrap();
    std::fs::copy(
        bundle.library(),
        tampered_dir.join("bin").join("aci_edge_agent.dll"),
    )
    .unwrap();
    std::fs::write(tampered_dir.join("SOURCE-MANIFEST.json"), b"{}").unwrap();
    let tampered = BundledAgent::from_dir(&tampered_dir).unwrap();
    let error =
        AgentBackend::new(tampered.config(tampered.setup(state.path().join("other-state"))))
            .unwrap_err();
    assert_eq!(error.code(), ErrorCode::BackendUnavailable);
    assert!(
        error.to_string().to_lowercase().contains("manifest"),
        "{error}"
    );
    // Package and staging gates select this test, so their success includes these negative controls.
    sampled_fingerprints_cover_bounded_ranges();
    sampled_bundle_checks_keep_guards_and_reject_sample_changes();
    json_execution_and_build_reject_unapproved_bundle_before_agent_load();
}

fn sampled_fingerprints_cover_bounded_ranges() {
    use std::io::{Cursor, Read, Seek, SeekFrom};

    struct CountedReader {
        bytes: Cursor<Vec<u8>>,
        read: usize,
    }
    impl Read for CountedReader {
        fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
            let count = self.bytes.read(buffer)?;
            self.read += count;
            Ok(count)
        }
    }
    impl Seek for CountedReader {
        fn seek(&mut self, position: SeekFrom) -> std::io::Result<u64> {
            self.bytes.seek(position)
        }
    }

    for length in [0, 17, 12 * 1024, 64 * 1024 + 1] {
        let bytes = vec![0x5a; length];
        let mut reader = CountedReader {
            bytes: Cursor::new(bytes.clone()),
            read: 0,
        };
        let expected =
            signature_verification::file_fingerprint(&mut reader, length as u64).unwrap();
        assert_eq!(reader.read, length.min(12 * 1024));
        assert_eq!(expected, vec![0x5a; reader.read]);
        if length == 0 {
            continue;
        }
        for offset in [0, length / 2, length - 1] {
            let mut changed = bytes.clone();
            changed[offset] ^= 1;
            let actual =
                signature_verification::file_fingerprint(&mut Cursor::new(changed), length as u64)
                    .unwrap();
            assert_ne!(actual, expected, "sampled byte at {offset}");
        }
        let error =
            signature_verification::file_fingerprint(&mut Cursor::new(bytes), length as u64 + 1)
                .unwrap_err();
        assert_eq!(error.kind(), std::io::ErrorKind::UnexpectedEof);
    }
}

fn sampled_bundle_checks_keep_guards_and_reject_sample_changes() {
    let bundle = BundledAgent::discover().expect("crate-staged agent bundle");
    let state = tempfile::tempdir().expect("private fingerprint fixtures");
    copy_bundle(bundle.directory(), state.path());
    let verified =
        signature_verification::verify_bundle(state.path(), Some(BUNDLE_FINGERPRINTS)).unwrap();
    for name in ["guest/vmlinux", "SHA256SUMS"] {
        let error = std::fs::OpenOptions::new()
            .write(true)
            .open(state.path().join(name))
            .unwrap_err();
        assert_eq!(error.raw_os_error(), Some(32), "{error}");
    }
    drop(verified);

    // Changes in these gaps intentionally pass: runtime fingerprints do not verify all bytes.
    let guest = state.path().join("guest").join("vmlinux");
    flip_byte(&guest, 4097);
    let verified =
        signature_verification::verify_bundle(state.path(), Some(BUNDLE_FINGERPRINTS)).unwrap();
    drop(verified);
    let error = signature_verification::verify_bundle(state.path(), None).unwrap_err();
    assert!(error.to_string().contains("SHA-256 mismatch"), "{error}");

    flip_byte(&state.path().join("bin").join("aci_edge_agent.dll"), 4097);
    let verified =
        signature_verification::verify_bundle(state.path(), Some(BUNDLE_FINGERPRINTS)).unwrap();
    drop(verified);
    let error = signature_verification::verify_bundle(state.path(), None).unwrap_err();
    assert!(
        error
            .to_string()
            .contains("Authenticode trust verification failed"),
        "{error}"
    );

    flip_byte(&guest, guest.metadata().unwrap().len() - 1);
    let error =
        signature_verification::verify_bundle(state.path(), Some(BUNDLE_FINGERPRINTS)).unwrap_err();
    assert!(
        error.to_string().contains("sampled fingerprint mismatch"),
        "{error}"
    );

    let local_app_data = tempfile::tempdir().expect("private SDK validation state");
    let output = std::process::Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "crate_staged_bundle_opens_and_rejects_an_unverified_library",
            "--nocapture",
        ])
        .env(BUNDLE_CHILD, "approved-fingerprints")
        .env("ACI_EDGE_SANDBOXES_AGENT_ARTIFACTS_DIR", bundle.directory())
        .env("LOCALAPPDATA", local_app_data.path())
        .output()
        .expect("isolated public fingerprint validation");
    assert!(
        output.status.success(),
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn signatures_reject_unsigned_tampered_and_other_publishers() {
    let bundle = BundledAgent::discover().expect("crate-staged agent bundle");
    let state = tempfile::tempdir().expect("private signature fixtures");
    let unsigned = state.path().join("unsigned.dll");
    std::fs::copy(std::env::current_exe().unwrap(), &unsigned).unwrap();
    let error = signature_verification::verify_file(&unsigned).unwrap_err();
    assert!(
        error
            .to_string()
            .contains("Authenticode trust verification failed"),
        "{error}"
    );

    let tampered = state.path().join("tampered.dll");
    let mut bytes = std::fs::read(bundle.library()).unwrap();
    bytes[0x50] ^= 1;
    std::fs::write(&tampered, bytes).unwrap();
    let error = signature_verification::verify_file(&tampered).unwrap_err();
    assert!(error.to_string().contains("0x80096010"), "{error}");

    // Node is already a Windows CI prerequisite and supplies a trusted non-Microsoft signer.
    let node = std::process::Command::new("node")
        .args(["-p", "process.execPath"])
        .output()
        .expect("Node is required for the Windows validation suite");
    assert!(node.status.success());
    let node = std::path::PathBuf::from(String::from_utf8(node.stdout).unwrap().trim());
    let error = signature_verification::verify_file(&node).unwrap_err();
    assert!(
        error
            .to_string()
            .contains("expected Microsoft Corporation publisher"),
        "{error}"
    );
}

#[test]
fn verified_binary_cannot_be_replaced_until_guard_is_dropped() {
    let bundle = BundledAgent::discover().expect("crate-staged agent bundle");
    let state = tempfile::tempdir().expect("private signature fixture");
    let library = state.path().join("agent.dll");
    std::fs::copy(bundle.library(), &library).unwrap();
    let verified = signature_verification::verify_file(&library).unwrap();
    let error = std::fs::OpenOptions::new()
        .write(true)
        .open(&library)
        .unwrap_err();
    assert_eq!(error.raw_os_error(), Some(32), "{error}");
    let error = std::fs::remove_file(&library).unwrap_err();
    assert_eq!(error.raw_os_error(), Some(32), "{error}");
    drop(verified);
    std::fs::remove_file(&library).unwrap();
}

#[test]
fn verified_bundle_keeps_its_binary_directory_in_place() {
    let bundle = BundledAgent::discover().expect("crate-staged agent bundle");
    let state = tempfile::tempdir().expect("private signature fixtures");
    let bin = state.path().join("bin");
    copy_bundle(bundle.directory(), state.path());
    let verified = signature_verification::verify_bundle(state.path(), None).unwrap();
    for name in [
        "guest/vmlinux",
        "guest/initramfs-edge.cpio.gz",
        "guest/nvx-edge-agent",
        "SHA256SUMS",
    ] {
        let error = std::fs::OpenOptions::new()
            .write(true)
            .open(state.path().join(name))
            .unwrap_err();
        assert_eq!(error.raw_os_error(), Some(32), "{name}: {error}");
    }
    let moved = state.path().join("moved-bin");
    let error = std::fs::rename(&bin, &moved).unwrap_err();
    assert!(matches!(error.raw_os_error(), Some(5 | 32)), "{error}");
    drop(verified);
    std::fs::rename(&bin, &moved).unwrap();
    std::fs::OpenOptions::new()
        .write(true)
        .open(state.path().join("guest/vmlinux"))
        .unwrap();
}

fn json_execution_and_build_reject_unapproved_bundle_before_agent_load() {
    if std::env::var_os(BUNDLE_CHILD).is_some() {
        // Even a broken pre-load gate must not reach VM provisioning.
        let error = mxc_sdk::__ffi::run_json(
            r#"{"version":"1.1.0-alpha","containment":"microvm","microvm":{"image":"mcr.microsoft.com/azurelinux/base/core:3.0"},"runtimeConfig":{"networkProxy":"http://[::1]:3128"},"process":{"commandLine":"printf forbidden"}}"#,
            true,
        )
        .unwrap_err();
        assert_eq!(error.code, mxc_sdk::v1::ErrorCode::BackendUnavailable);
        assert!(error.message.contains("NVX bundle"), "{error}");
        let module = unsafe {
            windows::Win32::System::LibraryLoader::GetModuleHandleW(windows::core::w!(
                "aci_edge_agent.dll"
            ))
        };
        assert_eq!(
            module.unwrap_err().code(),
            windows::core::HRESULT::from_win32(126),
            "bundle rejection must precede agent loading"
        );
        let error = verify_nvx_runtime_signatures::run().unwrap_err();
        assert!(error.to_string().contains("NVX bundle"), "{error}");
        return;
    }

    let bundle = BundledAgent::discover().expect("crate-staged agent bundle");
    let _approved = signature_verification::verify_bundle(bundle.directory(), None).unwrap();
    let local_app_data = tempfile::tempdir().expect("private bundle-rejection state");
    for changed in [
        "guest/vmlinux",
        "guest/initramfs-edge.cpio.gz",
        "guest/nvx-edge-agent",
        "SHA256SUMS",
        "missing-file",
        "unexpected-file",
        "guest-head",
        "guest-middle",
        "guest-tail",
    ] {
        let state = tempfile::tempdir().unwrap();
        copy_bundle(bundle.directory(), state.path());
        match changed {
            "SHA256SUMS" => {
                let guest = "guest/nvx-edge-agent";
                std::fs::write(state.path().join(guest), b"unapproved guest").unwrap();
                rewrite_guest_checksum(state.path(), guest);
            }
            "missing-file" => {
                std::fs::remove_file(state.path().join("source/linux/BUILD-ENVIRONMENT.txt"))
                    .unwrap();
            }
            "unexpected-file" => {
                std::fs::write(state.path().join("unapproved.extra"), b"unexpected").unwrap();
            }
            "guest-head" | "guest-middle" | "guest-tail" => {
                let guest = state.path().join("guest").join("vmlinux");
                let length = guest.metadata().unwrap().len();
                let offset = match changed {
                    "guest-head" => 0,
                    "guest-middle" => length / 2,
                    _ => length - 1,
                };
                flip_byte(&guest, offset);
            }
            name => std::fs::write(state.path().join(name), b"unapproved guest").unwrap(),
        }
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "crate_staged_bundle_opens_and_rejects_an_unverified_library",
                "--nocapture",
            ])
            .env(BUNDLE_CHILD, changed)
            .env("LOCALAPPDATA", local_app_data.path())
            .env("ACI_EDGE_SANDBOXES_AGENT_ARTIFACTS_DIR", state.path())
            .env("DEP_ACI_EDGE_SANDBOXES_AGENT_ARTIFACTS_DIR", state.path())
            .env("CARGO_FEATURE_MICROVM", "1")
            .env("CARGO_CFG_TARGET_OS", "windows")
            .env("CARGO_CFG_TARGET_ARCH", "x86_64")
            .env(
                "OUT_DIR",
                state
                    .path()
                    .join("profile")
                    .join("build")
                    .join("sdk")
                    .join("out"),
            )
            .output()
            .expect("isolated unapproved-bundle rejection");
        assert!(
            output.status.success(),
            "{changed}: {}{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }
}

#[test]
fn verified_tools_can_execute_while_file_guards_are_held() {
    let bundle = BundledAgent::discover().expect("crate-staged agent bundle");
    let _verified = signature_verification::verify_bundle(bundle.directory(), None).unwrap();
    for name in ["openvmm.exe", "direct-images.exe"] {
        let output = std::process::Command::new(bundle.directory().join("bin").join(name))
            .arg("--help")
            .output()
            .expect("verified tool launches without provisioning a VM");
        assert!(
            output.status.success(),
            "{name}: {}{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(!output.stdout.is_empty(), "{name} must print its help");
    }
}

#[test]
fn json_execution_rejects_each_unsigned_binary_before_agent_load() {
    const CHILD: &str = "MXC_NVX_SIGNATURE_CHILD";
    if let Some(name) = std::env::var_os(CHILD) {
        let error = mxc_sdk::__ffi::run_json(
            r#"{"version":"1.1.0-alpha","containment":"microvm","microvm":{"image":"mcr.microsoft.com/azurelinux/base/core:3.0"},"process":{"commandLine":"printf forbidden"}}"#,
            true,
        )
        .unwrap_err();
        assert_eq!(error.code, mxc_sdk::v1::ErrorCode::BackendUnavailable);
        // This isolated child has not opened an agent through any other test.
        let module = unsafe {
            windows::Win32::System::LibraryLoader::GetModuleHandleW(windows::core::w!(
                "aci_edge_agent.dll"
            ))
        };
        assert_eq!(
            module.unwrap_err().code(),
            windows::core::HRESULT::from_win32(126),
            "fingerprint rejection must precede loading the agent"
        );
        assert!(
            error.message.contains("sampled fingerprint mismatch"),
            "{error}"
        );
        assert!(error.message.contains(&*name.to_string_lossy()), "{error}");
        let error = verify_nvx_runtime_signatures::run().unwrap_err();
        assert!(
            error
                .to_string()
                .contains("Authenticode trust verification failed"),
            "{error}"
        );
        assert!(
            error.to_string().contains(&*name.to_string_lossy()),
            "{error}"
        );
        return;
    }

    let bundle = BundledAgent::discover().expect("crate-staged agent bundle");
    let local_app_data = tempfile::tempdir().expect("private binary-rejection state");
    for rejected in ["aci_edge_agent.dll", "openvmm.exe", "direct-images.exe"] {
        let state = tempfile::tempdir().expect("isolated invalid runtime");
        copy_bundle(bundle.directory(), state.path());
        flip_byte(&state.path().join("bin").join(rejected), 0x50);
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "json_execution_rejects_each_unsigned_binary_before_agent_load",
                "--nocapture",
            ])
            .env(CHILD, rejected)
            .env("LOCALAPPDATA", local_app_data.path())
            .env("ACI_EDGE_SANDBOXES_AGENT_ARTIFACTS_DIR", state.path())
            .env("DEP_ACI_EDGE_SANDBOXES_AGENT_ARTIFACTS_DIR", state.path())
            .env("CARGO_FEATURE_MICROVM", "1")
            .env("CARGO_CFG_TARGET_OS", "windows")
            .env("CARGO_CFG_TARGET_ARCH", "x86_64")
            .env(
                "OUT_DIR",
                state
                    .path()
                    .join("profile")
                    .join("build")
                    .join("sdk")
                    .join("out"),
            )
            .output()
            .expect("isolated signature rejection");
        assert!(
            output.status.success(),
            "signature rejection for {rejected}: {}{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }
}
