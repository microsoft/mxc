// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#![cfg(all(windows, target_arch = "x86_64", feature = "microvm"))]

use aci_edge_sandboxes::agent::{AgentBackend, BundledAgent};
use aci_edge_sandboxes::ErrorCode;

#[path = "../../build/verify_nvx_runtime_signatures.rs"]
mod verify_nvx_runtime_signatures;
use verify_nvx_runtime_signatures::signature_verification;

#[test]
fn crate_staged_bundle_opens_and_rejects_an_unverified_library() {
    let bundle = BundledAgent::discover().expect("crate-staged agent bundle");
    let _verified = signature_verification::verify_bundle(bundle.directory())
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
    std::fs::create_dir(&bin).unwrap();
    for name in ["aci_edge_agent.dll", "openvmm.exe", "direct-images.exe"] {
        std::fs::copy(bundle.directory().join("bin").join(name), bin.join(name)).unwrap();
    }
    let verified = signature_verification::verify_bundle(state.path()).unwrap();
    let moved = state.path().join("moved-bin");
    let error = std::fs::rename(&bin, &moved).unwrap_err();
    assert!(matches!(error.raw_os_error(), Some(5 | 32)), "{error}");
    drop(verified);
    std::fs::rename(&bin, &moved).unwrap();
}

#[test]
fn verified_tools_can_execute_while_file_guards_are_held() {
    let bundle = BundledAgent::discover().expect("crate-staged agent bundle");
    let _verified = signature_verification::verify_bundle(bundle.directory()).unwrap();
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
            "signature rejection must precede loading the agent"
        );
        assert!(
            error
                .message
                .contains("Authenticode trust verification failed"),
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
    for rejected in ["aci_edge_agent.dll", "openvmm.exe", "direct-images.exe"] {
        let state = tempfile::tempdir().expect("isolated invalid runtime");
        std::fs::create_dir(state.path().join("bin")).unwrap();
        std::fs::copy(
            bundle.directory().join("SOURCE-MANIFEST.json"),
            state.path().join("SOURCE-MANIFEST.json"),
        )
        .unwrap();
        for name in ["aci_edge_agent.dll", "openvmm.exe", "direct-images.exe"] {
            let destination = state.path().join("bin").join(name);
            if name == rejected {
                std::fs::write(destination, b"unsigned runtime replacement").unwrap();
            } else {
                std::fs::copy(bundle.directory().join("bin").join(name), destination).unwrap();
            }
        }
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "json_execution_rejects_each_unsigned_binary_before_agent_load",
                "--nocapture",
            ])
            .env(CHILD, rejected)
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
