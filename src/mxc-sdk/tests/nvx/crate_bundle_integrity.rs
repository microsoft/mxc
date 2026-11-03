// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#![cfg(all(windows, target_arch = "x86_64", feature = "microvm"))]

use aci_edge_sandboxes::agent::{AgentBackend, BundledAgent};
use aci_edge_sandboxes::ErrorCode;

#[test]
fn crate_staged_bundle_opens_and_rejects_an_unverified_library() {
    let bundle = BundledAgent::discover().expect("crate-staged agent bundle");
    let state = tempfile::tempdir().expect("private test state");
    let config = bundle.config(bundle.setup(state.path()));
    let backend = AgentBackend::new(config.clone()).expect("verified signed runtime opens");
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
