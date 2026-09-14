// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use std::fs;
use std::path::Path;
use std::process::Command;

#[test]
fn writes_schema_to_bare_filename() {
    let directory = tempfile::tempdir().expect("create temporary directory");
    let output = Command::new(env!("CARGO_BIN_EXE_mxc_schema_gen"))
        .current_dir(directory.path())
        .args(["schema", "--legacy-wire", "--out", "schema.json"])
        .output()
        .expect("run schema generator");

    assert!(
        output.status.success(),
        "schema generator failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let schema =
        fs::read_to_string(directory.path().join("schema.json")).expect("read generated schema");
    assert!(schema.contains("\"$schema\""), "{schema}");
}

#[test]
fn regenerates_contract_registry() {
    let directory = tempfile::tempdir().expect("create temporary directory");
    let output_path = directory.path().join("contract-registry.generated.json");
    let repo_root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join("..");
    let output = Command::new(env!("CARGO_BIN_EXE_mxc_schema_gen"))
        .args([
            "registry",
            "--repo-root",
            repo_root.to_str().expect("UTF-8 repository path"),
            "--out",
            output_path.to_str().expect("UTF-8 output path"),
        ])
        .output()
        .expect("run registry generator");

    assert!(
        output.status.success(),
        "registry generator failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let generated = fs::read_to_string(output_path).expect("read generated registry");
    let registry: serde_json::Value =
        serde_json::from_str(&generated).expect("parse generated registry");
    assert!(registry["$comment"]
        .as_str()
        .unwrap()
        .contains("Rust exact-contract registry"));
    let contracts = registry["contracts"].as_array().expect("contract array");
    assert_eq!(
        contracts
            .iter()
            .find(|contract| contract["version"] == "0.9.0-alpha")
            .unwrap()["status"],
        "development"
    );
}

#[test]
fn publication_dry_run_does_not_modify_the_repository() {
    let repo_root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join("..");
    let output = Command::new(env!("CARGO_BIN_EXE_mxc_schema_gen"))
        .args([
            "publish",
            "--version",
            "0.9.0-alpha",
            "--next-dev",
            "0.10.0-alpha",
            "--repo-root",
            repo_root.to_str().expect("UTF-8 repository path"),
            "--dry-run",
        ])
        .output()
        .expect("run publication dry-run");

    assert!(
        output.status.success(),
        "publication dry-run failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(String::from_utf8_lossy(&output.stdout)
        .contains("then update the Rust registry to publish 0.9.0-alpha"));
}

#[test]
fn publication_writes_only_the_stable_schema() {
    let directory = tempfile::tempdir().expect("create temporary directory");
    let repo_root = directory.path();
    let output = Command::new(env!("CARGO_BIN_EXE_mxc_schema_gen"))
        .args([
            "publish",
            "--version",
            "0.9.0-alpha",
            "--next-dev",
            "0.10.0-alpha",
            "--repo-root",
            repo_root.to_str().expect("UTF-8 repository path"),
        ])
        .output()
        .expect("run publication");
    assert!(
        output.status.success(),
        "publication failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("published schema SHA-256:"));
    assert!(stdout.contains("update the Rust ContractVersion/CONTRACTS registry"));

    let schema = fs::read_to_string(
        repo_root
            .join("schemas")
            .join("stable")
            .join("mxc-config.schema.0.9.0-alpha.json"),
    )
    .expect("read published schema");
    assert!(!schema.contains("\"experimental\""));
    assert!(!schema.contains("\"windows_sandbox\""));
    assert!(schema.contains("\"processcontainer\""));
    assert!(!repo_root
        .join("schemas")
        .join("contract-registry.generated.json")
        .exists());

    let repeated = Command::new(env!("CARGO_BIN_EXE_mxc_schema_gen"))
        .args([
            "publish",
            "--version",
            "0.9.0-alpha",
            "--next-dev",
            "0.10.0-alpha",
            "--repo-root",
            repo_root.to_str().expect("UTF-8 repository path"),
        ])
        .output()
        .expect("repeat publication");
    assert!(!repeated.status.success());
}
