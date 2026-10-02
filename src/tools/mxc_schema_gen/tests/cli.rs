// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use std::fs;
use std::process::Command;

#[test]
fn writes_schema_to_bare_filename() {
    let directory = tempfile::tempdir().expect("create temporary directory");
    let output = Command::new(env!("CARGO_BIN_EXE_mxc_schema_gen"))
        .current_dir(directory.path())
        .args(["schema", "--version", "1.1.0-alpha", "--out", "schema.json"])
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
fn writes_csharp_to_nested_filename() {
    let directory = tempfile::tempdir().expect("create temporary directory");
    let output = Command::new(env!("CARGO_BIN_EXE_mxc_schema_gen"))
        .current_dir(directory.path())
        .args([
            "csharp",
            "--version",
            "1.0.0",
            "--out",
            "Generated/MxcConfigV1_0_0.g.cs",
        ])
        .output()
        .expect("run C# generator");

    assert!(
        output.status.success(),
        "C# generator failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let csharp = fs::read_to_string(
        directory
            .path()
            .join("Generated")
            .join("MxcConfigV1_0_0.g.cs"),
    )
    .expect("read generated C#");
    assert!(
        csharp.contains("internal sealed class OneShotRequest"),
        "{csharp}"
    );
}
