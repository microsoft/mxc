// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use std::fs;
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
