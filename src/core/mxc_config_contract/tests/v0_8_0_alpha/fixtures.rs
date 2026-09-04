// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use mxc_config_contract::published::v0_8_0_alpha::Request;
use std::fs;
use std::path::{Path, PathBuf};

fn fixture_directory(kind: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("v0_8_0_alpha")
        .join("fixtures")
        .join(kind)
}

fn read_fixtures(kind: &str) -> Vec<(String, String)> {
    let directory = fixture_directory(kind);
    let mut paths = fs::read_dir(&directory)
        .unwrap_or_else(|error| panic!("failed to read {}: {error}", directory.display()))
        .map(|entry| {
            entry
                .unwrap_or_else(|error| {
                    panic!(
                        "failed to read an entry in {}: {error}",
                        directory.display()
                    )
                })
                .path()
        })
        .filter(|path| {
            path.extension()
                .is_some_and(|extension| extension == "json")
        })
        .collect::<Vec<_>>();
    paths.sort();
    assert!(
        !paths.is_empty(),
        "fixture directory {} is empty",
        directory.display()
    );

    paths
        .into_iter()
        .map(|path| {
            let name = path
                .file_name()
                .expect("fixture path should have a file name")
                .to_string_lossy()
                .into_owned();
            let json = fs::read_to_string(&path)
                .unwrap_or_else(|error| panic!("failed to read {}: {error}", path.display()));
            (name, json)
        })
        .collect()
}

#[test]
fn accepts_every_discovered_valid_fixture() {
    for (name, json) in read_fixtures("valid") {
        serde_json::from_str::<Request>(&json)
            .unwrap_or_else(|error| panic!("valid fixture '{name}' was rejected: {error}"));
    }
}

#[test]
fn rejects_every_discovered_invalid_fixture() {
    for (name, json) in read_fixtures("invalid") {
        assert!(
            serde_json::from_str::<Request>(&json).is_err(),
            "invalid fixture '{name}' was accepted"
        );
    }
}
