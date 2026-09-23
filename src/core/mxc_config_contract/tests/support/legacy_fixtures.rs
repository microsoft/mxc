// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use crate::FixtureRequest;
use std::path::Path;

fn fixtures(kind: &str) -> Vec<(String, String)> {
    let directory = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join(crate::FIXTURE_VERSION)
        .join("fixtures")
        .join(kind);
    crate::fixture_corpus::read_fixture_directory(&directory)
}

#[test]
fn accepts_every_discovered_valid_fixture() {
    for (name, json) in fixtures("valid") {
        serde_json::from_str::<FixtureRequest>(&json)
            .unwrap_or_else(|error| panic!("valid fixture '{name}' was rejected: {error}"));
    }
}

#[test]
fn rejects_every_discovered_invalid_fixture() {
    for (name, json) in fixtures("invalid") {
        assert!(
            serde_json::from_str::<FixtureRequest>(&json).is_err(),
            "invalid fixture '{name}' was accepted"
        );
    }
}
