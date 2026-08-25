// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use mxc_config_contract::dev::{
    DeprovisionRequest, ExecRequest, IsolationSessionProvisionRequest, OneShotRequest,
    StartRequest, StopRequest, WindowsSandboxProvisionRequest, WslcProvisionRequest,
};
use serde::de::DeserializeOwned;
use std::fs;
use std::path::{Path, PathBuf};

fn fixture_directory(root: &str, kind: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("v0_9_0_alpha")
        .join("fixtures")
        .join(root)
        .join(kind)
}

fn read_fixtures(root: &str, kind: &str) -> Vec<(String, String)> {
    let directory = fixture_directory(root, kind);
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

fn assert_root_fixtures<T>(root: &str)
where
    T: DeserializeOwned,
{
    for (name, json) in read_fixtures(root, "valid") {
        serde_json::from_str::<T>(&json)
            .unwrap_or_else(|error| panic!("valid fixture '{root}/valid/{name}' failed: {error}"));
    }

    for (name, json) in read_fixtures(root, "invalid") {
        assert!(
            serde_json::from_str::<T>(&json).is_err(),
            "invalid fixture '{root}/invalid/{name}' was accepted"
        );
    }
}

#[test]
fn accepts_and_rejects_every_discovered_fixture() {
    assert_root_fixtures::<OneShotRequest>("one_shot");
    assert_root_fixtures::<WindowsSandboxProvisionRequest>("windows_sandbox_provision");
    assert_root_fixtures::<IsolationSessionProvisionRequest>("isolation_session_provision");
    assert_root_fixtures::<WslcProvisionRequest>("wslc_provision");
    assert_root_fixtures::<StartRequest>("start");
    assert_root_fixtures::<ExecRequest>("exec");
    assert_root_fixtures::<StopRequest>("stop");
    assert_root_fixtures::<DeprovisionRequest>("deprovision");
}
