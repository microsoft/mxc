// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use serde::de::DeserializeOwned;
use std::fs;
use std::path::Path;

pub(crate) fn assert_valid<T: DeserializeOwned>(json: &str) {
    serde_json::from_str::<T>(json).unwrap();
}

pub(crate) fn assert_invalid<T: DeserializeOwned>(json: &str, context: &str) {
    if let Err(error) = serde_json::from_str::<serde_json::Value>(json) {
        panic!("{context} used malformed test JSON: {error}");
    }
    assert!(
        serde_json::from_str::<T>(json).is_err(),
        "{context} was accepted"
    );
}

pub(crate) fn with_contract_version(json: &str, version: &str) -> String {
    let non_exact = version.strip_suffix("-alpha").unwrap_or(version);
    json.replace("\"0.9.0-alpha\"", &format!("\"{version}\""))
        .replace("\"0.9.0\"", &format!("\"{non_exact}\""))
}

pub(crate) fn assert_versioned_valid<T: DeserializeOwned>(json: &str, version: &str) {
    assert_valid::<T>(&with_contract_version(json, version));
}

pub(crate) fn assert_versioned_invalid<T: DeserializeOwned>(json: &str, version: &str) {
    assert_invalid::<T>(
        &with_contract_version(json, version),
        "invalid configuration",
    );
}

pub(crate) fn assert_versioned_invalid_cases<'a, T: DeserializeOwned>(
    cases: impl IntoIterator<Item = (&'a str, &'a str, &'a str)>,
    failure_kind: &str,
    version: &str,
) {
    for (name, required_fields, invalid_fields) in cases {
        let json = format!(
            r#"{{
                {required_fields},
                {invalid_fields}
            }}"#
        );
        assert_invalid::<T>(
            &with_contract_version(&json, version),
            &format!("{failure_kind} '{name}'"),
        );
    }
}

pub(crate) fn read_fixtures(
    manifest_dir: &str,
    version: &str,
    root: &str,
    kind: &str,
) -> Vec<(String, String)> {
    let directory = Path::new(manifest_dir)
        .join("tests")
        .join(version)
        .join("fixtures")
        .join(root)
        .join(kind);
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

pub(crate) fn assert_root_fixtures<T: DeserializeOwned>(
    manifest_dir: &str,
    version: &str,
    root: &str,
) {
    for (name, json) in read_fixtures(manifest_dir, version, root, "valid") {
        serde_json::from_str::<T>(&json)
            .unwrap_or_else(|error| panic!("valid fixture '{root}/valid/{name}' failed: {error}"));
    }

    for (name, json) in read_fixtures(manifest_dir, version, root, "invalid") {
        assert!(
            serde_json::from_str::<T>(&json).is_err(),
            "invalid fixture '{root}/invalid/{name}' was accepted"
        );
    }
}
