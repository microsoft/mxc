// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Every config in the repository corpus must declare a schema version and
//! still parse.
//!
//! The behavioural counter-check to the first-appearance oracle, which can only
//! see when a field appeared *in the schema* — not that it was accepted for
//! longer than the schema described it (`experimental`, and the state-aware
//! `phase`/`sandboxId` pair). An annotation can look right against the schemas
//! and still break configs that have always worked.

use std::fs;
use std::path::{Path, PathBuf};

use wxc_common::config_parser::{load_mxc_request_from_json, ParseError};
use wxc_common::error::WxcError;
use wxc_common::logger::{Logger, Mode};

/// Fixtures that are deliberately rejected; one that starts passing is as much
/// a regression as a positive case that starts failing.
const EXPECTED_REJECTIONS: &[&str] = &["tests/configs/rejected_version_too_old.json"];

fn repo_root() -> PathBuf {
    // .../src/core/wxc_common -> repo root
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(3)
        .expect("the crate lives three levels below the repo root")
        .to_path_buf()
}

fn collect(dir: &Path, root: &Path, out: &mut Vec<(String, PathBuf)>) {
    let Ok(entries) = fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            collect(&path, root, out);
        } else if path.extension().is_some_and(|e| e == "json") {
            let rel = path
                .strip_prefix(root)
                .expect("collected under the root")
                .to_string_lossy()
                .replace('\\', "/");
            out.push((rel, path));
        }
    }
}

fn corpus() -> Vec<(String, PathBuf)> {
    let root = repo_root();
    let mut out = Vec::new();
    for dir in ["tests/examples", "tests/configs"] {
        collect(&root.join(dir), &root, &mut out);
    }
    out.sort();
    assert!(
        out.len() > 150,
        "expected the full corpus, found only {} file(s) under {}",
        out.len(),
        root.display()
    );
    out
}

#[test]
fn every_corpus_config_declares_a_version() {
    let mut missing = Vec::new();
    for (rel, path) in corpus() {
        let text = fs::read_to_string(&path).expect("corpus file is readable");
        let value: serde_json::Value =
            serde_json::from_str(&text).unwrap_or_else(|e| panic!("{rel}: invalid JSON: {e}"));
        match value.get("version").and_then(serde_json::Value::as_str) {
            Some(v) if !v.is_empty() => {}
            _ => missing.push(rel),
        }
    }
    assert!(
        missing.is_empty(),
        "`version` is required, so every corpus config must declare one. Missing in:\n  {}",
        missing.join("\n  ")
    );
}

#[test]
fn every_corpus_config_parses() {
    let files = corpus();
    let mut failures = Vec::new();
    let mut unexpectedly_accepted = Vec::new();

    // A deleted or renamed negative fixture must fail rather than silently
    // reduce this to a positive-only test.
    for expected in EXPECTED_REJECTIONS {
        assert!(
            files.iter().any(|(rel, _)| rel == expected),
            "negative fixture `{expected}` is missing from the corpus; it is what proves \
             an unsupported version is still rejected"
        );
    }

    for (rel, path) in files {
        let text = fs::read_to_string(&path).expect("corpus file is readable");
        let mut logger = Logger::new(Mode::Buffer);
        let result = load_mxc_request_from_json(&text, &mut logger);
        let expected_rejection = EXPECTED_REJECTIONS.contains(&rel.as_str());

        match (result, expected_rejection) {
            (Ok(_), false) => {}
            (Err(_), true) => {}
            (Ok(_), true) => unexpectedly_accepted.push(rel),
            (Err(e), false) => failures.push(format!("{rel}: {e:?}")),
        }
    }

    assert!(
        failures.is_empty(),
        "corpus configs failed to parse:\n  {}",
        failures.join("\n  ")
    );
    assert!(
        unexpectedly_accepted.is_empty(),
        "these are negative fixtures and must keep being rejected:\n  {}",
        unexpectedly_accepted.join("\n  ")
    );
}

#[test]
fn the_out_of_range_fixture_is_rejected_for_the_right_reason() {
    // Accepting any error would let a typo or unrelated failure pass.
    let root = repo_root();
    let path = root.join("tests/configs/rejected_version_too_old.json");
    let text = fs::read_to_string(&path).expect("the negative fixture is readable");
    let mut logger = Logger::new(Mode::Buffer);

    let error = load_mxc_request_from_json(&text, &mut logger)
        .expect_err("a version below the supported floor must be rejected");
    let details = match error {
        ParseError::OneShot(WxcError::VersionIncompatible(details)) => details,
        other => panic!("expected a one-shot VersionIncompatible, got {other:?}"),
    };
    assert_eq!(details.field, "version");
    assert_eq!(details.since.as_deref(), Some("0.6"));
    assert_eq!(details.until.as_deref(), Some("0.8"));
    assert!(
        details.message.contains("older than supported"),
        "got: {}",
        details.message
    );
}
