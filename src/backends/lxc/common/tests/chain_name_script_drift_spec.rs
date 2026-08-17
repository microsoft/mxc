// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Drift guard: the bash network scripts must derive the firewall chain name at
//! run time rather than hard-coding it.
//!
//! This is deliberately not a unit test. It reads the repository from disk, so
//! it crosses Feathers' file-system line, and it lives in its own file so that
//! `chain_name_spec.rs` stays filesystem- and dependency-free.
//!
//! Why it exists rather than more `chain_name_for` cases: on the day
//! `run_lxc_network_enforcement_test.sh` was asserting against
//! `MXC-CLI-LXC-Net-Deny`, every one of the twenty naming tests in
//! `chain_name_spec.rs` was green. They cover what the function returns, and
//! the defect was in what the scripts believed it returned. A chain name is a
//! digest of the container name, so a literal in a script names a chain that
//! cannot exist: `iptables -S <that name>` always fails, the cleanup assertion
//! reads that failure as "the chain was removed", and the test passes without
//! examining anything. Catching that class requires reading the scripts.

use lxc_common::network_iptables::chain_name_for;
use std::fs;
use std::path::PathBuf;

/// Repository `tests/scripts/` directory.
///
/// `CARGO_MANIFEST_DIR` is `src/backends/lxc/common/` during `cargo test`.
fn scripts_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent() // src/backends/lxc
        .and_then(|p| p.parent()) // src/backends
        .and_then(|p| p.parent()) // src
        .and_then(|p| p.parent()) // repo root
        .expect("could not determine repo root")
        .join("tests")
        .join("scripts")
}

/// The network scripts that make assertions about MXC-owned chains, and so must
/// derive the chain name instead of naming one.
///
/// Enumerated rather than discovered: a glob would silently shrink to zero on a
/// rename or a path change and still report success, which is the same
/// vacuous-pass defect this file exists to catch. A new network script that
/// asserts on chains belongs in this list.
const CHAIN_ASSERTING_SCRIPTS: &[&str] = &[
    "run_lxc_network_cidr_boundary_test.sh",
    "run_lxc_network_deny_precedence_test.sh",
    "run_lxc_network_dualstack_test.sh",
    "run_lxc_network_enforcement_test.sh",
    "run_lxc_network_invalid_cidr_test.sh",
    "run_lxc_network_ipv6_cidr_test.sh",
];

/// Read every `run_lxc_network_*.sh` as (file name, contents).
///
/// A missing directory or an empty match is a hard failure: a drift guard that
/// finds nothing to check is indistinguishable from one that passes.
fn network_scripts() -> Vec<(String, String)> {
    let dir = scripts_dir();
    let entries =
        fs::read_dir(&dir).unwrap_or_else(|e| panic!("could not read {}: {e}", dir.display()));

    let mut scripts = Vec::new();
    for entry in entries {
        let path = entry.expect("could not read a directory entry").path();
        let Some(name) = path.file_name().and_then(|n| n.to_str()) else {
            continue;
        };
        if !name.starts_with("run_lxc_network_") || !name.ends_with(".sh") {
            continue;
        }
        let body = fs::read_to_string(&path)
            .unwrap_or_else(|e| panic!("could not read {}: {e}", path.display()));
        scripts.push((name.to_string(), body));
    }

    assert!(
        !scripts.is_empty(),
        "no run_lxc_network_*.sh scripts found under {} -- this guard verified nothing",
        dir.display()
    );
    scripts
}

/// Every `MXC-<something>` on a line of a network script.
///
/// A hard-coded chain name is vacuous wherever it appears, not only in an
/// assignment: `assert_no_forward_reference "MXC-CLI-LXC-Net-Deny"` names a
/// chain that can never exist, and so asserts nothing about the real one.
///
/// The legitimate idioms -- the shape check and the chain-enumerating `sed`
/// program -- live in `lib/chain_name.sh`, which this never scans, so there is
/// nothing here to exempt.
fn illegal_mxc_literals(line: &str) -> Vec<String> {
    if line.trim_start().starts_with('#') {
        return Vec::new();
    }

    let mut found = Vec::new();
    let mut search = line;
    while let Some(at) = search.find("MXC-") {
        search = &search[at + "MXC-".len()..];
        let tail: String = search
            .chars()
            .take_while(|c| c.is_ascii_alphanumeric() || *c == '-' || *c == '_')
            .collect();
        if !tail.is_empty() {
            found.push(format!("MXC-{tail}"));
        }
    }
    found
}

#[test]
fn no_network_script_names_a_specific_chain() {
    let mut offenders = Vec::new();

    for (name, body) in network_scripts() {
        for (index, line) in body.lines().enumerate() {
            for literal in illegal_mxc_literals(line) {
                offenders.push(format!("{name}:{} names '{literal}'", index + 1));
            }
        }
    }

    assert!(
        offenders.is_empty(),
        "chain names are derived from a digest of the container name, so naming \
         a specific chain -- whether by assignment or inline in an assertion -- \
         names one that cannot exist, and every assertion against it passes \
         vacuously. Derive the name from the run's own --debug output instead. \
         Offenders:\n  {}",
        offenders.join("\n  ")
    );
}

/// The chain shape [`matches_documented_shape`] models.
///
/// Not a second copy of the scripts' check: the scripts apply exactly one
/// pattern, in `lib/chain_name.sh`, and the test below reads it from there.
/// This is the tripwire that fires when that pattern changes and the
/// hand-rolled recognizer no longer models it.
const MODELED_SHAPE_ERE: &str = "^MXC-([A-Za-z0-9_-]{1,7}-)?[a-z2-7]{16}$";

/// The chain shape the scripts actually check, read from the shared helper.
fn helper_shape_ere() -> String {
    let path = scripts_dir().join("lib").join("chain_name.sh");
    let body = fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("could not read {}: {e}", path.display()));

    for line in body.lines() {
        if let Some(rest) = line.strip_prefix("MXC_CHAIN_NAME_ERE=") {
            return rest.trim().trim_matches('\'').to_string();
        }
    }

    panic!(
        "{} no longer defines MXC_CHAIN_NAME_ERE, so the shape the scripts \
         check could not be found and this guard verified nothing",
        path.display()
    );
}

/// Recognizer for [`MODELED_SHAPE_ERE`], hand-rolled to keep this suite free
/// of a regex dependency, matching the convention in `chain_name_spec.rs`.
///
/// The 16-character base32 hash is a fixed-width suffix, so the separator (when
/// a slug is present) is always the byte immediately before it, which makes the
/// parse unambiguous even though `-` is legal inside the slug.
fn matches_documented_shape(chain: &str) -> bool {
    if !chain.is_ascii() {
        return false;
    }
    let Some(rest) = chain.strip_prefix("MXC-") else {
        return false;
    };
    if rest.len() < 16 {
        return false;
    }
    let (head, hash) = rest.split_at(rest.len() - 16);
    if !hash.bytes().all(|b| matches!(b, b'a'..=b'z' | b'2'..=b'7')) {
        return false;
    }
    if head.is_empty() {
        return true;
    }
    let Some(slug) = head.strip_suffix('-') else {
        return false;
    };
    !slug.is_empty()
        && slug.len() <= 7
        && slug
            .bytes()
            .all(|b| matches!(b, b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'_' | b'-'))
}

#[test]
fn the_shape_the_scripts_check_accepts_the_names_the_code_produces() {
    assert_eq!(
        helper_shape_ere(),
        MODELED_SHAPE_ERE,
        "the shared helper's chain-shape pattern changed, so the recognizer in \
         this file no longer models what bash applies and the check below \
         proves nothing about the scripts. Update both together."
    );

    // Representative of what the scripts feed it: ordinary names, names whose
    // slug is exhausted or absent, and a name long enough to be truncated.
    for input in [
        "lxc-network-enforcement-deny",
        "lxc_network_deny_precedence_control",
        "web",
        "",
        "----",
        &"container-name-that-is-very-long".repeat(8),
    ] {
        let chain = chain_name_for(input);
        assert!(
            matches_documented_shape(&chain),
            "chain_name_for({input:?}) produced '{chain}', which the shape the \
             network scripts check would reject. The scripts would fail on a \
             correct name, so the shared pattern is stale."
        );
    }
}

#[test]
fn every_chain_asserting_script_derives_the_name_it_asserts_on() {
    let scripts = network_scripts();

    for expected in CHAIN_ASSERTING_SCRIPTS {
        let (_, body) = scripts
            .iter()
            .find(|(name, _)| name == expected)
            .unwrap_or_else(|| {
                panic!(
                    "{expected} is listed as a chain-asserting script but is not in {}. \
                     If it was renamed or removed, update CHAIN_ASSERTING_SCRIPTS.",
                    scripts_dir().display()
                )
            });

        // Either idiom reads the name back from the run rather than assuming
        // it: `mxc_chains` enumerates the chains a tool actually holds, and
        // `derive_chain_name` parses the name out of this run's --debug output.
        assert!(
            body.contains("mxc_chains") || body.contains("derive_chain_name"),
            "{expected} asserts on MXC chains but never derives a chain name. \
             Without a derivation its assertions cannot be checking a real \
             chain. Use the mxc_chains snapshot or derive_chain_name."
        );
    }
}
