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
/// Fails rather than returning an empty vector when the directory is missing or
/// holds no network scripts, so a broken path cannot look like a clean run.
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

/// The `sed` program `mxc_chains` uses to enumerate MXC-owned chains.
///
/// Legitimate because it names the prefix and matches whatever follows, rather
/// than claiming to know a specific digest.
const MXC_CHAIN_SED_PROGRAM: &str = r"s/^-N \(MXC-.*\)$/\1/p";

/// Every `MXC-<something>` on a line that is not one of the two legitimate
/// idioms: the pinned shape check and the chain-enumerating `sed` program.
///
/// Scans whole lines rather than just assignments, because a literal is just as
/// vacuous passed straight to an assertion --
/// `assert_no_forward_reference "MXC-CLI-LXC-Net-Deny"` names a chain that
/// cannot exist exactly as an assignment would.
fn illegal_mxc_literals(line: &str) -> Vec<String> {
    if line.trim_start().starts_with('#') {
        return Vec::new();
    }

    let stripped = line
        .replace(DOCUMENTED_SHAPE_ERE, " ")
        .replace(MXC_CHAIN_SED_PROGRAM, " ");

    let mut found = Vec::new();
    let mut search = stripped.as_str();
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

/// The one shape every script checks its derived chain name against.
///
/// Pinned here because the check is copy-pasted into each script: nothing in
/// bash ties those copies to each other or to `chain_name_for`, so a change to
/// the hash width would leave five stale patterns behind. The test below
/// hand-rolls this exact pattern's semantics, so changing the constant means
/// updating `matches_documented_shape` in the same edit.
const DOCUMENTED_SHAPE_ERE: &str = "^MXC-([A-Za-z0-9_-]{1,7}-)?[a-z2-7]{16}$";

/// Recognizer for [`DOCUMENTED_SHAPE_ERE`], hand-rolled to keep this suite free
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

/// Every `grep -Eq '<pattern>'` shape check found in the network scripts, as
/// (script name, line number, pattern).
///
/// A comment is not a check, and neither is a pattern that is not applied to
/// the derived name, so both are excluded: a disabled check that still mentions
/// the pattern would otherwise satisfy the guard below while validating
/// nothing. That makes this deliberately coupled to the scripts' exact idiom --
/// if the idiom changes, this stops finding checks and the guard fails loudly
/// rather than going quietly green.
fn shape_patterns() -> Vec<(String, usize, String)> {
    let mut found = Vec::new();
    for (name, body) in network_scripts() {
        for (index, line) in body.lines().enumerate() {
            if line.trim_start().starts_with('#')
                || !line.contains("grep -Eq")
                || !line.contains("<<<\"$CHAIN_NAME\"")
            {
                continue;
            }
            let Some(open) = line.find('\'') else {
                continue;
            };
            let Some(close) = line[open + 1..].find('\'') else {
                continue;
            };
            let pattern = &line[open + 1..open + 1 + close];
            found.push((name.clone(), index + 1, pattern.to_string()));
        }
    }
    found
}

#[test]
fn every_script_checks_the_same_documented_shape() {
    let patterns = shape_patterns();

    assert!(
        !patterns.is_empty(),
        "no chain-shape check found in any network script -- either the scripts \
         stopped validating the derived name, or this guard stopped finding the \
         check and is now verifying nothing"
    );

    let mismatched: Vec<String> = patterns
        .iter()
        .filter(|(_, _, pattern)| pattern != DOCUMENTED_SHAPE_ERE)
        .map(|(name, line, pattern)| format!("{name}:{line} uses '{pattern}'"))
        .collect();

    assert!(
        mismatched.is_empty(),
        "the chain-shape check is copy-pasted into each script, so every copy \
         must stay identical to the pinned shape '{DOCUMENTED_SHAPE_ERE}'. A \
         copy that drifts either rejects a valid name and fails the suite for \
         the wrong reason, or accepts a malformed one. Offenders:\n  {}",
        mismatched.join("\n  ")
    );
}

#[test]
fn the_pinned_shape_accepts_the_names_the_code_actually_produces() {
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
            "chain_name_for({input:?}) produced '{chain}', which the shape \
             pinned in every network script would reject. The scripts would \
             fail on a correct name, so the pinned shape is stale."
        );
    }
}

#[test]
fn a_script_that_derives_a_name_also_validates_its_shape() {
    let patterns = shape_patterns();

    for (name, body) in network_scripts() {
        // A script that never derives a name has nothing to validate. One that
        // does is about to feed that name to `iptables -S` and to a FORWARD
        // grep, so an unvalidated parse failure would hand those assertions a
        // malformed string instead of failing here.
        if !body.contains("derive_chain_name") {
            continue;
        }
        assert!(
            patterns.iter().any(|(script, _, _)| script == &name),
            "{name} derives a chain name but never checks its shape, so a \
             mis-parse reaches the chain assertions instead of failing loudly. \
             Add the pinned shape check '{DOCUMENTED_SHAPE_ERE}'."
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
