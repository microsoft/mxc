// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use lxc_common::network_iptables::chain_name_for;
use std::fs;
use std::path::PathBuf;

fn scripts_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(|p| p.parent())
        .and_then(|p| p.parent())
        .and_then(|p| p.parent())
        .expect("could not determine repo root")
        .join("tests")
        .join("scripts")
}

const CHAIN_ASSERTING_SCRIPTS: &[&str] = &[
    "run_lxc_network_cidr_boundary_test.sh",
    "run_lxc_network_deny_precedence_test.sh",
    "run_lxc_network_dualstack_test.sh",
    "run_lxc_network_enforcement_test.sh",
    "run_lxc_network_invalid_cidr_test.sh",
    "run_lxc_network_ipv6_cidr_test.sh",
];

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

const MODELED_SHAPE_ERE: &str = "^MXC-([A-Za-z0-9_-]{1,7}-)?[a-z2-7]{16}$";

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

        assert!(
            body.contains("mxc_chains") || body.contains("derive_chain_name"),
            "{expected} asserts on MXC chains but never derives a chain name. \
             Without a derivation its assertions cannot be checking a real \
             chain. Use the mxc_chains snapshot or derive_chain_name."
        );
    }
}
