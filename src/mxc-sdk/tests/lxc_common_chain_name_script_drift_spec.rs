// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use mxc_sdk::lxc_common::network_iptables::chain_name_for;
use std::collections::BTreeSet;
use std::fs;
use std::path::PathBuf;

fn scripts_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(|p| p.parent())
        .expect("could not determine repo root")
        .join("tests")
        .join("scripts")
}

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
fn cidr_fixtures_retain_the_destinations_the_kernel_checks_expect() {
    let cases: [(&str, &[&str], &[&str]); 3] = [
        (
            "lxc_network_cidr_boundary",
            &[
                "0.0.0.0/0",
                "::/0",
                "140.82.112.0/20",
                "140.82.112.5/32",
                "2606:50c0::/32",
            ],
            &["198.51.100.42/32", "2001:db8::5/128"],
        ),
        (
            "lxc_network_ipv6_cidr",
            &[
                "140.82.112.0/20",
                "2606:50c0::/32",
                "2606:50c0:8000::153/128",
            ],
            &["10.0.0.0/8", "2001:db8::/32", "fe80::1/128"],
        ),
        (
            "lxc_network_dualstack_cidr",
            &[
                "127.0.0.1/32",
                "1.1.1.1/32",
                "2606:4700:4700::1111/128",
                "8.8.8.8/32",
                "2001:4860:4860::8888/128",
            ],
            &["10.0.0.0/8", "2001:db8::/32"],
        ),
    ];
    for (fixture, allow, deny) in cases {
        let path = scripts_dir()
            .parent()
            .expect("scripts directory has no parent")
            .join("configs")
            .join(format!("{fixture}.json"));
        let config: serde_json::Value =
            serde_json::from_slice(&fs::read(&path).expect("could not read CIDR fixture"))
                .expect("CIDR fixture is not valid JSON");
        let egress = &config["network"]["egress"];
        assert_eq!(egress["default"], "deny", "{fixture} changed its default");
        for (action, expected) in [("allow", allow), ("deny", deny)] {
            let actual: BTreeSet<_> = egress[action]
                .as_array()
                .expect("CIDR rules are not an array")
                .iter()
                .flat_map(|rule| {
                    rule["to"]
                        .as_array()
                        .expect("CIDR destinations are not an array")
                })
                .map(|target| target["cidr"].as_str().expect("CIDR is not a string"))
                .collect();
            assert_eq!(
                actual,
                expected.iter().copied().collect::<BTreeSet<_>>(),
                "{fixture} changed the {action} destinations checked in the host kernel"
            );
        }
    }
}

#[cfg(target_os = "linux")]
#[test]
fn ordinary_raw_packet_controls_survive_unavailable_io_uring() {
    let output = std::process::Command::new("python3")
        .env("PYTHONDONTWRITEBYTECODE", "1")
        .arg(
            scripts_dir()
                .join("lib")
                .join("test_io_uring_egress_probe.py"),
        )
        .output()
        .expect("could not run the offline raw/packet probe regression");
    assert!(
        output.status.success(),
        "ordinary raw/packet checks disappeared when io_uring was unavailable:\n{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}
