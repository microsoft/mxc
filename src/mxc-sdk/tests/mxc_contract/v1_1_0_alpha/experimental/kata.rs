// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use crate::common::{assert_invalid, assert_valid};

fn kata_request(fields: &str) -> String {
    format!(
        r#"{{
            "version": "1.1.0-alpha",
            "containment": "kata",
            "kata": {{{fields}}},
            "process": {{"commandLine": "uname -r"}}
        }}"#
    )
}

#[test]
fn accepts_a_rootfs_alone() {
    assert_valid(&kata_request(r#""rootfs": "/srv/rootfs""#));
}

#[test]
fn accepts_every_hypervisor_spelling() {
    for hypervisor in ["qemu", "clh", "cloud-hypervisor", "firecracker", "dragonball"] {
        assert_valid(&kata_request(&format!(
            r#""rootfs": "/srv/rootfs.ext4", "hypervisor": "{hypervisor}""#
        )));
    }
}

#[test]
fn requires_a_rootfs_when_the_section_is_present() {
    assert_invalid(&kata_request(""));
    assert_invalid(&kata_request(r#""hypervisor": "qemu""#));
}

#[test]
fn rejects_unknown_hypervisor_values() {
    for value in [
        r#""Qemu""#,
        r#""kvm""#,
        r#""xen""#,
        r#""""#,
        "1",
        "true",
        "null",
        "[]",
        "{}",
    ] {
        assert_invalid(&kata_request(&format!(
            r#""rootfs": "/srv/rootfs", "hypervisor": {value}"#
        )));
    }
}

#[test]
fn rejects_a_non_string_rootfs() {
    for value in ["1", "true", "null", "[]", "{}"] {
        assert_invalid(&kata_request(&format!(r#""rootfs": {value}"#)));
    }
}

#[test]
fn rejects_unknown_kata_fields() {
    assert_invalid(&kata_request(r#""rootfs": "/srv/rootfs", "image": "alpine""#));
    assert_invalid(&kata_request(
        r#""rootfs": "/srv/rootfs", "configPath": "/etc/kata.toml""#,
    ));
}
