// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use crate::state_aware::common::{
    assert_invalid as assert_invalid_request, assert_valid as assert_valid_request,
};
use mxc_sdk::mxc_contract::dev::KataProvisionRequest;

fn assert_valid(json: &str) {
    assert_valid_request::<KataProvisionRequest>(json);
}

fn assert_invalid(json: &str) {
    assert_invalid_request::<KataProvisionRequest>(json);
}

fn request_with_additional_fields(additional_fields: &str) -> String {
    let separator = if additional_fields.is_empty() { "" } else { "," };
    format!(
        r#"{{
            "version": "1.1.0-alpha",
            "phase": "provision",
            "containment": "kata"{separator}
            {additional_fields}
        }}"#
    )
}

const KATA: &str = r#""kata": {"rootfs": "/srv/rootfs"}"#;

#[test]
fn accepts_the_minimal_request() {
    assert_valid(&request_with_additional_fields(KATA));
}

#[test]
fn accepts_policy_and_every_hypervisor() {
    for hypervisor in ["qemu", "clh", "cloud-hypervisor", "firecracker", "dragonball"] {
        assert_valid(&request_with_additional_fields(&format!(
            r#""kata": {{"rootfs": "/srv/rootfs", "hypervisor": "{hypervisor}"}},
               "filesystem": {{"readonlyPaths": ["/opt"]}},
               "network": {{"egress": {{"default": "deny"}}}},
               "telemetry": {{}}"#
        )));
    }
}

#[test]
fn requires_the_kata_section_and_its_rootfs() {
    assert_invalid(&request_with_additional_fields(""));
    assert_invalid(&request_with_additional_fields(r#""kata": {}"#));
    assert_invalid(&request_with_additional_fields(r#""kata": {"hypervisor": "qemu"}"#));
}

#[test]
fn rejects_unknown_fields_and_other_backend_sections() {
    assert_invalid(&request_with_additional_fields(&format!(
        r#"{KATA}, "sandbox": {{}}"#
    )));
    assert_invalid(&request_with_additional_fields(&format!(
        r#"{KATA}, "wslc": {{"provision": {{}}}}"#
    )));
    assert_invalid(&request_with_additional_fields(&format!(
        r#"{KATA}, "process": {{"commandLine": "echo"}}"#
    )));
}

#[test]
fn rejects_the_wrong_phase_or_containment() {
    assert_invalid(
        r#"{"version": "1.1.0-alpha", "phase": "start", "containment": "kata",
            "kata": {"rootfs": "/r"}}"#,
    );
    assert_invalid(
        r#"{"version": "1.1.0-alpha", "phase": "provision", "containment": "lxc",
            "kata": {"rootfs": "/r"}}"#,
    );
}
