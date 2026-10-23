// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use super::common::{adapt, assert_clean_common};
use crate::mxc_common::models::WslcProvisionSessionConfig;
use crate::mxc_common::state_aware_operation::StateAwareOperation;

fn provision_session(
    fields: &str,
) -> (
    crate::mxc_common::common_request_ir::CommonRequestIR,
    StateAwareOperation,
) {
    adapt(&format!(
        r#"{{"version":"1.1.0-alpha","phase":"provision-session","containment":"wslc"{fields}}}"#
    ))
}

#[test]
fn an_absent_wslc_section_leaves_the_sizing_absent() {
    for fields in ["", r#","wslc":{}"#, r#","wslc":{"provisionSession":{}}"#] {
        let (common, operation) = provision_session(fields);
        assert_clean_common(&common);
        assert!(common.process.is_none());
        assert!(common.filesystem.is_none());
        assert!(common.network.is_none());

        let expected = if fields.contains("provisionSession") {
            Some(WslcProvisionSessionConfig::default())
        } else {
            None
        };
        assert_eq!(
            operation,
            StateAwareOperation::ProvisionSession(expected),
            "{fields}"
        );
    }
}

#[test]
fn each_sizing_field_survives_adaptation_independently() {
    let (_, operation) = provision_session(
        r#","wslc":{"provisionSession":{"cpuCount":4,"memoryMb":8192,"gpu":true}}"#,
    );
    assert_eq!(
        operation,
        StateAwareOperation::ProvisionSession(Some(WslcProvisionSessionConfig {
            cpu_count: Some(4),
            memory_mb: Some(8192),
            gpu: Some(true),
        }))
    );

    let (_, gpu_off) = provision_session(r#","wslc":{"provisionSession":{"gpu":false}}"#);
    assert_eq!(
        gpu_off,
        StateAwareOperation::ProvisionSession(Some(WslcProvisionSessionConfig {
            gpu: Some(false),
            ..Default::default()
        })),
        "an explicit false must not read as an absent field"
    );
}

#[test]
fn a_session_release_carries_its_id_and_nothing_else() {
    let (common, operation) = adapt(
        r#"{"version":"1.1.0-alpha","phase":"deprovision-session","containment":"wslc",
            "sessionId":"wslcsess:0123456789abcdef0123456789abcdef"}"#,
    );
    assert_clean_common(&common);
    assert!(common.process.is_none());
    assert!(common.filesystem.is_none());
    assert!(common.network.is_none());
    assert_eq!(
        operation,
        StateAwareOperation::DeprovisionSession {
            session_id: "wslcsess:0123456789abcdef0123456789abcdef".to_string(),
        }
    );
}

#[test]
fn both_session_phases_declare_wslc_containment() {
    let (_, provisioned) = provision_session("");
    let (_, released) = adapt(
        r#"{"version":"1.1.0-alpha","phase":"deprovision-session","containment":"wslc",
            "sessionId":"wslcsess:0123456789abcdef0123456789abcdef"}"#,
    );
    for operation in [provisioned, released] {
        assert_eq!(
            operation.containment(),
            Some(crate::mxc_common::models::ContainmentBackend::Wslc)
        );
        assert!(operation.sandbox_id().is_none());
    }
}

#[test]
fn a_provision_carries_the_session_it_joins_only_when_one_is_named() {
    let config = |fields: &str| {
        let (_, operation) = adapt(&format!(
            r#"{{"version":"1.1.0-alpha","phase":"provision","containment":"wslc",
                 "wslc":{{"provision":{{{fields}}}}}}}"#
        ));
        let StateAwareOperation::Provision(
            crate::mxc_common::state_aware_operation::StateAwareProvision::Wslc(config),
        ) = operation
        else {
            panic!("expected a WSLc provision");
        };
        config.expect("a present provision section yields a config")
    };

    assert_eq!(config(r#""image":"alpine:latest""#).session_id, None);
    assert_eq!(
        config(r#""sessionId":"wslcsess:0123456789abcdef0123456789abcdef""#).session_id,
        Some("wslcsess:0123456789abcdef0123456789abcdef".to_string())
    );
    assert_eq!(
        config(r#""sessionId":"""#).session_id,
        Some(String::new()),
        "an explicitly empty string is distinct from an absent field"
    );
}
