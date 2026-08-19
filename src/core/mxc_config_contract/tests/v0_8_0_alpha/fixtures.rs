// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use mxc_config_contract::dev::{
    DeprovisionRequest, ExecRequest, IsolationSessionProvisionRequest, OneShotRequest,
    StartRequest, StopRequest, WindowsSandboxProvisionRequest, WslcProvisionRequest,
};
use serde::de::DeserializeOwned;

const VALID_FIXTURES: &[(&str, &str)] = &[
    (
        "minimal",
        include_str!("fixtures/one_shot/valid/minimal.json"),
    ),
    (
        "complete",
        include_str!("fixtures/one_shot/valid/complete.json"),
    ),
    (
        "experimental field",
        include_str!("fixtures/one_shot/valid/experimental.json"),
    ),
    (
        "empty optional objects",
        include_str!("fixtures/one_shot/valid/empty_optional_objects.json"),
    ),
    (
        "appContainer alias",
        include_str!("fixtures/one_shot/valid/app_container_alias.json"),
    ),
    (
        "localhost proxy",
        include_str!("fixtures/one_shot/valid/proxy_localhost.json"),
    ),
    (
        "built-in proxy",
        include_str!("fixtures/one_shot/valid/proxy_builtin.json"),
    ),
    (
        "URL proxy",
        include_str!("fixtures/one_shot/valid/proxy_url.json"),
    ),
    (
        "schema and comments",
        include_str!("fixtures/one_shot/valid/annotations.json"),
    ),
    (
        "macos_sandbox alias",
        include_str!("fixtures/one_shot/valid/macos_sandbox_alias.json"),
    ),
    (
        "seatbelt minimal",
        include_str!("fixtures/one_shot/valid/seatbelt_minimal.json"),
    ),
    (
        "seatbelt complete",
        include_str!("fixtures/one_shot/valid/seatbelt_complete.json"),
    ),
];

const INVALID_FIXTURES: &[(&str, &str)] = &[
    (
        "state-aware request",
        include_str!("fixtures/one_shot/invalid/state_aware.json"),
    ),
    (
        "unknown root field",
        include_str!("fixtures/one_shot/invalid/unknown_root_field.json"),
    ),
    (
        "unknown nested field",
        include_str!("fixtures/one_shot/invalid/unknown_nested_field.json"),
    ),
    (
        "incomplete LXC section",
        include_str!("fixtures/one_shot/invalid/incomplete_lxc.json"),
    ),
    (
        "seatbelt invalid launch method",
        include_str!("fixtures/one_shot/invalid/seatbelt_invalid_launch_method.json"),
    ),
    (
        "seatbelt unknown field",
        include_str!("fixtures/one_shot/invalid/seatbelt_unknown_field.json"),
    ),
    (
        "comma-delimited ProcessContainer capability",
        include_str!("fixtures/one_shot/invalid/capability_with_comma.json"),
    ),
    (
        "reserved learning-mode logging capability",
        include_str!("fixtures/one_shot/invalid/capability_learning_mode_logging_reserved.json"),
    ),
    (
        "reserved permissive learning-mode capability",
        include_str!(
            "fixtures/one_shot/invalid/capability_permissive_learning_mode_reserved.json"
        ),
    ),
    (
        "duplicate ProcessContainer alias",
        include_str!("fixtures/one_shot/invalid/duplicate_process_container_alias.json"),
    ),
    (
        "duplicate Seatbelt alias",
        include_str!("fixtures/one_shot/invalid/duplicate_seatbelt_alias.json"),
    ),
    (
        "out-of-range WSLC port",
        include_str!("fixtures/one_shot/invalid/port_out_of_range.json"),
    ),
];

#[test]
fn accepts_valid_fixtures() {
    for (name, json) in VALID_FIXTURES {
        serde_json::from_str::<OneShotRequest>(json)
            .unwrap_or_else(|error| panic!("valid fixture '{name}' was rejected: {error}"));
    }
}

#[test]
fn rejects_invalid_fixtures() {
    for (name, json) in INVALID_FIXTURES {
        assert!(
            serde_json::from_str::<OneShotRequest>(json).is_err(),
            "invalid fixture '{name}' was accepted"
        );
    }
}

fn assert_root_fixtures<T>(root: &str, valid: &str, invalid: &str)
where
    T: DeserializeOwned,
{
    serde_json::from_str::<T>(valid)
        .unwrap_or_else(|error| panic!("valid {root} fixture was rejected: {error}"));
    assert!(
        serde_json::from_str::<T>(invalid).is_err(),
        "invalid {root} fixture was accepted"
    );
}

#[test]
fn accepts_and_rejects_each_state_aware_root_fixture() {
    assert_root_fixtures::<WindowsSandboxProvisionRequest>(
        "Windows Sandbox provision",
        include_str!("fixtures/windows_sandbox_provision/valid/minimal.json"),
        include_str!("fixtures/windows_sandbox_provision/invalid/foreign_network.json"),
    );
    assert_root_fixtures::<IsolationSessionProvisionRequest>(
        "IsolationSession provision",
        include_str!("fixtures/isolation_session_provision/valid/minimal.json"),
        include_str!("fixtures/isolation_session_provision/invalid/missing_network.json"),
    );
    assert_root_fixtures::<WslcProvisionRequest>(
        "WSLC provision",
        include_str!("fixtures/wslc_provision/valid/minimal.json"),
        include_str!("fixtures/wslc_provision/invalid/foreign_sandbox_id.json"),
    );
    assert_root_fixtures::<StartRequest>(
        "start",
        include_str!("fixtures/start/valid/minimal.json"),
        include_str!("fixtures/start/invalid/foreign_process.json"),
    );
    assert_root_fixtures::<ExecRequest>(
        "exec",
        include_str!("fixtures/exec/valid/minimal.json"),
        include_str!("fixtures/exec/invalid/missing_process.json"),
    );
    assert_root_fixtures::<StopRequest>(
        "stop",
        include_str!("fixtures/stop/valid/minimal.json"),
        include_str!("fixtures/stop/invalid/unknown_field.json"),
    );
    assert_root_fixtures::<DeprovisionRequest>(
        "deprovision",
        include_str!("fixtures/deprovision/valid/minimal.json"),
        include_str!("fixtures/deprovision/invalid/foreign_containment.json"),
    );
}
