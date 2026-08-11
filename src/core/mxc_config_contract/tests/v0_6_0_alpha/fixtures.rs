// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use mxc_config_contract::published::v0_6_0_alpha::Request;

const VALID_FIXTURES: &[(&str, &str)] = &[
    ("minimal", include_str!("fixtures/valid/minimal.json")),
    ("complete", include_str!("fixtures/valid/complete.json")),
    (
        "empty optional objects",
        include_str!("fixtures/valid/empty_optional_objects.json"),
    ),
    (
        "appContainer alias",
        include_str!("fixtures/valid/app_container_alias.json"),
    ),
    (
        "localhost proxy",
        include_str!("fixtures/valid/proxy_localhost.json"),
    ),
    (
        "built-in proxy",
        include_str!("fixtures/valid/proxy_builtin.json"),
    ),
    ("URL proxy", include_str!("fixtures/valid/proxy_url.json")),
];

const INVALID_FIXTURES: &[(&str, &str)] = &[
    (
        "experimental field",
        include_str!("fixtures/invalid/experimental.json"),
    ),
    (
        "state-aware request",
        include_str!("fixtures/invalid/state_aware.json"),
    ),
    (
        "unknown root field",
        include_str!("fixtures/invalid/unknown_root_field.json"),
    ),
    (
        "unknown nested field",
        include_str!("fixtures/invalid/unknown_nested_field.json"),
    ),
    (
        "incomplete LXC section",
        include_str!("fixtures/invalid/incomplete_lxc.json"),
    ),
];

#[test]
fn accepts_valid_fixtures() {
    for (name, json) in VALID_FIXTURES {
        serde_json::from_str::<Request>(json)
            .unwrap_or_else(|error| panic!("valid fixture '{name}' was rejected: {error}"));
    }
}

#[test]
fn rejects_invalid_fixtures() {
    for (name, json) in INVALID_FIXTURES {
        assert!(
            serde_json::from_str::<Request>(json).is_err(),
            "invalid fixture '{name}' was accepted"
        );
    }
}
