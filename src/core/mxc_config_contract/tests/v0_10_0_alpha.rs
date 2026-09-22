// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

pub(crate) const CONTRACT_VERSION: &str = "0.10.0-alpha";
pub(crate) use mxc_config_contract::dev::{
    DeprovisionRequest, ExecRequest, IsolationSessionProvisionRequest, OneShotRequest,
    StartRequest, StopRequest,
};
pub(crate) const OPTIONAL_EMPTY_OBJECT_ADDITIONS: &[&str] =
    &[r#""test": {}"#, r#""windowsSandbox": {}"#, r#""wslc": {}"#];
pub(crate) const OPTIONAL_NULL_FIELD_ADDITIONS: &[(&str, &str)] = &[
    ("test", r#""test": null"#),
    ("test.message", r#""test": {"message": null}"#),
    ("windowsSandbox", r#""windowsSandbox": null"#),
    (
        "windowsSandbox.idleTimeoutMs",
        r#""windowsSandbox": {"idleTimeoutMs": null}"#,
    ),
    (
        "windowsSandbox.idleTimeout",
        r#""windowsSandbox": {"idleTimeout": null}"#,
    ),
    (
        "windowsSandbox.daemonPipeName",
        r#""windowsSandbox": {"daemonPipeName": null}"#,
    ),
    ("wslc", r#""wslc": null"#),
    ("wslc.targetOs", r#""wslc": {"targetOs": null}"#),
    ("wslc.image", r#""wslc": {"image": null}"#),
    ("wslc.imageTarPath", r#""wslc": {"imageTarPath": null}"#),
    ("wslc.cpuCount", r#""wslc": {"cpuCount": null}"#),
    ("wslc.memoryMb", r#""wslc": {"memoryMb": null}"#),
    ("wslc.gpu", r#""wslc": {"gpu": null}"#),
    ("wslc.storagePath", r#""wslc": {"storagePath": null}"#),
    ("wslc.portMappings", r#""wslc": {"portMappings": null}"#),
    (
        "wslc.portMappings[].protocol",
        r#""wslc": {"portMappings": [{"windowsPort": 8080, "containerPort": 80, "protocol": null}]}"#,
    ),
];

#[path = "support/annotations.rs"]
mod annotations;
#[path = "support/common.rs"]
mod common;
#[path = "v0_10_0_alpha/enums.rs"]
mod enums;
#[path = "support/exact.rs"]
mod exact_test_support;
#[path = "v0_10_0_alpha/experimental.rs"]
mod experimental;
#[path = "support/fixture_corpus.rs"]
mod fixture_corpus;
#[path = "v0_10_0_alpha/fixtures.rs"]
mod fixtures;
#[path = "v0_10_0_alpha/network.rs"]
mod network;
#[path = "support/one_shot.rs"]
mod one_shot;
#[path = "support/optional_fields.rs"]
mod optional_fields;
#[path = "v0_10_0_alpha/request.rs"]
mod request;
#[path = "v0_10_0_alpha/seatbelt.rs"]
mod seatbelt;
#[path = "support/state_aware.rs"]
mod state_aware;
#[path = "v0_10_0_alpha/state_aware/provision/mod.rs"]
mod state_aware_provision;
