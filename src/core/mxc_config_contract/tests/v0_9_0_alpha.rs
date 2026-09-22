// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

pub(crate) const CONTRACT_VERSION: &str = "0.9.0-alpha";
pub(crate) use mxc_config_contract::published::v0_9_0_alpha::{
    DeprovisionRequest, ExecRequest, IsolationSessionProvisionRequest, OneShotRequest,
    StartRequest, StopRequest,
};
pub(crate) const OPTIONAL_EMPTY_OBJECT_ADDITIONS: &[&str] =
    &[r#""processContainer": {"filesystem": {}}"#];
pub(crate) const OPTIONAL_NULL_FIELD_ADDITIONS: &[(&str, &str)] = &[
    (
        "processContainer.filesystem",
        r#""processContainer": {"filesystem": null}"#,
    ),
    (
        "processContainer.filesystem.enumeratePaths",
        r#""processContainer": {"filesystem": {"enumeratePaths": null}}"#,
    ),
];

#[path = "support/annotations.rs"]
mod annotations;
#[path = "support/common.rs"]
mod common;
#[path = "v0_9_0_alpha/enums.rs"]
mod enums;
#[path = "support/exact.rs"]
mod exact_test_support;
#[path = "v0_9_0_alpha/experimental.rs"]
mod experimental;
#[path = "support/fixture_corpus.rs"]
mod fixture_corpus;
#[path = "v0_9_0_alpha/fixtures.rs"]
mod fixtures;
#[path = "v0_9_0_alpha/network.rs"]
mod network;
#[path = "support/one_shot.rs"]
mod one_shot;
#[path = "support/optional_fields.rs"]
mod optional_fields;
#[path = "v0_9_0_alpha/request.rs"]
mod request;
#[path = "v0_9_0_alpha/seatbelt.rs"]
mod seatbelt;
#[path = "support/state_aware.rs"]
mod state_aware;
#[path = "v0_9_0_alpha/state_aware/provision/mod.rs"]
mod state_aware_provision;
#[path = "v0_9_0_alpha/wslc.rs"]
mod wslc;
