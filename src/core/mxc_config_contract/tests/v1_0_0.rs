// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

pub(crate) const CONTRACT_VERSION: &str = "1.0.0";
pub(crate) const COMPATIBILITY_ALIASES: bool = false;
pub(crate) use mxc_config_contract::published::v1_0_0::{
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
#[path = "v1_0_0/enums.rs"]
mod enums;
#[path = "support/exact.rs"]
mod exact_test_support;
#[path = "v1_0_0/experimental.rs"]
mod experimental;
#[path = "support/fixture_corpus.rs"]
mod fixture_corpus;
#[path = "v1_0_0/fixtures.rs"]
mod fixtures;
#[path = "v1_0_0/network.rs"]
mod network;
#[path = "support/one_shot.rs"]
mod one_shot;
#[path = "v1_0_0/one_shot_backend_sections.rs"]
mod one_shot_backend_sections;
#[path = "support/optional_fields.rs"]
mod optional_fields;
#[path = "v1_0_0/request.rs"]
mod request;
#[path = "v1_0_0/seatbelt.rs"]
mod seatbelt;
#[path = "support/state_aware.rs"]
mod state_aware;
#[path = "v1_0_0/state_aware/provision/mod.rs"]
mod state_aware_provision;
#[path = "v1_0_0/wslc.rs"]
mod wslc;
