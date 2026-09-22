// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

pub(crate) const FIXTURE_VERSION: &str = "v0_6_0_alpha";
pub(crate) use mxc_config_contract::published::v0_6_0_alpha::Request as FixtureRequest;

#[path = "v0_6_0_alpha/common.rs"]
mod common;
#[path = "v0_6_0_alpha/enums.rs"]
mod enums;
#[path = "support/fixture_corpus.rs"]
mod fixture_corpus;
#[path = "support/legacy_fixtures.rs"]
mod fixtures;
#[path = "v0_6_0_alpha/network.rs"]
mod network;
#[path = "v0_6_0_alpha/optional_fields.rs"]
mod optional_fields;
#[path = "v0_6_0_alpha/root.rs"]
mod root;
