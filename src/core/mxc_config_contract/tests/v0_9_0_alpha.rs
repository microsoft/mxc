// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

pub(crate) const CONTRACT_VERSION: &str = "0.9.0-alpha";

#[path = "support/annotations.rs"]
mod annotations;
#[path = "v0_9_0_alpha/common.rs"]
mod common;
#[path = "v0_9_0_alpha/enums.rs"]
mod enums;
#[path = "support/exact.rs"]
mod exact_test_support;
#[path = "v0_9_0_alpha/experimental.rs"]
mod experimental;
#[path = "v0_9_0_alpha/fixtures.rs"]
mod fixtures;
#[path = "v0_9_0_alpha/network.rs"]
mod network;
#[path = "support/one_shot.rs"]
mod one_shot;
#[path = "v0_9_0_alpha/optional_fields.rs"]
mod optional_fields;
#[path = "v0_9_0_alpha/request.rs"]
mod request;
#[path = "v0_9_0_alpha/seatbelt.rs"]
mod seatbelt;
#[path = "v0_9_0_alpha/state_aware.rs"]
mod state_aware;
#[path = "v0_9_0_alpha/wslc.rs"]
mod wslc;
