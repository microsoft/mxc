// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Shared ProcessContainer network-policy helpers.

use wxc_common::models::{ContainerPolicy, NetworkAction, NetworkPolicy};

pub(crate) fn allows_network_egress(policy: &ContainerPolicy) -> bool {
    policy.network_egress.as_ref().map_or(
        policy.default_network_policy == NetworkPolicy::Allow,
        |egress| egress.default == NetworkAction::Allow || !egress.allow.is_empty(),
    )
}

pub(crate) fn denies_network_egress_by_default(policy: &ContainerPolicy) -> bool {
    policy.network_egress.as_ref().map_or(
        policy.default_network_policy == NetworkPolicy::Block,
        |egress| egress.default == NetworkAction::Deny,
    )
}
