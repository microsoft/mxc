// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

// Phase 3 introduces and tests the adapter before Phase 8 wires it into
// shadow exact-contract dispatch.
#[cfg_attr(not(test), allow(dead_code))]
pub(crate) mod v0_6;

// Phase 4 introduces and tests the adapter before Phase 8 wires it into
// shadow exact-contract dispatch.
#[cfg_attr(not(test), allow(dead_code))]
pub(crate) mod v0_7;

// Phase 5 introduces and tests the adapter before Phase 8 wires it into
// shadow exact-contract dispatch.
#[cfg_attr(not(test), allow(dead_code))]
pub(crate) mod dev;
