// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

pub(crate) mod v0_6;

pub(crate) mod v0_7;

pub(crate) mod v0_8;

// The development mappings are reachable only through private exact paths;
// production entry points use rolling parsing.
#[cfg_attr(not(test), allow(dead_code))]
pub(crate) mod dev;
