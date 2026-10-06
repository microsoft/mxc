// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#[path = "state_aware/common.rs"]
pub(crate) mod common;
#[path = "state_aware/deprovision.rs"]
mod deprovision;
#[path = "state_aware/exec.rs"]
mod exec;
#[path = "state_aware/start.rs"]
mod start;
#[path = "state_aware/stop.rs"]
mod stop;
