// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#[path = "state_aware/common.rs"]
mod common;
#[path = "../support/state_aware/deprovision.rs"]
mod deprovision;
#[path = "../support/state_aware/exec.rs"]
mod exec;
#[path = "state_aware/provision/mod.rs"]
mod provision;
#[path = "../support/state_aware/start.rs"]
mod start;
#[path = "../support/state_aware/stop.rs"]
mod stop;
