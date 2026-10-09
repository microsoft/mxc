// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Caller-authored exact-JSON APIs.

mod one_shot;
mod state_aware;

pub use one_shot::{run_json, spawn_json, spawn_with_pty_json};
pub use state_aware::{
    deprovision_container_json, provision_container_json, run_in_container_json,
    spawn_in_container_json, spawn_in_container_with_pty_json, start_container_json,
    stop_container_json, validate_deprovision_json, validate_process_json, validate_provision_json,
    validate_start_json, validate_stop_json,
};

use crate::sandbox::MxcPtySize;

/// Invocation controls for an exact-JSON operation.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct JsonOptions {
    /// Authorize experimental backends separately from the JSON contract version.
    pub experimental: bool,
}

/// Invocation controls for an exact-JSON terminal operation.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct PtyJsonOptions {
    /// Authorize experimental backends separately from the JSON contract version.
    pub experimental: bool,
    /// Initial terminal dimensions.
    pub size: MxcPtySize,
}
