// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Operations for provisioned sandboxes.

use crate::sandbox::{Sandbox, WaitOutcome};
use crate::Error;
use wxc_common::state_aware_backend::ExecOutcome;

/// Provision a sandbox from operation-neutral request JSON.
pub fn provision(request_json: &str, experimental: bool) -> Result<String, Error> {
    mxc_engine::run_state_aware_operation_json(
        request_json,
        mxc_engine::LifecycleOperation::Provision,
        None,
        false,
        experimental,
    )
}

/// Start an existing sandbox.
pub fn start(sandbox_id: &str, request_json: &str, experimental: bool) -> Result<String, Error> {
    mxc_engine::run_state_aware_operation_json(
        request_json,
        mxc_engine::LifecycleOperation::Start,
        Some(sandbox_id),
        false,
        experimental,
    )
}

/// Execute in an existing sandbox and return a live streaming handle.
pub fn exec(sandbox_id: &str, request_json: &str, experimental: bool) -> Result<Sandbox, Error> {
    mxc_engine::exec_state_aware_operation_json(request_json, sandbox_id, experimental)
        .map(Sandbox::new)
}

/// Run an operation in an existing sandbox attached to this process's stdio.
///
/// The call blocks until the sandboxed process exits. This process's stdout
/// and stdin must both be terminals, or the operation is refused with
/// [`ErrorCode::MalformedRequest`](crate::ErrorCode::MalformedRequest) and
/// nothing is run.
pub fn exec_attached(
    sandbox_id: &str,
    request_json: &str,
    experimental: bool,
) -> Result<WaitOutcome, Error> {
    mxc_engine::exec_state_aware_attached(request_json, sandbox_id, experimental).map(|outcome| {
        match outcome {
            ExecOutcome::Exited(code) => WaitOutcome::Exited(code),
            ExecOutcome::TimedOut => WaitOutcome::TimedOut,
        }
    })
}

/// Stop an existing sandbox.
pub fn stop(sandbox_id: &str, request_json: &str, experimental: bool) -> Result<String, Error> {
    mxc_engine::run_state_aware_operation_json(
        request_json,
        mxc_engine::LifecycleOperation::Stop,
        Some(sandbox_id),
        false,
        experimental,
    )
}

/// Deprovision an existing sandbox.
pub fn deprovision(
    sandbox_id: &str,
    request_json: &str,
    experimental: bool,
) -> Result<String, Error> {
    mxc_engine::run_state_aware_operation_json(
        request_json,
        mxc_engine::LifecycleOperation::Deprovision,
        Some(sandbox_id),
        false,
        experimental,
    )
}
