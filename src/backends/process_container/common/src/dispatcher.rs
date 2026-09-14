// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Native Windows ProcessContainer dispatch.
//!
//! Process containment uses only the native PSEC contract. MXC does not fall
//! back to SBOX, AppContainer filesystem brokering, or host-DACL mutation.

use crate::base_container_runner::BaseContainerRunner;
use wxc_common::logger::Logger;
use wxc_common::models::{ExecutionRequest, ScriptResponse};
use wxc_common::sandbox_process::{Runner, SandboxBackend, SandboxProcess, StdioMode};
use wxc_common::script_runner::ScriptRunner;

/// Failure to construct a native ProcessContainer runner.
#[derive(Debug)]
pub enum DispatchError {
    /// PSEC cannot fully enforce the requested policy.
    BackendUnavailable,
}

impl std::fmt::Display for DispatchError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::BackendUnavailable => write!(
                f,
                "Windows ProcessContainer is unavailable: PSEC cannot fully enforce the requested \
                 policy"
            ),
        }
    }
}

impl std::error::Error for DispatchError {}

fn build_backend(request: &ExecutionRequest) -> Result<BaseContainerRunner, DispatchError> {
    if !BaseContainerRunner::is_usable_for_request(request) {
        return Err(DispatchError::BackendUnavailable);
    }

    Ok(BaseContainerRunner::new())
}

/// Construct the native PSEC run-to-completion runner.
pub fn dispatch(request: &ExecutionRequest) -> Result<Box<dyn ScriptRunner>, DispatchError> {
    Ok(Box::new(Runner::new(build_backend(request)?)))
}

/// Error from native ProcessContainer streaming dispatch.
pub enum SpawnDispatchError {
    /// Native backend selection failed before launch.
    Dispatch(DispatchError),
    /// The selected backend rejected or failed to launch the request.
    Spawn(Box<ScriptResponse>),
}

/// Spawn a native PSEC process with streaming stdio.
pub fn spawn(
    request: &ExecutionRequest,
    logger: &mut Logger,
    stdio: StdioMode,
) -> Result<Box<dyn SandboxProcess>, SpawnDispatchError> {
    let mut backend = build_backend(request).map_err(SpawnDispatchError::Dispatch)?;
    backend
        .spawn(request, logger, stdio)
        .map_err(|response| SpawnDispatchError::Spawn(Box::new(response)))
}
