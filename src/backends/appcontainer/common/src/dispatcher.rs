// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Native Windows ProcessContainer dispatch.
//!
//! Process containment uses only the OS BaseContainer contracts: PSEC when it
//! is usable and policy-compatible, otherwise the transitional SBOX contract.
//! MXC does not fall back to AppContainer filesystem brokering or host-DACL
//! mutation.

use std::sync::Arc;

use crate::base_container_runner::BaseContainerRunner;
use crate::guarded_capture::GuardedCaptureFactory;
use wxc_common::logger::Logger;
use wxc_common::models::{ExecutionRequest, ScriptResponse};
use wxc_common::sandbox_process::{Runner, SandboxBackend, SandboxProcess, StdioMode};
use wxc_common::script_runner::ScriptRunner;

/// Failure to construct a native ProcessContainer runner.
#[derive(Debug)]
pub enum DispatchError {
    /// Neither PSEC nor SBOX can fully enforce the requested policy.
    BackendUnavailable,
    /// Denial capture requires guarded WPR when native PSEC capture is
    /// unavailable, but the caller did not provide a capture factory.
    CaptureDenialsUnsupported,
}

impl std::fmt::Display for DispatchError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::BackendUnavailable => write!(
                f,
                "Windows ProcessContainer is unavailable: neither PSEC nor SBOX can fully enforce \
                 the requested policy"
            ),
            Self::CaptureDenialsUnsupported => write!(
                f,
                "captureDenials requires native PSEC learning-mode support or the guarded-WPR \
                 capture provider"
            ),
        }
    }
}

impl std::error::Error for DispatchError {}

fn build_backend(
    request: &ExecutionRequest,
    capture_factory: Option<Arc<dyn GuardedCaptureFactory>>,
) -> Result<BaseContainerRunner, DispatchError> {
    if !BaseContainerRunner::is_usable_for_request(request) {
        return Err(DispatchError::BackendUnavailable);
    }

    let guarded_capture_required = request.policy.capture_denials.is_some()
        && !BaseContainerRunner::uses_native_capture_for_request(request);
    if guarded_capture_required {
        let factory = capture_factory.ok_or(DispatchError::CaptureDenialsUnsupported)?;
        Ok(BaseContainerRunner::new().with_guarded_capture_factory(factory))
    } else {
        Ok(BaseContainerRunner::new())
    }
}

/// Construct the native PSEC/SBOX run-to-completion runner.
pub fn dispatch(
    request: &ExecutionRequest,
    capture_factory: Option<Arc<dyn GuardedCaptureFactory>>,
) -> Result<Box<dyn ScriptRunner>, DispatchError> {
    Ok(Box::new(Runner::new(build_backend(
        request,
        capture_factory,
    )?)))
}

/// Error from native ProcessContainer streaming dispatch.
pub enum SpawnDispatchError {
    /// Native backend selection failed before launch.
    Dispatch(DispatchError),
    /// The selected backend rejected or failed to launch the request.
    Spawn(Box<ScriptResponse>),
}

/// Spawn a native PSEC/SBOX process with streaming stdio.
pub fn spawn(
    request: &ExecutionRequest,
    logger: &mut Logger,
    stdio: StdioMode,
    capture_factory: Option<Arc<dyn GuardedCaptureFactory>>,
) -> Result<Box<dyn SandboxProcess>, SpawnDispatchError> {
    let mut backend =
        build_backend(request, capture_factory).map_err(SpawnDispatchError::Dispatch)?;
    backend
        .spawn(request, logger, stdio)
        .map_err(|response| SpawnDispatchError::Spawn(Box::new(response)))
}
