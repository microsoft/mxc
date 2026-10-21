// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Native Windows ProcessContainer dispatch.
//!
//! Requests run on native PSEC. A request that PSEC cannot fully enforce is
//! rejected before a runner is constructed.

use crate::mxc_common::logger::Logger;
use crate::mxc_common::models::{ExecutionRequest, ScriptResponse};
use crate::mxc_common::sandbox_process::{Runner, SandboxBackend, SandboxProcess, StdioMode};
use crate::mxc_common::script_runner::ScriptRunner;
use crate::process_container_common::base_container_runner::BaseContainerRunner;

/// Failure to construct a native ProcessContainer runner.
#[derive(Debug)]
pub enum DispatchError {
    /// PSEC cannot fully enforce the requested policy.
    BackendUnavailable(&'static str),
}

impl std::fmt::Display for DispatchError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::BackendUnavailable(reason) => f.write_str(reason),
        }
    }
}

impl std::error::Error for DispatchError {}

fn build_backend(request: &ExecutionRequest) -> Result<BaseContainerRunner, DispatchError> {
    if let Some(reason) =
        BaseContainerRunner::can_backend_service_request(request).rejection_message()
    {
        return Err(DispatchError::BackendUnavailable(reason));
    }

    Ok(BaseContainerRunner::new_for_selected_request())
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::process_container_common::base_container_runner::BaseContainerRequestDecision;
    use crate::process_container_common::probe::run_probe;
    use crate::process_container_common::test_env::{
        CaptureCapabilityGuard, PolicyCapabilityGuard,
    };

    #[test]
    fn lpac_is_rejected_before_constructing_a_backend() {
        let _guard = CaptureCapabilityGuard::set(true, true);
        let mut request = ExecutionRequest::default();
        request.policy.least_privilege_mode = true;
        assert!(matches!(
            build_backend(&request),
            Err(DispatchError::BackendUnavailable(
                "Windows ProcessContainer cannot enforce the requested LPAC or legacy network.proxy policy"
            ))
        ));
    }

    #[test]
    fn unsupported_host_capabilities_are_rejected_by_selection_dispatch_and_probe() {
        use BaseContainerRequestDecision::{
            DeniedPathsUnsupported, EnumeratePathsUnsupported, NativeCaptureUnavailable,
        };

        for (decision, message) in [
            (
                DeniedPathsUnsupported,
                "Windows ProcessContainer requires native PSEC denied-path support for this request",
            ),
            (
                EnumeratePathsUnsupported,
                "Windows ProcessContainer requires native PSEC enumeration-only access support for this request",
            ),
            (
                NativeCaptureUnavailable,
                "Windows ProcessContainer requires native Learning Mode capture support for this request",
            ),
        ] {
            let _guard = PolicyCapabilityGuard::set(
                decision != DeniedPathsUnsupported,
                decision != EnumeratePathsUnsupported,
                decision != NativeCaptureUnavailable,
            );
            let mut request = ExecutionRequest::default();
            match decision {
                DeniedPathsUnsupported => request.policy.denied_paths.push(r"C:\denied".into()),
                EnumeratePathsUnsupported => request.policy.enumerate_paths.push(r"C:\enumerate".into()),
                NativeCaptureUnavailable => request.policy.capture_denials = Some(Default::default()),
                _ => unreachable!("only unsupported capability decisions are exercised"),
            }
            assert_eq!(
                BaseContainerRunner::can_backend_service_request(&request),
                decision
            );
            let error = match build_backend(&request) {
                Err(error) => error,
                Ok(_) => panic!("unsupported policy constructed a backend"),
            };
            assert_eq!(error.to_string(), message);
            let probe = run_probe(&request);
            assert_eq!(probe.tier, None);
            assert_eq!(probe.needs_dacl_augmentation, None);
            assert_eq!(probe.error.as_deref(), Some(message));
        }
    }
}
