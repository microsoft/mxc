// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Revised creation options within the V1 request-contract line.
//!
//! This API revision adds invocation-only policy mutation without changing the
//! published [`crate::v1`] option structs or the SDK-owned request contract.
//! Requests, results and process ownership retain their V1 meanings.

pub use crate::v1::{ContainerRequest, Error, ExecutionResult, MxcProcess, TelemetryConfig};

/// Invocation controls for captured container execution.
///
/// Construct with [`Default`] and set the desired fields:
///
/// ```
/// use mxc_sdk::v1_1::RunOptions;
///
/// let mut options = RunOptions::default();
/// options.mutate_policy = true;
/// ```
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct RunOptions {
    /// Per-invocation telemetry opt-in, subject to consent and policy.
    pub telemetry: Option<TelemetryConfig>,
    /// Authorize restrictive creation-policy corrections; defaults to `false`.
    ///
    /// Supported only by native Windows ProcessContainer creation. Changes are
    /// described in [`ExecutionResult::warnings`].
    pub mutate_policy: bool,
}

/// Invocation controls for spawning a live process.
///
/// Construct with [`Default`] and set the desired fields. These options are
/// separate from [`crate::v1::SpawnOptions`] to preserve published callers.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct SpawnOptions {
    /// Per-invocation telemetry opt-in, subject to consent and policy.
    pub telemetry: Option<TelemetryConfig>,
    /// Authorize restrictive creation-policy corrections; defaults to `false`.
    ///
    /// Supported only by native Windows ProcessContainer creation. Changes are
    /// described in [`MxcProcess::warnings`].
    pub mutate_policy: bool,
}

fn prepare_creation_request(
    request: &ContainerRequest,
    telemetry: Option<TelemetryConfig>,
    mutate_policy: bool,
) -> Result<crate::policy::PreparedContainerRequest, Error> {
    let mut prepared = crate::policy::prepare_creation_request(request, telemetry)?;
    prepared.inner.policy_mutation_enabled = mutate_policy;
    Ok(prepared)
}

/// Create a container and return its live process with standard pipes.
///
/// With [`SpawnOptions::mutate_policy`] enabled, MXC may apply restrictive
/// corrections to a private request copy before launch. It never switches
/// backends or isolation tiers to evade a refusal, or replays a workload.
/// Mutation descriptions are available through [`MxcProcess::warnings`].
///
/// # Errors
///
/// Returns an error if request validation, backend selection or creation fails.
/// Opted-in mutation also rejects unsupported backends and unsafe repairs.
pub fn spawn(request: ContainerRequest, options: SpawnOptions) -> Result<MxcProcess, Error> {
    let prepared = prepare_creation_request(&request, options.telemetry, options.mutate_policy)?;
    crate::mxc_engine::spawn_execution_request(&prepared.inner).map(MxcProcess::new)
}

/// Run a container to completion and capture its output.
///
/// Uses [`spawn`] with the same invocation controls. Creation is strict unless
/// [`RunOptions::mutate_policy`] is enabled; mutation descriptions use
/// [`ExecutionResult::warnings`], not workload stdout or stderr.
///
/// # Errors
///
/// Returns creation errors described by [`spawn`], or an error if waiting for
/// the workload fails at the operating-system level.
pub fn run(request: ContainerRequest, options: RunOptions) -> Result<ExecutionResult, Error> {
    crate::wait_with_output(spawn(
        request,
        SpawnOptions {
            telemetry: options.telemetry,
            mutate_policy: options.mutate_policy,
        },
    )?)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mutation_is_disabled_by_default() {
        assert!(!RunOptions::default().mutate_policy);
        assert!(!SpawnOptions::default().mutate_policy);
    }

    #[test]
    fn creation_options_set_only_invocation_authorization() {
        let request = ContainerRequest::new("echo unchanged");
        for mutate_policy in [false, true] {
            let prepared = prepare_creation_request(
                &request,
                Some(TelemetryConfig {
                    enabled: Some(false),
                }),
                mutate_policy,
            )
            .expect("typed request prepares without execution");
            assert_eq!(prepared.inner.policy_mutation_enabled, mutate_policy);
            assert!(!prepared.inner.experimental_enabled);
            assert_eq!(
                prepared
                    .inner
                    .telemetry
                    .as_ref()
                    .and_then(|value| value.enabled),
                Some(false)
            );
        }
        assert_eq!(request.command, "echo unchanged");
    }

    #[test]
    fn revised_creation_apis_preserve_result_and_ownership_types() {
        let _: fn(ContainerRequest, SpawnOptions) -> Result<MxcProcess, Error> = spawn;
        let _: fn(ContainerRequest, RunOptions) -> Result<ExecutionResult, Error> = run;
    }

    #[test]
    fn mutation_rejects_other_backends_before_launch() {
        let mut request = ContainerRequest::new("echo must not execute");
        request.containment = crate::v1::Containment::Bubblewrap;
        let error = run(
            request,
            RunOptions {
                mutate_policy: true,
                ..Default::default()
            },
        )
        .expect_err("mutation cannot execute through another backend");
        assert_eq!(error.code, crate::v1::ErrorCode::UnsupportedContainment);
        assert!(error
            .message
            .contains("creation-policy mutation requires native Windows ProcessContainer"));
    }
}
