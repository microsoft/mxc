// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! MXC implementation shared with the private SDK facade.
//!
//! This implementation root is shared by the private SDK implementation and
//! the non-published `mxc-internal` workspace crate. The published SDK exposes
//! only `v1`; workspace consumers use `mxc_internal` for implementation access.

#[path = "backends/mod.rs"]
pub(crate) mod backend_modules;
#[path = "core/mod.rs"]
pub(crate) mod core_modules;

#[doc(hidden)]
pub use backend_modules::bubblewrap::common as bwrap_common;
#[doc(hidden)]
#[cfg(all(feature = "hyperlight", target_arch = "x86_64"))]
pub use backend_modules::hyperlight::common as hyperlight_common;
#[doc(hidden)]
#[cfg(all(target_os = "windows", feature = "isolation_session"))]
pub use backend_modules::isolation_session::bindings as isolation_session_bindings;
#[doc(hidden)]
#[cfg(all(target_os = "windows", feature = "isolation_session"))]
pub use backend_modules::isolation_session::common as isolation_session_common;
#[doc(hidden)]
pub use backend_modules::lxc::common as lxc_common;
#[doc(hidden)]
#[cfg(all(feature = "microvm", any(target_os = "windows", target_os = "linux")))]
pub use backend_modules::nanvix::binaries as nanvix_binaries;
#[doc(hidden)]
#[cfg(all(feature = "microvm", any(target_os = "windows", target_os = "linux")))]
pub use backend_modules::nanvix::common as nanvix_common;
#[doc(hidden)]
#[cfg(all(feature = "microvm", any(target_os = "windows", target_os = "linux")))]
pub use backend_modules::nanvix::runner as nanvix_runner;
#[doc(hidden)]
#[cfg(target_os = "windows")]
pub use backend_modules::process_container::common as process_container_common;
#[doc(hidden)]
pub use backend_modules::seatbelt::common as seatbelt_common;
#[doc(hidden)]
#[cfg(target_os = "windows")]
pub use backend_modules::windows_sandbox::common as windows_sandbox_common;
#[doc(hidden)]
#[cfg(target_os = "windows")]
pub use backend_modules::windows_sandbox::lifecycle as windows_sandbox_lifecycle;
#[doc(hidden)]
#[cfg(all(target_os = "windows", feature = "wslc"))]
pub use backend_modules::wslc::common as wslc_common;
#[doc(hidden)]
pub use core_modules::learning_mode_core;
#[doc(hidden)]
pub use core_modules::learning_mode_windows;
#[doc(hidden)]
pub use core_modules::mxc_common;
#[doc(hidden)]
pub use core_modules::mxc_contract;
#[doc(hidden)]
pub use core_modules::mxc_engine;
#[doc(hidden)]
pub use core_modules::mxc_pty;
#[doc(hidden)]
pub use core_modules::mxc_schema_support;
#[doc(hidden)]
pub use core_modules::mxc_telemetry;
#[doc(hidden)]
pub use core_modules::plm;
#[doc(hidden)]
pub use core_modules::process_security_environment_spec;

pub(crate) mod configs;
pub(crate) mod options;
pub(crate) mod policy;
pub(crate) mod sandbox;
pub(crate) mod state_aware_sdk;

pub(crate) mod telemetry;

#[cfg(target_os = "windows")]
pub(crate) use crate::mxc_engine::ProbeOutput;
pub(crate) use crate::mxc_engine::{Error, ErrorCode};

pub(crate) use sandbox::{ExecutionResult, MxcProcess};

/// V1 contract-mapped request and typed lifecycle APIs.
///
/// These types and entry points target the latest published V1 contract
/// owned by this SDK. Callers supply typed requests rather than JSON or a
/// schema version.
///
pub mod v1 {
    pub use crate::mxc_engine::{
        available_backends, platform_support, AvailableBackend, BackendCapability,
        BubblewrapNetworkSupport, Error, ErrorCode, PlatformSupport, ProxyEnforcement,
    };
    #[cfg(target_os = "windows")]
    pub use crate::mxc_engine::{ProbeFacts, ProbeOutput, UiCapabilitySupport};
    pub use crate::options::{
        DeprovisionOptions, ProvisionOptions, RunInContainerOptions, RunOptions,
        SpawnInContainerOptions, SpawnInContainerWithPtyOptions, SpawnOptions, SpawnWithPtyOptions,
        StartOptions, StopOptions, TelemetryConfig,
    };

    /// V1 telemetry consent administration.
    pub mod telemetry {
        pub use crate::telemetry::*;
    }

    /// Backend-specific V1 configuration sections.
    pub mod configs {
        pub use crate::configs::{
            CaptureDenials, CaptureDenialsMode, LxcConfig, ProcessContainerConfig,
            ProcessContainerFilesystem, ProcessContainerNetwork, ProcessContainerSystemSettings,
            ProcessContainerUi, ProcessContainerUiIsolation, SeatbeltConfig, WslcConfig,
        };
    }

    /// V1 policy authoring types.
    pub mod policy {
        /// Host filesystem-policy discovery helpers and their options.
        pub mod filesystem {
            pub use crate::policy::{
                available_tools_policy, temporary_files_policy, user_profile_policy,
                FilesystemPolicyResult, ToolsPolicyContainerType, ToolsPolicyOptions,
            };
        }

        pub use crate::policy::{
            ClipboardPolicy, Containment, FilesystemPolicy, NetworkAction, NetworkEgressPolicy,
            NetworkIngressPolicy, NetworkPeerPolicy, NetworkPolicy, NetworkPortPolicy,
            NetworkProtocol, NetworkRulePolicy, NetworkRuntimeConfig, UiPolicy,
        };
    }

    /// V1 typed lifecycle entry points.
    pub mod container {
        use super::{
            ContainerId, Error, ExecutionRequest, ExecutionResult, RunInContainerOptions,
            SpawnInContainerOptions,
        };

        pub use crate::sandbox::{
            deprovision as deprovision_container, provision as provision_container,
            spawn_in_container, spawn_in_container_with_pty, start as start_container,
            stop as stop_container, validate_deprovision, validate_process, validate_provision,
            validate_start, validate_stop,
        };

        /// Run a workload in an existing container to completion and capture output.
        pub fn run_in_container(
            container_id: &ContainerId,
            request: ExecutionRequest,
            options: RunInContainerOptions,
        ) -> Result<ExecutionResult, Error> {
            crate::wait_with_output(spawn_in_container(
                container_id,
                request,
                SpawnInContainerOptions {
                    telemetry: options.telemetry,
                },
            )?)
        }
    }

    pub use crate::policy::{
        ClipboardPolicy, ContainerRequest, Containment, FilesystemPolicy, NetworkAction,
        NetworkEgressPolicy, NetworkIngressPolicy, NetworkPeerPolicy, NetworkPolicy,
        NetworkPortPolicy, NetworkProtocol, NetworkRulePolicy, NetworkRuntimeConfig, UiPolicy,
    };
    pub use crate::sandbox::{
        CaptureDenialsError, CaptureDenialsResult, ExecutionMetadata, ExecutionResult, MxcProcess,
        MxcPtyProcess, MxcPtySize, StreamCloser, WaitResult,
    };
    pub use crate::state_aware_sdk::{
        ContainerId, ExecutionRequest, IsolationSessionProvisionMetadata, LifecycleResult,
        ProcessNetworkPolicy, ProvisionMetadata, ProvisionRequest, ProvisionResult,
        ValidationResult,
    };

    /// Probe an optional ProcessContainer request without creating a container.
    ///
    /// Other containments use backend availability discovery and their normal
    /// launch-time validation because this result describes ProcessContainer tiers.
    #[cfg(target_os = "windows")]
    pub fn probe(request: Option<&ContainerRequest>) -> Result<crate::ProbeOutput, Error> {
        let prepared = request.map(crate::policy::prepare_request).transpose()?;
        crate::mxc_engine::probe_execution_request(prepared.as_ref().map(|request| &request.inner))
    }

    /// Spawn a [`ContainerRequest`] and return its live process.
    ///
    /// Returns a [`MxcProcess`] handle for live bidirectional stdio and termination;
    /// no pty is allocated. Any stdout/stderr stream the caller does not
    /// `take_*` is drained and discarded by [`wait`](MxcProcess::wait).
    pub fn spawn(request: ContainerRequest, options: SpawnOptions) -> Result<MxcProcess, Error> {
        let prepared = crate::policy::prepare_creation_request(&request, options.telemetry)?;
        crate::mxc_engine::spawn_execution_request(&prepared.inner).map(MxcProcess::new)
    }

    /// Spawn a [`ContainerRequest`] attached to a caller-controlled PTY.
    pub fn spawn_with_pty(
        request: ContainerRequest,
        options: SpawnWithPtyOptions,
    ) -> Result<MxcPtyProcess, Error> {
        options.size.validate()?;
        let prepared = crate::policy::prepare_creation_request(&request, options.telemetry)?;
        crate::mxc_engine::spawn_with_pty(&prepared.inner, options.size.into())
            .and_then(MxcPtyProcess::new)
    }

    /// Run a [`ContainerRequest`] to completion and capture its output.
    ///
    /// Both streams are drained concurrently, so an output-heavy child cannot
    /// deadlock. No pty is allocated.
    ///
    /// Use [`spawn`] instead when you need to stream stdio, feed stdin, or kill
    /// the process while it runs.
    ///
    /// `Err` is returned when the backend can't be selected/spawned (an
    /// [`Error`]), or when waiting on the child fails at the OS level.
    pub fn run(request: ContainerRequest, options: RunOptions) -> Result<ExecutionResult, Error> {
        crate::wait_with_output(spawn(
            request,
            SpawnOptions {
                telemetry: options.telemetry,
            },
        )?)
    }

    #[cfg(all(test, target_os = "windows"))]
    mod tests {
        use super::*;

        #[test]
        fn public_request_probe_uses_sdk_request_model() {
            let request = ContainerRequest::new("cmd /c exit 0");
            let output = probe(Some(&request)).expect("default request probes");
            assert!(output.error.is_some() || output.tier.is_some());
        }
    }
}

/// Internal adapters for the C ABI and native contract tests, not SDK authoring APIs.
#[doc(hidden)]
pub mod __ffi {
    use super::*;
    use crate::sandbox::WaitResult;

    /// Spawn a raw exact-version JSON container request as a live process.
    ///
    /// The JSON must declare an exact registered `version` and contain a
    /// container request. Lifecycle requests are rejected; use lifecycle APIs.
    /// `experimental` permits selecting an experimental backend (MicroVM,
    /// Hyperlight, or Windows Sandbox), which is otherwise refused with
    /// [`ErrorCode::BackendUnavailable`]. It is ignored for production backends and
    /// is never read from the JSON.
    pub fn spawn_container_json(
        request_json: &str,
        experimental: bool,
    ) -> Result<MxcProcess, Error> {
        crate::mxc_engine::spawn_one_shot_json(request_json, experimental).map(MxcProcess::new)
    }

    /// Spawn an exact-version JSON request attached to a caller-controlled PTY.
    #[doc(hidden)]
    pub fn spawn_with_pty_json(
        request_json: &str,
        experimental: bool,
        size: v1::MxcPtySize,
    ) -> Result<v1::MxcPtyProcess, Error> {
        size.validate()?;
        crate::mxc_engine::spawn_one_shot_pty_json(request_json, experimental, size.into())
            .and_then(v1::MxcPtyProcess::new)
    }

    /// Run a raw exact-version JSON container request to completion and capture
    /// its output. The JSON and `experimental` rules match [`spawn_container_json`].
    pub fn run_json(request_json: &str, experimental: bool) -> Result<ExecutionResult, Error> {
        wait_with_output(spawn_container_json(request_json, experimental)?)
    }

    /// Run a lifecycle request (as a JSON string) and return the
    /// response-envelope JSON string.
    ///
    /// Handles the envelope phases (`provision`, `start`, `stop`, `deprovision`)
    /// and a dry run of any phase. A non-dry-run execution produces no envelope, so
    /// it is rejected here; use an execution entry point instead:
    /// [`execute_lifecycle_json`] to drive the pipes yourself.
    ///
    /// The request JSON is the same wire format the executor accepts (an object with
    /// a `phase` field). Errors (malformed request, unsupported phase, backend
    /// failures) come back as an [`Error`] with the matching [`ErrorCode`].
    ///
    /// `experimental` is the in-process equivalent of the executor's
    /// `--experimental` flag. It permits selecting an experimental backend, which
    /// is otherwise refused with [`ErrorCode::BackendUnavailable`] before any work
    /// is done, and is ignored for production backends.
    /// It is an API parameter rather than a field in the request JSON so that a
    /// config cannot grant itself experimental access.
    pub fn run_lifecycle_json(
        request_json: &str,
        dry_run: bool,
        experimental: bool,
    ) -> Result<String, Error> {
        crate::mxc_engine::run_state_aware_json(request_json, dry_run, experimental)
    }

    /// Execute a lifecycle request (as a JSON string) as a **live streaming**
    /// process, returning a [`MxcProcess`] handle for output streaming, waiting,
    /// and termination, exactly like [`v1::spawn`]. Backends that expose process
    /// input also make [`MxcProcess::take_stdin`] available.
    ///
    /// The request JSON must specify the `exec` lifecycle phase (with a
    /// `sandboxId` identifying a started container). No pty is allocated.
    ///
    /// IsolationSession and WSLC serve this with the crate's corresponding
    /// `isolation_session` or `wslc` feature. WSLC returns separate stdout/stderr
    /// pipes but no stdin. Windows Sandbox cannot hand back pipes and refuses.
    /// `experimental` opts in to experimental backends, as for
    /// [`run_lifecycle_json`].
    ///
    /// [`MxcProcess::kill`] reaches only the foreground process here; a descendant the
    /// workload backgrounded is reclaimed when the container is stopped and
    /// deprovisioned.
    pub fn execute_lifecycle_json(
        request_json: &str,
        experimental: bool,
    ) -> Result<MxcProcess, Error> {
        crate::mxc_engine::exec_state_aware_json(request_json, experimental).map(MxcProcess::new)
    }

    /// Spawn a lifecycle execution request with a caller-controlled PTY.
    #[doc(hidden)]
    pub fn spawn_in_container_with_pty_json(
        request_json: &str,
        size: v1::MxcPtySize,
        experimental: bool,
    ) -> Result<v1::MxcPtyProcess, Error> {
        size.validate()?;
        crate::mxc_engine::exec_state_aware_pty_json(request_json, experimental, size.into())
            .and_then(v1::MxcPtyProcess::new)
    }

    /// Execute a lifecycle request attached to this process's stdio.
    #[expect(
        dead_code,
        reason = "Attached exec is reserved but not exposed by the SDK yet"
    )]
    fn exec_attached(request_json: &str, experimental: bool) -> Result<WaitResult, Error> {
        exec_attached_json(request_json, experimental)
    }

    /// Run an exact-JSON lifecycle execution request attached to this process's stdio.
    fn exec_attached_json(request_json: &str, experimental: bool) -> Result<WaitResult, Error> {
        use crate::mxc_common::state_aware_backend::ExecOutcome;
        crate::mxc_engine::exec_state_aware_attached(request_json, experimental).map(|outcome| {
            match outcome {
                ExecOutcome::Exited(code) => WaitResult::Exited(code),
                ExecOutcome::TimedOut => WaitResult::TimedOut,
            }
        })
    }
}

pub(crate) fn wait_with_output(sandbox: MxcProcess) -> Result<ExecutionResult, Error> {
    sandbox.wait_with_output().map_err(|e| {
        Error::new(
            ErrorCode::BackendError,
            format!("waiting for the sandbox to complete failed: {e}"),
        )
    })
}
