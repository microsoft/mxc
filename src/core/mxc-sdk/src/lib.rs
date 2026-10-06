// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! `mxc-sdk` â€” an importable library for running MXC containers in-process.
//!
//! Create a [`v1::ContainerRequest`] with its command and restrictions, then either:
//!
//! - hand it to [`v1::run`] to run the contained process **to completion** and get
//!   its captured stdout/stderr and exit outcome in one call, or
//! - hand it to [`v1::spawn`] for a live [`v1::MxcProcess`] handle you can
//!   stream stdio through, feed stdin, and kill while it runs.
//! - hand it to [`v1::spawn_with_pty`] for an [`v1::MxcPtyProcess`] with
//!   merged terminal output and resize support.
//!
//! Either way the right containment backend is selected for the host and the
//! ordinary `run` and `spawn` paths allocate no PTY.
//!
//! ```no_run
//! use mxc_sdk::v1::{self, WaitResult};
//!
//! let request = v1::ContainerRequest::new("echo hi");
//! let output = v1::run(request, Default::default())?;
//! match output.outcome {
//!     WaitResult::Exited(code) => println!("exit={code}"),
//!     WaitResult::TimedOut => println!("timed out"),
//! }
//! println!("stdout: {}", String::from_utf8_lossy(&output.stdout));
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```
//!
//! ## Backend support
//!
//! The selected backend is driven by the request's [`v1::Containment`].
//! Requests default to the host's native process backend.
//!
//! | Backend | Host | Selected by |
//! |---------|------|-------------|
//! | Bubblewrap | Linux | [`v1::Containment::Process`] or [`v1::Containment::Bubblewrap`] |
//! | LXC | Linux | [`v1::Containment::Lxc`] |
//! | Seatbelt | macOS | [`v1::Containment::Process`] or [`v1::Containment::Seatbelt`] |
//! | ProcessContainer (AppContainer / BaseContainer) | Windows | [`v1::Containment::Process`] |
//! | Explicit ProcessContainer configuration | Windows | [`v1::Containment::ProcessContainer`] |
//! | WSLC (WSL Container) | Windows | [`v1::Containment::Wslc`] |
//! | IsolationSession | Windows | [`v1::Containment::IsolationSession`] |
//!
//! LXC is reachable only by naming it: [`v1::Containment::Process`] resolves to
//! Bubblewrap on Linux. It needs root. Ordinary streaming uses pipes, while
//! [`v1::spawn_with_pty`] allocates a caller-controlled terminal.
//!
//! WSLC requires the crate's `wslc` build feature, and IsolationSession
//! requires the `isolation_session` build feature. WSLC's container has no
//! stdin (the WSLC SDK exposes no process-input API), so
//! [`MxcProcess::take_stdin`] returns `None` for it.
//! IsolationSession is also available through the typed lifecycle API.
//!
//! The `wslc` feature stages `wslcsdk.dll` into the cargo profile directory,
//! and WSLC loads it from beside the module holding this code, so an executable
//! copied or installed out of that directory needs the DLL brought along. The
//! crate README covers that and the separate `wxc-wslc-daemon.exe` that the
//! container lifecycle needs.
//!
//! A concrete backend selected on another host returns an [`Error`] with
//! [`ErrorCode::UnsupportedContainment`].
//!
//! # Diagnosing a failure
//!
//! [`Error`] carries a closed [`ErrorCode`] and a message, and â€” when the
//! failure came from an underlying platform API â€” the call that failed and its
//! status:
//!
//! ```no_run
//! # fn demo(error: mxc_sdk::v1::Error) {
//! if let Some(operation) = &error.operation {
//!     eprintln!("{operation} failed with {:?}", error.native_code);
//! }
//! if let Some(hint) = &error.remediation {
//!     eprintln!("  try: {hint}");
//! }
//! # }
//! ```
//!
//! [`Error::operation`] and [`Error::native_code`] are absent for a failure
//! raised before any API call was reached â€” a malformed policy, say â€” and a
//! native code only ever appears alongside the operation it belongs to.
//! `Display` renders both, so logging the error alone does not lose them.
//!
//! ```no_run
//! use mxc_sdk::v1;
//!
//! // Run a command inside a WSL container (Windows, --features wslc).
//! let wslc = v1::configs::WslcConfig { image: "python:3.12".to_string(), ..Default::default() };
//! let request = v1::ContainerRequest {
//!     containment: v1::Containment::Wslc(wslc),
//!     ..v1::ContainerRequest::new("python3 -c 'print(42)'")
//! };
//! let output = v1::run(request, Default::default())?;
//! # Ok::<(), mxc_sdk::v1::Error>(())
//! ```
//!
//! ## Choosing an entry point
//!
//! |             | container request | existing container | Stdio |
//! |-------------|-------------------|--------------------|-------|
//! | **capture** | [`v1::run`] | [`v1::container::run_in_container`] | captured stdout and stderr |
//! | **handle**  | [`v1::spawn`] | [`v1::container::spawn_in_container`] | separate live pipes |
//! | **PTY**     | [`v1::spawn_with_pty`] | [`v1::container::spawn_in_container_with_pty`] | merged output, resize |
//!
//! [`v1::container::provision_container`], [`v1::container::start_container`],
//! [`v1::container::stop_container`], and
//! [`v1::container::deprovision_container`] drive the lifecycle with typed Rust
//! requests. All SDK execution APIs take typed requests.
//!
//! ## Standard streams
//!
//! The V1 `run` and `spawn` APIs use ordinary pipes; PTY allocation is explicit
//! through [`v1::spawn_with_pty`] and
//! [`v1::container::spawn_in_container_with_pty`]. [`v1::run`] captures both output streams. With
//! [`v1::spawn`] or [`v1::container::spawn_in_container`], callers
//! can take the streams from [`MxcProcess`] or let `wait` drain and discard any
//! stream they did not take. WSLC does not expose stdin.
//!
//! [`v1::spawn_with_pty`] allocates a caller-controlled PTY for supported one-shot
//! backends, including IsolationSession, Bubblewrap, LXC, and Seatbelt direct
//! execution.
//! [`v1::container::spawn_in_container_with_pty`] does the same for a process in
//! an existing IsolationSession container. Unsupported backends reject the
//! request before creating a sandbox.
//!
//! Policy and operational warnings are available through [`MxcProcess::warnings`]
//! and [`ExecutionResult::warnings`]. These include security warnings, network rules
//! that cannot carry traffic, and operational warnings such as unavailable
//! telemetry routing.
//!
//! ## Relationship to `mxc_engine`
//!
//! This crate is a thin, streaming-focused public facade. Backend dispatch,
//! host probing, and execution live in the internal `mxc_engine` crate;
//! `mxc-sdk` owns the public policy/config authoring layer and wraps the
//! engine's streaming handle in [`MxcProcess`].

mod configs;
mod options;
mod policy;
mod sandbox;
mod state_aware_sdk;

mod telemetry;

#[cfg(doctest)]
mod api_tests;

#[cfg(target_os = "windows")]
use mxc_engine::ProbeOutput;
use mxc_engine::{Error, ErrorCode};

use sandbox::{ExecutionResult, MxcProcess};

/// V1 contract-mapped request and typed lifecycle APIs.
///
/// These types and entry points target the latest published V1 contract
/// owned by this SDK. Callers supply typed requests rather than JSON or a
/// schema version.
///
pub mod v1 {
    pub use crate::options::{
        DeprovisionOptions, ProvisionOptions, RunInContainerOptions, RunOptions,
        SpawnInContainerOptions, SpawnInContainerWithPtyOptions, SpawnOptions, SpawnWithPtyOptions,
        StartOptions, StopOptions, TelemetryConfig,
    };
    pub use mxc_engine::{
        available_backends, platform_support, AvailableBackend, BackendCapability,
        BubblewrapNetworkSupport, Error, ErrorCode, PlatformSupport, ProxyEnforcement,
    };
    #[cfg(target_os = "windows")]
    pub use mxc_engine::{ProbeFacts, ProbeOutput, UiCapabilitySupport};

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
                    experimental: options.experimental,
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
        mxc_engine::probe_execution_request(prepared.as_ref().map(|request| &request.inner))
    }

    /// Spawn a [`ContainerRequest`] and return its live process.
    ///
    /// Returns a [`MxcProcess`] handle for live bidirectional stdio and termination;
    /// no pty is allocated. Any stdout/stderr stream the caller does not
    /// `take_*` is drained and discarded by [`wait`](MxcProcess::wait).
    pub fn spawn(request: ContainerRequest, options: SpawnOptions) -> Result<MxcProcess, Error> {
        let prepared = crate::policy::prepare_creation_request(
            &request,
            options.experimental,
            options.telemetry,
        )?;
        mxc_engine::spawn_execution_request(&prepared.inner).map(MxcProcess::new)
    }

    /// Spawn a [`ContainerRequest`] attached to a caller-controlled PTY.
    pub fn spawn_with_pty(
        request: ContainerRequest,
        options: SpawnWithPtyOptions,
    ) -> Result<MxcPtyProcess, Error> {
        options.size.validate()?;
        let prepared = crate::policy::prepare_creation_request(
            &request,
            options.experimental,
            options.telemetry,
        )?;
        mxc_engine::spawn_with_pty(&prepared.inner, options.size.into())
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
                experimental: options.experimental,
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
        mxc_engine::spawn_one_shot_json(request_json, experimental).map(MxcProcess::new)
    }

    /// Spawn an exact-version JSON request attached to a caller-controlled PTY.
    #[doc(hidden)]
    pub fn spawn_with_pty_json(
        request_json: &str,
        experimental: bool,
        size: v1::MxcPtySize,
    ) -> Result<v1::MxcPtyProcess, Error> {
        size.validate()?;
        mxc_engine::spawn_one_shot_pty_json(request_json, experimental, size.into())
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
    /// Handles the envelope phases â€” `provision`, `start`, `stop`, `deprovision` â€”
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
        mxc_engine::run_state_aware_json(request_json, dry_run, experimental)
    }

    /// Execute a lifecycle request (as a JSON string) as a **live streaming**
    /// process, returning a [`MxcProcess`] handle for output streaming, waiting,
    /// and termination â€” exactly like [`v1::spawn`]. Backends that expose process
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
        mxc_engine::exec_state_aware_json(request_json, experimental).map(MxcProcess::new)
    }

    /// Spawn a lifecycle execution request with a caller-controlled PTY.
    #[doc(hidden)]
    pub fn spawn_in_container_with_pty_json(
        request_json: &str,
        size: v1::MxcPtySize,
        experimental: bool,
    ) -> Result<v1::MxcPtyProcess, Error> {
        size.validate()?;
        mxc_engine::exec_state_aware_pty_json(request_json, experimental, size.into())
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
        use wxc_common::state_aware_backend::ExecOutcome;
        mxc_engine::exec_state_aware_attached(request_json, experimental).map(|outcome| {
            match outcome {
                ExecOutcome::Exited(code) => WaitResult::Exited(code),
                ExecOutcome::TimedOut => WaitResult::TimedOut,
            }
        })
    }
}

fn wait_with_output(sandbox: MxcProcess) -> Result<ExecutionResult, Error> {
    sandbox.wait_with_output().map_err(|e| {
        Error::new(
            ErrorCode::BackendError,
            format!("waiting for the sandbox to complete failed: {e}"),
        )
    })
}
