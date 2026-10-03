// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! `mxc-sdk` — an importable library for starting MXC sandboxes in-process.
//!
//! Create a [`v1::ContainerRequest`] with its command and restrictions, then either:
//!
//! - hand it to [`v1::run`] to run the sandboxed process **to completion** and get
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
//! use mxc_sdk::v1::{self, WaitOutcome};
//!
//! let request = v1::ContainerRequest::new("echo hi");
//! let output = v1::run(request)?;
//! match output.outcome {
//!     WaitOutcome::Exited(code) => println!("exit={code}"),
//!     WaitOutcome::TimedOut => println!("timed out"),
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
//! Bubblewrap on Linux. It needs root, and it streams over pipes, so the
//! workload sees no TTY, unlike the `lxc-exec` binary, which allocates a pty.
//!
//! WSLC requires the crate's `wslc` build feature, and IsolationSession
//! requires the `isolation_session` build feature. WSLC's container has no
//! stdin (the WSLC SDK exposes no process-input API), so
//! [`MxcProcess::take_stdin`] returns `None` for it.
//! IsolationSession is also available through the typed state-aware lifecycle.
//!
//! The `wslc` feature stages `wslcsdk.dll` into the cargo profile directory,
//! and WSLC loads it from beside the module holding this code, so an executable
//! copied or installed out of that directory needs the DLL brought along. The
//! crate README covers that and the separate `wxc-wslc-daemon.exe` that the
//! state-aware lifecycle needs.
//!
//! A concrete backend selected on another host returns an [`Error`] with
//! [`ErrorCode::UnsupportedContainment`].
//!
//! # Diagnosing a failure
//!
//! [`Error`] carries a closed [`ErrorCode`] and a message, and — when the
//! failure came from an underlying platform API — the call that failed and its
//! status:
//!
//! ```no_run
//! # fn demo(error: mxc_sdk::Error) {
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
//! raised before any API call was reached — a malformed policy, say — and a
//! native code only ever appears alongside the operation it belongs to.
//! `Display` renders both, so logging the error alone does not lose them.
//!
//! ```no_run
//! use mxc_sdk::v1;
//!
//! // Run a command inside a WSL container (Windows, --features wslc).
//! let wslc = v1::WslcSection { image: "python:3.12".to_string(), ..Default::default() };
//! let mut request = v1::ContainerRequest::new("python3 -c 'print(42)'");
//! request.set_containment(v1::Containment::Wslc(wslc));
//! let output = v1::run(request)?;
//! # Ok::<(), mxc_sdk::Error>(())
//! ```
//!
//! ## Choosing an entry point
//!
//! |             | one-shot          | existing container | Stdio |
//! |-------------|-------------------|--------------------|-------|
//! | **capture** | [`v1::run`] | [`v1::run_in_container`] | captured stdout and stderr |
//! | **handle**  | [`v1::spawn`] | [`v1::spawn_in_container`] or [`v1::exec_in_sandbox`] | separate live pipes |
//! | **PTY**     | [`v1::spawn_with_pty`] | [`v1::container::spawn_in_container_with_pty`] | merged output, resize |
//!
//! [`v1::container::provision_sandbox`], [`v1::container::start_sandbox`],
//! [`v1::container::stop_sandbox`], and
//! [`v1::container::deprovision_sandbox`] drive the lifecycle with typed Rust
//! requests. Raw exact-JSON entry points remain available separately for
//! callers that need direct wire-contract access.
//!
//! ## Standard streams
//!
//! The V1 `run` and `spawn` APIs use ordinary pipes; PTY allocation is explicit
//! through [`v1::spawn_with_pty`] and
//! [`v1::container::spawn_in_container_with_pty`]. [`v1::run`] captures both output streams. With
//! [`v1::spawn`], [`v1::spawn_in_container`], or [`v1::exec_in_sandbox`], callers
//! can take the streams from [`MxcProcess`] or let `wait` drain and discard any
//! stream they did not take. WSLC does not expose stdin.
//!
//! Policy and operational warnings are available through [`MxcProcess::warnings`]
//! and [`ExecutionOutput::warnings`]. These include security warnings, network rules
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
mod policy;
mod sandbox;
mod state_aware_sdk;

pub mod telemetry;

pub use mxc_engine::{
    available_backends, platform_support, AvailableBackend, BackendCapability,
    BubblewrapNetworkSupport, Error, ErrorCode, PlatformSupport, ProxyEnforcement,
};
#[cfg(target_os = "windows")]
pub use mxc_engine::{ProbeFacts, ProbeOutput, UiCapabilitySupport};

use sandbox::{ExecutionOutput, MxcProcess, WaitOutcome};

/// V1 contract-mapped request and typed lifecycle APIs.
///
/// These types and entry points target the latest published v1 exact contract
/// owned by this SDK. Callers do not supply a schema version on this path; use
/// the root raw exact-JSON functions when a request must declare its own
/// contract version.
///
/// The legacy root probe and lifecycle module paths are not exported:
///
/// ```compile_fail
/// use mxc_sdk::probe;
/// ```
///
/// ```compile_fail
/// use mxc_sdk::v1::sandbox;
/// ```
///
/// ```compile_fail
/// use mxc_sdk::v1::container::exec_in_attached;
/// ```
///
/// ```compile_fail
/// use mxc_sdk::exec_attached;
/// ```
pub mod v1 {
    /// Backend-specific V1 configuration sections.
    pub mod configs {
        pub use crate::configs::*;
    }

    /// V1 policy authoring types.
    pub mod policy {
        pub use crate::policy::{
            available_tools_policy, temporary_files_policy, user_profile_policy, ClipboardPolicy,
            Containment, FilesystemPolicyResult, FilesystemSection, NetworkAction,
            NetworkEgressSection, NetworkIngressSection, NetworkPeerSection, NetworkPortSection,
            NetworkProtocol, NetworkRuleSection, NetworkSection, RuntimeConfigSection, UiSection,
            WslcSection,
        };
    }

    /// V1 typed state-aware lifecycle entry points.
    pub mod container {
        pub use crate::sandbox::{
            deprovision as deprovision_sandbox, provision as provision_sandbox,
            spawn_in_container_with_pty, start as start_sandbox, stop as stop_sandbox,
            validate_deprovision, validate_exec, validate_provision, validate_start, validate_stop,
        };
    }

    pub use crate::policy::{
        available_tools_policy, temporary_files_policy, user_profile_policy, ClipboardPolicy,
        ContainerRequest, Containment, FilesystemPolicyResult, FilesystemSection, NetworkAction,
        NetworkEgressSection, NetworkIngressSection, NetworkPeerSection, NetworkPortSection,
        NetworkProtocol, NetworkRuleSection, NetworkSection, RuntimeConfigSection, UiSection,
        WslcSection,
    };
    pub use crate::sandbox::{
        CaptureDenialsErrorOutput, CaptureDenialsOutput, ExecutionOutput, MxcProcess,
        MxcPtyProcess, MxcPtySize, SandboxOutputMetadata, StreamCloser, WaitOutcome,
    };
    pub use crate::state_aware_sdk::{
        ContainerId, ExecBackendOptions, ExecRequest, IsolationSessionProvisionMetadata,
        LifecycleResult, OperationOptions, ProvisionMetadata, ProvisionRequest, ProvisionResult,
        ValidationResult,
    };

    use crate::Error;

    /// Probe an optional ProcessContainer request without creating a sandbox.
    ///
    /// Other containments use backend availability discovery and their normal
    /// launch-time validation because this result describes ProcessContainer tiers.
    #[cfg(target_os = "windows")]
    pub fn probe(request: Option<&ContainerRequest>) -> Result<crate::ProbeOutput, Error> {
        let prepared = request.map(crate::policy::prepare_request).transpose()?;
        mxc_engine::probe_execution_request(prepared.as_ref().map(|request| &request.inner))
    }

    /// Spawn a one-shot [`ContainerRequest`] and return its live process.
    ///
    /// Returns a [`MxcProcess`] handle for live bidirectional stdio and termination;
    /// no pty is allocated. Any stdout/stderr stream the caller does not
    /// `take_*` is drained and discarded by [`wait`](MxcProcess::wait).
    pub fn spawn(request: ContainerRequest) -> Result<MxcProcess, Error> {
        let prepared = crate::policy::prepare_request(&request)?;
        mxc_engine::spawn_execution_request(&prepared.inner).map(MxcProcess::new)
    }

    /// Spawn a one-shot [`ContainerRequest`] attached to a caller-controlled PTY.
    pub fn spawn_with_pty(
        request: ContainerRequest,
        size: MxcPtySize,
    ) -> Result<MxcPtyProcess, Error> {
        size.validate()?;
        let prepared = crate::policy::prepare_request(&request)?;
        mxc_engine::spawn_with_pty(&prepared.inner, size.into()).and_then(MxcPtyProcess::new)
    }

    /// Run a one-shot [`ContainerRequest`] to completion and capture its output.
    ///
    /// Both streams are drained concurrently, so an output-heavy child cannot
    /// deadlock. No pty is allocated.
    ///
    /// Use [`spawn`] instead when you need to stream stdio, feed stdin, or kill
    /// the process while it runs.
    ///
    /// `Err` is returned when the backend can't be selected/spawned (an
    /// [`Error`]), or when waiting on the child fails at the OS level.
    pub fn run(request: ContainerRequest) -> Result<ExecutionOutput, Error> {
        crate::wait_with_output(spawn(request)?)
    }

    /// Spawn a workload in an existing container and return its live process.
    pub fn spawn_in_container(
        container_id: &ContainerId,
        request: ExecRequest,
        options: OperationOptions,
    ) -> Result<MxcProcess, Error> {
        crate::sandbox::spawn_in_container(container_id, request, options)
    }

    /// Execute the state-aware exec phase in an existing container as a live process.
    ///
    /// This is the state-aware counterpart to [`spawn_in_container`]. Both
    /// entry points return the same pipe-backed process handle.
    pub fn exec_in_sandbox(
        container_id: &ContainerId,
        request: ExecRequest,
        options: OperationOptions,
    ) -> Result<MxcProcess, Error> {
        spawn_in_container(container_id, request, options)
    }

    /// Run a workload in an existing container to completion and capture output.
    pub fn run_in_container(
        container_id: &ContainerId,
        request: ExecRequest,
        options: OperationOptions,
    ) -> Result<ExecutionOutput, Error> {
        crate::wait_with_output(spawn_in_container(container_id, request, options)?)
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

/// Spawn a raw exact-version one-shot JSON request as a live sandbox.
///
/// The JSON must declare an exact registered `version` and contain a one-shot
/// request. Lifecycle requests are rejected; use the state-aware JSON APIs.
/// `experimental` permits selecting an experimental backend (MicroVM,
/// Hyperlight, or Windows MxcProcess), which is otherwise refused with
/// [`ErrorCode::BackendUnavailable`]. It is ignored for production backends and
/// is never read from the JSON.
pub fn spawn_sandbox_json(request_json: &str, experimental: bool) -> Result<MxcProcess, Error> {
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

/// Run a raw exact-version one-shot JSON request to completion, capturing its
/// output. The JSON and `experimental` rules match [`spawn_sandbox_json`].
pub fn run_json(request_json: &str, experimental: bool) -> Result<ExecutionOutput, Error> {
    wait_with_output(spawn_sandbox_json(request_json, experimental)?)
}

fn wait_with_output(sandbox: MxcProcess) -> Result<ExecutionOutput, Error> {
    sandbox.wait_with_output().map_err(|e| {
        Error::new(
            ErrorCode::BackendError,
            format!("waiting for the sandbox to complete failed: {e}"),
        )
    })
}

/// Run a lifecycle request (as a JSON string) and return the
/// response-envelope JSON string.
///
/// Handles the envelope phases — `provision`, `start`, `stop`, `deprovision` —
/// and a dry run of any phase. A non-dry-run `exec` produces no envelope, so it
/// is rejected here; run it through an exec entry point instead:
/// [`exec_sandbox`] to drive the pipes yourself.
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

/// Run the `exec` phase of a lifecycle request (as a JSON string) as a **live
/// streaming** process, returning a [`MxcProcess`] handle for output streaming,
/// waiting, and termination — exactly like [`v1::spawn`]. Backends
/// that expose process input also make [`MxcProcess::take_stdin`] available.
///
/// The request JSON must be an `exec`-phase lifecycle request (with a
/// `sandboxId` identifying a started sandbox). No pty is allocated.
///
/// IsolationSession and WSLC serve this with the crate's corresponding
/// `isolation_session` or `wslc` feature. WSLC returns separate stdout/stderr
/// pipes but no stdin. Windows MxcProcess cannot hand back pipes and refuses.
/// `experimental` opts in to experimental backends, as for
/// [`run_lifecycle_json`].
///
/// [`MxcProcess::kill`] reaches only the foreground process here; a descendant the
/// workload backgrounded is reclaimed when the sandbox is stopped and
/// deprovisioned.
pub fn exec_sandbox(request_json: &str, experimental: bool) -> Result<MxcProcess, Error> {
    exec_sandbox_json(request_json, experimental)
}

/// Run a raw exact-JSON state-aware exec request as a live streaming sandbox.
pub fn exec_sandbox_json(request_json: &str, experimental: bool) -> Result<MxcProcess, Error> {
    mxc_engine::exec_state_aware_json(request_json, experimental).map(MxcProcess::new)
}

/// Spawn a state-aware exec request with a caller-controlled PTY.
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

/// Run the `exec` phase of a lifecycle request **attached to this process's
/// stdio**, blocking until the sandboxed process exits.
///
/// The backend relays the workload's output onto this process's stdout and
/// stderr; see *Pty allocation* for which backends also forward stdin and
/// allocate a pseudo-console.
///
/// **This process's stdout and stdin must both be terminals**, or the call is
/// refused with [`ErrorCode::MalformedRequest`] and nothing is run.
///
/// Attached execution has no process handle on which to report a typed timeout.
/// A backend-native timeout that cannot be represented as an exit code is
/// returned as an [`Error`]. Use [`exec_sandbox`] when timeout must remain a
/// distinct [`WaitOutcome::TimedOut`] result.
///
/// `experimental` opts in to the experimental backends, as for
/// [`run_lifecycle_json`].
#[expect(
    dead_code,
    reason = "Attached exec is reserved but not exposed by the SDK yet"
)]
fn exec_attached(request_json: &str, experimental: bool) -> Result<WaitOutcome, Error> {
    exec_attached_json(request_json, experimental)
}

/// Run a raw exact-JSON state-aware exec request attached to this process's
/// stdio.
fn exec_attached_json(request_json: &str, experimental: bool) -> Result<WaitOutcome, Error> {
    use wxc_common::state_aware_backend::ExecOutcome;
    mxc_engine::exec_state_aware_attached(request_json, experimental).map(|outcome| match outcome {
        ExecOutcome::Exited(code) => WaitOutcome::Exited(code),
        ExecOutcome::TimedOut => WaitOutcome::TimedOut,
    })
}
