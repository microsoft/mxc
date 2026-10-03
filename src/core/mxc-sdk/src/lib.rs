// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! `mxc-sdk` — an importable library for starting MXC sandboxes in-process.
//!
//! Build a [`v1::SandboxRequest`] from a [`v1::SandboxPolicy`] with
//! [`v1::build_request`], then either:
//!
//! - hand it to [`v1::run`] to run the sandboxed process **to completion** and get
//!   its captured stdout/stderr and exit outcome in one call, or
//! - hand it to [`v1::spawn_sandbox`] for a live [`Sandbox`] handle you can
//!   stream stdio through, feed stdin, and kill while it runs, or
//! - hand it to [`v1::spawn_with_pty`] for an MXC-owned [`MxcPtyProcess`] with
//!   merged terminal output and resize support.
//!
//! Either way the right containment backend is selected for the host and the
//! ordinary run/spawn paths allocate no pty.
//!
//! ```no_run
//! use mxc_sdk::{v1, WaitOutcome};
//!
//! // Turn a policy into a request, fill in the command, and run it.
//! let policy = v1::SandboxPolicy::default();
//! let request = v1::build_request(&policy, "echo hi", None)?;
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
//! The selected backend is driven by the `containment` field in the request:
//! [`v1::build_request`] resolves the host's native one, and
//! [`v1::build_request_with_containment`] takes an explicit
//! [`v1::Containment`].
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
//! [`Sandbox::take_stdin`] returns `None` for it.
//! IsolationSession is also reachable through the state-aware lifecycle below,
//! which additionally serves an attached, pseudo-console exec.
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
//! # let policy = v1::SandboxPolicy::default();
//! // Run a command inside a WSL container (Windows, --features wslc).
//! let wslc = v1::WslcSection { image: "python:3.12".to_string(), ..Default::default() };
//! let request = v1::build_request_with_containment(&policy, &v1::Containment::Wslc(wslc), "python3 -c 'print(42)'", None)?;
//! let output = v1::run(request)?;
//! # Ok::<(), mxc_sdk::Error>(())
//! ```
//!
//! ## Choosing an entry point
//!
//! |             | one-shot          | typed state-aware | Stdio                             |
//! |-------------|-------------------|-------------------|-----------------------------------|
//! | **capture** | [`v1::run`]           | `v1::container::exec(…)?.wait_with_output()` | captured |
//! | **handle**  | [`v1::spawn_sandbox`] | [`v1::container::exec`] | live pipes (stream, kill); no TTY |
//! | **PTY**     | [`v1::spawn_with_pty`] | [`v1::container::spawn_in_container_with_pty`] | MXC-owned terminal; merged output, resize, kill |
//! | **attach**  | *not available*   | [`v1::container::exec_attached`] | this process's stdio; TTY if present |
//!
//! [`v1::container::provision`], [`v1::container::start`],
//! [`v1::container::stop`], and [`v1::container::deprovision`] drive the lifecycle
//! with typed Rust requests.
//! [`run_state_aware_json`], [`exec_sandbox_json`], and [`exec_attached_json`]
//! are the separate raw exact-JSON lane. The crate README covers which backends
//! implement the lifecycle and how each is compiled in.
//!
//! ## Pty allocation
//!
//! Every entry point except [`v1::spawn_with_pty`],
//! [`v1::container::spawn_in_container_with_pty`],
//! [`v1::container::exec_attached`], and [`exec_attached`] wires the child's
//! stdio to ordinary pipes and allocates no pty. [`v1::run`] captures both
//! streams; with [`v1::spawn_sandbox`] or [`v1::container::exec`], stream the handle's
//! `take_stdout`/`take_stderr`, or let [`wait`](Sandbox::wait) drain and
//! discard any untaken stream. WSLC exposes no stdin because its SDK has no
//! process-input API.
//!
//! [`v1::spawn_with_pty`] allocates a caller-driven PTY for supported one-shot
//! backends, including Windows ProcessContainer and IsolationSession.
//! [`v1::container::spawn_in_container_with_pty`] does the same for a process in
//! an existing IsolationSession container. Unsupported backends reject the
//! request before creating a sandbox.
//!
//! Under an attached exec, IsolationSession allocates a pseudo-console and
//! forwards stdin, so interactive shells render and resize. A pseudo-console
//! has one output stream, so the sandbox's stderr arrives merged into stdout.
//!
//! IsolationSession and WSLC serve typed attached exec through
//! [`v1::container::exec_attached`]. Windows Sandbox is reachable only through
//! the raw [`exec_attached_json`] path with an exact `1.1.0-alpha` request and
//! the experimental opt-in. IsolationSession additionally forwards stdin
//! through a pseudo-console; Windows Sandbox drops terminal input pending PTY
//! support, and WSLC has no process-input API.
//!
//! Policy and operational warnings are available through [`Sandbox::warnings`]
//! and [`Output::warnings`]. Attached exec has no returned handle, so it
//! writes those warnings to the host stderr that the caller explicitly attached.
//! These include security warnings, network rules that cannot carry traffic,
//! and operational warnings such as unavailable telemetry routing.
//!
//! ## Relationship to `mxc_engine`
//!
//! This crate is a thin, streaming-focused public facade. Backend dispatch,
//! host probing, and execution live in the internal `mxc_engine` crate;
//! `mxc-sdk` owns the public policy/config authoring layer and wraps the
//! engine's streaming handle in [`Sandbox`].

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

pub use sandbox::{
    CaptureDenialsErrorOutput, CaptureDenialsOutput, MxcPtyProcess, MxcPtySize, Output, Sandbox,
    SandboxOutputMetadata, StreamCloser, WaitOutcome,
};

/// V1 contract-mapped policy, request, and typed lifecycle APIs.
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
pub mod v1 {
    /// Backend-specific V1 configuration sections.
    pub mod configs {
        pub use crate::configs::*;
    }

    /// V1 high-level policy sections.
    pub mod policy {
        pub use crate::policy::*;
    }

    /// V1 typed state-aware lifecycle entry points.
    pub mod container {
        pub use crate::sandbox::{
            deprovision, exec, exec_attached, provision, start, stop, validate_deprovision,
            validate_exec, validate_provision, validate_start, validate_stop,
        };

        use crate::state_aware_sdk::{ExecRequest, OperationOptions, SandboxId};
        use crate::{Error, MxcPtyProcess, MxcPtySize};

        /// Spawn a process in an existing container with a caller-controlled PTY.
        pub fn spawn_in_container_with_pty(
            sandbox_id: &SandboxId,
            request: ExecRequest,
            size: MxcPtySize,
            options: OperationOptions,
        ) -> Result<MxcPtyProcess, Error> {
            size.validate()?;
            let input = request
                .into_sdk_input(sandbox_id, options.telemetry_opt_in)
                .map_err(Error::from)?;
            mxc_engine::exec_typed_state_aware_pty_request(input, options.experimental, size.into())
                .and_then(MxcPtyProcess::new)
        }
    }

    pub use crate::policy::{
        available_tools_policy, build_request, build_request_with_containment,
        temporary_files_policy, user_profile_policy, Containment, FilesystemPolicyResult,
        NetworkAction, NetworkEgressSection, NetworkIngressSection, NetworkPeerSection,
        NetworkPortSection, NetworkProtocol, NetworkRuleSection, RuntimeConfigSection,
        SandboxPolicy, SandboxRequest, WslcSection,
    };
    pub use crate::state_aware_sdk::{
        ExecRequest, IsolationSessionProvisionMetadata, LifecycleResult, OperationOptions,
        ProvisionMetadata, ProvisionRequest, ProvisionResult, SandboxId,
        StateAwareExecBackendOptions, StateAwareProvision, ValidationResult,
    };

    use crate::{Error, MxcPtyProcess, MxcPtySize, Output, Sandbox};

    /// Probe an optional ProcessContainer request without creating a sandbox.
    ///
    /// Other containments use backend availability discovery and their normal
    /// launch-time validation because this result describes ProcessContainer tiers.
    #[cfg(target_os = "windows")]
    pub fn probe(request: Option<&SandboxRequest>) -> Result<crate::ProbeOutput, Error> {
        mxc_engine::probe_execution_request(request.map(|request| &request.inner))
    }

    /// Spawn a sandbox from a [`SandboxRequest`] built by [`build_request`] (with
    /// the command, and any working directory / env, filled in).
    ///
    /// Returns a [`Sandbox`] handle for live bidirectional stdio and termination;
    /// no pty is allocated. Any stdout/stderr stream the caller does not
    /// `take_*` is drained and discarded by [`wait`](Sandbox::wait).
    pub fn spawn_sandbox(request: SandboxRequest) -> Result<Sandbox, Error> {
        mxc_engine::spawn_execution_request(&request.inner).map(Sandbox::new)
    }

    /// Spawn a sandboxed process attached to an MXC-owned pseudo-terminal.
    pub fn spawn_with_pty(
        request: SandboxRequest,
        size: MxcPtySize,
    ) -> Result<MxcPtyProcess, Error> {
        size.validate()?;
        mxc_engine::spawn_with_pty(&request.inner, size.into()).and_then(MxcPtyProcess::new)
    }

    /// Run a sandbox from a [`SandboxRequest`] **to completion**, capturing its
    /// output.
    ///
    /// A convenience over [`spawn_sandbox`] + [`Sandbox::wait_with_output`]: it
    /// spawns the sandboxed process, waits for it to exit (honouring the
    /// request's `scriptTimeout`), and returns the captured stdout/stderr plus
    /// the root [`crate::WaitOutcome`]. Both streams are drained concurrently,
    /// so an output-heavy child can't deadlock. No pty is allocated.
    ///
    /// Use [`spawn_sandbox`] instead when you need to stream stdio live, feed
    /// stdin, or kill the process while it runs.
    ///
    /// `Err` is returned when the backend can't be selected/spawned (an
    /// [`Error`]), or when waiting on the child fails at the OS level.
    pub fn run(request: SandboxRequest) -> Result<Output, Error> {
        crate::wait_with_output(spawn_sandbox(request)?)
    }

    #[cfg(all(test, target_os = "windows"))]
    mod tests {
        use super::*;

        #[test]
        fn public_request_probe_uses_sdk_request_model() {
            let request = build_request(&SandboxPolicy::default(), "cmd /c exit 0", None)
                .expect("default Windows policy builds");
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
/// Hyperlight, or Windows Sandbox), which is otherwise refused with
/// [`ErrorCode::BackendUnavailable`]. It is ignored for production backends and
/// is never read from the JSON.
pub fn spawn_sandbox_json(request_json: &str, experimental: bool) -> Result<Sandbox, Error> {
    mxc_engine::spawn_one_shot_json(request_json, experimental).map(Sandbox::new)
}

/// Spawn a raw exact-version one-shot JSON request attached to an MXC-owned PTY.
///
/// The JSON and `experimental` rules match [`spawn_sandbox_json`].
pub fn spawn_with_pty_json(
    request_json: &str,
    experimental: bool,
    size: MxcPtySize,
) -> Result<MxcPtyProcess, Error> {
    size.validate()?;
    mxc_engine::spawn_one_shot_pty_json(request_json, experimental, size.into())
        .and_then(MxcPtyProcess::new)
}

/// Run a raw exact-version one-shot JSON request to completion, capturing its
/// output. The JSON and `experimental` rules match [`spawn_sandbox_json`].
pub fn run_json(request_json: &str, experimental: bool) -> Result<Output, Error> {
    wait_with_output(spawn_sandbox_json(request_json, experimental)?)
}

fn wait_with_output(sandbox: Sandbox) -> Result<Output, Error> {
    sandbox.wait_with_output().map_err(|e| {
        Error::new(
            ErrorCode::BackendError,
            format!("waiting for the sandbox to complete failed: {e}"),
        )
    })
}

/// Run a **state-aware lifecycle** request (as a JSON string) and return the
/// response-envelope JSON string.
///
/// Handles the envelope phases — `provision`, `start`, `stop`, `deprovision` —
/// and a dry run of any phase. A non-dry-run `exec` produces no envelope, so it
/// is rejected here; run it through an exec entry point instead:
/// [`exec_attached`] to attach the workload to this process's stdio, or
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
pub fn run_state_aware_json(
    request_json: &str,
    dry_run: bool,
    experimental: bool,
) -> Result<String, Error> {
    mxc_engine::run_state_aware_json(request_json, dry_run, experimental)
}

/// Run the `exec` phase of a state-aware request (as a JSON string) as a **live
/// streaming** process, returning a [`Sandbox`] handle for output streaming,
/// waiting, and termination — exactly like [`v1::spawn_sandbox`]. Backends
/// that expose process input also make [`Sandbox::take_stdin`] available.
///
/// The request JSON must be an `exec`-phase state-aware request (with a
/// `sandboxId` identifying a started sandbox). No pty is allocated.
///
/// IsolationSession and WSLC serve this with the crate's corresponding
/// `isolation_session` or `wslc` feature. WSLC returns separate stdout/stderr
/// pipes but no stdin. Windows Sandbox cannot hand back pipes and refuses.
/// `experimental` opts in to experimental backends, as for
/// [`run_state_aware_json`].
///
/// [`Sandbox::kill`] reaches only the foreground process here; a descendant the
/// workload backgrounded is reclaimed when the sandbox is stopped and
/// deprovisioned.
pub fn exec_sandbox(request_json: &str, experimental: bool) -> Result<Sandbox, Error> {
    exec_sandbox_json(request_json, experimental)
}

/// Run a raw exact-JSON state-aware exec request as a live streaming sandbox.
pub fn exec_sandbox_json(request_json: &str, experimental: bool) -> Result<Sandbox, Error> {
    mxc_engine::exec_state_aware_json(request_json, experimental).map(Sandbox::new)
}

/// Run a raw exact-JSON state-aware exec request with a caller-controlled PTY.
pub fn spawn_in_container_with_pty_json(
    request_json: &str,
    size: MxcPtySize,
    experimental: bool,
) -> Result<MxcPtyProcess, Error> {
    size.validate()?;
    mxc_engine::exec_state_aware_pty_json(request_json, experimental, size.into())
        .and_then(MxcPtyProcess::new)
}

/// Run the `exec` phase of a state-aware request **attached to this process's
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
/// [`run_state_aware_json`].
pub fn exec_attached(request_json: &str, experimental: bool) -> Result<WaitOutcome, Error> {
    exec_attached_json(request_json, experimental)
}

/// Run a raw exact-JSON state-aware exec request attached to this process's
/// stdio.
pub fn exec_attached_json(request_json: &str, experimental: bool) -> Result<WaitOutcome, Error> {
    use wxc_common::state_aware_backend::ExecOutcome;
    mxc_engine::exec_state_aware_attached(request_json, experimental).map(|outcome| match outcome {
        ExecOutcome::Exited(code) => WaitOutcome::Exited(code),
        ExecOutcome::TimedOut => WaitOutcome::TimedOut,
    })
}
