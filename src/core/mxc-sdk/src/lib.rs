// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! `mxc-sdk` — an importable library for starting MXC sandboxes in-process.
//!
//! Build a [`SandboxRequest`] from a [`SandboxPolicy`] with [`build_request`],
//! then either:
//!
//! - hand it to [`run`] to run the sandboxed process **to completion** and get
//!   its captured stdout/stderr and exit outcome in one call, or
//! - hand it to [`spawn_sandbox`] for a live [`Sandbox`] handle you can stream
//!   stdio through, feed stdin, and kill while it runs.
//!
//! Either way the right containment backend is selected for the host and the
//! process runs **without ever allocating a pty**.
//!
//! ```no_run
//! use mxc_sdk::{build_request, run, SandboxPolicy, WaitOutcome};
//!
//! // Turn a policy into a request, fill in the command, and run it.
//! let policy = SandboxPolicy {
//!     version: "0.7.0-alpha".to_string(),
//!     filesystem: None,
//!     network: None,
//!     ui: None,
//!     timeout_ms: None,
//! };
//! let request = build_request(&policy, "echo hi", None)?;
//! let output = run(request)?;
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
//! [`build_request`] resolves the host's native one, and
//! [`build_request_with_containment`] takes an explicit [`Containment`].
//!
//! | Backend | Host | Selected by |
//! |---------|------|-------------|
//! | Bubblewrap | Linux | [`Containment::Process`] or [`Containment::Bubblewrap`] |
//! | Seatbelt | macOS | [`Containment::Process`] or [`Containment::Seatbelt`] |
//! | ProcessContainer (AppContainer / BaseContainer) | Windows | [`Containment::Process`] |
//! | Explicit ProcessContainer configuration | Windows | [`Containment::ProcessContainer`] |
//! | WSLC (WSL Container) | Windows | [`Containment::Wslc`] |
//! | IsolationSession | Windows | [`Containment::IsolationSession`] |
//!
//! [`Containment::Lxc`] models explicit LXC settings, but the in-process
//! [`run`] and [`spawn_sandbox`] APIs return
//! [`ErrorCode::UnsupportedContainment`] because LXC does not expose captured
//! pipe-based execution. Use the standalone `lxc-exec` binary for LXC.
//!
//! WSLC and IsolationSession are **experimental**: build with the crate's
//! `wslc` / `isolation_session` feature, and call
//! [`SandboxRequest::set_experimental(true)`](SandboxRequest::set_experimental)
//! on the request. WSLC's container has no stdin (the WSLC SDK exposes no
//! process-input API), so [`Sandbox::take_stdin`] returns `None` for it.
//! IsolationSession is also reachable through the state-aware lifecycle below,
//! which additionally serves an attached, pseudo-console exec.
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
//! use mxc_sdk::{
//!     build_request_with_containment, run, Containment, SandboxPolicy, WslcSection,
//! };
//!
//! # let policy = SandboxPolicy {
//! #     version: "0.9.0-alpha".to_string(),
//! #     filesystem: None, network: None, ui: None, timeout_ms: None,
//! # };
//! // Run a command inside a WSL container (Windows, --features wslc).
//! let wslc = WslcSection { image: "python:3.12".to_string(), ..Default::default() };
//! let mut request = build_request_with_containment(&policy, &Containment::Wslc(wslc), "python3 -c 'print(42)'", None)?;
//! request.set_experimental(true);
//! let output = run(request)?;
//! # Ok::<(), mxc_sdk::Error>(())
//! ```
//!
//! ## Choosing an entry point
//!
//! |             | one-shot            | state-aware                           | Stdio                                    |
//! |-------------|---------------------|---------------------------------------|------------------------------------------|
//! | **capture** | [`run`]             | `sandbox::exec(…)?.wait_with_output()` | captured                              |
//! | **handle**  | [`spawn_sandbox`]   | [`sandbox::exec`]                   | live pipes (stream, kill); no TTY        |
//! | **attach**  | *not available*     | [`sandbox::exec_attached`]           | this process's stdio; TTY if it has one  |
//!
//! The explicit sandbox lifecycle methods drive provision, start, exec, stop,
//! and deprovision. Operation and sandbox identity are API arguments rather
//! than fields in the configuration JSON.
//!
//! **IsolationSession is refused from a single-threaded apartment.**
//!
//! ## Pty allocation
//!
//! Every entry point except [`sandbox::exec_attached`] wires the child's stdio to
//! ordinary pipes and allocates no pty. [`run`] captures both streams; with
//! [`spawn_sandbox`] or [`sandbox::exec`], stream the handle's
//! `take_stdout`/`take_stderr`, or let [`wait`](Sandbox::wait) drain and
//! discard any untaken stream.
//!
//! Under [`sandbox::exec_attached`], IsolationSession allocates a pseudo-console and
//! forwards stdin, so interactive shells render and resize. A pseudo-console
//! has one output stream, so the sandbox's stderr arrives merged into stdout.
//!
//! [`sandbox::exec_attached`] is verified against IsolationSession only.
//!
//! Policy and operational warnings are available through [`Sandbox::warnings`]
//! and [`Output::warnings`]. [`sandbox::exec_attached`] has no returned handle, so it
//! writes those warnings to the host stderr that the caller explicitly attached.
//! These include security warnings, network rules that cannot carry traffic,
//! and operational warnings such as unavailable telemetry routing.
//!
//! ## Relationship to `mxc_engine`
//!
//! This crate is a thin, streaming-focused public facade. Backend dispatch,
//! host probing, and config building live in the internal `mxc_engine` crate;
//! `mxc-sdk` re-exports the curated surface and wraps the engine's streaming
//! handle in [`Sandbox`].

pub mod sandbox;
mod sandbox_operations;

pub mod telemetry;

pub use mxc_engine::configs;
pub use mxc_engine::policy;
#[doc(hidden)]
pub use mxc_engine::LifecycleOperation;
pub use mxc_engine::{
    available_backends, available_tools_policy, build_request, build_request_with_containment,
    platform_support, temporary_files_policy, user_profile_policy, AvailableBackend,
    BackendCapability, BubblewrapNetworkSupport, Containment, Error, ErrorCode,
    FilesystemPolicyResult, NetworkAction, NetworkEgressSection, NetworkIngressSection,
    NetworkPeerSection, NetworkPortSection, NetworkProtocol, NetworkRuleSection, PlatformSupport,
    ProxyEnforcement, RuntimeConfigSection, SandboxPolicy, SandboxRequest, WslcSection,
};

pub use sandbox::{
    CaptureDenialsErrorOutput, CaptureDenialsOutput, Output, Sandbox, SandboxOutputMetadata,
    StreamCloser, WaitOutcome,
};

/// Spawn a sandbox from a [`SandboxRequest`] built by [`build_request`] (with
/// the command, and any working directory / env, filled in).
///
/// Returns a [`Sandbox`] handle for live bidirectional stdio and termination;
/// no pty is allocated. Any stdout/stderr stream the caller does not `take_*` is
/// drained and discarded by [`wait`](Sandbox::wait).
pub fn spawn_sandbox(request: SandboxRequest) -> Result<Sandbox, Error> {
    mxc_engine::spawn(&request).map(Sandbox::new)
}

/// Run a sandbox from a [`SandboxRequest`] **to completion**, capturing its
/// output.
///
/// A convenience over [`spawn_sandbox`] + [`Sandbox::wait_with_output`]: it
/// spawns the sandboxed process, waits for it to exit (honouring the request's
/// `scriptTimeout`), and returns the captured stdout/stderr plus the
/// [`WaitOutcome`]. Both streams are drained concurrently, so an output-heavy
/// child can't deadlock. No pty is allocated.
///
/// Use [`spawn_sandbox`] instead when you need to stream stdio live, feed
/// stdin, or kill the process while it runs.
///
/// `Err` is returned when the backend can't be selected/spawned (an
/// [`Error`]), or when waiting on the child fails at the OS level.
pub fn run(request: SandboxRequest) -> Result<Output, Error> {
    let sandbox = spawn_sandbox(request)?;
    sandbox.wait_with_output().map_err(|e| {
        Error::new(
            ErrorCode::BackendError,
            format!("waiting for the sandbox to complete failed: {e}"),
        )
    })
}

/// Workspace-internal lifecycle bridge used by generated language bindings.
#[doc(hidden)]
pub fn run_lifecycle_operation(
    request_json: &str,
    operation: LifecycleOperation,
    sandbox_id: Option<&str>,
    dry_run: bool,
    experimental: bool,
) -> Result<String, Error> {
    mxc_engine::run_state_aware_operation_json(
        request_json,
        operation,
        sandbox_id,
        dry_run,
        experimental,
    )
}
