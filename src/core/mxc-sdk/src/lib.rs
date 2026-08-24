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
//! let mut request = build_request(&policy, None)?;
//! request.set_script("echo hi");
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
//! | Bubblewrap | Linux | [`Containment::Process`] |
//! | Seatbelt | macOS | [`Containment::Process`] |
//! | ProcessContainer (AppContainer / BaseContainer) | Windows | [`Containment::Process`] |
//! | Explicit ProcessContainer configuration | Windows | [`Containment::ProcessContainer`] |
//! | WSLC (WSL Container) | Windows | [`Containment::Wslc`] |
//!
//! WSLC is **experimental**: build with the crate's `wslc` feature, and call
//! [`SandboxRequest::set_experimental(true)`](SandboxRequest::set_experimental)
//! on the request. Its container has no stdin (the WSLC SDK exposes no
//! process-input API), so [`Sandbox::take_stdin`] returns `None` for it.
//!
//! Backends with no [`Containment`] variant return an [`Error`] with
//! [`ErrorCode::UnsupportedContainment`]; drive the standalone executor
//! binaries for those. IsolationSession refuses the one-shot surface the same
//! way, and is reached through the state-aware lifecycle below.
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
//! use mxc_sdk::{build_request_with_containment, run, Containment, SandboxPolicy, WslcSection};
//!
//! # let policy = SandboxPolicy {
//! #     version: "0.7.0-alpha".to_string(),
//! #     filesystem: None, network: None, ui: None, timeout_ms: None,
//! # };
//! // Run a command inside a WSL container (Windows, --features wslc).
//! let wslc = WslcSection { image: "python:3.12".to_string(), ..Default::default() };
//! let mut request = build_request_with_containment(&policy, &Containment::Wslc(wslc), None)?;
//! request.set_script("python3 -c 'print(42)'").set_experimental(true);
//! let output = run(request)?;
//! # Ok::<(), mxc_sdk::Error>(())
//! ```
//!
//! ## Choosing an entry point
//!
//! |             | one-shot            | state-aware                           | Stdio                                    |
//! |-------------|---------------------|---------------------------------------|------------------------------------------|
//! | **capture** | [`run`]             | `exec_sandbox(…)?.wait_with_output()` | captured                                 |
//! | **handle**  | [`spawn_sandbox`]   | [`exec_sandbox`]                      | live pipes (stream, kill); no TTY        |
//! | **attach**  | *not available*     | [`exec_attached`]                     | this process's stdio; TTY if it has one  |
//!
//! [`run_state_aware_json`] sits alongside these and drives the *other*
//! state-aware phases — `provision`, `start`, `stop`, `deprovision`, and a dry
//! run of any phase — taking the wire-format request JSON and returning the
//! response-envelope JSON. The crate README covers which backends implement the
//! lifecycle and how each is compiled in.
//!
//! **IsolationSession is refused from a single-threaded apartment.**
//!
//! ## Pty allocation
//!
//! Every entry point except [`exec_attached`] wires the child's stdio to
//! ordinary pipes and allocates no pty. [`run`] captures both streams; with
//! [`spawn_sandbox`] or [`exec_sandbox`], stream the handle's
//! `take_stdout`/`take_stderr`, or let [`wait`](Sandbox::wait) drain and
//! discard any untaken stream.
//!
//! Under [`exec_attached`], IsolationSession allocates a pseudo-console and
//! forwards stdin, so interactive shells render and resize. A pseudo-console
//! has one output stream, so the sandbox's stderr arrives merged into stdout.
//!
//! [`exec_attached`] is verified against IsolationSession only.
//!
//! Policy security warnings are available through [`Sandbox::warnings`] and
//! [`Output::warnings`].
//!
//! ## Relationship to `mxc_engine`
//!
//! This crate is a thin, streaming-focused public facade. Backend dispatch,
//! host probing, and config building live in the internal `mxc_engine` crate;
//! `mxc-sdk` re-exports the curated surface and wraps the engine's streaming
//! handle in [`Sandbox`].

mod sandbox;

pub use mxc_engine::configs;
pub use mxc_engine::policy;
pub use mxc_engine::{
    available_backends, available_tools_policy, build_request, build_request_with_containment,
    platform_support, temporary_files_policy, user_profile_policy, AvailableBackend,
    BackendCapability, Containment, Error, ErrorCode, FilesystemPolicyResult, NetworkAction,
    NetworkEgressSection, NetworkIngressSection, NetworkPeerSection, NetworkPortSection,
    NetworkProtocol, NetworkRuleSection, PlatformSupport, RuntimeConfigSection, SandboxPolicy,
    SandboxRequest, WslcSection,
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
/// `--experimental` flag. The experimental backends — WindowsSandbox,
/// IsolationSession and WSLc — are refused with
/// [`ErrorCode::BackendUnavailable`] unless it is set, before any work is done.
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
/// streaming** process, returning a [`Sandbox`] handle for bidirectional stdio,
/// waiting, and termination — exactly like [`spawn_sandbox`].
///
/// The request JSON must be an `exec`-phase state-aware request (with a
/// `sandboxId` identifying a started sandbox). No pty is allocated.
///
/// **IsolationSession is the only backend that serves this**, and only with this
/// crate's `isolation_session` feature; the others cannot hand back pipes and
/// refuse. `experimental` opts in to the experimental backends, as for
/// [`run_state_aware_json`].
///
/// [`Sandbox::kill`] reaches only the foreground process here; a descendant the
/// workload backgrounded is reclaimed when the sandbox is stopped and
/// deprovisioned.
pub fn exec_sandbox(request_json: &str, experimental: bool) -> Result<Sandbox, Error> {
    mxc_engine::exec_state_aware_json(request_json, experimental).map(Sandbox::new)
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
/// A spent `scriptTimeout` arrives as [`WaitOutcome::Exited`]: a backend
/// relaying to a caller's stdio reports an exit code, and the relay rejects
/// anything else.
///
/// `experimental` opts in to the experimental backends, as for
/// [`run_state_aware_json`].
pub fn exec_attached(request_json: &str, experimental: bool) -> Result<WaitOutcome, Error> {
    use wxc_common::state_aware_backend::ExecOutcome;
    mxc_engine::exec_state_aware_attached(request_json, experimental).map(|outcome| match outcome {
        ExecOutcome::Exited(code) => WaitOutcome::Exited(code),
        ExecOutcome::TimedOut => WaitOutcome::TimedOut,
    })
}
