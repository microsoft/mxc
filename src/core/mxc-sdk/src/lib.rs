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
//! The selected backend is driven by the `containment` field in the request
//! (or the host default). The library supports Bubblewrap (Linux), Seatbelt
//! (macOS), and ProcessContainer — AppContainer and BaseContainer —
//! (Windows). Other backends (Windows Sandbox, IsolationSession, MicroVM,
//! Hyperlight, WSLC, LXC) return an [`Error`] with
//! [`ErrorCode::UnsupportedContainment`]; drive the standalone executor
//! binaries for those.
//!
//! | Entry point            | Stdio                                   |
//! |------------------------|-----------------------------------------|
//! | [`run`]                | captured (stdout/stderr returned)       |
//! | [`spawn_sandbox`]      | live (stream, feed stdin, kill)         |
//! | [`run_state_aware_json`] | state-aware envelope phases (JSON in/out) |
//! | [`exec_sandbox`]       | state-aware exec, live (stream/kill)    |
//!
//! ## State-aware lifecycle
//!
//! [`run_state_aware_json`] drives the envelope phases — `provision`, `start`,
//! `stop`, `deprovision` (and a dry run of any phase) — taking the wire-format
//! request JSON and returning the response-envelope JSON. [`exec_sandbox`] runs
//! the `exec` phase as a live streaming [`Sandbox`], the same handle
//! [`spawn_sandbox`] returns. The only in-tree state-aware backend
//! (IsolationSession) is Windows-only and needs its OS-side service.
//!
//! ## No pty
//!
//! The child's stdio is always wired to ordinary pipes — the library never
//! allocates a pty. [`run`] captures both streams; with [`spawn_sandbox`],
//! stream the handle's `take_stdout`/`take_stderr`, or let
//! [`wait`](Sandbox::wait) drain and discard any untaken stream.
//!
//! ## Relationship to `mxc_engine`
//!
//! This crate is a thin, streaming-focused public facade. Backend dispatch,
//! host probing, and config building live in the internal `mxc_engine` crate;
//! `mxc-sdk` re-exports the curated surface and wraps the engine's streaming
//! handle in [`Sandbox`].

mod sandbox;

pub use mxc_engine::policy;
pub use mxc_engine::{
    available_tools_policy, build_request, platform_support, temporary_files_policy,
    user_profile_policy, Error, ErrorCode, FilesystemPolicyResult, PlatformSupport, SandboxPolicy,
    SandboxRequest,
};

pub use sandbox::{Output, Sandbox, StreamCloser, WaitOutcome};

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
    sandbox.wait_with_output().map_err(|e| Error {
        code: ErrorCode::BackendError,
        message: format!("waiting for the sandbox to complete failed: {e}"),
    })
}

/// Run a **state-aware lifecycle** request (as a JSON string) and return the
/// response-envelope JSON string.
///
/// Handles the envelope phases — `provision`, `start`, `stop`, `deprovision` —
/// and a dry run of any phase. A non-dry-run `exec` streams its output, so it is
/// rejected here; drive it through [`exec_sandbox`] instead.
///
/// The request JSON is the same wire format the executor accepts (an object with
/// a `phase` field). Errors (malformed request, unsupported phase, backend
/// failures) come back as an [`Error`] with the matching [`ErrorCode`].
pub fn run_state_aware_json(request_json: &str, dry_run: bool) -> Result<String, Error> {
    mxc_engine::run_state_aware_json(request_json, dry_run)
}

/// Run the `exec` phase of a state-aware request (as a JSON string) as a **live
/// streaming** process, returning a [`Sandbox`] handle for bidirectional stdio,
/// waiting, and termination — exactly like [`spawn_sandbox`].
///
/// The request JSON must be an `exec`-phase state-aware request (with a
/// `sandboxId` identifying a started sandbox). No pty is allocated.
pub fn exec_sandbox(request_json: &str) -> Result<Sandbox, Error> {
    mxc_engine::exec_state_aware_json(request_json).map(Sandbox::new)
}
