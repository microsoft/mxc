// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! `mxc-sdk` — an importable library for starting MXC sandboxes in-process.
//!
//! Build a [`SandboxRequest`] from a [`SandboxPolicy`] with [`build_request`],
//! then hand it to [`spawn_sandbox`]:
//! it selects the right containment backend for the host and spawns the
//! sandboxed process **without ever allocating a pty**, returning a
//! [`Sandbox`] handle for live bidirectional stdio and termination.
//!
//! ```no_run
//! use mxc_sdk::{build_request, spawn_sandbox, SandboxPolicy, WaitOutcome};
//!
//! // Turn a policy into a request, fill in the command, and spawn it.
//! let policy = SandboxPolicy {
//!     version: "0.7.0-alpha".to_string(),
//!     filesystem: None,
//!     network: None,
//!     ui: None,
//!     timeout_ms: None,
//! };
//! let mut request = build_request(&policy, None)?;
//! request.set_script("echo hi");
//! let mut proc = spawn_sandbox(request)?;
//! match proc.wait()? {
//!     WaitOutcome::Exited(code) => println!("exit={code}"),
//!     WaitOutcome::TimedOut => println!("timed out"),
//! }
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```
//!
//! ## Backend support
//!
//! The selected backend is driven by the `containment` field in the request
//! (or the host default). The library supports Bubblewrap (Linux), Seatbelt
//! (macOS), and ProcessContainer — AppContainer and BaseContainer —
//! (Windows). Other backends return an [`Error`] with
//! [`ErrorCode::UnsupportedContainment`].
//!
//! ## No pty
//!
//! The child's stdio is always wired to ordinary pipes — the library never
//! allocates a pty. Stream the handle's `take_stdout`/`take_stderr`, or let
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
