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

mod dispatch;
mod error;
mod platform;
pub mod policy;
mod sandbox;

use dispatch::spawn_runner;
pub use platform::{platform_support, PlatformSupport};
pub use policy::{
    available_tools_policy, build_request, temporary_files_policy, user_profile_policy,
    FilesystemPolicyResult, SandboxPolicy, SandboxRequest,
};

pub use error::{Error, ErrorCode};
pub use sandbox::{Sandbox, StreamCloser, WaitOutcome};

use wxc_common::logger::{Logger, Mode};

/// Spawn a sandbox from a [`SandboxRequest`] built by [`build_request`] (with
/// the command, and any working directory / env, filled in).
///
/// Returns a [`Sandbox`] handle for live bidirectional stdio and termination;
/// no pty is allocated. Any stdout/stderr stream the caller does not `take_*` is
/// drained and discarded by [`wait`](Sandbox::wait).
pub fn spawn_sandbox(request: SandboxRequest) -> Result<Sandbox, Error> {
    let mut logger = Logger::new(Mode::Buffer);
    spawn_runner(&request.inner, &mut logger)
        .map(Sandbox::new)
        .map_err(Error::from)
}
