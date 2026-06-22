// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! `mxc-sdk` — an importable library for starting MXC sandboxes in-process.
//!
//! Build an [`ExecutionRequest`] from a [`SandboxPolicy`] with [`build_request`]
//! (or construct one directly), then hand it to [`spawn_sandbox`]:
//! it selects the right containment backend for the host and spawns the
//! sandboxed process **without ever allocating a pty**, returning a
//! [`SandboxProcess`] handle for live bidirectional stdio and termination.
//!
//! ```no_run
//! use mxc_sdk::{build_request, spawn_sandbox, SandboxPolicy};
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
//! request.script_code = "echo hi".to_string();
//! let mut proc = spawn_sandbox(request)?;
//! let exit_code = proc.wait()?;
//! println!("exit={exit_code}");
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```
//!
//! ## Backend support
//!
//! The selected backend is driven by the `containment` field in the request
//! (or the host default). The library supports Bubblewrap (Linux), Seatbelt
//! (macOS), and ProcessContainer — AppContainer plus the BaseContainer
//! fallback — (Windows). Other backends return
//! [`MxcError::unsupported_containment`].
//!
//! ## No pty
//!
//! The child's stdio is always wired to ordinary pipes — the library never
//! allocates a pty. Stream the handle's `take_stdout`/`take_stderr`, or let
//! [`wait`](SandboxProcess::wait) drain and discard any untaken stream.

mod dispatch;
mod platform;
pub mod policy;

use dispatch::spawn_runner;
pub use platform::{platform_support, PlatformSupport};
pub use policy::{
    available_tools_policy, build_request, temporary_files_policy, user_profile_policy,
    FilesystemPolicyResult, SandboxPolicy,
};

// Re-export the wire/model types callers need so they don't have to depend
// on `wxc_common` directly.
pub use wxc_common::models::ExecutionRequest;
pub use wxc_common::mxc_error::{MxcError, MxcErrorCode};
pub use wxc_common::sandbox_process::{SandboxProcess, StreamCloser};

use wxc_common::logger::{Logger, Mode};

/// Spawn a sandbox from a fully-built [`ExecutionRequest`].
///
/// Typically the request comes from [`build_request`] (with `script_code`, and
/// any working directory / env, filled in), but callers may also construct one
/// directly. Returns a [`SandboxProcess`] for live bidirectional stdio and
/// termination; no pty is allocated. Any stdout/stderr stream the caller does
/// not `take_*` is drained and discarded by [`wait`](SandboxProcess::wait).
///
/// A request with `dry_run` set is rejected with
/// [`MxcErrorCode::MalformedRequest`]: there is no process to stream.
pub fn spawn_sandbox(request: ExecutionRequest) -> Result<Box<dyn SandboxProcess>, MxcError> {
    let mut logger = Logger::new(Mode::Buffer);
    spawn_runner(&request, &mut logger)
}
