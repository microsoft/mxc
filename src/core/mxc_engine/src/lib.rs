// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! `mxc_engine` — the MXC execution engine.
//!
//! This crate owns the logic that turns an execution request into a running
//! sandbox: backend dispatch, host-platform probing, and config building from
//! a [`SandboxPolicy`]. It is the single implementation that both the public
//! Rust SDK (`mxc-sdk`) and — over subsequent increments — the executor
//! binaries call into, so backend selection lives in exactly one place.
//!
//! It depends on the `backends/*` crates (cfg-split by target), which is why
//! it cannot live in `wxc_common` (the cross-platform foundation those backends
//! build on).
//!
//! ## Surface
//!
//! - [`build_request`] / [`SandboxPolicy`] / [`SandboxRequest`] — build a
//!   spawnable request from a policy (the Rust port of the SDK's
//!   `createConfigFromPolicy`).
//! - [`spawn`] — spawn a streaming [`SandboxProcess`] handle for a request.
//! - [`run`] / [`resolve_runner`] (Windows) — run-to-completion backend
//!   selection and execution.
//! - [`run_state_aware`] — state-aware lifecycle backend resolution + dispatch.
//! - [`platform_support`] / [`PlatformSupport`] — host support detection.
//! - [`Error`] / [`ErrorCode`] — the crate-owned error facade over
//!   `wxc_common`'s internal error type.

mod dispatch;
mod error;
mod platform;
pub mod policy;
#[cfg(any(target_os = "windows", target_os = "linux", target_os = "macos"))]
mod run;
mod state_aware;

pub use error::{Error, ErrorCode};
pub use platform::{platform_support, PlatformSupport};
pub use policy::{
    available_tools_policy, build_request, temporary_files_policy, user_profile_policy,
    FilesystemPolicyResult, SandboxPolicy, SandboxRequest,
};
#[cfg(any(target_os = "windows", target_os = "linux", target_os = "macos"))]
pub use run::{resolve_runner, run, ResolvedRunner};
pub use state_aware::{exec_state_aware_json, run_state_aware, run_state_aware_json};

use wxc_common::logger::{Logger, Mode};
use wxc_common::sandbox_process::SandboxProcess;

/// Spawn a streaming [`SandboxProcess`] handle for a [`SandboxRequest`] built
/// by [`build_request`] (with the command, and any working directory / env,
/// filled in).
///
/// Selects the containment backend for the host, spawns the sandboxed process
/// with piped stdio, and returns the handle. No pty is allocated. Backends
/// without a streaming implementation return an [`Error`] with
/// [`ErrorCode::UnsupportedContainment`].
pub fn spawn(request: &SandboxRequest) -> Result<Box<dyn SandboxProcess>, Error> {
    let mut logger = Logger::new(Mode::Buffer);
    dispatch::spawn_runner(&request.inner, &mut logger).map_err(Error::from)
}
