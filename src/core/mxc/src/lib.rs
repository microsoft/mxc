// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! `mxc` — an importable library for starting MXC sandboxes in-process.
//!
//! This is the Rust analogue of the SDK's `spawnSandboxFromConfig` with
//! `usePty: false`: it takes the same JSON config the executor binaries
//! consume, selects the right containment backend for the host, runs the
//! sandboxed process **without ever allocating a pty**, and returns the
//! captured stdout/stderr and exit code in a [`ScriptResponse`].
//!
//! ```no_run
//! use mxc::{spawn_sandbox_from_config, SpawnOptions};
//!
//! // `config` is the same JSON the SDK produces from a SandboxPolicy
//! // (see `sdk/src` -> ContainerConfig). It can be a raw JSON string or a
//! // base64-encoded blob (set `is_base64`).
//! let config = r#"{ "version": "0.7.0-alpha", "process": { "commandLine": "echo hi" } }"#;
//! let result = spawn_sandbox_from_config(config, &SpawnOptions::default())?;
//! println!("exit={} out={}", result.exit_code, result.standard_out);
//! # Ok::<(), mxc::MxcError>(())
//! ```
//!
//! ## Backend support
//!
//! The selected backend is driven by the `containment` field in the config
//! (or the host default). The library supports Bubblewrap (Linux), Seatbelt
//! (macOS), and ProcessContainer — AppContainer plus the BaseContainer
//! fallback — (Windows). Other backends return
//! [`MxcError::unsupported_containment`].
//!
//! ## Output capture
//!
//! The library always sets [`ExecutionRequest::capture_output`] so the
//! child's stdout/stderr are captured into the returned [`ScriptResponse`]
//! rather than streamed to the host's stdio. No pty is allocated for any
//! backend.

pub mod dispatch;
pub mod platform;
pub mod policy;

pub use dispatch::{select_runner, spawn_runner, Selection};
pub use platform::{platform_support, PlatformSupport};
pub use policy::{
    available_tools_policy, build_request, temporary_files_policy, user_profile_policy,
    Containment, FilesystemPolicyResult, SandboxPolicy,
};

// Re-export the wire/model types callers need so they don't have to depend
// on `wxc_common` directly.
pub use wxc_common::models::{ContainmentBackend, ExecutionRequest, FailurePhase, ScriptResponse};
pub use wxc_common::mxc_error::{MxcError, MxcErrorCode};
pub use wxc_common::sandbox_process::SandboxProcess;

use wxc_common::config_parser::load_request;
use wxc_common::logger::{Logger, Mode};

/// Options controlling how a config is loaded and run.
///
/// Mirrors the knobs the executor-binary CLI exposes and the SDK's
/// `spawnSandboxFromConfig` accepts, minus anything pty-related (the library
/// never uses a pty).
#[derive(Debug, Clone, Default)]
pub struct SpawnOptions {
    /// Treat the `config` argument as a base64-encoded JSON blob (matching
    /// the binaries' `--config-base64` mode and the SDK wire format). When
    /// `false` (the default), `config` is parsed as a raw JSON string.
    pub is_base64: bool,

    /// Enable experimental features (equivalent to the `--experimental`
    /// flag). Required for the Windows BaseContainer fallback and for any
    /// experimental policy fields.
    pub experimental: bool,

    /// Validate the config and runner setup, then return success without
    /// executing the sandboxed process (equivalent to `--dry-run`).
    pub dry_run: bool,

    /// Override the working directory the sandboxed process runs in. When
    /// `None`, the directory from the config (if any) is used.
    pub working_directory: Option<String>,

    /// Override the command line to execute, replacing `process.commandLine`
    /// from the config. When `None`, the config's command line is used.
    pub command: Option<String>,

    /// Additional environment variables to expose to the sandboxed process,
    /// as `(key, value)` pairs. These are merged into the config's
    /// `process.env` (a matching key already present is replaced), mirroring
    /// the SDK's `injectEnvIntoConfig` behaviour on the `usePty: false` path.
    pub env: Vec<(String, String)>,
}

/// Run a sandbox from a JSON config, capturing its output.
///
/// `config` is the same JSON the SDK serialises from a `SandboxPolicy`
/// (a `ContainerConfig`); pass `options.is_base64 = true` to supply it
/// base64-encoded. The function:
///
/// 1. Parses and validates the config (reusing the executor parser),
/// 2. Applies the [`SpawnOptions`] overrides,
/// 3. Forces output capture and selects the host backend, and
/// 4. Runs the sandboxed process and returns its [`ScriptResponse`].
///
/// Diagnostic output from parsing/selection is buffered and surfaced on
/// errors; it is not written to the process's stdio.
pub fn spawn_sandbox_from_config(
    config: &str,
    options: &SpawnOptions,
) -> Result<ScriptResponse, MxcError> {
    let (request, mut logger) = load_and_prepare(config, options)?;
    run_request(request, &mut logger)
}

/// Spawn a sandbox from a JSON config and return a handle to the running
/// process for live bidirectional stdio and termination.
///
/// The streaming counterpart to [`spawn_sandbox_from_config`]: instead of
/// running to completion, it returns a [`SandboxProcess`] the caller can
/// write to (`take_stdin`), read from (`take_stdout` / `take_stderr`),
/// [`wait`](SandboxProcess::wait) on, or [`kill`](SandboxProcess::kill). No
/// pty is allocated. Any stdout/stderr stream the caller does not take is
/// captured by `wait()`.
///
/// `config` and `options` are interpreted exactly as in
/// [`spawn_sandbox_from_config`] (the `command`, `working_directory`, and
/// `env` overrides apply; `dry_run` is ignored — there is nothing to run).
pub fn spawn_sandbox(
    config: &str,
    options: &SpawnOptions,
) -> Result<Box<dyn SandboxProcess>, MxcError> {
    let (request, mut logger) = load_and_prepare(config, options)?;
    spawn_runner(&request, &mut logger)
}

/// Parse a config string and apply [`SpawnOptions`], returning the prepared
/// request and the diagnostic logger. Shared by the run-to-completion and
/// streaming entrypoints.
fn load_and_prepare(
    config: &str,
    options: &SpawnOptions,
) -> Result<(ExecutionRequest, Logger), MxcError> {
    let mut logger = Logger::new(Mode::Buffer);

    // `load_request` interprets a non-base64 string as a *file path*; only
    // base64 input is parsed as inline JSON. To accept a raw JSON config
    // string (the natural analogue of the SDK's ContainerConfig object) we
    // base64-encode it ourselves and always parse inline. Callers who already
    // hold a base64 blob set `is_base64` and we pass it straight through.
    let encoded;
    let input: &str = if options.is_base64 {
        config
    } else {
        encoded = wxc_common::encoding::base64_encode(config.as_bytes());
        &encoded
    };

    let mut request = load_request(input, &mut logger, true).map_err(|e| {
        MxcError::malformed_request(format!(
            "failed to load config: {e}\n{}",
            logger.get_buffer()
        ))
    })?;

    apply_options(&mut request, options);

    if request.script_code.is_empty() {
        return Err(MxcError::malformed_request(
            "no command to run: provide `process.commandLine` in the config or set \
             SpawnOptions::command",
        ));
    }

    Ok((request, logger))
}

/// Run a fully-built [`ExecutionRequest`], capturing its output.
///
/// Lower-level entrypoint for callers that already hold an
/// [`ExecutionRequest`] (e.g. built by hand or obtained from
/// [`wxc_common::config_parser`]). [`spawn_sandbox_from_config`] is the usual
/// way in. `capture_output` is forced on regardless of the request's value.
pub fn spawn_sandbox_from_request(
    mut request: ExecutionRequest,
) -> Result<ScriptResponse, MxcError> {
    let mut logger = Logger::new(Mode::Buffer);
    request.capture_output = true;
    run_request(request, &mut logger)
}

/// Spawn a streaming handle for a fully-built [`ExecutionRequest`].
///
/// The streaming counterpart to [`spawn_sandbox_from_request`]: returns a
/// [`SandboxProcess`] for live stdio and termination. Usually the request
/// comes from [`build_request`] with `script_code` (and working directory /
/// env) filled in by the caller.
pub fn spawn_streaming_from_request(
    mut request: ExecutionRequest,
) -> Result<Box<dyn SandboxProcess>, MxcError> {
    let mut logger = Logger::new(Mode::Buffer);
    request.capture_output = true;
    spawn_runner(&request, &mut logger)
}

fn apply_options(request: &mut ExecutionRequest, options: &SpawnOptions) {
    request.experimental_enabled = options.experimental;
    request.dry_run = options.dry_run;

    if let Some(ref wd) = options.working_directory {
        request.working_directory = wd.clone();
    }

    if let Some(ref cmd) = options.command {
        request.script_code = cmd.clone();
    }

    for (key, value) in &options.env {
        let prefix = format!("{key}=");
        request.env.retain(|kv| !kv.starts_with(&prefix));
        request.env.push(format!("{key}={value}"));
    }
}

fn run_request(
    mut request: ExecutionRequest,
    logger: &mut Logger,
) -> Result<ScriptResponse, MxcError> {
    // Never stream to host stdio / allocate a pty: capture into the response.
    request.capture_output = true;

    // Keep the whole `Selection` alive across the run: on Windows it owns the
    // DACL guard whose `Drop` restores host ACEs, and that restore must happen
    // *after* the child is reaped — not when selection is unpacked.
    let mut selection = select_runner(&request, logger)?;

    for w in &selection.warnings {
        logger.log_line(w);
    }

    let response = selection.runner.run(&request, logger);

    // Drop the selection (runner first, then the DACL guard) now that the
    // child has exited, so ACE restore runs promptly.
    drop(selection);

    Ok(response)
}
