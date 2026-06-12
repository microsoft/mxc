// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! `mxc` — an importable library for starting MXC sandboxes in-process.
//!
//! It takes the same JSON config the executor binaries consume, selects the
//! right containment backend for the host, and spawns the sandboxed process
//! **without ever allocating a pty**, returning a [`SandboxProcess`] handle for
//! live bidirectional stdio and termination.
//!
//! ```no_run
//! use mxc::{spawn_sandbox, SpawnOptions};
//!
//! // `config` is the same JSON the SDK produces from a SandboxPolicy
//! // (see `sdk/src` -> ContainerConfig). It can be a raw JSON string or a
//! // base64-encoded blob (set `is_base64`).
//! let config = r#"{ "version": "0.7.0-alpha", "process": { "commandLine": "echo hi" } }"#;
//! let mut proc = spawn_sandbox(config, &SpawnOptions::default())?;
//! let exit_code = proc.wait().expect("wait for the sandboxed child");
//! println!("exit={exit_code}");
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
//! ## No pty
//!
//! The child's stdio is always wired to ordinary pipes — the library never
//! allocates a pty. Stream the handle's `take_stdout`/`take_stderr`, or let
//! [`wait`](SandboxProcess::wait) drain and discard any untaken stream.

mod dispatch;
mod platform;
pub mod policy;

use dispatch::spawn_runner;
pub use dispatch::{select_runner, Selection};
pub use platform::{platform_support, PlatformSupport};
pub use policy::{
    available_tools_policy, build_request, temporary_files_policy, user_profile_policy,
    Containment, FilesystemPolicyResult, SandboxPolicy,
};

// Re-export the wire/model types callers need so they don't have to depend
// on `wxc_common` directly.
pub use wxc_common::models::ExecutionRequest;
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
    /// as `(key, value)` pairs. Each is merged into the config's `process.env`,
    /// **replacing** any existing entry with the same key (note: this differs
    /// from the SDK's `injectEnvIntoConfig`, which appends, leaving the native
    /// parser to resolve duplicate `KEY=` entries).
    pub env: Vec<(String, String)>,
}

/// Spawn a sandbox from a JSON config and return a handle to the running
/// process for live bidirectional stdio and termination.
///
/// `config` is the same JSON the SDK serialises from a `SandboxPolicy`
/// (a `ContainerConfig`); pass `options.is_base64 = true` to supply it
/// base64-encoded. The returned [`SandboxProcess`] lets the caller write to
/// (`take_stdin`), read from (`take_stdout` / `take_stderr`),
/// [`wait`](SandboxProcess::wait) on, or [`kill`](SandboxProcess::kill) the
/// child. No pty is allocated. Any stdout/stderr stream the caller does not
/// take is captured by `wait()`.
///
/// Setting `options.dry_run` is rejected with
/// [`MxcErrorCode::MalformedRequest`]: there is no process to stream.
///
/// Diagnostic output from parsing/selection is buffered and surfaced on
/// errors; it is not written to the process's stdio.
pub fn spawn_sandbox(
    config: &str,
    options: &SpawnOptions,
) -> Result<Box<dyn SandboxProcess>, MxcError> {
    let (request, mut logger) = load_and_prepare(config, options)?;
    spawn_runner(&request, &mut logger)
}

/// Parse a config string and apply [`SpawnOptions`], returning the prepared
/// request and the diagnostic logger.
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

    let mut request = load_request(input, &mut logger, true)
        .map_err(|e| MxcError::malformed_request(format!("failed to load config: {e}")))?;

    apply_options(&mut request, options);

    if request.script_code.is_empty() {
        return Err(MxcError::malformed_request(
            "no command to run: provide `process.commandLine` in the config or set \
             SpawnOptions::command",
        ));
    }

    Ok((request, logger))
}

/// Spawn a streaming handle for a fully-built [`ExecutionRequest`].
///
/// Lower-level counterpart to [`spawn_sandbox`] for callers that already hold
/// an [`ExecutionRequest`] — usually from [`build_request`] with `script_code`
/// (and working directory / env) filled in. Returns a [`SandboxProcess`] for
/// live stdio and termination; no pty is allocated.
pub fn spawn_streaming_from_request(
    request: ExecutionRequest,
) -> Result<Box<dyn SandboxProcess>, MxcError> {
    let mut logger = Logger::new(Mode::Buffer);
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
