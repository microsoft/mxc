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
//! use mxc::{spawn_sandbox, Config, ProcessConfig, SpawnOptions};
//!
//! // Build a typed config and spawn it.
//! let config = Config {
//!     version: Some("0.7.0-alpha".to_string()),
//!     process: Some(ProcessConfig {
//!         command_line: Some("echo hi".to_string()),
//!         ..Default::default()
//!     }),
//!     ..Default::default()
//! };
//! let mut proc = spawn_sandbox(&config, &SpawnOptions::default())?;
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
pub use platform::{platform_support, PlatformSupport};
pub use policy::{
    available_tools_policy, build_request, temporary_files_policy, user_profile_policy,
    FilesystemPolicyResult, SandboxPolicy,
};

// The typed wire config — a clean public mirror of the SDK's `ContainerConfig`
// that maps 1:1 onto the parser's internal representation, so the library
// converts straight to an `ExecutionRequest` with no JSON. Built programmatically.
pub use wxc_common::config::{
    Config, FallbackConfig, FilesystemConfig, LifecycleConfig, NetworkConfig, ProcessConfig,
    ProcessContainerConfig, ProcessContainerUiConfig, SeatbeltConfig, UiConfig,
};
// Re-export the wire/model types callers need so they don't have to depend
// on `wxc_common` directly.
pub use wxc_common::models::ExecutionRequest;
pub use wxc_common::mxc_error::{MxcError, MxcErrorCode};
pub use wxc_common::sandbox_process::SandboxProcess;

use wxc_common::config::execution_request_from_config;
use wxc_common::logger::{Logger, Mode};

/// Options controlling how a config is loaded and run.
///
/// Mirrors the knobs the executor-binary CLI exposes and the SDK's
/// `spawnSandboxFromConfig` accepts, minus anything pty-related (the library
/// never uses a pty).
#[derive(Debug, Clone, Default)]
pub struct SpawnOptions {
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

/// Spawn a sandbox from a [`Config`] and return a handle to the
/// running process for live bidirectional stdio and termination.
///
/// `config` is the typed mirror of the SDK's wire `ContainerConfig`, built
/// programmatically. The returned [`SandboxProcess`] lets the caller write to
/// (`take_stdin`), read from (`take_stdout` / `take_stderr`),
/// [`wait`](SandboxProcess::wait) on, or [`kill`](SandboxProcess::kill) the
/// child. No pty is allocated. Any stdout/stderr stream the caller does not
/// take is drained and discarded by `wait()`.
///
/// Setting `options.dry_run` is rejected with
/// [`MxcErrorCode::MalformedRequest`]: there is no process to stream.
///
/// Diagnostic output from parsing/selection is buffered and surfaced on
/// errors; it is not written to the process's stdio.
pub fn spawn_sandbox(
    config: &Config,
    options: &SpawnOptions,
) -> Result<Box<dyn SandboxProcess>, MxcError> {
    let mut logger = Logger::new(Mode::Buffer);

    // Convert the typed wire config straight to an ExecutionRequest — same
    // validation and wire→model mapping as the executor binaries, no JSON.
    let mut request = execution_request_from_config(config.clone(), &mut logger, false)
        .map_err(|e| MxcError::malformed_request(format!("failed to load config: {e}")))?;

    apply_options(&mut request, options);

    if request.script_code.is_empty() {
        return Err(MxcError::malformed_request(
            "no command to run: provide `process.commandLine` in the config or set \
             SpawnOptions::command",
        ));
    }

    spawn_runner(&request, &mut logger)
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
