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
//! - [`build_request`] / [`build_request_with_containment`] / [`SandboxPolicy`]
//!   / [`SandboxRequest`] — build a spawnable request from a policy (the Rust
//!   port of the SDK's `createConfigFromPolicy`), for the host's native
//!   containment or an explicitly selected [`Containment`] backend.
//! - [`spawn`] — spawn a streaming [`SandboxProcess`] handle for a request.
//! - [`run`] / [`resolve_runner`] (Windows) — run-to-completion backend
//!   selection and execution.
//! - [`run_state_aware`] — state-aware lifecycle backend resolution + dispatch.
//! - [`platform_support`] / [`PlatformSupport`] — host support detection.
//! - [`available_backends`] / [`AvailableBackend`] — read-only host
//!   backend-availability probe (with effective isolation tier).
//! - [`Error`] / [`ErrorCode`] — the crate-owned error facade over
//!   `wxc_common`'s internal error type.

mod dispatch;
mod error;
mod platform;
pub mod policy;
mod probe;
#[cfg(any(target_os = "windows", target_os = "linux", target_os = "macos"))]
mod run;
mod state_aware;

pub use error::{Error, ErrorCode};
#[cfg(all(target_os = "windows", feature = "isolation_session"))]
pub use platform::isolation_session_available;
pub use platform::{platform_support, PlatformSupport};
pub use policy::{
    available_tools_policy, build_request, build_request_with_containment, temporary_files_policy,
    user_profile_policy, Containment, FilesystemPolicyResult, SandboxPolicy, SandboxRequest,
    WslcSection,
};
pub use probe::{available_backends, AvailableBackend, BackendCapability};
#[cfg(any(target_os = "windows", target_os = "linux", target_os = "macos"))]
pub use run::{resolve_runner, run, ResolvedRunner};
pub use state_aware::{exec_state_aware_json, run_state_aware, run_state_aware_json};

use wxc_common::logger::{Logger, Mode};
use wxc_common::models::{ContainmentBackend, FailurePhase, ScriptResponse};
use wxc_common::sandbox_process::{SandboxProcess, StreamCloser};
use wxc_common::telemetry;

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
    let telemetry_active = request
        .inner
        .telemetry
        .as_ref()
        .map(|config| telemetry::init(config, &mut logger))
        .unwrap_or(false);
    let containment = request.inner.containment.clone();
    let started = std::time::Instant::now();
    let process = match dispatch::spawn_runner(&request.inner, &mut logger) {
        Ok(process) => process,
        Err(error) => {
            telemetry::emit_sdk_early_exit(
                telemetry_active,
                &containment,
                telemetry::FailureReason::InitError,
            );
            return Err(Error::from(error));
        }
    };
    let mut warnings = process.warnings().to_vec();
    for warning in logger.take_warnings() {
        if !warnings.contains(&warning) {
            warnings.push(warning);
        }
    }
    let process: Box<dyn SandboxProcess> = if warnings.is_empty() {
        process
    } else {
        Box::new(ProcessWithWarnings {
            inner: process,
            warnings,
        })
    };
    if telemetry_active {
        Ok(Box::new(TelemetryProcess {
            inner: process,
            active: true,
            mode: TelemetryMode::OneShot(containment),
            started,
        }))
    } else {
        Ok(process)
    }
}

/// Streaming process wrapper that owns one telemetry provider reference and
/// emits exactly one terminal event for this SDK invocation.
struct TelemetryProcess {
    inner: Box<dyn SandboxProcess>,
    active: bool,
    mode: TelemetryMode,
    started: std::time::Instant,
}

enum TelemetryMode {
    OneShot(ContainmentBackend),
    StateAware {
        backend: String,
        phase: String,
        correlation_vector: String,
    },
}

pub(crate) fn wrap_state_aware_telemetry_process(
    process: Box<dyn SandboxProcess>,
    active: bool,
    backend: String,
    phase: String,
    correlation_vector: String,
    started: std::time::Instant,
) -> Box<dyn SandboxProcess> {
    if active {
        Box::new(TelemetryProcess {
            inner: process,
            active: true,
            mode: TelemetryMode::StateAware {
                backend,
                phase,
                correlation_vector,
            },
            started,
        })
    } else {
        process
    }
}

impl TelemetryProcess {
    fn emit(&mut self, result: &std::io::Result<i32>) {
        if !self.active {
            return;
        }
        let response = match result {
            Ok(exit_code) => ScriptResponse {
                exit_code: *exit_code,
                ..Default::default()
            },
            Err(error) if error.kind() == std::io::ErrorKind::TimedOut => ScriptResponse {
                error_message: "sandbox execution timed out".to_string(),
                failure_phase: FailurePhase::Timeout,
                ..Default::default()
            },
            Err(error) => ScriptResponse {
                error_message: error.to_string(),
                failure_phase: FailurePhase::PostLaunchFailed,
                ..Default::default()
            },
        };
        match &self.mode {
            TelemetryMode::OneShot(containment) => {
                telemetry::emit_sdk_completion(true, containment, &response, self.started.elapsed())
            }
            TelemetryMode::StateAware {
                backend,
                phase,
                correlation_vector,
            } => {
                let outcome = match result {
                    Ok(exit_code) => Ok(
                        wxc_common::state_aware_dispatch::DispatchOutcome::ExecCompleted {
                            exit_code: *exit_code,
                        },
                    ),
                    Err(error) => Err(wxc_common::mxc_error::MxcError::backend_error(
                        error.to_string(),
                    )),
                };
                telemetry::emit_sdk_state_aware(
                    true,
                    telemetry::TelemetryContext {
                        backend,
                        phase,
                        correlation_vector,
                    },
                    &outcome,
                    self.started.elapsed(),
                );
            }
        }
        self.active = false;
    }
}

impl Drop for TelemetryProcess {
    fn drop(&mut self) {
        if self.active {
            telemetry::shutdown();
            self.active = false;
        }
    }
}

impl SandboxProcess for TelemetryProcess {
    fn warnings(&self) -> &[String] {
        self.inner.warnings()
    }

    fn output_metadata(&self) -> Option<&wxc_common::models::SandboxOutputMetadata> {
        self.inner.output_metadata()
    }

    fn take_stdin(&mut self) -> Option<Box<dyn std::io::Write + Send>> {
        self.inner.take_stdin()
    }

    fn take_stdout(&mut self) -> Option<Box<dyn std::io::Read + Send>> {
        self.inner.take_stdout()
    }

    fn take_stderr(&mut self) -> Option<Box<dyn std::io::Read + Send>> {
        self.inner.take_stderr()
    }

    fn try_wait(&mut self) -> std::io::Result<Option<i32>> {
        let result = self.inner.try_wait();
        if let Ok(Some(exit_code)) = result {
            self.emit(&Ok(exit_code));
        }
        result
    }

    fn id(&self) -> u32 {
        self.inner.id()
    }

    fn kill(&mut self) -> std::io::Result<()> {
        self.inner.kill()
    }

    fn wait(&mut self) -> std::io::Result<i32> {
        let result = self.inner.wait();
        self.emit(&result);
        result
    }

    fn stdout_closer(&self) -> Option<Box<dyn StreamCloser>> {
        self.inner.stdout_closer()
    }

    fn stderr_closer(&self) -> Option<Box<dyn StreamCloser>> {
        self.inner.stderr_closer()
    }
}

/// A streaming process paired with security warnings emitted during spawn.
struct ProcessWithWarnings {
    inner: Box<dyn SandboxProcess>,
    warnings: Vec<String>,
}

impl SandboxProcess for ProcessWithWarnings {
    fn warnings(&self) -> &[String] {
        &self.warnings
    }

    fn output_metadata(&self) -> Option<&wxc_common::models::SandboxOutputMetadata> {
        self.inner.output_metadata()
    }

    fn take_stdin(&mut self) -> Option<Box<dyn std::io::Write + Send>> {
        self.inner.take_stdin()
    }

    fn take_stdout(&mut self) -> Option<Box<dyn std::io::Read + Send>> {
        self.inner.take_stdout()
    }

    fn take_stderr(&mut self) -> Option<Box<dyn std::io::Read + Send>> {
        self.inner.take_stderr()
    }

    fn try_wait(&mut self) -> std::io::Result<Option<i32>> {
        self.inner.try_wait()
    }

    fn id(&self) -> u32 {
        self.inner.id()
    }

    fn kill(&mut self) -> std::io::Result<()> {
        self.inner.kill()
    }

    fn wait(&mut self) -> std::io::Result<i32> {
        self.inner.wait()
    }

    fn stdout_closer(&self) -> Option<Box<dyn StreamCloser>> {
        self.inner.stdout_closer()
    }

    fn stderr_closer(&self) -> Option<Box<dyn StreamCloser>> {
        self.inner.stderr_closer()
    }
}
