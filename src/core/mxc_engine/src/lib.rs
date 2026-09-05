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

#[cfg(feature = "ffi-internals")]
#[doc(hidden)]
pub mod binding;
pub mod configs;
mod dispatch;
mod error;
#[cfg(target_os = "windows")]
mod guarded_capture;
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
    user_profile_policy, Containment, FilesystemPolicyResult, NetworkAction, NetworkEgressSection,
    NetworkIngressSection, NetworkPeerSection, NetworkPortSection, NetworkProtocol,
    NetworkRuleSection, RuntimeConfigSection, SandboxPolicy, SandboxRequest, WslcSection,
};
pub use probe::{available_backends, AvailableBackend, BackendCapability};
#[cfg(target_os = "windows")]
pub use run::resolve_runner_for_audit;
#[cfg(any(target_os = "windows", target_os = "linux", target_os = "macos"))]
pub use run::{log_policy_hash, resolve_runner, run, ResolvedRunner};
pub use state_aware::{
    exec_state_aware_attached, exec_state_aware_json, run_state_aware, run_state_aware_json,
};

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
///
/// # Safety / lifetime contract for library-context callers
///
/// When this crate is compiled into a dynamically-loadable library (the
/// `mxc_ffi` cdylib, or a host that dlopens `mxc-sdk`), the ETW telemetry
/// provider is registered while an invocation is live. The provider retains
/// callbacks into this module's code, so **the library must remain loaded
/// until every spawned handle produced by this function has been dropped**
/// (which releases the corresponding provider reference through
/// [`telemetry::shutdown`] via the [`TelemetryProcess`] `Drop` impl below).
/// Callers that dlclose / `FreeLibrary` while a spawned handle is still live
/// would leave ETW with dangling callbacks into unmapped memory.
///
/// The registration is reference-counted per `telemetry::init` call and
/// released once when the returned handle is dropped, so multiple concurrent
/// spawns from the same load are safe as long as the library outlives them.
pub fn spawn(request: &SandboxRequest) -> Result<Box<dyn SandboxProcess>, Error> {
    let mut logger = Logger::new(Mode::Buffer);
    let telemetry_active = request
        .inner
        .telemetry
        .as_ref()
        .map(|config| telemetry::init(config, &mut logger))
        .unwrap_or(false);
    let mut telemetry_registration = TelemetryRegistration::new(telemetry_active);
    let requested_sandbox_kind = request
        .inner
        .telemetry
        .as_ref()
        .and_then(|config| config.requested_sandbox_kind);
    let containment = request.inner.containment.clone();
    let started = std::time::Instant::now();
    let process = match dispatch::spawn_runner(&request.inner, &mut logger) {
        Ok(process) => process,
        Err(error) => {
            // Preserve the actual error category so bounded telemetry
            // categorises malformed requests, unsupported containment, and
            // policy validation failures under their real reason — not the
            // catch-all `InitError`. Shares the exhaustive `MxcErrorCode` →
            // `FailureReason` mapping with the state-aware path.
            telemetry::emit_sdk_early_exit_with_kind(
                telemetry_registration.transfer(),
                &containment,
                requested_sandbox_kind,
                telemetry::classify_mxc_error(&error),
            );
            return Err(Error::from(error));
        }
    };
    let extra_warnings = logger.take_warnings();
    let process: Box<dyn SandboxProcess> = ProcessWithWarnings::wrap(process, extra_warnings);
    if telemetry_registration.active() {
        Ok(Box::new(TelemetryProcess {
            inner: process,
            active: telemetry_registration.transfer(),
            mode: TelemetryMode::OneShot {
                containment,
                requested_sandbox_kind,
            },
            started,
        }))
    } else {
        Ok(process)
    }
}

pub(crate) struct TelemetryRegistration {
    active: bool,
}

impl TelemetryRegistration {
    pub(crate) fn new(active: bool) -> Self {
        Self { active }
    }

    pub(crate) fn active(&self) -> bool {
        self.active
    }

    pub(crate) fn transfer(&mut self) -> bool {
        std::mem::take(&mut self.active)
    }
}

impl Drop for TelemetryRegistration {
    fn drop(&mut self) {
        if self.active {
            telemetry::shutdown();
        }
    }
}

/// Streaming process wrapper that owns one telemetry provider reference and
/// emits exactly one terminal event for this SDK invocation.
///
/// # Terminal-event invariant
///
/// Every non-nop path a caller can drive this wrapper through emits exactly
/// one terminal telemetry event before the provider reference is released:
///
/// * [`SandboxProcess::wait`] — real completion / timeout / spawn error.
/// * [`SandboxProcess::try_wait`] — emits when a poll observes an exit or a
///   terminal timeout. A pending or otherwise failed poll leaves the invariant
///   to a later successful `try_wait`, `wait`, `kill`, or `Drop`.
/// * [`SandboxProcess::kill`] — cancellation event after the wrapped process
///   confirms the kill succeeded. A failed kill leaves the slot active for a
///   later `wait` / successful `try_wait`.
/// * [`Drop`] — polls once for a completed child and emits its real exit code;
///   only a still-running or unpollable child is reported as abandoned.
///
/// `active` doubles as the exactly-once flag: it starts `true`, and every
/// terminal path calls [`TelemetryProcess::emit`] which flips it to `false`
/// after the event and after [`telemetry::shutdown`] releases the provider
/// reference.
struct TelemetryProcess {
    inner: Box<dyn SandboxProcess>,
    active: bool,
    mode: TelemetryMode,
    started: std::time::Instant,
}

enum TelemetryMode {
    OneShot {
        containment: ContainmentBackend,
        requested_sandbox_kind: Option<&'static str>,
    },
    StateAware {
        backend: String,
        phase: String,
        correlation_vector: String,
        requested_sandbox_kind: Option<&'static str>,
    },
}

pub(crate) fn wrap_state_aware_telemetry_process_with_kind(
    process: Box<dyn SandboxProcess>,
    active: bool,
    backend: String,
    phase: String,
    correlation_vector: String,
    requested_sandbox_kind: Option<&'static str>,
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
                requested_sandbox_kind,
            },
            started,
        })
    } else {
        process
    }
}

impl TelemetryProcess {
    /// Emit the single terminal event for this invocation and release the
    /// provider reference. Idempotent — subsequent calls (from another exit
    /// path or `Drop`) are silent no-ops.
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
            TelemetryMode::OneShot {
                containment,
                requested_sandbox_kind,
            } => telemetry::emit_sdk_completion_with_kind(
                true,
                containment,
                *requested_sandbox_kind,
                &response,
                self.started.elapsed(),
            ),
            TelemetryMode::StateAware {
                backend,
                phase,
                correlation_vector,
                requested_sandbox_kind,
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
                let failure_reason = Self::state_aware_wait_failure_reason(result);
                telemetry::emit_sdk_state_aware_with_kind_and_failure(
                    true,
                    *requested_sandbox_kind,
                    telemetry::TelemetryContext {
                        backend,
                        phase,
                        correlation_vector,
                    },
                    &outcome,
                    self.started.elapsed(),
                    failure_reason,
                );
            }
        }
        self.active = false;
    }

    fn state_aware_wait_failure_reason(
        result: &std::io::Result<i32>,
    ) -> Option<telemetry::FailureReason> {
        result
            .as_ref()
            .err()
            .filter(|error| error.kind() == std::io::ErrorKind::TimedOut)
            .map(|_| telemetry::FailureReason::Timeout)
    }

    /// Emit a synthesised terminal event when no real completion result is
    /// available (drop-without-wait). Routes through
    /// [`Self::emit`] so it shares the exactly-once slot and the
    /// provider-release path with the natural exit paths.
    fn emit_synthetic(&mut self, kind: SyntheticTerminal) {
        if !self.active {
            return;
        }
        let (raw_kind, message) = match kind {
            SyntheticTerminal::Dropped => (
                std::io::ErrorKind::Other,
                "sandbox handle was dropped before completion",
            ),
        };
        // The Err path in `emit` classifies non-timeout errors as
        // PostLaunchFailed → FailureReason::InitError (one-shot) or
        // BackendError → FailureReason::ProcessError (state-aware).
        self.emit(&Err(std::io::Error::new(raw_kind, message)));
    }

    /// Emit the terminal event for a confirmed explicit kill.
    fn emit_cancellation(&mut self) {
        if !self.active {
            return;
        }
        match &self.mode {
            TelemetryMode::OneShot {
                containment,
                requested_sandbox_kind,
            } => telemetry::emit_sdk_cancellation_with_kind(
                true,
                *requested_sandbox_kind,
                telemetry::TelemetryContext {
                    backend: containment.wire_name(),
                    phase: "",
                    correlation_vector: "",
                },
                self.started.elapsed(),
            ),
            TelemetryMode::StateAware {
                backend,
                phase,
                correlation_vector,
                requested_sandbox_kind,
            } => telemetry::emit_sdk_cancellation_with_kind(
                true,
                *requested_sandbox_kind,
                telemetry::TelemetryContext {
                    backend,
                    phase,
                    correlation_vector,
                },
                self.started.elapsed(),
            ),
        }
        self.active = false;
    }
}

/// Synthetic terminal callsites for which no real completion result is
/// available, so [`TelemetryProcess::emit_synthetic`]
/// can attribute the event to the exit path that produced it.
#[derive(Debug, Clone, Copy)]
enum SyntheticTerminal {
    /// The wrapper was dropped without a preceding `wait` / successful `try_wait`.
    Dropped,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DropDisposition {
    Exited(i32),
    TimedOut,
    Abandoned,
}

fn observe_before_drop(process: &mut dyn SandboxProcess) -> DropDisposition {
    match process.try_wait() {
        Ok(Some(exit_code)) => DropDisposition::Exited(exit_code),
        Err(error) if error.kind() == std::io::ErrorKind::TimedOut => DropDisposition::TimedOut,
        Ok(None) | Err(_) => DropDisposition::Abandoned,
    }
}

impl Drop for TelemetryProcess {
    fn drop(&mut self) {
        // If `wait` / `try_wait(Ok(Some))` / `kill` already emitted the
        // terminal event, `active` is false and this is a no-op. Otherwise,
        // preserve a completion that raced with Drop instead of misreporting a
        // successful fire-and-forget run as abandonment.
        if !self.active {
            return;
        }
        match observe_before_drop(self.inner.as_mut()) {
            DropDisposition::Exited(exit_code) => self.emit(&Ok(exit_code)),
            DropDisposition::TimedOut => self.emit(&Err(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "sandbox execution timed out",
            ))),
            DropDisposition::Abandoned => self.emit_synthetic(SyntheticTerminal::Dropped),
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
        match &result {
            // Exit observed: emit the terminal event now.
            Ok(Some(exit_code)) => self.emit(&Ok(*exit_code)),
            // Still running: leave the invariant to a later `wait` / `kill` / `Drop`.
            Ok(None) => {}
            // Backends use TimedOut only for a settled terminal timeout.
            Err(error) if error.kind() == std::io::ErrorKind::TimedOut => {
                self.emit(&Err(std::io::Error::new(error.kind(), error.to_string())));
            }
            // A poll error does not prove termination. Preserve the slot and
            // provider so a later wait, successful poll, kill, or Drop can
            // report the actual terminal outcome.
            Err(_) => {}
        }
        result
    }

    fn id(&self) -> u32 {
        self.inner.id()
    }

    fn kill(&mut self) -> std::io::Result<()> {
        // A failed kill does not prove termination, so retain the exactly-once
        // slot for a later wait/try_wait that can report the real outcome.
        let result = self.inner.kill();
        if result.is_ok() {
            self.emit_cancellation();
        }
        result
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

/// A streaming process paired with warnings emitted during spawn.
pub(crate) struct ProcessWithWarnings {
    inner: Box<dyn SandboxProcess>,
    warnings: Vec<String>,
}

impl ProcessWithWarnings {
    /// Wrap `inner` so its `warnings()` reports the union of its own warnings
    /// and `extra_warnings` (duplicates deduplicated). Returns `inner`
    /// unchanged if the merged list is empty.
    pub(crate) fn wrap(
        inner: Box<dyn SandboxProcess>,
        extra_warnings: Vec<String>,
    ) -> Box<dyn SandboxProcess> {
        let mut warnings = inner.warnings().to_vec();
        for warning in extra_warnings {
            if !warnings.contains(&warning) {
                warnings.push(warning);
            }
        }
        if warnings.is_empty() {
            inner
        } else {
            Box::new(ProcessWithWarnings { inner, warnings })
        }
    }
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

#[cfg(test)]
mod telemetry_process_tests {
    use super::*;

    enum TryWaitResult {
        Running,
        Exited(i32),
        TimedOut,
        Failed,
    }

    struct StubProcess {
        try_wait_result: TryWaitResult,
        wait_result: std::io::Result<i32>,
        kill_fails: bool,
    }

    impl SandboxProcess for StubProcess {
        fn take_stdin(&mut self) -> Option<Box<dyn std::io::Write + Send>> {
            None
        }

        fn take_stdout(&mut self) -> Option<Box<dyn std::io::Read + Send>> {
            None
        }

        fn take_stderr(&mut self) -> Option<Box<dyn std::io::Read + Send>> {
            None
        }

        fn try_wait(&mut self) -> std::io::Result<Option<i32>> {
            match self.try_wait_result {
                TryWaitResult::Running => Ok(None),
                TryWaitResult::Exited(code) => Ok(Some(code)),
                TryWaitResult::TimedOut => Err(std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    "timed out",
                )),
                TryWaitResult::Failed => Err(std::io::Error::other("poll failed")),
            }
        }

        fn id(&self) -> u32 {
            1
        }

        fn kill(&mut self) -> std::io::Result<()> {
            if self.kill_fails {
                Err(std::io::Error::other("kill failed"))
            } else {
                Ok(())
            }
        }

        fn wait(&mut self) -> std::io::Result<i32> {
            self.wait_result
                .as_ref()
                .copied()
                .map_err(|error| std::io::Error::new(error.kind(), error.to_string()))
        }
    }

    fn wrapped(try_wait_result: TryWaitResult) -> TelemetryProcess {
        wrapped_with_kill_failure(try_wait_result, false)
    }

    fn wrapped_with_kill_failure(
        try_wait_result: TryWaitResult,
        kill_fails: bool,
    ) -> TelemetryProcess {
        TelemetryProcess {
            inner: Box::new(StubProcess {
                try_wait_result,
                wait_result: Ok(0),
                kill_fails,
            }),
            active: true,
            mode: TelemetryMode::StateAware {
                backend: "test".to_string(),
                phase: "exec".to_string(),
                correlation_vector: String::new(),
                requested_sandbox_kind: None,
            },
            started: std::time::Instant::now(),
        }
    }

    #[test]
    fn terminal_paths_consume_the_exactly_once_slot() {
        let mut waited = wrapped(TryWaitResult::Running);
        assert_eq!(waited.wait().unwrap(), 0);
        assert!(!waited.active);
        waited.kill().unwrap();
        assert!(!waited.active);

        let mut killed = wrapped(TryWaitResult::Running);
        killed.kill().unwrap();
        assert!(!killed.active);
        assert_eq!(killed.wait().unwrap(), 0);
        assert!(!killed.active);

        let mut exited = wrapped(TryWaitResult::Exited(7));
        assert_eq!(exited.try_wait().unwrap(), Some(7));
        assert!(!exited.active);

        let mut poll_failed = wrapped(TryWaitResult::Failed);
        assert!(poll_failed.try_wait().is_err());
        assert!(poll_failed.active);
        assert_eq!(poll_failed.wait().unwrap(), 0);
        assert!(!poll_failed.active);

        let mut timed_out = wrapped(TryWaitResult::TimedOut);
        assert_eq!(
            timed_out.try_wait().unwrap_err().kind(),
            std::io::ErrorKind::TimedOut
        );
        assert!(!timed_out.active);
    }

    #[test]
    fn state_aware_wait_timeout_preserves_timeout_failure_reason() {
        let timed_out = Err(std::io::Error::new(
            std::io::ErrorKind::TimedOut,
            "timed out",
        ));
        assert_eq!(
            TelemetryProcess::state_aware_wait_failure_reason(&timed_out),
            Some(telemetry::FailureReason::Timeout)
        );

        let failed = Err(std::io::Error::other("failed"));
        assert_eq!(
            TelemetryProcess::state_aware_wait_failure_reason(&failed),
            None
        );
    }

    #[test]
    fn nonterminal_poll_leaves_the_exactly_once_slot_active() {
        let mut process = wrapped(TryWaitResult::Running);
        assert_eq!(process.try_wait().unwrap(), None);
        assert!(process.active);
        process.emit_synthetic(SyntheticTerminal::Dropped);
        assert!(!process.active);
    }

    #[test]
    fn drop_observation_preserves_completed_exit_code() {
        let mut exited = StubProcess {
            try_wait_result: TryWaitResult::Exited(7),
            wait_result: Ok(0),
            kill_fails: false,
        };
        assert_eq!(observe_before_drop(&mut exited), DropDisposition::Exited(7));

        let mut running = StubProcess {
            try_wait_result: TryWaitResult::Running,
            wait_result: Ok(0),
            kill_fails: false,
        };
        assert_eq!(
            observe_before_drop(&mut running),
            DropDisposition::Abandoned
        );

        let mut failed = StubProcess {
            try_wait_result: TryWaitResult::Failed,
            wait_result: Ok(0),
            kill_fails: false,
        };
        assert_eq!(observe_before_drop(&mut failed), DropDisposition::Abandoned);

        let mut timed_out = StubProcess {
            try_wait_result: TryWaitResult::TimedOut,
            wait_result: Ok(0),
            kill_fails: false,
        };
        assert_eq!(
            observe_before_drop(&mut timed_out),
            DropDisposition::TimedOut
        );
    }

    #[test]
    fn failed_kill_leaves_the_exactly_once_slot_active() {
        let mut process = wrapped_with_kill_failure(TryWaitResult::Running, true);

        assert!(process.kill().is_err());
        assert!(process.active);
        assert_eq!(process.wait().unwrap(), 0);
        assert!(!process.active);
    }
}
