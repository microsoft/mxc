// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! The SDK's sandbox handle — a crate-owned facade over the internal
//! `wxc_common` streaming handle, so the public API never exposes the
//! foundation crate's traits.

use std::io::{Read, Write};

use crate::{
    Error, ExecRequest, LifecycleRequest, LifecycleResult, OperationOptions, ProvisionRequest,
    ProvisionResult, SandboxId, ValidationResult,
};
pub use wxc_common::models::{
    CaptureDenialsErrorOutput, CaptureDenialsOutput, SandboxOutputMetadata,
};
use wxc_common::sandbox_process::{NativeStdio, SandboxProcess, StreamCloser as InnerCloser};
use wxc_common::state_aware_backend::ExecOutcome;

/// Provision a sandbox from typed Rust policy.
pub fn provision(
    request: ProvisionRequest,
    options: OperationOptions,
) -> Result<ProvisionResult, Error> {
    mxc_engine::provision_sandbox(request, options)
}

/// Validate a provision request without creating a sandbox.
pub fn validate_provision(
    request: ProvisionRequest,
    options: OperationOptions,
) -> Result<ValidationResult, Error> {
    mxc_engine::validate_provision(request, options)
}

/// Start an existing sandbox.
pub fn start(
    sandbox_id: &SandboxId,
    request: LifecycleRequest,
    options: OperationOptions,
) -> Result<LifecycleResult, Error> {
    mxc_engine::start_sandbox(sandbox_id, request, options)
}

/// Validate a start request without starting the sandbox.
pub fn validate_start(
    sandbox_id: &SandboxId,
    request: LifecycleRequest,
    options: OperationOptions,
) -> Result<ValidationResult, Error> {
    mxc_engine::validate_start(sandbox_id, request, options)
}

/// Stop an existing sandbox.
pub fn stop(
    sandbox_id: &SandboxId,
    request: LifecycleRequest,
    options: OperationOptions,
) -> Result<LifecycleResult, Error> {
    mxc_engine::stop_sandbox(sandbox_id, request, options)
}

/// Validate a stop request without stopping the sandbox.
pub fn validate_stop(
    sandbox_id: &SandboxId,
    request: LifecycleRequest,
    options: OperationOptions,
) -> Result<ValidationResult, Error> {
    mxc_engine::validate_stop(sandbox_id, request, options)
}

/// Deprovision an existing sandbox.
pub fn deprovision(
    sandbox_id: &SandboxId,
    request: LifecycleRequest,
    options: OperationOptions,
) -> Result<LifecycleResult, Error> {
    mxc_engine::deprovision_sandbox(sandbox_id, request, options)
}

/// Validate a deprovision request without changing the sandbox.
pub fn validate_deprovision(
    sandbox_id: &SandboxId,
    request: LifecycleRequest,
    options: OperationOptions,
) -> Result<ValidationResult, Error> {
    mxc_engine::validate_deprovision(sandbox_id, request, options)
}

/// Execute in an existing sandbox and return a live streaming handle.
pub fn exec(
    sandbox_id: &SandboxId,
    request: ExecRequest,
    options: OperationOptions,
) -> Result<Sandbox, Error> {
    mxc_engine::exec_sandbox_request(sandbox_id, request, options).map(Sandbox::new)
}

/// Execute in an existing sandbox attached to this process's stdio.
pub fn exec_attached(
    sandbox_id: &SandboxId,
    request: ExecRequest,
    options: OperationOptions,
) -> Result<WaitOutcome, Error> {
    mxc_engine::exec_attached_request(sandbox_id, request, options).map(|outcome| match outcome {
        ExecOutcome::Exited(code) => WaitOutcome::Exited(code),
        ExecOutcome::TimedOut => WaitOutcome::TimedOut,
    })
}

/// Validate an exec request without running a workload.
pub fn validate_exec(
    sandbox_id: &SandboxId,
    request: ExecRequest,
    options: OperationOptions,
) -> Result<ValidationResult, Error> {
    mxc_engine::validate_exec(sandbox_id, request, options)
}

/// The outcome of waiting on a [`Sandbox`] (see [`Sandbox::wait`]).
///
/// An ordinary exit and a timeout are both represented here as success
/// outcomes; [`Sandbox::wait`] reserves its `Err` for an actual OS / wait
/// failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WaitOutcome {
    /// The process exited with this code. On Unix a process terminated by a
    /// signal (rather than exiting normally) surfaces as `Exited(-1)`.
    Exited(i32),
    /// The request's `scriptTimeout` elapsed while the process was running, and
    /// the process is no longer running.
    ///
    /// **Deadline spent, and the process is gone.** Whether it was killed or
    /// exited on its own a moment past the deadline is not distinguished: both
    /// missed the deadline the caller asked for, and reporting the exit code
    /// one of them happened to produce would hide that.
    ///
    /// How far "gone" reaches depends on the backend. A process-spawning
    /// backend kills the whole tree. A backend whose only primitive is the
    /// foreground process — the state-aware `exec` path over IsolationSession —
    /// confirms that process, and a descendant the workload backgrounded is
    /// reclaimed when the sandbox is stopped and deprovisioned rather than here.
    ///
    /// That state-aware route is reachable from this crate once the caller
    /// passes the `experimental` opt-in to
    /// [`exec_sandbox`](crate::exec_sandbox) and the backend is compiled in via
    /// this crate's `isolation_session` feature, which forwards to the engine.
    /// Both refusals are
    /// [`ErrorCode::BackendUnavailable`](crate::ErrorCode::BackendUnavailable).
    TimedOut,
}

/// The captured result of running a [`Sandbox`] to completion via
/// [`wait_with_output`](Sandbox::wait_with_output).
#[derive(Debug, Clone)]
pub struct Output {
    /// How the process finished.
    pub outcome: WaitOutcome,
    /// Policy and operational warnings from the sandbox, such as security
    /// warnings, network rules that cannot carry traffic, or a cleanup step
    /// that failed after the workload exited.
    pub warnings: Vec<String>,
    /// Everything the child wrote to stdout.
    pub stdout: Vec<u8>,
    /// Everything the child wrote to stderr.
    pub stderr: Vec<u8>,
    /// Structured outputs produced by optional sandbox features.
    pub output_metadata: Option<SandboxOutputMetadata>,
}

/// Captured output and explicitly requested creation-policy diagnostics.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct ReportedOutput {
    /// Captured workload output, using the unchanged legacy result shape.
    pub output: Output,
    /// The creation-policy report requested by the sandbox configuration, if available.
    pub policy_enforcement: Option<Box<crate::PolicyEnforcementReport>>,
}

/// Diagnostics retained when [`Sandbox::wait_with_output_and_report`] fails.
#[derive(Debug)]
pub struct OutputError {
    source: std::io::Error,
    output_metadata: Option<Box<SandboxOutputMetadata>>,
    policy_enforcement: Option<Box<crate::PolicyEnforcementReport>>,
}

impl OutputError {
    /// The original wait error, including its native OS code when present.
    pub fn io_error(&self) -> &std::io::Error {
        &self.source
    }

    /// Outputs available when waiting failed, before the sandbox was dropped.
    pub fn output_metadata(&self) -> Option<&SandboxOutputMetadata> {
        self.output_metadata.as_deref()
    }

    /// The explicitly requested creation-policy report, when available.
    pub fn policy_enforcement_report(&self) -> Option<&crate::PolicyEnforcementReport> {
        self.policy_enforcement.as_deref()
    }

    pub(crate) fn into_sdk_error(self) -> Error {
        let mut error = Error::new(
            crate::ErrorCode::BackendError,
            format!("waiting for the sandbox to complete failed: {self}"),
        );
        if let Some(report) = self.policy_enforcement_report() {
            let mut details = serde_json::json!({ "policyEnforcement": report });
            if let Some(metadata) = self.output_metadata() {
                details["outputMetadata"] = serde_json::json!(metadata);
            }
            error.details = Some(Box::new(details));
        }
        error
    }
}

impl std::fmt::Display for OutputError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.source.fmt(formatter)
    }
}

impl std::error::Error for OutputError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.source)
    }
}

/// A live sandboxed process, returned by [`spawn_sandbox`](crate::spawn_sandbox)
/// and [`exec_sandbox`](crate::exec_sandbox).
///
/// Stream the child's stdio with the `take_*` accessors, wait for it, or kill
/// it. No pty is allocated — the streams are ordinary pipes. Any stdout/stderr
/// the caller does not `take_*` is drained and discarded by [`wait`](Self::wait).
pub struct Sandbox {
    inner: Box<dyn SandboxProcess>,
    stdio_access: StdioAccess,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
enum StdioAccess {
    /// No stdio ownership has been transferred from the sandbox.
    #[default]
    Untouched,
    /// One or more Rust streams were taken; remaining streams may be taken individually.
    Individual,
    /// All available native endpoints were transferred; individual access is disabled.
    Native,
}

impl Sandbox {
    pub(crate) fn new(inner: Box<dyn SandboxProcess>) -> Self {
        Self {
            inner,
            stdio_access: StdioAccess::Untouched,
        }
    }

    /// Policy and operational warnings from this sandbox, such as security
    /// warnings, network rules that cannot carry traffic, or a cleanup step
    /// that failed after the workload exited.
    pub fn warnings(&self) -> Vec<String> {
        self.inner.warnings()
    }

    /// Capture outputs available after a terminal wait completes.
    pub fn output_metadata(&self) -> Option<&SandboxOutputMetadata> {
        self.inner.output_metadata()
    }

    /// Explicitly requested creation-policy diagnostics, available after spawn.
    pub fn policy_enforcement_report(&self) -> Option<&crate::PolicyEnforcementReport> {
        self.inner.policy_enforcement_report()
    }

    /// Take the child's stdin pipe. Returns `None` after the first call.
    pub fn take_stdin(&mut self) -> Option<Box<dyn Write + Send>> {
        if self.stdio_access == StdioAccess::Native {
            return None;
        }
        let stream = self.inner.take_stdin();
        if stream.is_some() {
            self.stdio_access = StdioAccess::Individual;
        }
        stream
    }

    /// Take the child's stdout pipe. Returns `None` after the first call.
    pub fn take_stdout(&mut self) -> Option<Box<dyn Read + Send>> {
        if self.stdio_access == StdioAccess::Native {
            return None;
        }
        let stream = self.inner.take_stdout();
        if stream.is_some() {
            self.stdio_access = StdioAccess::Individual;
        }
        stream
    }

    /// Take the child's stderr pipe. Returns `None` after the first call.
    pub fn take_stderr(&mut self) -> Option<Box<dyn Read + Send>> {
        if self.stdio_access == StdioAccess::Native {
            return None;
        }
        let stream = self.inner.take_stderr();
        if stream.is_some() {
            self.stdio_access = StdioAccess::Individual;
        }
        stream
    }

    #[doc(hidden)]
    pub fn take_native_stdio(&mut self) -> std::io::Result<Option<NativeStdio>> {
        match self.stdio_access {
            StdioAccess::Individual => {
                return Err(std::io::Error::other(
                    "native stdio must be taken before taking individual streams",
                ));
            }
            StdioAccess::Native => return Ok(None),
            StdioAccess::Untouched => {}
        }
        let stdio = self.inner.take_native_stdio()?;
        if stdio.is_some() {
            self.stdio_access = StdioAccess::Native;
        }
        Ok(stdio)
    }

    /// A [`StreamCloser`] that unblocks a parked blocking read on stdout without
    /// killing the child. `None` if stdout was not piped.
    pub fn stdout_closer(&self) -> Option<StreamCloser> {
        self.inner.stdout_closer().map(StreamCloser::new)
    }

    /// As [`stdout_closer`](Self::stdout_closer), for stderr.
    pub fn stderr_closer(&self) -> Option<StreamCloser> {
        self.inner.stderr_closer().map(StreamCloser::new)
    }

    /// Non-blocking exit check: `Some(code)` if the child has exited.
    pub fn try_wait(&mut self) -> std::io::Result<Option<i32>> {
        self.inner.try_wait()
    }

    /// The child's process id.
    pub fn id(&self) -> u32 {
        self.inner.id()
    }

    /// Kill the child.
    pub fn kill(&mut self) -> std::io::Result<()> {
        self.inner.kill()
    }

    /// Request timeout termination and permanently classify a later successful
    /// terminal observation as timed out. Call only after the deadline elapsed.
    #[doc(hidden)]
    pub fn kill_for_timeout(&mut self) -> std::io::Result<()> {
        self.inner.kill_for_timeout()
    }

    /// Wait for the child to exit, draining and discarding any untaken
    /// stdout/stderr so it can't block on a full pipe.
    ///
    /// Returns [`WaitOutcome::Exited`] with the exit code, or
    /// [`WaitOutcome::TimedOut`] if the request's `scriptTimeout` elapsed. `Err`
    /// is reserved for an actual OS / wait failure.
    pub fn wait(&mut self) -> std::io::Result<WaitOutcome> {
        match self.inner.wait() {
            Ok(code) => Ok(WaitOutcome::Exited(code)),
            Err(e) if e.kind() == std::io::ErrorKind::TimedOut => Ok(WaitOutcome::TimedOut),
            Err(e) => Err(e),
        }
    }

    /// Wait for the child to exit, capturing its stdout and stderr.
    ///
    /// The safe alternative to [`take_stdout`](Self::take_stdout) +
    /// [`take_stderr`](Self::take_stderr): it drains both streams **concurrently**
    /// on separate threads, so an output-heavy child can't deadlock (reading one
    /// stream to EOF before the other can). Consumes the handle.
    ///
    /// `Err` is reserved for an actual OS / wait failure; a timeout is reported
    /// as [`Output`] with `outcome: WaitOutcome::TimedOut` and whatever each
    /// stream produced. Wait errors are returned unchanged, including native
    /// OS codes and custom error payloads.
    pub fn wait_with_output(mut self) -> std::io::Result<Output> {
        self.collect_output(false)
    }

    /// Consume the sandbox while retaining creation-policy diagnostics on
    /// success or failure. This waits and drains streams exactly once.
    ///
    /// # Errors
    ///
    /// Returns [`OutputError`] for an OS/wait failure, retaining the original
    /// I/O error and any available capture outputs and policy report.
    pub fn wait_with_output_and_report(mut self) -> Result<ReportedOutput, OutputError> {
        match self.collect_output(true) {
            Ok(output) => Ok(ReportedOutput {
                output,
                policy_enforcement: self
                    .inner
                    .policy_enforcement_report()
                    .cloned()
                    .map(Box::new),
            }),
            Err(source) => Err(OutputError {
                source,
                output_metadata: self.inner.output_metadata().cloned().map(Box::new),
                policy_enforcement: self
                    .inner
                    .policy_enforcement_report()
                    .cloned()
                    .map(Box::new),
            }),
        }
    }

    fn collect_output(&mut self, retain_terminal_diagnostics: bool) -> std::io::Result<Output> {
        fn capture(stream: Option<Box<dyn Read + Send>>) -> std::thread::JoinHandle<Vec<u8>> {
            std::thread::spawn(move || {
                let mut buf = Vec::new();
                if let Some(mut stream) = stream {
                    let _ = stream.read_to_end(&mut buf);
                }
                buf
            })
        }

        // Take both streams before waiting so `wait` won't discard them, and
        // read each on its own thread so the child never blocks on a full pipe.
        let stdout = capture(self.inner.take_stdout());
        let stderr = capture(self.inner.take_stderr());
        let mut terminal_diagnostic = None;
        let outcome = match self.inner.wait() {
            Ok(code) => WaitOutcome::Exited(code),
            Err(error) if error.kind() == std::io::ErrorKind::TimedOut => {
                if retain_terminal_diagnostics && self.inner.policy_enforcement_report().is_some() {
                    terminal_diagnostic = Some(error.to_string());
                }
                WaitOutcome::TimedOut
            }
            Err(error) => return Err(error),
        };
        // Sampled after the wait: a backend whose teardown runs there reports
        // its failures here.
        let mut warnings = self.inner.warnings();
        if let Some(message) = terminal_diagnostic {
            if !warnings.contains(&message) {
                warnings.push(message);
            }
        }
        let output_metadata = self.inner.output_metadata().cloned();
        Ok(Output {
            outcome,
            warnings,
            stdout: stdout.join().unwrap_or_default(),
            stderr: stderr.join().unwrap_or_default(),
            output_metadata,
        })
    }
}

/// Closes one of a [`Sandbox`]'s streams, unblocking a read parked on it without
/// killing the process. Obtained from [`Sandbox::stdout_closer`] /
/// [`Sandbox::stderr_closer`].
pub struct StreamCloser {
    inner: Box<dyn InnerCloser>,
}

impl StreamCloser {
    fn new(inner: Box<dyn InnerCloser>) -> Self {
        Self { inner }
    }

    /// Close the stream, making any read currently parked on it return.
    pub fn close(&self) {
        self.inner.close();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Default)]
    struct FakeProcess {
        warnings: Vec<String>,
        wait_warning: Option<String>,
        output_metadata: Option<SandboxOutputMetadata>,
        stdout: Option<Box<dyn Read + Send>>,
        wait_error: Option<std::io::Error>,
        wait_metadata: Option<SandboxOutputMetadata>,
        policy_report: Option<crate::PolicyEnforcementReport>,
    }

    struct NativeOnlyFake;

    impl SandboxProcess for NativeOnlyFake {
        fn warnings(&self) -> Vec<String> {
            Vec::new()
        }

        fn take_stdin(&mut self) -> Option<Box<dyn Write + Send>> {
            panic!("individual stdin must not be delegated after native transfer")
        }

        fn take_stdout(&mut self) -> Option<Box<dyn Read + Send>> {
            panic!("individual stdout must not be delegated after native transfer")
        }

        fn take_stderr(&mut self) -> Option<Box<dyn Read + Send>> {
            panic!("individual stderr must not be delegated after native transfer")
        }

        fn take_native_stdio(&mut self) -> std::io::Result<Option<NativeStdio>> {
            Ok(Some(NativeStdio {
                stdin: None,
                stdout: None,
                stderr: None,
            }))
        }

        fn try_wait(&mut self) -> std::io::Result<Option<i32>> {
            Ok(Some(0))
        }

        fn id(&self) -> u32 {
            1
        }

        fn kill(&mut self) -> std::io::Result<()> {
            Ok(())
        }

        fn wait(&mut self) -> std::io::Result<i32> {
            Ok(0)
        }
    }

    impl SandboxProcess for FakeProcess {
        fn warnings(&self) -> Vec<String> {
            self.warnings.clone()
        }

        fn output_metadata(&self) -> Option<&SandboxOutputMetadata> {
            self.output_metadata.as_ref()
        }

        fn policy_enforcement_report(&self) -> Option<&crate::PolicyEnforcementReport> {
            self.policy_report.as_ref()
        }

        fn take_stdin(&mut self) -> Option<Box<dyn Write + Send>> {
            None
        }

        fn take_stdout(&mut self) -> Option<Box<dyn Read + Send>> {
            self.stdout.take()
        }

        fn take_stderr(&mut self) -> Option<Box<dyn Read + Send>> {
            None
        }

        fn take_native_stdio(&mut self) -> std::io::Result<Option<NativeStdio>> {
            panic!("native stdio must not be delegated after taking a stream")
        }

        fn try_wait(&mut self) -> std::io::Result<Option<i32>> {
            Ok(Some(0))
        }

        fn id(&self) -> u32 {
            1
        }

        fn kill(&mut self) -> std::io::Result<()> {
            Ok(())
        }

        fn wait(&mut self) -> std::io::Result<i32> {
            if let Some(warning) = self.wait_warning.take() {
                self.warnings.push(warning);
            }
            if let Some(metadata) = self.wait_metadata.take() {
                self.output_metadata
                    .get_or_insert_with(SandboxOutputMetadata::default)
                    .merge(metadata);
            }
            if let Some(error) = self.wait_error.take() {
                return Err(error);
            }
            Ok(0)
        }
    }

    #[test]
    fn sandbox_and_output_expose_security_warnings() {
        let warning = "permissive mode weakens containment".to_string();
        let wait_warning = "telemetry emission failed".to_string();
        let sandbox = Sandbox::new(Box::new(FakeProcess {
            warnings: vec![warning.clone()],
            wait_warning: Some(wait_warning.clone()),
            output_metadata: Some(SandboxOutputMetadata {
                capture_denials: Some(CaptureDenialsOutput {
                    kind: CaptureDenialsOutput::KIND.to_string(),
                    output_path: "denials.json".to_string(),
                    exit_code: 0,
                    total_denials: 2,
                    denied_resources_truncated: false,
                    etl_path: None,
                }),
                capture_denials_error: None,
            }),
            stdout: None,
            ..Default::default()
        }));

        assert_eq!(sandbox.warnings(), [warning.as_str()]);

        let output = sandbox.wait_with_output().expect("wait succeeds");
        assert_eq!(output.warnings, [warning, wait_warning]);
        assert_eq!(
            output
                .output_metadata
                .unwrap()
                .capture_denials
                .unwrap()
                .total_denials,
            2
        );
    }

    #[test]
    fn native_stdio_is_rejected_after_an_individual_stream_is_taken() {
        let mut sandbox = Sandbox::new(Box::new(FakeProcess {
            warnings: Vec::new(),
            wait_warning: None,
            output_metadata: None,
            stdout: Some(Box::new(std::io::Cursor::new(Vec::<u8>::new()))),
            ..Default::default()
        }));

        assert!(sandbox.take_stdout().is_some());
        let error = sandbox
            .take_native_stdio()
            .expect_err("mixed stream ownership must be rejected");

        assert_eq!(
            error.to_string(),
            "native stdio must be taken before taking individual streams"
        );
    }

    #[test]
    fn policy_enforcement_consuming_wait_failure_retains_report_and_original_error() {
        let report = crate::PolicyEnforcementReport::new(
            crate::PolicyEnforcementMode::Mutate,
            crate::PolicyEnforcementAvailability::Available,
            "policy-hash".into(),
        );
        let source = std::io::Error::from_raw_os_error(5);
        let kind = source.kind();
        let message = source.to_string();
        let sandbox = Sandbox::new(Box::new(FakeProcess {
            policy_report: Some(report.clone()),
            wait_metadata: Some(SandboxOutputMetadata {
                capture_denials_error: Some(CaptureDenialsErrorOutput {
                    message: "capture finalization failed".into(),
                    etl_path: "retained.etl".into(),
                }),
                ..Default::default()
            }),
            wait_error: Some(source),
            ..Default::default()
        }));
        assert!(sandbox.output_metadata().is_none());
        assert_eq!(sandbox.policy_enforcement_report(), Some(&report));
        let error = sandbox.wait_with_output_and_report().unwrap_err();
        assert_eq!(error.io_error().kind(), kind);
        assert_eq!(error.to_string(), message);
        assert_eq!(error.io_error().raw_os_error(), Some(5));
        assert_eq!(error.policy_enforcement_report(), Some(&report));
        assert_eq!(
            error
                .output_metadata()
                .unwrap()
                .capture_denials_error
                .as_ref()
                .unwrap()
                .etl_path,
            "retained.etl"
        );
        let sdk_error = error.into_sdk_error();
        let details = sdk_error.details.as_deref().unwrap();
        assert_eq!(details["policyEnforcement"], serde_json::json!(report));
        assert_eq!(
            details["outputMetadata"]["captureDenialsError"]["etlPath"],
            "retained.etl"
        );
    }

    #[test]
    fn policy_enforcement_timeout_retains_terminal_diagnostics_without_capture_metadata() {
        let message = "sandbox execution timed out; additionally capture sealing failed";
        for reporting in [false, true] {
            let report = reporting.then(|| {
                crate::PolicyEnforcementReport::new(
                    crate::PolicyEnforcementMode::PassThrough,
                    crate::PolicyEnforcementAvailability::Available,
                    "hash".into(),
                )
            });
            let sandbox = Sandbox::new(Box::new(FakeProcess {
                policy_report: report,
                wait_error: Some(std::io::Error::new(std::io::ErrorKind::TimedOut, message)),
                stdout: Some(Box::new(std::io::Cursor::new(b"once".to_vec()))),
                ..Default::default()
            }));
            let reported = sandbox.wait_with_output_and_report().unwrap();
            assert_eq!(reported.output.outcome, WaitOutcome::TimedOut);
            assert_eq!(reported.output.stdout, b"once");
            assert!(reported.output.output_metadata.is_none());
            assert_eq!(
                reported.output.warnings,
                if reporting { vec![message] } else { vec![] }
            );
        }
    }

    #[test]
    fn policy_enforcement_reported_output_owns_report_and_legacy_capture() {
        let report = crate::PolicyEnforcementReport::new(
            crate::PolicyEnforcementMode::PassThrough,
            crate::PolicyEnforcementAvailability::Available,
            "hash".into(),
        );
        let capture = SandboxOutputMetadata {
            capture_denials: None,
            capture_denials_error: Some(CaptureDenialsErrorOutput {
                message: "retained diagnostic".into(),
                etl_path: "capture.etl".into(),
            }),
        };
        let sandbox = Sandbox::new(Box::new(FakeProcess {
            policy_report: Some(report.clone()),
            output_metadata: Some(capture.clone()),
            stdout: Some(Box::new(std::io::Cursor::new(b"once".to_vec()))),
            ..Default::default()
        }));
        let reported = sandbox.wait_with_output_and_report().unwrap();
        assert_eq!(reported.output.stdout, b"once");
        assert_eq!(reported.output.outcome, WaitOutcome::Exited(0));
        assert_eq!(reported.output.output_metadata, Some(capture));
        assert_eq!(reported.policy_enforcement.as_deref(), Some(&report));
    }

    #[test]
    fn legacy_consuming_wait_preserves_the_original_os_error() {
        for output_metadata in [
            None,
            Some(SandboxOutputMetadata::default()),
            Some(SandboxOutputMetadata {
                capture_denials_error: Some(CaptureDenialsErrorOutput {
                    message: "capture failed".into(),
                    etl_path: "capture.etl".into(),
                }),
                ..Default::default()
            }),
        ] {
            let source = std::io::Error::from_raw_os_error(5);
            let kind = source.kind();
            let message = source.to_string();
            let sandbox = Sandbox::new(Box::new(FakeProcess {
                output_metadata,
                wait_error: Some(source),
                ..Default::default()
            }));
            let error = sandbox.wait_with_output().unwrap_err();
            assert_eq!(error.raw_os_error(), Some(5));
            assert_eq!(error.kind(), kind);
            assert_eq!(error.to_string(), message);
        }
    }

    #[test]
    fn legacy_consuming_wait_preserves_custom_error_downcasts() {
        #[derive(Debug)]
        struct OriginalError;
        impl std::fmt::Display for OriginalError {
            fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                formatter.write_str("original wait failure")
            }
        }
        impl std::error::Error for OriginalError {}

        let sandbox = Sandbox::new(Box::new(FakeProcess {
            output_metadata: Some(SandboxOutputMetadata::default()),
            wait_error: Some(std::io::Error::other(OriginalError)),
            ..Default::default()
        }));
        let error = sandbox.wait_with_output().unwrap_err();
        assert!(error
            .get_ref()
            .and_then(|source| source.downcast_ref::<OriginalError>())
            .is_some());
    }

    #[test]
    fn individual_streams_are_not_delegated_after_native_stdio_is_taken() {
        let mut sandbox = Sandbox::new(Box::new(NativeOnlyFake));

        assert!(sandbox
            .take_native_stdio()
            .expect("native stdio transfer succeeds")
            .is_some());
        assert!(sandbox.take_stdin().is_none());
        assert!(sandbox.take_stdout().is_none());
        assert!(sandbox.take_stderr().is_none());
        assert!(sandbox
            .take_native_stdio()
            .expect("repeated native transfer is empty")
            .is_none());
    }
}
