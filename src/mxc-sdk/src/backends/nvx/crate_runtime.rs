// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use std::io::{self, Read, Seek, SeekFrom};
use std::path::Path;
use std::sync::{mpsc, Arc, Mutex};
use std::time::{Duration, Instant};

use crate::mxc_common::logger::Logger;
use crate::mxc_common::mxc_error::{MxcError, MxcErrorCode};
use crate::mxc_common::script_runner::RunCancellation;
use aci_edge_sandboxes::agent::{AgentBackend, AgentConfig, ImageDigest, SandboxDiagnostics};
use aci_edge_sandboxes::{
    AciEdgeSandbox, Backend, Capabilities, Error, ErrorCode, ExecIo, ExecOutcome, ExecRequest,
    ImageSource, OutputSink, ProvisionRequest, SandboxId, SandboxSpec,
};

pub(super) const CAPTURE_LIMIT_BYTES: usize = 64 * 1024 * 1024;
const STARTUP_LOG_LIMIT: usize = 8 * 1024;
const HOST_TIMEOUT_SLACK_MS: u64 = 30_000;
const POLL: Duration = Duration::from_millis(100);

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct PreparedProvision {
    pub request: ProvisionRequest,
    pub spec: SandboxSpec,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct ExecOutput {
    pub outcome: ExecOutcome,
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
}

pub(super) trait SandboxClient {
    fn capabilities(&self) -> Result<Capabilities, MxcError>;
    fn validate_provision(&self, input: &PreparedProvision) -> Result<(), MxcError>;
    fn validate_exec(&self, request: &ExecRequest) -> Result<(), MxcError>;
    fn probe(&self) -> Result<(), MxcError>;
    fn provision(&self, input: &PreparedProvision) -> Result<SandboxId, MxcError>;
    fn start(&self, sandbox_id: &SandboxId) -> Result<(), MxcError>;
    fn diagnostics(&self, sandbox_id: &SandboxId) -> Result<SandboxDiagnostics, MxcError>;
    fn exec_and_wait(
        &self,
        sandbox_id: &SandboxId,
        request: &ExecRequest,
        cancellation: Option<&RunCancellation>,
        logger: &mut Logger,
    ) -> Result<ExecOutput, MxcError>;
    fn stop(&self, sandbox_id: &SandboxId) -> Result<(), MxcError>;
    fn deprovision(&self, sandbox_id: &SandboxId) -> Result<(), MxcError>;
    fn close(&mut self) -> Result<(), MxcError>;
}

pub(super) fn startup_diagnostics(diagnostics: &SandboxDiagnostics) -> String {
    let mut excerpt = String::new();
    for (name, path) in [
        ("vmm_log", &diagnostics.vmm_log),
        ("console_log", &diagnostics.console_log),
        ("outcome_report", &diagnostics.outcome_report),
    ] {
        excerpt.push_str(&format!("; {name}: "));
        match read_startup_log(path) {
            Ok((bytes, truncated)) => {
                if truncated {
                    excerpt.push_str("[truncated] ");
                }
                if bytes.is_empty() {
                    excerpt.push_str("[empty]");
                } else {
                    excerpt.push_str(&String::from_utf8_lossy(&bytes));
                }
            }
            Err(error) => excerpt.push_str(&format!("unavailable ({}): {error}", path.display())),
        }
    }
    excerpt
}

fn read_startup_log(path: &Path) -> io::Result<(Vec<u8>, bool)> {
    let mut file = std::fs::File::open(path)?;
    let length = file.metadata()?.len();
    let start = length.saturating_sub(STARTUP_LOG_LIMIT as u64);
    file.seek(SeekFrom::Start(start))?;
    let mut bytes = Vec::new();
    file.take(STARTUP_LOG_LIMIT as u64 + 1)
        .read_to_end(&mut bytes)?;
    let truncated = start != 0 || bytes.len() > STARTUP_LOG_LIMIT;
    bytes.truncate(STARTUP_LOG_LIMIT);
    Ok((bytes, truncated))
}

pub(super) fn map_error(error: Error) -> MxcError {
    let code = match error.code() {
        ErrorCode::MalformedRequest => MxcErrorCode::MalformedRequest,
        ErrorCode::MalformedId => MxcErrorCode::MalformedId,
        ErrorCode::StaleId => MxcErrorCode::StaleId,
        ErrorCode::NotStarted => MxcErrorCode::NotStarted,
        ErrorCode::AlreadyStarted => MxcErrorCode::AlreadyStarted,
        ErrorCode::AlreadyStopped => MxcErrorCode::AlreadyStopped,
        ErrorCode::PolicyValidation => MxcErrorCode::PolicyValidation,
        ErrorCode::BackendUnavailable => MxcErrorCode::BackendUnavailable,
        ErrorCode::Unsupported | ErrorCode::BackendError => MxcErrorCode::BackendError,
        _ => MxcErrorCode::BackendError,
    };
    let mut message = format!("NVX signed bundled agent: {error}");
    let mut source = std::error::Error::source(&error);
    while let Some(cause) = source {
        message.push_str(&format!(": {cause}"));
        source = cause.source();
    }
    MxcError::new(code, message)
}

pub(super) fn sandbox_spec(image: &str) -> Result<SandboxSpec, MxcError> {
    crate::mxc_contract::dev::ImageReference::validate(image)
        .map_err(MxcError::malformed_request)?;
    Ok(SandboxSpec::new().with_image(ImageSource::Reference(image.to_owned())))
}

struct ClientInner {
    backend: Arc<AgentBackend>,
    client: AciEdgeSandbox,
}

pub(super) struct NvxClient(Option<ClientInner>);

pub(super) fn create_client(state_root: &Path) -> Result<NvxClient, MxcError> {
    let config = AgentConfig::bundled(state_root).map_err(map_error)?;
    let backend = Arc::new(AgentBackend::new(config).map_err(map_error)?);
    let client = AciEdgeSandbox::from_shared(backend.clone());
    Ok(NvxClient(Some(ClientInner { backend, client })))
}

impl NvxClient {
    fn inner(&self) -> Result<&ClientInner, MxcError> {
        self.0
            .as_ref()
            .ok_or_else(|| MxcError::backend_error("NVX client is closed"))
    }
}

#[derive(Default)]
struct Captured {
    stdout: Vec<u8>,
    stderr: Vec<u8>,
    overflow: bool,
}

struct CaptureSink {
    shared: Arc<Mutex<Captured>>,
    stderr: bool,
    limit: usize,
}

impl OutputSink for CaptureSink {
    fn write(&mut self, data: &[u8]) -> io::Result<()> {
        let mut captured = self
            .shared
            .lock()
            .map_err(|_| io::Error::other("NVX capture lock poisoned"))?;
        if data.len()
            > self
                .limit
                .saturating_sub(captured.stdout.len() + captured.stderr.len())
        {
            captured.overflow = true;
            return Err(io::Error::other("NVX capture limit exceeded"));
        }
        if self.stderr {
            captured.stderr.extend_from_slice(data);
        } else {
            captured.stdout.extend_from_slice(data);
        }
        Ok(())
    }
}

pub(super) fn capture_limit_error(limit: usize) -> MxcError {
    MxcError::backend_error(format!(
        "NVX signed bundled agent: combined stdout/stderr capture limit of {limit} bytes exceeded"
    ))
}

fn collect_execution(
    control: Arc<dyn aci_edge_sandboxes::ExecControl>,
    captured: Arc<Mutex<Captured>>,
    deadline: Option<Instant>,
    cancellation: Option<&RunCancellation>,
    limit: usize,
) -> Result<ExecOutput, MxcError> {
    let (sender, receiver) = mpsc::channel();
    let waiting = control.clone();
    let waiter = match std::thread::Builder::new()
        .name("mxc-nvx-wait".to_owned())
        .spawn(move || {
            let _ = sender.send(waiting.wait());
        }) {
        Ok(waiter) => waiter,
        Err(error) => {
            let mut primary =
                MxcError::backend_error(format!("cannot start NVX wait thread: {error}"));
            if let Err(cleanup) = control.cancel().map_err(map_error) {
                primary
                    .message
                    .push_str(&format!("; cleanup failure: {cleanup}"));
            }
            if let Err(cleanup) = control.wait().map_err(map_error) {
                primary
                    .message
                    .push_str(&format!("; cleanup failure: {cleanup}"));
            }
            return Err(primary);
        }
    };
    let mut failure = None;
    let mut host_timeout = false;
    let outcome = loop {
        match receiver.recv_timeout(POLL) {
            Ok(result) => break result.map_err(map_error),
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                break Err(MxcError::backend_error(
                    "NVX wait thread terminated without an outcome",
                ))
            }
            Err(mpsc::RecvTimeoutError::Timeout) => {}
        }
        if failure.is_none() && !host_timeout {
            match captured.lock() {
                Ok(capture) if capture.overflow => failure = Some(capture_limit_error(limit)),
                Err(_) => failure = Some(MxcError::backend_error("NVX capture lock poisoned")),
                _ => {}
            }
            if failure.is_none() {
                if let Some(cancellation) = cancellation {
                    failure = cancellation.check().err();
                }
            }
            if failure.is_none() && deadline.is_some_and(|deadline| Instant::now() >= deadline) {
                host_timeout = true;
            }
            if failure.is_some() || host_timeout {
                if let Err(cleanup) = control.cancel().map_err(map_error) {
                    if let Some(primary) = failure.as_mut() {
                        primary
                            .message
                            .push_str(&format!("; cleanup failure: {cleanup}"));
                    } else {
                        failure = Some(cleanup);
                    }
                }
            }
        }
    };
    if waiter.join().is_err() {
        return Err(MxcError::backend_error("NVX wait thread panicked"));
    }
    let mut captured = captured
        .lock()
        .map_err(|_| MxcError::backend_error("NVX capture lock poisoned"))?;
    if captured.overflow && failure.is_none() {
        failure = Some(capture_limit_error(limit));
    }
    if let Some(mut error) = failure {
        if let Err(cleanup) = outcome {
            error
                .message
                .push_str(&format!("; cleanup failure: {cleanup}"));
        }
        return Err(error);
    }
    let outcome = outcome?;
    Ok(ExecOutput {
        outcome: if host_timeout
            && matches!(outcome, ExecOutcome::Cancelled | ExecOutcome::TimedOut)
        {
            ExecOutcome::TimedOut
        } else {
            outcome
        },
        stdout: std::mem::take(&mut captured.stdout),
        stderr: std::mem::take(&mut captured.stderr),
    })
}

impl SandboxClient for NvxClient {
    fn capabilities(&self) -> Result<Capabilities, MxcError> {
        Ok(self.inner()?.client.capabilities())
    }
    fn validate_provision(&self, input: &PreparedProvision) -> Result<(), MxcError> {
        self.inner()?
            .client
            .validate_provision_with(&input.request, &input.spec)
            .map_err(map_error)
    }
    fn validate_exec(&self, request: &ExecRequest) -> Result<(), MxcError> {
        self.inner()?
            .client
            .validate_exec(request)
            .map_err(map_error)
    }
    fn probe(&self) -> Result<(), MxcError> {
        self.inner()?.client.probe().map_err(map_error)
    }
    fn provision(&self, input: &PreparedProvision) -> Result<SandboxId, MxcError> {
        let inner = self.inner()?;
        if let Some(ImageSource::Reference(reference)) = &input.spec.image {
            inner
                .backend
                .register_reference(reference, ImageDigest::Compute)
                .map_err(map_error)?;
        }
        inner
            .client
            .provision_with(&input.request, &input.spec)
            .map(|result| result.sandbox_id)
            .map_err(map_error)
    }
    fn start(&self, sandbox_id: &SandboxId) -> Result<(), MxcError> {
        self.inner()?
            .client
            .start(sandbox_id)
            .map(|_| ())
            .map_err(map_error)
    }
    fn diagnostics(&self, sandbox_id: &SandboxId) -> Result<SandboxDiagnostics, MxcError> {
        self.inner()?
            .backend
            .diagnostics(sandbox_id)
            .map_err(map_error)
    }
    fn exec_and_wait(
        &self,
        sandbox_id: &SandboxId,
        request: &ExecRequest,
        cancellation: Option<&RunCancellation>,
        logger: &mut Logger,
    ) -> Result<ExecOutput, MxcError> {
        if let Some(cancellation) = cancellation {
            cancellation.check()?;
        }
        let inner = self.inner()?;
        inner.client.validate_exec(request).map_err(map_error)?;
        let captured = Arc::new(Mutex::new(Captured::default()));
        let io = ExecIo {
            stdout: Box::new(CaptureSink {
                shared: captured.clone(),
                stderr: false,
                limit: CAPTURE_LIMIT_BYTES,
            }),
            stderr: Box::new(CaptureSink {
                shared: captured.clone(),
                stderr: true,
                limit: CAPTURE_LIMIT_BYTES,
            }),
            stdin: None,
        };
        let control: Arc<dyn aci_edge_sandboxes::ExecControl> = Arc::from(
            inner
                .backend
                .exec(sandbox_id, request, io)
                .map_err(map_error)?,
        );
        logger.log_diagnostic_line("NVX execution started");
        let deadline = request
            .process
            .timeout
            .filter(|v| !v.is_zero())
            .and_then(|v| {
                Instant::now()
                    .checked_add(v.saturating_add(Duration::from_millis(HOST_TIMEOUT_SLACK_MS)))
            });
        collect_execution(
            control,
            captured,
            deadline,
            cancellation,
            CAPTURE_LIMIT_BYTES,
        )
    }

    fn stop(&self, sandbox_id: &SandboxId) -> Result<(), MxcError> {
        self.inner()?
            .client
            .stop(sandbox_id)
            .map(|_| ())
            .map_err(map_error)
    }
    fn deprovision(&self, sandbox_id: &SandboxId) -> Result<(), MxcError> {
        self.inner()?
            .client
            .deprovision(sandbox_id)
            .map(|_| ())
            .map_err(map_error)
    }
    fn close(&mut self) -> Result<(), MxcError> {
        let Some(ClientInner { backend, client }) = self.0.take() else {
            return Ok(());
        };
        drop(client);
        let backend = Arc::try_unwrap(backend).map_err(|_| {
            MxcError::backend_error("cannot close NVX agent: backend still has other owners")
        })?;
        backend.close().map_err(map_error)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aci_edge_sandboxes::ExecControl;
    use std::sync::Condvar;

    struct FakeControl {
        state: Mutex<bool>,
        wake: Condvar,
        outcome: ExecOutcome,
    }

    impl FakeControl {
        fn new(complete: bool, outcome: ExecOutcome) -> Self {
            Self {
                state: Mutex::new(complete),
                wake: Condvar::new(),
                outcome,
            }
        }
    }

    impl ExecControl for FakeControl {
        fn wait(&self) -> aci_edge_sandboxes::Result<ExecOutcome> {
            let mut ready = self.state.lock().unwrap();
            while !*ready {
                ready = self.wake.wait(ready).unwrap();
            }
            Ok(self.outcome)
        }
        fn cancel(&self) -> aci_edge_sandboxes::Result<()> {
            *self.state.lock().unwrap() = true;
            self.wake.notify_all();
            Ok(())
        }
    }

    #[test]
    fn capture_enforces_one_combined_binary_limit() {
        for (stderr, overflow) in [(b"xy".as_slice(), false), (b"xyz".as_slice(), true)] {
            let capture = Arc::new(Mutex::new(Captured::default()));
            let mut stdout = CaptureSink {
                shared: capture.clone(),
                stderr: false,
                limit: 5,
            };
            let mut error = CaptureSink {
                shared: capture.clone(),
                stderr: true,
                limit: 5,
            };
            stdout.write(&[0xff, 0, 0x80]).unwrap();
            assert_eq!(error.write(stderr).is_err(), overflow);
            let control = Arc::new(FakeControl::new(!overflow, ExecOutcome::Exited(7)));
            let result = collect_execution(control, capture, None, None, 5);
            if overflow {
                assert!(result.unwrap_err().message.contains("capture limit of 5"));
            } else {
                let output = result.unwrap();
                assert_eq!(output.outcome, ExecOutcome::Exited(7));
                assert_eq!(output.stdout, [0xff, 0, 0x80]);
                assert_eq!(output.stderr, stderr);
            }
        }
    }

    #[test]
    fn unbounded_output_without_a_deadline_hits_the_capture_limit() {
        let captured = Arc::new(Mutex::new(Captured::default()));
        let mut sink = CaptureSink {
            shared: captured.clone(),
            stderr: false,
            limit: 16,
        };
        let writer = std::thread::spawn(move || while sink.write(&[0xff]).is_ok() {});
        let control = Arc::new(FakeControl::new(false, ExecOutcome::Cancelled));
        let error = collect_execution(control.clone(), captured, None, None, 16).unwrap_err();
        writer.join().unwrap();
        assert!(error.message.contains("capture limit of 16"));
        assert!(*control.state.lock().unwrap());
    }

    #[test]
    fn cancellation_and_host_deadline_wait_for_terminal_outcome() {
        let cancelled = RunCancellation::default();
        cancelled.request();
        let control = Arc::new(FakeControl::new(false, ExecOutcome::Cancelled));
        let error = collect_execution(
            control.clone(),
            Arc::new(Mutex::new(Captured::default())),
            None,
            Some(&cancelled),
            5,
        )
        .unwrap_err();
        assert_eq!(error.message, "execution cancelled");
        assert!(*control.state.lock().unwrap());

        let captured = Arc::new(Mutex::new(Captured {
            stdout: b"partial".to_vec(),
            ..Default::default()
        }));
        let control = Arc::new(FakeControl::new(false, ExecOutcome::Cancelled));
        let output =
            collect_execution(control.clone(), captured, Some(Instant::now()), None, 32).unwrap();
        assert_eq!(output.outcome, ExecOutcome::TimedOut);
        assert_eq!(output.stdout, b"partial");
        assert!(*control.state.lock().unwrap());
    }

    #[test]
    fn failed_cancel_waits_for_independent_observer_error() {
        struct FailedCancel {
            done: Mutex<bool>,
            wake: Condvar,
            cancelled: mpsc::Sender<()>,
        }
        impl ExecControl for FailedCancel {
            fn wait(&self) -> aci_edge_sandboxes::Result<ExecOutcome> {
                let mut done = self.done.lock().unwrap();
                while !*done {
                    done = self.wake.wait(done).unwrap();
                }
                Err(Error::new(
                    ErrorCode::BackendError,
                    "workload may still be running; stop or deprovision the sandbox",
                )
                .with_source("native cancellation failed"))
            }
            fn cancel(&self) -> aci_edge_sandboxes::Result<()> {
                self.cancelled.send(()).unwrap();
                Err(Error::new(ErrorCode::BackendError, "cancel failed"))
            }
        }
        let (sender, receiver) = mpsc::channel();
        let control = Arc::new(FailedCancel {
            done: Mutex::new(false),
            wake: Condvar::new(),
            cancelled: sender,
        });
        let observer_control = control.clone();
        let observer = std::thread::spawn(move || {
            let cancelled = receiver.recv_timeout(Duration::from_secs(5)).is_ok();
            std::thread::sleep(Duration::from_millis(100));
            *observer_control.done.lock().unwrap() = true;
            observer_control.wake.notify_all();
            cancelled
        });
        let cancelled = RunCancellation::default();
        cancelled.request();
        let error = collect_execution(
            control,
            Arc::new(Mutex::new(Captured::default())),
            None,
            Some(&cancelled),
            5,
        )
        .unwrap_err();
        assert!(observer.join().unwrap(), "cancellation was never requested");
        assert!(error.message.contains("execution cancelled"), "{error}");
        assert!(error.message.contains("cancel failed"), "{error}");
        assert!(
            error.message.contains("workload may still be running"),
            "{error}"
        );
        assert!(
            error.message.contains("native cancellation failed"),
            "{error}"
        );
    }

    #[test]
    fn release_failure_keeps_outcome_and_native_cause() {
        struct ReleaseFailure;
        impl ExecControl for ReleaseFailure {
            fn wait(&self) -> aci_edge_sandboxes::Result<ExecOutcome> {
                Err(Error::new(
                    ErrorCode::BackendError,
                    "execution exited but release failed",
                )
                .with_source("native release failure"))
            }
            fn cancel(&self) -> aci_edge_sandboxes::Result<()> {
                panic!("completed execution must not be cancelled")
            }
        }
        let error = collect_execution(
            Arc::new(ReleaseFailure),
            Arc::new(Mutex::new(Captured::default())),
            None,
            None,
            5,
        )
        .unwrap_err();
        assert_eq!(error.code, MxcErrorCode::BackendError);
        assert!(error
            .message
            .contains("execution exited but release failed"));
        assert!(error.message.contains("native release failure"));
    }

    #[test]
    fn cancellation_and_wait_errors_are_reported() {
        struct FailingControl {
            state: Mutex<bool>,
            wake: Condvar,
        }
        impl ExecControl for FailingControl {
            fn wait(&self) -> aci_edge_sandboxes::Result<ExecOutcome> {
                let mut ready = self.state.lock().unwrap();
                while !*ready {
                    ready = self.wake.wait(ready).unwrap();
                }
                Err(Error::new(ErrorCode::BackendError, "wait failed"))
            }
            fn cancel(&self) -> aci_edge_sandboxes::Result<()> {
                *self.state.lock().unwrap() = true;
                self.wake.notify_all();
                Err(Error::new(ErrorCode::BackendError, "cancel failed"))
            }
        }
        let cancelled = RunCancellation::default();
        cancelled.request();
        let control = Arc::new(FailingControl {
            state: Mutex::new(false),
            wake: Condvar::new(),
        });
        let error = collect_execution(
            control,
            Arc::new(Mutex::new(Captured::default())),
            None,
            Some(&cancelled),
            5,
        )
        .unwrap_err();
        assert_eq!(error.code, MxcErrorCode::BackendError);
        assert!(error.message.contains("execution cancelled"));
        assert!(error.message.contains("cancel failed"));
        assert!(error.message.contains("wait failed"));
    }

    #[test]
    fn maps_crate_errors_without_success_fallbacks() {
        for (native, expected) in [
            (ErrorCode::MalformedRequest, MxcErrorCode::MalformedRequest),
            (ErrorCode::PolicyValidation, MxcErrorCode::PolicyValidation),
            (
                ErrorCode::BackendUnavailable,
                MxcErrorCode::BackendUnavailable,
            ),
            (ErrorCode::Unsupported, MxcErrorCode::BackendError),
        ] {
            assert_eq!(map_error(Error::new(native, "detail")).code, expected);
        }
    }
}
