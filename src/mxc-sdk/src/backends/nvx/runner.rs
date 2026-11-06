// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Minimal create-and-run adapter for the signed bundled NVX agent.

use std::io::Write;
use std::os::windows::io::{AsRawHandle, OwnedHandle};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::time::{Duration, Instant};

use crate::mxc_common::audit::{AuditEvent, AuditEventName};
use crate::mxc_common::captured_run::{
    error_response, finish_with_cleanup, CapturedOutcome, CapturedRun,
};
use crate::mxc_common::logger::Logger;
use crate::mxc_common::models::{ExecutionRequest, ScriptResponse};
use crate::mxc_common::mxc_error::{MxcError, MxcErrorCode};
use crate::mxc_common::proxy_env::proxy_url_has_credentials;
use crate::mxc_common::sandbox_process::{SandboxProcess, StreamCloser};
use crate::mxc_common::script_runner::{RunCancellation, ScriptRunner};
use crate::mxc_common::state_aware_backend::{ExecHandle, ExecOutcome as MxcExecOutcome};

use super::runtime::{Event, NvxClient, PreparedProvision, SandboxClient};
#[cfg(test)]
use aci_edge_sandboxes::{Capabilities, ExecRequest};
use aci_edge_sandboxes::{ExecOutcome, ExecRequest as NativeExecRequest};

const BACKEND_LABEL: &str = "NVX";

#[derive(Debug, Default)]
pub struct NvxRunner {
    cancellation: RunCancellation,
}

impl NvxRunner {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn run_captured(
        &mut self,
        request: &ExecutionRequest,
        logger: &mut Logger,
    ) -> Result<CapturedRun, MxcError> {
        self.cancellation.begin();
        let result = self.run_captured_inner(request, logger);
        self.cancellation.complete();
        result
    }

    fn validate_dry_run(request: &ExecutionRequest) -> Result<(), MxcError> {
        super::policy::validate_request(request)?;
        let (_, mut client) = open_client()?;
        validate_with_client(&mut client, request)
    }

    fn run_captured_inner(
        &mut self,
        request: &ExecutionRequest,
        logger: &mut Logger,
    ) -> Result<CapturedRun, MxcError> {
        super::policy::validate_request(request)?;
        self.cancellation.check()?;
        let (state_root, mut client) = open_client()?;
        run_with_client(
            &mut client,
            &state_root,
            request,
            logger,
            Some(&self.cancellation),
        )
    }
}

fn open_client() -> Result<(PathBuf, NvxClient), MxcError> {
    let state_root = super::runtime::state_root()?;
    let path = state_root.path().to_path_buf();
    let client = super::runtime::create_persistent_client(state_root)?;
    Ok((path, client))
}

pub(super) fn request_has_sensitive_proxy(request: &ExecutionRequest) -> bool {
    request
        .policy
        .network_proxy
        .address
        .as_ref()
        .is_some_and(|proxy| proxy_url_has_credentials(&proxy.to_url()))
}

fn prepare_request(
    client: &impl SandboxClient,
    request: &ExecutionRequest,
) -> Result<(PreparedProvision, NativeExecRequest), MxcError> {
    let sensitive_proxy = request_has_sensitive_proxy(request);
    let protect = |operation, error| protect_native_error(error, operation, sensitive_proxy);
    let capabilities = client
        .capabilities()
        .map_err(|error| protect("capabilities", error))?;
    let (provision, spec) = super::policy::provision_request(request, &capabilities)?;
    let exec = super::policy::exec_request(request, &capabilities)?;
    let input = PreparedProvision {
        request: provision,
        spec,
    };
    client
        .validate_provision(&input)
        .map_err(|error| protect("validate_provision", error))?;
    client
        .validate_exec(&exec)
        .map_err(|error| protect("validate_exec", error))?;
    Ok((input, exec))
}

fn validate_with_client(
    client: &mut impl SandboxClient,
    request: &ExecutionRequest,
) -> Result<(), MxcError> {
    let sensitive_proxy = request_has_sensitive_proxy(request);
    let result = prepare_request(client, request).map(|_| ());
    let cleanup = client
        .close()
        .err()
        .map(|error| protect_native_error(error, "close", sensitive_proxy))
        .into_iter()
        .collect();
    finish_run(
        result,
        cleanup,
        &mut Logger::new(crate::mxc_common::logger::Mode::Buffer),
    )
}

fn run_with_client(
    client: &mut impl SandboxClient,
    state_root: &Path,
    request: &ExecutionRequest,
    logger: &mut Logger,
    cancellation: Option<&RunCancellation>,
) -> Result<CapturedRun, MxcError> {
    let sensitive_proxy = request_has_sensitive_proxy(request);
    let protect = |operation, error| protect_native_error(error, operation, sensitive_proxy);
    let prepared = prepare_and_provision(client, request, cancellation, logger);
    let (sandbox_id, exec) = match prepared {
        Ok(prepared) => prepared,
        Err(error) => {
            let cleanup = client
                .close()
                .err()
                .map(|close_error| protect("close", close_error))
                .into_iter()
                .collect();
            return finish_run(Err(error), cleanup, logger);
        }
    };

    let identity = sandbox_id.to_string();
    logger.log_audit_event(
        &AuditEvent::new(AuditEventName::SandboxIdentity)
            .str("identity", &identity)
            .str("backend", "microvm")
            .str("runtime", "signed-bundled-agent"),
    );
    let primary = (|| {
        if let Some(cancellation) = cancellation {
            cancellation.check()?;
        }
        start_sandbox(client, &sandbox_id, sensitive_proxy, logger)?;
        if let Some(cancellation) = cancellation {
            cancellation.check()?;
        }
        client
            .exec_and_wait(&sandbox_id, &exec, cancellation, logger)
            .map_err(|error| protect("exec", error))
    })();

    let cleanup_errors = cleanup_sandbox(
        client,
        &sandbox_id,
        state_root,
        primary.is_err(),
        sensitive_proxy,
        logger,
    );
    let output = finish_run(primary, cleanup_errors, logger)?;

    Ok(CapturedRun {
        outcome: map_outcome(output.outcome)?,
        warnings: Vec::new(),
        stdout: output.stdout,
        stderr: output.stderr,
        backend_label: BACKEND_LABEL,
    })
}

/// Starts the sandbox and logs how it booted: as a clone of a platform snapshot template, or cold,
/// and why.
pub(super) fn start_sandbox(
    client: &impl SandboxClient,
    sandbox_id: &super::runtime::SandboxId,
    sensitive_proxy: bool,
    logger: &mut Logger,
) -> Result<(), MxcError> {
    let started = client
        .start(sandbox_id)
        .map_err(|error| start_error(client, sandbox_id, error, sensitive_proxy))?;
    logger.log_diagnostic_line(&format!(
        "NVX sandbox started: {}",
        serde_json::Value::Object(started.metadata.unwrap_or_default())
    ));
    Ok(())
}

fn start_error(
    client: &impl SandboxClient,
    sandbox_id: &super::runtime::SandboxId,
    error: MxcError,
    sensitive_proxy: bool,
) -> MxcError {
    let mut error = protect_native_error(error, "start", sensitive_proxy);
    if sensitive_proxy {
        error.message.push_str("; startup diagnostics withheld");
    } else {
        error.message.push_str("; startup diagnostics");
        match client.diagnostics(sandbox_id) {
            Ok(diagnostics) => error
                .message
                .push_str(&super::runtime::startup_diagnostics(&diagnostics)),
            Err(diagnostic_error) => {
                error.message.push_str(" unavailable: ");
                error.message.push_str(&diagnostic_error.to_string());
            }
        }
    }
    error
}

fn prepare_and_provision(
    client: &mut impl SandboxClient,
    request: &ExecutionRequest,
    cancellation: Option<&RunCancellation>,
    logger: &mut Logger,
) -> Result<(super::runtime::SandboxId, NativeExecRequest), MxcError> {
    let sensitive_proxy = request_has_sensitive_proxy(request);
    let (input, exec) = prepare_request(client, request)?;
    prepare_execution(client, sensitive_proxy, cancellation, logger)?;
    let sandbox_id = client
        .provision(&input)
        .map_err(|error| protect_native_error(error, "provision", sensitive_proxy))?
        .sandbox_id;
    Ok((sandbox_id, exec))
}

pub(super) fn prepare_execution(
    client: &mut impl SandboxClient,
    sensitive_proxy: bool,
    cancellation: Option<&RunCancellation>,
    logger: &mut Logger,
) -> Result<(), MxcError> {
    if let Some(cancellation) = cancellation {
        cancellation.check()?;
    }
    client
        .probe()
        .map_err(|error| protect_native_error(error, "probe", sensitive_proxy))?;
    if let Some(cancellation) = cancellation {
        cancellation.check()?;
    }
    // Opening the execution host can capture templates, so validation and probing must precede it.
    if let Some(error) = client
        .open_execution_host()
        .map_err(|error| protect_native_error(error, "platform_snapshots", sensitive_proxy))?
    {
        logger.warning_line(&format!(
            "NVX platform snapshots are unavailable, so sandboxes cold boot: {}",
            protect_native_error(error, "platform_snapshots", sensitive_proxy)
        ));
    }
    if let Some(cancellation) = cancellation {
        cancellation.check()?;
    }
    Ok(())
}

struct StreamingSandbox {
    client: NvxClient,
    sandbox_id: super::runtime::SandboxId,
    state_root: PathBuf,
}

struct StreamingPipes {
    stdout_reader: std::io::PipeReader,
    stderr_reader: std::io::PipeReader,
    stdout_writer: crate::mxc_common::process_util::InterruptiblePipeWriter,
    stderr_writer: crate::mxc_common::process_util::InterruptiblePipeWriter,
    stdout_handle: windows::Win32::Foundation::HANDLE,
    stderr_handle: windows::Win32::Foundation::HANDLE,
}

#[derive(Clone, Copy)]
struct StreamExecutionOptions {
    timeout: Option<u64>,
    started: Instant,
    capture_limit: Option<usize>,
    sensitive_proxy: bool,
}

impl StreamingPipes {
    fn new() -> Result<Self, MxcError> {
        let (stdout_reader, stdout_writer) = std::io::pipe().map_err(|error| {
            MxcError::backend_error(format!("cannot create NVX stdout pipe: {error}"))
        })?;
        let (stderr_reader, stderr_writer) = std::io::pipe().map_err(|error| {
            MxcError::backend_error(format!("cannot create NVX stderr pipe: {error}"))
        })?;
        let stdout_handle = windows::Win32::Foundation::HANDLE(stdout_reader.as_raw_handle());
        let stderr_handle = windows::Win32::Foundation::HANDLE(stderr_reader.as_raw_handle());
        Ok(Self {
            stdout_reader,
            stderr_reader,
            stdout_writer: crate::mxc_common::process_util::InterruptiblePipeWriter::new(
                std::fs::File::from(OwnedHandle::from(stdout_writer)),
            ),
            stderr_writer: crate::mxc_common::process_util::InterruptiblePipeWriter::new(
                std::fs::File::from(OwnedHandle::from(stderr_writer)),
            ),
            stdout_handle,
            stderr_handle,
        })
    }

    fn into_handle(
        self,
        execution: super::runtime::StreamingExecution,
        timeout: Option<u64>,
        execution_started: Instant,
        capture_limit: Option<usize>,
        sensitive_proxy: bool,
        finish: impl FnOnce(Result<MxcExecOutcome, MxcError>) -> Result<MxcExecOutcome, MxcError>
            + Send
            + 'static,
    ) -> ExecHandle {
        let Self {
            stdout_reader,
            stderr_reader,
            stdout_writer,
            stderr_writer,
            stdout_handle,
            stderr_handle,
        } = self;
        let stdout_cancel = stdout_writer.canceller();
        let stderr_cancel = stderr_writer.canceller();
        let deadline_stdout = stdout_cancel.clone();
        let deadline_stderr = stderr_cancel.clone();
        let cancel_execution = execution.clone();
        let waiter = Box::new(move || {
            drop(stdout_reader);
            drop(stderr_reader);
            finish(stream_execution(
                &execution,
                stdout_writer,
                stderr_writer,
                (deadline_stdout, deadline_stderr),
                StreamExecutionOptions {
                    timeout,
                    started: execution_started,
                    capture_limit,
                    sensitive_proxy,
                },
            ))
        });
        let terminator = Box::new(move || {
            let result = cancel_execution
                .cancel()
                .map_err(|error| protect_native_error(error, "exec", sensitive_proxy));
            stdout_cancel.close();
            stderr_cancel.close();
            result
        });
        ExecHandle {
            stdout: stdout_handle,
            stderr: stderr_handle,
            stdin: crate::mxc_common::state_aware_backend::null_pipe_handle(),
            waiter,
            terminator,
            stdin_closer: None,
        }
    }
}

pub(crate) fn spawn_streaming(
    request: &ExecutionRequest,
    logger: &mut Logger,
    stdin: bool,
) -> Result<Box<dyn SandboxProcess>, MxcError> {
    if stdin {
        return Err(MxcError::unsupported_containment(
            "MicroVM streaming does not support writable stdin",
        ));
    }
    crate::mxc_common::validator::validate_common(request).map_err(|response| {
        if request.script_code.is_empty() {
            MxcError::malformed_request(response.error_message)
        } else {
            MxcError::policy_validation(response.error_message)
        }
    })?;
    super::policy::validate_request(request)?;
    let pipes = StreamingPipes::new()?;
    let sensitive_proxy = request_has_sensitive_proxy(request);
    let (state_root, mut client) = open_client()?;
    let (sandbox_id, exec) = match prepare_and_provision(&mut client, request, None, logger) {
        Ok(prepared) => prepared,
        Err(error) => {
            let mut cleanup = Vec::new();
            if let Err(close) = client.close() {
                cleanup.push(protect_native_error(close, "close", sensitive_proxy));
            }
            return finish_run(Err(error), cleanup, logger);
        }
    };
    logger.log_audit_event(
        &AuditEvent::new(AuditEventName::SandboxIdentity)
            .str("identity", &sandbox_id.to_string())
            .str("backend", "microvm")
            .str("runtime", "signed-bundled-agent"),
    );
    let started = start_sandbox(&client, &sandbox_id, sensitive_proxy, logger).and_then(|()| {
        let execution_started = Instant::now();
        client
            .start_execution(&sandbox_id, &exec)
            .map(|execution| (execution, execution_started))
            .map_err(|error| protect_native_error(error, "exec", sensitive_proxy))
    });
    let (execution, execution_started) = match started {
        Ok(execution) => execution,
        Err(error) => {
            let cleanup = cleanup_sandbox(
                &mut client,
                &sandbox_id,
                &state_root,
                true,
                sensitive_proxy,
                logger,
            );
            return finish_run(Err(error), cleanup, logger);
        }
    };
    let timeout = exec
        .process
        .timeout
        .map(|value| u64::try_from(value.as_millis()).unwrap_or(u64::MAX));
    let state_path = state_root.clone();
    let mut sandbox = StreamingSandbox {
        client,
        sandbox_id,
        state_root: state_root.clone(),
    };
    let handle = pipes.into_handle(
        execution,
        timeout,
        execution_started,
        None,
        sensitive_proxy,
        move |primary| {
            let mut logger = Logger::new(crate::mxc_common::logger::Mode::Buffer);
            let cleanup = cleanup_sandbox(
                &mut sandbox.client,
                &sandbox.sandbox_id,
                &sandbox.state_root,
                primary.is_err(),
                sensitive_proxy,
                &mut logger,
            );
            finish_run(primary, cleanup, &mut logger)
        },
    );
    crate::mxc_common::exec_stream::ExecSandboxProcess::from_exec_handle(handle)
        .map(|process| Box::new(process) as Box<dyn SandboxProcess>)
        .map_err(|mut error| {
            if state_path.exists() {
                error.message.push_str(&format!(
                    "; NVX agent state directory: {}",
                    state_path.display()
                ));
            }
            error
        })
}

pub(super) fn exec_existing(
    mut client: NvxClient,
    sandbox_id: super::runtime::SandboxId,
    request: &NativeExecRequest,
    stdio: crate::mxc_common::state_aware_backend::ExecStdio,
    capture_limit: Option<usize>,
    sensitive_proxy: bool,
) -> Result<ExecHandle, MxcError> {
    let prepared = (|| {
        let pipes = StreamingPipes::new()?;
        let execution_started = Instant::now();
        let execution = client
            .start_execution(&sandbox_id, request)
            .map_err(|error| protect_native_error(error, "exec", sensitive_proxy))?;
        Ok((pipes, execution, execution_started))
    })();
    let (pipes, execution, execution_started) = match prepared {
        Ok(prepared) => prepared,
        Err(error) => {
            let cleanup = client
                .close()
                .err()
                .map(|error| protect_native_error(error, "close", sensitive_proxy))
                .into_iter()
                .collect();
            return finish_run(
                Err(error),
                cleanup,
                &mut Logger::new(crate::mxc_common::logger::Mode::Buffer),
            );
        }
    };
    let timeout = request
        .process
        .timeout
        .map(|value| u64::try_from(value.as_millis()).unwrap_or(u64::MAX));
    Ok(pipes.into_handle(
        execution,
        timeout,
        execution_started,
        capture_limit,
        sensitive_proxy,
        move |primary| {
            let primary = match (stdio, primary) {
                (
                    crate::mxc_common::state_aware_backend::ExecStdio::Relayed,
                    Ok(MxcExecOutcome::TimedOut),
                ) => Err(MxcError::backend_error(
                    "NVX relayed exec timed out; workload deadline elapsed",
                )),
                (_, primary) => primary,
            };
            let cleanup = client
                .close()
                .err()
                .map(|error| protect_native_error(error, "close", sensitive_proxy))
                .into_iter()
                .collect();
            finish_run(
                primary,
                cleanup,
                &mut Logger::new(crate::mxc_common::logger::Mode::Buffer),
            )
        },
    ))
}

fn stream_execution(
    execution: &super::runtime::StreamingExecution,
    mut stdout: impl Write,
    mut stderr: impl Write,
    output_cancellers: (
        crate::mxc_common::process_util::PipeWriteCanceller,
        crate::mxc_common::process_util::PipeWriteCanceller,
    ),
    options: StreamExecutionOptions,
) -> Result<MxcExecOutcome, MxcError> {
    let StreamExecutionOptions {
        timeout,
        started,
        capture_limit,
        sensitive_proxy,
    } = options;
    let (stdout_cancel, stderr_cancel) = output_cancellers;
    let deadline = timeout
        .filter(|&value| value != 0)
        .and_then(|value| started.checked_add(Duration::from_millis(value)));
    let finished = Arc::new((Mutex::new(false), Condvar::new()));
    let timed_out = Arc::new(AtomicBool::new(false));
    let watchdog = if let Some(deadline) = deadline {
        let finished = Arc::clone(&finished);
        let timed_out = Arc::clone(&timed_out);
        let watchdog_execution = execution.clone();
        match std::thread::Builder::new()
            .name("mxc-nvx-deadline".to_owned())
            .spawn(move || {
                let (lock, signal) = &*finished;
                let done = lock.lock().unwrap_or_else(|error| error.into_inner());
                let (done, _) = signal
                    .wait_timeout_while(
                        done,
                        deadline.saturating_duration_since(Instant::now()),
                        |done| !*done,
                    )
                    .unwrap_or_else(|error| error.into_inner());
                if *done {
                    return Ok(());
                }
                timed_out.store(true, Ordering::Release);
                drop(done);
                let result = watchdog_execution.cancel();
                stdout_cancel.close();
                stderr_cancel.close();
                result
            }) {
            Ok(watchdog) => Some(watchdog),
            Err(error) => {
                let primary = Err(MxcError::backend_error(format!(
                    "cannot start NVX deadline worker: {error}"
                )));
                let cleanup = [execution.cancel().err(), execution.release().err()]
                    .into_iter()
                    .flatten()
                    .map(|error| protect_native_error(error, "exec", sensitive_proxy))
                    .collect();
                return finish_run(
                    primary,
                    cleanup,
                    &mut Logger::new(crate::mxc_common::logger::Mode::Buffer),
                );
            }
        }
    } else {
        None
    };
    let host_deadline = deadline.and_then(|deadline| deadline.checked_add(Duration::from_secs(30)));
    let mut captured_bytes = 0usize;
    let (primary, cancel_needed) = loop {
        let remaining = host_deadline.map(|deadline| {
            u64::try_from(
                deadline
                    .saturating_duration_since(Instant::now())
                    .as_millis(),
            )
            .unwrap_or(u64::MAX)
        });
        let event = execution.next(remaining, |event| match event {
            Event::Stdout(bytes) => {
                write_captured_stream(&mut stdout, &bytes, &mut captured_bytes, capture_limit)
                    .map(|()| None)
            }
            Event::Stderr(bytes) => {
                write_captured_stream(&mut stderr, &bytes, &mut captured_bytes, capture_limit)
                    .map(|()| None)
            }
            Event::Exit(result) => result.map(Some),
        });
        match event {
            Ok(Some(Ok(None))) => {}
            Ok(Some(Ok(Some(outcome)))) => {
                break (
                    match outcome {
                        ExecOutcome::Exited(code) => Ok(MxcExecOutcome::Exited(code)),
                        ExecOutcome::Signaled(signal) => {
                            Ok(MxcExecOutcome::Exited(128_i32.saturating_add(signal)))
                        }
                        ExecOutcome::TimedOut => Ok(MxcExecOutcome::TimedOut),
                        ExecOutcome::Cancelled => Ok(MxcExecOutcome::Exited(137)),
                        other => Err(MxcError::backend_error(format!(
                            "NVX workload did not complete normally: {other}"
                        ))),
                    },
                    false,
                )
            }
            Ok(Some(Err(error))) | Err(error) => break (Err(error), true),
            Ok(None) => break (Ok(MxcExecOutcome::TimedOut), true),
        }
    };
    let mut cleanup = Vec::new();
    {
        let (lock, signal) = &*finished;
        *lock.lock().unwrap_or_else(|error| error.into_inner()) = true;
        signal.notify_all();
    }
    if let Some(watchdog) = watchdog {
        match watchdog.join() {
            Ok(Ok(())) => {}
            Ok(Err(error)) => cleanup.push(protect_native_error(error, "exec", sensitive_proxy)),
            Err(_) => cleanup.push(MxcError::backend_error("NVX deadline worker panicked")),
        }
    }
    if cancel_needed {
        if let Err(error) = execution.cancel() {
            cleanup.push(protect_native_error(error, "exec", sensitive_proxy));
        }
    }
    if let Err(error) = execution.release() {
        cleanup.push(protect_native_error(error, "exec", sensitive_proxy));
    }
    let primary = primary
        .map(|outcome| {
            if timed_out.load(Ordering::Acquire) {
                MxcExecOutcome::TimedOut
            } else {
                outcome
            }
        })
        .map_err(|error| protect_native_error(error, "exec", sensitive_proxy));
    finish_run(
        primary,
        cleanup,
        &mut Logger::new(crate::mxc_common::logger::Mode::Buffer),
    )
}

fn write_captured_stream(
    stream: &mut impl Write,
    bytes: &[u8],
    captured_bytes: &mut usize,
    capture_limit: Option<usize>,
) -> Result<(), MxcError> {
    if let Some(limit) = capture_limit {
        let next = captured_bytes
            .checked_add(bytes.len())
            .ok_or_else(|| super::runtime::capture_limit_error(limit))?;
        if next > limit {
            return Err(super::runtime::capture_limit_error(limit));
        }
        *captured_bytes = next;
    }
    write_stream(stream, bytes)
}

fn write_stream(writer: &mut impl Write, bytes: &[u8]) -> Result<(), MxcError> {
    match writer.write_all(bytes) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::BrokenPipe => Ok(()),
        Err(error) => Err(MxcError::backend_error(format!(
            "cannot relay NVX output: {error}"
        ))),
    }
}

fn cleanup_sandbox(
    client: &mut impl SandboxClient,
    sandbox_id: &super::runtime::SandboxId,
    state_root: &Path,
    primary_failed: bool,
    sensitive_proxy: bool,
    logger: &mut Logger,
) -> Vec<MxcError> {
    let protect = |operation, error| protect_native_error(error, operation, sensitive_proxy);
    let stop_error = match client.stop(sandbox_id).err() {
        Some(error) if primary_failed && error.code == MxcErrorCode::AlreadyStopped => None,
        other => other.map(|error| protect("stop", error)),
    };
    let deprovision_error = client
        .deprovision(sandbox_id)
        .err()
        .map(|error| protect("deprovision", error));
    let retain_state = deprovision_error.is_some();
    let close_error = client.close().err().map(|error| protect("close", error));
    let mut cleanup_errors: Vec<MxcError> = [stop_error, deprovision_error, close_error]
        .into_iter()
        .flatten()
        .collect();
    if retain_state {
        cleanup_errors.push(MxcError::backend_error(format!(
            "NVX sandbox records remain in the agent state directory after deprovision failure: {}",
            state_root.display()
        )));
    }
    logger.log_audit_event(
        &AuditEvent::new(AuditEventName::SandboxTornDown)
            .str("identity", &sandbox_id.to_string())
            .str("backend", "microvm")
            .str(
                "status",
                if cleanup_errors.is_empty() {
                    "ok"
                } else {
                    "failed"
                },
            )
            .bool("state_retained", retain_state),
    );
    cleanup_errors
}

pub(super) fn protect_native_error(
    mut error: MxcError,
    operation: &str,
    sensitive_proxy: bool,
) -> MxcError {
    if !sensitive_proxy {
        return error;
    }

    error.details = None;
    error.api_failure = None;
    error.remediation = None;

    if operation == "exec" {
        let (primary, cleanup) = match error.message.split_once("; cleanup failure: ") {
            Some((primary, _)) => (primary, true),
            None => (error.message.as_str(), false),
        };
        let capture_limit =
            super::runtime::capture_limit_error(super::runtime::CAPTURE_LIMIT_BYTES);
        if primary == "execution cancelled"
            || primary == capture_limit.message
            || primary == super::runtime::UNKNOWN_OUTCOME
            || primary == super::runtime::CANCEL_UNFINISHED
        {
            if cleanup {
                error.message = format!(
                    "{primary}; execution cleanup failed; native error detail withheld to protect potentially sensitive proxy configuration"
                );
            }
            return error;
        }
    }
    error.message = format!(
        "NVX {operation} failed; native error detail withheld to protect potentially sensitive proxy configuration"
    );
    error
}

pub(super) fn finish_run<T>(
    primary: Result<T, MxcError>,
    cleanup_errors: Vec<MxcError>,
    logger: &mut Logger,
) -> Result<T, MxcError> {
    finish_with_cleanup(BACKEND_LABEL, primary, cleanup_errors, logger)
}

impl ScriptRunner for NvxRunner {
    fn cancellation(&self) -> Option<RunCancellation> {
        Some(self.cancellation.clone())
    }

    fn validate_runner(&self, request: &ExecutionRequest) -> Result<(), ScriptResponse> {
        let result = if request.dry_run {
            Self::validate_dry_run(request)
        } else {
            super::policy::validate_request(request)
        };
        result.map_err(error_response)
    }

    fn execute(&mut self, request: &ExecutionRequest, logger: &mut Logger) -> ScriptResponse {
        let result = self.run_captured(request, logger).and_then(|result| {
            result.relay(&mut std::io::stdout().lock(), &mut std::io::stderr().lock())
        });
        match result {
            Ok(response) => response,
            Err(error) => error_response(error),
        }
    }
}

fn map_outcome(outcome: ExecOutcome) -> Result<CapturedOutcome, MxcError> {
    match outcome {
        ExecOutcome::Exited(code) => Ok(CapturedOutcome::Exited(code)),
        ExecOutcome::TimedOut => Ok(CapturedOutcome::TimedOut),
        ExecOutcome::Signaled(signal) => {
            Ok(CapturedOutcome::Exited(128_i32.saturating_add(signal)))
        }
        other => Err(MxcError::backend_error(format!(
            "NVX workload did not complete normally: {other}"
        ))),
    }
}

#[cfg(test)]
mod tests {
    use std::cell::RefCell;
    use std::io::Write;

    use super::super::runtime::{ExecOutput, ProvisionOutput, SandboxId};
    use super::*;
    use crate::mxc_common::models::FailurePhase;
    use aci_edge_sandboxes::agent::SandboxDiagnostics;
    use aci_edge_sandboxes::{BootMode, ColdReason, StartResult};

    fn test_capabilities() -> Capabilities {
        let mut capabilities = Capabilities::default();
        capabilities.exec.command_line = true;
        capabilities.exec.cwd = true;
        capabilities.exec.env = true;
        capabilities.spec.image_reference = true;
        capabilities.filesystem.readonly_paths = true;
        capabilities.filesystem.readwrite_paths = true;
        capabilities.filesystem.denied_paths = true;
        capabilities.network.egress_deny = true;
        capabilities.network.ingress_deny = true;
        capabilities.network.host_loopback_deny = true;
        capabilities
    }

    fn test_request() -> ExecutionRequest {
        ExecutionRequest {
            microvm_image: Some("docker.io/library/python:3.12-alpine".to_owned()),
            ..Default::default()
        }
    }

    #[test]
    fn maps_exit_signal_and_timeout_outcomes() {
        assert_eq!(
            map_outcome(ExecOutcome::Exited(42)).unwrap(),
            CapturedOutcome::Exited(42)
        );
        assert_eq!(
            map_outcome(ExecOutcome::Signaled(9)).unwrap(),
            CapturedOutcome::Exited(137)
        );
        assert_eq!(
            map_outcome(ExecOutcome::TimedOut).unwrap(),
            CapturedOutcome::TimedOut
        );
    }

    #[test]
    fn cancelled_runner_disarms_after_cleanup_and_can_be_reused() {
        let mut runner = NvxRunner::new();
        let signal = runner.cancellation().unwrap();
        assert!(signal.request());
        let request = ExecutionRequest {
            script_code: "printf test".to_owned(),
            ..test_request()
        };
        let error = runner
            .run_captured(
                &request,
                &mut Logger::new(crate::mxc_common::logger::Mode::Buffer),
            )
            .unwrap_err();
        assert_eq!(error.message, "execution cancelled");
        assert!(signal.was_cancelled());
        assert!(
            !signal.request(),
            "a finished backend must not claim output-relay interruption"
        );
        signal.begin();
        assert!(signal.check().is_ok());
        assert!(!signal.was_cancelled());
    }

    #[test]
    fn rejects_non_terminal_success_outcomes() {
        assert!(map_outcome(ExecOutcome::Cancelled).is_err());
    }

    #[test]
    fn executor_adapter_names_nvx_in_timeout_and_relay_failures() {
        let run = |outcome| CapturedRun {
            outcome,
            warnings: Vec::new(),
            stdout: b"partial-out\xff".to_vec(),
            stderr: b"partial-err\x80".to_vec(),
            backend_label: BACKEND_LABEL,
        };
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        let response = run(CapturedOutcome::TimedOut)
            .relay(&mut stdout, &mut stderr)
            .unwrap();
        assert_eq!(response.exit_code, -1);
        assert_eq!(response.failure_phase, FailurePhase::Timeout);
        assert_eq!(response.error_message, "NVX workload timed out");
        assert_eq!(stdout, b"partial-out\xff");
        assert_eq!(stderr, b"partial-err\x80");

        struct FailingWriter;

        impl Write for FailingWriter {
            fn write(&mut self, _bytes: &[u8]) -> std::io::Result<usize> {
                Err(std::io::Error::other("test write failure"))
            }

            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }

        let error = run(CapturedOutcome::Exited(0))
            .relay(&mut FailingWriter, &mut std::io::sink())
            .unwrap_err();
        assert_eq!(error.code, MxcErrorCode::BackendError);
        assert_eq!(error.message, "cannot relay NVX stdout: test write failure");
    }

    #[test]
    fn cleanup_failure_is_not_success_and_preserves_primary_error() {
        let mut logger = Logger::new(crate::mxc_common::logger::Mode::Buffer);
        let cleanup = || vec![MxcError::backend_error("deprovision failed")];
        let success = finish_run(Ok(42), cleanup(), &mut logger).unwrap_err();
        assert!(success
            .message
            .contains("cleanup failed after workload completion"));

        let failure = finish_run::<()>(
            Err(MxcError::backend_unavailable("start failed")),
            cleanup(),
            &mut logger,
        )
        .unwrap_err();
        assert_eq!(failure.code, MxcErrorCode::BackendUnavailable);
        assert!(failure.message.contains("start failed"));
        assert!(failure.message.contains("deprovision failed"));
    }

    #[test]
    fn process_mapping_preserves_command_timeout_cwd_and_environment_presence() {
        let mut capabilities = Capabilities::default();
        capabilities.exec.command_line = true;
        capabilities.exec.cwd = true;
        capabilities.exec.env = true;
        let request = ExecutionRequest {
            script_code: "printf '%s' \"$KEY\"".to_owned(),
            working_directory: "/tmp".to_owned(),
            script_timeout: 250,
            env: Some(Vec::new()),
            inherit_default_env: true,
            microvm_image: Some("docker.io/library/python:3.12-alpine".to_owned()),
            ..Default::default()
        };
        let mapped = super::super::policy::exec_request(&request, &capabilities).unwrap();
        assert_eq!(
            mapped.process.command,
            aci_edge_sandboxes::Command::CommandLine(request.script_code.clone())
        );
        assert_eq!(
            mapped.process.timeout,
            Some(std::time::Duration::from_millis(250))
        );
        assert_eq!(mapped.process.cwd.as_deref(), Some("/tmp"));
        assert_eq!(mapped.process.env, Some(Vec::new()));
        assert_eq!(mapped.process.inherit_default_env, Some(true));

        let defaults = super::super::policy::exec_request(
            &ExecutionRequest {
                microvm_image: Some("docker.io/library/python:3.12-alpine".to_owned()),
                ..Default::default()
            },
            &capabilities,
        )
        .unwrap();
        assert_eq!(defaults.process.env, None);
        assert_eq!(defaults.process.timeout, None);
        assert_eq!(defaults.process.cwd, None);
    }

    struct MockClient {
        calls: RefCell<Vec<&'static str>>,
        validated_request: RefCell<Option<ExecRequest>>,
        executed_request: RefCell<Option<ExecRequest>>,
        validated_provision: RefCell<Option<PreparedProvision>>,
        provisioned_input: RefCell<Option<PreparedProvision>>,
        capabilities_res: Result<Capabilities, MxcError>,
        validate_provision_res: Result<(), MxcError>,
        validate_res: Result<(), MxcError>,
        platform_snapshots_res: Result<Option<MxcError>, MxcError>,
        probe_res: Result<(), MxcError>,
        provision_res: Result<SandboxId, MxcError>,
        start_res: Result<StartResult, MxcError>,
        diagnostics_res: Result<SandboxDiagnostics, MxcError>,
        exec_res: Result<ExecOutput, MxcError>,
        stop_res: Result<(), MxcError>,
        deprovision_res: Result<(), MxcError>,
        close_res: Result<(), MxcError>,
        cancel_at: Option<(&'static str, RunCancellation)>,
    }

    impl MockClient {
        fn ok() -> Self {
            Self {
                calls: RefCell::new(Vec::new()),
                validated_request: RefCell::new(None),
                executed_request: RefCell::new(None),
                validated_provision: RefCell::new(None),
                provisioned_input: RefCell::new(None),
                capabilities_res: Ok(test_capabilities()),
                validate_provision_res: Ok(()),
                validate_res: Ok(()),
                platform_snapshots_res: Ok(None),
                probe_res: Ok(()),
                provision_res: SandboxId::from_token("0123456789abcdef0123456789abcdef")
                    .map_err(super::super::runtime::map_error),
                start_res: Ok(StartResult::default().with_boot_mode(BootMode::Clone)),
                diagnostics_res: Err(MxcError::backend_error("diagnostics unavailable")),
                exec_res: Ok(ExecOutput {
                    outcome: ExecOutcome::Exited(0),
                    stdout: b"ok".to_vec(),
                    stderr: Vec::new(),
                }),
                stop_res: Ok(()),
                deprovision_res: Ok(()),
                close_res: Ok(()),
                cancel_at: None,
            }
        }

        fn record(&self, phase: &'static str) {
            self.calls.borrow_mut().push(phase);
            if let Some((at, cancellation)) = &self.cancel_at {
                if *at == phase {
                    cancellation.request();
                }
            }
        }
    }

    impl SandboxClient for MockClient {
        fn capabilities(&self) -> Result<Capabilities, MxcError> {
            self.calls.borrow_mut().push("capabilities");
            self.capabilities_res.clone()
        }

        fn validate_provision(&self, input: &PreparedProvision) -> Result<(), MxcError> {
            self.calls.borrow_mut().push("validate_provision");
            *self.validated_provision.borrow_mut() = Some(input.clone());
            self.validate_provision_res.clone()
        }

        fn validate_exec(&self, request: &ExecRequest) -> Result<(), MxcError> {
            self.record("validate");
            *self.validated_request.borrow_mut() = Some(request.clone());
            self.validate_res.clone()
        }

        fn open_execution_host(&mut self) -> Result<Option<MxcError>, MxcError> {
            self.record("platform_snapshots");
            self.platform_snapshots_res.clone()
        }

        fn probe(&self) -> Result<(), MxcError> {
            self.record("probe");
            self.probe_res.clone()
        }

        fn provision(&self, input: &PreparedProvision) -> Result<ProvisionOutput, MxcError> {
            self.record("provision");
            *self.provisioned_input.borrow_mut() = Some(input.clone());
            self.provision_res
                .clone()
                .map(|sandbox_id| ProvisionOutput {
                    sandbox_id,
                    metadata: None,
                })
        }

        fn start(&self, _sandbox_id: &SandboxId) -> Result<StartResult, MxcError> {
            self.record("start");
            self.start_res.clone()
        }

        fn diagnostics(&self, _sandbox_id: &SandboxId) -> Result<SandboxDiagnostics, MxcError> {
            self.calls.borrow_mut().push("diagnostics");
            self.diagnostics_res.clone()
        }

        fn exec_and_wait(
            &self,
            _sandbox_id: &SandboxId,
            request: &ExecRequest,
            cancellation: Option<&RunCancellation>,
            _logger: &mut Logger,
        ) -> Result<ExecOutput, MxcError> {
            self.record("exec");
            if let Some(cancellation) = cancellation {
                cancellation.check()?;
            }
            *self.executed_request.borrow_mut() = Some(request.clone());
            self.exec_res.clone()
        }

        fn stop(&self, _sandbox_id: &SandboxId) -> Result<(), MxcError> {
            self.calls.borrow_mut().push("stop");
            self.stop_res.clone()
        }

        fn deprovision(&self, _sandbox_id: &SandboxId) -> Result<(), MxcError> {
            self.calls.borrow_mut().push("deprovision");
            self.deprovision_res.clone()
        }

        fn close(&mut self) -> Result<(), MxcError> {
            self.calls.borrow_mut().push("close");
            self.close_res.clone()
        }
    }

    #[test]
    fn native_validation_errors_have_the_same_response_and_cleanup_in_both_paths() {
        for validation in ["provision", "exec"] {
            for cleanup_fails in [false, true] {
                let mut responses = Vec::new();
                for dry_run in [false, true] {
                    let mut client = MockClient::ok();
                    let error = MxcError::malformed_request("native malformed input");
                    if validation == "provision" {
                        client.validate_provision_res = Err(error);
                    } else {
                        client.validate_res = Err(error);
                    }
                    if cleanup_fails {
                        client.close_res = Err(MxcError::backend_error("close failed"));
                    }
                    let state_root = tempfile::tempdir().unwrap();
                    let error = if dry_run {
                        validate_with_client(&mut client, &test_request()).unwrap_err()
                    } else {
                        run_with_client(
                            &mut client,
                            state_root.path(),
                            &test_request(),
                            &mut Logger::new(crate::mxc_common::logger::Mode::Buffer),
                            None,
                        )
                        .unwrap_err()
                    };
                    assert_eq!(error.code, MxcErrorCode::MalformedRequest);
                    let response = error_response(error);
                    assert_eq!(response.failure_phase, FailurePhase::Rejected);
                    assert_eq!(response.exit_code, 1);
                    assert_eq!(
                        response.failure_phase.error_code(),
                        MxcErrorCode::PolicyValidation
                    );
                    assert!(response.error_message.starts_with("native malformed input"));
                    assert_eq!(
                        response.error_message.contains("close failed"),
                        cleanup_fails
                    );
                    let expected: &[&str] = if validation == "provision" {
                        &["capabilities", "validate_provision", "close"]
                    } else {
                        &["capabilities", "validate_provision", "validate", "close"]
                    };
                    assert_eq!(*client.calls.borrow(), expected);
                    responses.push(response);
                }
                assert_eq!(responses[0].error_message, responses[1].error_message);
            }
        }
    }

    #[test]
    fn dry_run_prepares_and_closes_without_probing_or_provisioning() {
        for failure in ["none", "capabilities", "provision", "exec", "close", "both"] {
            let mut client = MockClient::ok();
            match failure {
                "capabilities" => {
                    client.capabilities_res =
                        Err(MxcError::backend_unavailable("missing capability"));
                }
                "provision" | "both" => {
                    client.validate_provision_res = Err(MxcError::policy_validation("bad policy"));
                    if failure == "both" {
                        client.close_res = Err(MxcError::backend_error("close failed"));
                    }
                }
                "exec" => client.validate_res = Err(MxcError::policy_validation("bad process")),
                "close" => client.close_res = Err(MxcError::backend_error("close failed")),
                _ => {}
            }
            let result = validate_with_client(&mut client, &test_request());
            assert_eq!(result.is_ok(), failure == "none", "{failure}: {result:?}");
            if failure == "capabilities" {
                let error = result.unwrap_err();
                assert_eq!(error.code, MxcErrorCode::BackendUnavailable);
                assert_eq!(error.message, "missing capability");
            } else if failure == "provision" {
                assert_eq!(result.unwrap_err().message, "bad policy");
            } else if failure == "exec" {
                assert_eq!(result.unwrap_err().message, "bad process");
            } else if failure == "close" {
                assert!(result.unwrap_err().message.contains("close failed"));
            } else if failure == "both" {
                let error = result.unwrap_err();
                assert_eq!(error.code, MxcErrorCode::PolicyValidation);
                assert!(error.message.starts_with("bad policy; cleanup failure: "));
                assert!(error.message.contains("close failed"));
            }
            let expected: &[&str] = if failure == "capabilities" {
                &["capabilities", "close"]
            } else if matches!(failure, "provision" | "both") {
                &["capabilities", "validate_provision", "close"]
            } else {
                &["capabilities", "validate_provision", "validate", "close"]
            };
            assert_eq!(*client.calls.borrow(), expected, "{failure}");
        }
    }

    #[test]
    fn dry_run_rejects_ingress_capabilities_not_advertised_by_the_runtime() {
        let mut client = MockClient::ok();
        let mut request = test_request();
        request.policy.network_specified = true;
        request.policy.network_ingress = Some(crate::mxc_common::models::NetworkIngressPolicy {
            default: crate::mxc_common::models::NetworkAction::Allow,
            ..Default::default()
        });
        let error = validate_with_client(&mut client, &request).unwrap_err();
        assert_eq!(error.code, MxcErrorCode::PolicyValidation);
        assert!(error.message.contains("network.ingress.default=allow"));
        assert_eq!(*client.calls.borrow(), ["capabilities", "close"]);
    }

    #[test]
    fn dry_run_withholds_native_proxy_credentials() {
        let mut client = MockClient::ok();
        client
            .capabilities_res
            .as_mut()
            .unwrap()
            .network
            .network_proxy = true;
        client.validate_provision_res = Err(MxcError::policy_validation("native synthetic secret"));
        let error = validate_with_client(
            &mut client,
            &request_with_proxy("http://synthetic:secret@localhost:3128"),
        )
        .unwrap_err();
        assert_eq!(error.code, MxcErrorCode::PolicyValidation);
        assert!(error.message.contains("validate_provision"));
        assert!(error.message.contains("withheld"));
        assert!(!format!("{error:?}").contains("synthetic"));
        assert_eq!(
            *client.calls.borrow(),
            ["capabilities", "validate_provision", "close"]
        );
    }

    fn request_with_proxy(url: &str) -> ExecutionRequest {
        let mut request = test_request();
        request.policy.runtime_network_proxy_specified = true;
        request.policy.network_proxy.address = Some(
            crate::mxc_common::models::ProxyAddress::from_url(url, "localhost".to_owned(), 3128),
        );
        request
    }

    #[test]
    fn credential_proxy_withholds_native_errors_and_preserves_input() {
        let proxy = "http://synthetic%3Auser:synthetic%40secret@localhost:3128";
        for phase in [
            "capabilities",
            "validate_provision",
            "validate_exec",
            "probe",
            "platform_snapshots",
            "provision",
            "start",
            "exec",
        ] {
            let mut client = MockClient::ok();
            client
                .capabilities_res
                .as_mut()
                .unwrap()
                .network
                .network_proxy = true;
            let failure = MxcError::policy_validation("native synthetic@secret fragment")
                .with_details(serde_json::json!({"native": "synthetic detail"}))
                .with_api_failure(
                    crate::mxc_common::mxc_error::ApiFailure::new("synthetic operation")
                        .with_native_code("synthetic code"),
                )
                .with_remediation("synthetic remediation");
            match phase {
                "capabilities" => client.capabilities_res = Err(failure),
                "validate_provision" => client.validate_provision_res = Err(failure),
                "validate_exec" => client.validate_res = Err(failure),
                "platform_snapshots" => client.platform_snapshots_res = Err(failure),
                "probe" => client.probe_res = Err(failure),
                "provision" => client.provision_res = Err(failure),
                "start" => client.start_res = Err(failure),
                "exec" => client.exec_res = Err(failure),
                _ => unreachable!(),
            }
            let mut logger = Logger::new(crate::mxc_common::logger::Mode::Buffer);
            let error = run_with_client(
                &mut client,
                Path::new("state"),
                &request_with_proxy(proxy),
                &mut logger,
                None,
            )
            .unwrap_err();
            assert_eq!(error.code, MxcErrorCode::PolicyValidation, "{phase}");
            assert!(error.message.contains(phase), "{phase}: {}", error.message);
            assert!(
                error.message.contains("withheld"),
                "{phase}: {}",
                error.message
            );
            assert!(
                !error.message.contains("synthetic"),
                "{phase}: {}",
                error.message
            );
            assert!(!format!("{error:?}").contains("synthetic"), "{phase}");
            assert!(
                !serde_json::to_string(&error.to_envelope())
                    .unwrap()
                    .contains("synthetic"),
                "{phase}"
            );
            assert!(!logger.get_buffer().contains("synthetic"), "{phase}");
            if phase != "capabilities" {
                let input = client.validated_provision.borrow();
                assert_eq!(
                    input
                        .as_ref()
                        .unwrap()
                        .request
                        .runtime_config
                        .as_ref()
                        .unwrap()
                        .network_proxy
                        .as_deref(),
                    Some(proxy),
                    "{phase}"
                );
            }
            if phase == "start" {
                assert!(error.message.contains("startup diagnostics withheld"));
                assert!(!client.calls.borrow().contains(&"diagnostics"));
            }
        }
    }

    #[test]
    fn credential_proxy_withholds_cleanup_errors_before_logging() {
        let mut client = MockClient::ok();
        client
            .capabilities_res
            .as_mut()
            .unwrap()
            .network
            .network_proxy = true;
        client.start_res = Err(MxcError::backend_error("synthetic primary detail"));
        client.stop_res = Err(MxcError::backend_error("synthetic cleanup detail"));
        client.close_res = Err(MxcError::backend_error("synthetic close detail"));
        let mut logger = Logger::new(crate::mxc_common::logger::Mode::Buffer);
        let error = run_with_client(
            &mut client,
            Path::new("state"),
            &request_with_proxy("http://user:synthetic-secret@localhost:3128"),
            &mut logger,
            None,
        )
        .unwrap_err();
        assert!(error.message.contains("start"));
        assert!(error.message.contains("stop"));
        assert!(error.message.contains("close"));
        assert!(error.message.contains("withheld"));
        assert!(!error.message.contains("synthetic"));
        assert!(!logger.get_buffer().contains("synthetic"));
        assert!(logger
            .warnings()
            .iter()
            .all(|warning| !warning.contains("synthetic")));
    }

    #[test]
    fn credential_proxy_preserves_local_execution_failures() {
        for message in [
            "execution cancelled",
            "NVX signed bundled agent: combined stdout/stderr capture limit of 67108864 bytes exceeded",
            super::super::runtime::UNKNOWN_OUTCOME,
            super::super::runtime::CANCEL_UNFINISHED,
        ] {
            for cleanup_failure in [false, true] {
                let mut client = MockClient::ok();
                client
                    .capabilities_res
                    .as_mut()
                    .unwrap()
                    .network
                    .network_proxy = true;
                let detail = if cleanup_failure {
                    format!("{message}; cleanup failure: synthetic secret")
                } else {
                    message.to_owned()
                };
                client.exec_res = Err(MxcError::backend_error(detail));
                let error = run_with_client(
                    &mut client,
                    Path::new("state"),
                    &request_with_proxy("http://user:synthetic-secret@localhost:3128"),
                    &mut Logger::new(crate::mxc_common::logger::Mode::Buffer),
                    None,
                )
                .unwrap_err();
                assert!(error.message.starts_with(message), "{}", error.message);
                assert!(!error.message.contains("synthetic"), "{}", error.message);
                if cleanup_failure {
                    assert!(error.message.contains("withheld"), "{}", error.message);
                } else {
                    assert_eq!(error.message, message);
                }
            }
        }
    }

    #[test]
    fn credential_free_proxy_keeps_native_diagnostics() {
        let mut client = MockClient::ok();
        client
            .capabilities_res
            .as_mut()
            .unwrap()
            .network
            .network_proxy = true;
        client.start_res = Err(MxcError::backend_error("native start detail"));
        let error = run_with_client(
            &mut client,
            Path::new("state"),
            &request_with_proxy("http://localhost:3128"),
            &mut Logger::new(crate::mxc_common::logger::Mode::Buffer),
            None,
        )
        .unwrap_err();
        assert!(error.message.contains("native start detail"));
        assert!(error.message.contains("diagnostics unavailable"));
        assert!(!error.message.contains("withheld"));
        assert!(client.calls.borrow().contains(&"diagnostics"));
    }

    #[test]
    fn credential_proxy_keeps_runtime_input_and_captured_output() {
        let proxy = "http://synthetic%3Auser:synthetic%40secret@localhost:3128";
        let mut client = MockClient::ok();
        client
            .capabilities_res
            .as_mut()
            .unwrap()
            .network
            .network_proxy = true;
        let result = run_with_client(
            &mut client,
            Path::new("state"),
            &request_with_proxy(proxy),
            &mut Logger::new(crate::mxc_common::logger::Mode::Buffer),
            None,
        )
        .unwrap();
        assert_eq!(result.outcome, CapturedOutcome::Exited(0));
        assert_eq!(result.stdout, b"ok");
        for input in [&client.validated_provision, &client.provisioned_input] {
            assert_eq!(
                input
                    .borrow()
                    .as_ref()
                    .unwrap()
                    .request
                    .runtime_config
                    .as_ref()
                    .unwrap()
                    .network_proxy
                    .as_deref(),
                Some(proxy)
            );
        }
    }

    #[test]
    fn credential_proxy_withholds_retained_state_cleanup_error() {
        let state_root = tempfile::tempdir().unwrap();
        let mut client = MockClient::ok();
        client
            .capabilities_res
            .as_mut()
            .unwrap()
            .network
            .network_proxy = true;
        client.deprovision_res = Err(MxcError::backend_error("synthetic secret"));
        let error = run_with_client(
            &mut client,
            state_root.path(),
            &request_with_proxy("http://user:synthetic-secret@localhost:3128"),
            &mut Logger::new(crate::mxc_common::logger::Mode::Buffer),
            None,
        )
        .unwrap_err();
        assert!(error.message.contains("deprovision"));
        assert!(error.message.contains("withheld"));
        assert!(error.message.contains(&format!(
            "records remain in the agent state directory after deprovision failure: {}",
            state_root.path().display()
        )));
        assert!(!error.message.contains("synthetic"));
    }

    #[test]
    fn cancellation_during_startup_or_execution_runs_ordered_teardown() {
        for phase in [
            "validate",
            "probe",
            "platform_snapshots",
            "provision",
            "start",
            "exec",
        ] {
            for cleanup_fails in [false, true] {
                let cancellation = RunCancellation::default();
                let mut client = MockClient::ok();
                client.cancel_at = Some((phase, cancellation.clone()));
                if cleanup_fails {
                    client.close_res = Err(MxcError::backend_error("host_close failed"));
                }
                let state_root = tempfile::tempdir().unwrap();
                let error = run_with_client(
                    &mut client,
                    state_root.path(),
                    &test_request(),
                    &mut Logger::new(crate::mxc_common::logger::Mode::Buffer),
                    Some(&cancellation),
                )
                .unwrap_err();
                assert_eq!(error.code, MxcErrorCode::BackendError);
                assert!(error.message.starts_with("execution cancelled"));
                assert!(cancellation.was_cancelled());
                let expected: &[&str] = match phase {
                    "validate" => &["validate", "close"],
                    "probe" => &["validate", "probe", "close"],
                    "platform_snapshots" => &["validate", "probe", "platform_snapshots", "close"],
                    "provision" => &[
                        "validate",
                        "probe",
                        "platform_snapshots",
                        "provision",
                        "stop",
                        "deprovision",
                        "close",
                    ],
                    "start" => &[
                        "validate",
                        "probe",
                        "platform_snapshots",
                        "provision",
                        "start",
                        "stop",
                        "deprovision",
                        "close",
                    ],
                    _ => &[
                        "validate",
                        "probe",
                        "platform_snapshots",
                        "provision",
                        "start",
                        "exec",
                        "stop",
                        "deprovision",
                        "close",
                    ],
                };
                let expected: Vec<_> = ["capabilities", "validate_provision"]
                    .into_iter()
                    .chain(expected.iter().copied())
                    .collect();
                assert_eq!(*client.calls.borrow(), expected);
                if cleanup_fails {
                    assert!(error.message.contains("cleanup failure"));
                    assert!(error.message.contains("host_close failed"));
                } else {
                    assert_eq!(error.message, "execution cancelled");
                }
            }
        }
    }

    #[test]
    fn start_failure_wins_over_a_racing_cancellation() {
        let cancellation = RunCancellation::default();
        let mut client = MockClient::ok();
        client.cancel_at = Some(("start", cancellation.clone()));
        client.start_res = Err(MxcError::backend_unavailable("primary start failure"));
        let state_root = tempfile::tempdir().unwrap();
        let error = run_with_client(
            &mut client,
            state_root.path(),
            &test_request(),
            &mut Logger::new(crate::mxc_common::logger::Mode::Buffer),
            Some(&cancellation),
        )
        .unwrap_err();
        assert_eq!(error.code, MxcErrorCode::BackendUnavailable);
        assert!(error
            .message
            .starts_with("primary start failure; startup diagnostics unavailable"));
        assert!(
            !cancellation.was_cancelled(),
            "the primary failure must keep its category"
        );
        assert_eq!(
            client.calls.borrow().as_slice(),
            [
                "capabilities",
                "validate_provision",
                "validate",
                "probe",
                "platform_snapshots",
                "provision",
                "start",
                "diagnostics",
                "stop",
                "deprovision",
                "close"
            ]
        );
    }

    #[test]
    fn startup_diagnostics_survive_cleanup_with_bounded_logs_and_secondary_errors() {
        for unavailable in [false, true] {
            let state_root = tempfile::tempdir().unwrap();
            let state_path = state_root.path().to_path_buf();
            let log = state_path.join("native-vmm.log");
            std::fs::write(
                &log,
                format!("{}boot failure marker", "x".repeat(40 * 1024)),
            )
            .unwrap();
            let mut client = MockClient::ok();
            client.start_res = Err(MxcError::backend_unavailable("primary start failure")
                .with_details(serde_json::json!({"phase": "boot"})));
            if !unavailable {
                client.diagnostics_res = Ok(SandboxDiagnostics::new(
                    log,
                    state_path.join("missing-console"),
                    state_path.join("missing-outcome"),
                ));
            }
            let error = run_with_client(
                &mut client,
                state_root.path(),
                &test_request(),
                &mut Logger::new(crate::mxc_common::logger::Mode::Buffer),
                None,
            )
            .unwrap_err();
            assert_eq!(error.code, MxcErrorCode::BackendUnavailable);
            assert_eq!(error.details, Some(serde_json::json!({"phase": "boot"})));
            assert!(error
                .message
                .starts_with("primary start failure; startup diagnostics"));
            if unavailable {
                assert!(error.message.contains("diagnostics unavailable"));
            } else {
                assert!(error.message.contains("[truncated]"));
                assert!(error.message.contains("boot failure marker"));
                assert!(error.message.contains("console_log: unavailable"));
                assert!(error.message.contains("outcome_report: unavailable"));
                assert!(error.message.len() < 12 * 1024);
            }
            assert_eq!(
                *client.calls.borrow(),
                [
                    "capabilities",
                    "validate_provision",
                    "validate",
                    "probe",
                    "platform_snapshots",
                    "provision",
                    "start",
                    "diagnostics",
                    "stop",
                    "deprovision",
                    "close"
                ]
            );
        }
    }

    #[test]
    fn lifecycle_cleanup_surfaces_host_close_and_retains_state_on_deprovision_failure() {
        let mut logger = Logger::new(crate::mxc_common::logger::Mode::Buffer);
        let request = ExecutionRequest {
            script_code: "echo ok".to_owned(),
            ..test_request()
        };

        // 1. Probe failure still closes host and surfaces close failure.
        let state_root = tempfile::tempdir().unwrap();
        let mut client = MockClient::ok();
        client.probe_res = Err(MxcError::backend_unavailable("probe failed"));
        client.close_res = Err(MxcError::backend_error("host_close failed"));
        let err = run_with_client(&mut client, state_root.path(), &request, &mut logger, None)
            .unwrap_err();
        assert_eq!(err.code, MxcErrorCode::BackendUnavailable);
        assert!(err.message.contains("probe failed"));
        assert!(err.message.contains("host_close failed"));
        assert_eq!(
            *client.calls.borrow(),
            [
                "capabilities",
                "validate_provision",
                "validate",
                "probe",
                "close"
            ]
        );

        // 2. Start failure suppresses AlreadyStopped on stop, deprovisions, closes host, removes state.
        let state_root = tempfile::tempdir().unwrap();
        let mut client = MockClient::ok();
        client.start_res = Err(MxcError::backend_error("start failed"));
        client.stop_res = Err(MxcError::new(
            MxcErrorCode::AlreadyStopped,
            "already stopped",
        ));
        let err = run_with_client(&mut client, state_root.path(), &request, &mut logger, None)
            .unwrap_err();
        assert!(err
            .message
            .starts_with("start failed; startup diagnostics unavailable: "));
        assert_eq!(
            *client.calls.borrow(),
            [
                "capabilities",
                "validate_provision",
                "validate",
                "probe",
                "platform_snapshots",
                "provision",
                "start",
                "diagnostics",
                "stop",
                "deprovision",
                "close"
            ]
        );

        // 3. Host close failure after workload success fails the run.
        let state_root = tempfile::tempdir().unwrap();
        let mut client = MockClient::ok();
        client.close_res = Err(MxcError::backend_error("host_close failed"));
        let err = run_with_client(&mut client, state_root.path(), &request, &mut logger, None)
            .unwrap_err();
        assert!(err
            .message
            .contains("NVX cleanup failed after workload completion"));
        assert!(err.message.contains("host_close failed"));

        // 4. Deprovision failure fails the run and names the directory that keeps its records.
        let state_root = tempfile::tempdir().unwrap();
        let mut client = MockClient::ok();
        client.deprovision_res = Err(MxcError::backend_error("deprovision failed"));
        let err = run_with_client(&mut client, state_root.path(), &request, &mut logger, None)
            .unwrap_err();
        assert!(err.message.contains("deprovision failed"));
        assert!(err.message.contains(&format!(
            "NVX sandbox records remain in the agent state directory after deprovision failure: {}",
            state_root.path().display()
        )));
    }

    #[test]
    fn native_validation_failure_closes_host_without_probing_or_provisioning() {
        for cleanup_fails in [false, true] {
            let mut logger = Logger::new(crate::mxc_common::logger::Mode::Buffer);
            let state_root = tempfile::tempdir().unwrap();
            let mut client = MockClient::ok();
            client.validate_res = Err(MxcError::policy_validation("native validation rejected"));
            if cleanup_fails {
                client.close_res = Err(MxcError::backend_error("close failed"));
            }
            let error = run_with_client(
                &mut client,
                state_root.path(),
                &test_request(),
                &mut logger,
                None,
            )
            .unwrap_err();
            assert_eq!(error.code, MxcErrorCode::PolicyValidation);
            if cleanup_fails {
                assert!(error
                    .message
                    .starts_with("native validation rejected; cleanup failure: "));
                assert!(error.message.contains("close failed"));
            } else {
                assert_eq!(error.message, "native validation rejected");
            }
            assert_eq!(
                *client.calls.borrow(),
                ["capabilities", "validate_provision", "validate", "close"]
            );
        }
    }

    #[test]
    fn validates_and_executes_the_same_mapped_request_in_order() {
        let mut logger = Logger::new(crate::mxc_common::logger::Mode::Buffer);
        for environment in [None, Some(Vec::new()), Some(vec!["KEY=value".to_owned()])] {
            let request = ExecutionRequest {
                script_code: "printf '%s' \"$KEY\"".to_owned(),
                script_timeout: 250,
                working_directory: "/tmp".to_owned(),
                env: environment,
                inherit_default_env: true,
                ..test_request()
            };
            let state_root = tempfile::tempdir().unwrap();
            let mut client = MockClient::ok();
            let result =
                run_with_client(&mut client, state_root.path(), &request, &mut logger, None)
                    .unwrap();
            assert_eq!(result.outcome, CapturedOutcome::Exited(0));
            assert_eq!(
                *client.validated_request.borrow(),
                Some(super::super::policy::exec_request(&request, &test_capabilities()).unwrap())
            );
            assert_eq!(
                *client.executed_request.borrow(),
                *client.validated_request.borrow()
            );
            assert_eq!(
                *client.calls.borrow(),
                [
                    "capabilities",
                    "validate_provision",
                    "validate",
                    "probe",
                    "platform_snapshots",
                    "provision",
                    "start",
                    "exec",
                    "stop",
                    "deprovision",
                    "close"
                ]
            );
        }
    }

    #[test]
    fn snapshot_fallback_warns_without_exposing_proxy_credentials() {
        for sensitive in [false, true] {
            let mut client = MockClient::ok();
            client
                .capabilities_res
                .as_mut()
                .unwrap()
                .network
                .network_proxy = true;
            client.platform_snapshots_res = Ok(Some(MxcError::backend_unavailable(
                "synthetic capture failure with synthetic@secret",
            )));
            let request = if sensitive {
                request_with_proxy("http://synthetic:synthetic%40secret@localhost:3128")
            } else {
                test_request()
            };
            let mut logger = Logger::new(crate::mxc_common::logger::Mode::Buffer);
            let result =
                run_with_client(&mut client, Path::new("state"), &request, &mut logger, None)
                    .unwrap();
            assert_eq!(result.outcome, CapturedOutcome::Exited(0));
            let warnings = logger.take_warnings();
            assert_eq!(warnings.len(), 1);
            assert!(warnings[0].contains("platform snapshots are unavailable"));
            if sensitive {
                assert!(warnings[0].contains("withheld"), "{warnings:?}");
                assert!(!warnings[0].contains("synthetic"), "{warnings:?}");
            } else {
                assert!(
                    warnings[0].contains("synthetic capture failure"),
                    "{warnings:?}"
                );
            }
        }
    }

    #[test]
    fn start_logs_how_the_sandbox_booted() {
        let directory = tempfile::tempdir().unwrap();
        let log_path = directory.path().join("diagnostics.log");
        let mut logger = Logger::new(crate::mxc_common::logger::Mode::Buffer);
        logger.enable_file_sink(&log_path).unwrap();
        let request = ExecutionRequest {
            script_code: "printf ok".to_owned(),
            ..test_request()
        };
        let mut client = MockClient::ok();
        client.start_res = Ok(StartResult::default()
            .with_boot_mode(BootMode::Cold)
            .with_cold_reason(ColdReason::MemoryAboveCapacity));
        run_with_client(&mut client, directory.path(), &request, &mut logger, None).unwrap();
        drop(logger);
        let log = std::fs::read_to_string(&log_path).unwrap();
        assert!(
            log.contains(
                r#"NVX sandbox started: {"bootMode":"cold","coldReason":"memory-above-capacity"}"#
            ),
            "{log}"
        );
    }

    #[test]
    fn capture_failure_runs_full_teardown_and_preserves_primary_and_cleanup_errors() {
        let primary = "NVX signed bundled agent: combined stdout/stderr capture limit of 67108864 bytes exceeded";
        for cleanup_fails in [false, true] {
            let mut logger = Logger::new(crate::mxc_common::logger::Mode::Buffer);
            let state_root = tempfile::tempdir().unwrap();
            let mut client = MockClient::ok();
            client.exec_res = Err(MxcError::backend_error(primary));
            if cleanup_fails {
                client.stop_res = Err(MxcError::backend_error("stop failed"));
                client.close_res = Err(MxcError::backend_error("close failed"));
            }
            let error = run_with_client(
                &mut client,
                state_root.path(),
                &test_request(),
                &mut logger,
                None,
            )
            .unwrap_err();
            assert_eq!(error.code, MxcErrorCode::BackendError);
            if cleanup_fails {
                assert!(error.message.starts_with(primary));
                assert!(error.message.contains("; cleanup failure: "));
                assert!(error.message.contains("stop failed"));
                assert!(error.message.contains("close failed"));
            } else {
                assert_eq!(error.message, primary);
            }
            assert_eq!(
                *client.calls.borrow(),
                [
                    "capabilities",
                    "validate_provision",
                    "validate",
                    "probe",
                    "platform_snapshots",
                    "provision",
                    "start",
                    "exec",
                    "stop",
                    "deprovision",
                    "close"
                ]
            );
        }
    }

    #[test]
    fn selected_image_and_policy_are_validated_and_provisioned_unchanged() {
        let json = serde_json::json!({
            "version": "1.1.0-alpha", "containment": "microvm",
            "microvm": {"image": "docker.io/library/python:3.12-alpine"},
            "process": {"commandLine": "printf ok"},
            "filesystem": {
                "readonlyPaths": [r"C:\ro"], "readwritePaths": [r"C:\rw"],
                "deniedPaths": [r"C:\rw\secret"]
            },
            "network": {}
        });
        let mut logger = Logger::new(crate::mxc_common::logger::Mode::Buffer);
        let crate::mxc_common::state_aware_request::MxcRequest::OneShot(request) =
            crate::mxc_common::config_parser::load_mxc_request_from_json(
                &json.to_string(),
                &mut logger,
            )
            .unwrap()
        else {
            panic!("expected create-and-run request");
        };
        let mut client = MockClient::ok();
        let mut logger = Logger::new(crate::mxc_common::logger::Mode::Buffer);
        run_with_client(&mut client, Path::new("state"), &request, &mut logger, None).unwrap();
        let input = client.provisioned_input.borrow();
        assert_eq!(*input, *client.validated_provision.borrow());
        assert_eq!(
            serde_json::json!({"request": input.as_ref().unwrap().request, "spec": input.as_ref().unwrap().spec}),
            serde_json::json!({
                "request": {
                    "filesystem": {
                        "readonlyPaths": [r"C:\ro"],
                        "readwritePaths": [r"C:\rw"],
                        "deniedPaths": [r"C:\rw\secret"]
                    },
                    "network": {
                        "egress": {"default": "deny"},
                        "ingress": {"default": "deny", "hostLoopback": "deny"}
                    }
                },
                "spec": {"image": {"reference": "docker.io/library/python:3.12-alpine"}}
            })
        );
    }

    #[test]
    fn capability_and_provision_validation_failures_close_without_side_effects() {
        for failure in [
            "query",
            "unsupported-image",
            "unsupported-filesystem",
            "validation",
        ] {
            let mut client = MockClient::ok();
            let mut request = test_request();
            let (expected_calls, expected_code, expected_message) = match failure {
                "query" => {
                    client.capabilities_res =
                        Err(MxcError::backend_error("capability query failed"));
                    (
                        vec!["capabilities", "close"],
                        MxcErrorCode::BackendError,
                        "capability query failed",
                    )
                }
                "unsupported-image" => {
                    client
                        .capabilities_res
                        .as_mut()
                        .unwrap()
                        .spec
                        .image_reference = false;
                    (
                        vec!["capabilities", "close"],
                        MxcErrorCode::PolicyValidation,
                        "the configured NVX runtime does not support microvm.image",
                    )
                }
                "unsupported-filesystem" => {
                    request.policy.denied_paths.push(r"C:\secret".to_owned());
                    client
                        .capabilities_res
                        .as_mut()
                        .unwrap()
                        .filesystem
                        .denied_paths = false;
                    (
                        vec!["capabilities", "close"],
                        MxcErrorCode::PolicyValidation,
                        "the configured NVX runtime does not support filesystem.deniedPaths",
                    )
                }
                _ => {
                    client.validate_provision_res =
                        Err(MxcError::policy_validation("provision rejected"));
                    (
                        vec!["capabilities", "validate_provision", "close"],
                        MxcErrorCode::PolicyValidation,
                        "provision rejected",
                    )
                }
            };
            let state_root = tempfile::tempdir().unwrap();
            let mut logger = Logger::new(crate::mxc_common::logger::Mode::Buffer);
            let error =
                run_with_client(&mut client, state_root.path(), &request, &mut logger, None)
                    .unwrap_err();
            assert_eq!(error.code, expected_code);
            assert_eq!(error.message, expected_message);
            assert_eq!(*client.calls.borrow(), expected_calls);
            assert!(client.provisioned_input.borrow().is_none());
        }
    }
}
