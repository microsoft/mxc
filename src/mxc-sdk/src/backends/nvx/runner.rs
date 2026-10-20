// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Minimal one-shot adapter for the signed NVX agent runtime.

use std::io::{Read, Write};

use aci_edge_sandboxes::{AciEdgeSandbox, ExecOutcome, SandboxId};

use crate::mxc_common::audit::{AuditEvent, AuditEventName};
use crate::mxc_common::logger::Logger;
use crate::mxc_common::models::{ExecutionRequest, FailurePhase, ScriptResponse};
use crate::mxc_common::mxc_error::{MxcError, MxcErrorCode};
use crate::mxc_common::sandbox_process::{NativeStdio, SandboxProcess, StreamCloser};
use crate::mxc_common::script_runner::ScriptRunner;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CapturedOutcome {
    Exited(i32),
    TimedOut,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CapturedRun {
    pub outcome: CapturedOutcome,
    pub warnings: Vec<String>,
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
}

#[derive(Debug, Default)]
pub struct NvxRunner;

impl NvxRunner {
    pub fn new() -> Self {
        Self
    }

    pub fn run_captured(
        &mut self,
        request: &ExecutionRequest,
        logger: &mut Logger,
    ) -> Result<CapturedRun, MxcError> {
        validate_one_shot_lifecycle(request)?;
        super::policy::validate_request(request)?;
        let state_root = new_state_root()?;
        let prepared = (|| {
            let client = super::runtime::create_client(state_root.path())?;
            client.probe().map_err(super::runtime::map_nvx_error)?;
            let capabilities = client.capabilities();
            let (provision, spec) = super::policy::provision_request(request, None, &capabilities)?;
            let exec = super::policy::exec_request(request, false, &capabilities)?;
            let provisioned = client
                .provision_with(&provision, &spec)
                .map_err(super::runtime::map_nvx_error)?;
            Ok((client, provisioned.sandbox_id, exec))
        })();
        let (client, sandbox_id, exec) = match prepared {
            Ok(prepared) => prepared,
            Err(error) => {
                let cleanup = state_root
                    .close()
                    .err()
                    .map(|error| {
                        MxcError::backend_error(format!("cannot remove NVX state: {error}"))
                    })
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
            client
                .start(&sandbox_id)
                .map_err(super::runtime::map_nvx_error)?;
            client
                .exec(&sandbox_id, &exec)
                .map_err(super::runtime::map_nvx_error)?
                .wait_with_output()
                .map_err(super::runtime::map_nvx_error)
        })();

        let stop_error = client
            .stop(&sandbox_id)
            .err()
            .map(super::runtime::map_nvx_error);
        let stop_error = match stop_error {
            Some(error) if primary.is_err() && error.code == MxcErrorCode::AlreadyStopped => None,
            other => other,
        };
        let deprovision_error = client
            .deprovision(&sandbox_id)
            .err()
            .map(super::runtime::map_nvx_error);
        let retain_state = deprovision_error.is_some();
        let mut cleanup_errors: Vec<MxcError> = [stop_error, deprovision_error]
            .into_iter()
            .flatten()
            .collect();
        drop(client);
        if retain_state {
            let retained = state_root.keep();
            cleanup_errors.push(MxcError::backend_error(format!(
                "NVX state retained for recovery after deprovision failure: {}",
                retained.display()
            )));
        } else if let Err(error) = state_root.close() {
            cleanup_errors.push(MxcError::backend_error(format!(
                "cannot remove NVX state directory: {error}"
            )));
        }
        logger.log_audit_event(
            &AuditEvent::new(AuditEventName::SandboxTornDown)
                .str("identity", &identity)
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
        let output = finish_run(primary, cleanup_errors, logger)?;

        Ok(CapturedRun {
            outcome: map_outcome(output.outcome)?,
            warnings: Vec::new(),
            stdout: output.stdout,
            stderr: output.stderr,
        })
    }

    pub fn spawn_streaming(
        request: &ExecutionRequest,
    ) -> Result<Box<dyn SandboxProcess>, MxcError> {
        spawn_streaming_with(
            request,
            super::runtime::create_client,
            adapt_streaming_execution,
        )
    }
}

fn adapt_streaming_execution(
    execution: aci_edge_sandboxes::Execution,
) -> Result<Box<dyn SandboxProcess>, MxcError> {
    let handle = super::process::into_exec_handle(
        execution,
        crate::mxc_common::state_aware_backend::ExecStdio::Piped,
    )?;
    Ok(Box::new(
        crate::mxc_common::exec_stream::ExecSandboxProcess::from_exec_handle(handle)?,
    ))
}

fn spawn_streaming_with(
    request: &ExecutionRequest,
    create_client: impl FnOnce(&std::path::Path) -> Result<AciEdgeSandbox, MxcError>,
    adapt: impl FnOnce(aci_edge_sandboxes::Execution) -> Result<Box<dyn SandboxProcess>, MxcError>,
) -> Result<Box<dyn SandboxProcess>, MxcError> {
    validate_one_shot_lifecycle(request)?;
    super::policy::validate_request(request)?;
    let state_root = new_state_root()?;
    let client = create_client(state_root.path())?;
    client.probe().map_err(super::runtime::map_nvx_error)?;
    let (provision, spec) =
        super::policy::provision_request(request, None, &client.capabilities())?;
    let exec = super::policy::exec_request(request, true, &client.capabilities())?;
    client
        .validate_exec(&exec)
        .map_err(super::runtime::map_nvx_error)?;
    let provisioned = match client.provision_with(&provision, &spec) {
        Ok(provisioned) => provisioned,
        Err(error) => {
            let mut error = super::runtime::map_nvx_error(error);
            drop(client);
            error.message.push_str(&format!(
                "; provision failed without a sandbox ID; state retained for recovery at {}",
                state_root.keep().display()
            ));
            return Err(error);
        }
    };
    let sandbox_id = provisioned.sandbox_id;
    let primary = (|| {
        client
            .start(&sandbox_id)
            .map_err(super::runtime::map_nvx_error)?;
        let execution = client
            .exec(&sandbox_id, &exec)
            .map_err(super::runtime::map_nvx_error)?;
        adapt(execution)
    })();
    let inner = match primary {
        Ok(inner) => inner,
        Err(mut error) => {
            if let Err(cleanup) = cleanup_sandbox(client, sandbox_id, state_root) {
                error
                    .message
                    .push_str(&format!("; cleanup failure: {cleanup}"));
            }
            return Err(error);
        }
    };
    Ok(Box::new(NvxOneShotProcess::new(
        inner,
        Box::new(move || cleanup_sandbox(client, sandbox_id, state_root)),
    )))
}

type Teardown = Box<dyn FnOnce() -> std::io::Result<()> + Send>;
type PendingTeardown = std::sync::Arc<std::sync::Mutex<Option<Teardown>>>;

#[derive(Clone)]
struct CachedIoError {
    kind: std::io::ErrorKind,
    message: String,
}

impl CachedIoError {
    fn capture(error: std::io::Error) -> Self {
        Self {
            kind: error.kind(),
            message: error.to_string(),
        }
    }

    fn restore(&self) -> std::io::Error {
        std::io::Error::new(self.kind, self.message.clone())
    }
}

enum CleanupState {
    Pending {
        task: PendingTeardown,
        launch_error: Option<CachedIoError>,
    },
    Running {
        worker: std::thread::JoinHandle<std::io::Result<()>>,
    },
    Finished {
        result: Result<(), CachedIoError>,
    },
}

struct NvxOneShotProcess {
    inner: Box<dyn SandboxProcess>,
    terminal: Option<Result<i32, CachedIoError>>,
    cleanup: CleanupState,
}

fn cleanup_sandbox(
    client: AciEdgeSandbox,
    sandbox_id: SandboxId,
    state_root: tempfile::TempDir,
) -> std::io::Result<()> {
    let stop = client
        .stop(&sandbox_id)
        .map(|_| ())
        .map_err(super::runtime::map_nvx_error);
    let stop = match stop {
        Err(error) if error.code == MxcErrorCode::AlreadyStopped => Ok(()),
        other => other,
    };
    let deprovision = client
        .deprovision(&sandbox_id)
        .map(|_| ())
        .map_err(super::runtime::map_nvx_error);
    drop(client);
    finish_cleanup(stop, deprovision, state_root)
}

fn finish_cleanup(
    stop: Result<(), MxcError>,
    deprovision: Result<(), MxcError>,
    state_root: tempfile::TempDir,
) -> std::io::Result<()> {
    let retained = deprovision.is_err();
    let mut failures: Vec<String> = [stop.err(), deprovision.err()]
        .into_iter()
        .flatten()
        .map(|error| error.to_string())
        .collect();
    if retained {
        failures.push(format!(
            "state retained for recovery at {}",
            state_root.keep().display()
        ));
    } else if let Err(error) = state_root.close() {
        failures.push(format!("cannot remove NVX state directory: {error}"));
    }
    if failures.is_empty() {
        Ok(())
    } else {
        Err(std::io::Error::other(format!(
            "NVX cleanup failed: {}",
            failures.join("; ")
        )))
    }
}

impl NvxOneShotProcess {
    fn new(inner: Box<dyn SandboxProcess>, teardown: Teardown) -> Self {
        Self {
            inner,
            terminal: None,
            cleanup: CleanupState::Pending {
                task: std::sync::Arc::new(std::sync::Mutex::new(Some(teardown))),
                launch_error: None,
            },
        }
    }

    fn start_cleanup(&mut self) {
        self.start_cleanup_with(|task| {
            std::thread::Builder::new()
                .name("mxc-nvx-teardown".to_owned())
                .spawn(task)
        });
    }

    fn start_cleanup_with(
        &mut self,
        spawn: impl FnOnce(Teardown) -> std::io::Result<std::thread::JoinHandle<std::io::Result<()>>>,
    ) {
        let CleanupState::Pending {
            task,
            launch_error: None,
        } = &self.cleanup
        else {
            return;
        };
        // Keep ownership here if the OS refuses to spawn and drops the worker closure.
        let worker_task = std::sync::Arc::clone(task);
        match spawn(Box::new(move || run_pending_teardown(&worker_task))) {
            Ok(worker) => self.cleanup = CleanupState::Running { worker },
            Err(error) => {
                if let CleanupState::Pending { launch_error, .. } = &mut self.cleanup {
                    *launch_error = Some(CachedIoError::capture(std::io::Error::other(format!(
                        "cannot start NVX cleanup worker: {error}; teardown remains owned until wait or Drop"
                    ))));
                }
            }
        }
    }

    fn cleanup(&mut self, blocking: bool) -> std::io::Result<bool> {
        match &self.cleanup {
            CleanupState::Finished { result } => {
                return result
                    .as_ref()
                    .map(|()| true)
                    .map_err(CachedIoError::restore);
            }
            CleanupState::Running { worker } if !blocking && !worker.is_finished() => {
                return Ok(false);
            }
            CleanupState::Pending { launch_error, .. } if !blocking => {
                return match launch_error {
                    Some(error) => Err(error.restore()),
                    None => Ok(false),
                };
            }
            _ => {}
        }
        let state = std::mem::replace(&mut self.cleanup, CleanupState::Finished { result: Ok(()) });
        let result = match state {
            CleanupState::Pending { task, launch_error } => {
                let result = run_pending_teardown(&task);
                match launch_error {
                    Some(error) => finish_wait(Err(error.restore()), result),
                    None => result,
                }
            }
            CleanupState::Running { worker } => worker.join().unwrap_or_else(|_| {
                Err(std::io::Error::other(
                    "NVX cleanup worker panicked; teardown completion is unknown",
                ))
            }),
            CleanupState::Finished { result } => result.map_err(|error| error.restore()),
        };
        self.cleanup = CleanupState::Finished {
            result: result.map_err(CachedIoError::capture),
        };
        self.cleanup(blocking)
    }

    fn terminal_result(&self) -> std::io::Result<i32> {
        match &self.terminal {
            Some(Ok(code)) => Ok(*code),
            Some(Err(error)) => Err(error.restore()),
            None => Err(std::io::Error::other("NVX process has no terminal outcome")),
        }
    }
}

fn run_pending_teardown(task: &PendingTeardown) -> std::io::Result<()> {
    let (teardown, poisoned) = match task.lock() {
        Ok(mut pending) => (pending.take(), false),
        Err(poisoned) => (poisoned.into_inner().take(), true),
    };
    let result = match teardown {
        Some(teardown) => teardown(),
        None => Err(std::io::Error::other(
            "NVX teardown task was already consumed",
        )),
    };
    if poisoned {
        finish_wait(
            Err(std::io::Error::other(
                "NVX teardown ownership lock was poisoned",
            )),
            result,
        )
    } else {
        result
    }
}

fn finish_wait<T>(primary: std::io::Result<T>, cleanup: std::io::Result<()>) -> std::io::Result<T> {
    match (primary, cleanup) {
        (Ok(value), Ok(())) => Ok(value),
        (Err(primary), Err(cleanup)) => Err(std::io::Error::other(format!(
            "{primary}; cleanup failure: {cleanup}"
        ))),
        (Err(error), Ok(())) | (Ok(_), Err(error)) => Err(error),
    }
}

impl SandboxProcess for NvxOneShotProcess {
    fn warnings(&self) -> Vec<String> {
        self.inner.warnings()
    }

    fn take_native_stdio(&mut self) -> std::io::Result<Option<NativeStdio>> {
        self.inner.take_native_stdio()
    }

    fn take_stdin(&mut self) -> Option<Box<dyn Write + Send>> {
        self.inner.take_stdin()
    }

    fn stdin_closer(&self) -> Option<Box<dyn StreamCloser>> {
        self.inner.stdin_closer()
    }

    fn take_stdout(&mut self) -> Option<Box<dyn Read + Send>> {
        self.inner.take_stdout()
    }

    fn take_stderr(&mut self) -> Option<Box<dyn Read + Send>> {
        self.inner.take_stderr()
    }

    fn stdout_closer(&self) -> Option<Box<dyn StreamCloser>> {
        self.inner.stdout_closer()
    }

    fn stderr_closer(&self) -> Option<Box<dyn StreamCloser>> {
        self.inner.stderr_closer()
    }

    fn try_wait(&mut self) -> std::io::Result<Option<i32>> {
        if self.terminal.is_none() {
            match self.inner.try_wait() {
                Ok(None) => return Ok(None),
                Ok(Some(code)) => self.terminal = Some(Ok(code)),
                Err(error) => self.terminal = Some(Err(CachedIoError::capture(error))),
            }
        }
        self.start_cleanup();
        match self.cleanup(false) {
            Ok(false) => Ok(None),
            cleanup => finish_wait(self.terminal_result().map(Some), cleanup.map(|_| ())),
        }
    }

    fn id(&self) -> u32 {
        self.inner.id()
    }

    fn kill(&mut self) -> std::io::Result<()> {
        self.inner.kill()
    }

    fn kill_for_timeout(&mut self) -> std::io::Result<()> {
        self.inner.kill_for_timeout()
    }

    fn wait(&mut self) -> std::io::Result<i32> {
        if self.terminal.is_none() {
            self.terminal = Some(self.inner.wait().map_err(CachedIoError::capture));
        }
        let cleanup = self.cleanup(true);
        finish_wait(self.terminal_result(), cleanup.map(|_| ()))
    }
}

impl Drop for NvxOneShotProcess {
    fn drop(&mut self) {
        if self.terminal.is_none() {
            match self.inner.kill() {
                Ok(()) => {
                    let result = self.inner.wait();
                    if let Err(error) = &result {
                        eprintln!("NVX wait during Drop failed: {error}");
                    }
                    self.terminal = Some(result.map_err(CachedIoError::capture));
                }
                Err(error) => eprintln!("NVX cancellation during Drop refused: {error}"),
            }
        }
        if let Err(error) = self.cleanup(true) {
            eprintln!("NVX teardown during Drop failed: {error}");
        }
    }
}

impl ScriptRunner for NvxRunner {
    fn validate_runner(&self, request: &ExecutionRequest) -> Result<(), ScriptResponse> {
        validate_one_shot_lifecycle(request)
            .map_err(|error| ScriptResponse::rejected(&error.message))?;
        super::policy::validate_request(request)
            .map_err(|error| ScriptResponse::rejected(&error.message))
    }

    fn execute(&mut self, request: &ExecutionRequest, logger: &mut Logger) -> ScriptResponse {
        let result = self.run_captured(request, logger).and_then(|result| {
            captured_to_script_response(
                result,
                &mut std::io::stdout().lock(),
                &mut std::io::stderr().lock(),
            )
        });
        match result {
            Ok(response) => response,
            Err(error) if error.code == MxcErrorCode::PolicyValidation => {
                ScriptResponse::rejected(&error.message)
            }
            Err(error) => backend_failure_response(error),
        }
    }
}

fn backend_failure_response(error: MxcError) -> ScriptResponse {
    ScriptResponse {
        exit_code: -1,
        error_message: error.to_string(),
        failure_phase: if error.code == MxcErrorCode::BackendUnavailable {
            FailurePhase::BackendUnavailable
        } else {
            FailurePhase::PostLaunchFailed
        },
        ..Default::default()
    }
}

fn new_state_root() -> Result<tempfile::TempDir, MxcError> {
    tempfile::Builder::new()
        .prefix(&format!("mxc-nvx-{}-", std::process::id()))
        .tempdir()
        .map_err(|error| {
            MxcError::backend_unavailable(format!(
                "cannot create a private NVX state directory: {error}"
            ))
        })
}

fn finish_run<T>(
    primary: Result<T, MxcError>,
    cleanup_errors: Vec<MxcError>,
    logger: &mut Logger,
) -> Result<T, MxcError> {
    match primary {
        Ok(output) if cleanup_errors.is_empty() => Ok(output),
        Ok(_) => Err(MxcError::backend_error(format!(
            "NVX cleanup failed after workload completion: {}",
            cleanup_errors
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>()
                .join("; ")
        ))),
        Err(mut error) => {
            for cleanup in cleanup_errors {
                logger.warning_line(&format!("NVX cleanup failed: {cleanup}"));
                error.message.push_str("; cleanup failure: ");
                error.message.push_str(&cleanup.to_string());
            }
            Err(error)
        }
    }
}

fn validate_one_shot_lifecycle(request: &ExecutionRequest) -> Result<(), MxcError> {
    if !request.lifecycle.destroy_on_exit {
        return Err(MxcError::policy_validation(
            "NVX create-and-run requires lifecycle.destroyOnExit=true",
        ));
    }
    if request.lifecycle.preserve_policy {
        return Err(MxcError::policy_validation(
            "NVX create-and-run requires lifecycle.preservePolicy=false",
        ));
    }
    let image = request
        .microvm_image
        .as_deref()
        .ok_or_else(|| MxcError::malformed_request("microvm.image is required"))?;
    crate::mxc_contract::dev::ImageReference::validate(image)
        .map_err(MxcError::malformed_request)?;
    Ok(())
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

fn captured_to_script_response(
    result: CapturedRun,
    stdout: &mut impl Write,
    stderr: &mut impl Write,
) -> Result<ScriptResponse, MxcError> {
    stdout
        .write_all(&result.stdout)
        .and_then(|()| stdout.flush())
        .map_err(|error| MxcError::backend_error(format!("cannot relay NVX stdout: {error}")))?;
    stderr
        .write_all(&result.stderr)
        .and_then(|()| stderr.flush())
        .map_err(|error| MxcError::backend_error(format!("cannot relay NVX stderr: {error}")))?;
    Ok(match result.outcome {
        CapturedOutcome::Exited(exit_code) => ScriptResponse {
            exit_code,
            ..Default::default()
        },
        CapturedOutcome::TimedOut => ScriptResponse {
            exit_code: -1,
            error_message: "NVX workload timed out".to_string(),
            failure_phase: FailurePhase::Timeout,
            ..Default::default()
        },
    })
}

#[cfg(test)]
mod tests {
    use super::super::test_support::Fixture;
    use super::*;
    use std::sync::{Arc, Mutex};

    fn poll_terminal(process: &mut dyn SandboxProcess) -> std::io::Result<i32> {
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
        loop {
            match process.try_wait() {
                Ok(None) if std::time::Instant::now() < deadline => std::thread::yield_now(),
                Ok(None) => return Err(std::io::Error::other("terminal poll exceeded test bound")),
                result => return result.map(|code| code.unwrap()),
            }
        }
    }

    fn streaming_request() -> ExecutionRequest {
        ExecutionRequest {
            script_code: "printf test".to_owned(),
            script_timeout: 1_000,
            microvm_image: Some("python:3.12-alpine".to_owned()),
            inherit_default_env: true,
            ..Default::default()
        }
    }

    fn injected_launch(
        request: &ExecutionRequest,
        fixture: &Fixture,
        break_adapter: bool,
    ) -> (
        Result<Box<dyn SandboxProcess>, MxcError>,
        std::path::PathBuf,
    ) {
        let observed_root = Mutex::new(None);
        let factory_fixture = fixture.clone();
        let adapter_fixture = fixture.clone();
        let result = spawn_streaming_with(
            request,
            |root| {
                *observed_root.lock().unwrap() = Some(root.to_owned());
                factory_fixture
                    .event("create_client")
                    .map_err(super::super::runtime::map_nvx_error)?;
                Ok(AciEdgeSandbox::new(factory_fixture))
            },
            move |mut execution| {
                adapter_fixture
                    .event("adapter")
                    .map_err(super::super::runtime::map_nvx_error)?;
                if break_adapter {
                    // Exercise the real native adapter's rejected-stream cleanup path.
                    drop(execution.take_stdout());
                    drop(execution.take_stderr());
                    drop(execution.take_stdin());
                }
                adapt_streaming_execution(execution)
            },
        );
        (result, observed_root.into_inner().unwrap().unwrap())
    }

    #[test]
    fn streaming_admission_refuses_before_any_provision_or_start() {
        for refusal in [
            "command_line",
            "stdin",
            "cwd",
            "env",
            "timeout",
            "validate_exec",
        ] {
            let mut request = streaming_request();
            let mut capabilities = Fixture::supported_capabilities();
            let mut fixture = Fixture::default();
            let expected = match refusal {
                "command_line" => {
                    capabilities.exec.command_line = false;
                    "process.commandLine"
                }
                "stdin" => {
                    capabilities.exec.stdin = false;
                    "piped standard input"
                }
                "cwd" => {
                    request.working_directory = "/work".to_owned();
                    capabilities.exec.cwd = false;
                    "process.cwd"
                }
                "env" => {
                    request.env = Some(vec!["KEY=value".to_owned()]);
                    capabilities.exec.env = false;
                    "process.env"
                }
                "timeout" => {
                    capabilities.exec.max_timeout_ms = Some(500);
                    "NVX process.timeout must not exceed 500 ms"
                }
                "validate_exec" => {
                    fixture.fail = Some("validate_exec");
                    "injected validate_exec failure"
                }
                _ => unreachable!(),
            };
            fixture.capabilities = Some(capabilities);
            let (result, root) = injected_launch(&request, &fixture, false);
            let error = result.err().expect("admission must refuse the launch");
            assert!(error.message.contains(expected), "{refusal}: {error}");
            assert_eq!(
                error.code,
                if refusal == "validate_exec" {
                    MxcErrorCode::BackendError
                } else {
                    MxcErrorCode::PolicyValidation
                }
            );
            let mut events = vec!["create_client", "probe"];
            if refusal == "validate_exec" {
                events.push("validate_exec");
            }
            assert_eq!(*fixture.events.lock().unwrap(), events, "{refusal}");
            assert!(
                !root.exists(),
                "admission failure must release temporary state"
            );
        }
    }

    #[test]
    fn streaming_stage_failures_preserve_primary_and_attempt_both_cleanup_steps() {
        for stage in ["start", "exec", "adapter"] {
            for stop_fails in [false, true] {
                for deprovision_fails in [false, true] {
                    let fixture = Fixture {
                        fail: (stage != "adapter").then_some(stage),
                        stop_fails,
                        deprovision_fails,
                        ..Default::default()
                    };
                    let (result, root) =
                        injected_launch(&streaming_request(), &fixture, stage == "adapter");
                    let error = result.err().expect("injected stage must fail");
                    assert_eq!(error.code, MxcErrorCode::BackendError);
                    let primary = if stage == "adapter" {
                        "this backend returned no stdout, stderr or stdin for an in-process exec"
                    } else if stage == "start" {
                        "NVX signed bundled agent: injected start failure"
                    } else {
                        "NVX signed bundled agent: injected exec failure"
                    };
                    assert!(error.message.starts_with(primary), "{error}");
                    assert_eq!(error.message.contains("injected stop failure"), stop_fails);
                    assert_eq!(
                        error.message.contains("injected deprovision failure"),
                        deprovision_fails
                    );
                    assert_eq!(root.exists(), deprovision_fails);
                    assert_eq!(
                        error.message.contains(&root.display().to_string()),
                        deprovision_fails
                    );
                    let mut expected = vec![
                        "create_client",
                        "probe",
                        "validate_exec",
                        "validate_provision",
                        "provision",
                        "start",
                    ];
                    if stage != "start" {
                        expected.extend(["validate_exec", "exec"]);
                    }
                    if stage == "adapter" {
                        expected.extend(["adapter", "cancel", "wait"]);
                    }
                    expected.extend(["stop", "deprovision"]);
                    assert_eq!(*fixture.events.lock().unwrap(), expected, "{stage}");
                    if deprovision_fails {
                        std::fs::remove_dir(&root).unwrap();
                    }
                }
            }
        }
    }

    #[test]
    fn streaming_provision_failure_retains_unknown_partial_state_without_guessing_an_id() {
        let fixture = Fixture {
            fail: Some("provision"),
            ..Default::default()
        };
        let (result, root) = injected_launch(&streaming_request(), &fixture, false);
        let error = result.err().expect("provision must fail");
        assert_eq!(error.code, MxcErrorCode::BackendError);
        assert!(error
            .message
            .starts_with("NVX signed bundled agent: injected provision failure"));
        assert!(error
            .message
            .contains("provision failed without a sandbox ID"));
        assert!(error.message.contains(&root.display().to_string()));
        assert!(root.is_dir());
        assert_eq!(
            *fixture.events.lock().unwrap(),
            [
                "create_client",
                "probe",
                "validate_exec",
                "validate_provision",
                "provision"
            ]
        );
        std::fs::remove_dir(&root).unwrap();
    }

    #[test]
    fn streaming_success_uses_validated_image_and_owns_teardown_until_wait() {
        let fixture = Fixture::default();
        let (result, root) = injected_launch(&streaming_request(), &fixture, false);
        let process = result.unwrap();
        assert!(root.exists());
        let output = crate::sandbox::MxcProcess::new(process)
            .wait_with_output()
            .unwrap();
        assert_eq!(output.outcome, crate::sandbox::WaitResult::Exited(7));
        assert_eq!(output.stdout, b"out");
        assert_eq!(output.stderr, b"err");
        assert!(!root.exists());
        assert_eq!(
            *fixture.image.lock().unwrap(),
            Some(aci_edge_sandboxes::ImageSource::Reference(
                "python:3.12-alpine".to_owned()
            ))
        );
        assert_eq!(*fixture.stdin_piped.lock().unwrap(), Some(true));
        assert_eq!(
            *fixture.events.lock().unwrap(),
            [
                "create_client",
                "probe",
                "validate_exec",
                "validate_provision",
                "provision",
                "start",
                "validate_exec",
                "exec",
                "adapter",
                "wait",
                "stop",
                "deprovision"
            ]
        );
    }

    #[test]
    fn real_streaming_terminal_wait_and_poll_preserve_teardown_failures_on_repeat_wait() {
        for terminal in ["exit", "timeout", "wait_error"] {
            for poll in [false, true] {
                for stop_fails in [false, true] {
                    for deprovision_fails in [false, true] {
                        let fixture = Fixture {
                            fail: (terminal == "wait_error").then_some("wait"),
                            outcome: Some(if terminal == "timeout" {
                                aci_edge_sandboxes::ExecOutcome::TimedOut
                            } else {
                                aci_edge_sandboxes::ExecOutcome::Exited(7)
                            }),
                            stop_fails,
                            deprovision_fails,
                            ..Default::default()
                        };
                        let (result, root) = injected_launch(&streaming_request(), &fixture, false);
                        let mut process = result.unwrap();
                        let first = if poll {
                            let deadline =
                                std::time::Instant::now() + std::time::Duration::from_secs(2);
                            loop {
                                match process.try_wait() {
                                    Ok(None) => {
                                        assert!(
                                            std::time::Instant::now() < deadline,
                                            "native waiter did not complete"
                                        );
                                        std::thread::yield_now();
                                    }
                                    result => break result.map(|code| code.unwrap()),
                                }
                            }
                        } else {
                            process.wait()
                        };
                        let expected = first
                            .as_ref()
                            .copied()
                            .map_err(|error| (error.kind(), error.to_string()));
                        for _ in 0..3 {
                            let repeated = process
                                .try_wait()
                                .map(|code| code.unwrap())
                                .map_err(|error| (error.kind(), error.to_string()));
                            assert_eq!(
                                repeated, expected,
                                "repeated poll lost terminal or cleanup failure"
                            );
                        }
                        let cleanup_failed = stop_fails || deprovision_fails;
                        if cleanup_failed || terminal == "wait_error" {
                            let error = first.unwrap_err();
                            assert_eq!(error.kind(), std::io::ErrorKind::Other);
                            let message = error.to_string();
                            assert_eq!(message.contains("injected stop failure"), stop_fails);
                            assert_eq!(
                                message.contains("injected deprovision failure"),
                                deprovision_fails
                            );
                            if terminal == "wait_error" {
                                assert!(message.contains("injected wait failure"));
                            }
                            if terminal == "timeout" {
                                assert!(message.starts_with("the exec timed out and the sandbox terminated it; cleanup failure: "));
                            }
                            if deprovision_fails {
                                assert!(message.contains(&root.display().to_string()));
                            }
                        } else if terminal == "timeout" {
                            assert_eq!(first.unwrap_err().kind(), std::io::ErrorKind::TimedOut);
                        } else {
                            assert_eq!(first.unwrap(), 7);
                        }
                        let mut public = crate::sandbox::MxcProcess::new(process);
                        let repeated = public.wait();
                        if cleanup_failed {
                            let error = repeated.unwrap_err();
                            assert_eq!(error.kind(), std::io::ErrorKind::Other);
                            assert_eq!(
                                error.to_string().contains("injected deprovision failure"),
                                deprovision_fails
                            );
                            if terminal == "timeout" {
                                assert!(error.to_string().contains("the exec timed out"));
                            }
                        } else if terminal == "timeout" {
                            assert_eq!(repeated.unwrap(), crate::sandbox::WaitResult::TimedOut);
                        } else if terminal == "exit" {
                            assert_eq!(repeated.unwrap(), crate::sandbox::WaitResult::Exited(7));
                        }
                        drop(public);
                        let events = fixture.events.lock().unwrap();
                        assert_eq!(events.iter().filter(|&&event| event == "stop").count(), 1);
                        assert_eq!(
                            events
                                .iter()
                                .filter(|&&event| event == "deprovision")
                                .count(),
                            1
                        );
                        assert_eq!(root.exists(), deprovision_fails);
                        if deprovision_fails {
                            std::fs::remove_dir(&root).unwrap();
                        }
                    }
                }
            }
        }
    }

    #[test]
    fn real_streaming_poll_is_prompt_while_cleanup_blocks_and_wait_or_drop_joins() {
        use super::super::test_support::CleanupGate;
        use std::sync::atomic::Ordering;
        use std::time::Duration;

        for terminal in ["exit", "timeout", "wait_error"] {
            for cleanup_fails in [false, true] {
                for drop_barrier in [false, true] {
                    let gate = Arc::new(CleanupGate::default());
                    let fixture = Fixture {
                        fail: (terminal == "wait_error").then_some("wait"),
                        outcome: Some(if terminal == "timeout" {
                            aci_edge_sandboxes::ExecOutcome::TimedOut
                        } else {
                            aci_edge_sandboxes::ExecOutcome::Exited(7)
                        }),
                        stop_fails: cleanup_fails,
                        deprovision_fails: cleanup_fails,
                        stop_gate: Some(Arc::clone(&gate)),
                        ..Default::default()
                    };
                    let (launched, root) = injected_launch(&streaming_request(), &fixture, false);
                    let mut process = launched.unwrap();
                    let worker_gate = Arc::clone(&gate);
                    let (polled, polling) = std::sync::mpsc::channel();
                    let (done, completion) = std::sync::mpsc::channel();
                    let worker = std::thread::spawn(move || {
                        let deadline = std::time::Instant::now() + Duration::from_secs(2);
                        let mut observations = Vec::new();
                        while !worker_gate.entered.load(Ordering::Acquire)
                            && std::time::Instant::now() < deadline
                        {
                            observations
                                .push(process.try_wait().map_err(|error| error.to_string()));
                            std::thread::yield_now();
                        }
                        for _ in 0..3 {
                            observations
                                .push(process.try_wait().map_err(|error| error.to_string()));
                        }
                        polled.send(observations).unwrap();
                        if drop_barrier {
                            drop(process);
                            done.send(None).unwrap();
                        } else {
                            let first = process
                                .wait()
                                .map_err(|error| (error.kind(), error.to_string()));
                            let repeated = (0..3)
                                .map(|_| {
                                    process
                                        .try_wait()
                                        .map(|code| code.unwrap())
                                        .map_err(|error| (error.kind(), error.to_string()))
                                })
                                .collect::<Vec<_>>();
                            let last = process
                                .wait()
                                .map_err(|error| (error.kind(), error.to_string()));
                            drop(process);
                            done.send(Some((first, repeated, last))).unwrap();
                        }
                    });
                    let pending = polling.recv_timeout(Duration::from_secs(2));
                    let before_release = completion.recv_timeout(Duration::from_millis(30));
                    // Release even if synchronous teardown regresses and the first poll is parked.
                    gate.release();
                    let finished = completion.recv_timeout(Duration::from_secs(2));
                    worker.join().unwrap();
                    let pending = pending.expect("try_wait blocked inside sandbox teardown");
                    assert!(
                        gate.entered.load(Ordering::Acquire),
                        "positive control never entered stop"
                    );
                    assert!(!pending.is_empty());
                    assert!(
                        pending.iter().all(|result| matches!(result, Ok(None))),
                        "{pending:?}"
                    );
                    assert!(
                        matches!(
                            before_release,
                            Err(std::sync::mpsc::RecvTimeoutError::Timeout)
                        ),
                        "wait/Drop returned before owned teardown finished"
                    );
                    if let Some((first, repeated, last)) = finished.unwrap() {
                        for result in repeated.into_iter().chain([last]) {
                            assert_eq!(result, first);
                        }
                        if cleanup_fails {
                            let (kind, message) = first.unwrap_err();
                            assert_eq!(kind, std::io::ErrorKind::Other);
                            assert!(message.contains("injected stop failure"));
                            assert!(message.contains("injected deprovision failure"));
                            assert!(message.contains(&root.display().to_string()));
                            if terminal == "timeout" {
                                assert!(message.contains("the exec timed out"));
                            } else if terminal == "wait_error" {
                                assert!(message.contains("injected wait failure"));
                            }
                        } else {
                            match terminal {
                                "timeout" => {
                                    assert_eq!(first.unwrap_err().0, std::io::ErrorKind::TimedOut)
                                }
                                "wait_error" => {
                                    assert!(first.unwrap_err().1.contains("injected wait failure"))
                                }
                                _ => assert_eq!(first.unwrap(), 7),
                            }
                        }
                    }
                    let events = fixture.events.lock().unwrap();
                    for event in ["stop", "deprovision", "wait"] {
                        assert_eq!(
                            events.iter().filter(|&&entry| entry == event).count(),
                            1,
                            "{events:?}"
                        );
                    }
                    assert_eq!(root.exists(), cleanup_fails);
                    if cleanup_fails {
                        std::fs::remove_dir(root).unwrap();
                    }
                }
            }
        }
    }

    #[test]
    fn cleanup_worker_spawn_failure_preserves_task_for_wait_and_drop() {
        for terminal in ["exit", "timeout", "wait_error"] {
            for drop_barrier in [false, true] {
                let (mut process, events) = test_process(false, true, false);
                process.terminal = Some(match terminal {
                    "timeout" => Err(CachedIoError::capture(std::io::Error::new(
                        std::io::ErrorKind::TimedOut,
                        "workload timed out",
                    ))),
                    "wait_error" => Err(CachedIoError::capture(std::io::Error::other(
                        "native waiter failed",
                    ))),
                    _ => Ok(7),
                });
                process.start_cleanup_with(|_| {
                    Err(std::io::Error::other("injected thread spawn failure"))
                });
                process.start_cleanup_with(|_| panic!("failed worker creation must not retry"));
                for _ in 0..3 {
                    let error = process.try_wait().unwrap_err();
                    assert_eq!(error.kind(), std::io::ErrorKind::Other);
                    assert!(error.to_string().contains("injected thread spawn failure"));
                    if terminal == "timeout" {
                        assert!(error.to_string().contains("workload timed out"));
                    } else if terminal == "wait_error" {
                        assert!(error.to_string().contains("native waiter failed"));
                    }
                }
                assert!(
                    events.lock().unwrap().is_empty(),
                    "poll must not perform synchronous cleanup"
                );
                if !drop_barrier {
                    let error = process.wait().unwrap_err().to_string();
                    assert!(error.contains("injected thread spawn failure"));
                    assert!(error.contains("recovery at test-root"));
                    assert_eq!(process.try_wait().unwrap_err().to_string(), error);
                    assert_eq!(process.wait().unwrap_err().to_string(), error);
                }
                drop(process);
                assert_eq!(*events.lock().unwrap(), ["cleanup"]);
            }
        }
    }

    struct TestProcess {
        events: Arc<Mutex<Vec<&'static str>>>,
        timeout: bool,
        refuse_kill: bool,
    }

    impl SandboxProcess for TestProcess {
        fn take_stdin(&mut self) -> Option<Box<dyn Write + Send>> {
            None
        }
        fn take_stdout(&mut self) -> Option<Box<dyn Read + Send>> {
            None
        }
        fn take_stderr(&mut self) -> Option<Box<dyn Read + Send>> {
            None
        }
        fn id(&self) -> u32 {
            0
        }
        fn try_wait(&mut self) -> std::io::Result<Option<i32>> {
            self.wait().map(Some)
        }
        fn wait(&mut self) -> std::io::Result<i32> {
            self.events.lock().unwrap().push("wait");
            if self.timeout {
                Err(std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    "workload timed out",
                ))
            } else {
                Ok(7)
            }
        }
        fn kill(&mut self) -> std::io::Result<()> {
            self.events.lock().unwrap().push("kill");
            if self.refuse_kill {
                Err(std::io::Error::other("kill refused"))
            } else {
                Ok(())
            }
        }
    }

    fn test_process(
        timeout: bool,
        cleanup_fails: bool,
        refuse_kill: bool,
    ) -> (NvxOneShotProcess, Arc<Mutex<Vec<&'static str>>>) {
        let events = Arc::new(Mutex::new(Vec::new()));
        let cleanup_events = Arc::clone(&events);
        (
            NvxOneShotProcess::new(
                Box::new(TestProcess {
                    events: Arc::clone(&events),
                    timeout,
                    refuse_kill,
                }),
                Box::new(move || {
                    cleanup_events.lock().unwrap().push("cleanup");
                    if cleanup_fails {
                        Err(std::io::Error::other(
                            "deprovision failed; recovery at test-root",
                        ))
                    } else {
                        Ok(())
                    }
                }),
            ),
            events,
        )
    }

    #[test]
    fn wrapper_wait_preserves_timeout_and_teardown_failure_matrix() {
        for timeout in [false, true] {
            for cleanup_fails in [false, true] {
                for poll in [false, true] {
                    let (mut process, events) = test_process(timeout, cleanup_fails, false);
                    let result = if poll {
                        poll_terminal(&mut process)
                    } else {
                        process.wait()
                    };
                    if cleanup_fails {
                        let error = result.unwrap_err();
                        assert_eq!(error.kind(), std::io::ErrorKind::Other);
                        assert!(error.to_string().contains("recovery at test-root"));
                        if timeout {
                            assert!(error.to_string().contains("workload timed out"));
                        }
                    } else if timeout {
                        assert_eq!(result.unwrap_err().kind(), std::io::ErrorKind::TimedOut);
                    } else {
                        assert_eq!(result.unwrap(), 7);
                    }
                    drop(process);
                    assert_eq!(*events.lock().unwrap(), ["wait", "cleanup"]);
                }
            }
        }
    }

    #[test]
    fn drop_refusal_skips_wait_but_reaches_cleanup() {
        let (process, events) = test_process(false, false, true);
        let (tx, rx) = std::sync::mpsc::channel();
        let join = std::thread::spawn(move || {
            drop(process);
            tx.send(()).unwrap();
        });
        rx.recv_timeout(std::time::Duration::from_secs(2))
            .expect("Drop must not join refused cancellation");
        join.join().unwrap();
        assert_eq!(*events.lock().unwrap(), ["kill", "cleanup"]);
    }

    #[test]
    fn refused_native_exec_drop_detaches_waiter_after_teardown() {
        use crate::mxc_common::state_aware_backend::{null_pipe_handle, ExecHandle, ExecOutcome};
        use std::os::windows::io::AsRawHandle;
        let (stdout, _writer) = std::io::pipe().unwrap();
        let (release, parked) = std::sync::mpsc::channel();
        let events = Arc::new(Mutex::new(Vec::new()));
        let kill_events = Arc::clone(&events);
        let cleanup_events = Arc::clone(&events);
        let inner =
            crate::mxc_common::exec_stream::ExecSandboxProcess::from_exec_handle(ExecHandle {
                stdin: null_pipe_handle(),
                stdout: windows::Win32::Foundation::HANDLE(stdout.as_raw_handle()),
                stderr: null_pipe_handle(),
                stdin_closer: None,
                waiter: Box::new(move || {
                    parked.recv().unwrap();
                    Ok(ExecOutcome::Exited(0))
                }),
                terminator: Box::new(move || {
                    kill_events.lock().unwrap().push("kill");
                    Err(MxcError::backend_error("cancellation refused"))
                }),
            })
            .unwrap();
        let process = NvxOneShotProcess::new(
            Box::new(inner),
            Box::new(move || {
                cleanup_events.lock().unwrap().push("cleanup");
                Ok(())
            }),
        );
        let (done, completion) = std::sync::mpsc::channel();
        let join = std::thread::spawn(move || {
            drop(process);
            done.send(()).unwrap();
        });
        let result = completion.recv_timeout(std::time::Duration::from_secs(2));
        release.send(()).unwrap();
        join.join().unwrap();
        result.expect("Drop must detach the still-parked native waiter");
        assert_eq!(*events.lock().unwrap(), ["kill", "cleanup"]);
    }

    #[test]
    fn teardown_retains_root_only_when_deprovision_fails() {
        for stop_fails in [false, true] {
            for deprovision_fails in [false, true] {
                let root = tempfile::tempdir().unwrap();
                let path = root.path().to_owned();
                let stop = if stop_fails {
                    Err(MxcError::backend_error("stop refused"))
                } else {
                    Ok(())
                };
                let deprovision = if deprovision_fails {
                    Err(MxcError::backend_error("deprovision refused"))
                } else {
                    Ok(())
                };
                let result = finish_cleanup(stop, deprovision, root);
                assert_eq!(path.exists(), deprovision_fails);
                if stop_fails || deprovision_fails {
                    let error = result.unwrap_err().to_string();
                    if stop_fails {
                        assert!(error.contains("stop refused"));
                    }
                    if deprovision_fails {
                        assert!(error.contains("deprovision refused"));
                        assert!(error.contains(&path.display().to_string()));
                    }
                } else {
                    result.unwrap();
                }
                if deprovision_fails {
                    std::fs::remove_dir(&path).unwrap();
                }
            }
        }
    }

    #[test]
    fn wrapper_capture_interrupts_both_parked_readers_on_timeout() {
        use std::sync::Condvar;
        struct Parked(Arc<(Mutex<bool>, Condvar)>);
        impl Read for Parked {
            fn read(&mut self, _: &mut [u8]) -> std::io::Result<usize> {
                let (lock, wake) = &*self.0;
                let mut released = lock.lock().unwrap();
                while !*released {
                    released = wake.wait(released).unwrap();
                }
                Ok(0)
            }
        }
        impl StreamCloser for Parked {
            fn close(&self) {
                let (lock, wake) = &*self.0;
                *lock.lock().unwrap() = true;
                wake.notify_all();
            }
        }
        struct CaptureProcess {
            stdout: Arc<(Mutex<bool>, Condvar)>,
            stderr: Arc<(Mutex<bool>, Condvar)>,
        }
        impl SandboxProcess for CaptureProcess {
            fn take_stdin(&mut self) -> Option<Box<dyn Write + Send>> {
                None
            }
            fn take_stdout(&mut self) -> Option<Box<dyn Read + Send>> {
                Some(Box::new(Parked(Arc::clone(&self.stdout))))
            }
            fn take_stderr(&mut self) -> Option<Box<dyn Read + Send>> {
                Some(Box::new(Parked(Arc::clone(&self.stderr))))
            }
            fn stdout_closer(&self) -> Option<Box<dyn StreamCloser>> {
                Some(Box::new(Parked(Arc::clone(&self.stdout))))
            }
            fn stderr_closer(&self) -> Option<Box<dyn StreamCloser>> {
                Some(Box::new(Parked(Arc::clone(&self.stderr))))
            }
            fn try_wait(&mut self) -> std::io::Result<Option<i32>> {
                self.wait().map(Some)
            }
            fn id(&self) -> u32 {
                0
            }
            fn kill(&mut self) -> std::io::Result<()> {
                Ok(())
            }
            fn wait(&mut self) -> std::io::Result<i32> {
                Err(std::io::Error::new(std::io::ErrorKind::TimedOut, "timeout"))
            }
        }
        let stdout = Arc::new((Mutex::new(false), Condvar::new()));
        let stderr = Arc::new((Mutex::new(false), Condvar::new()));
        let process = NvxOneShotProcess::new(
            Box::new(CaptureProcess {
                stdout: Arc::clone(&stdout),
                stderr: Arc::clone(&stderr),
            }),
            Box::new(|| Ok(())),
        );
        let (tx, rx) = std::sync::mpsc::channel();
        let join = std::thread::spawn(move || {
            tx.send(crate::sandbox::MxcProcess::new(Box::new(process)).wait_with_output())
                .unwrap();
        });
        let result = rx.recv_timeout(std::time::Duration::from_secs(2));
        // Always release readers before asserting, including on a regression.
        Parked(stdout).close();
        Parked(stderr).close();
        join.join().unwrap();
        assert_eq!(
            result
                .expect("capture must cancel both reads")
                .unwrap()
                .outcome,
            crate::sandbox::WaitResult::TimedOut
        );
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
    fn rejects_non_terminal_success_outcomes() {
        assert!(map_outcome(ExecOutcome::Cancelled).is_err());
    }

    #[test]
    fn executor_adapter_preserves_exit_and_output() {
        for (expected_stdout, expected_stderr) in [
            (b"out".as_slice(), b"err".as_slice()),
            (b"\xff\0\xfe".as_slice(), b"\x80\0\x81".as_slice()),
            (b"".as_slice(), b"".as_slice()),
        ] {
            let mut stdout = Vec::new();
            let mut stderr = Vec::new();
            let response = captured_to_script_response(
                CapturedRun {
                    outcome: CapturedOutcome::Exited(42),
                    warnings: Vec::new(),
                    stdout: expected_stdout.to_vec(),
                    stderr: expected_stderr.to_vec(),
                },
                &mut stdout,
                &mut stderr,
            )
            .unwrap();
            assert_eq!(response.exit_code, 42);
            assert_eq!(stdout, expected_stdout);
            assert_eq!(stderr, expected_stderr);
            assert!(response.standard_out.is_empty());
            assert!(response.standard_err.is_empty());
            assert!(response.error_message.is_empty());
        }
    }

    #[test]
    fn executor_adapter_marks_timeout() {
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        let response = captured_to_script_response(
            CapturedRun {
                outcome: CapturedOutcome::TimedOut,
                warnings: Vec::new(),
                stdout: b"partial-out\xff".to_vec(),
                stderr: b"partial-err\x80".to_vec(),
            },
            &mut stdout,
            &mut stderr,
        )
        .unwrap();
        assert_eq!(response.exit_code, -1);
        assert_eq!(response.failure_phase, FailurePhase::Timeout);
        assert_eq!(response.error_message, "NVX workload timed out");
        assert_eq!(stdout, b"partial-out\xff");
        assert_eq!(stderr, b"partial-err\x80");
        assert!(response.standard_out.is_empty());
        assert!(response.standard_err.is_empty());
    }

    #[test]
    fn executor_adapter_surfaces_output_write_and_flush_failures() {
        struct FailingWriter {
            on_flush: bool,
        }

        impl Write for FailingWriter {
            fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
                if self.on_flush {
                    Ok(bytes.len())
                } else {
                    Err(std::io::Error::other("test write failure"))
                }
            }

            fn flush(&mut self) -> std::io::Result<()> {
                Err(std::io::Error::other("test flush failure"))
            }
        }

        for on_flush in [false, true] {
            for stream in ["stdout", "stderr"] {
                let result = CapturedRun {
                    outcome: CapturedOutcome::Exited(0),
                    warnings: Vec::new(),
                    stdout: b"out".to_vec(),
                    stderr: b"err".to_vec(),
                };
                let mut failing = FailingWriter { on_flush };
                let mut sink = std::io::sink();
                let error = if stream == "stdout" {
                    captured_to_script_response(result, &mut failing, &mut sink)
                } else {
                    captured_to_script_response(result, &mut sink, &mut failing)
                }
                .unwrap_err();
                assert_eq!(error.code, MxcErrorCode::BackendError);
                let operation = if on_flush { "flush" } else { "write" };
                assert_eq!(
                    error.message,
                    format!("cannot relay NVX {stream}: test {operation} failure")
                );
            }
        }
    }

    #[test]
    fn create_and_run_rejects_non_default_lifecycle() {
        let mut request = ExecutionRequest::default();
        request.lifecycle.destroy_on_exit = false;
        assert!(validate_one_shot_lifecycle(&request)
            .unwrap_err()
            .message
            .contains("destroyOnExit=true"));
        request.lifecycle.destroy_on_exit = true;
        request.lifecycle.preserve_policy = true;
        assert!(validate_one_shot_lifecycle(&request)
            .unwrap_err()
            .message
            .contains("preservePolicy=false"));
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
        use std::time::Duration;
        let mut capabilities = aci_edge_sandboxes::Capabilities::new("agent");
        capabilities.exec.command_line = true;
        capabilities.exec.cwd = true;
        capabilities.exec.env = true;
        let request = ExecutionRequest {
            script_code: "printf '%s' \"$KEY\"".to_owned(),
            working_directory: "/tmp".to_owned(),
            script_timeout: 250,
            env: Some(Vec::new()),
            inherit_default_env: true,
            microvm_image: Some("python:3.12-alpine".to_owned()),
            ..Default::default()
        };
        let mapped = super::super::policy::exec_request(&request, false, &capabilities).unwrap();
        assert_eq!(
            mapped.process.command,
            aci_edge_sandboxes::Command::CommandLine(request.script_code)
        );
        assert_eq!(mapped.process.timeout, Some(Duration::from_millis(250)));
        assert_eq!(mapped.process.cwd.as_deref(), Some("/tmp"));
        assert_eq!(mapped.process.env, Some(Vec::new()));
        assert_eq!(mapped.process.inherit_default_env, Some(true));
        let defaults = super::super::policy::exec_request(
            &ExecutionRequest {
                microvm_image: Some("python:3.12-alpine".to_owned()),
                ..Default::default()
            },
            false,
            &capabilities,
        )
        .unwrap();
        assert_eq!(defaults.process.env, None);
        assert_eq!(defaults.process.timeout, None);
        assert_eq!(defaults.process.cwd, None);
    }
}
