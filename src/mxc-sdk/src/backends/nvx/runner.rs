// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Minimal create-and-run adapter for the signed bundled NVX agent.

use std::io::Write;

use crate::mxc_common::audit::{AuditEvent, AuditEventName};
use crate::mxc_common::logger::Logger;
use crate::mxc_common::models::{ExecutionRequest, FailurePhase, ScriptResponse};
use crate::mxc_common::mxc_error::{MxcError, MxcErrorCode};
use crate::mxc_common::proxy_env::proxy_url_has_credentials;
use crate::mxc_common::script_runner::{RunCancellation, ScriptRunner};

#[cfg(test)]
use super::abi::{Capabilities, ExecRequest};
use super::abi::{ExecOutcome, ProvisionInput};
use super::runtime::{NvxClient, SandboxClient};

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

impl CapturedRun {
    pub(crate) fn response(&self) -> ScriptResponse {
        match self.outcome {
            CapturedOutcome::Exited(exit_code) => ScriptResponse {
                exit_code,
                ..Default::default()
            },
            CapturedOutcome::TimedOut => ScriptResponse {
                exit_code: -1,
                error_message: "NVX workload timed out".to_owned(),
                failure_phase: FailurePhase::Timeout,
                ..Default::default()
            },
        }
    }
}

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
        let mut logger = Logger::new(crate::mxc_common::logger::Mode::Buffer);
        let (state_root, mut client) = open_client(&mut logger)?;
        validate_with_client(&mut client, state_root, request)
    }

    fn run_captured_inner(
        &mut self,
        request: &ExecutionRequest,
        logger: &mut Logger,
    ) -> Result<CapturedRun, MxcError> {
        super::policy::validate_request(request)?;
        self.cancellation.check()?;
        let (state_root, mut client) = open_client(logger)?;
        run_with_client(
            &mut client,
            state_root,
            request,
            logger,
            Some(&self.cancellation),
        )
    }
}

fn open_client(logger: &mut Logger) -> Result<(tempfile::TempDir, NvxClient), MxcError> {
    let state_root = tempfile::Builder::new()
        .prefix(&format!("mxc-nvx-{}-", std::process::id()))
        .tempdir()
        .map_err(|error| {
            MxcError::backend_unavailable(format!(
                "cannot create a private NVX state directory: {error}"
            ))
        })?;
    match super::runtime::create_client(state_root.path()) {
        Ok(client) => Ok((state_root, client)),
        Err(error) => {
            let cleanup = state_root
                .close()
                .err()
                .map(|error| MxcError::backend_error(format!("cannot remove NVX state: {error}")))
                .into_iter()
                .collect();
            finish_run(Err(error), cleanup, logger)
        }
    }
}

fn request_has_sensitive_proxy(request: &ExecutionRequest) -> bool {
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
) -> Result<(ProvisionInput, super::abi::ExecRequest), MxcError> {
    let sensitive_proxy = request_has_sensitive_proxy(request);
    let protect = |operation, error| protect_native_error(error, operation, sensitive_proxy);
    let capabilities = client
        .capabilities()
        .map_err(|error| protect("capabilities", error))?;
    let (provision, spec) = super::policy::provision_request(request, &capabilities)?;
    let exec = super::policy::exec_request(request, &capabilities)?;
    let input = ProvisionInput {
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
    state_root: tempfile::TempDir,
    request: &ExecutionRequest,
) -> Result<(), MxcError> {
    let sensitive_proxy = request_has_sensitive_proxy(request);
    let result = prepare_request(client, request).map(|_| ());
    let mut cleanup = Vec::new();
    if let Err(error) = client.close() {
        cleanup.push(protect_native_error(error, "close", sensitive_proxy));
    }
    if let Err(error) = state_root.close() {
        cleanup.push(MxcError::backend_error(format!(
            "cannot remove NVX state directory: {error}"
        )));
    }
    finish_run(
        result,
        cleanup,
        &mut Logger::new(crate::mxc_common::logger::Mode::Buffer),
    )
}

fn run_with_client(
    client: &mut impl SandboxClient,
    state_root: tempfile::TempDir,
    request: &ExecutionRequest,
    logger: &mut Logger,
    cancellation: Option<&RunCancellation>,
) -> Result<CapturedRun, MxcError> {
    let sensitive_proxy = request_has_sensitive_proxy(request);
    let protect = |operation, error| protect_native_error(error, operation, sensitive_proxy);
    let prepared = (|| {
        let (input, exec) = prepare_request(client, request)?;
        if let Some(cancellation) = cancellation {
            cancellation.check()?;
        }
        client.probe().map_err(|error| protect("probe", error))?;
        if let Some(cancellation) = cancellation {
            cancellation.check()?;
        }
        let sandbox_id = client
            .provision(&input)
            .map_err(|error| protect("provision", error))?;
        Ok((sandbox_id, exec))
    })();
    let (sandbox_id, exec) = match prepared {
        Ok(prepared) => prepared,
        Err(error) => {
            let mut cleanup = Vec::new();
            if let Err(close_error) = client.close() {
                cleanup.push(protect("close", close_error));
            }
            if let Err(remove_error) = state_root.close() {
                cleanup.push(MxcError::backend_error(format!(
                    "cannot remove NVX state: {remove_error}"
                )));
            }
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
        if let Err(error) = client.start(&sandbox_id) {
            let mut error = protect("start", error);
            if sensitive_proxy {
                error.message.push_str("; startup diagnostics withheld");
            } else {
                error.message.push_str("; startup diagnostics");
                match client.diagnostics(&sandbox_id) {
                    Ok(diagnostics) => {
                        error
                            .message
                            .push_str(&super::runtime::startup_diagnostics(&diagnostics));
                    }
                    Err(diagnostic_error) => {
                        error.message.push_str(" unavailable: ");
                        error.message.push_str(&diagnostic_error.to_string());
                    }
                }
            }
            return Err(error);
        }
        if let Some(cancellation) = cancellation {
            cancellation.check()?;
        }
        client
            .exec_and_wait(&sandbox_id, &exec, cancellation, logger)
            .map_err(|error| protect("exec", error))
    })();

    let stop_error = match client.stop(&sandbox_id).err() {
        Some(error) if primary.is_err() && error.code == MxcErrorCode::AlreadyStopped => None,
        other => other.map(|error| protect("stop", error)),
    };
    let deprovision_error = client
        .deprovision(&sandbox_id)
        .err()
        .map(|error| protect("deprovision", error));
    let retain_state = deprovision_error.is_some();
    let close_error = client.close().err().map(|error| protect("close", error));
    let mut cleanup_errors: Vec<MxcError> = [stop_error, deprovision_error, close_error]
        .into_iter()
        .flatten()
        .collect();
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

fn protect_native_error(mut error: MxcError, operation: &str, sensitive_proxy: bool) -> MxcError {
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
        if primary == "execution cancelled" || primary == capture_limit.message {
            if cleanup {
                error.message = format!(
                    "{primary}; execution cleanup failed; native error detail withheld because the configured proxy contains credentials"
                );
            }
            return error;
        }
    }
    error.message = format!(
        "NVX {operation} failed; native error detail withheld because the configured proxy contains credentials"
    );
    error
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
            captured_to_script_response(
                result,
                &mut std::io::stdout().lock(),
                &mut std::io::stderr().lock(),
            )
        });
        match result {
            Ok(response) => response,
            Err(error) => error_response(error),
        }
    }
}

fn error_response(error: MxcError) -> ScriptResponse {
    match error.code {
        MxcErrorCode::PolicyValidation | MxcErrorCode::MalformedRequest => {
            ScriptResponse::rejected(&error.message)
        }
        MxcErrorCode::BackendUnavailable => ScriptResponse::unavailable(&error.message),
        _ => ScriptResponse::failed(FailurePhase::PostLaunchFailed, &error.to_string()),
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
    Ok(result.response())
}

#[cfg(test)]
mod tests {
    use std::cell::RefCell;

    use super::super::abi::SandboxDiagnostics;
    use super::super::runtime::{ExecOutput, SandboxId};
    use super::*;

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
        assert_eq!(mapped.process.command_line, request.script_code);
        assert_eq!(mapped.process.timeout, Some(250));
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
        validated_provision: RefCell<Option<ProvisionInput>>,
        provisioned_input: RefCell<Option<ProvisionInput>>,
        capabilities_res: Result<Capabilities, MxcError>,
        validate_provision_res: Result<(), MxcError>,
        validate_res: Result<(), MxcError>,
        probe_res: Result<(), MxcError>,
        provision_res: Result<SandboxId, MxcError>,
        start_res: Result<(), MxcError>,
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
                probe_res: Ok(()),
                provision_res: SandboxId::from_token("0123456789abcdef0123456789abcdef"),
                start_res: Ok(()),
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

        fn validate_provision(&self, input: &ProvisionInput) -> Result<(), MxcError> {
            self.calls.borrow_mut().push("validate_provision");
            *self.validated_provision.borrow_mut() = Some(input.clone());
            self.validate_provision_res.clone()
        }

        fn validate_exec(&self, request: &ExecRequest) -> Result<(), MxcError> {
            self.record("validate");
            *self.validated_request.borrow_mut() = Some(request.clone());
            self.validate_res.clone()
        }

        fn probe(&self) -> Result<(), MxcError> {
            self.record("probe");
            self.probe_res.clone()
        }

        fn provision(&self, input: &ProvisionInput) -> Result<SandboxId, MxcError> {
            self.record("provision");
            *self.provisioned_input.borrow_mut() = Some(input.clone());
            self.provision_res.clone()
        }

        fn start(&self, _sandbox_id: &SandboxId) -> Result<(), MxcError> {
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
                    let path = state_root.path().to_path_buf();
                    let error = if dry_run {
                        validate_with_client(&mut client, state_root, &test_request()).unwrap_err()
                    } else {
                        run_with_client(
                            &mut client,
                            state_root,
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
                    assert!(!path.exists());
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
            let state_root = tempfile::tempdir().unwrap();
            let path = state_root.path().to_path_buf();
            let result = validate_with_client(&mut client, state_root, &test_request());
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
            assert!(!path.exists(), "{failure}");
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
        let state_root = tempfile::tempdir().unwrap();
        let path = state_root.path().to_path_buf();
        let error = validate_with_client(&mut client, state_root, &request).unwrap_err();
        assert_eq!(error.code, MxcErrorCode::PolicyValidation);
        assert!(error.message.contains("network.ingress.default=allow"));
        assert_eq!(*client.calls.borrow(), ["capabilities", "close"]);
        assert!(!path.exists());
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
        let state_root = tempfile::tempdir().unwrap();
        let path = state_root.path().to_path_buf();
        let error = validate_with_client(
            &mut client,
            state_root,
            &request_with_proxy("http://synthetic:secret@localhost:3128"),
        )
        .unwrap_err();
        assert_eq!(error.code, MxcErrorCode::PolicyValidation);
        assert!(error.message.contains("validate_provision"));
        assert!(error.message.contains("withheld"));
        assert!(!format!("{error:?}").contains("synthetic"));
        assert!(!path.exists());
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
                "probe" => client.probe_res = Err(failure),
                "provision" => client.provision_res = Err(failure),
                "start" => client.start_res = Err(failure),
                "exec" => client.exec_res = Err(failure),
                _ => unreachable!(),
            }
            let mut logger = Logger::new(crate::mxc_common::logger::Mode::Buffer);
            let error = run_with_client(
                &mut client,
                tempfile::tempdir().unwrap(),
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
            tempfile::tempdir().unwrap(),
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
                    tempfile::tempdir().unwrap(),
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
            tempfile::tempdir().unwrap(),
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
            tempfile::tempdir().unwrap(),
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
        let state_path = state_root.path().to_path_buf();
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
            state_root,
            &request_with_proxy("http://user:synthetic-secret@localhost:3128"),
            &mut Logger::new(crate::mxc_common::logger::Mode::Buffer),
            None,
        )
        .unwrap_err();
        assert!(error.message.contains("deprovision"));
        assert!(error.message.contains("withheld"));
        assert!(error.message.contains("state retained"));
        assert!(!error.message.contains("synthetic"));
        assert!(state_path.exists());
        std::fs::remove_dir_all(state_path).unwrap();
    }

    #[test]
    fn cancellation_during_startup_or_execution_runs_ordered_teardown() {
        for phase in ["validate", "probe", "provision", "start", "exec"] {
            for cleanup_fails in [false, true] {
                let cancellation = RunCancellation::default();
                let mut client = MockClient::ok();
                client.cancel_at = Some((phase, cancellation.clone()));
                if cleanup_fails {
                    client.close_res = Err(MxcError::backend_error("host_close failed"));
                }
                let state_root = tempfile::tempdir().unwrap();
                let path = state_root.path().to_path_buf();
                let error = run_with_client(
                    &mut client,
                    state_root,
                    &test_request(),
                    &mut Logger::new(crate::mxc_common::logger::Mode::Buffer),
                    Some(&cancellation),
                )
                .unwrap_err();
                assert_eq!(error.code, MxcErrorCode::BackendError);
                assert!(error.message.starts_with("execution cancelled"));
                assert!(cancellation.was_cancelled());
                assert!(!path.exists());
                let expected: &[&str] = match phase {
                    "validate" => &["validate", "close"],
                    "probe" => &["validate", "probe", "close"],
                    "provision" => &[
                        "validate",
                        "probe",
                        "provision",
                        "stop",
                        "deprovision",
                        "close",
                    ],
                    "start" => &[
                        "validate",
                        "probe",
                        "provision",
                        "start",
                        "stop",
                        "deprovision",
                        "close",
                    ],
                    _ => &[
                        "validate",
                        "probe",
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
        let path = state_root.path().to_path_buf();
        let error = run_with_client(
            &mut client,
            state_root,
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
        assert!(!path.exists());
        assert_eq!(
            client.calls.borrow().as_slice(),
            [
                "capabilities",
                "validate_provision",
                "validate",
                "probe",
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
                client.diagnostics_res = Ok(SandboxDiagnostics {
                    vmm_log: log,
                    console_log: state_path.join("missing-console"),
                    outcome_report: state_path.join("missing-outcome"),
                });
            }
            let error = run_with_client(
                &mut client,
                state_root,
                &test_request(),
                &mut Logger::new(crate::mxc_common::logger::Mode::Buffer),
                None,
            )
            .unwrap_err();
            assert!(
                !state_path.exists(),
                "diagnostics must not retain run state"
            );
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
        let state_path = state_root.path().to_path_buf();
        let mut client = MockClient::ok();
        client.probe_res = Err(MxcError::backend_unavailable("probe failed"));
        client.close_res = Err(MxcError::backend_error("host_close failed"));
        let err =
            run_with_client(&mut client, state_root, &request, &mut logger, None).unwrap_err();
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
        assert!(!state_path.exists());

        // 2. Start failure suppresses AlreadyStopped on stop, deprovisions, closes host, removes state.
        let state_root = tempfile::tempdir().unwrap();
        let state_path = state_root.path().to_path_buf();
        let mut client = MockClient::ok();
        client.start_res = Err(MxcError::backend_error("start failed"));
        client.stop_res = Err(MxcError::new(
            MxcErrorCode::AlreadyStopped,
            "already stopped",
        ));
        let err =
            run_with_client(&mut client, state_root, &request, &mut logger, None).unwrap_err();
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
                "provision",
                "start",
                "diagnostics",
                "stop",
                "deprovision",
                "close"
            ]
        );
        assert!(!state_path.exists());

        // 3. Host close failure after workload success fails the run.
        let state_root = tempfile::tempdir().unwrap();
        let state_path = state_root.path().to_path_buf();
        let mut client = MockClient::ok();
        client.close_res = Err(MxcError::backend_error("host_close failed"));
        let err =
            run_with_client(&mut client, state_root, &request, &mut logger, None).unwrap_err();
        assert!(err
            .message
            .contains("NVX cleanup failed after workload completion"));
        assert!(err.message.contains("host_close failed"));
        assert!(!state_path.exists());

        // 4. Deprovision failure retains state directory and fails the run.
        let state_root = tempfile::tempdir().unwrap();
        let state_path = state_root.path().to_path_buf();
        let mut client = MockClient::ok();
        client.deprovision_res = Err(MxcError::backend_error("deprovision failed"));
        let err =
            run_with_client(&mut client, state_root, &request, &mut logger, None).unwrap_err();
        assert!(err.message.contains("deprovision failed"));
        assert!(err
            .message
            .contains("NVX state retained for recovery after deprovision failure"));
        assert!(state_path.exists());
        std::fs::remove_dir_all(&state_path).unwrap();
    }

    #[test]
    fn native_validation_failure_closes_host_without_probing_or_provisioning() {
        for cleanup_fails in [false, true] {
            let mut logger = Logger::new(crate::mxc_common::logger::Mode::Buffer);
            let state_root = tempfile::tempdir().unwrap();
            let state_path = state_root.path().to_path_buf();
            let mut client = MockClient::ok();
            client.validate_res = Err(MxcError::policy_validation("native validation rejected"));
            if cleanup_fails {
                client.close_res = Err(MxcError::backend_error("close failed"));
            }
            let error =
                run_with_client(&mut client, state_root, &test_request(), &mut logger, None)
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
            assert!(!state_path.exists());
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
            let state_path = state_root.path().to_path_buf();
            let mut client = MockClient::ok();
            let result =
                run_with_client(&mut client, state_root, &request, &mut logger, None).unwrap();
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
                    "provision",
                    "start",
                    "exec",
                    "stop",
                    "deprovision",
                    "close"
                ]
            );
            assert!(!state_path.exists());
        }
    }

    #[test]
    fn capture_failure_runs_full_teardown_and_preserves_primary_and_cleanup_errors() {
        let primary = "NVX signed bundled agent: combined stdout/stderr capture limit of 67108864 bytes exceeded";
        for cleanup_fails in [false, true] {
            let mut logger = Logger::new(crate::mxc_common::logger::Mode::Buffer);
            let state_root = tempfile::tempdir().unwrap();
            let state_path = state_root.path().to_path_buf();
            let mut client = MockClient::ok();
            client.exec_res = Err(MxcError::backend_error(primary));
            if cleanup_fails {
                client.stop_res = Err(MxcError::backend_error("stop failed"));
                client.close_res = Err(MxcError::backend_error("close failed"));
            }
            let error =
                run_with_client(&mut client, state_root, &test_request(), &mut logger, None)
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
                    "provision",
                    "start",
                    "exec",
                    "stop",
                    "deprovision",
                    "close"
                ]
            );
            assert!(!state_path.exists());
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
        run_with_client(
            &mut client,
            tempfile::tempdir().unwrap(),
            &request,
            &mut logger,
            None,
        )
        .unwrap();
        let input = client.provisioned_input.borrow();
        assert_eq!(*input, *client.validated_provision.borrow());
        assert_eq!(
            serde_json::to_value(input.as_ref().unwrap()).unwrap(),
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
            let path = state_root.path().to_owned();
            let mut logger = Logger::new(crate::mxc_common::logger::Mode::Buffer);
            let error =
                run_with_client(&mut client, state_root, &request, &mut logger, None).unwrap_err();
            assert_eq!(error.code, expected_code);
            assert_eq!(error.message, expected_message);
            assert_eq!(*client.calls.borrow(), expected_calls);
            assert!(client.provisioned_input.borrow().is_none());
            assert!(!path.exists());
        }
    }
}
