// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Minimal create-and-run adapter for the signed bundled NVX agent.

use std::io::Write;

use crate::mxc_common::audit::{AuditEvent, AuditEventName};
use crate::mxc_common::logger::Logger;
use crate::mxc_common::models::{ExecutionRequest, FailurePhase, ScriptResponse};
use crate::mxc_common::mxc_error::{MxcError, MxcErrorCode};
use crate::mxc_common::script_runner::ScriptRunner;

#[cfg(test)]
use super::abi::{Capabilities, ExecRequest};
use super::abi::{ExecOutcome, ProvisionInput};
use super::runtime::SandboxClient;

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
        super::policy::validate_request(request)?;
        let state_root = tempfile::Builder::new()
            .prefix(&format!("mxc-nvx-{}-", std::process::id()))
            .tempdir()
            .map_err(|error| {
                MxcError::backend_unavailable(format!(
                    "cannot create a private NVX state directory: {error}"
                ))
            })?;
        let mut client = match super::runtime::create_client(state_root.path()) {
            Ok(client) => client,
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
        run_with_client(&mut client, state_root, request, logger)
    }
}

fn run_with_client(
    client: &mut impl SandboxClient,
    state_root: tempfile::TempDir,
    request: &ExecutionRequest,
    logger: &mut Logger,
) -> Result<CapturedRun, MxcError> {
    let prepared = (|| {
        let capabilities = client.capabilities()?;
        let (provision, spec) = super::policy::provision_request(request, &capabilities)?;
        let exec = super::policy::exec_request(request, &capabilities)?;
        let input = ProvisionInput {
            request: provision,
            spec,
        };
        client.validate_provision(&input)?;
        client.validate_exec(&exec)?;
        client.probe()?;
        let sandbox_id = client.provision(&input)?;
        Ok((sandbox_id, exec))
    })();
    let (sandbox_id, exec) = match prepared {
        Ok(prepared) => prepared,
        Err(error) => {
            let mut cleanup = Vec::new();
            if let Err(close_error) = client.close() {
                cleanup.push(close_error);
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
        client.start(&sandbox_id)?;
        client.exec_and_wait(&sandbox_id, &exec)
    })();

    let stop_error = match client.stop(&sandbox_id).err() {
        Some(error) if primary.is_err() && error.code == MxcErrorCode::AlreadyStopped => None,
        other => other,
    };
    let deprovision_error = client.deprovision(&sandbox_id).err();
    let retain_state = deprovision_error.is_some();
    let close_error = client.close().err();
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
    fn validate_runner(&self, request: &ExecutionRequest) -> Result<(), ScriptResponse> {
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
            Err(error) => ScriptResponse {
                exit_code: -1,
                error_message: error.to_string(),
                failure_phase: if error.code == MxcErrorCode::BackendUnavailable {
                    FailurePhase::BackendUnavailable
                } else {
                    FailurePhase::PostLaunchFailed
                },
                ..Default::default()
            },
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
    use std::cell::RefCell;

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
            microvm_image: Some("python:3.12-alpine".to_owned()),
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
            microvm_image: Some("python:3.12-alpine".to_owned()),
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
                microvm_image: Some("python:3.12-alpine".to_owned()),
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
        exec_res: Result<ExecOutput, MxcError>,
        stop_res: Result<(), MxcError>,
        deprovision_res: Result<(), MxcError>,
        close_res: Result<(), MxcError>,
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
                exec_res: Ok(ExecOutput {
                    outcome: ExecOutcome::Exited(0),
                    stdout: b"ok".to_vec(),
                    stderr: Vec::new(),
                }),
                stop_res: Ok(()),
                deprovision_res: Ok(()),
                close_res: Ok(()),
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
            self.calls.borrow_mut().push("validate");
            *self.validated_request.borrow_mut() = Some(request.clone());
            self.validate_res.clone()
        }

        fn probe(&self) -> Result<(), MxcError> {
            self.calls.borrow_mut().push("probe");
            self.probe_res.clone()
        }

        fn provision(&self, input: &ProvisionInput) -> Result<SandboxId, MxcError> {
            self.calls.borrow_mut().push("provision");
            *self.provisioned_input.borrow_mut() = Some(input.clone());
            self.provision_res.clone()
        }

        fn start(&self, _sandbox_id: &SandboxId) -> Result<(), MxcError> {
            self.calls.borrow_mut().push("start");
            self.start_res.clone()
        }

        fn exec_and_wait(
            &self,
            _sandbox_id: &SandboxId,
            request: &ExecRequest,
        ) -> Result<ExecOutput, MxcError> {
            self.calls.borrow_mut().push("exec");
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
        let err = run_with_client(&mut client, state_root, &request, &mut logger).unwrap_err();
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
        let err = run_with_client(&mut client, state_root, &request, &mut logger).unwrap_err();
        assert_eq!(err.message, "start failed");
        assert_eq!(
            *client.calls.borrow(),
            [
                "capabilities",
                "validate_provision",
                "validate",
                "probe",
                "provision",
                "start",
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
        let err = run_with_client(&mut client, state_root, &request, &mut logger).unwrap_err();
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
        let err = run_with_client(&mut client, state_root, &request, &mut logger).unwrap_err();
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
                run_with_client(&mut client, state_root, &test_request(), &mut logger).unwrap_err();
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
            let result = run_with_client(&mut client, state_root, &request, &mut logger).unwrap();
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
                run_with_client(&mut client, state_root, &test_request(), &mut logger).unwrap_err();
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
        let request = crate::policy::prepare_creation_request(
            &crate::v1::ContainerRequest {
                containment: crate::v1::Containment::MicroVm {
                    image: "python:3.12-alpine".to_owned(),
                },
                filesystem: Some(crate::v1::FilesystemPolicy {
                    readonly_paths: vec![r"C:\ro".to_owned()],
                    readwrite_paths: vec![r"C:\rw".to_owned()],
                    denied_paths: vec![r"C:\rw\secret".to_owned()],
                    ..Default::default()
                }),
                network: Some(crate::v1::NetworkPolicy::default()),
                ..crate::v1::ContainerRequest::new("printf ok")
            },
            None,
        )
        .unwrap()
        .inner;
        let mut client = MockClient::ok();
        let mut logger = Logger::new(crate::mxc_common::logger::Mode::Buffer);
        run_with_client(
            &mut client,
            tempfile::tempdir().unwrap(),
            &request,
            &mut logger,
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
                "spec": {"image": {"reference": "python:3.12-alpine"}}
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
                run_with_client(&mut client, state_root, &request, &mut logger).unwrap_err();
            assert_eq!(error.code, expected_code);
            assert_eq!(error.message, expected_message);
            assert_eq!(*client.calls.borrow(), expected_calls);
            assert!(client.provisioned_input.borrow().is_none());
            assert!(!path.exists());
        }
    }
}
