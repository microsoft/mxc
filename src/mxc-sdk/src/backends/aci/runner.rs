// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Create-and-run adapter for ACI sandboxes: creates a sandbox, waits for its
//! guest, runs one command, captures its output, and deletes the sandbox.

use std::time::{Duration, Instant};

use crate::mxc_common::audit::{AuditEvent, AuditEventName};
use crate::mxc_common::captured_run::{
    error_response, finish_with_cleanup, CapturedOutcome, CapturedRun,
};
use crate::mxc_common::logger::Logger;
use crate::mxc_common::models::{ExecutionRequest, ScriptResponse};
use crate::mxc_common::mxc_error::MxcError;
use crate::mxc_common::script_runner::{RunCancellation, ScriptRunner};

use super::credentials;
use super::gateway::{ExecReply, Gateway, GatewayAddress, GrpcStatus, GRPC_DEADLINE_EXCEEDED};
use super::policy::{self, ExecSpec, SandboxSpec};
use super::proto::{SandboxState, WaitForReadyResponse};
use super::service::{self, bounded, DataPlane, Rest, SandboxGroup};

const BACKEND_LABEL: &str = "ACI";
/// How long the sandbox may take from creation until its guest is ready,
/// including the image pull.
const STARTUP_TIMEOUT: Duration = Duration::from_secs(300);
/// The gateway ends each readiness wait after 30 seconds.
const READY_WAIT_SECONDS: u32 = 30;
#[cfg(not(test))]
const READY_RETRY_PAUSE: Duration = Duration::from_secs(1);
#[cfg(test)]
const READY_RETRY_PAUSE: Duration = Duration::from_millis(10);
const CREATE_POLL_INTERVAL: Duration = Duration::from_secs(1);

const GRPC_UNKNOWN: u32 = 2;
const GRPC_INTERNAL: u32 = 13;
const GRPC_UNAVAILABLE: u32 = 14;

/// The Azure operations one create-and-run needs.
pub(super) trait SandboxService {
    /// Creates the sandbox and returns its gateway once the service reports
    /// one, or fails once `deadline` passes.
    fn create_sandbox(
        &mut self,
        name: &str,
        spec: &SandboxSpec,
        deadline: Instant,
        cancellation: Option<&RunCancellation>,
    ) -> Result<GatewayAddress, MxcError>;
    /// The reason the service gives for a sandbox that cannot start, if any.
    fn sandbox_failure(&mut self, name: &str) -> Result<Option<String>, MxcError>;
    fn wait_for_ready(
        &mut self,
        gateway: &GatewayAddress,
        wait_seconds: u32,
        cancellation: Option<&RunCancellation>,
    ) -> Result<Result<WaitForReadyResponse, GrpcStatus>, MxcError>;
    fn sandbox_state(&mut self, gateway: &GatewayAddress) -> Result<SandboxState, MxcError>;
    fn exec(
        &mut self,
        gateway: &GatewayAddress,
        spec: &ExecSpec,
        cancellation: Option<&RunCancellation>,
    ) -> Result<ExecReply, MxcError>;
    /// Requests deletion; a sandbox that no longer exists is deleted.
    fn delete_sandbox(&mut self, name: &str) -> Result<(), MxcError>;
}

#[derive(Debug, Default)]
pub struct AciRunner {
    cancellation: RunCancellation,
}

impl AciRunner {
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

    fn run_captured_inner(
        &mut self,
        request: &ExecutionRequest,
        logger: &mut Logger,
    ) -> Result<CapturedRun, MxcError> {
        let spec = policy::sandbox_spec(request)?;
        let exec = policy::exec_spec(request);
        self.cancellation.check()?;
        let mut service = AzureService::connect(&spec.group)?;
        run_with_service(&mut service, &spec, &exec, logger, Some(&self.cancellation))
    }

    /// Checks the request, credentials, and sandbox group access without
    /// creating a sandbox.
    fn validate_dry_run(request: &ExecutionRequest) -> Result<(), MxcError> {
        let spec = policy::sandbox_spec(request)?;
        AzureService::connect(&spec.group).map(|_| ())
    }
}

/// A sandbox name that is unique to this run.
fn sandbox_name() -> String {
    format!("mxc-{}", uuid::Uuid::new_v4().simple())
}

fn run_with_service(
    service: &mut impl SandboxService,
    spec: &SandboxSpec,
    exec: &ExecSpec,
    logger: &mut Logger,
    cancellation: Option<&RunCancellation>,
) -> Result<CapturedRun, MxcError> {
    let check = || cancellation.map_or(Ok(()), RunCancellation::check);
    check()?;
    let name = sandbox_name();
    let identity = format!("{}/sandboxes/{name}", spec.group.id);
    logger.log_audit_event(
        &AuditEvent::new(AuditEventName::SandboxIdentity)
            .str("identity", &identity)
            .str("backend", "aci")
            .str("runtime", "azure-container-instances"),
    );
    let deadline = Instant::now() + STARTUP_TIMEOUT;
    // A failed creation can still leave a sandbox, so deletion always follows.
    let primary = service
        .create_sandbox(&name, spec, deadline, cancellation)
        .and_then(|gateway| {
            check()?;
            wait_until_ready(service, &name, &gateway, deadline, cancellation)?;
            check()?;
            logger.log_diagnostic_line("ACI execution started");
            service.exec(&gateway, exec, cancellation)
        });
    let cleanup: Vec<MxcError> = service
        .delete_sandbox(&name)
        .err()
        .map(|mut error| {
            error.message.push_str(&format!(
                "; delete sandbox {name} from sandbox group {} to release its resources",
                spec.group.id
            ));
            error
        })
        .into_iter()
        .collect();
    logger.log_audit_event(
        &AuditEvent::new(AuditEventName::SandboxTornDown)
            .str("identity", &identity)
            .str("backend", "aci")
            .str("status", if cleanup.is_empty() { "ok" } else { "failed" }),
    );
    let reply = finish_with_cleanup(BACKEND_LABEL, primary, cleanup, logger)?;
    captured_run(reply)
}

fn captured_run(reply: ExecReply) -> Result<CapturedRun, MxcError> {
    let (outcome, stdout, stderr) = match reply {
        ExecReply::TimedOut => (CapturedOutcome::TimedOut, Vec::new(), Vec::new()),
        ExecReply::Completed(response) if response.timed_out => {
            (CapturedOutcome::TimedOut, response.stdout, response.stderr)
        }
        // The gateway reports a process it could not start, such as a missing
        // shell or working directory, as a negative exit code.
        ExecReply::Completed(response) if response.exit_code < 0 => {
            return Err(MxcError::backend_error(format!(
                "ACI could not start the command: {}",
                bounded(&String::from_utf8_lossy(&response.stderr))
            )));
        }
        ExecReply::Completed(response) => (
            CapturedOutcome::Exited(response.exit_code),
            response.stdout,
            response.stderr,
        ),
    };
    Ok(CapturedRun {
        outcome,
        warnings: Vec::new(),
        stdout,
        stderr,
        backend_label: BACKEND_LABEL,
    })
}

/// Waits for the guest, consulting the sandbox state between waits because
/// the gateway reports a sandbox that is still starting as an error.
fn wait_until_ready(
    service: &mut impl SandboxService,
    name: &str,
    gateway: &GatewayAddress,
    deadline: Instant,
    cancellation: Option<&RunCancellation>,
) -> Result<(), MxcError> {
    let mut last_wait = String::from("no readiness reply");
    let mut last_state = None;
    loop {
        if let Some(cancellation) = cancellation {
            cancellation.check()?;
        }
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err(startup_error(
                name,
                &format!(
                    "the sandbox did not become ready within {} s",
                    STARTUP_TIMEOUT.as_secs()
                ),
                &last_wait,
                last_state.as_ref(),
            ));
        }
        let wait_seconds = u32::try_from(remaining.as_secs())
            .unwrap_or(u32::MAX)
            .clamp(1, READY_WAIT_SECONDS);
        let started = Instant::now();
        match service.wait_for_ready(gateway, wait_seconds, cancellation)? {
            Ok(response) if response.ready => return Ok(()),
            Ok(response) => {
                last_wait = format!("guest state {}", describe(&response));
                if response.current_state.eq_ignore_ascii_case("failed") {
                    let state = service.sandbox_state(gateway).ok();
                    return Err(startup_error(
                        name,
                        "the guest failed to start",
                        &last_wait,
                        state.as_ref(),
                    ));
                }
            }
            Err(status) if is_transient(&status) => {
                last_wait = format!("gRPC status {}: {}", status.code, status.message);
            }
            Err(status) => return Err(status.into_error("WaitForReady")),
        }
        if let Some(failure) = service.sandbox_failure(name)? {
            return Err(startup_error(
                name,
                &failure,
                &last_wait,
                last_state.as_ref(),
            ));
        }
        if let Ok(state) = service.sandbox_state(gateway) {
            if !state.failure_message.is_empty()
                || state.current_state.eq_ignore_ascii_case("failed")
            {
                return Err(startup_error(
                    name,
                    "the guest failed to start",
                    &last_wait,
                    Some(&state),
                ));
            }
            last_state = Some(state);
        }
        // A wait that ended early is not a reason to call again immediately.
        if started.elapsed() < READY_RETRY_PAUSE {
            std::thread::sleep(
                READY_RETRY_PAUSE.min(deadline.saturating_duration_since(Instant::now())),
            );
        }
    }
}

fn is_transient(status: &GrpcStatus) -> bool {
    matches!(
        status.code,
        GRPC_UNKNOWN | GRPC_DEADLINE_EXCEEDED | GRPC_INTERNAL | GRPC_UNAVAILABLE
    )
}

fn describe(response: &WaitForReadyResponse) -> String {
    let mut text = if response.current_state.is_empty() {
        "unknown".to_owned()
    } else {
        response.current_state.clone()
    };
    for detail in [&response.reason, &response.error_code] {
        if !detail.is_empty() {
            text.push_str(&format!(" ({})", bounded(detail)));
        }
    }
    text
}

/// A startup failure with bounded diagnostics, as NVX reports startup logs.
fn startup_error(
    name: &str,
    reason: &str,
    last_wait: &str,
    state: Option<&SandboxState>,
) -> MxcError {
    let mut message = format!(
        "ACI sandbox {name} did not start: {}; startup diagnostics: last readiness check: {}",
        bounded(reason),
        bounded(last_wait)
    );
    match state {
        Some(state) => {
            message.push_str(&format!(
                "; sandbox state: current {}, target {}",
                or_unknown(&state.current_state),
                or_unknown(&state.target_state)
            ));
            if !state.failure_message.is_empty() {
                message.push_str(&format!("; failure: {}", bounded(&state.failure_message)));
            }
        }
        None => message.push_str("; sandbox state unavailable"),
    }
    MxcError::backend_error(message)
}

fn or_unknown(value: &str) -> &str {
    if value.is_empty() {
        "unknown"
    } else {
        value
    }
}

impl ScriptRunner for AciRunner {
    fn cancellation(&self) -> Option<RunCancellation> {
        Some(self.cancellation.clone())
    }

    fn validate_runner(&self, request: &ExecutionRequest) -> Result<(), ScriptResponse> {
        let result = if request.dry_run {
            Self::validate_dry_run(request)
        } else {
            policy::validate_request(request).map(|_| ())
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

/// [`SandboxService`] backed by Azure Resource Manager, the sandbox group's
/// data plane, and the sandbox gateway.
struct AzureService {
    rest: Rest,
    group: SandboxGroup,
    location: String,
    data_plane: DataPlane,
}

impl AzureService {
    fn connect(group: &SandboxGroup) -> Result<Self, MxcError> {
        let rest = Rest::new();
        let token = credentials::arm_token(&group.subscription)?;
        let location = service::group_location(&rest, group, &token)?;
        let data_plane = service::connect(&rest, group, &token)?;
        Ok(Self {
            rest,
            group: group.clone(),
            location,
            data_plane,
        })
    }

    /// Opens a new data-plane session when the current one is about to expire,
    /// as it can after a long command.
    fn refresh_if_expiring(&mut self) -> Result<(), MxcError> {
        if self.data_plane.expires_soon() {
            let token = credentials::arm_token(&self.group.subscription)?;
            self.data_plane = service::connect(&self.rest, &self.group, &token)?;
        }
        Ok(())
    }
}

fn is_terminal_provisioning_state(state: &str) -> bool {
    ["Failed", "Canceled", "Cancelled", "Deleting", "Deleted"]
        .iter()
        .any(|terminal| state.eq_ignore_ascii_case(terminal))
}

impl SandboxService for AzureService {
    fn create_sandbox(
        &mut self,
        name: &str,
        spec: &SandboxSpec,
        deadline: Instant,
        cancellation: Option<&RunCancellation>,
    ) -> Result<GatewayAddress, MxcError> {
        let created = self
            .data_plane
            .put_sandbox(&self.rest, name, &spec.body(&self.location))?;
        let resource = if created.connection_string.is_some()
            || is_terminal_provisioning_state(&created.provisioning_state)
        {
            Some(created)
        } else {
            service::poll_until(deadline, CREATE_POLL_INTERVAL, || {
                if let Some(cancellation) = cancellation {
                    cancellation.check()?;
                }
                Ok(self
                    .data_plane
                    .get_sandbox(&self.rest, name)?
                    .filter(|resource| {
                        resource.connection_string.is_some()
                            || is_terminal_provisioning_state(&resource.provisioning_state)
                    }))
            })?
        };
        let resource = resource.ok_or_else(|| {
            MxcError::backend_error(format!(
                "ACI sandbox {name} was not provisioned within {} s",
                STARTUP_TIMEOUT.as_secs()
            ))
        })?;
        if is_terminal_provisioning_state(&resource.provisioning_state) {
            return Err(MxcError::backend_error(format!(
                "ACI could not provision sandbox {name} (state {}): {}",
                resource.provisioning_state,
                resource
                    .error_message
                    .as_deref()
                    .unwrap_or("the service gave no reason")
            )));
        }
        let connection = resource.connection_string.ok_or_else(|| {
            MxcError::backend_error(format!("ACI returned no connection for sandbox {name}"))
        })?;
        GatewayAddress::parse(&connection)
    }

    fn sandbox_failure(&mut self, name: &str) -> Result<Option<String>, MxcError> {
        Ok(match self.data_plane.get_sandbox(&self.rest, name)? {
            None => Some("the sandbox no longer exists".to_owned()),
            Some(resource) if is_terminal_provisioning_state(&resource.provisioning_state) => {
                Some(format!(
                    "the sandbox is {}: {}",
                    resource.provisioning_state,
                    resource
                        .error_message
                        .as_deref()
                        .unwrap_or("the service gave no reason")
                ))
            }
            Some(_) => None,
        })
    }

    fn wait_for_ready(
        &mut self,
        gateway: &GatewayAddress,
        wait_seconds: u32,
        cancellation: Option<&RunCancellation>,
    ) -> Result<Result<WaitForReadyResponse, GrpcStatus>, MxcError> {
        Gateway::new(gateway.clone()).wait_for_ready(wait_seconds, cancellation)
    }

    fn sandbox_state(&mut self, gateway: &GatewayAddress) -> Result<SandboxState, MxcError> {
        Gateway::new(gateway.clone()).sandbox_state()
    }

    fn exec(
        &mut self,
        gateway: &GatewayAddress,
        spec: &ExecSpec,
        cancellation: Option<&RunCancellation>,
    ) -> Result<ExecReply, MxcError> {
        Gateway::new(gateway.clone()).exec(&spec.request, spec.timeout, cancellation)
    }

    fn delete_sandbox(&mut self, name: &str) -> Result<(), MxcError> {
        self.refresh_if_expiring()?;
        self.data_plane.delete_sandbox(&self.rest, name)
    }
}

#[cfg(test)]
mod tests {
    use std::collections::VecDeque;

    use super::*;
    use crate::mxc_common::models::{AciConfig, ContainmentBackend, FailurePhase};
    use crate::mxc_common::mxc_error::MxcErrorCode;

    const GROUP: &str = "/subscriptions/51aca303-03da-4510-849d-d4f32d3f39ac/resourceGroups/tryme-01/providers/Microsoft.ContainerInstance/sandboxGroups/sbg-001";

    fn request() -> ExecutionRequest {
        ExecutionRequest {
            script_code: "echo ok".to_owned(),
            containment: ContainmentBackend::Aci,
            aci: Some(AciConfig {
                sandbox_group: GROUP.to_owned(),
                image: "mcr.microsoft.com/azurelinux/base/core:3.0".to_owned(),
                cpu: None,
                memory_gb: None,
            }),
            ..ExecutionRequest::default()
        }
    }

    fn gateway() -> GatewayAddress {
        GatewayAddress::parse(
            &credentials::Secret::new(
                "address=gateway.example.com;token=eyJ0.eyJ1.sig;token_type=bearer".to_owned(),
                "connection string",
            )
            .unwrap(),
        )
        .unwrap()
    }

    #[derive(Default)]
    struct FakeService {
        calls: Vec<String>,
        create: Option<Result<(), MxcError>>,
        waits: VecDeque<Result<Result<WaitForReadyResponse, GrpcStatus>, MxcError>>,
        failure: Option<String>,
        state: SandboxState,
        exec: Option<Result<ExecReply, MxcError>>,
        delete: Option<MxcError>,
        cancel_during: Option<(&'static str, RunCancellation)>,
    }

    impl FakeService {
        fn record(&mut self, call: &str) {
            self.calls.push(call.to_owned());
            if let Some((when, cancellation)) = &self.cancel_during {
                if *when == call {
                    cancellation.request();
                }
            }
        }

        fn names(&self) -> Vec<&str> {
            self.calls.iter().map(String::as_str).collect()
        }
    }

    fn ready() -> Result<Result<WaitForReadyResponse, GrpcStatus>, MxcError> {
        Ok(Ok(WaitForReadyResponse {
            ready: true,
            current_state: "running".to_owned(),
            ..Default::default()
        }))
    }

    fn completed(
        exit_code: i32,
        stdout: &[u8],
        stderr: &[u8],
    ) -> Option<Result<ExecReply, MxcError>> {
        Some(Ok(ExecReply::Completed(
            super::super::proto::ExecSandboxResponse {
                exit_code,
                stdout: stdout.to_vec(),
                stderr: stderr.to_vec(),
                timed_out: false,
            },
        )))
    }

    impl SandboxService for FakeService {
        fn create_sandbox(
            &mut self,
            name: &str,
            spec: &SandboxSpec,
            _deadline: Instant,
            _cancellation: Option<&RunCancellation>,
        ) -> Result<GatewayAddress, MxcError> {
            assert!(name.starts_with("mxc-") && name.len() == 36, "{name}");
            assert_eq!(spec.group.id, GROUP);
            self.record("create");
            self.create.take().unwrap_or(Ok(())).map(|()| gateway())
        }

        fn sandbox_failure(&mut self, _name: &str) -> Result<Option<String>, MxcError> {
            self.record("failure");
            Ok(self.failure.clone())
        }

        fn wait_for_ready(
            &mut self,
            _gateway: &GatewayAddress,
            wait_seconds: u32,
            _cancellation: Option<&RunCancellation>,
        ) -> Result<Result<WaitForReadyResponse, GrpcStatus>, MxcError> {
            assert!((1..=READY_WAIT_SECONDS).contains(&wait_seconds));
            self.record("wait");
            self.waits.pop_front().unwrap_or_else(ready)
        }

        fn sandbox_state(&mut self, _gateway: &GatewayAddress) -> Result<SandboxState, MxcError> {
            self.record("state");
            Ok(self.state.clone())
        }

        fn exec(
            &mut self,
            _gateway: &GatewayAddress,
            spec: &ExecSpec,
            _cancellation: Option<&RunCancellation>,
        ) -> Result<ExecReply, MxcError> {
            assert_eq!(spec.request.args, ["-c", "echo ok"]);
            self.record("exec");
            self.exec
                .take()
                .unwrap_or_else(|| completed(0, b"", b"").unwrap())
        }

        fn delete_sandbox(&mut self, _name: &str) -> Result<(), MxcError> {
            self.record("delete");
            self.delete.take().map_or(Ok(()), Err)
        }
    }

    /// Runs `service` and returns the result and the audit records it logged.
    fn run(
        service: &mut FakeService,
        cancellation: Option<&RunCancellation>,
    ) -> (Result<CapturedRun, MxcError>, String) {
        let request = request();
        let spec = policy::sandbox_spec(&request).unwrap();
        let exec = policy::exec_spec(&request);
        let directory = tempfile::tempdir().unwrap();
        let audit_path = directory.path().join("audit.log");
        let mut logger = Logger::new(crate::mxc_common::logger::Mode::Buffer);
        logger.enable_file_sink(&audit_path).unwrap();
        let result = run_with_service(service, &spec, &exec, &mut logger, cancellation);
        drop(logger);
        (result, std::fs::read_to_string(&audit_path).unwrap())
    }

    #[test]
    fn a_completed_command_returns_its_output_and_deletes_the_sandbox() {
        let mut service = FakeService {
            exec: completed(3, b"out\xff", b"err"),
            ..Default::default()
        };
        let (result, audit) = run(&mut service, None);
        let result = result.unwrap();
        assert_eq!(result.outcome, CapturedOutcome::Exited(3));
        assert_eq!(result.stdout, b"out\xff");
        assert_eq!(result.stderr, b"err");
        assert_eq!(result.backend_label, "ACI");
        assert_eq!(service.names(), ["create", "wait", "exec", "delete"]);
        assert!(audit.contains("mxc.SandboxIdentity"), "{audit}");
        assert!(audit.contains("mxc.SandboxTornDown"), "{audit}");
        assert!(
            audit.contains(&format!("{GROUP}/sandboxes/mxc-")),
            "{audit}"
        );
        assert!(audit.contains(r#""status":"ok""#), "{audit}");
    }

    #[test]
    fn timeouts_map_to_the_timed_out_outcome() {
        for reply in [
            ExecReply::TimedOut,
            ExecReply::Completed(super::super::proto::ExecSandboxResponse {
                exit_code: 0,
                stdout: b"partial".to_vec(),
                stderr: Vec::new(),
                timed_out: true,
            }),
        ] {
            let mut service = FakeService {
                exec: Some(Ok(reply)),
                ..Default::default()
            };
            let (result, _) = run(&mut service, None);
            let result = result.unwrap();
            assert_eq!(result.outcome, CapturedOutcome::TimedOut);
            let response = result.response();
            assert_eq!(response.failure_phase, FailurePhase::Timeout);
            assert_eq!(response.error_message, "ACI workload timed out");
            assert_eq!(service.calls.last().unwrap(), "delete");
        }
    }

    #[test]
    fn a_command_the_gateway_cannot_start_is_an_error_not_an_exit_code() {
        let mut service = FakeService {
            exec: completed(
                -1,
                b"",
                b"An error occurred trying to start process '/bin/sh' with working directory '/missing'.",
            ),
            ..Default::default()
        };
        let (result, _) = run(&mut service, None);
        let error = result.unwrap_err();
        assert_eq!(error.code, MxcErrorCode::BackendError);
        assert!(
            error.message.contains("could not start the command"),
            "{error}"
        );
        assert!(error.message.contains("/missing"), "{error}");
        assert_eq!(service.calls.last().unwrap(), "delete");
    }

    #[test]
    fn failed_creation_still_deletes_and_keeps_the_primary_error() {
        let mut service = FakeService {
            create: Some(Err(MxcError::malformed_request("ACI rejected the request"))),
            delete: Some(MxcError::backend_error(
                "ACI could not delete the sandbox (HTTP 500)",
            )),
            ..Default::default()
        };
        let (result, _) = run(&mut service, None);
        let error = result.unwrap_err();
        assert_eq!(error.code, MxcErrorCode::MalformedRequest);
        assert!(error.message.contains("ACI rejected the request"));
        assert!(error.message.contains("cleanup failure"));
        assert!(error.message.contains("to release its resources"));
        assert_eq!(service.names(), ["create", "delete"]);
    }

    #[test]
    fn a_cleanup_failure_after_success_is_an_error() {
        let mut service = FakeService {
            delete: Some(MxcError::backend_error("delete failed")),
            ..Default::default()
        };
        let (result, audit) = run(&mut service, None);
        let error = result.unwrap_err();
        assert_eq!(error.code, MxcErrorCode::BackendError);
        assert!(error
            .message
            .starts_with("ACI cleanup failed after workload completion"));
        assert!(audit.contains(r#""status":"failed""#), "{audit}");
    }

    #[test]
    fn startup_waits_through_transient_statuses_and_reports_failures() {
        let mut service = FakeService {
            waits: VecDeque::from([
                Ok(Err(GrpcStatus {
                    code: GRPC_INTERNAL,
                    message: "An internal error occurred.".to_owned(),
                })),
                Ok(Ok(WaitForReadyResponse {
                    ready: false,
                    current_state: "creating".to_owned(),
                    ..Default::default()
                })),
            ]),
            state: SandboxState {
                current_state: "creating".to_owned(),
                target_state: "running".to_owned(),
                failure_message: String::new(),
            },
            ..Default::default()
        };
        let (result, _) = run(&mut service, None);
        assert!(result.is_ok());
        assert_eq!(
            service.names(),
            [
                "create", "wait", "failure", "state", "wait", "failure", "state", "wait", "exec",
                "delete"
            ]
        );

        let mut failed = FakeService {
            waits: VecDeque::from([Ok(Err(GrpcStatus {
                code: GRPC_INTERNAL,
                message: "An internal error occurred.".to_owned(),
            }))]),
            state: SandboxState {
                current_state: "failed".to_owned(),
                target_state: "running".to_owned(),
                failure_message: "image pull failed".to_owned(),
            },
            ..Default::default()
        };
        let (result, _) = run(&mut failed, None);
        let error = result.unwrap_err();
        assert_eq!(error.code, MxcErrorCode::BackendError);
        assert!(error.message.contains("did not start"), "{error}");
        assert!(
            error.message.contains("failure: image pull failed"),
            "{error}"
        );
        assert!(
            error.message.contains("INTERNAL") || error.message.contains("13"),
            "{error}"
        );
        assert_eq!(failed.calls.last().unwrap(), "delete");
        assert!(!failed.calls.contains(&"exec".to_owned()));

        let mut provisioning_failed = FakeService {
            waits: VecDeque::from([Ok(Err(GrpcStatus {
                code: GRPC_UNAVAILABLE,
                message: String::new(),
            }))]),
            failure: Some("the sandbox is Failed: Allocation failed permanently".to_owned()),
            ..Default::default()
        };
        let (result, _) = run(&mut provisioning_failed, None);
        assert!(result
            .unwrap_err()
            .message
            .contains("Allocation failed permanently"));

        let mut rejected = FakeService {
            waits: VecDeque::from([Ok(Err(GrpcStatus {
                code: 16,
                message: "bad token".to_owned(),
            }))]),
            ..Default::default()
        };
        let (result, _) = run(&mut rejected, None);
        assert!(result.unwrap_err().message.contains("UNAUTHENTICATED"));
        assert_eq!(rejected.calls.last().unwrap(), "delete");
    }

    #[test]
    fn cancellation_stops_before_exec_and_still_deletes() {
        let cancellation = RunCancellation::default();
        let mut service = FakeService {
            cancel_during: Some(("create", cancellation.clone())),
            ..Default::default()
        };
        cancellation.begin();
        let (result, _) = run(&mut service, Some(&cancellation));
        assert_eq!(result.unwrap_err().message, "execution cancelled");
        assert!(cancellation.was_cancelled());
        assert_eq!(service.names(), ["create", "delete"]);
    }

    #[test]
    fn a_cancelled_runner_does_not_create_a_sandbox_and_can_be_reused() {
        let mut runner = AciRunner::new();
        let signal = runner.cancellation().unwrap();
        assert!(signal.request());
        let error = runner
            .run_captured(
                &request(),
                &mut Logger::new(crate::mxc_common::logger::Mode::Buffer),
            )
            .unwrap_err();
        assert_eq!(error.message, "execution cancelled");
        assert!(signal.was_cancelled());
        assert!(
            !signal.request(),
            "a finished run must not accept a late request"
        );
        signal.begin();
        assert!(signal.check().is_ok());
    }

    #[test]
    fn invalid_requests_fail_before_any_azure_call() {
        let mut runner = AciRunner::new();
        let mut request = request();
        request.policy.readonly_paths = vec![r"C:\data".to_owned()];
        let error = runner
            .run_captured(
                &request,
                &mut Logger::new(crate::mxc_common::logger::Mode::Buffer),
            )
            .unwrap_err();
        assert_eq!(error.code, MxcErrorCode::PolicyValidation);
        let response = runner.validate_runner(&request).unwrap_err();
        assert_eq!(response.failure_phase, FailurePhase::Rejected);
    }

    #[test]
    fn provisioning_states_that_end_creation_are_recognized() {
        for state in ["Failed", "canceled", "Cancelled", "Deleting", "deleted"] {
            assert!(is_terminal_provisioning_state(state), "{state}");
        }
        for state in ["Succeeded", "Creating", "Updating", ""] {
            assert!(!is_terminal_provisioning_state(state), "{state}");
        }
    }
}
