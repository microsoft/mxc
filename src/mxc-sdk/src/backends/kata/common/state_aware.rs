// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Container lifecycle operations for the Kata backend.
//!
//! Each operation maps to one [`Sandbox`] call. The sandbox identifier is
//! `kata:<token>`, where the token names a directory under the state
//! directory, so a later call, possibly from another process, finds the
//! sandbox again.

use std::io::{self, PipeWriter};
use std::os::fd::AsRawFd;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use crate::kata_common::error::KataError;
use crate::kata_common::execution::{ExitOutcome, KillScope, Pump, StdinWriter};
use crate::kata_common::host;
use crate::kata_common::policy;
use crate::kata_common::sandbox::{is_valid_token, Sandbox};
use crate::mxc_common::logger::{Logger, Mode};
use crate::mxc_common::models::{ExecutionRequest, KataConfig};
use crate::mxc_common::mxc_error::MxcError;
use crate::mxc_common::state_aware_backend::{
    null_pipe_handle, DeprovisionResult, ExecHandle, ExecOutcome, ExecStdio, PipeHandle,
    ProvisionResult, StartResult, StatefulSandboxBackend, StopResult,
};

/// The lifecycle runner for the Kata backend.
#[derive(Debug, Default)]
pub struct KataStateAwareRunner;

impl KataStateAwareRunner {
    pub fn new() -> Self {
        Self
    }
}

/// The token in `kata:<token>`.
fn token_of(sandbox_id: &str) -> Result<&str, MxcError> {
    let token = sandbox_id.strip_prefix("kata:").ok_or_else(|| {
        MxcError::malformed_id(format!(
            "sandbox id {sandbox_id:?} is not a Kata sandbox id"
        ))
    })?;
    if is_valid_token(token) {
        Ok(token)
    } else {
        Err(MxcError::malformed_id(format!(
            "sandbox id {sandbox_id:?} is malformed: kata ids are kata:<8 hexadecimal digits>"
        )))
    }
}

fn open(sandbox_id: &str) -> Result<Sandbox, MxcError> {
    let token = token_of(sandbox_id)?;
    Sandbox::open(&host::state_dir(&host::process_env), token).map_err(KataError::into_mxc_error)
}

/// Accepts a provision request and finds what it needs on the host.
fn plan_provision(
    request: &ExecutionRequest,
    config: Option<&KataConfig>,
) -> Result<(policy::Plan, host::Install), KataError> {
    let config = config.ok_or_else(|| {
        KataError::rejected("provisioning a kata sandbox requires the kata section")
    })?;
    let mut logger = Logger::new(Mode::Buffer);
    let plan = policy::plan(request, config, &host::process_env, &mut logger)?;
    let install = host::locate_installed(plan.hypervisor).map_err(KataError::unavailable)?;
    host::check_prerequisites().map_err(KataError::unavailable)?;
    Ok((plan, install))
}

/// Descriptors the exec handle lends out. They stay open until the waiter
/// finishes, and consumers duplicate them rather than closing these.
struct Streams {
    _stdout: std::os::fd::OwnedFd,
    _stderr: std::os::fd::OwnedFd,
}

/// The stdin a piped exec lends: the write end of a pipe that a pump copies
/// into the process's FIFO. The process sees end of input only when every write
/// end is closed, the caller's included, as for any other backend's pipe. The
/// FIFO alone cannot say so, because Kata needs an explicit CloseIO.
struct StdinRelay {
    write_end: Arc<Mutex<Option<PipeWriter>>>,
    pump: Pump,
}

impl StdinRelay {
    fn start(writer: StdinWriter) -> io::Result<Self> {
        let (write_end, pump) = Pump::pipe(writer)?;
        Ok(Self {
            write_end: Arc::new(Mutex::new(Some(write_end))),
            pump,
        })
    }

    fn handle(&self) -> PipeHandle {
        let end = self.write_end.lock().unwrap_or_else(|e| e.into_inner());
        end.as_ref()
            .map_or_else(null_pipe_handle, |end| end.as_raw_fd())
    }

    /// Closes the backend's own write end.
    fn closer(&self) -> Box<dyn FnOnce() + Send> {
        let slot = Arc::clone(&self.write_end);
        Box::new(move || {
            slot.lock().unwrap_or_else(|e| e.into_inner()).take();
        })
    }

    /// Ends the input and stops the pump, once the process has exited.
    fn finish(self) {
        self.write_end
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .take();
        self.pump.stop();
    }
}

impl StatefulSandboxBackend for KataStateAwareRunner {
    const ID_PREFIX: &'static str = "kata";
    const BACKEND_KEY: &'static str = "kata";

    type ProvisionConfig = KataConfig;
    type StartConfig = ();
    type ExecConfig = ();
    type StopConfig = ();
    type DeprovisionConfig = ();
    type ProvisionMetadata = ();
    type StartMetadata = ();
    type StopMetadata = ();
    type DeprovisionMetadata = ();

    fn validate_provision(
        &self,
        request: &ExecutionRequest,
        config: Option<&KataConfig>,
    ) -> Result<(), MxcError> {
        plan_provision(request, config)
            .map(drop)
            .map_err(KataError::into_mxc_error)
    }

    fn provision(
        &mut self,
        request: &ExecutionRequest,
        config: Option<KataConfig>,
    ) -> Result<ProvisionResult<()>, MxcError> {
        let (plan, install) =
            plan_provision(request, config.as_ref()).map_err(KataError::into_mxc_error)?;
        // Kept until deprovisioned, so no process owns it.
        let sandbox =
            Sandbox::provision(&plan, &install, &host::state_dir(&host::process_env), false)
                .map_err(KataError::into_mxc_error)?;
        Ok(ProvisionResult {
            sandbox_id: format!("kata:{}", sandbox.token()),
            metadata: None,
        })
    }

    fn validate_start(
        &self,
        sandbox_id: &str,
        _request: &ExecutionRequest,
        _config: Option<&()>,
    ) -> Result<(), MxcError> {
        token_of(sandbox_id).map(drop)
    }

    fn start(
        &mut self,
        sandbox_id: &str,
        _request: &ExecutionRequest,
        _config: Option<()>,
    ) -> Result<StartResult<()>, MxcError> {
        open(sandbox_id)?
            .start()
            .map_err(KataError::into_mxc_error)?;
        Ok(StartResult { metadata: None })
    }

    fn validate_exec(
        &self,
        sandbox_id: &str,
        request: &ExecutionRequest,
        _config: Option<&()>,
    ) -> Result<(), MxcError> {
        token_of(sandbox_id)?;
        policy::validate_request(request).map_err(KataError::into_mxc_error)
    }

    fn exec(
        &mut self,
        sandbox_id: &str,
        request: &ExecutionRequest,
        _config: Option<()>,
        stdio: ExecStdio,
    ) -> Result<ExecHandle, MxcError> {
        policy::validate_request(request).map_err(KataError::into_mxc_error)?;
        let mut execution = open(sandbox_id)?
            .exec(request, KillScope::Process)
            .map_err(KataError::into_mxc_error)?;

        let killer = execution.killer();
        let missing = |stream: &str| {
            MxcError::backend_error(format!("the {stream} stream of the new process is missing"))
        };
        let stdout = execution.take_stdout().ok_or_else(|| missing("stdout"))?;
        let stderr = execution.take_stderr().ok_or_else(|| missing("stderr"))?;
        let stdin = execution.take_stdin().ok_or_else(|| missing("stdin"))?;

        // A relayed exec forwards no input, so end the process's input now.
        let relay = match stdio {
            ExecStdio::Relayed => {
                drop(stdin);
                None
            }
            ExecStdio::Piped => Some(StdinRelay::start(stdin).map_err(|e| {
                MxcError::backend_error(format!("cannot start the stdin relay: {e}"))
            })?),
        };
        let stdin_handle = relay
            .as_ref()
            .map_or_else(null_pipe_handle, StdinRelay::handle);
        let stdin_closer = relay.as_ref().map(StdinRelay::closer);

        let handles = (stdout.as_raw_fd(), stderr.as_raw_fd());
        let streams = Streams {
            _stdout: stdout,
            _stderr: stderr,
        };
        let timeout_ms = request.script_timeout;
        let deadline =
            (timeout_ms > 0).then(|| Instant::now() + Duration::from_millis(u64::from(timeout_ms)));

        Ok(ExecHandle {
            stdout: handles.0,
            stderr: handles.1,
            stdin: stdin_handle,
            waiter: Box::new(move || {
                let _streams = streams;
                let outcome = execution.wait(deadline);
                // Before the release, so end of input reaches a registered process.
                if let Some(relay) = relay {
                    relay.finish();
                }
                execution.release();
                match outcome.map_err(KataError::into_mxc_error)? {
                    ExitOutcome::Exited(code) => Ok(ExecOutcome::Exited(code)),
                    // The relay cannot represent a timeout, so report it as an error.
                    ExitOutcome::TimedOut if stdio == ExecStdio::Relayed => {
                        Err(MxcError::backend_error(format!(
                            "Kata exec timed out after {timeout_ms}ms"
                        )))
                    }
                    ExitOutcome::TimedOut => Ok(ExecOutcome::TimedOut),
                }
            }),
            terminator: Box::new(move || killer.kill().map_err(KataError::into_mxc_error)),
            stdin_closer,
        })
    }

    fn validate_stop(
        &self,
        sandbox_id: &str,
        _request: &ExecutionRequest,
        _config: Option<&()>,
    ) -> Result<(), MxcError> {
        token_of(sandbox_id).map(drop)
    }

    fn stop(
        &mut self,
        sandbox_id: &str,
        _request: &ExecutionRequest,
        _config: Option<()>,
    ) -> Result<StopResult<()>, MxcError> {
        open(sandbox_id)?
            .stop()
            .map_err(KataError::into_mxc_error)?;
        Ok(StopResult { metadata: None })
    }

    fn validate_deprovision(
        &self,
        sandbox_id: &str,
        _request: &ExecutionRequest,
        _config: Option<&()>,
    ) -> Result<(), MxcError> {
        token_of(sandbox_id).map(drop)
    }

    fn deprovision(
        &mut self,
        sandbox_id: &str,
        _request: &ExecutionRequest,
        _config: Option<()>,
    ) -> Result<DeprovisionResult<()>, MxcError> {
        open(sandbox_id)?
            .deprovision()
            .map_err(KataError::into_mxc_error)?;
        Ok(DeprovisionResult { metadata: None })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kata_common::execution::testing::stdin_fixture;
    use crate::mxc_common::exec_stream::ExecSandboxProcess;
    use crate::mxc_common::mxc_error::MxcErrorCode;
    use crate::mxc_common::sandbox_process::SandboxProcess;

    #[test]
    fn only_kata_ids_with_a_well_formed_token_are_accepted() {
        assert_eq!(token_of("kata:0a1b2c3d").unwrap(), "0a1b2c3d");
        for bad in [
            "iso:0a1b2c3d",
            "kata:",
            "kata:0a1b2c3",
            "kata:../../etc",
            "kata:0A1B2C3D",
            "0a1b2c3d",
        ] {
            let error = token_of(bad).unwrap_err();
            assert_eq!(error.code, MxcErrorCode::MalformedId, "{bad}");
        }
    }

    #[test]
    fn a_provision_without_the_kata_section_is_rejected_before_the_host_is_touched() {
        let runner = KataStateAwareRunner::new();
        let request = ExecutionRequest::default();
        let error = runner.validate_provision(&request, None).unwrap_err();
        assert_eq!(error.code, MxcErrorCode::PolicyValidation);
    }

    #[test]
    fn a_provision_naming_a_missing_rootfs_is_a_policy_error() {
        let runner = KataStateAwareRunner::new();
        let config = KataConfig {
            rootfs: "/nonexistent/mxc/rootfs".into(),
            hypervisor: None,
        };
        let error = runner
            .validate_provision(&ExecutionRequest::default(), Some(&config))
            .unwrap_err();
        assert_eq!(error.code, MxcErrorCode::PolicyValidation);
        assert!(
            error.message.contains("/nonexistent/mxc/rootfs"),
            "{error:?}"
        );
    }

    #[test]
    fn exec_policy_is_checked_with_the_same_network_rules_as_provision() {
        use crate::mxc_common::models::{NetworkAction, NetworkEgressPolicy};
        let runner = KataStateAwareRunner::new();
        let mut request = ExecutionRequest {
            script_code: "true".into(),
            ..Default::default()
        };
        runner
            .validate_exec("kata:0a1b2c3d", &request, None)
            .unwrap();
        request.policy.network_egress = Some(NetworkEgressPolicy {
            default: NetworkAction::Allow,
            ..Default::default()
        });
        let error = runner
            .validate_exec("kata:0a1b2c3d", &request, None)
            .unwrap_err();
        assert_eq!(error.code, MxcErrorCode::PolicyValidation);
    }

    /// A piped exec's input as the shared adapter hands it on, over a fake shim.
    /// `waiter` runs when the process is waited on.
    fn adapter_over_relay(
        writer: StdinWriter,
        waiter: impl FnOnce() -> Result<(), MxcError> + Send + 'static,
    ) -> ExecSandboxProcess {
        let relay = StdinRelay::start(writer).unwrap();
        let handle = ExecHandle {
            stdout: null_pipe_handle(),
            stderr: null_pipe_handle(),
            stdin: relay.handle(),
            stdin_closer: Some(relay.closer()),
            waiter: Box::new(move || {
                waiter()?;
                relay.finish();
                Ok(ExecOutcome::Exited(0))
            }),
            terminator: Box::new(|| Ok(())),
        };
        ExecSandboxProcess::from_exec_handle(handle).unwrap()
    }

    #[test]
    fn transferred_stdin_ends_only_when_the_caller_closes_it() {
        use std::io::Write;
        use std::sync::mpsc;
        let mut fixture = stdin_fixture();
        let (finish, finished) = mpsc::channel::<()>();
        let mut process = adapter_over_relay(fixture.take_writer(), move || {
            finished
                .recv_timeout(Duration::from_secs(10))
                .map_err(|_| MxcError::backend_error("the test never finished the process"))
        });

        let stdio = process.take_native_stdio().unwrap().expect("native stdio");
        let mut stdin = std::fs::File::from(stdio.stdin.expect("stdin"));
        assert!(
            fixture
                .calls
                .recv_timeout(Duration::from_millis(300))
                .is_err(),
            "the transfer ended the input before the caller used it"
        );
        stdin.write_all(b"hello").unwrap();
        assert_eq!(fixture.read_exactly(5), b"hello");

        drop(stdin);
        assert_eq!(
            fixture.calls.recv_timeout(Duration::from_secs(10)).unwrap(),
            "CloseIO"
        );
        finish.send(()).unwrap();
        assert_eq!(process.wait().unwrap(), 0);
    }

    #[test]
    fn waiting_ends_input_that_nobody_took() {
        let mut fixture = stdin_fixture();
        let writer = fixture.take_writer();
        let calls = fixture.calls;
        let mut process = adapter_over_relay(writer, move || {
            calls
                .recv_timeout(Duration::from_secs(10))
                .map(drop)
                .map_err(|_| MxcError::backend_error("the input was not ended"))
        });
        assert_eq!(process.wait().unwrap(), 0);
    }
}
