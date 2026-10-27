// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! `StatefulSandboxBackend` impl for the state-aware WSLc lifecycle.
//!
//! Each lifecycle phase (`provision` / `start` / `exec` / `stop` /
//! `deprovision`) runs as a separate short-lived `wxc-exec` process. Because the
//! WSLc SDK has no cross-process re-attach, this backend does **not** touch the
//! SDK directly: it translates runtime-owned phase configuration plus
//! the cross-cutting `policy` section into [`daemon_protocol`] frames and drives
//! the long-lived `wxc-wslc-daemon` (which owns the live session/container
//! handles) over an owner-only named pipe via [`DaemonClient`].
//!
//! Windows-only: the daemon and its pipe transport are a Windows feature.

use std::io::{Read, Write};
#[cfg(windows)]
use std::os::windows::io::AsRawHandle;
#[cfg(windows)]
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use crate::mxc_common::logger::{Logger, Mode};
use crate::mxc_common::models::{
    ContainerPolicy, ExecutionRequest, WslcProvisionConfig, WslcProvisionSessionConfig,
};
use crate::mxc_common::mxc_error::MxcError;
use crate::mxc_common::state_aware_backend::{
    null_pipe_handle, DeprovisionResult, ExecHandle, ExecOutcome, ExecStdio, ProvisionResult,
    ProvisionSessionResult, StartResult, StatefulSandboxBackend, StopResult,
};
use crate::mxc_common::state_aware_operation::validate_wslc_session_id;
use crate::mxc_common::validator::validate_state_aware_network_policy_support;

use crate::wslc_common::container_steps::OutStream;
use crate::wslc_common::daemon_client::{
    truncation_suffix, DaemonClient, DaemonError, DaemonExecOutcome,
};
use crate::wslc_common::daemon_protocol::{
    DeprovisionConfig, DeprovisionSessionConfig, ErrKind, ExecConfig, NetworkMode,
    PortMapping as DaemonPortMapping, ProvisionConfig,
    ProvisionSessionConfig as DaemonProvisionSessionConfig, StartConfig, StopConfig, VolumeMount,
};
use crate::wslc_common::policy::{
    exec_proxy_url, validate_exec_policy, validate_post_provision_policy, validate_provision_policy,
};
use crate::wslc_common::process_env::EnvScope;
#[cfg(windows)]
use crate::wslc_common::sandbox::prepare_native_output;
#[cfg(windows)]
use crate::wslc_common::stream_buffer::bounded_stream_pair;

/// Default image when a provision request omits `wslc.provision.image`.
const DEFAULT_IMAGE: &str = "alpine:latest";

/// Per-stream ceiling between daemon frames and the synthesized native pipe.
///
/// The relay must keep consuming until the terminal frame, so it cannot block
/// when a caller leaves its native pipe unread. Crossing this ceiling drops the
/// remaining output and turns an otherwise successful exit into an error.
#[cfg(windows)]
const PIPE_BRIDGE_MAX_BUFFERED_BYTES: usize = 8 * 1024 * 1024;

/// State-aware WSLc backend. Every phase opens a fresh [`DaemonClient`]
/// connection (the daemon holds all persistent state).
#[derive(Debug, Default, Clone, Copy)]
pub struct WslcStateAwareRunner {
    forward_stdin: bool,
}

impl WslcStateAwareRunner {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_piped_stdin() -> Self {
        Self {
            forward_stdin: true,
        }
    }
}

impl StatefulSandboxBackend for WslcStateAwareRunner {
    const ID_PREFIX: &'static str = "wslc";
    const BACKEND_KEY: &'static str = "wslc";

    type ProvisionConfig = WslcProvisionConfig;
    type StartConfig = ();
    type ExecConfig = ();
    type StopConfig = ();
    type DeprovisionConfig = ();
    type ProvisionMetadata = ();
    type StartMetadata = ();
    type StopMetadata = ();
    type DeprovisionMetadata = ();

    fn provision_session(
        &mut self,
        _request: &ExecutionRequest,
        config: Option<WslcProvisionSessionConfig>,
    ) -> Result<ProvisionSessionResult, MxcError> {
        let session_config = build_provision_session_config(config);

        let client = connect_daemon()?;
        let session_id = client
            .provision_session(session_config)
            .map_err(map_daemon_error)?;

        Ok(ProvisionSessionResult { session_id })
    }

    fn provision(
        &mut self,
        request: &ExecutionRequest,
        config: Option<WslcProvisionConfig>,
    ) -> Result<ProvisionResult<()>, MxcError> {
        let provision_config = build_provision_config(request, config)?;

        let client = connect_daemon()?;
        let sandbox_id = client
            .provision(provision_config)
            .map_err(map_daemon_error)?;

        Ok(ProvisionResult {
            sandbox_id,
            metadata: None,
        })
    }

    fn start(
        &mut self,
        sandbox_id: &str,
        _request: &ExecutionRequest,
        _config: Option<()>,
    ) -> Result<StartResult<()>, MxcError> {
        let client = connect_daemon()?;
        client
            .start(StartConfig {
                sandbox_id: sandbox_id.to_string(),
            })
            .map_err(map_daemon_error)?;
        Ok(StartResult { metadata: None })
    }

    fn stop(
        &mut self,
        sandbox_id: &str,
        _request: &ExecutionRequest,
        _config: Option<()>,
    ) -> Result<StopResult<()>, MxcError> {
        let client = connect_daemon()?;
        client
            .stop(StopConfig {
                sandbox_id: sandbox_id.to_string(),
            })
            .map_err(map_daemon_error)?;
        Ok(StopResult { metadata: None })
    }

    fn deprovision(
        &mut self,
        sandbox_id: &str,
        _request: &ExecutionRequest,
        _config: Option<()>,
    ) -> Result<DeprovisionResult<()>, MxcError> {
        let client = connect_daemon()?;
        client
            .deprovision(DeprovisionConfig {
                sandbox_id: sandbox_id.to_string(),
            })
            .map_err(map_daemon_error)?;
        Ok(DeprovisionResult { metadata: None })
    }

    fn deprovision_session(
        &mut self,
        session_id: &str,
        _request: &ExecutionRequest,
    ) -> Result<(), MxcError> {
        validate_wslc_session_id(session_id)?;
        let client = connect_daemon()?;
        client
            .deprovision_session(DeprovisionSessionConfig {
                session_ref: session_id.to_string(),
            })
            .map_err(map_daemon_error)
    }

    /// Runs one command in the warm container. Relayed callers receive live
    /// output on this process's stdout/stderr, and the command reads this
    /// process's stdin unless it is a terminal; piped callers receive
    /// synthesized native stdout/stderr pipes bridged to the same daemon
    /// streams, plus a stdin pipe if the runner was made
    /// [`with_piped_stdin`](Self::with_piped_stdin).
    fn exec(
        &mut self,
        sandbox_id: &str,
        request: &ExecutionRequest,
        _config: Option<()>,
        stdio: ExecStdio,
    ) -> Result<ExecHandle, MxcError> {
        let client = connect_daemon()?;
        let exec_id = uuid::Uuid::new_v4().simple().to_string();
        let run_token = uuid::Uuid::new_v4().simple().to_string();
        let config = exec_config(sandbox_id, request, exec_id.clone(), run_token.clone());

        match stdio {
            ExecStdio::Relayed => exec_relayed(client, config),
            ExecStdio::Piped => exec_piped(client, config, exec_id, run_token, self.forward_stdin),
        }
    }

    fn validate_provision(
        &self,
        request: &ExecutionRequest,
        config: Option<&WslcProvisionConfig>,
    ) -> Result<(), MxcError> {
        if let Some(session_id) = config.and_then(|config| config.session_id.as_deref()) {
            validate_wslc_session_id(session_id)?;
        }
        validate_state_aware_network_policy_support(
            request,
            crate::wslc_common::policy::network_policy_support(),
        )?;
        validate_provision_policy(request)
    }

    fn validate_provision_session(
        &self,
        request: &ExecutionRequest,
        config: Option<&WslcProvisionSessionConfig>,
    ) -> Result<(), MxcError> {
        validate_session_sizing(config)?;
        validate_state_aware_network_policy_support(
            request,
            crate::wslc_common::policy::network_policy_support(),
        )?;

        // Filesystem and network policy belong to containers, not the session.
        validate_post_provision_policy(request)
    }

    fn validate_deprovision_session(
        &self,
        session_id: &str,
        request: &ExecutionRequest,
    ) -> Result<(), MxcError> {
        validate_wslc_session_id(session_id)?;
        validate_state_aware_network_policy_support(
            request,
            crate::wslc_common::policy::network_policy_support(),
        )?;
        validate_post_provision_policy(request)
    }

    fn validate_start(
        &self,
        sandbox_id: &str,
        request: &ExecutionRequest,
        _config: Option<&()>,
    ) -> Result<(), MxcError> {
        validate_sandbox_id(sandbox_id)?;
        validate_state_aware_network_policy_support(
            request,
            crate::wslc_common::policy::network_policy_support(),
        )?;
        validate_post_provision_policy(request)
    }

    fn validate_exec(
        &self,
        sandbox_id: &str,
        request: &ExecutionRequest,
        _config: Option<&()>,
    ) -> Result<(), MxcError> {
        validate_sandbox_id(sandbox_id)?;
        validate_state_aware_network_policy_support(
            request,
            crate::wslc_common::policy::network_policy_support(),
        )?;
        validate_exec_policy(request)
    }

    fn validate_stop(
        &self,
        sandbox_id: &str,
        request: &ExecutionRequest,
        _config: Option<&()>,
    ) -> Result<(), MxcError> {
        validate_sandbox_id(sandbox_id)?;
        validate_state_aware_network_policy_support(
            request,
            crate::wslc_common::policy::network_policy_support(),
        )?;
        validate_post_provision_policy(request)
    }

    fn validate_deprovision(
        &self,
        sandbox_id: &str,
        request: &ExecutionRequest,
        _config: Option<&()>,
    ) -> Result<(), MxcError> {
        validate_sandbox_id(sandbox_id)?;
        validate_state_aware_network_policy_support(
            request,
            crate::wslc_common::policy::network_policy_support(),
        )?;
        validate_post_provision_policy(request)
    }
}

fn exec_relayed(client: DaemonClient, config: ExecConfig) -> Result<ExecHandle, MxcError> {
    use std::io::IsTerminal;

    let stdin = std::io::stdin();
    let input = (!stdin.is_terminal()).then_some(stdin);
    relay_exec(client, config, input)
}

/// Run an exec that relays its output to this process's stdout/stderr, feeding
/// it `input`, or nothing if the host stdin is a terminal.
fn relay_exec(
    client: DaemonClient,
    mut config: ExecConfig,
    input: Option<impl Read + Send + 'static>,
) -> Result<ExecHandle, MxcError> {
    let timeout_ms = config.timeout_ms;
    let exec_id = config.exec_id.clone();
    let run_token = config.run_token.clone();
    config.stdin = input.is_some();
    if input.is_none() {
        eprintln!(
            "WARNING: stdin is a terminal, but the state-aware WSLc exec path does not forward \
             interactive input. The command sees end-of-file on stdin. Redirect stdin from a file \
             or a pipe to send it input."
        );
    }

    let exec = client.admit_exec(config).map_err(map_daemon_error)?;

    // A pump blocked on a host stdin that never closes does not hold up this
    // exec: the executor process exits once the run is over, ending the pump.
    let forwarding = StdinForwarding::default();
    if let Some(input) = input {
        start_stdin_pump(&client, exec_id, run_token, input, &forwarding);
    }

    // Relay each chunk to our own stdio as it arrives. Hold the stdout/stderr
    // locks for the whole relay so we don't reacquire the handle per chunk,
    // and coalesce flushes: `std::io::Stdout`/`Stderr` are line-buffered, so
    // newline-terminated output already reaches the consumer promptly; we only
    // force a flush for a chunk that does *not* end in a newline (progress
    // output — prompts, spinners) so it isn't stranded in the line buffer.
    // This avoids a flush syscall per bulk chunk while preserving low latency.
    // Best-effort: a failed local write must not mask the container's exit code.
    let stdout = std::io::stdout();
    let stderr = std::io::stderr();
    let completion = {
        let mut out = stdout.lock();
        let mut err = stderr.lock();
        let result = exec.read_to_completion(|stream, bytes| match stream {
            OutStream::Stdout => {
                let _ = out.write_all(bytes);
                if bytes.last() != Some(&b'\n') {
                    let _ = out.flush();
                }
            }
            OutStream::Stderr => {
                let _ = err.write_all(bytes);
                if bytes.last() != Some(&b'\n') {
                    let _ = err.flush();
                }
            }
        });
        let _ = out.flush();
        let _ = err.flush();
        // Drop the locks before mapping the error so error conversion never
        // contends with the writers we just held.
        drop((out, err));
        result.map_err(map_daemon_error)?
    };
    let stdin_failure = forwarding.finish();

    let exit_code = match completion.outcome {
        DaemonExecOutcome::Exited(code) if completion.truncated => {
            return Err(truncated_run_error(code))
        }
        DaemonExecOutcome::Exited(code) => code,
        DaemonExecOutcome::TimedOut => {
            return Err(MxcError::backend_error(format!(
                "WSLc exec timed out after {timeout_ms}ms{}",
                truncation_suffix(completion.truncated)
            )))
        }
        DaemonExecOutcome::Cancelled => {
            if let Some(reason) = stdin_failure {
                return Err(stdin_forwarding_error(&reason));
            }
            return Err(MxcError::backend_error(format!(
                "WSLc relayed exec was cancelled unexpectedly{}",
                truncation_suffix(completion.truncated)
            )));
        }
    };

    Ok(ExecHandle {
        stdout: null_pipe_handle(),
        stderr: null_pipe_handle(),

        // This path feeds the process from host stdin itself.
        stdin: null_pipe_handle(),
        stdin_closer: None,
        // Relayed execution has already completed before this handle is
        // returned; timeouts were surfaced above as an error because the
        // relay adapter has no typed timeout result.
        waiter: Box::new(move || Ok(ExecOutcome::Exited(exit_code))),
        // Nothing to terminate: the workload is already gone. `Ok(())` is
        // the truthful answer here, not a placeholder.
        terminator: Box::new(|| Ok(())),
    })
}

#[cfg(windows)]
fn exec_piped(
    client: DaemonClient,
    mut config: ExecConfig,
    exec_id: String,
    run_token: String,
    forward_stdin: bool,
) -> Result<ExecHandle, MxcError> {
    use crate::mxc_common::process_util::{create_local_pipe, InterruptiblePipeReader};
    use crate::mxc_common::sandbox_process::StreamCloser;

    let stdout_pipe = prepare_native_output()
        .map_err(|error| MxcError::backend_error(format!("create WSLC stdout pipe: {error}")))?;
    let stderr_pipe = prepare_native_output()
        .map_err(|error| MxcError::backend_error(format!("create WSLC stderr pipe: {error}")))?;
    let stdin_pipe = if forward_stdin {
        let (read, write) = create_local_pipe()
            .map_err(|error| MxcError::backend_error(format!("create WSLC stdin pipe: {error}")))?;
        let write = write
            .try_into_std_owned_handle()
            .map_err(|error| MxcError::backend_error(format!("create WSLC stdin pipe: {error}")))?;
        Some((InterruptiblePipeReader::new(read), write))
    } else {
        None
    };
    let (stdout_writer, stdout_source, stdout_overflow) =
        bounded_stream_pair(PIPE_BRIDGE_MAX_BUFFERED_BYTES);
    let (stderr_writer, stderr_source, stderr_overflow) =
        bounded_stream_pair(PIPE_BRIDGE_MAX_BUFFERED_BYTES);
    let (stdout_reader, stdout_pump) = stdout_pipe
        .activate(stdout_source)
        .map_err(|error| MxcError::backend_error(format!("start WSLC stdout pump: {error}")))?;
    let (stderr_reader, stderr_pump) = stderr_pipe
        .activate(stderr_source)
        .map_err(|error| MxcError::backend_error(format!("start WSLC stderr pump: {error}")))?;
    let stdout = windows::Win32::Foundation::HANDLE(stdout_reader.as_raw_handle());
    let stderr = windows::Win32::Foundation::HANDLE(stderr_reader.as_raw_handle());
    let stdin = stdin_pipe
        .as_ref()
        .map_or_else(null_pipe_handle, |(_, write)| {
            windows::Win32::Foundation::HANDLE(write.as_raw_handle())
        });
    let (stdin_read, stdin_write) = stdin_pipe.unzip();
    let stdin_canceller = stdin_read.as_ref().map(InterruptiblePipeReader::canceller);
    let stdin_write = Arc::new(Mutex::new(stdin_write));
    let closer_stdin_write = Arc::clone(&stdin_write);
    let terminator_client = client.clone();
    let relay_exec_id = exec_id.clone();
    let relay_run_token = run_token.clone();
    let cancellation = Arc::new(AtomicBool::new(false));
    let relay_cancellation = Arc::clone(&cancellation);
    let (done_tx, done_rx) = std::sync::mpsc::sync_channel(1);
    config.stdin = forward_stdin;

    std::thread::Builder::new()
        .name("wslc-state-aware-exec".to_string())
        .spawn(move || {
            let forwarding = StdinForwarding::default();
            let result = client
                .admit_exec(config)
                .and_then(|exec| {
                    if relay_cancellation.load(Ordering::Acquire) {
                        client.cancel_exec(relay_exec_id, relay_run_token)?;
                    } else if let Some(input) = stdin_read {
                        start_stdin_pump(
                            &client,
                            relay_exec_id,
                            relay_run_token,
                            input,
                            &forwarding,
                        );
                    }
                    exec.read_to_completion(|stream, bytes| match stream {
                        OutStream::Stdout => stdout_writer.write(bytes),
                        OutStream::Stderr => stderr_writer.write(bytes),
                    })
                })
                .map_err(map_daemon_error)
                .and_then(|completion| {
                    let stdin_failure = forwarding.finish();
                    // Either end of the bridge can drop output: the daemon's
                    // queue on the way out, or these pipes if the caller is slow.
                    let truncated = completion.truncated
                        || stdout_overflow.has_overflowed()
                        || stderr_overflow.has_overflowed();
                    match completion.outcome {
                        DaemonExecOutcome::Exited(code) if truncated => {
                            Err(truncated_run_error(code))
                        }
                        DaemonExecOutcome::Exited(code) => Ok(ExecOutcome::Exited(code)),
                        DaemonExecOutcome::TimedOut => Ok(ExecOutcome::TimedOut),
                        DaemonExecOutcome::Cancelled => piped_cancelled_outcome(
                            relay_cancellation.load(Ordering::Acquire),
                            stdin_failure,
                        ),
                    }
                });

            // The caller may never close its stdin, so the pump's read is
            // ended here rather than left waiting on a run that is over.
            if let Some(canceller) = stdin_canceller {
                canceller.close();
            }
            stdout_writer.close();
            stderr_writer.close();
            let _ = done_tx.send(result);
            // Caller-owned pipes can remain full when the caller uses
            // `try_wait` or drops without draining. Joining the pumps here
            // would then block terminal completion and create a Drop cycle.
            // Dropping a JoinHandle detaches the pump; closing the read end
            // during ExecHandle teardown lets the blocked write unwind.
            drop(stdout_pump);
            drop(stderr_pump);
        })
        .map_err(|error| {
            MxcError::backend_error(format!("start WSLC exec stream thread: {error}"))
        })?;

    let stdin_closer: Option<Box<dyn FnOnce() + Send>> = forward_stdin.then(|| {
        Box::new(move || {
            closer_stdin_write
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .take();
        }) as Box<dyn FnOnce() + Send>
    });
    Ok(ExecHandle {
        stdout,
        stderr,
        stdin,
        stdin_closer,
        waiter: Box::new(move || {
            // A native handle transfer never calls `stdin_closer`, so this is
            // what leaves the caller's copy as the only stdin write end.
            stdin_write
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .take();

            // Keep the original read handles alive until the daemon stream
            // reaches a terminal frame.
            let _readers = (stdout_reader, stderr_reader);
            done_rx.recv().map_err(|_| {
                MxcError::backend_error(
                    "WSLc exec stream thread ended without reporting an outcome",
                )
            })?
        }),
        terminator: Box::new(move || {
            cancellation.store(true, Ordering::Release);
            terminator_client
                .cancel_exec(exec_id, run_token)
                .map_err(map_daemon_error)
        }),
    })
}

#[cfg(not(windows))]
fn exec_piped(
    _client: DaemonClient,
    _config: ExecConfig,
    _exec_id: String,
    _run_token: String,
    _forward_stdin: bool,
) -> Result<ExecHandle, MxcError> {
    Err(MxcError::backend_unavailable(
        "WSLc piped execution is available only on Windows",
    ))
}

/// The daemon's inputs for one exec, with the cooperative proxy applied.
fn exec_config(
    sandbox_id: &str,
    request: &ExecutionRequest,
    exec_id: String,
    run_token: String,
) -> ExecConfig {
    // `exec_proxy_url` yields the routable URL only when the proxy is enabled
    // *and* in the required `url` form — `validate_exec` has already rejected
    // the non-`url` form before we get here, so a `None` here means the proxy
    // is disabled, not malformed.
    let env = match exec_proxy_url(request) {
        Some(proxy_url) => split_env(&crate::mxc_common::proxy_env::apply_cooperative_proxy_env(
            request.env_entries(),
            proxy_url,
        )),
        None => split_env(request.env_entries()),
    };

    ExecConfig {
        exec_id,
        run_token,
        sandbox_id: sandbox_id.to_string(),
        script_code: request.script_code.clone(),
        working_directory: request.working_directory.clone(),
        env,
        env_scope: EnvScope::of(request),
        timeout_ms: request.script_timeout,
        stdin: false,
    }
}

/// What went wrong forwarding an exec's stdin, kept so a cancellation nobody
/// asked for can be explained.
#[derive(Clone, Default)]
struct StdinForwarding(Arc<Mutex<StdinForwardingState>>);

#[derive(Default)]
struct StdinForwardingState {
    exec_over: bool,
    failure: Option<String>,
}

impl StdinForwarding {
    fn state(&self) -> std::sync::MutexGuard<'_, StdinForwardingState> {
        self.0
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    /// Record `reason` and return whether the exec must be cancelled, which it
    /// need not be once its outcome is known.
    fn fail(&self, reason: String) -> bool {
        let mut state = self.state();
        if state.exec_over {
            return false;
        }
        state.failure = Some(reason);
        true
    }

    /// Mark the exec's outcome as known and return any failure recorded before.
    fn finish(&self) -> Option<String> {
        let mut state = self.state();
        state.exec_over = true;
        state.failure.take()
    }
}

/// Copy `input` into an admitted exec's stdin on a thread of its own, cancelling
/// the exec if that fails so its process does not wait for input forever.
fn start_stdin_pump(
    client: &DaemonClient,
    exec_id: String,
    run_token: String,
    input: impl Read + Send + 'static,
    forwarding: &StdinForwarding,
) {
    let pump_forwarding = forwarding.clone();
    let pump_client = client.clone();
    let (pump_exec_id, pump_run_token) = (exec_id.clone(), run_token.clone());
    let spawned = std::thread::Builder::new()
        .name("wslc-exec-stdin".to_string())
        .spawn(move || {
            if let Err(error) =
                pump_client.forward_stdin(pump_exec_id.clone(), pump_run_token.clone(), input)
            {
                if pump_forwarding.fail(error.to_string()) {
                    let _ = pump_client.cancel_exec(pump_exec_id, pump_run_token);
                }
            }
        });
    if let Err(error) = spawned {
        if forwarding.fail(format!("could not start a thread to forward it: {error}")) {
            let _ = client.cancel_exec(exec_id, run_token);
        }
    }
}

fn piped_cancelled_outcome(
    caller_cancelled: bool,
    stdin_failure: Option<String>,
) -> Result<ExecOutcome, MxcError> {
    match stdin_failure {
        Some(reason) if !caller_cancelled => Err(stdin_forwarding_error(&reason)),

        // `SandboxProcess::kill` is a request followed by reaping; there is no
        // distinct cancelled variant in `ExecOutcome`.
        _ => Ok(ExecOutcome::Exited(-1)),
    }
}

fn stdin_forwarding_error(reason: &str) -> MxcError {
    MxcError::backend_error(format!(
        "WSLc exec was cancelled because its stdin could not be forwarded: {reason}"
    ))
}

/// Discover (or spawn) the daemon. A discovery/spawn failure is a
/// `backend_unavailable` — the backend cannot service any phase without it.
fn connect_daemon() -> Result<DaemonClient, MxcError> {
    DaemonClient::connect().map_err(|e| {
        MxcError::backend_unavailable(format!("failed to reach the WSLc daemon: {e:#}"))
    })
}

/// The process finished, but the caller's copy of its output is incomplete.
///
/// Reported as a failure so a short capture is never mistaken for a whole one,
/// with `details.exitCode` keeping the code the process produced.
fn truncated_run_error(exit_code: i32) -> MxcError {
    MxcError::backend_error(
        "WSLc live output was truncated: it was not drained fast enough and a bounded output \
         queue overflowed",
    )
    .with_details(serde_json::json!({ "exitCode": exit_code }))
}

fn build_provision_session_config(
    config: Option<WslcProvisionSessionConfig>,
) -> DaemonProvisionSessionConfig {
    let config = config.unwrap_or_default();
    DaemonProvisionSessionConfig {
        cpu_count: config.cpu_count,
        memory_mb: config.memory_mb,
        gpu: config.gpu.unwrap_or(false),
    }
}

fn validate_session_sizing(config: Option<&WslcProvisionSessionConfig>) -> Result<(), MxcError> {
    let Some(config) = config else {
        return Ok(());
    };
    if let Some(memory_mb) = config.memory_mb {
        u32::try_from(memory_mb).map_err(|_| {
            MxcError::policy_validation(format!(
                "wslc.provisionSession.memoryMb {memory_mb} exceeds the {} MB the WSLc SDK accepts",
                u32::MAX
            ))
        })?;
    }
    crate::wslc_common::container_steps::check_sizing_against_host(
        crate::wslc_common::container_steps::SessionSizing {
            cpu_count: config.cpu_count,
            memory_mb: config.memory_mb,
            gpu: config.gpu.unwrap_or(false),
        },
    )
    .map_err(|response| MxcError::policy_validation(response.error_message))
}

/// Map a typed [`DaemonError`] onto the matching wire-format [`MxcError`] code.
fn map_daemon_error(err: DaemonError) -> MxcError {
    match err {
        DaemonError::Daemon { kind, message } => match kind {
            ErrKind::NotProvisioned => MxcError::not_provisioned(message),
            ErrKind::NotStarted => MxcError::not_started(message),
            ErrKind::Unavailable => MxcError::backend_unavailable(message),
            ErrKind::Rejected => MxcError::policy_validation(message),
            ErrKind::Busy
            | ErrKind::NotReady
            | ErrKind::Protocol
            | ErrKind::Backend
            | ErrKind::Unknown => MxcError::backend_error(message),
        },
        DaemonError::Transport(e) => MxcError::backend_error(format!("{e:#}")),
    }
}

/// Validate the `wslc:<32 lowercase hex>` shape. The dispatcher already routes
/// by prefix; this is defence in depth so a malformed id surfaces as
/// `malformed_id` rather than a confusing daemon-side `not_provisioned`. The
/// grammar mirrors the daemon-minted id (`wslc:` + a UUID simple form).
fn validate_sandbox_id(sandbox_id: &str) -> Result<(), MxcError> {
    let malformed = || {
        MxcError::malformed_id(format!(
            "expected wslc:<32 lowercase hex>, got {sandbox_id:?}"
        ))
    };
    let (prefix, rest) = sandbox_id.split_once(':').ok_or_else(malformed)?;
    let is_lower_hex = rest.len() == 32
        && rest
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b));
    if prefix == <WslcStateAwareRunner as StatefulSandboxBackend>::ID_PREFIX && is_lower_hex {
        Ok(())
    } else {
        Err(malformed())
    }
}

/// Build the daemon `ProvisionConfig` from the request + phase config without
/// contacting the daemon. Runs the same normalization/delegation + volume/network
/// mapping as `provision`, so the forwarded config (image, imageTarPath, volumes,
/// network) can be observed directly by a host-independent test — catching a
/// serialization/forwarding regression that an E2E run would only surface on a
/// live WSL host.
fn build_provision_config(
    request: &ExecutionRequest,
    config: Option<WslcProvisionConfig>,
) -> Result<ProvisionConfig, MxcError> {
    let image = config
        .as_ref()
        .and_then(|c| c.image.clone())
        .unwrap_or_else(|| DEFAULT_IMAGE.to_string());
    let port_mappings: Vec<DaemonPortMapping> = config
        .as_ref()
        .and_then(|c| c.port_mappings.as_ref())
        .map(|mappings| {
            mappings
                .iter()
                .map(|mapping| DaemonPortMapping {
                    windows_port: mapping.windows_port,
                    container_port: mapping.container_port,
                })
                .collect()
        })
        .unwrap_or_default();
    let image_tar_path = config.as_ref().and_then(|c| c.image_tar_path.clone());
    let session_id = config.and_then(|c| c.session_id);
    if let Some(session_id) = session_id.as_deref() {
        validate_wslc_session_id(session_id)?;
    }

    // WSLc provision-time filesystem-policy gate (D6 normalization → D3
    // delegation → denied-path overlap), shared verbatim with the one-shot
    // runner via `policy_mapping::apply_provision_policy_gate`. The daemon must
    // mount the tightened policy, so a writable alias of a readonly object never
    // leaks and a persistent daemon never mounts a path the phase caller could
    // not delegate.
    let normalized = normalize_and_check_delegation(request)?;
    let normalized_request;
    let request = match normalized {
        Some(policy) => {
            normalized_request = ExecutionRequest {
                policy,
                ..request.clone()
            };
            &normalized_request
        }
        None => request,
    };

    let volumes = build_daemon_volumes(request)?;
    let network = map_network(request);
    crate::wslc_common::policy::reject_port_mappings_without_bridged_network(
        request,
        "wslc.provision.portMappings",
        !port_mappings.is_empty(),
    )?;

    Ok(ProvisionConfig {
        image,
        image_tar_path,
        volumes,
        network,
        port_mappings,
        session_ref: session_id,
    })
}

/// State-aware adapter over the shared WSLc provision policy gate
/// ([`crate::wslc_common::policy_mapping::apply_provision_policy_gate`]): runs the full
/// three-step gate (D6 normalization → D3 delegation → denied-path overlap),
/// buffering normalization diagnostics and surfacing them on stderr (stdout
/// carries the phase envelope), and maps the gate's `String` error to a
/// `policy_validation` [`MxcError`]. Returns the tightened policy when
/// normalization changed something, else `None`.
fn normalize_and_check_delegation(
    request: &ExecutionRequest,
) -> Result<Option<ContainerPolicy>, MxcError> {
    let mut logger = Logger::new(Mode::Buffer);
    let result =
        crate::wslc_common::policy_mapping::apply_provision_policy_gate(request, &mut logger);
    // Surface any normalization notes (policy tightening / unresolved paths) on
    // stderr even when the gate then fails, rather than dropping the buffer.
    let notes = logger.get_buffer();
    if !notes.is_empty() {
        eprint!("{notes}");
    }
    result.map_err(MxcError::policy_validation)
}

/// Build daemon volume mounts from the request's filesystem policy. Overlapping
/// denied paths are rejected earlier in `validate_provision`; an invalid mount
/// path (e.g. a UNC share) surfaces here as `policy_validation`.
fn build_daemon_volumes(request: &ExecutionRequest) -> Result<Vec<VolumeMount>, MxcError> {
    let mounts = crate::wslc_common::policy_mapping::build_volume_mounts(
        &request.policy.readwrite_paths,
        &request.policy.readonly_paths,
    )
    .map_err(MxcError::policy_validation)?;
    Ok(mounts
        .into_iter()
        .map(|m| VolumeMount {
            host: m.windows_path,
            container: m.container_path,
            read_only: m.read_only,
        })
        .collect())
}

/// Map the validated directional egress default to the daemon's binary
/// network mode: `Deny` → isolated, `Allow` → bridged NAT.
fn map_network(request: &ExecutionRequest) -> NetworkMode {
    if crate::wslc_common::policy::network_is_isolated(request) {
        NetworkMode::None
    } else {
        NetworkMode::Bridged
    }
}

/// Split `"KEY=VALUE"` env entries into `(name, value)` pairs (the daemon's
/// `ExecConfig.env` shape). An entry naming no variable is dropped.
fn split_env(env: &[String]) -> Vec<(String, String)> {
    crate::mxc_common::default_env::env_pairs(env)
        .into_iter()
        .map(|(name, value)| (name.to_string(), value.to_string()))
        .collect()
}

#[cfg(all(test, windows))]
mod stdin_relay_tests {
    use super::*;
    use crate::wslc_common::daemon_client::test_daemon::TestDaemon;
    use crate::wslc_common::daemon_protocol::{DaemonRequest, DaemonResponse, StreamFrame};
    use std::os::windows::io::BorrowedHandle;
    use std::time::Duration;

    fn config() -> ExecConfig {
        ExecConfig {
            exec_id: "exec-1".to_string(),
            run_token: "run-1".to_string(),
            sandbox_id: "wslc:test".to_string(),
            script_code: "cat".to_string(),
            working_directory: String::new(),
            env: Vec::new(),
            env_scope: EnvScope::Merge,
            timeout_ms: 0,
            stdin: false,
        }
    }

    fn within<T: Send + 'static>(what: &str, work: impl FnOnce() -> T + Send + 'static) -> T {
        let (done_tx, done_rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let _ = done_tx.send(work());
        });
        done_rx
            .recv_timeout(Duration::from_secs(10))
            .unwrap_or_else(|_| panic!("{what} did not finish"))
    }

    struct BrokenInput;

    impl Read for BrokenInput {
        fn read(&mut self, _: &mut [u8]) -> std::io::Result<usize> {
            Err(std::io::Error::other("input broke"))
        }
    }

    #[test]
    fn a_relayed_exec_whose_stdin_cannot_be_read_is_cancelled_with_the_reason() {
        let daemon = TestDaemon::start();
        let client = daemon.client.clone();
        let running = std::thread::spawn(move || {
            relay_exec(client, config(), Some(BrokenInput))
                .err()
                .map(|error| error.message)
        });

        let mut exec = daemon.next();
        assert!(matches!(&exec.request, DaemonRequest::Exec(config) if config.stdin));
        exec.reply(&DaemonResponse::Ok);
        let mut cancel = daemon.next();
        assert!(matches!(
            &cancel.request,
            DaemonRequest::CancelExec(config)
                if config.exec_id == "exec-1" && config.run_token == "run-1"
        ));
        cancel.reply(&DaemonResponse::Ok);
        exec.reply(&StreamFrame::Cancelled);

        let message = running.join().unwrap().expect("the exec must fail");
        assert!(
            message.contains("stdin could not be forwarded") && message.contains("input broke"),
            "{message}"
        );
    }

    #[test]
    fn a_relayed_exec_from_a_terminal_does_not_ask_for_stdin() {
        let daemon = TestDaemon::start();
        let client = daemon.client.clone();
        let running = std::thread::spawn(move || {
            relay_exec(client, config(), None::<std::io::Empty>)
                .and_then(|handle| (handle.waiter)())
        });

        let mut exec = daemon.next();
        assert!(matches!(&exec.request, DaemonRequest::Exec(config) if !config.stdin));
        exec.reply(&DaemonResponse::Ok);
        exec.reply(&StreamFrame::Exit { code: 0 });

        assert_eq!(running.join().unwrap().unwrap(), ExecOutcome::Exited(0));
    }

    #[test]
    fn a_piped_exec_without_stdin_gives_the_command_end_of_file() {
        let daemon = TestDaemon::start();
        let handle = exec_piped(
            daemon.client.clone(),
            config(),
            "exec-1".to_string(),
            "run-1".to_string(),
            false,
        )
        .unwrap();
        let mut exec = daemon.next();
        assert!(matches!(&exec.request, DaemonRequest::Exec(config) if !config.stdin));
        exec.reply(&DaemonResponse::Ok);
        exec.reply(&StreamFrame::Exit { code: 0 });

        assert!(handle.stdin.0.is_null());
        assert!(handle.stdin_closer.is_none());
        assert_eq!(
            within("the waiter", handle.waiter).unwrap(),
            ExecOutcome::Exited(0)
        );
    }

    #[test]
    fn killing_a_piped_exec_while_its_stdin_is_backed_up_ends_the_exec_and_the_write() {
        let daemon = TestDaemon::start();
        let handle = exec_piped(
            daemon.client.clone(),
            config(),
            "exec-1".to_string(),
            "run-1".to_string(),
            true,
        )
        .unwrap();
        let mut exec = daemon.next();
        exec.reply(&DaemonResponse::Ok);

        // SAFETY: the handle stays open until the waiter runs, below.
        let stdin = unsafe { BorrowedHandle::borrow_raw(handle.stdin.0) }
            .try_clone_to_owned()
            .unwrap();
        let mut stdin = std::fs::File::from(stdin);
        let writing = std::thread::spawn(move || stdin.write_all(&vec![0; 8 * 1024 * 1024]));
        let mut stdin_connection = daemon.next();
        assert!(matches!(
            &stdin_connection.request,
            DaemonRequest::ExecStdin(_)
        ));
        stdin_connection.reply(&DaemonResponse::Ok);
        let _first: StreamFrame = stdin_connection.read();

        let killing = std::thread::spawn(handle.terminator);
        let mut cancel = daemon.next();
        assert!(matches!(&cancel.request, DaemonRequest::CancelExec(_)));
        cancel.reply(&DaemonResponse::Ok);
        killing.join().unwrap().unwrap();
        exec.reply(&StreamFrame::Cancelled);
        drop(stdin_connection);

        assert_eq!(
            within("the waiter", handle.waiter).unwrap(),
            ExecOutcome::Exited(-1)
        );
        assert!(
            within("the caller's stdin write", move || writing.join().unwrap()).is_err(),
            "input written after the kill must not be reported as delivered"
        );
    }
}

#[cfg(test)]
mod session_tests {
    use super::*;
    use crate::mxc_common::mxc_error::MxcErrorCode;

    const VALID_SESSION_ID: &str = "wslcsess:0123456789abcdef0123456789abcdef";

    #[test]
    fn validate_session_id_accepts_a_daemon_minted_id() {
        assert!(validate_wslc_session_id(VALID_SESSION_ID).is_ok());
    }

    #[test]
    fn validate_session_id_rejects_everything_else() {
        let mut runner = WslcStateAwareRunner::new();
        for session_id in [
            "",
            "wslcsess",
            "wslcsess:",
            "0123456789abcdef0123456789abcdef",
            "wslc:0123456789abcdef0123456789abcdef",
            "wslcsess:default",
            "wslcsess:0123456789abcdef0123456789abcde",
            "wslcsess:0123456789abcdef0123456789abcdef0",
            "wslcsess:0123456789ABCDEF0123456789ABCDEF",
            "wslcsess:0123456789abcdef0123456789abcdeg",
        ] {
            let error = validate_wslc_session_id(session_id)
                .expect_err("malformed session IDs must not be accepted");
            assert_eq!(error.code, MxcErrorCode::MalformedId);
            let error = runner
                .deprovision_session(session_id, &ExecutionRequest::default())
                .expect_err("direct session release must reject a malformed ID before connecting");
            assert_eq!(error.code, MxcErrorCode::MalformedId);
        }
    }

    #[test]
    fn absent_sizing_reaches_the_daemon_as_host_defaults() {
        for config in [None, Some(WslcProvisionSessionConfig::default())] {
            let forwarded = build_provision_session_config(config);
            assert_eq!(forwarded.cpu_count, None);
            assert_eq!(forwarded.memory_mb, None);
            assert!(
                !forwarded.gpu,
                "an unrequested GPU must not become a passthrough grant"
            );
        }
    }

    #[test]
    fn each_sizing_field_is_forwarded_to_the_daemon() {
        let forwarded = build_provision_session_config(Some(WslcProvisionSessionConfig {
            cpu_count: Some(4),
            memory_mb: Some(8192),
            gpu: Some(true),
        }));
        assert_eq!(forwarded.cpu_count, Some(4));
        assert_eq!(forwarded.memory_mb, Some(8192));
        assert!(forwarded.gpu);

        let gpu_off = build_provision_session_config(Some(WslcProvisionSessionConfig {
            gpu: Some(false),
            ..Default::default()
        }));
        assert!(!gpu_off.gpu);
    }

    #[test]
    fn zero_sizing_is_accepted_and_forwarded_as_the_sdk_default() {
        for config in [
            WslcProvisionSessionConfig {
                cpu_count: Some(0),
                ..Default::default()
            },
            WslcProvisionSessionConfig {
                memory_mb: Some(0),
                ..Default::default()
            },
            WslcProvisionSessionConfig {
                cpu_count: Some(0),
                memory_mb: Some(0),
                gpu: Some(false),
            },
        ] {
            validate_session_sizing(Some(&config))
                .unwrap_or_else(|error| panic!("zero selects the SDK default: {error}"));
            let forwarded = build_provision_session_config(Some(config));
            assert_eq!(forwarded.cpu_count, config.cpu_count);
            assert_eq!(forwarded.memory_mb, config.memory_mb);
            assert!(!forwarded.gpu);
        }
        assert!(validate_session_sizing(None).is_ok());
    }

    #[test]
    fn session_memory_is_bounded_by_the_sdk_integer_width() {
        for memory_mb in [u64::from(u32::MAX) + 1, u64::MAX] {
            let error = validate_session_sizing(Some(&WslcProvisionSessionConfig {
                memory_mb: Some(memory_mb),
                ..Default::default()
            }))
            .expect_err("the SDK cannot represent this memory size");
            assert_eq!(error.code, MxcErrorCode::PolicyValidation);
            assert!(error.message.contains("wslc.provisionSession.memoryMb"));
            assert!(error.message.contains(&u32::MAX.to_string()));
        }
        assert!(validate_session_sizing(Some(&WslcProvisionSessionConfig {
            memory_mb: Some(u64::from(u32::MAX)),
            ..Default::default()
        }))
        .is_ok());
    }

    #[test]
    fn session_cpu_validation_reuses_the_create_and_run_host_check() {
        let expected = crate::wslc_common::container_steps::check_sizing_against_host(
            crate::wslc_common::container_steps::SessionSizing {
                cpu_count: Some(u32::MAX),
                ..Default::default()
            },
        )
        .expect_err("this host cannot supply u32::MAX virtual CPUs");
        let error = validate_session_sizing(Some(&WslcProvisionSessionConfig {
            cpu_count: Some(u32::MAX),
            ..Default::default()
        }))
        .expect_err("session provisioning must reject the same host CPU limit");
        assert_eq!(error.code, MxcErrorCode::PolicyValidation);
        assert_eq!(error.message, expected.error_message);
    }

    #[test]
    fn a_provision_forwards_the_session_it_names_and_omits_one_it_does_not() {
        let forward = |session_id: Option<&str>| {
            build_provision_config(
                &ExecutionRequest::default(),
                Some(WslcProvisionConfig {
                    image: Some("alpine:latest".to_string()),
                    session_id: session_id.map(str::to_string),
                    ..Default::default()
                }),
            )
        };

        assert_eq!(forward(None).unwrap().session_ref, None);
        assert_eq!(
            forward(Some(VALID_SESSION_ID)).unwrap().session_ref,
            Some(VALID_SESSION_ID.to_string())
        );
    }

    #[test]
    fn a_provision_naming_a_malformed_session_is_refused_before_the_daemon() {
        let runner = WslcStateAwareRunner::new();
        let config = WslcProvisionConfig {
            session_id: Some("wslcsess:not-hex".to_string()),
            ..Default::default()
        };

        let validated = runner
            .validate_provision(&ExecutionRequest::default(), Some(&config))
            .expect_err("a malformed session must not validate");
        assert_eq!(validated.code, MxcErrorCode::MalformedId);

        let built = build_provision_config(&ExecutionRequest::default(), Some(config))
            .expect_err("a malformed session must not be forwarded");
        assert_eq!(built.code, MxcErrorCode::MalformedId);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mxc_common::models::{
        ContainerPolicy, NetworkAction, NetworkEgressPolicy, NetworkIngressPolicy, ProxyAddress,
        ProxyConfig,
    };

    /// The exit code is unrecoverable once dropped, so failing the call must not
    /// discard it.
    #[test]
    fn a_truncated_run_reports_the_exit_code_it_produced() {
        let error = truncated_run_error(3);
        assert_eq!(
            error.code,
            crate::mxc_common::mxc_error::MxcErrorCode::BackendError
        );
        assert_eq!(
            error.details.as_ref().and_then(|d| d.get("exitCode")),
            Some(&serde_json::json!(3))
        );
    }

    #[test]
    fn an_untruncated_run_adds_no_suffix() {
        assert_eq!(truncation_suffix(false), "");
        assert!(truncation_suffix(true).contains("truncated"));
    }

    #[test]
    fn a_stdin_failure_while_the_exec_runs_cancels_it_and_explains_the_cancellation() {
        let forwarding = StdinForwarding::default();

        assert!(forwarding.fail("the stdin connection broke".to_string()));
        let failure = forwarding.finish();

        assert_eq!(failure.as_deref(), Some("the stdin connection broke"));
        let error = piped_cancelled_outcome(false, failure).unwrap_err();
        assert!(
            error.message.contains("the stdin connection broke"),
            "{}",
            error.message
        );
    }

    #[test]
    fn a_stdin_refusal_after_the_exec_ended_is_ignored() {
        let forwarding = StdinForwarding::default();
        assert_eq!(forwarding.finish(), None);

        assert!(
            !forwarding.fail("the run is already over".to_string()),
            "an exec whose outcome is known must not be cancelled again"
        );
        assert_eq!(forwarding.finish(), None);
    }

    #[test]
    fn a_caller_kill_is_reported_as_a_kill_even_if_stdin_also_failed() {
        let outcome =
            piped_cancelled_outcome(true, Some("the run is already over".to_string())).unwrap();

        assert_eq!(outcome, ExecOutcome::Exited(-1));
        assert_eq!(
            piped_cancelled_outcome(false, None).unwrap(),
            ExecOutcome::Exited(-1)
        );
    }

    #[test]
    fn backend_key_matches_wire_format() {
        assert_eq!(
            <WslcStateAwareRunner as StatefulSandboxBackend>::BACKEND_KEY,
            "wslc"
        );
    }

    #[test]
    fn id_prefix_matches_wire_format() {
        assert_eq!(
            <WslcStateAwareRunner as StatefulSandboxBackend>::ID_PREFIX,
            "wslc"
        );
    }

    #[test]
    fn validate_sandbox_id_accepts_prefixed_id() {
        validate_sandbox_id("wslc:0123456789abcdef0123456789abcdef").unwrap();
    }

    #[test]
    fn validate_sandbox_id_rejects_wrong_prefix() {
        let err = validate_sandbox_id("iso:0123456789abcdef0123456789abcdef").unwrap_err();
        assert_eq!(
            err.code,
            crate::mxc_common::mxc_error::MxcErrorCode::MalformedId
        );
    }

    #[test]
    fn validate_sandbox_id_rejects_empty_tail() {
        assert!(validate_sandbox_id("wslc:").is_err());
    }

    #[test]
    fn validate_sandbox_id_rejects_bare_token() {
        assert!(validate_sandbox_id("abc123").is_err());
    }

    #[test]
    fn validate_sandbox_id_rejects_non_hex_tail() {
        // Nonempty but not the 32-hex grammar: reaches the daemon today and is
        // misreported as not_provisioned rather than malformed_id.
        assert!(validate_sandbox_id("wslc:not-a-uuid").is_err());
    }

    #[test]
    fn validate_sandbox_id_rejects_wrong_length() {
        assert!(validate_sandbox_id("wslc:abc123").is_err());
        assert!(validate_sandbox_id("wslc:0123456789abcdef0123456789abcdef0").is_err());
    }

    #[test]
    fn validate_sandbox_id_rejects_uppercase_hex() {
        assert!(validate_sandbox_id("wslc:0123456789ABCDEF0123456789abcdef").is_err());
    }

    #[test]
    fn post_provision_hooks_reject_raw_directional_network_fields() {
        let runner = WslcStateAwareRunner::new();
        let request = ExecutionRequest {
            policy: ContainerPolicy {
                network_egress: Some(NetworkEgressPolicy::default()),
                ..Default::default()
            },
            ..Default::default()
        };
        let id = "wslc:0123456789abcdef0123456789abcdef";

        assert!(runner.validate_start(id, &request, None).is_err());
        assert!(runner.validate_exec(id, &request, None).is_err());
        assert!(runner.validate_stop(id, &request, None).is_err());
        assert!(runner.validate_deprovision(id, &request, None).is_err());
    }

    /// Enumerating all five hooks (rather than testing the shared validator) is
    /// what catches a hook that forgets to call its validator at all.
    #[test]
    fn every_validate_hook_rejects_supplied_ui() {
        let runner = WslcStateAwareRunner::new();
        let request = ExecutionRequest {
            policy: ContainerPolicy {
                ui_specified: true,
                ..Default::default()
            },
            ..Default::default()
        };
        let id = "wslc:0123456789abcdef0123456789abcdef";

        let results = [
            ("provision", runner.validate_provision(&request, None)),
            ("start", runner.validate_start(id, &request, None)),
            ("exec", runner.validate_exec(id, &request, None)),
            ("stop", runner.validate_stop(id, &request, None)),
            (
                "deprovision",
                runner.validate_deprovision(id, &request, None),
            ),
        ];
        for (phase, result) in results {
            let err = result.expect_err(&format!("{phase} must reject a supplied ui"));
            assert_eq!(
                err.code,
                crate::mxc_common::mxc_error::MxcErrorCode::PolicyValidation
            );
            assert!(
                err.message.contains("ui section is not supported"),
                "{phase}: {}",
                err.message
            );
        }
    }

    /// A rule-based posture cannot be mapped to the daemon's binary
    /// [`NetworkMode`], so validation must refuse it before provision.
    #[test]
    fn validate_provision_rejects_unimplementable_network_posture() {
        let runner = WslcStateAwareRunner::new();
        let request = ExecutionRequest {
            policy: ContainerPolicy {
                network_egress: Some(NetworkEgressPolicy {
                    allow: vec![Default::default()],
                    ..Default::default()
                }),
                ..Default::default()
            },
            ..Default::default()
        };
        let err = runner.validate_provision(&request, None).unwrap_err();
        assert_eq!(
            err.code,
            crate::mxc_common::mxc_error::MxcErrorCode::PolicyValidation
        );
        assert!(
            err.message.contains("network.egress"),
            "got: {}",
            err.message
        );
    }

    /// Guards against rejecting either supported all-or-nothing posture.
    #[test]
    fn validate_provision_accepts_the_postures_wslc_can_honour() {
        let runner = WslcStateAwareRunner::new();
        for (label, policy) in [
            ("isolated", ContainerPolicy::default()),
            (
                "bridged",
                ContainerPolicy {
                    network_egress: Some(NetworkEgressPolicy {
                        default: NetworkAction::Allow,
                        ..Default::default()
                    }),
                    network_ingress: Some(NetworkIngressPolicy {
                        default: NetworkAction::Allow,
                        host_loopback: NetworkAction::Allow,
                    }),
                    ..Default::default()
                },
            ),
            (
                "absent ui",
                ContainerPolicy {
                    ui_specified: false,
                    ..Default::default()
                },
            ),
        ] {
            let request = ExecutionRequest {
                policy,
                ..Default::default()
            };
            assert!(
                runner.validate_provision(&request, None).is_ok(),
                "{label} is honoured by WSLc and must not be rejected"
            );
        }
    }

    #[test]
    fn map_network_maps_block_to_none() {
        let req = ExecutionRequest::default();
        assert_eq!(map_network(&req), NetworkMode::None);
    }

    #[test]
    fn map_network_maps_allow_to_bridged() {
        let req = ExecutionRequest {
            policy: ContainerPolicy {
                network_egress: Some(NetworkEgressPolicy {
                    default: NetworkAction::Allow,
                    ..Default::default()
                }),
                ..Default::default()
            },
            ..Default::default()
        };
        assert_eq!(map_network(&req), NetworkMode::Bridged);
    }

    #[test]
    fn build_provision_config_maps_directional_postures_to_daemon_modes() {
        for (action, expected) in [
            (NetworkAction::Deny, NetworkMode::None),
            (NetworkAction::Allow, NetworkMode::Bridged),
        ] {
            let request = ExecutionRequest {
                policy: ContainerPolicy {
                    network_egress: Some(NetworkEgressPolicy {
                        default: action,
                        ..Default::default()
                    }),
                    network_ingress: Some(NetworkIngressPolicy {
                        default: action,
                        host_loopback: action,
                    }),
                    ..Default::default()
                },
                ..Default::default()
            };

            let config = build_provision_config(&request, None).unwrap();
            assert_eq!(config.network, expected);
        }
    }

    #[test]
    fn build_provision_config_forwards_image_and_tar_path() {
        let phase = WslcProvisionConfig {
            image: Some("custom/image:tag".to_string()),
            image_tar_path: Some("C:\\images\\custom.tar".to_string()),
            session_id: None,
            port_mappings: None,
        };
        let cfg = build_provision_config(&ExecutionRequest::default(), Some(phase)).unwrap();
        assert_eq!(cfg.image, "custom/image:tag");
        assert_eq!(
            cfg.image_tar_path.as_deref(),
            Some("C:\\images\\custom.tar")
        );
    }

    #[test]
    fn build_provision_config_defaults_image_and_omits_tar_when_absent() {
        for phase in [None, Some(WslcProvisionConfig::default())] {
            let cfg = build_provision_config(&ExecutionRequest::default(), phase).unwrap();
            assert_eq!(cfg.image, "alpine:latest");
            assert!(cfg.image_tar_path.is_none());
            assert!(cfg.port_mappings.is_empty());
        }
    }

    #[test]
    fn build_provision_config_forwards_port_mappings_to_the_daemon() {
        let phase = WslcProvisionConfig {
            port_mappings: Some(vec![
                crate::mxc_common::models::PortMapping {
                    windows_port: 8080,
                    container_port: 80,
                    protocol: "tcp".to_string(),
                },
                crate::mxc_common::models::PortMapping {
                    windows_port: 8443,
                    container_port: 443,
                    protocol: "tcp".to_string(),
                },
            ]),
            ..Default::default()
        };
        let cfg = build_provision_config(&bridged_request(), Some(phase)).unwrap();
        assert_eq!(
            cfg.port_mappings,
            vec![
                DaemonPortMapping {
                    windows_port: 8080,
                    container_port: 80,
                },
                DaemonPortMapping {
                    windows_port: 8443,
                    container_port: 443,
                },
            ]
        );
    }

    fn bridged_request() -> ExecutionRequest {
        ExecutionRequest {
            policy: ContainerPolicy {
                network_egress: Some(NetworkEgressPolicy {
                    default: NetworkAction::Allow,
                    ..Default::default()
                }),
                network_ingress: Some(NetworkIngressPolicy {
                    default: NetworkAction::Allow,
                    host_loopback: NetworkAction::Allow,
                }),
                ..Default::default()
            },
            ..Default::default()
        }
    }

    #[test]
    fn isolated_networking_rejects_port_mappings_before_the_daemon_sees_them() {
        let phase = WslcProvisionConfig {
            port_mappings: Some(vec![crate::mxc_common::models::PortMapping {
                windows_port: 8080,
                container_port: 80,
                protocol: "tcp".to_string(),
            }]),
            ..Default::default()
        };
        let err = build_provision_config(&ExecutionRequest::default(), Some(phase)).unwrap_err();
        assert_eq!(
            err.code,
            crate::mxc_common::mxc_error::MxcErrorCode::PolicyValidation
        );
        assert!(
            err.message.contains("portMappings"),
            "the message must name the field to remove; got: {}",
            err.message
        );
    }

    #[test]
    fn build_provision_config_distinguishes_absent_from_empty_port_mappings() {
        for mappings in [None, Some(Vec::new())] {
            let phase = WslcProvisionConfig {
                port_mappings: mappings,
                ..Default::default()
            };
            let cfg = build_provision_config(&ExecutionRequest::default(), Some(phase)).unwrap();
            assert!(cfg.port_mappings.is_empty());
        }
    }

    #[test]
    fn build_provision_config_preserves_each_field_and_empty_strings() {
        for (phase, expected_image, expected_tar_path) in [
            (
                WslcProvisionConfig {
                    image: Some("custom/image:tag".to_string()),
                    image_tar_path: None,
                    session_id: None,
                    port_mappings: None,
                },
                "custom/image:tag",
                None,
            ),
            (
                WslcProvisionConfig {
                    image: None,
                    image_tar_path: Some("C:\\images\\custom.tar".to_string()),
                    session_id: None,
                    port_mappings: None,
                },
                "alpine:latest",
                Some("C:\\images\\custom.tar"),
            ),
            (
                WslcProvisionConfig {
                    image: Some(String::new()),
                    image_tar_path: Some(String::new()),
                    session_id: None,
                    port_mappings: None,
                },
                "",
                Some(""),
            ),
        ] {
            let cfg = build_provision_config(&ExecutionRequest::default(), Some(phase)).unwrap();
            assert_eq!(cfg.image, expected_image);
            assert_eq!(cfg.image_tar_path.as_deref(), expected_tar_path);
        }
    }

    #[test]
    fn build_provision_config_rejects_denied_overlap_after_normalization() {
        // Guard: `build_provision_config` must re-run the denied-path overlap
        // check on the (post-normalization) lists, mirroring the one-shot
        // runner. A `deniedPaths` entry nested under a mounted parent has no
        // masking primitive on WSLc's flat mount surface, so it must be
        // rejected here even though the surrounding dispatcher also validates.
        let req = ExecutionRequest {
            policy: ContainerPolicy {
                readwrite_paths: vec!["C:\\parent".to_string()],
                denied_paths: vec!["C:\\parent\\secret".to_string()],
                ..Default::default()
            },
            ..Default::default()
        };
        let err = build_provision_config(&req, None).unwrap_err();
        assert_eq!(
            err.code,
            crate::mxc_common::mxc_error::MxcErrorCode::PolicyValidation
        );
        assert!(err.message.contains("deniedPaths"), "got: {}", err.message);
    }

    #[test]
    fn build_daemon_volumes_maps_rw_and_ro() {
        let req = ExecutionRequest {
            policy: ContainerPolicy {
                readwrite_paths: vec!["C:\\src".to_string()],
                readonly_paths: vec!["D:\\data".to_string()],
                ..Default::default()
            },
            ..Default::default()
        };
        let volumes = build_daemon_volumes(&req).unwrap();
        assert_eq!(volumes.len(), 2);
        assert_eq!(volumes[0].host, "C:\\src");
        assert_eq!(volumes[0].container, "/mnt/c/src");
        assert!(!volumes[0].read_only);
        assert_eq!(volumes[1].container, "/mnt/d/data");
        assert!(volumes[1].read_only);
    }

    #[test]
    fn build_daemon_volumes_rejects_unc_path() {
        let req = ExecutionRequest {
            policy: ContainerPolicy {
                readwrite_paths: vec!["\\\\server\\share".to_string()],
                ..Default::default()
            },
            ..Default::default()
        };
        let err = build_daemon_volumes(&req).unwrap_err();
        assert_eq!(
            err.code,
            crate::mxc_common::mxc_error::MxcErrorCode::PolicyValidation
        );
    }

    #[test]
    fn normalize_and_check_delegation_empty_policy_is_none() {
        let req = ExecutionRequest::default();
        assert!(normalize_and_check_delegation(&req).unwrap().is_none());
    }

    #[test]
    fn normalize_and_check_delegation_tightens_rw_alias_of_ro() {
        // The same host object listed both readwrite and readonly must be
        // tightened to readonly (D6) before the daemon mounts it, so a writable
        // alias of a readonly object never leaks.
        let dir = tempfile::tempdir().unwrap();
        let d = dir.path().to_str().unwrap().to_string();
        let req = ExecutionRequest {
            policy: ContainerPolicy {
                readwrite_paths: vec![d.clone()],
                readonly_paths: vec![d.clone()],
                ..Default::default()
            },
            ..Default::default()
        };
        let tightened = normalize_and_check_delegation(&req)
            .unwrap()
            .expect("aliasing conflict should tighten the policy");
        assert!(tightened.readwrite_paths.is_empty());
        assert_eq!(tightened.readonly_paths, vec![d]);
    }

    #[cfg(windows)]
    #[test]
    fn provision_delegation_tightens_rw_alias_of_denied_and_drops_mount() {
        // A writable path that resolves to the same object as a `denied` entry
        // (here a case-variant string on case-insensitive NTFS) must tighten to
        // denied, and the daemon volumes must be built from that tightened policy
        // — otherwise the writable alias would still be mounted, granting access
        // the deny was meant to block.
        let dir = tempfile::tempdir().unwrap();
        let denied = dir.path().to_str().unwrap().to_string();
        let rw_alias = denied.to_uppercase();
        let raw = ExecutionRequest {
            policy: ContainerPolicy {
                readwrite_paths: vec![rw_alias],
                denied_paths: vec![denied],
                ..Default::default()
            },
            ..Default::default()
        };
        // Pre-fix behaviour the bug relied on: the raw request WOULD mount the
        // alias writable.
        let raw_mounts = build_daemon_volumes(&raw).unwrap();
        assert_eq!(raw_mounts.len(), 1);
        assert!(!raw_mounts[0].read_only);

        let tightened = normalize_and_check_delegation(&raw)
            .unwrap()
            .expect("rw alias of a denied object should tighten");
        assert!(tightened.readwrite_paths.is_empty());
        assert!(!tightened.denied_paths.is_empty());
        let tightened_req = ExecutionRequest {
            policy: tightened,
            ..raw.clone()
        };
        assert!(build_daemon_volumes(&tightened_req).unwrap().is_empty());
    }

    #[cfg(windows)]
    #[test]
    fn provision_delegation_rejects_inaccessible_path() {
        // A delegated path the invoking user cannot access must fail closed
        // before provisioning mounts anything. `C:\mxc_invalid<name` is an
        // illegal name → ERROR_INVALID_NAME → not-accessible (not merely
        // missing), so delegation rejects it.
        let req = ExecutionRequest {
            policy: ContainerPolicy {
                readonly_paths: vec!["C:\\mxc_invalid<name".to_string()],
                ..Default::default()
            },
            ..Default::default()
        };
        let err = normalize_and_check_delegation(&req).unwrap_err();
        assert_eq!(
            err.code,
            crate::mxc_common::mxc_error::MxcErrorCode::PolicyValidation
        );
    }

    #[test]
    fn split_env_splits_pairs_and_drops_bare_keys() {
        let env = vec![
            "PATH=/usr/bin".to_string(),
            "EMPTY=".to_string(),
            "BARE".to_string(),
            "URL=http://a=b".to_string(),
        ];
        let pairs = split_env(&env);
        assert_eq!(pairs[0], ("PATH".to_string(), "/usr/bin".to_string()));
        assert_eq!(pairs[1], ("EMPTY".to_string(), String::new()));
        // Only the first '=' splits; the value keeps the rest verbatim.
        assert_eq!(pairs[2], ("URL".to_string(), "http://a=b".to_string()));
        assert_eq!(pairs.len(), 3);
    }

    #[test]
    fn the_exec_config_carries_the_scope_each_state_of_process_env_selects() {
        struct Case {
            label: &'static str,
            env: Option<Vec<&'static str>>,
            inherit_default_env: bool,
            scope: EnvScope,
            entries: &'static [(&'static str, &'static str)],
        }

        let cases = [
            Case {
                label: "omitted takes the image environment",
                env: None,
                inherit_default_env: false,
                scope: EnvScope::Merge,
                entries: &[],
            },
            Case {
                label: "explicitly empty leaves the child nothing",
                env: Some(vec![]),
                inherit_default_env: false,
                scope: EnvScope::Replace,
                entries: &[],
            },
            Case {
                label: "explicitly empty plus inheritDefaultEnv takes the image environment",
                env: Some(vec![]),
                inherit_default_env: true,
                scope: EnvScope::Merge,
                entries: &[],
            },
            Case {
                label: "supplied is used verbatim",
                env: Some(vec!["FOO=bar"]),
                inherit_default_env: false,
                scope: EnvScope::Replace,
                entries: &[("FOO", "bar")],
            },
            Case {
                label: "supplied plus inheritDefaultEnv layers over the image environment",
                env: Some(vec!["FOO=bar"]),
                inherit_default_env: true,
                scope: EnvScope::Merge,
                entries: &[("FOO", "bar")],
            },
        ];

        for case in cases {
            let request = ExecutionRequest {
                env: case.env.map(|e| e.into_iter().map(String::from).collect()),
                inherit_default_env: case.inherit_default_env,
                script_code: "echo hi".to_string(),
                ..Default::default()
            };

            let config = exec_config(
                "wslc:abc",
                &request,
                "exec-1".to_string(),
                "run-1".to_string(),
            );

            assert_eq!(config.env_scope, case.scope, "scope for {}", case.label);
            let expected: Vec<(String, String)> = case
                .entries
                .iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect();
            assert_eq!(config.env, expected, "entries for {}", case.label);
            assert_eq!(config.sandbox_id, "wslc:abc");
            assert_eq!(config.script_code, "echo hi");
        }
    }

    #[test]
    fn the_exec_config_keeps_the_cooperative_proxy_out_of_the_callers_reach() {
        let request = ExecutionRequest {
            env: Some(vec![
                "FOO=bar".to_string(),
                "HTTP_PROXY=http://attacker.invalid:1".to_string(),
            ]),
            policy: ContainerPolicy {
                network_proxy: ProxyConfig {
                    address: Some(ProxyAddress::from_url(
                        "http://127.0.0.1:8888",
                        "127.0.0.1".to_string(),
                        8888,
                    )),
                },
                ..Default::default()
            },
            ..Default::default()
        };

        let config = exec_config(
            "wslc:abc",
            &request,
            "exec-1".to_string(),
            "run-1".to_string(),
        );

        // Replacement still applies, so the proxy variables must survive into
        // the entries argv carries rather than being left to the SDK's setter.
        assert_eq!(config.env_scope, EnvScope::Replace);
        let value = |name: &str| {
            config
                .env
                .iter()
                .find(|(k, _)| k == name)
                .map(|(_, v)| v.clone())
        };
        assert_eq!(value("FOO").as_deref(), Some("bar"));
        assert_eq!(
            value("HTTP_PROXY").as_deref(),
            Some("http://127.0.0.1:8888")
        );
        assert_eq!(value("NO_PROXY").as_deref(), Some(""));
        assert!(!config.env.iter().any(|(_, v)| v.contains("attacker")));
    }

    #[test]
    fn map_daemon_error_preserves_not_provisioned() {
        let err = map_daemon_error(DaemonError::Daemon {
            kind: ErrKind::NotProvisioned,
            message: "unknown sandbox".to_string(),
        });
        assert_eq!(
            err.code,
            crate::mxc_common::mxc_error::MxcErrorCode::NotProvisioned
        );
    }

    #[test]
    fn map_daemon_error_preserves_not_started() {
        let err = map_daemon_error(DaemonError::Daemon {
            kind: ErrKind::NotStarted,
            message: "not started".to_string(),
        });
        assert_eq!(
            err.code,
            crate::mxc_common::mxc_error::MxcErrorCode::NotStarted
        );
    }

    #[test]
    fn map_daemon_error_collapses_busy_to_backend_error() {
        let err = map_daemon_error(DaemonError::Daemon {
            kind: ErrKind::Busy,
            message: "busy".to_string(),
        });
        assert_eq!(
            err.code,
            crate::mxc_common::mxc_error::MxcErrorCode::BackendError
        );
    }

    #[test]
    fn map_daemon_error_preserves_unavailable() {
        let err = map_daemon_error(DaemonError::Daemon {
            kind: ErrKind::Unavailable,
            message: "WSLc components are missing".to_string(),
        });
        assert_eq!(
            err.code,
            crate::mxc_common::mxc_error::MxcErrorCode::BackendUnavailable
        );
    }

    #[test]
    fn map_daemon_error_preserves_rejected() {
        let err = map_daemon_error(DaemonError::Daemon {
            kind: ErrKind::Rejected,
            message: "network.allowLocalNetwork=true is not supported".to_string(),
        });
        assert_eq!(
            err.code,
            crate::mxc_common::mxc_error::MxcErrorCode::PolicyValidation
        );
    }

    #[test]
    fn map_daemon_error_degrades_unknown_to_backend_error() {
        let err = map_daemon_error(DaemonError::Daemon {
            kind: ErrKind::Unknown,
            message: "from a newer daemon".to_string(),
        });
        assert_eq!(
            err.code,
            crate::mxc_common::mxc_error::MxcErrorCode::BackendError
        );
    }
}
