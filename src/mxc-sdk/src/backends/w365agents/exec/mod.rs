// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

mod frame;
mod input;
mod output;
mod payload;
mod piped;
mod stream_buffer;
mod transport;

use super::{data_plane, service::Identity};
use crate::mxc_common::{
    exec_stream::ExecSandboxProcess,
    models::ExecutionRequest,
    mxc_error::MxcError,
    sandbox_process::SandboxProcess,
    state_aware_backend::{null_pipe_handle, ExecHandle, ExecOutcome, ExecStdio},
};

pub(super) fn validate(id: &str, request: &ExecutionRequest) -> Result<(), MxcError> {
    let identity = Identity::parse(id)?;
    payload::ExecStartPayload::from_request(request)?;
    data_plane::client(&identity).map(|_| ())
}

pub(super) fn run(
    id: &str,
    request: &ExecutionRequest,
    stdio: ExecStdio,
) -> Result<ExecHandle, MxcError> {
    let identity = Identity::parse(id)?;
    let start = payload::ExecStartPayload::from_request(request)?;
    let target = transport::UpgradeTarget::new(data_plane::client(&identity)?, &identity);
    let result = piped::run(target, start)
        .map(|handle| {
            let ExecHandle {
                stdout,
                stderr,
                stdin,
                stdin_closer,
                waiter,
                terminator,
            } = handle;
            let wait_id = identity.encode();
            let terminate_id = wait_id.clone();
            ExecHandle {
                stdout,
                stderr,
                stdin,
                stdin_closer,
                waiter: Box::new(move || waiter().map_err(|error| identify(error, &wait_id))),
                terminator: Box::new(move || {
                    terminator().map_err(|error| identify(error, &terminate_id))
                }),
            }
        })
        .and_then(|handle| match stdio {
            ExecStdio::Piped => Ok(handle),
            ExecStdio::Relayed => relay(handle),
        });
    result.map_err(|error| identify(error, &identity.encode()))
}

fn identify(mut error: MxcError, id: &str) -> MxcError {
    error.details.get_or_insert_with(|| serde_json::json!({}))["sandboxId"] = serde_json::json!(id);
    error
}

fn relay(mut handle: ExecHandle) -> Result<ExecHandle, MxcError> {
    // Keep backend details for the executor without changing the shared process error contract.
    let wait_error = std::sync::Arc::new(std::sync::Mutex::new(None));
    let recorded_error = wait_error.clone();
    let waiter = handle.waiter;
    handle.waiter = Box::new(move || {
        let result = waiter();
        if let Err(error) = &result {
            *recorded_error.lock().unwrap_or_else(|e| e.into_inner()) = Some(error.clone());
        }
        result
    });
    let mut process = ExecSandboxProcess::from_exec_handle(handle)?;
    let mut pipes = process
        .take_native_stdio()
        .map_err(|error| MxcError::backend_error(format!("cannot take W365 relay pipes: {error}")))?
        .ok_or_else(|| MxcError::backend_error("W365 relay has no native pipes"))?;
    let input = input::InputRelay::start(
        pipes
            .stdin
            .take()
            .ok_or_else(|| MxcError::backend_error("W365 relay has no stdin"))?,
    )
    .map_err(|error| MxcError::backend_error(format!("cannot start W365 input relay: {error}")))?;
    let stdout = pipes
        .stdout
        .take()
        .ok_or_else(|| MxcError::backend_error("W365 relay has no stdout"))?;
    let stderr = pipes
        .stderr
        .take()
        .ok_or_else(|| MxcError::backend_error("W365 relay has no stderr"))?;
    let outputs = output::OutputRelays::start_native(stdout, stderr).map_err(|error| {
        MxcError::backend_error(format!("cannot start W365 output relay: {error}"))
    })?;
    let outcome = process.wait();
    let input = input.finish(outcome.is_ok());
    let output = outputs.finish();
    let input_error = input.result().err();
    let code = outcome.map_err(|error| {
        let mut error = wait_error
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .take()
            .unwrap_or_else(|| MxcError::backend_error(format!("W365 relay wait failed: {error}")));
        if output.undelivered.iter().any(|value| *value) {
            error
                .message
                .push_str("; host_output_undelivered: host output did not drain");
            let details = error.details.get_or_insert_with(|| serde_json::json!({}));
            details["hostStderrUndelivered"] = serde_json::json!(output.undelivered[1]);
            details["hostStdoutUndelivered"] = serde_json::json!(output.undelivered[0]);
        }
        if let Some(input_error) = &input_error {
            error
                .message
                .push_str(&format!("; W365 input relay failed: {input_error}"));
        }
        error
    })?;
    output.writes.map_err(|error| {
        let mut error = MxcError::backend_error(format!("W365 output relay failed: {error}"))
            .with_details(serde_json::json!({
                "code": if output.undelivered.iter().any(|value| *value) {
                    "host_output_undelivered"
                } else { "output_io" },
                "hostStdoutUndelivered":output.undelivered[0],
                "hostStderrUndelivered":output.undelivered[1],
                "exitCode":code
            }));
        if let Some(input_error) = &input_error {
            error
                .message
                .push_str(&format!("; W365 input relay failed: {input_error}"));
        }
        error
    })?;
    if let Some(error) = input_error {
        return Err(MxcError::backend_error(format!(
            "W365 input relay failed: {error}"
        )));
    }
    Ok(ExecHandle {
        stdout: null_pipe_handle(),
        stderr: null_pipe_handle(),
        stdin: null_pipe_handle(),
        stdin_closer: None,
        waiter: Box::new(move || Ok(ExecOutcome::Exited(code))),
        terminator: Box::new(|| Ok(())),
    })
}
