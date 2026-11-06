// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

mod frame;
mod payload;
mod piped;
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

fn relay(handle: ExecHandle) -> Result<ExecHandle, MxcError> {
    let mut process = ExecSandboxProcess::from_exec_handle(handle)?;
    let mut input = process
        .take_stdin()
        .ok_or_else(|| MxcError::backend_error("W365 relay has no stdin"))?;
    // Host console stdin may stay blocked until input/EOF or executor exit.
    // It owns only local I/O; process teardown cancels the managed pipe reader.
    let input_fault = std::sync::Arc::new(std::sync::Mutex::new(None));
    let input_result = input_fault.clone();
    std::thread::Builder::new()
        .name("w365-console-input".into())
        .spawn(move || {
            if let Err(error) = std::io::copy(&mut std::io::stdin().lock(), &mut input) {
                *input_result
                    .lock()
                    .unwrap_or_else(|error| error.into_inner()) = Some(error);
            }
        })
        .map_err(|_| MxcError::backend_error("cannot start W365 console input relay"))?;
    let mut stdout = process
        .take_stdout()
        .ok_or_else(|| MxcError::backend_error("W365 relay has no stdout"))?;
    let mut stderr = process
        .take_stderr()
        .ok_or_else(|| MxcError::backend_error("W365 relay has no stderr"))?;
    let out = std::thread::Builder::new()
        .name("w365-console-output".into())
        .spawn(move || std::io::copy(&mut stdout, &mut std::io::stdout().lock()))
        .map_err(|_| MxcError::backend_error("cannot start W365 stdout relay"))?;
    let err = std::thread::Builder::new()
        .name("w365-console-error".into())
        .spawn(move || std::io::copy(&mut stderr, &mut std::io::stderr().lock()))
        .map_err(|_| MxcError::backend_error("cannot start W365 stderr relay"))?;
    let outcome = process.wait();
    let output = out
        .join()
        .map_err(|_| MxcError::backend_error("W365 stdout relay panicked"))?;
    let errors = err
        .join()
        .map_err(|_| MxcError::backend_error("W365 stderr relay panicked"))?;
    let code = outcome.map_err(|error| {
        error
            .get_ref()
            .and_then(|inner| inner.downcast_ref::<MxcError>())
            .cloned()
            .unwrap_or_else(|| MxcError::backend_error(format!("W365 relay wait failed: {error}")))
    })?;
    output
        .and(errors)
        .map_err(|error| MxcError::backend_error(format!("W365 output relay failed: {error}")))?;
    if let Some(error) = input_fault
        .lock()
        .unwrap_or_else(|error| error.into_inner())
        .take()
    {
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
