// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

mod frame;
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
use std::io::{self, Read, Write};

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

enum InputRelayError {
    Read(io::Error),
    Write(io::Error),
}

fn relay_stdin(mut source: impl Read, mut input: impl Write) -> Result<(), InputRelayError> {
    let mut bytes = [0; 8192];
    loop {
        let count = match source.read(&mut bytes) {
            Ok(0) => return Ok(()),
            Ok(count) => count,
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(error) => return Err(InputRelayError::Read(error)),
        };
        input
            .write_all(&bytes[..count])
            .map_err(InputRelayError::Write)?;
    }
}

fn input_pipe_closed(error: &io::Error) -> bool {
    if error.kind() == io::ErrorKind::BrokenPipe {
        return true;
    }
    #[cfg(windows)]
    {
        use windows::Win32::Foundation::{ERROR_BROKEN_PIPE, ERROR_NO_DATA};
        matches!(error.raw_os_error(), Some(code)
            if code == ERROR_BROKEN_PIPE.0 as i32 || code == ERROR_NO_DATA.0 as i32)
    }
    #[cfg(not(windows))]
    {
        false
    }
}

fn relay_output(mut source: impl Read, mut output: impl Write) -> io::Result<()> {
    let mut bytes = [0; 8192];
    loop {
        let count = match source.read(&mut bytes) {
            Ok(0) => return Ok(()),
            Ok(count) => count,
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(error) => return Err(error),
        };
        output.write_all(&bytes[..count])?;
        output.flush()?;
    }
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
            if let Err(error) = relay_stdin(std::io::stdin().lock(), &mut input) {
                *input_result
                    .lock()
                    .unwrap_or_else(|error| error.into_inner()) = Some(error);
            }
        })
        .map_err(|_| MxcError::backend_error("cannot start W365 console input relay"))?;
    let stdout = process
        .take_stdout()
        .ok_or_else(|| MxcError::backend_error("W365 relay has no stdout"))?;
    let stderr = process
        .take_stderr()
        .ok_or_else(|| MxcError::backend_error("W365 relay has no stderr"))?;
    let out = std::thread::Builder::new()
        .name("w365-console-output".into())
        .spawn(move || relay_output(stdout, std::io::stdout().lock()))
        .map_err(|_| MxcError::backend_error("cannot start W365 stdout relay"))?;
    let err = std::thread::Builder::new()
        .name("w365-console-error".into())
        .spawn(move || relay_output(stderr, std::io::stderr().lock()))
        .map_err(|_| MxcError::backend_error("cannot start W365 stderr relay"))?;
    let outcome = process.wait();
    let output = out
        .join()
        .map_err(|_| MxcError::backend_error("W365 stdout relay panicked"))?;
    let errors = err
        .join()
        .map_err(|_| MxcError::backend_error("W365 stderr relay panicked"))?;
    let code = outcome.map_err(|error| {
        wait_error
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .take()
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
        // A confirmed Exit closes the execution input reader, even if the
        // console is still forwarding data. Host read errors remain failures.
        match error {
            InputRelayError::Write(error) if input_pipe_closed(&error) => {}
            InputRelayError::Read(error) => {
                return Err(MxcError::backend_error(format!(
                    "W365 input relay failed: read host stdin: {error}"
                )))
            }
            InputRelayError::Write(error) => {
                return Err(MxcError::backend_error(format!(
                    "W365 input relay failed: write execution stdin: {error}"
                )))
            }
        }
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
