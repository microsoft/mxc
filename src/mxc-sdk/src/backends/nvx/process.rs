// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use std::os::windows::io::AsRawHandle;
use std::sync::{Arc, Mutex, PoisonError};

use aci_edge_sandboxes::{ExecOutcome as NvxExecOutcome, Execution};
use windows::Win32::Foundation::HANDLE;

use crate::mxc_common::mxc_error::MxcError;
use crate::mxc_common::state_aware_backend::{ExecHandle, ExecOutcome, ExecStdio};

struct LiveExecution {
    execution: Option<Execution>,
    stdin: Option<std::io::PipeWriter>,
    stdout: Option<std::io::PipeReader>,
    stderr: Option<std::io::PipeReader>,
}

pub(super) fn into_exec_handle(
    mut execution: Execution,
    stdio: ExecStdio,
) -> Result<ExecHandle, MxcError> {
    let canceller = execution.canceller();
    let stdin = match stdio {
        ExecStdio::Piped => execution.take_stdin(),
        ExecStdio::Relayed => {
            drop(execution.take_stdin());
            None
        }
    };
    let stdout = execution.take_stdout();
    let stderr = execution.take_stderr();
    let stdout_handle = pipe_reader_handle(stdout.as_ref());
    let stderr_handle = pipe_reader_handle(stderr.as_ref());
    let stdin_handle = pipe_writer_handle(stdin.as_ref());
    let has_stdin = stdin.is_some();
    let shared = Arc::new(Mutex::new(LiveExecution {
        execution: Some(execution),
        stdin,
        stdout,
        stderr,
    }));
    let waiter_state = Arc::clone(&shared);
    let stdin_state = Arc::clone(&shared);
    let stdin_closer: Option<Box<dyn FnOnce() + Send>> = if has_stdin {
        Some(Box::new(move || {
            stdin_state
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .stdin = None;
        }))
    } else {
        None
    };

    Ok(ExecHandle {
        stdout: stdout_handle,
        stderr: stderr_handle,
        stdin: stdin_handle,
        waiter: Box::new(move || {
            let execution = waiter_state
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .execution
                .take()
                .ok_or_else(|| MxcError::backend_error("NVX execution was already waited"))?;
            let outcome = execution
                .wait()
                .map_err(super::runtime::map_nvx_error)
                .and_then(|outcome| map_outcome_for_stdio(outcome, stdio));
            let mut state = waiter_state.lock().unwrap_or_else(PoisonError::into_inner);
            state.stdin = None;
            state.stdout = None;
            state.stderr = None;
            outcome
        }),
        terminator: Box::new(move || canceller.cancel().map_err(super::runtime::map_nvx_error)),
        stdin_closer,
    })
}

fn map_outcome_for_stdio(
    outcome: NvxExecOutcome,
    stdio: ExecStdio,
) -> Result<ExecOutcome, MxcError> {
    if outcome == NvxExecOutcome::TimedOut && stdio == ExecStdio::Relayed {
        return Err(MxcError::backend_error(
            "NVX relayed exec timed out; workload deadline elapsed",
        ));
    }
    map_outcome(outcome)
}

fn pipe_reader_handle(reader: Option<&std::io::PipeReader>) -> HANDLE {
    reader.map_or_else(
        || HANDLE(std::ptr::null_mut()),
        |reader| HANDLE(reader.as_raw_handle()),
    )
}

fn pipe_writer_handle(writer: Option<&std::io::PipeWriter>) -> HANDLE {
    writer.map_or_else(
        || HANDLE(std::ptr::null_mut()),
        |writer| HANDLE(writer.as_raw_handle()),
    )
}

fn map_outcome(outcome: NvxExecOutcome) -> Result<ExecOutcome, MxcError> {
    match outcome {
        NvxExecOutcome::Exited(code) => Ok(ExecOutcome::Exited(code)),
        NvxExecOutcome::Signaled(signal) => Ok(ExecOutcome::Exited(128_i32.saturating_add(signal))),
        NvxExecOutcome::Cancelled => Ok(ExecOutcome::Exited(137)),
        NvxExecOutcome::TimedOut => Ok(ExecOutcome::TimedOut),
        other => Err(MxcError::backend_error(format!(
            "NVX workload did not complete normally: {other}"
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn relayed_adapter_closes_real_stdin_before_waiting_for_eof() {
        let fixture = super::super::test_support::Fixture {
            require_stdin_eof: true,
            ..Default::default()
        };
        let client = aci_edge_sandboxes::AciEdgeSandbox::new(fixture.clone());
        let execution = client
            .exec(
                &super::super::test_support::Fixture::id(),
                &aci_edge_sandboxes::ExecRequest::command_line("read-input")
                    .with_stdin(aci_edge_sandboxes::StdinMode::Piped),
            )
            .unwrap();
        let handle = into_exec_handle(execution, ExecStdio::Relayed).unwrap();
        assert!(handle.stdin.0.is_null());
        assert!(handle.stdin_closer.is_none());
        let (tx, rx) = std::sync::mpsc::channel();
        let waiter = std::thread::spawn(move || tx.send((handle.waiter)()).unwrap());
        let result = rx.recv_timeout(std::time::Duration::from_secs(2));
        // Release a regressed retained writer path before joining the test waiter.
        if let Some(closer) = fixture.stdin_closer.lock().unwrap().as_ref() {
            closer.close();
        }
        waiter.join().unwrap();
        assert_eq!(
            result
                .expect("Relayed adapter retained a stdin writer")
                .unwrap(),
            ExecOutcome::Exited(7)
        );
    }

    #[test]
    fn timeout_obeys_stdio_contract() {
        assert_eq!(
            map_outcome_for_stdio(NvxExecOutcome::TimedOut, ExecStdio::Piped).unwrap(),
            ExecOutcome::TimedOut
        );
        let error =
            map_outcome_for_stdio(NvxExecOutcome::TimedOut, ExecStdio::Relayed).unwrap_err();
        assert_eq!(
            error.code,
            crate::mxc_common::mxc_error::MxcErrorCode::BackendError
        );
        assert_eq!(
            error.message,
            "NVX relayed exec timed out; workload deadline elapsed"
        );
    }

    #[test]
    fn maps_terminal_outcomes() {
        assert_eq!(
            map_outcome(NvxExecOutcome::Exited(7)).unwrap(),
            ExecOutcome::Exited(7)
        );
        assert_eq!(
            map_outcome(NvxExecOutcome::Signaled(9)).unwrap(),
            ExecOutcome::Exited(137)
        );
        assert_eq!(
            map_outcome(NvxExecOutcome::Cancelled).unwrap(),
            ExecOutcome::Exited(137)
        );
        assert_eq!(
            map_outcome(NvxExecOutcome::TimedOut).unwrap(),
            ExecOutcome::TimedOut
        );
    }
}
