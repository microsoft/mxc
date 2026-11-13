// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Development-contract execution example using the V1.Dev JSON SDK.
//! No allocation, release, token acquisition, retry or request logging.

use mxc_sdk::mxc_common::mxc_error::MxcError;
use mxc_sdk::v1::{dev, Error, WaitResult};
use std::io::{self, Read, Write};

#[path = "../src/backends/w365agents/exec/output.rs"]
mod output;

fn io_error(error: std::io::Error) -> MxcError {
    error
        .get_ref()
        .and_then(|inner| inner.downcast_ref::<MxcError>())
        .cloned()
        .unwrap_or_else(|| MxcError::backend_error(format!("native execution I/O failed: {error}")))
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

fn execute() -> Result<i32, MxcError> {
    let args: Vec<_> = std::env::args().skip(1).collect();
    if args.len() != 3
        || args[0] != "--experimental"
        || !matches!(args[1].as_str(), "live" | "capture")
    {
        return Err(MxcError::policy_validation(
            "usage: w365_execution --experimental <live|capture> <exec-request.json>",
        ));
    }
    let json = std::fs::read_to_string(&args[2]).map_err(io_error)?;
    let mut process = dev::spawn_in_container_json(&json, dev::JsonOptions { experimental: true })
        .map_err(Error::into_mxc_error)?;
    let mut input = process
        .take_stdin()
        .ok_or_else(|| MxcError::backend_error("missing native stdin"))?;
    let live = args[1] == "live";
    let input_fault = std::sync::Arc::new(std::sync::Mutex::new(None));
    if live {
        let fault = input_fault.clone();
        std::thread::Builder::new()
            .name("native-example-input".into())
            .spawn(move || {
                if let Err(error) = relay_stdin(std::io::stdin().lock(), &mut input) {
                    *fault.lock().unwrap_or_else(|error| error.into_inner()) = Some(error);
                }
            })
            .map_err(io_error)?;
    } else {
        drop(input);
    }
    let stdout = process
        .take_stdout()
        .ok_or_else(|| MxcError::backend_error("missing native stdout"))?;
    let stderr = process
        .take_stderr()
        .ok_or_else(|| MxcError::backend_error("missing native stderr"))?;
    if live {
        let close_stdout = process.stdout_closer();
        let close_stderr = process.stderr_closer();
        let outputs = output::OutputRelays::start(
            stdout,
            stderr,
            move || {
                if let Some(closer) = &close_stdout {
                    closer.close();
                }
            },
            move || {
                if let Some(closer) = &close_stderr {
                    closer.close();
                }
            },
        )
        .map_err(io_error)?;
        let outcome = process.wait();
        let output = outputs.finish();
        let outcome = outcome.map_err(|error| {
            let mut error = io_error(error);
            if output.undelivered.iter().any(|value| *value) {
                error
                    .message
                    .push_str("; host_output_undelivered: host output did not drain");
                let details = error.details.get_or_insert_with(|| serde_json::json!({}));
                details["hostStderrUndelivered"] = serde_json::json!(output.undelivered[1]);
                details["hostStdoutUndelivered"] = serde_json::json!(output.undelivered[0]);
            }
            error
        })?;
        output.writes.map_err(|error| {
            io_error(error).with_details(serde_json::json!({
                "hostStderrUndelivered":output.undelivered[1],
                "hostStdoutUndelivered":output.undelivered[0]
            }))
        })?;
        check_input(&input_fault)?;
        return exit_code(outcome);
    }
    let start_reader = |mut reader: Box<dyn Read + Send>| {
        std::thread::Builder::new()
            .name("native-example-output".into())
            .spawn(move || {
                let mut bytes = Vec::new();
                reader.read_to_end(&mut bytes)?;
                Ok::<_, std::io::Error>(bytes)
            })
    };
    let out = start_reader(stdout).map_err(io_error)?;
    let err = start_reader(stderr).map_err(io_error)?;
    let outcome = process.wait();
    if outcome.is_err() {
        if let Some(closer) = process.stdout_closer() {
            closer.close();
        }
        if let Some(closer) = process.stderr_closer() {
            closer.close();
        }
    }
    let stdout = out
        .join()
        .map_err(|_| MxcError::backend_error("stdout reader panicked"))?;
    let stderr = err
        .join()
        .map_err(|_| MxcError::backend_error("stderr reader panicked"))?;
    let code = exit_code(outcome.map_err(io_error)?)?;
    let stdout = stdout.map_err(io_error)?;
    let stderr = stderr.map_err(io_error)?;
    std::io::stdout().write_all(&stdout).map_err(io_error)?;
    std::io::stderr().write_all(&stderr).map_err(io_error)?;
    Ok(code)
}

fn exit_code(outcome: WaitResult) -> Result<i32, MxcError> {
    match outcome {
        WaitResult::Exited(code) => Ok(code),
        WaitResult::TimedOut => Err(MxcError::backend_error(
            "execution timed out without an exit code",
        )),
    }
}

fn check_input(input_fault: &std::sync::Mutex<Option<InputRelayError>>) -> Result<(), MxcError> {
    if let Some(error) = input_fault
        .lock()
        .unwrap_or_else(|error| error.into_inner())
        .take()
    {
        // A confirmed Exit may close guest stdin while host input is still pending.
        match error {
            InputRelayError::Write(error) if input_pipe_closed(&error) => {}
            InputRelayError::Read(error) => {
                return Err(MxcError::backend_error(format!(
                    "native execution I/O failed: read host stdin: {error}"
                )))
            }
            InputRelayError::Write(error) => return Err(io_error(error)),
        }
    }
    Ok(())
}

fn main() {
    match execute() {
        Ok(code) => std::process::exit(code),
        Err(error) => {
            if !error
                .details
                .as_ref()
                .is_some_and(|details| details["hostStderrUndelivered"] == true)
            {
                eprintln!("{}", error.to_envelope_string());
            }
            std::process::exit(125);
        }
    }
}
