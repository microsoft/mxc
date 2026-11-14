// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Development-contract execution example using the V1.Dev JSON SDK.
//! No allocation, release, token acquisition, retry or request logging.

use mxc_sdk::mxc_common::{self, mxc_error::MxcError};
use mxc_sdk::v1::{dev, Error, WaitResult};
use std::io::{Read, Write};

#[path = "../src/backends/w365agents/exec/input.rs"]
mod input;

#[path = "../src/backends/w365agents/exec/output.rs"]
mod output;

fn io_error(error: std::io::Error) -> MxcError {
    error
        .get_ref()
        .and_then(|inner| inner.downcast_ref::<MxcError>())
        .cloned()
        .unwrap_or_else(|| MxcError::backend_error(format!("native execution I/O failed: {error}")))
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
    let live = args[1] == "live";
    if live {
        let mut pipes = process
            .take_native_stdio()
            .map_err(io_error)?
            .ok_or_else(|| MxcError::backend_error("missing native pipes"))?;
        let input = input::InputRelay::start(
            pipes
                .stdin
                .take()
                .ok_or_else(|| MxcError::backend_error("missing native stdin"))?,
        )
        .map_err(io_error)?;
        let outputs = output::OutputRelays::start_native(
            pipes
                .stdout
                .take()
                .ok_or_else(|| MxcError::backend_error("missing native stdout"))?,
            pipes
                .stderr
                .take()
                .ok_or_else(|| MxcError::backend_error("missing native stderr"))?,
        )
        .map_err(io_error)?;
        let outcome = process.wait();
        let input = input.finish(matches!(outcome, Ok(WaitResult::Exited(_))));
        let output = outputs.finish();
        let input_error = input.result().err();
        let outcome = outcome.map_err(|error| {
            let mut error = io_error(error);
            if output.undelivered.iter().any(|value| *value) {
                error
                    .message
                    .push_str("; host_output_undelivered: host output did not drain");
                let details = error.details.get_or_insert_with(|| serde_json::json!({}));
                details["hostStderrUndelivered"] = serde_json::json!(output.undelivered[1]);
                details["hostStdoutUndelivered"] = serde_json::json!(output.undelivered[0]);
                details["hostStderrUnavailable"] = serde_json::json!(output.stderr_unavailable);
            }
            if let Some(input_error) = &input_error {
                error
                    .message
                    .push_str(&format!("; input relay failed: {input_error}"));
            }
            error
        })?;
        output.writes.map_err(|error| {
            let mut error = io_error(error).with_details(serde_json::json!({
                "hostStderrUndelivered":output.undelivered[1],
                "hostStderrUnavailable":output.stderr_unavailable,
                "hostStdoutUndelivered":output.undelivered[0]
            }));
            if let Some(input_error) = &input_error {
                error
                    .message
                    .push_str(&format!("; input relay failed: {input_error}"));
            }
            error
        })?;
        if let Some(error) = input_error {
            return Err(io_error(error));
        }
        return exit_code(outcome);
    }
    drop(
        process
            .take_stdin()
            .ok_or_else(|| MxcError::backend_error("missing native stdin"))?,
    );
    let stdout = process
        .take_stdout()
        .ok_or_else(|| MxcError::backend_error("missing native stdout"))?;
    let stderr = process
        .take_stderr()
        .ok_or_else(|| MxcError::backend_error("missing native stderr"))?;
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

fn main() {
    match execute() {
        Ok(code) => std::process::exit(code),
        Err(error) => {
            if !error
                .details
                .as_ref()
                .is_some_and(|details| details["hostStderrUnavailable"] == true)
            {
                eprintln!("{}", error.to_envelope_string());
            }
            std::process::exit(125);
        }
    }
}
