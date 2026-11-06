// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Development-only native execution example, not a supported public SDK API.
//! No allocation, release, token acquisition, retry or request logging.

use mxc_sdk::mxc_common::{
    config_parser::load_mxc_request_from_json,
    logger::{Logger, Mode},
    mxc_error::MxcError,
    state_aware_request::MxcRequest,
};
use std::io::{Read, Write};

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
            "usage: w365_native_execution --experimental <live|capture> <exec-request.json>",
        ));
    }
    let json = std::fs::read_to_string(&args[2]).map_err(io_error)?;
    let MxcRequest::StateAware(mut parsed) =
        load_mxc_request_from_json(&json, &mut Logger::new(Mode::Buffer))
            .map_err(|error| error.to_mxc_error())?
    else {
        return Err(MxcError::unsupported_phase(
            "provide a development lifecycle exec request",
        ));
    };
    parsed.set_experimental_enabled(true);
    let mut process = mxc_sdk::mxc_engine::exec_native_state_aware(parsed, true)?;
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
                if let Err(error) = std::io::copy(&mut std::io::stdin().lock(), &mut input) {
                    *fault.lock().unwrap_or_else(|error| error.into_inner()) =
                        Some(io_error(error));
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
    let start_reader = |mut reader: Box<dyn Read + Send>, is_stderr: bool| {
        std::thread::Builder::new()
            .name("native-example-output".into())
            .spawn(move || {
                let mut bytes = Vec::new();
                if live {
                    if is_stderr {
                        std::io::copy(&mut reader, &mut std::io::stderr().lock())?;
                    } else {
                        std::io::copy(&mut reader, &mut std::io::stdout().lock())?;
                    }
                } else {
                    reader.read_to_end(&mut bytes)?;
                }
                Ok::<_, std::io::Error>(bytes)
            })
    };
    let out = start_reader(stdout, false).map_err(io_error)?;
    let err = start_reader(stderr, true).map_err(io_error)?;
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
    let code = outcome.map_err(io_error)?;
    if let Some(error) = input_fault
        .lock()
        .unwrap_or_else(|error| error.into_inner())
        .take()
    {
        return Err(error);
    }
    let stdout = stdout.map_err(io_error)?;
    let stderr = stderr.map_err(io_error)?;
    if !live {
        std::io::stdout().write_all(&stdout).map_err(io_error)?;
        std::io::stderr().write_all(&stderr).map_err(io_error)?;
    }
    Ok(code)
}

fn main() {
    match execute() {
        Ok(code) => std::process::exit(code),
        Err(error) => {
            eprintln!("{}", error.to_envelope_string());
            std::process::exit(125);
        }
    }
}
