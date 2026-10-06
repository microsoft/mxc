// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Runs a transient container and returns its complete captured output.

use std::error::Error;
use std::io::{self, Write};

use mxc_sdk::v1::{self, ContainerRequest, WaitResult};

fn sample_command() -> &'static str {
    if cfg!(target_os = "windows") {
        "cmd.exe /d /s /c \"echo hello from MXC\""
    } else {
        "sh -c \"printf 'hello from MXC\\n'\""
    }
}

fn run() -> Result<i32, Box<dyn Error>> {
    let mut request = ContainerRequest::new(sample_command());
    request.timeout_ms = Some(30_000);

    let result = v1::run(request, Default::default())?;
    // The process has finished, so these buffers contain its complete output.
    io::stdout().write_all(&result.stdout)?;
    io::stderr().write_all(&result.stderr)?;

    for warning in result.warnings {
        eprintln!("warning: {warning}");
    }

    Ok(match result.outcome {
        WaitResult::Exited(code) => {
            assert!(
                String::from_utf8_lossy(&result.stdout).contains("hello from MXC"),
                "expected greeting was not captured"
            );
            code
        }
        WaitResult::TimedOut => {
            eprintln!("workload timed out");
            124
        }
    })
}

fn main() {
    match run() {
        Ok(code) => std::process::exit(code),
        Err(error) => {
            eprintln!("MXC error: {error}");
            std::process::exit(1);
        }
    }
}
