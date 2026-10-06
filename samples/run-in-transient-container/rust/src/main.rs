// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use std::error::Error;
use std::io::{self, Write};

use mxc_sdk::v1::{self, ContainerRequest, Containment, WaitResult};

fn sample_command() -> &'static str {
    if cfg!(target_os = "windows") {
        "cmd.exe /d /s /c \"echo hello from %MXC_SAMPLE_NAME%\""
    } else {
        "sh -c \"printf 'hello from %s\\n' \\\"$MXC_SAMPLE_NAME\\\"\""
    }
}

fn run() -> Result<i32, Box<dyn Error>> {
    let support = v1::platform_support();
    if !support.is_supported {
        return Err(io::Error::other(
            support
                .reason
                .unwrap_or_else(|| "MXC is not supported on this host".to_string()),
        )
        .into());
    }

    let request = ContainerRequest {
        containment: Containment::Process,
        timeout_ms: Some(30_000),
        environment: Some(vec![(
            "MXC_SAMPLE_NAME".to_string(),
            "transient-container".to_string(),
        )]),
        inherit_default_environment: Some(true),
        ..ContainerRequest::new(sample_command())
    };
    let result = v1::run(request, Default::default())?;

    io::stdout().write_all(&result.stdout)?;
    io::stderr().write_all(&result.stderr)?;
    for warning in result.warnings {
        eprintln!("warning: {warning}");
    }

    Ok(match result.outcome {
        WaitResult::Exited(code) => code,
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
