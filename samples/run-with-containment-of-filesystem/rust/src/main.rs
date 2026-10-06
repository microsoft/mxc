// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Grants the sample directory read-only to a transient container.

use std::error::Error;
use std::io::{self, Write};

use mxc_sdk::v1::policy::FilesystemPolicy;
use mxc_sdk::v1::{self, ContainerRequest, Containment, WaitResult};

fn sample_command() -> &'static str {
    if cfg!(target_os = "windows") {
        "cmd.exe /d /s /c \"echo unexpected>blocked.txt 2>nul & if exist blocked.txt (del blocked.txt & echo ERROR: write unexpectedly succeeded & exit /b 1) else (type input.txt & echo write access blocked by policy)\""
    } else {
        "sh -c \"if printf unexpected > blocked.txt 2>/dev/null; then rm -f blocked.txt; echo 'ERROR: write unexpectedly succeeded' >&2; exit 1; fi; cat input.txt; printf 'write access blocked by policy\\n'\""
    }
}

fn run() -> Result<i32, Box<dyn Error>> {
    let sample_dir = std::env::current_dir()?
        .parent()
        .ok_or_else(|| io::Error::other("sample directory has no parent"))?
        .to_path_buf();
    let sample_dir = sample_dir.to_string_lossy().into_owned();

    let request = ContainerRequest {
        containment: Containment::Process,
        filesystem: Some(FilesystemPolicy {
            readonly_paths: vec![sample_dir.clone()],
            ..Default::default()
        }),
        working_directory: Some(sample_dir),
        timeout_ms: Some(30_000),
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
