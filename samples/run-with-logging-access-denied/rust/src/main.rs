// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Captures one intentionally denied ProcessContainer file access.

use std::error::Error;
use std::io;

use mxc_sdk::v1::configs::{CaptureDenials, ProcessContainerConfig};
use mxc_sdk::v1::policy::FilesystemPolicy;
use mxc_sdk::v1::{self, ContainerRequest, Containment, WaitResult};

fn run() -> Result<i32, Box<dyn Error>> {
    if !cfg!(target_os = "windows") {
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "denial capture is available only with Windows ProcessContainer",
        )
        .into());
    }

    let sample_dir = std::env::current_dir()?
        .parent()
        .ok_or_else(|| io::Error::other("sample directory has no parent"))?
        .to_path_buf();
    let denied_path = sample_dir.join("denied.txt").to_string_lossy().into_owned();
    let mut process_container = ProcessContainerConfig::default();
    process_container.capture_denials = Some(CaptureDenials::default());

    let request = ContainerRequest {
        containment: Containment::ProcessContainer(process_container),
        filesystem: Some(FilesystemPolicy {
            denied_paths: vec![denied_path.clone()],
            ..Default::default()
        }),
        environment: Some(vec![("MXC_DENIED_FILE".to_string(), denied_path)]),
        inherit_default_environment: Some(true),
        timeout_ms: Some(30_000),
        ..ContainerRequest::new(concat!(
            "cmd.exe /d /s /c \"type \\\"%MXC_DENIED_FILE%\\\" >nul 2>&1 & ",
            "if errorlevel 1 (exit /b 0) else ",
            "(echo ERROR: denied file was readable 1>&2 & exit /b 1)\""
        ))
    };
    let result = v1::run(request, Default::default())?;

    for warning in result.warnings {
        eprintln!("warning: {warning}");
    }
    match result.outcome {
        WaitResult::Exited(0) => {}
        WaitResult::Exited(code) => return Ok(code),
        WaitResult::TimedOut => {
            eprintln!("workload timed out");
            return Ok(124);
        }
    }

    let metadata = result
        .output_metadata
        .ok_or_else(|| io::Error::other("denial capture returned no output metadata"))?;
    if let Some(error) = metadata.capture_denials_error {
        return Err(io::Error::other(error.message).into());
    }
    let capture = metadata
        .capture_denials
        .ok_or_else(|| io::Error::other("denial capture returned no report"))?;
    if capture.total_denials == 0 {
        return Err(io::Error::other("denial capture returned an empty report").into());
    }

    println!(
        "captured {} denial(s) in {}",
        capture.total_denials, capture.output_path
    );
    Ok(0)
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
