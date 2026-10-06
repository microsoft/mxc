// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use std::error::Error;
use std::io::{self, Write};

use mxc_sdk::v1::{container, ContainerId, ExecutionRequest, ProvisionRequest, WaitResult};

fn cleanup(container_id: &ContainerId, started: bool) -> Result<(), Box<dyn Error>> {
    let mut first_error: Option<Box<dyn Error>> = None;

    if started {
        if let Err(error) = container::stop_container(container_id, Default::default()) {
            eprintln!("cleanup error while stopping container: {error}");
            first_error = Some(Box::new(error));
        }
    }

    if let Err(error) = container::deprovision_container(container_id, Default::default()) {
        eprintln!("cleanup error while deprovisioning container: {error}");
        if first_error.is_none() {
            first_error = Some(Box::new(error));
        }
    }

    match first_error {
        Some(error) => Err(error),
        None => Ok(()),
    }
}

fn run() -> Result<i32, Box<dyn Error>> {
    if !cfg!(target_os = "windows") {
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "the persisted IsolationSession sample requires Windows",
        )
        .into());
    }

    let provisioned = container::provision_container(
        ProvisionRequest::isolation_session(None),
        Default::default(),
    )?;
    let container_id = provisioned.container_id;
    println!("provisioned: {container_id}");
    let mut started = false;

    let operation = (|| -> Result<i32, Box<dyn Error>> {
        container::start_container(&container_id, Default::default())?;
        started = true;

        let result = container::run_in_container(
            &container_id,
            ExecutionRequest {
                timeout_ms: Some(30_000),
                ..ExecutionRequest::new(
                    "cmd.exe /d /s /c \"echo hello from persisted container\"",
                )
            },
            Default::default(),
        )?;
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
    })();

    let cleanup_result = cleanup(&container_id, started);
    match operation {
        Err(error) => Err(error),
        Ok(code) => {
            cleanup_result?;
            Ok(code)
        }
    }
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
