// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use std::error::Error;
use std::time::Duration;

struct SandboxCleanup {
    id: mxc_sdk::sandbox::SandboxId,
    started: bool,
}

impl Drop for SandboxCleanup {
    fn drop(&mut self) {
        if self.started {
            let _ = mxc_sdk::sandbox::stop(&self.id);
        }
        if let Err(error) = mxc_sdk::sandbox::deprovision(&self.id) {
            eprintln!("WARNING: deprovision failed: {error}");
        }
    }
}

fn run() -> Result<i32, Box<dyn Error>> {
    let provisioned = mxc_sdk::sandbox::provision(mxc_sdk::sandbox::ProvisionOptions {
        version: "0.9.0-alpha",
        containment: mxc_sdk::sandbox::Containment::Wslc {
            image: "alpine:latest",
        },
        network: mxc_sdk::sandbox::NetworkPolicy::isolated(),
        experimental: true,
    })?;

    let mut sandbox = SandboxCleanup {
        id: provisioned.sandbox_id,
        started: false,
    };
    println!("Sandbox ID: {}", sandbox.id);

    mxc_sdk::sandbox::start(&sandbox.id)?;
    sandbox.started = true;

    let outcome = mxc_sdk::sandbox::exec_attached(
        &sandbox.id,
        r#"sh -c 'echo "hello from wslc bash"; sleep 3; echo "hello again from wslc bash"'"#,
        mxc_sdk::sandbox::ExecOptions {
            timeout: Duration::from_secs(30),
        },
    )?;

    Ok(match outcome {
        mxc_sdk::WaitOutcome::Exited(code) => code,
        mxc_sdk::WaitOutcome::TimedOut => 1,
    })
}

fn main() {
    let exit_code = run().unwrap_or_else(|error| {
        eprintln!("{error}");
        1
    });
    std::process::exit(exit_code);
}
