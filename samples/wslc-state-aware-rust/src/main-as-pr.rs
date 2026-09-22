// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use std::error::Error;
use std::io;

struct SandboxCleanup {
    id: String,
    started: bool,
}

impl Drop for SandboxCleanup {
    fn drop(&mut self) {
        let request = r#"{"version":"0.9.0-alpha"}"#;
        if self.started {
            let _ = mxc_sdk::sandbox::stop(&self.id, request, true);
        }
        if let Err(error) = mxc_sdk::sandbox::deprovision(&self.id, request, true) {
            eprintln!("WARNING: deprovision failed: {error}");
        }
    }
}

fn run() -> Result<i32, Box<dyn Error>> {
    let provisioned = mxc_sdk::sandbox::provision(
        r#"{
            "version": "0.9.0-alpha",
            "containment": "wslc",
            "network": {
                "egress": { "default": "deny" },
                "ingress": {
                    "default": "deny",
                    "hostLoopback": "deny"
                }
            },
            "experimental": {
                "wslc": { "image": "alpine:latest" }
            }
        }"#,
        true,
    )?;
    let response: serde_json::Value = serde_json::from_str(&provisioned)?;
    let sandbox_id = response["result"]["sandboxId"]
        .as_str()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "missing sandboxId"))?
        .to_owned();
    println!("Sandbox ID: {sandbox_id}");

    let mut cleanup = SandboxCleanup {
        id: sandbox_id,
        started: false,
    };
    mxc_sdk::sandbox::start(&cleanup.id, r#"{"version":"0.9.0-alpha"}"#, true)?;
    cleanup.started = true;

    let outcome = mxc_sdk::sandbox::exec_attached(
        &cleanup.id,
        r#"{
            "version": "0.9.0-alpha",
            "process": {
                "commandLine": "sh -c 'echo \"hello from wslc bash\"; sleep 3; echo \"hello again from wslc bash\"'",
                "timeout": 30000
            }
        }"#,
        true,
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
