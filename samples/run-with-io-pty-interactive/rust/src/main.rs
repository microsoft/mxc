// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Connects the calling terminal to a transient contained shell.

use std::error::Error;
use std::io::{self, IsTerminal};
use std::thread;

use mxc_sdk::v1::policy::{
    NetworkAction, NetworkEgressPolicy, NetworkIngressPolicy, NetworkPolicy,
};
use mxc_sdk::v1::{self, ContainerRequest, Containment, WaitResult};

fn run() -> Result<i32, Box<dyn Error>> {
    if !io::stdin().is_terminal() || !io::stdout().is_terminal() {
        return Err(io::Error::other("run this sample from an interactive terminal").into());
    }

    let (command, containment, network) = if cfg!(target_os = "windows") {
        (
            "powershell.exe -NoLogo",
            Containment::IsolationSession,
            Some(NetworkPolicy {
                egress: Some(NetworkEgressPolicy {
                    default: Some(NetworkAction::Allow),
                    ..Default::default()
                }),
                ingress: Some(NetworkIngressPolicy {
                    default: Some(NetworkAction::Allow),
                    host_loopback: Some(NetworkAction::Allow),
                }),
                ..Default::default()
            }),
        )
    } else {
        ("sh", Containment::Process, None)
    };
    eprintln!("Starting a contained shell. Type `exit` to leave.");
    let request = ContainerRequest {
        containment,
        network,
        ..ContainerRequest::new(command)
    };
    let terminal = v1::spawn_with_pty(request, Default::default())?;
    let mut input = terminal.take_writer()?;
    let mut output = terminal.try_clone_reader()?;

    let _input_forwarder = thread::spawn(move || {
        let _ = io::copy(&mut io::stdin(), &mut input);
    });
    io::copy(&mut output, &mut io::stdout())?;

    let outcome = terminal.wait()?;
    for warning in terminal.warnings() {
        eprintln!("warning: {warning}");
    }

    Ok(match outcome {
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
