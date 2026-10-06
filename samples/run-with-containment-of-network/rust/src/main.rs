// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Runs a transient container with all directional network access denied.

use std::error::Error;
use std::io::{self, Write};
use std::net::{Ipv4Addr, TcpListener};
use std::thread;

use mxc_sdk::v1::policy::{
    NetworkAction, NetworkEgressPolicy, NetworkIngressPolicy, NetworkPolicy,
};
use mxc_sdk::v1::{self, ContainerRequest, Containment, WaitResult};

fn sample_command(port: u16) -> String {
    if cfg!(target_os = "windows") {
        format!(
            "powershell.exe -NoProfile -Command \"$curl = (Get-Command curl.exe -ErrorAction Stop).Source; & $curl --silent --fail --max-time 3 http://127.0.0.1:{port}/ *> $null; if ($LASTEXITCODE -eq 0) {{ Write-Error 'network access unexpectedly succeeded'; exit 1 }}; Write-Output 'network access blocked by policy'\""
        )
    } else {
        format!(
            "sh -c \"command -v curl >/dev/null || {{ echo 'curl is required' >&2; exit 2; }}; if curl --silent --fail --max-time 3 http://127.0.0.1:{port}/ >/dev/null 2>&1; then echo 'ERROR: network access unexpectedly succeeded' >&2; exit 1; fi; printf 'network access blocked by policy\\n'\""
        )
    }
}

fn run() -> Result<i32, Box<dyn Error>> {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))?;
    let port = listener.local_addr()?.port();
    thread::spawn(move || {
        if let Ok((mut stream, _)) = listener.accept() {
            let _ = stream.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK");
        }
    });

    let request = ContainerRequest {
        containment: Containment::Process,
        network: Some(NetworkPolicy {
            egress: Some(NetworkEgressPolicy {
                default: Some(NetworkAction::Deny),
                ..Default::default()
            }),
            ingress: Some(NetworkIngressPolicy {
                default: Some(NetworkAction::Deny),
                host_loopback: Some(NetworkAction::Deny),
            }),
            ..Default::default()
        }),
        timeout_ms: Some(30_000),
        ..ContainerRequest::new(sample_command(port))
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
