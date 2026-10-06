// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Runs a transient container while forwarding stdout and stderr.

use std::error::Error;
use std::io::{self, BufRead, BufReader, Read};
use std::thread;

use mxc_sdk::v1::{self, ContainerRequest, WaitResult};

fn sample_command() -> &'static str {
    if cfg!(target_os = "windows") {
        "powershell.exe -NoProfile -NonInteractive -Command \
         \"Write-Output first; Start-Sleep -Milliseconds 750; Write-Output second\""
    } else {
        "sh -c \"printf 'first\\n'; sleep 1; printf 'second\\n'\""
    }
}

fn forward_lines(
    stream: Box<dyn Read + Send>,
    prefix: &'static str,
) -> thread::JoinHandle<io::Result<()>> {
    thread::spawn(move || {
        for line in BufReader::new(stream).lines() {
            let line = line?;
            if prefix.is_empty() {
                println!("{line}");
            } else {
                eprintln!("{prefix}{line}");
            }
        }
        Ok(())
    })
}

fn join_reader(reader: thread::JoinHandle<io::Result<()>>) -> Result<(), Box<dyn Error>> {
    reader
        .join()
        .map_err(|_| io::Error::other("output reader thread panicked"))??;
    Ok(())
}

fn run() -> Result<i32, Box<dyn Error>> {
    let mut request = ContainerRequest::new(sample_command());
    request.timeout_ms = Some(30_000);

    let mut process = v1::spawn(request, Default::default())?;
    let stdout = process
        .take_stdout()
        .ok_or_else(|| io::Error::other("the selected backend did not provide stdout"))?;
    let stderr = process
        .take_stderr()
        .ok_or_else(|| io::Error::other("the selected backend did not provide stderr"))?;
    let stdout_reader = forward_lines(stdout, "");
    let stderr_reader = forward_lines(stderr, "stderr: ");

    let outcome = process.wait()?;
    join_reader(stdout_reader)?;
    join_reader(stderr_reader)?;

    for warning in process.warnings() {
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
