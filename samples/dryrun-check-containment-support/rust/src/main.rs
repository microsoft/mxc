// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use std::error::Error;

use mxc_sdk::v1;
#[cfg(target_os = "windows")]
use mxc_sdk::v1::ContainerRequest;

fn run() -> Result<i32, Box<dyn Error>> {
    let support = v1::platform_support();
    println!("platform supported: {}", support.is_supported);
    if let Some(reason) = &support.reason {
        println!("reason: {reason}");
    }

    let backends = v1::available_backends();
    if backends.is_empty() {
        println!("no containment backends are currently available");
    }
    for backend in backends {
        println!("backend: {}", backend.backend);
        if !backend.capabilities.is_empty() {
            println!("  capabilities: {:?}", backend.capabilities);
        }
        for warning in backend.warnings {
            println!("  warning: {warning}");
        }
    }

    #[cfg(target_os = "windows")]
    {
        let request = ContainerRequest::new("cmd.exe /d /s /c \"echo support check only\"");
        let probe = v1::probe(Some(&request))?;
        for warning in probe.warnings {
            println!("probe warning: {warning}");
        }
        if let Some(error) = probe.error {
            eprintln!("probe error: {error}");
            return Ok(1);
        }
    }

    Ok(if support.is_supported { 0 } else { 1 })
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
