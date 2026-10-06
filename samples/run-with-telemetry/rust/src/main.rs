// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Requests telemetry consent, then opts one transient run into telemetry.

use std::error::Error;
use std::io::{self, Write};
use std::process::Command;

use mxc_sdk::v1::telemetry::{self, ConsentDecision, ConsentPrompt};
use mxc_sdk::v1::{self, ContainerRequest, Containment, RunOptions, TelemetryConfig};

fn sample_command() -> &'static str {
    if cfg!(target_os = "windows") {
        "cmd.exe /d /s /c \"echo hello from telemetry\""
    } else {
        "sh -c \"printf 'hello from telemetry\\n'\""
    }
}

fn open_privacy_statement(url: &str) -> Result<(), String> {
    Command::new("rundll32.exe")
        .args(["url.dll,FileProtocolHandler", url])
        .spawn()
        .map(|_| ())
        .map_err(|error| format!("failed to open the privacy statement: {error}"))
}

fn present_consent(prompt: &ConsentPrompt) -> Result<ConsentDecision, String> {
    println!("{}", prompt.title.text);
    println!();
    println!("{}", prompt.body.text);
    println!();
    println!(
        "{}: {}",
        prompt.learn_more_label.text, prompt.learn_more_url
    );

    loop {
        print!(
            "{} [y], {} [n], {} [l]: ",
            prompt.affirmative_label.text, prompt.negative_label.text, prompt.learn_more_label.text
        );
        io::stdout().flush().map_err(|error| error.to_string())?;

        let mut response = String::new();
        if io::stdin()
            .read_line(&mut response)
            .map_err(|error| error.to_string())?
            == 0
        {
            return Ok(ConsentDecision::Dismissed);
        }

        match response.trim().to_ascii_lowercase().as_str() {
            "y" | "yes" => return Ok(ConsentDecision::Yes),
            "n" | "no" => return Ok(ConsentDecision::No),
            "l" => open_privacy_statement(prompt.learn_more_url)?,
            _ => eprintln!("Enter y, n, or l."),
        }
    }
}

fn run() -> Result<(), Box<dyn Error>> {
    let support = v1::platform_support();
    if !support.is_supported {
        return Err(io::Error::other(
            support
                .reason
                .unwrap_or_else(|| "MXC is not supported on this host".to_string()),
        )
        .into());
    }

    if telemetry::needs_consent_prompt() {
        let outcome = telemetry::request_consent(Some("en-US"), present_consent)?;
        eprintln!("telemetry consent result: {}", outcome.result.as_str());
    }

    let consent = telemetry::get_consent();
    if !consent.allows_collection() {
        eprintln!(
            "telemetry is not authorized ({}) and will remain off",
            consent.as_str()
        );
    }

    let request = ContainerRequest {
        containment: Containment::Process,
        timeout_ms: Some(30_000),
        ..ContainerRequest::new(sample_command())
    };

    // This opts only this invocation into optional diagnostic telemetry. In a
    // Microsoft telemetry-routed build, authorized diagnostics may be sent to
    // Microsoft. Commands, output, credentials, and customer content are excluded.
    let options = RunOptions {
        telemetry: Some(TelemetryConfig {
            enabled: Some(true),
        }),
        ..Default::default()
    };
    v1::run(request, options)?;
    Ok(())
}

fn main() {
    match run() {
        Ok(()) => {}
        Err(error) => {
            eprintln!("MXC error: {error}");
            std::process::exit(1);
        }
    }
}
