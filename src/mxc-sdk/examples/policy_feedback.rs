// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use mxc_sdk::v1::{
    dev::{self, JsonOptions, PolicyFailureResult, PolicyFailures},
    Error, ExecutionResult, WaitResult,
};
use std::io::Write;

fn run_with_feedback(
    config: &str,
    feedback: &mut Option<PolicyFailures>,
) -> Result<ExecutionResult, Error> {
    let mut remaining = 8; // Application retry budget, including the first call.
    loop {
        remaining -= 1;
        let mut options = JsonOptions::default();
        options.policy_failures = feedback.as_ref();
        match dev::run_json(config, options) {
            Ok(output) => return Ok(output),
            Err(error) => {
                let Some(next) = PolicyFailures::from_error(&error)? else {
                    return Err(error);
                };
                let progress = feedback.as_ref() != Some(&next);
                let blocked = next
                    .results
                    .last()
                    .is_some_and(|result| result.outcome == PolicyFailureResult::OUTCOME_BLOCKED);
                let terminal = error
                    .details
                    .as_deref()
                    .is_some_and(|details| details.get("policyFeedbackError").is_some());
                let policy_refusal = error.operation.as_deref()
                    == Some("CreateProcessSecurityEnvironment")
                    && error.native_code.as_deref()
                        == Some(PolicyFailures::NATIVE_CODE_POLICY_BLOCKED);
                *feedback = Some(next); // Replace with the complete cumulative value.
                if remaining == 0 || !progress || !blocked || terminal || !policy_refusal {
                    return Err(error);
                }
            }
        }
    }
}

fn execute() -> Result<i32, Box<dyn std::error::Error>> {
    let args: Vec<_> = std::env::args_os().collect();
    if args.len() != 3 {
        return Err("Usage: policy_feedback <config.json> <feedback.json>".into());
    }
    let config = std::fs::read_to_string(&args[1])?;
    let mut feedback = match std::fs::read_to_string(&args[2]) {
        Ok(json) => Some(PolicyFailures::from_json(&json)?),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
        Err(error) => return Err(error.into()),
    };
    let result = run_with_feedback(&config, &mut feedback);
    if let Some(feedback) = feedback {
        std::fs::write(&args[2], feedback.to_json()?)?;
    }
    let output = result?;
    std::io::stdout().write_all(&output.stdout)?;
    std::io::stderr().write_all(&output.stderr)?;
    std::io::stdout().flush()?;
    std::io::stderr().flush()?;
    Ok(match output.outcome {
        WaitResult::Exited(code) => code,
        WaitResult::TimedOut => 124,
    })
}

fn main() {
    let code = match execute() {
        Ok(code) => code,
        Err(error) => {
            // Display retains the generic message/status, not structured policy data.
            eprintln!("{error}");
            1
        }
    };
    std::process::exit(code);
}
