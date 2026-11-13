// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use mxc_sdk::v1::{
    dev::{self, JsonOptions, PolicyFailureResult, PolicyFailures, PreparedPolicyRequest},
    Error, ErrorCode, ExecutionResult, WaitResult,
};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

fn is_policy_refusal(error: &Error, current: &PolicyFailures) -> bool {
    error.operation.as_deref() == Some("CreateProcessSecurityEnvironment")
        && error.native_code.as_deref() == Some(PolicyFailures::NATIVE_CODE_POLICY_BLOCKED)
        && current
            .results
            .last()
            .is_some_and(|result| result.outcome == PolicyFailureResult::OUTCOME_BLOCKED)
        && error
            .details
            .as_deref()
            .is_none_or(|details| details.get("policyFeedbackError").is_none())
}

fn accepts(prepared: &PreparedPolicyRequest, approved: Option<&PreparedPolicyRequest>) -> bool {
    prepared.changes.is_empty() || approved == Some(prepared)
}

fn run_with_preparation(
    config: &str,
    failures: &mut Option<PolicyFailures>,
    mut decide: impl FnMut(&PreparedPolicyRequest) -> Result<bool, Box<dyn std::error::Error>>,
) -> Result<ExecutionResult, Box<dyn std::error::Error>> {
    let mut submitted = config.to_owned();
    if let Some(stored) = failures.as_ref() {
        let prepared = dev::prepare_policy_json(config, stored, Default::default())?;
        if !decide(&prepared)? {
            return Err(Error::new(
                ErrorCode::PolicyValidation,
                "Caller approval is required; inspect the candidate output file.",
            )
            .into());
        }
        submitted = prepared.request_json;
    }
    let mut remaining = 8; // Application retry budget, including the first call.
    loop {
        remaining -= 1;
        match dev::run_json(
            &submitted,
            JsonOptions {
                experimental: false,
            },
        ) {
            Ok(output) => return Ok(output),
            Err(error) => {
                let Some(current) = PolicyFailures::from_error(&error)? else {
                    return Err(error.into());
                };
                let prior = failures.as_ref().cloned().unwrap_or_default();
                let next = prior.merged_with(&current)?;
                let progress = next != prior;
                *failures = Some(next.clone());
                if remaining == 0 || !progress || !is_policy_refusal(&error, &current) {
                    return Err(error.into());
                }
                let prepared = dev::prepare_policy_json(config, &next, Default::default())?;
                if prepared.changes.is_empty()
                    || prepared.request_json == submitted
                    || !decide(&prepared)?
                {
                    return Err(error.into());
                }
                submitted = prepared.request_json;
            }
        }
    }
}

fn read_bounded(path: &Path, limit: usize) -> std::io::Result<String> {
    let mut json = String::new();
    std::fs::File::open(path)?
        .take((limit + 1) as u64)
        .read_to_string(&mut json)?;
    if json.len() > limit {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "input file exceeds its byte limit",
        ));
    }
    Ok(json)
}

fn artifact_path(path: &Path) -> std::io::Result<PathBuf> {
    if path.exists() {
        return path.canonicalize();
    }
    let absolute = if path.is_absolute() {
        path.to_owned()
    } else {
        std::env::current_dir()?.join(path)
    };
    let parent = absolute.parent().ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "output requires a parent directory",
        )
    })?;
    let name = absolute.file_name().ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "output requires a file name",
        )
    })?;
    Ok(parent.canonicalize()?.join(name))
}

fn execute() -> Result<i32, Box<dyn std::error::Error>> {
    let args: Vec<_> = std::env::args_os().collect();
    if !(4..=5).contains(&args.len()) {
        return Err(
            "Usage: policy_feedback <config.json> <policy-failures.json> <candidate.json> [<approved-candidate.json>]"
                .into(),
        );
    }
    let candidate_path = artifact_path(Path::new(&args[3]))?;
    for source in args[1..3].iter().chain(args.get(4)) {
        if artifact_path(Path::new(source))? == candidate_path {
            return Err(
                "The candidate output must be separate from inputs and approval storage.".into(),
            );
        }
    }
    let config = read_bounded(Path::new(&args[1]), 8 * 1024 * 1024)?;
    let mut failures = match read_bounded(Path::new(&args[2]), 4 * 1024 * 1024 + 512 * 1024) {
        Ok(json) => Some(PolicyFailures::from_json(&json)?),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
        Err(error) => return Err(error.into()),
    };
    let approved = args
        .get(4)
        .map(|path| {
            let json = read_bounded(Path::new(path), 32 * 1024 * 1024)?;
            PreparedPolicyRequest::from_json(&json).map_err(Box::<dyn std::error::Error>::from)
        })
        .transpose()?;
    let result = run_with_preparation(&config, &mut failures, |prepared| {
        std::fs::write(&candidate_path, prepared.to_json()?)?;
        Ok(accepts(prepared, approved.as_ref()))
    });
    if let Some(failures) = failures {
        std::fs::write(&args[2], failures.to_json()?)?;
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn caller_acceptance_requires_the_complete_reviewed_candidate() {
        let prepared = PreparedPolicyRequest::from_json(
            r#"{"requestJson":"{}","changes":[{"operation":"add","path":"/a","before":null,"after":true}]}"#,
        ).unwrap();
        assert!(!accepts(&prepared, None));
        assert!(accepts(&prepared, Some(&prepared)));
        let mut changed = prepared.clone();
        changed.request_json = "{\"different\":true}".into();
        assert!(!accepts(&changed, Some(&prepared)));
    }

    #[test]
    fn native_status_outcome_and_every_terminal_code_guard_preparation() {
        const E_ACCESSDENIED: &str = "0x80070005";
        let mut blocked = PolicyFailureResult::default();
        blocked.outcome = PolicyFailureResult::OUTCOME_BLOCKED;
        let mut current = PolicyFailures::default();
        current.results.push(blocked);
        let mut error = Error::new(ErrorCode::BackendError, "Policy refused creation.");
        error.operation = Some("CreateProcessSecurityEnvironment".into());
        error.native_code = Some(PolicyFailures::NATIVE_CODE_POLICY_BLOCKED.into());
        assert!(is_policy_refusal(&error, &current));
        error.operation = Some("CreateProcessW".into());
        assert!(!is_policy_refusal(&error, &current));
        error.operation = Some("CreateProcessSecurityEnvironment".into());
        error.native_code = Some(E_ACCESSDENIED.into());
        assert!(!is_policy_refusal(&error, &current));
        error.native_code = Some(PolicyFailures::NATIVE_CODE_POLICY_BLOCKED.into());
        error.details = Some(Box::new(serde_json::json!({
            "policyFeedbackError": { "code": "futureTerminalCode", "reason": "terminal" }
        })));
        assert!(!is_policy_refusal(&error, &current));
    }
}
