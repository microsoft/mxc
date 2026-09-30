// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use mxc_sdk::{Output, SandboxOutputMetadata, WaitOutcome};

#[test]
fn pass_through_options_remain_extensible() {
    let mut options = mxc_sdk::PolicyEnforcementOptions::default();
    options.mode = Some(mxc_sdk::PolicyEnforcementMode::PassThrough);
    let mxc_sdk::PolicyEnforcementOptions { mode, .. } = options;
    assert_eq!(mode, Some(mxc_sdk::PolicyEnforcementMode::PassThrough));
}

#[test]
fn legacy_output_literals_and_patterns_remain_valid() {
    let metadata = SandboxOutputMetadata {
        capture_denials: None,
        capture_denials_error: None,
    };
    let output = Output {
        outcome: WaitOutcome::Exited(0),
        warnings: Vec::new(),
        stdout: Vec::new(),
        stderr: Vec::new(),
        output_metadata: Some(metadata),
    };
    let Output {
        outcome,
        warnings,
        stdout,
        stderr,
        output_metadata,
    } = output;
    let SandboxOutputMetadata {
        capture_denials,
        capture_denials_error,
    } = output_metadata.unwrap();
    assert_eq!(outcome, WaitOutcome::Exited(0));
    assert!(warnings.is_empty() && stdout.is_empty() && stderr.is_empty());
    assert!(capture_denials.is_none() && capture_denials_error.is_none());
}
