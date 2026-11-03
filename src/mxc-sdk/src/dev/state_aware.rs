// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Exact-JSON execution and lifecycle operations for state-aware containers.

use crate::mxc_contract::dev::{probe_phase, Phase, PhaseProbeError};
use crate::mxc_engine::{Error, ErrorCode};
use crate::sandbox::{ExecutionResult, MxcProcess, MxcPtyProcess};

use super::{JsonOptions, PtyJsonOptions};

fn require_phase(json: &str, expected: Phase, operation: &str) -> Result<(), Error> {
    let declared = probe_phase(json).map_err(|error| {
        let message = match error {
            PhaseProbeError::InvalidDeclaration(source) => {
                format!("Invalid phase declaration: {source}")
            }
            PhaseProbeError::UnsupportedPhase(_) => "Unsupported phase".to_string(),
        };
        Error::new(ErrorCode::MalformedRequest, message)
    })?;
    match declared {
        Some(actual) if actual == expected => Ok(()),
        Some(actual) => Err(Error::new(
            ErrorCode::MalformedRequest,
            format!(
                "{operation} requires phase '{}', got '{}'",
                expected.as_str(),
                actual.as_str()
            ),
        )),
        None => Err(Error::new(
            ErrorCode::MalformedRequest,
            format!("{operation} requires phase '{}'", expected.as_str()),
        )),
    }
}

fn run_phase(
    json: &str,
    expected: Phase,
    operation: &str,
    dry_run: bool,
    options: JsonOptions,
) -> Result<String, Error> {
    require_phase(json, expected, operation)?;
    crate::__ffi::run_lifecycle_json(json, dry_run, options.experimental)
}

/// Capture an exec workload without taking ownership of its container.
pub fn run_in_container_json(json: &str, options: JsonOptions) -> Result<ExecutionResult, Error> {
    require_phase(json, Phase::Exec, "run_in_container_json")?;
    crate::wait_with_output(crate::__ffi::execute_lifecycle_json(
        json,
        options.experimental,
    )?)
}

/// Spawn an exec workload with live pipes; the caller owns the returned process.
pub fn spawn_in_container_json(json: &str, options: JsonOptions) -> Result<MxcProcess, Error> {
    require_phase(json, Phase::Exec, "spawn_in_container_json")?;
    crate::__ffi::execute_lifecycle_json(json, options.experimental)
}

/// Spawn an exec workload with a PTY; the caller owns the returned terminal.
pub fn spawn_in_container_with_pty_json(
    json: &str,
    options: PtyJsonOptions,
) -> Result<MxcPtyProcess, Error> {
    require_phase(json, Phase::Exec, "spawn_in_container_with_pty_json")?;
    crate::__ffi::spawn_in_container_with_pty_json(json, options.size, options.experimental)
}

/// Provision a container and return its complete native response JSON.
pub fn provision_container_json(json: &str, options: JsonOptions) -> Result<String, Error> {
    run_phase(
        json,
        Phase::Provision,
        "provision_container_json",
        false,
        options,
    )
}

/// Start a container and return its complete native response JSON.
pub fn start_container_json(json: &str, options: JsonOptions) -> Result<String, Error> {
    run_phase(json, Phase::Start, "start_container_json", false, options)
}

/// Stop a container and return its complete native response JSON.
pub fn stop_container_json(json: &str, options: JsonOptions) -> Result<String, Error> {
    run_phase(json, Phase::Stop, "stop_container_json", false, options)
}

/// Deprovision a container and return its complete native response JSON.
pub fn deprovision_container_json(json: &str, options: JsonOptions) -> Result<String, Error> {
    run_phase(
        json,
        Phase::Deprovision,
        "deprovision_container_json",
        false,
        options,
    )
}

/// Validate provision without allocating a container; return the complete response JSON.
pub fn validate_provision_json(json: &str, options: JsonOptions) -> Result<String, Error> {
    run_phase(
        json,
        Phase::Provision,
        "validate_provision_json",
        true,
        options,
    )
}

/// Validate start without starting a container; return the complete response JSON.
pub fn validate_start_json(json: &str, options: JsonOptions) -> Result<String, Error> {
    run_phase(json, Phase::Start, "validate_start_json", true, options)
}

/// Validate stop without stopping a container; return the complete response JSON.
pub fn validate_stop_json(json: &str, options: JsonOptions) -> Result<String, Error> {
    run_phase(json, Phase::Stop, "validate_stop_json", true, options)
}

/// Validate deprovision without releasing a container; return the complete response JSON.
pub fn validate_deprovision_json(json: &str, options: JsonOptions) -> Result<String, Error> {
    run_phase(
        json,
        Phase::Deprovision,
        "validate_deprovision_json",
        true,
        options,
    )
}

/// Validate an exec request without starting a workload; return the complete response JSON.
pub fn validate_process_json(json: &str, options: JsonOptions) -> Result<String, Error> {
    run_phase(json, Phase::Exec, "validate_process_json", true, options)
}

#[cfg(test)]
mod tests {
    use super::*;

    type JsonPhaseCall = fn(&str, JsonOptions) -> Result<String, Error>;

    #[test]
    fn phase_specific_calls_reject_a_different_phase_before_dispatch() {
        let start = r#"{"version":"1.0.0","phase":"start","sandboxId":"iso:unused"}"#;
        let stop = r#"{"version":"1.0.0","phase":"stop","sandboxId":"iso:unused"}"#;
        let options = JsonOptions::default();
        let calls: &[(&str, JsonPhaseCall)] = &[
            ("provision_container_json", provision_container_json),
            ("stop_container_json", stop_container_json),
            ("deprovision_container_json", deprovision_container_json),
            ("validate_provision_json", validate_provision_json),
            ("validate_stop_json", validate_stop_json),
            ("validate_deprovision_json", validate_deprovision_json),
            ("validate_process_json", validate_process_json),
        ];
        for (name, call) in calls {
            let error = call(start, options).unwrap_err();
            assert_eq!(error.code, ErrorCode::MalformedRequest, "{name}");
            assert!(error.message.contains(name), "{error}");
        }
        for (name, call) in [
            (
                "start_container_json",
                start_container_json as JsonPhaseCall,
            ),
            ("validate_start_json", validate_start_json),
        ] {
            let error = call(stop, options).unwrap_err();
            assert_eq!(error.code, ErrorCode::MalformedRequest, "{name}");
            assert!(error.message.contains(name), "{error}");
        }

        for (name, error) in [
            (
                "run_in_container_json",
                run_in_container_json(start, options).err(),
            ),
            (
                "spawn_in_container_json",
                spawn_in_container_json(start, options).err(),
            ),
            (
                "spawn_in_container_with_pty_json",
                spawn_in_container_with_pty_json(start, PtyJsonOptions::default()).err(),
            ),
        ] {
            let error = error.expect("a non-exec phase must not start a workload");
            assert_eq!(error.code, ErrorCode::MalformedRequest, "{name}");
            assert!(error.message.contains(name), "{error}");
        }
    }

    #[test]
    fn phase_probe_rejects_missing_duplicate_and_invalid_phase() {
        for json in [
            r#"{"version":"1.0.0","process":{"commandLine":"echo hi"}}"#,
            r#"{"version":"1.0.0","phase":"start","phase":"stop"}"#,
            r#"{"version":"1.0.0","phase":null}"#,
            r#"{"version":"1.0.0","phase":"no-such-phase"}"#,
            "{ not json",
        ] {
            let error = start_container_json(json, JsonOptions::default()).unwrap_err();
            assert_eq!(error.code, ErrorCode::MalformedRequest, "{json}: {error}");
        }
    }

    #[test]
    fn matching_phase_is_still_checked_by_the_exact_contract() {
        for json in [
            r#"{"version":"999.0.0","phase":"start","sandboxId":"iso:unused"}"#,
            r#"{"version":"1.0.0","phase":"start","sandboxId":"iso:unused","extra":true}"#,
        ] {
            let error = validate_start_json(json, JsonOptions::default()).unwrap_err();
            assert_eq!(error.code, ErrorCode::MalformedRequest, "{json}: {error}");
        }
    }

    #[test]
    fn exec_paths_reach_native_backend_validation_without_launching() {
        let json = r#"{"version":"1.0.0","phase":"exec","sandboxId":"nosuchbackend:abc123","process":{"commandLine":"echo hi"}}"#;
        let options = JsonOptions::default();
        for error in [
            run_in_container_json(json, options).err(),
            spawn_in_container_json(json, options).err(),
            spawn_in_container_with_pty_json(json, PtyJsonOptions::default()).err(),
            validate_process_json(json, options).err(),
        ] {
            let error = error.expect("an unregistered backend must not run a workload");
            assert_eq!(error.code, ErrorCode::UnsupportedContainment, "{error}");
        }
    }

    #[test]
    fn dry_run_requires_separate_experimental_authorization() {
        let json =
            r#"{"version":"1.1.0-alpha","phase":"provision","containment":"windows_sandbox"}"#;
        let error = validate_provision_json(json, JsonOptions::default()).unwrap_err();
        assert_eq!(error.code, ErrorCode::BackendUnavailable);
        assert!(error.message.contains("experimental"), "{error}");

        if let Err(error) = validate_provision_json(json, JsonOptions { experimental: true }) {
            assert_ne!(error.code, ErrorCode::BackendUnavailable, "{error}");
        }
    }
}
