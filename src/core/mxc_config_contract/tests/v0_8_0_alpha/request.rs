// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use mxc_config_contract::dev::{
    parse_request, ContainmentProbeError, PhaseProbeError, ProvisionRequest, Request,
    RequestParseError,
};

#[test]
fn no_phase_selects_one_shot_request() {
    let json = r#"{
        "version": "0.8.0-alpha",
        "process": {"commandLine": "echo"}
    }"#;

    assert!(matches!(parse_request(json).unwrap(), Request::OneShot(_)));
}

#[test]
fn invalid_one_shot_root_returns_invalid_request() {
    let json = r#"{
        "version": "0.8.0-alpha"
    }"#;

    assert!(matches!(
        parse_request(json).unwrap_err(),
        RequestParseError::InvalidRequest {
            contract: "one-shot",
            ..
        }
    ));
}

#[test]
fn unknown_phase_returns_phase_error() {
    let json = r#"{
        "version": "0.8.0-alpha",
        "phase": "restart"
    }"#;

    assert!(matches!(
        parse_request(json).unwrap_err(),
        RequestParseError::Phase(PhaseProbeError::UnsupportedPhase(phase))
            if phase == "restart"
    ));
}

#[test]
fn non_string_phase_returns_phase_error() {
    for phase in ["42", "true", "{}", "[]"] {
        let json = format!(
            r#"{{
                "version": "0.8.0-alpha",
                "phase": {phase},
                "containment": "wslc"
            }}"#
        );
        assert!(matches!(
            parse_request(json.as_str()).unwrap_err(),
            RequestParseError::Phase(PhaseProbeError::InvalidDeclaration(_))
        ));
    }
}

#[test]
fn missing_provision_containment_returns_containment_error() {
    let json = r#"{
        "version": "0.8.0-alpha",
        "phase": "provision"
    }"#;

    assert!(matches!(
        parse_request(json).unwrap_err(),
        RequestParseError::Containment(ContainmentProbeError::InvalidDeclaration(_))
    ));
}

#[test]
fn unsupported_provision_containment_returns_containment_error() {
    let json = r#"{
        "version": "0.8.0-alpha",
        "phase": "provision",
        "containment": "somevalue"
    }"#;

    assert!(matches!(
        parse_request(json).unwrap_err(),
        RequestParseError::Containment(ContainmentProbeError::UnsupportedContainment(_))
    ));
}

#[test]
fn provision_phase_with_isolation_session_containment_selects_isolation_session_provision_request()
{
    let json = r#"{
            "version": "0.8.0-alpha",
            "phase": "provision",
            "containment": "isolation_session",
            "network": {
                "defaultPolicy": "allow",
                "allowLocalNetwork": true
            }
    }"#;

    assert!(matches!(
        parse_request(json).unwrap(),
        Request::Provision(ProvisionRequest::IsolationSession(_))
    ));
}

#[test]
fn provision_phase_with_windows_sandbox_containment_selects_windows_sandbox_provision_request() {
    let json = r#"{
            "version": "0.8.0-alpha",
            "phase": "provision",
            "containment": "windows_sandbox"
    }"#;

    assert!(matches!(
        parse_request(json).unwrap(),
        Request::Provision(ProvisionRequest::WindowsSandbox(_))
    ));
}

#[test]
fn provision_phase_with_wslc_containment_selects_wslc_provision_request() {
    let json = r#"{
            "version": "0.8.0-alpha",
            "phase": "provision",
            "containment": "wslc"
    }"#;

    assert!(matches!(
        parse_request(json).unwrap(),
        Request::Provision(ProvisionRequest::Wslc(_))
    ));
}

#[test]
fn invalid_provision_phase_isolation_session_root_returns_invalid_request() {
    let json = r#"{
            "version": "0.8.0-alpha",
            "phase": "provision",
            "containment": "isolation_session"
    }"#;

    assert!(matches!(
        parse_request(json).unwrap_err(),
        RequestParseError::InvalidRequest {
            contract: "IsolationSession provision",
            ..
        }
    ));
}

#[test]
fn deprovision_phase_selects_deprovision_request() {
    let json = r#"{
        "version": "0.8.0-alpha",
        "phase": "deprovision",
        "sandboxId": "test123456"
    }"#;

    assert!(matches!(
        parse_request(json).unwrap(),
        Request::Deprovision(_)
    ));
}

#[test]
fn invalid_deprovision_phase_root_returns_invalid_request() {
    let json = r#"{
        "version": "0.8.0-alpha",
        "phase": "deprovision"
    }"#;

    assert!(matches!(
        parse_request(json).unwrap_err(),
        RequestParseError::InvalidRequest {
            contract: "deprovision",
            ..
        }
    ));
}

#[test]
fn exec_phase_selects_exec_request() {
    let json = r#"{
        "version": "0.8.0-alpha",
        "phase": "exec",
        "sandboxId": "test123456",
        "process": {"commandLine": "echo"}
    }"#;

    assert!(matches!(parse_request(json).unwrap(), Request::Exec(_)));
}

#[test]
fn invalid_exec_phase_root_returns_invalid_request() {
    let json = r#"{
        "version": "0.8.0-alpha",
        "phase": "exec",
        "sandboxId": "test123456"
    }"#;

    assert!(matches!(
        parse_request(json).unwrap_err(),
        RequestParseError::InvalidRequest {
            contract: "exec",
            ..
        }
    ));
}

#[test]
fn start_phase_selects_start_request() {
    let json = r#"{
        "version": "0.8.0-alpha",
        "phase": "start",
        "sandboxId": "test123456"
    }"#;

    assert!(matches!(parse_request(json).unwrap(), Request::Start(_)));
}

#[test]
fn invalid_start_phase_root_returns_invalid_request() {
    let json = r#"{
        "version": "0.8.0-alpha",
        "phase": "start"
    }"#;

    assert!(matches!(
        parse_request(json).unwrap_err(),
        RequestParseError::InvalidRequest {
            contract: "start",
            ..
        }
    ));
}

#[test]
fn stop_phase_selects_stop_request() {
    let json = r#"{
        "version": "0.8.0-alpha",
        "phase": "stop",
        "sandboxId": "test123456"
    }"#;

    assert!(matches!(parse_request(json).unwrap(), Request::Stop(_)));
}

#[test]
fn invalid_stop_phase_root_returns_invalid_request() {
    let json = r#"{
        "version": "0.8.0-alpha",
        "phase": "stop"
    }"#;

    assert!(matches!(
        parse_request(json).unwrap_err(),
        RequestParseError::InvalidRequest {
            contract: "stop",
            ..
        }
    ));
}
