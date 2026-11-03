// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use mxc_sdk::mxc_contract::published::v1_0_0::{
    parse_request, ContainmentProbeError, PhaseProbeError, ProvisionRequest, Request,
    RequestParseError,
};

#[test]
fn no_phase_selects_one_shot_request() {
    let json = r#"{
        "version": "1.0.0",
        "process": {"commandLine": "echo"}
    }"#;

    assert!(matches!(parse_request(json).unwrap(), Request::OneShot(_)));
}

#[test]
fn denied_paths_override_readonly_and_readwrite_grants() {
    use mxc_sdk::mxc_common::config_parser::load_mxc_request_from_json;
    use mxc_sdk::mxc_common::logger::{Logger, Mode};
    use mxc_sdk::mxc_common::state_aware_request::MxcRequest;
    use std::path::Path;

    // Existing sibling fixture directories avoid host-specific existence warnings.
    let fixtures = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("mxc_contract")
        .join("v1_0_0")
        .join("fixtures");
    let [denied, readonly, readwrite] =
        ["one_shot", "start", "exec"].map(|name| fixtures.join(name).display().to_string());

    for (name, deny_readonly, deny_readwrite) in [
        ("deny vs readonly", true, false),
        ("deny vs readwrite", false, true),
        ("deny vs both allow lists", true, true),
    ] {
        let mut readonly_paths = vec![readonly.clone()];
        let mut readwrite_paths = vec![readwrite.clone()];
        if deny_readonly {
            readonly_paths.push(denied.clone());
        }
        if deny_readwrite {
            readwrite_paths.push(denied.clone());
        }
        let json = serde_json::json!({
            "version": "1.0.0",
            "process": {"commandLine": "echo"},
            "filesystem": {
                "readonlyPaths": readonly_paths,
                "readwritePaths": readwrite_paths,
                "deniedPaths": [&denied]
            }
        });
        let parsed =
            load_mxc_request_from_json(&json.to_string(), &mut Logger::new(Mode::Buffer))
                .unwrap_or_else(|error| panic!("{name}: {error:?}"));
        let MxcRequest::OneShot(request) = parsed else {
            panic!("{name}: expected a create-and-run request");
        };

        assert_eq!(
            request.policy.readonly_paths,
            std::slice::from_ref(&readonly),
            "{name}"
        );
        assert_eq!(
            request.policy.readwrite_paths,
            std::slice::from_ref(&readwrite),
            "{name}"
        );
        assert_eq!(
            request.policy.denied_paths,
            std::slice::from_ref(&denied),
            "{name}"
        );
    }
}

#[test]
fn isolation_session_one_shot_accepts_canonical_directional_network() {
    let json = r#"{
        "version": "1.0.0",
        "containment": "isolation_session",
        "process": {"commandLine": "echo"},
        "network": {
            "egress": {"default": "allow"},
            "ingress": {"default": "allow", "hostLoopback": "allow"}
        }
    }"#;

    assert!(matches!(parse_request(json).unwrap(), Request::OneShot(_)));
}

#[test]
fn isolation_session_one_shot_rejects_missing_partial_mixed_and_proxied_networks() {
    for fields in [
        "",
        r#","network": {}"#,
        r#","network": {"egress": {"default": "allow"}}"#,
        r#","network": {"ingress": {"default": "allow", "hostLoopback": "allow"}}"#,
        r#","network": {
            "egress": {"default": "allow"},
            "ingress": {"default": "deny", "hostLoopback": "allow"}
        }"#,
        r#","network": {
            "egress": {"default": "allow", "allow": []},
            "ingress": {"default": "allow", "hostLoopback": "allow"}
        }"#,
        r#","network": {
            "egress": {"default": "allow"},
            "ingress": {"default": "allow", "hostLoopback": "allow"}
        },
        "runtimeConfig": {"networkProxy": "http://127.0.0.1:8080"}"#,
    ] {
        let json = format!(
            r#"{{
                "version": "1.0.0",
                "containment": "isolation_session",
                "process": {{"commandLine": "echo"}}
                {fields}
            }}"#
        );
        let error = parse_request(&json).unwrap_err();
        assert!(matches!(
            &error,
            RequestParseError::InvalidCombination {
                contract: "one-shot",
                ..
            }
        ));
        assert!(
            error
                .to_string()
                .contains("IsolationSession requires an explicit network policy"),
            "{fields}: {error}"
        );
    }
}

#[test]
fn invalid_one_shot_root_returns_invalid_request() {
    let json = r#"{
        "version": "1.0.0"
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
        "version": "1.0.0",
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
                "version": "1.0.0",
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
        "version": "1.0.0",
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
        "version": "1.0.0",
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
            "version": "1.0.0",
            "phase": "provision",
            "containment": "isolation_session",
            "network": {"egress":{"default":"allow"},"ingress":{"default":"allow","hostLoopback":"allow"}}
    }"#;

    assert!(matches!(
        parse_request(json).unwrap(),
        Request::Provision(ProvisionRequest::IsolationSession(_))
    ));
}

#[test]
fn provision_phase_rejects_windows_sandbox_containment() {
    let json = r#"{
            "version": "1.0.0",
            "phase": "provision",
            "containment": "windows_sandbox"
    }"#;

    assert!(parse_request(json).is_err());
}

#[test]
fn provision_phase_with_wslc_containment_selects_wslc_provision_request() {
    let json = r#"{
            "version": "1.0.0",
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
            "version": "1.0.0",
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
        "version": "1.0.0",
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
        "version": "1.0.0",
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
        "version": "1.0.0",
        "phase": "exec",
        "sandboxId": "test123456",
        "process": {"commandLine": "echo"}
    }"#;

    assert!(matches!(parse_request(json).unwrap(), Request::Exec(_)));
}

#[test]
fn invalid_exec_phase_root_returns_invalid_request() {
    let json = r#"{
        "version": "1.0.0",
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
        "version": "1.0.0",
        "phase": "start",
        "sandboxId": "test123456"
    }"#;

    assert!(matches!(parse_request(json).unwrap(), Request::Start(_)));
}

#[test]
fn invalid_start_phase_root_returns_invalid_request() {
    let json = r#"{
        "version": "1.0.0",
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
        "version": "1.0.0",
        "phase": "stop",
        "sandboxId": "test123456"
    }"#;

    assert!(matches!(parse_request(json).unwrap(), Request::Stop(_)));
}

#[test]
fn invalid_stop_phase_root_returns_invalid_request() {
    let json = r#"{
        "version": "1.0.0",
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
