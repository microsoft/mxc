// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use mxc_sdk::mxc_contract::dev::{
    parse_request, ContainmentProbeError, PhaseProbeError, ProvisionRequest, Request,
    RequestParseError,
};

#[test]
fn microvm_creation_requires_an_image_on_both_paths() {
    for operation in [
        r#""process":{"commandLine":"echo"}"#,
        r#""phase":"provision""#,
    ] {
        for settings in [
            "", r#","microvm":{}"#, r#","microvm":{"image":""}"#,
            r#","microvm":{"image":" "}"#, r#","microvm":{"image":"python:\n3.12"}"#,
            r#","microvm":{"image":"python:\u00003.12"}"#, r#","microvm":{"image":null}"#,
        ] {
            let json = format!(
                r#"{{"version":"1.1.0-alpha","containment":"microvm",{operation}{settings}}}"#
            );
            assert!(parse_request(&json).is_err(), "accepted {json}");
        }
        let json = format!(
            r#"{{"version":"1.1.0-alpha","containment":"microvm",{operation},"microvm":{{"image":"docker.io/library/python:3.12-alpine"}}}}"#
        );
        assert!(parse_request(&json).is_ok(), "rejected {json}");
    }
}

#[test]
fn microvm_registry_reference_cases_apply_to_both_creation_contracts() {
    let cases: Vec<serde_json::Value> =
        serde_json::from_str(include_str!("image_reference_cases.json")).unwrap();
    for case in cases {
        let image = case["image"].as_str().unwrap();
        let valid = case["valid"].as_bool().unwrap();
        for operation in ["create-and-run", "provision"] {
            let mut request = serde_json::json!({
                "version": "1.1.0-alpha",
                "containment": "microvm",
                "microvm": {"image": image}
            });
            if operation == "provision" {
                request["phase"] = serde_json::json!("provision");
            } else {
                request["process"] = serde_json::json!({"commandLine": "echo"});
            }
            assert_eq!(
                parse_request(&request.to_string()).is_ok(),
                valid,
                "{operation}: {image:?}"
            );
        }
    }
}

#[test]
fn microvm_long_image_references_preserve_the_registry_contract() {
    let dotted = "a.".repeat(512 * 1024);
    for (image, valid) in [
        (dotted.clone(), false),
        (format!("{dotted}/"), false),
        (format!("{dotted}/repo"), true),
        (format!("{dotted}/repo\n"), false),
    ] {
        for provision in [false, true] {
            let mut request = serde_json::json!({
                "version": "1.1.0-alpha",
                "containment": "microvm",
                "microvm": {"image": image}
            });
            if provision {
                request["phase"] = serde_json::json!("provision");
            } else {
                request["process"] = serde_json::json!({"commandLine": "echo"});
            }
            assert_eq!(parse_request(&request.to_string()).is_ok(), valid);
        }
    }
}

#[test]
fn existing_microvm_execution_cannot_select_an_image() {
    let json = r#"{
        "version":"1.1.0-alpha",
        "phase":"exec",
        "sandboxId":"microvm:0123456789abcdef0123456789abcdef",
        "process":{"commandLine":"echo"},
        "microvm":{"image":"docker.io/library/python:3.12-alpine"}
    }"#;
    assert!(parse_request(json).is_err());
}

#[test]
fn both_microvm_creation_contracts_preserve_optional_provision_presence() {
    for lifecycle in [false, true] {
        for (settings, present, memory) in [
            ("", false, None),
            (r#","provision":{}"#, true, None),
            (r#","provision":{"memoryMib":512}"#, true, Some(512)),
        ] {
            let operation = if lifecycle {
                r#""phase":"provision""#
            } else {
                r#""process":{"commandLine":"echo"}"#
            };
            let json = format!(r#"{{"version":"1.1.0-alpha","containment":"microvm",{operation},"microvm":{{"image":"docker.io/library/python:3.12-alpine"{settings}}}}}"#);
            let provision = match parse_request(&json).unwrap() {
                Request::OneShot(request) => request.microvm.into_option().unwrap().provision,
                Request::Provision(ProvisionRequest::MicroVm(request)) => request.microvm.provision,
                other => panic!("unexpected request {other:?}"),
            };
            assert_eq!(provision.as_ref().is_some(), present);
            assert_eq!(
                provision
                    .into_option()
                    .and_then(|config| config.memory_mib.into_option()),
                memory
            );
        }
    }
}

const ACI_GROUP: &str = "/subscriptions/51aca303-03da-4510-849d-d4f32d3f39ac/resourceGroups/tryme-01/providers/Microsoft.ContainerInstance/sandboxGroups/sbg-001";

fn aci_request(aci: serde_json::Value) -> serde_json::Value {
    serde_json::json!({
        "version": "1.1.0-alpha",
        "containment": "aci",
        "aci": aci,
        "process": {"commandLine": "echo"}
    })
}

#[test]
fn aci_creation_requires_a_sandbox_group_and_image() {
    let image = "mcr.microsoft.com/azurelinux/base/core:3.0";
    for aci in [
        serde_json::json!({}),
        serde_json::json!({"image": image}),
        serde_json::json!({"sandboxGroup": ACI_GROUP}),
        serde_json::json!({"sandboxGroup": ACI_GROUP, "image": ""}),
        serde_json::json!({"sandboxGroup": ACI_GROUP, "image": "python:3.12"}),
        serde_json::json!({"sandboxGroup": ACI_GROUP, "image": null}),
        serde_json::json!({"sandboxGroup": "", "image": image}),
        serde_json::json!({"sandboxGroup": "/subscriptions/x", "image": image}),
        serde_json::json!({"sandboxGroup": format!("{ACI_GROUP}/sandboxes/s"), "image": image}),
        serde_json::json!({"sandboxGroup": ACI_GROUP, "image": image, "location": "westus"}),
    ] {
        let request = aci_request(aci);
        assert!(parse_request(&request.to_string()).is_err(), "accepted {request}");
    }
    let request = aci_request(serde_json::json!({"sandboxGroup": ACI_GROUP, "image": image}));
    assert!(matches!(
        parse_request(&request.to_string()),
        Ok(Request::OneShot(_))
    ));
}

#[test]
fn aci_image_reference_cases_match_the_microvm_contract() {
    let cases: Vec<serde_json::Value> =
        serde_json::from_str(include_str!("image_reference_cases.json")).unwrap();
    for case in cases {
        let image = case["image"].as_str().unwrap();
        let request = aci_request(serde_json::json!({"sandboxGroup": ACI_GROUP, "image": image}));
        assert_eq!(
            parse_request(&request.to_string()).is_ok(),
            case["valid"].as_bool().unwrap(),
            "{image:?}"
        );
    }
}

#[test]
fn aci_section_is_required_exactly_when_containment_is_aci() {
    let section = serde_json::json!({
        "sandboxGroup": ACI_GROUP,
        "image": "mcr.microsoft.com/azurelinux/base/core:3.0"
    });
    let mut without_section = aci_request(section.clone());
    without_section.as_object_mut().unwrap().remove("aci");
    let error = parse_request(&without_section.to_string()).unwrap_err();
    assert!(error.to_string().contains("aci section"), "{error}");
    for containment in [Some("process"), Some("microvm"), None] {
        let mut request = aci_request(section.clone());
        match containment {
            Some(containment) => request["containment"] = serde_json::json!(containment),
            None => {
                request.as_object_mut().unwrap().remove("containment");
            }
        }
        assert!(parse_request(&request.to_string()).is_err(), "accepted {request}");
    }
}

#[test]
fn aci_creation_preserves_optional_provision_presence() {
    for (provision, present, cpu, memory_gb) in [
        (None, false, None, None),
        (Some(serde_json::json!({})), true, None, None),
        (Some(serde_json::json!({"cpu": 2})), true, Some(2), None),
        (Some(serde_json::json!({"memoryGb": 4})), true, None, Some(4)),
        (
            Some(serde_json::json!({"cpu": 1, "memoryGb": 2})),
            true,
            Some(1),
            Some(2),
        ),
    ] {
        let mut aci = serde_json::json!({
            "sandboxGroup": ACI_GROUP,
            "image": "mcr.microsoft.com/azurelinux/base/core:3.0"
        });
        if let Some(provision) = provision {
            aci["provision"] = provision;
        }
        let Request::OneShot(request) = parse_request(&aci_request(aci).to_string()).unwrap()
        else {
            panic!("expected a one-shot request");
        };
        let provision = request.aci.into_option().unwrap().provision;
        assert_eq!(provision.as_ref().is_some(), present);
        let provision = provision.into_option();
        assert_eq!(
            provision.as_ref().and_then(|p| p.cpu.as_ref().copied()),
            cpu
        );
        assert_eq!(
            provision.as_ref().and_then(|p| p.memory_gb.as_ref().copied()),
            memory_gb
        );
    }
    for provision in [
        serde_json::json!({"cpu": -1}),
        serde_json::json!({"cpu": "2"}),
        serde_json::json!({"cpu": null}),
        serde_json::json!({"memoryGb": 1.5}),
        serde_json::json!({"memoryMib": 512}),
    ] {
        let request = aci_request(serde_json::json!({
            "sandboxGroup": ACI_GROUP,
            "image": "mcr.microsoft.com/azurelinux/base/core:3.0",
            "provision": provision
        }));
        assert!(parse_request(&request.to_string()).is_err(), "accepted {request}");
    }
}

#[test]
fn aci_is_not_a_lifecycle_containment() {
    let json = serde_json::json!({
        "version": "1.1.0-alpha",
        "phase": "provision",
        "containment": "aci",
        "aci": {
            "sandboxGroup": ACI_GROUP,
            "image": "mcr.microsoft.com/azurelinux/base/core:3.0"
        }
    });
    assert!(matches!(
        parse_request(&json.to_string()).unwrap_err(),
        RequestParseError::Containment(ContainmentProbeError::UnsupportedContainment(_))
    ));
}

#[test]
fn no_phase_selects_one_shot_request() {
    let json = r#"{
        "version": "1.1.0-alpha",
        "process": {"commandLine": "echo"}
    }"#;

    assert!(matches!(parse_request(json).unwrap(), Request::OneShot(_)));
}

#[test]
fn isolation_session_one_shot_requires_network() {
    let json = r#"{
        "version": "1.1.0-alpha",
        "containment": "isolation_session",
        "process": {"commandLine": "echo"}
    }"#;

    let error = parse_request(json).unwrap_err();
    assert!(matches!(
        error,
        RequestParseError::InvalidCombination {
            contract: "one-shot",
            message,
        } if message.contains("network.egress.default=allow")
    ));
}

#[test]
fn isolation_session_one_shot_accepts_directional_network() {
    let json = r#"{
        "version": "1.1.0-alpha",
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
fn invalid_one_shot_root_returns_invalid_request() {
    let json = r#"{
        "version": "1.1.0-alpha"
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
        "version": "1.1.0-alpha",
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
                "version": "1.1.0-alpha",
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
        "version": "1.1.0-alpha",
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
        "version": "1.1.0-alpha",
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
            "version": "1.1.0-alpha",
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
fn provision_phase_with_windows_sandbox_containment_selects_windows_sandbox_provision_request() {
    let json = r#"{
            "version": "1.1.0-alpha",
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
            "version": "1.1.0-alpha",
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
            "version": "1.1.0-alpha",
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
        "version": "1.1.0-alpha",
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
        "version": "1.1.0-alpha",
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
        "version": "1.1.0-alpha",
        "phase": "exec",
        "sandboxId": "test123456",
        "process": {"commandLine": "echo"}
    }"#;

    assert!(matches!(parse_request(json).unwrap(), Request::Exec(_)));
}

#[test]
fn invalid_exec_phase_root_returns_invalid_request() {
    let json = r#"{
        "version": "1.1.0-alpha",
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
        "version": "1.1.0-alpha",
        "phase": "start",
        "sandboxId": "test123456"
    }"#;

    assert!(matches!(parse_request(json).unwrap(), Request::Start(_)));
}

#[test]
fn invalid_start_phase_root_returns_invalid_request() {
    let json = r#"{
        "version": "1.1.0-alpha",
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
        "version": "1.1.0-alpha",
        "phase": "stop",
        "sandboxId": "test123456"
    }"#;

    assert!(matches!(parse_request(json).unwrap(), Request::Stop(_)));
}

#[test]
fn invalid_stop_phase_root_returns_invalid_request() {
    let json = r#"{
        "version": "1.1.0-alpha",
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
