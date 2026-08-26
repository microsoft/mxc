// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use mxc_config_contract::dev::{
    OneShotContainment as V09Containment, OneShotRequest as V09Request,
};
use mxc_config_contract::published::{
    v0_6_0_alpha::{Containment as V06Containment, Request as V06Request},
    v0_7_0_alpha::{Containment as V07Containment, Request as V07Request},
    v0_8_0_alpha::{Containment as V08Containment, Request as V08Request},
};

#[test]
fn appcontainer_containment_value_alias_remains_accepted_across_registered_contracts() {
    let v06_json = r#"{
        "version": "0.6.0-alpha",
        "containment": "appcontainer",
        "process": {
            "commandLine": "echo"
        }
    }"#;

    let v07_json = r#"{
        "version": "0.7.0-alpha",
        "containment": "appcontainer",
        "process": {
            "commandLine": "echo"
        }
    }"#;

    let v08_json = r#"{
        "version": "0.8.0-alpha",
        "containment": "appcontainer",
        "process": {
            "commandLine": "echo"
        }
    }"#;

    let v09_json = r#"{
        "version": "0.9.0-alpha",
        "containment": "appcontainer",
        "process": {
            "commandLine": "echo"
        }
    }"#;

    let v06_request: V06Request = serde_json::from_str(v06_json).unwrap();
    let v07_request: V07Request = serde_json::from_str(v07_json).unwrap();
    let v08_request: V08Request = serde_json::from_str(v08_json).unwrap();
    let v09_request: V09Request = serde_json::from_str(v09_json).unwrap();

    assert!(matches!(
        v06_request.containment.as_ref(),
        Some(V06Containment::ProcessContainer)
    ));

    assert!(matches!(
        v07_request.containment.as_ref(),
        Some(V07Containment::ProcessContainer)
    ));

    assert!(matches!(
        v08_request.containment.as_ref(),
        Some(V08Containment::ProcessContainer)
    ));

    assert!(matches!(
        v09_request.containment.as_ref(),
        Some(V09Containment::ProcessContainer)
    ));
}

#[test]
fn app_container_section_alias_remains_accepted_across_registered_contracts() {
    let v06_json = r#"{
        "version": "0.6.0-alpha",
        "containment": "process",
        "appContainer": {
            "leastPrivilege": true,
            "capabilities": [
                "internetClient"
            ]
        },
        "process": {
            "commandLine": "echo"
        }
    }"#;

    let v07_json = r#"{
        "version": "0.7.0-alpha",
        "containment": "process",
        "appContainer": {
            "leastPrivilege": true,
            "capabilities": [
                "internetClient"
            ]
        },
        "process": {
            "commandLine": "echo"
        }
    }"#;

    let v08_json = r#"{
        "version": "0.8.0-alpha",
        "containment": "process",
        "appContainer": {
            "leastPrivilege": true,
            "capabilities": [
                "internetClient"
            ]
        },
        "process": {
            "commandLine": "echo"
        }
    }"#;

    let v09_json = r#"{
        "version": "0.9.0-alpha",
        "containment": "process",
        "appContainer": {
            "leastPrivilege": true,
            "capabilities": [
                "internetClient"
            ]
        },
        "process": {
            "commandLine": "echo"
        }
    }"#;

    let v06_request: V06Request = serde_json::from_str(v06_json).unwrap();
    let v07_request: V07Request = serde_json::from_str(v07_json).unwrap();
    let v08_request: V08Request = serde_json::from_str(v08_json).unwrap();
    let v09_request: V09Request = serde_json::from_str(v09_json).unwrap();

    let v06_process_container = v06_request
        .process_container
        .as_ref()
        .expect("0.6 appContainer alias should populate process_container");

    let v07_process_container = v07_request
        .process_container
        .as_ref()
        .expect("0.7 appContainer alias should populate process_container");

    let v08_process_container = v08_request
        .process_container
        .as_ref()
        .expect("0.8 appContainer alias should populate process_container");

    let v09_process_container = v09_request
        .process_container
        .as_ref()
        .expect("0.9 appContainer alias should populate process_container");

    assert_eq!(v06_process_container.least_privilege.as_ref(), Some(&true));
    assert_eq!(v07_process_container.least_privilege.as_ref(), Some(&true));
    assert_eq!(v08_process_container.least_privilege.as_ref(), Some(&true));
    assert_eq!(v09_process_container.least_privilege.as_ref(), Some(&true));

    assert_eq!(
        v06_process_container
            .capabilities
            .as_ref()
            .expect("0.6 capabilities"),
        &vec!["internetClient".to_string()]
    );
    assert_eq!(
        v07_process_container
            .capabilities
            .as_ref()
            .expect("0.7 capabilities"),
        &vec!["internetClient".to_string()]
    );
    assert_eq!(
        v08_process_container
            .capabilities
            .as_ref()
            .expect("0.8 capabilities")
            .iter()
            .map(mxc_config_contract::published::v0_8_0_alpha::ProcessContainerCapability::as_str,)
            .collect::<Vec<_>>(),
        vec!["internetClient"]
    );
    assert_eq!(
        v09_process_container
            .capabilities
            .as_ref()
            .expect("0.9 capabilities")
            .iter()
            .map(mxc_config_contract::dev::ProcessContainerCapability::as_str)
            .collect::<Vec<_>>(),
        vec!["internetClient"]
    );
}

#[test]
fn macos_sandbox_containment_value_alias_remains_accepted_from_v07() {
    let v07_json = r#"{
        "version": "0.7.0-alpha",
        "containment": "macos_sandbox",
        "process": {"commandLine": "echo"}
    }"#;

    let v08_json = r#"{
        "version": "0.8.0-alpha",
        "containment": "macos_sandbox",
        "process": {"commandLine": "echo"}
    }"#;

    let v09_json = r#"{
        "version": "0.9.0-alpha",
        "containment": "macos_sandbox",
        "process": {"commandLine": "echo"}
    }"#;

    let v07_request: V07Request = serde_json::from_str(v07_json).unwrap();
    let v08_request: V08Request = serde_json::from_str(v08_json).unwrap();
    let v09_request: V09Request = serde_json::from_str(v09_json).unwrap();

    assert!(matches!(
        v07_request.containment.as_ref(),
        Some(V07Containment::Seatbelt)
    ));
    assert!(matches!(
        v08_request.containment.as_ref(),
        Some(V08Containment::Seatbelt)
    ));
    assert!(matches!(
        v09_request.containment.as_ref(),
        Some(V09Containment::Seatbelt)
    ));
}

#[test]
fn macos_sandbox_section_alias_remains_accepted_from_v07() {
    let v07_json = r#"{
        "version": "0.7.0-alpha",
        "macos_sandbox": {},
        "process": {"commandLine": "echo"}
    }"#;

    let v08_json = r#"{
        "version": "0.8.0-alpha",
        "macos_sandbox": {},
        "process": {"commandLine": "echo"}
    }"#;

    let v09_json = r#"{
        "version": "0.9.0-alpha",
        "macos_sandbox": {},
        "process": {"commandLine": "echo"}
    }"#;

    let v07_request: V07Request = serde_json::from_str(v07_json).unwrap();
    let v08_request: V08Request = serde_json::from_str(v08_json).unwrap();
    let v09_request: V09Request = serde_json::from_str(v09_json).unwrap();

    assert!(v07_request.seatbelt.as_ref().is_some());
    assert!(v08_request.seatbelt.as_ref().is_some());
    assert!(v09_request.seatbelt.as_ref().is_some());
}
