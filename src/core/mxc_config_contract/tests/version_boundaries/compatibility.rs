// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use mxc_config_contract::published::{
    v0_6_0_alpha::{Containment as V06Containment, Request as V06Request},
    v0_7_0_alpha::{Containment as V07Containment, Request as V07Request},
};
#[test]
fn appcontainer_containment_value_alias_remains_accepted_in_v07() {
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

    let v06_request: V06Request = serde_json::from_str(v06_json).unwrap();
    let v07_request: V07Request = serde_json::from_str(v07_json).unwrap();

    assert!(matches!(
        v06_request.containment.as_ref(),
        Some(V06Containment::ProcessContainer)
    ));

    assert!(matches!(
        v07_request.containment.as_ref(),
        Some(V07Containment::ProcessContainer)
    ));
}

#[test]
fn app_container_section_alias_remains_accepted_in_v07() {
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

    let v06_request: V06Request = serde_json::from_str(v06_json).unwrap();
    let v07_request: V07Request = serde_json::from_str(v07_json).unwrap();

    let v06_process_container = v06_request
        .process_container
        .as_ref()
        .expect("0.6 appContainer alias should populate process_container");

    let v07_process_container = v07_request
        .process_container
        .as_ref()
        .expect("0.7 appContainer alias should populate process_container");

    assert_eq!(v06_process_container.least_privilege.as_ref(), Some(&true));
    assert_eq!(v07_process_container.least_privilege.as_ref(), Some(&true));

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
}
