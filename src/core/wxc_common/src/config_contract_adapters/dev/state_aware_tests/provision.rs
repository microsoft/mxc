// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use super::super::{contract, provision_into_wire, wire};

const MINIMAL_ISOLATION_SESSION_REQUEST_JSON: &str = r#"{
    "version": "0.8.0-alpha",
    "phase": "provision",
    "containment": "isolation_session",
    "network": {
        "allowLocalNetwork": true,
        "defaultPolicy": "allow"
    }
}"#;

const ISOLATION_SESSION_ALL_FIELDS_REQUEST_JSON: &str = r#"{
    "$schema": "https://example.com/provision.schema.json",
    "_comment": "This is a comment",
    "version": "0.8.0-alpha",
    "phase": "provision",
    "containment": "isolation_session",
    "network": {
        "allowLocalNetwork": true,
        "defaultPolicy": "allow"
    },
    "experimental": {
        "isolation_session": {
            "provision": {
                "appId": "someAppId"
            }
        },
        "telemetry": {
            "enabled": false
        }
    }
}"#;

const MINIMAL_WINDOWS_SANDBOX_REQUEST_JSON: &str = r#"{
    "version": "0.8.0-alpha",
    "phase": "provision",
    "containment": "windows_sandbox"
}"#;

const WINDOWS_SANDBOX_ALL_FIELDS_REQUEST_JSON: &str = r#"{
    "$schema": "https://example.com/provision.schema.json",
    "_comment": "This is a comment",
    "version": "0.8.0-alpha",
    "phase": "provision",
    "containment": "windows_sandbox",
    "filesystem": {
        "readonlyPaths": ["C:\\Windows\\System32"],
        "readwritePaths": ["C:\\Users\\User\\Documents"],
        "deniedPaths": ["C:\\Users\\User\\Music"]
    },
    "experimental": {
        "telemetry": {
            "enabled": false
        }
    }
}"#;

const MINIMAL_WSLC_REQUEST_JSON: &str = r#"{
    "version": "0.8.0-alpha",
    "phase": "provision",
    "containment": "wslc"
}"#;

const WSLC_ALL_FIELDS_REQUEST_JSON: &str = r#"{
    "$schema": "https://example.com/provision.schema.json",
    "_comment": "This is a comment",
    "version": "0.8.0-alpha",
    "phase": "provision",
    "containment": "wslc",
    "filesystem": {
        "readonlyPaths": ["/usr/bin"],
        "readwritePaths": ["/home/user/documents"],
        "deniedPaths": ["/home/user/music"]
    },
    "network": {
        "allowLocalNetwork": false,
        "defaultPolicy": "block",
        "enforcementMode": "firewall",
        "allowedHosts": ["example.com"],
        "blockedHosts": ["blocked.example.com"],
        "proxy": {
            "url": "http://example.com/proxy"
        }
    },
    "experimental": {
        "wslc": {
            "provision": {
                "image": "someImage",
                "imageTarPath": "someImageTarPath"
            }
        },
        "telemetry": {
            "enabled": false
        }
    }
}"#;

pub(super) fn adapt(json: &str) -> wire::MxcConfig {
    let request = contract::parse_request(json).unwrap();

    let contract::Request::Provision(request) = request else {
        panic!("expected a ProvisionRequest");
    };
    provision_into_wire(request)
}

fn isolation_session_request_with_fields(fields: &str) -> String {
    format!(
        r#"{{
            "version": "0.8.0-alpha",
            "phase": "provision",
            "containment": "isolation_session",
            "network": {{
                "allowLocalNetwork": true,
                "defaultPolicy": "allow"
            }},
            {fields}
        }}"#
    )
}

fn windows_sandbox_request_with_fields(fields: &str) -> String {
    format!(
        r#"{{
            "version": "0.8.0-alpha",
            "phase": "provision",
            "containment": "windows_sandbox",
            {fields}
        }}"#
    )
}

fn wslc_request_with_fields(fields: &str) -> String {
    format!(
        r#"{{
            "version": "0.8.0-alpha",
            "phase": "provision",
            "containment": "wslc",
            {fields}
        }}"#
    )
}

#[test]
fn minimal_isolation_session_request_maps_expected_wire_fields() {
    let json = MINIMAL_ISOLATION_SESSION_REQUEST_JSON;

    let wire = adapt(json);

    assert!(wire.schema.is_none());
    assert!(wire.comment.is_none());
    assert_eq!(wire.version, Some("0.8.0-alpha".to_string()));
    assert!(matches!(wire.phase, Some(wire::Phase::Provision)));
    assert!(matches!(
        wire.containment,
        Some(wire::Containment::IsolationSession)
    ));

    let network = wire.network.expect("network should be present");
    assert_eq!(network.allow_local_network, Some(true));
    assert!(matches!(
        network.default_policy,
        Some(wire::NetworkPolicy::Allow)
    ));
    assert!(network.enforcement_mode.is_none());
    assert!(network.allowed_hosts.is_none());
    assert!(network.blocked_hosts.is_none());

    assert!(wire.sandbox_id.is_none());
    assert!(wire.correlation_vector.is_none());
    assert!(wire.container_id.is_none());
    assert!(wire.process.is_none());
    assert!(wire.lifecycle.is_none());
    assert!(wire.process_container.is_none());
    assert!(wire.lxc.is_none());
    assert!(wire.filesystem.is_none());
    assert!(wire.fallback.is_none());
    assert!(wire.ui.is_none());
    assert!(wire.seatbelt.is_none());
    assert!(wire.experimental.is_none());
}

#[test]
fn isolation_session_request_maps_expected_wire_fields() {
    let json = ISOLATION_SESSION_ALL_FIELDS_REQUEST_JSON;

    let wire = adapt(json);

    assert_eq!(
        wire.schema,
        Some("https://example.com/provision.schema.json".to_string())
    );
    assert_eq!(
        wire.comment.as_ref(),
        Some(&serde_json::json!("This is a comment"))
    );
    assert_eq!(wire.version, Some("0.8.0-alpha".to_string()));
    assert!(matches!(wire.phase, Some(wire::Phase::Provision)));
    assert!(matches!(
        wire.containment,
        Some(wire::Containment::IsolationSession)
    ));
    let network = wire.network.expect("network should be present");
    assert_eq!(network.allow_local_network, Some(true));
    assert!(matches!(
        network.default_policy,
        Some(wire::NetworkPolicy::Allow)
    ));
    assert!(network.enforcement_mode.is_none());
    assert!(network.allowed_hosts.is_none());
    assert!(network.blocked_hosts.is_none());

    let experimental = wire.experimental.expect("experimental should be present");
    let isolation_session = experimental
        .isolation_session
        .expect("isolation_session should be present");
    let provision = isolation_session
        .provision
        .expect("provision should be present");
    assert_eq!(provision.app_id.as_deref(), Some("someAppId"));

    let telemetry = experimental.telemetry.expect("telemetry should be present");
    assert_eq!(telemetry.enabled, Some(false));

    assert!(experimental.test.is_none());
    assert!(experimental.wslc.is_none());
    assert!(experimental.windows_sandbox.is_none());
    assert!(experimental.seatbelt.is_none());

    assert!(wire.sandbox_id.is_none());
    assert!(wire.correlation_vector.is_none());
    assert!(wire.container_id.is_none());
    assert!(wire.process.is_none());
    assert!(wire.lifecycle.is_none());
    assert!(wire.process_container.is_none());
    assert!(wire.lxc.is_none());
    assert!(wire.filesystem.is_none());
    assert!(wire.fallback.is_none());
    assert!(wire.ui.is_none());
    assert!(wire.seatbelt.is_none());
}

#[test]
fn minimal_windows_sandbox_request_maps_expected_wire_fields() {
    let json = MINIMAL_WINDOWS_SANDBOX_REQUEST_JSON;

    let wire = adapt(json);

    assert!(wire.schema.is_none());
    assert!(wire.comment.is_none());
    assert_eq!(wire.version, Some("0.8.0-alpha".to_string()));
    assert!(matches!(wire.phase, Some(wire::Phase::Provision)));
    assert!(matches!(
        wire.containment,
        Some(wire::Containment::WindowsSandbox)
    ));

    assert!(wire.sandbox_id.is_none());
    assert!(wire.correlation_vector.is_none());
    assert!(wire.container_id.is_none());
    assert!(wire.process.is_none());
    assert!(wire.lifecycle.is_none());
    assert!(wire.network.is_none());
    assert!(wire.process_container.is_none());
    assert!(wire.lxc.is_none());
    assert!(wire.filesystem.is_none());
    assert!(wire.fallback.is_none());
    assert!(wire.ui.is_none());
    assert!(wire.seatbelt.is_none());
    assert!(wire.experimental.is_none());
}

#[test]
fn windows_sandbox_request_maps_expected_wire_fields() {
    let json = WINDOWS_SANDBOX_ALL_FIELDS_REQUEST_JSON;

    let wire = adapt(json);

    assert_eq!(
        wire.schema,
        Some("https://example.com/provision.schema.json".to_string())
    );
    assert_eq!(
        wire.comment.as_ref(),
        Some(&serde_json::json!("This is a comment"))
    );
    assert_eq!(wire.version, Some("0.8.0-alpha".to_string()));
    assert!(matches!(wire.phase, Some(wire::Phase::Provision)));
    assert!(matches!(
        wire.containment,
        Some(wire::Containment::WindowsSandbox)
    ));

    let filesystem = wire.filesystem.expect("filesystem should be populated");
    assert_eq!(
        filesystem.readonly_paths,
        Some(vec!["C:\\Windows\\System32".to_string()])
    );
    assert_eq!(
        filesystem.readwrite_paths,
        Some(vec!["C:\\Users\\User\\Documents".to_string()])
    );
    assert_eq!(
        filesystem.denied_paths,
        Some(vec!["C:\\Users\\User\\Music".to_string()])
    );

    let experimental = wire.experimental.expect("experimental should be populated");

    let telemetry = experimental
        .telemetry
        .expect("telemetry should be populated");
    assert_eq!(telemetry.enabled, Some(false));

    assert!(experimental.test.is_none());
    assert!(experimental.isolation_session.is_none());
    assert!(experimental.wslc.is_none());
    assert!(experimental.seatbelt.is_none());

    assert!(wire.sandbox_id.is_none());
    assert!(wire.correlation_vector.is_none());
    assert!(wire.container_id.is_none());
    assert!(wire.process.is_none());
    assert!(wire.lifecycle.is_none());
    assert!(wire.network.is_none());
    assert!(wire.process_container.is_none());
    assert!(wire.lxc.is_none());
    assert!(wire.fallback.is_none());
    assert!(wire.ui.is_none());
    assert!(wire.seatbelt.is_none());
}

#[test]
fn minimal_wslc_request_maps_expected_wire_fields() {
    let json = MINIMAL_WSLC_REQUEST_JSON;

    let wire = adapt(json);

    assert!(wire.schema.is_none());
    assert!(wire.comment.is_none());
    assert_eq!(wire.version, Some("0.8.0-alpha".to_string()));
    assert!(matches!(wire.phase, Some(wire::Phase::Provision)));
    assert!(matches!(wire.containment, Some(wire::Containment::Wslc)));

    assert!(wire.sandbox_id.is_none());
    assert!(wire.correlation_vector.is_none());
    assert!(wire.container_id.is_none());
    assert!(wire.process.is_none());
    assert!(wire.lifecycle.is_none());
    assert!(wire.network.is_none());
    assert!(wire.process_container.is_none());
    assert!(wire.lxc.is_none());
    assert!(wire.filesystem.is_none());
    assert!(wire.fallback.is_none());
    assert!(wire.ui.is_none());
    assert!(wire.seatbelt.is_none());
    assert!(wire.experimental.is_none());
}

#[test]
fn wslc_request_maps_expected_wire_fields() {
    let json = WSLC_ALL_FIELDS_REQUEST_JSON;

    let wire = adapt(json);

    assert_eq!(
        wire.schema,
        Some("https://example.com/provision.schema.json".to_string())
    );
    assert_eq!(
        wire.comment.as_ref(),
        Some(&serde_json::json!("This is a comment"))
    );
    assert_eq!(wire.version, Some("0.8.0-alpha".to_string()));
    assert!(matches!(wire.phase, Some(wire::Phase::Provision)));
    assert!(matches!(wire.containment, Some(wire::Containment::Wslc)));

    let filesystem = wire.filesystem.expect("filesystem should be populated");
    assert_eq!(
        filesystem.readonly_paths,
        Some(vec!["/usr/bin".to_string()])
    );
    assert_eq!(
        filesystem.readwrite_paths,
        Some(vec!["/home/user/documents".to_string()])
    );
    assert_eq!(
        filesystem.denied_paths,
        Some(vec!["/home/user/music".to_string()])
    );

    let network = wire.network.expect("network should be populated");
    assert_eq!(network.allow_local_network, Some(false));
    assert!(matches!(
        network.default_policy,
        Some(wire::NetworkPolicy::Block)
    ));
    assert!(matches!(
        network.enforcement_mode,
        Some(wire::NetworkEnforcement::Firewall)
    ));
    assert_eq!(network.allowed_hosts, Some(vec!["example.com".to_string()]));
    assert_eq!(
        network.blocked_hosts,
        Some(vec!["blocked.example.com".to_string()])
    );
    assert!(network.proxy.is_some());
    assert_eq!(
        network.proxy.as_ref().unwrap().url,
        Some("http://example.com/proxy".to_string())
    );

    let experimental = wire.experimental.expect("experimental should be populated");

    let wslc = experimental.wslc.expect("wslc should be populated");
    let provision = wslc.provision.expect("provision should be populated");
    assert_eq!(provision.image.as_deref(), Some("someImage"));
    assert_eq!(
        provision.image_tar_path.as_deref(),
        Some("someImageTarPath")
    );
    assert!(wslc.target_os.is_none());
    assert!(wslc.image.is_none());
    assert!(wslc.image_tar_path.is_none());
    assert!(wslc.cpu_count.is_none());
    assert!(wslc.memory_mb.is_none());
    assert!(wslc.gpu.is_none());
    assert!(wslc.storage_path.is_none());
    assert!(wslc.port_mappings.is_none());

    let telemetry = experimental
        .telemetry
        .expect("telemetry should be populated");
    assert_eq!(telemetry.enabled, Some(false));

    assert!(experimental.test.is_none());
    assert!(experimental.isolation_session.is_none());
    assert!(experimental.windows_sandbox.is_none());
    assert!(experimental.seatbelt.is_none());

    assert!(wire.sandbox_id.is_none());
    assert!(wire.correlation_vector.is_none());
    assert!(wire.container_id.is_none());
    assert!(wire.process.is_none());
    assert!(wire.lifecycle.is_none());
    assert!(wire.process_container.is_none());
    assert!(wire.lxc.is_none());
    assert!(wire.fallback.is_none());
    assert!(wire.ui.is_none());
    assert!(wire.seatbelt.is_none());
}

#[test]
fn empty_isolation_session_sections_map_to_present_empty_wire_sections() {
    let wire = adapt(&isolation_session_request_with_fields(
        r#""experimental": {}"#,
    ));
    let experimental = wire.experimental.expect("experimental should be populated");
    assert!(experimental.telemetry.is_none());
    assert!(experimental.isolation_session.is_none());

    let wire = adapt(&isolation_session_request_with_fields(
        r#""experimental": {"telemetry": {}}"#,
    ));
    let experimental = wire.experimental.expect("experimental should be populated");
    let telemetry = experimental
        .telemetry
        .expect("telemetry should be populated");
    assert!(telemetry.enabled.is_none());

    let wire = adapt(&isolation_session_request_with_fields(
        r#""experimental": {"isolation_session": {}}"#,
    ));
    let experimental = wire.experimental.expect("experimental should be populated");
    let isolation_session = experimental
        .isolation_session
        .expect("isolation_session should be populated");
    assert!(isolation_session.provision.is_none());

    let wire = adapt(&isolation_session_request_with_fields(
        r#""experimental": {"isolation_session": {"provision": {}}}"#,
    ));
    let experimental = wire.experimental.expect("experimental should be populated");
    let isolation_session = experimental
        .isolation_session
        .expect("isolation_session should be populated");
    let provision = isolation_session
        .provision
        .expect("provision should be populated");
    assert!(provision.app_id.is_none());
}

#[test]
fn empty_windows_sandbox_sections_map_to_present_empty_wire_sections() {
    let wire = adapt(&windows_sandbox_request_with_fields(r#""filesystem": {}"#));
    let filesystem = wire.filesystem.expect("filesystem should be populated");
    assert!(filesystem.readwrite_paths.is_none());
    assert!(filesystem.readonly_paths.is_none());
    assert!(filesystem.denied_paths.is_none());

    let wire = adapt(&windows_sandbox_request_with_fields(
        r#""experimental": {}"#,
    ));
    let experimental = wire.experimental.expect("experimental should be populated");
    assert!(experimental.telemetry.is_none());

    let wire = adapt(&windows_sandbox_request_with_fields(
        r#""experimental": {"telemetry": {}}"#,
    ));
    let experimental = wire.experimental.expect("experimental should be populated");
    let telemetry = experimental
        .telemetry
        .expect("telemetry should be populated");
    assert!(telemetry.enabled.is_none());
}

#[test]
fn empty_wslc_sections_map_to_present_empty_wire_sections() {
    let wire = adapt(&wslc_request_with_fields(r#""filesystem": {}"#));
    let filesystem = wire.filesystem.expect("filesystem should be populated");
    assert!(filesystem.readwrite_paths.is_none());
    assert!(filesystem.readonly_paths.is_none());
    assert!(filesystem.denied_paths.is_none());

    let wire = adapt(&wslc_request_with_fields(r#""network": {}"#));
    let network = wire.network.expect("network should be populated");
    assert!(network.default_policy.is_none());
    assert!(network.enforcement_mode.is_none());
    assert!(network.allow_local_network.is_none());
    assert!(network.allowed_hosts.is_none());
    assert!(network.blocked_hosts.is_none());
    assert!(network.proxy.is_none());

    let wire = adapt(&wslc_request_with_fields(r#""experimental": {}"#));
    let experimental = wire.experimental.expect("experimental should be populated");
    assert!(experimental.telemetry.is_none());
    assert!(experimental.wslc.is_none());

    let wire = adapt(&wslc_request_with_fields(
        r#""experimental": {"telemetry": {}}"#,
    ));
    let experimental = wire.experimental.expect("experimental should be populated");
    let telemetry = experimental
        .telemetry
        .expect("telemetry should be populated");
    assert!(telemetry.enabled.is_none());

    let wire = adapt(&wslc_request_with_fields(r#""experimental": {"wslc": {}}"#));
    let experimental = wire.experimental.expect("experimental should be populated");
    let wslc = experimental.wslc.expect("wslc should be populated");
    assert!(wslc.provision.is_none());

    let wire = adapt(&wslc_request_with_fields(
        r#""experimental": {"wslc": {"provision": {}}}"#,
    ));
    let experimental = wire.experimental.expect("experimental should be populated");
    let wslc = experimental.wslc.expect("wslc should be populated");
    let provision = wslc.provision.expect("provision should be populated");
    assert!(provision.image.is_none());
    assert!(provision.image_tar_path.is_none());
}

#[test]
fn empty_isolation_session_app_id_maps_expected_wire_field() {
    let wire = adapt(&isolation_session_request_with_fields(
        r#""experimental": {"isolation_session": {"provision": {"appId": ""}}}"#,
    ));
    let app_id = wire
        .experimental
        .and_then(|experimental| experimental.isolation_session)
        .and_then(|isolation_session| isolation_session.provision)
        .and_then(|provision| provision.app_id);
    assert_eq!(app_id.as_deref(), Some(""));
}

#[test]
fn empty_wslc_provision_strings_map_expected_wire_fields() {
    let wire = adapt(&wslc_request_with_fields(
        r#""experimental": {"wslc": {"provision": {"image": "", "imageTarPath": ""}}}"#,
    ));
    let provision = wire
        .experimental
        .and_then(|experimental| experimental.wslc)
        .and_then(|wslc| wslc.provision)
        .expect("provision should be populated");
    assert_eq!(provision.image.as_deref(), Some(""));
    assert_eq!(provision.image_tar_path.as_deref(), Some(""));
}

#[test]
fn null_provision_comments_map_expected_wire_fields() {
    for json in [
        isolation_session_request_with_fields(r#""_comment": null"#),
        windows_sandbox_request_with_fields(r#""_comment": null"#),
        wslc_request_with_fields(r#""_comment": null"#),
    ] {
        let wire = adapt(&json);
        assert_eq!(wire.comment.as_ref(), Some(&serde_json::Value::Null));
    }
}

// Deserialization match tests
pub(super) fn assert_matches_current_wire_deserialization(json: &str) {
    let current: wire::MxcConfig = crate::config_deserialize::from_str(json).unwrap();
    let adapted = adapt(json);

    assert_eq!(
        serde_json::to_value(adapted).unwrap(),
        serde_json::to_value(current).unwrap()
    );
}

#[test]
fn minimal_isolation_session_request_matches_current_wire_deserialization() {
    let json = MINIMAL_ISOLATION_SESSION_REQUEST_JSON;
    assert_matches_current_wire_deserialization(json);
}

#[test]
fn isolation_session_request_matches_current_wire_deserialization() {
    let json = ISOLATION_SESSION_ALL_FIELDS_REQUEST_JSON;
    assert_matches_current_wire_deserialization(json);
}

#[test]
fn minimal_windows_sandbox_request_matches_current_wire_deserialization() {
    let json = MINIMAL_WINDOWS_SANDBOX_REQUEST_JSON;
    assert_matches_current_wire_deserialization(json);
}

#[test]
fn windows_sandbox_request_matches_current_wire_deserialization() {
    let json = WINDOWS_SANDBOX_ALL_FIELDS_REQUEST_JSON;
    assert_matches_current_wire_deserialization(json);
}

#[test]
fn minimal_wslc_request_matches_current_wire_deserialization() {
    let json = MINIMAL_WSLC_REQUEST_JSON;
    assert_matches_current_wire_deserialization(json);
}

#[test]
fn wslc_request_matches_current_wire_deserialization() {
    let json = WSLC_ALL_FIELDS_REQUEST_JSON;
    assert_matches_current_wire_deserialization(json);
}

#[test]
fn empty_isolation_session_sections_match_current_wire_deserialization() {
    for fields in [
        r#""experimental": {}"#,
        r#""experimental": {"telemetry": {}}"#,
        r#""experimental": {"isolation_session": {}}"#,
        r#""experimental": {"isolation_session": {"provision": {}}}"#,
    ] {
        assert_matches_current_wire_deserialization(&isolation_session_request_with_fields(fields));
    }
}

#[test]
fn empty_windows_sandbox_sections_match_current_wire_deserialization() {
    for fields in [
        r#""filesystem": {}"#,
        r#""experimental": {}"#,
        r#""experimental": {"telemetry": {}}"#,
    ] {
        assert_matches_current_wire_deserialization(&windows_sandbox_request_with_fields(fields));
    }
}

#[test]
fn empty_wslc_sections_match_current_wire_deserialization() {
    for fields in [
        r#""filesystem": {}"#,
        r#""network": {}"#,
        r#""experimental": {}"#,
        r#""experimental": {"telemetry": {}}"#,
        r#""experimental": {"wslc": {}}"#,
        r#""experimental": {"wslc": {"provision": {}}}"#,
    ] {
        assert_matches_current_wire_deserialization(&wslc_request_with_fields(fields));
    }
}

#[test]
fn empty_backend_strings_match_current_wire_deserialization() {
    let isolation_session = isolation_session_request_with_fields(
        r#""experimental": {"isolation_session": {"provision": {"appId": ""}}}"#,
    );
    assert_matches_current_wire_deserialization(&isolation_session);

    let wslc = wslc_request_with_fields(
        r#""experimental": {"wslc": {"provision": {"image": "", "imageTarPath": ""}}}"#,
    );
    assert_matches_current_wire_deserialization(&wslc);
}
