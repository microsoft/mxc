// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use crate::common::{assert_invalid, assert_valid};

// Enum value tests
#[test]
fn accepts_every_containment_value() {
    for containment in [
        "process",
        "processcontainer",
        "lxc",
        "bubblewrap",
        "seatbelt",
        "vm",
        "windows_sandbox",
        "microvm",
        "hyperlight",
        "isolation_session",
        "wslc",
    ] {
        let json = format!(
            r#"{{
                "version": "0.8.0-alpha",
                "containment": "{containment}",
                "process": {{"commandLine": "echo"}}
            }}"#
        );

        assert_valid(&json);
    }
}

#[test]
fn rejects_invalid_containment_value() {
    assert_invalid(
        r#"{
            "version": "0.8.0-alpha",
            "containment": "invalid",
            "process": {"commandLine": "echo"}
        }"#,
    );
}

#[test]
fn accepts_every_default_network_policy_value() {
    for default_network_policy in ["allow", "block"] {
        let json = format!(
            r#"{{
                "version": "0.8.0-alpha",
                "network": {{
                    "defaultPolicy": "{default_network_policy}"
                }},
                "process": {{"commandLine": "echo"}}
            }}"#
        );

        assert_valid(&json);
    }
}

#[test]
fn rejects_invalid_default_network_policy_value() {
    assert_invalid(
        r#"{
            "version": "0.8.0-alpha",
            "network": {
                "defaultPolicy": "invalid"
            },
            "process": {"commandLine": "echo"}
        }"#,
    );
}

#[test]
fn accepts_every_network_enforcement_mode_value() {
    for network_enforcement_mode in ["capabilities", "firewall", "both"] {
        let json = format!(
            r#"{{
                "version": "0.8.0-alpha",
                "network": {{
                    "enforcementMode": "{network_enforcement_mode}"
                }},
                "process": {{"commandLine": "echo"}}
            }}"#
        );

        assert_valid(&json);
    }
}

#[test]
fn rejects_invalid_network_enforcement_mode_value() {
    assert_invalid(
        r#"{
            "version": "0.8.0-alpha",
            "network": {
                "enforcementMode": "invalid"
            },
            "process": {"commandLine": "echo"}
        }"#,
    );
}

#[test]
fn accepts_every_ui_clipboard_value() {
    for ui_clipboard in ["none", "read", "write", "all"] {
        let json = format!(
            r#"{{
                "version": "0.8.0-alpha",
                "ui": {{
                    "clipboard": "{ui_clipboard}"
                }},
                "process": {{"commandLine": "echo"}}
            }}"#
        );

        assert_valid(&json);
    }
}

#[test]
fn rejects_invalid_ui_clipboard_value() {
    assert_invalid(
        r#"{
            "version": "0.8.0-alpha",
            "ui": {
                "clipboard": "invalid"
            },
            "process": {"commandLine": "echo"}
        }"#,
    );
}

#[test]
fn accepts_every_process_container_ui_isolation_value() {
    for process_container_ui_isolation in ["container", "desktop", "handles", "atoms"] {
        let json = format!(
            r#"{{
                "version": "0.8.0-alpha",
                "processContainer": {{
                    "ui": {{
                        "isolation": "{process_container_ui_isolation}"
                    }}
                }},
                "process": {{"commandLine": "echo"}}
            }}"#
        );

        assert_valid(&json);
    }
}

#[test]
fn rejects_invalid_process_container_ui_isolation_value() {
    assert_invalid(
        r#"{
            "version": "0.8.0-alpha",
            "processContainer": {
                "ui": {
                    "isolation": "invalid"
                }
            },
            "process": {"commandLine": "echo"}
        }"#,
    );
}

#[test]
fn accepts_every_capture_denials_mode_value() {
    for capture_denials_mode in ["allow", "block"] {
        let json = format!(
            r#"{{
                "version": "0.8.0-alpha",
                "processContainer": {{
                    "captureDenials": {{
                        "mode": "{capture_denials_mode}",
                        "outputPath": "c:\\temp\\denials.log"
                    }}
                }},
                "process": {{"commandLine": "echo"}}
            }}"#
        );

        assert_valid(&json);
    }
}

#[test]
fn rejects_invalid_capture_denials_mode_value() {
    assert_invalid(
        r#"{
            "version": "0.8.0-alpha",
            "processContainer": {
                "captureDenials": {
                    "mode": "invalid",
                    "outputPath": "c:\\temp\\denials.log"
                }
            },
            "process": {"commandLine": "echo"}
        }"#,
    );
}

#[test]
fn rejects_non_string_capture_denials_mode_value() {
    for capture_denials_mode in ["123", "true", "[]", "{}"] {
        let json = format!(
            r#"{{
                "version": "0.8.0-alpha",
                "processContainer": {{
                    "captureDenials": {{
                        "mode": {capture_denials_mode},
                        "outputPath": "c:\\temp\\denials.log"
                    }}
                }},
                "process": {{"commandLine": "echo"}}
            }}"#
        );

        assert_invalid(&json);
    }
}

#[test]
fn rejects_object_encoding_for_fieldless_enums() {
    let cases = [
        r#"{
                "version": {"0.8.0-alpha": null},
                "process": {"commandLine": "echo"}
            }"#,
        r#"{
                "version": "0.8.0-alpha",
                "containment": {"process": null},
                "process": {"commandLine": "echo"}
            }"#,
        r#"{
                "version": "0.8.0-alpha",
                "network": {"defaultPolicy": {"allow": null}},
                "process": {"commandLine": "echo"}
            }"#,
        r#"{
                "version": "0.8.0-alpha",
                "network": {"enforcementMode": {"both": null}},
                "process": {"commandLine": "echo"}
            }"#,
        r#"{
                "version": "0.8.0-alpha",
                "ui": {"clipboard": {"all": null}},
                "process": {"commandLine": "echo"}
            }"#,
        r#"{
                "version": "0.8.0-alpha",
                "processContainer": {
                    "ui": {"isolation": {"desktop": null}}
                },
                "process": {"commandLine": "echo"}
            }"#,
        r#"{
                "version": "0.8.0-alpha",
                "processContainer": {
                    "captureDenials": {"mode": {"block": null}}
                },
                "process": {"commandLine": "echo"}
            }"#,
        r#"{
                "version": "0.8.0-alpha",
                "seatbelt": {
                    "launchMethod": {"exec": null}
                },
                "process": {"commandLine": "echo"}
            }"#,
    ];

    for case in cases {
        assert_invalid(case);
    }
}

use mxc_config_contract::dev::{OneShotContainment, OneShotRequest};

#[test]
fn appcontainer_containment_value_alias_maps_to_process_container() {
    let json = r#"{
        "version": "0.8.0-alpha",
        "containment": "appcontainer",
        "process": {
            "commandLine": "echo"
        }
    }"#;

    let request: OneShotRequest = serde_json::from_str(json).unwrap();

    assert!(matches!(
        request.containment.as_ref(),
        Some(OneShotContainment::ProcessContainer)
    ));
}

#[test]
fn macos_sandbox_containment_value_alias_maps_to_seatbelt() {
    let json = r#"{
        "version": "0.8.0-alpha",
        "containment": "macos_sandbox",
        "process": {
            "commandLine": "echo"
        }
    }"#;

    let request: OneShotRequest = serde_json::from_str(json).unwrap();

    assert!(matches!(
        request.containment.as_ref(),
        Some(OneShotContainment::Seatbelt)
    ));
}
