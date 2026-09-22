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
        "isolation_session",
        "wslc",
    ] {
        let json = format!(
            r#"{{
                "version": "1.0.0",
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
            "version": "1.0.0",
            "containment": "invalid",
            "process": {"commandLine": "echo"}
        }"#,
    );
}

#[test]
fn rejects_every_removed_default_network_policy_value() {
    for default_network_policy in ["allow", "block"] {
        let json = format!(
            r#"{{
                "version": "1.0.0",
                "network": {{
                    "defaultPolicy": "{default_network_policy}"
                }},
                "process": {{"commandLine": "echo"}}
            }}"#
        );

        assert_invalid(&json);
    }
}

#[test]
fn rejects_invalid_default_network_policy_value() {
    assert_invalid(
        r#"{
            "version": "1.0.0",
            "network": {
                "defaultPolicy": "invalid"
            },
            "process": {"commandLine": "echo"}
        }"#,
    );
}

#[test]
fn rejects_every_removed_network_enforcement_mode_value() {
    for network_enforcement_mode in ["capabilities", "firewall", "both"] {
        let json = format!(
            r#"{{
                "version": "1.0.0",
                "network": {{
                    "enforcementMode": "{network_enforcement_mode}"
                }},
                "process": {{"commandLine": "echo"}}
            }}"#
        );

        assert_invalid(&json);
    }
}

#[test]
fn rejects_invalid_network_enforcement_mode_value() {
    assert_invalid(
        r#"{
            "version": "1.0.0",
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
                "version": "1.0.0",
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
            "version": "1.0.0",
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
                "version": "1.0.0",
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
            "version": "1.0.0",
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
                "version": "1.0.0",
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
            "version": "1.0.0",
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

use mxc_config_contract::published::v1_0_0::OneShotRequest;

#[test]
fn rejects_appcontainer_containment_value_alias() {
    let json = r#"{
        "version": "1.0.0",
        "containment": "appcontainer",
        "process": {
            "commandLine": "echo"
        }
    }"#;

    assert!(serde_json::from_str::<OneShotRequest>(json).is_err());
}

#[test]
fn rejects_macos_sandbox_containment_value_alias() {
    let json = r#"{
        "version": "1.0.0",
        "containment": "macos_sandbox",
        "process": {
            "commandLine": "echo"
        }
    }"#;

    assert!(serde_json::from_str::<OneShotRequest>(json).is_err());
}
