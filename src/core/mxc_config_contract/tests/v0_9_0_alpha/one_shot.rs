// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use crate::common::{assert_invalid, assert_invalid_cases, assert_valid};

// Root object tests
#[test]
fn rejects_unknown_root_field() {
    assert_invalid(
        r#"{
            "version": "0.9.0-alpha",
            "process": {"commandLine": "echo"},
            "unknownField": true
        }"#,
    );
}

#[test]
fn rejects_duplicate_root_fields() {
    let version = r#""version": "0.9.0-alpha""#;
    let process = r#""process": {"commandLine": "echo"}"#;
    let version_and_process = format!("{version}, {process}");

    assert_invalid_cases(
        [
            (
                "version",
                process,
                r#""version": "0.9.0-alpha", "version": "0.9.0-alpha""#,
            ),
            (
                "containerId",
                version_and_process.as_str(),
                r#""containerId": "first", "containerId": "second""#,
            ),
            (
                "containment",
                version_and_process.as_str(),
                r#""containment": "process", "containment": "processcontainer""#,
            ),
            (
                "lifecycle",
                version_and_process.as_str(),
                r#""lifecycle": {"destroyOnExit": true}, "lifecycle": {"preservePolicy": false}"#,
            ),
            (
                "process",
                version,
                r#""process": {"commandLine": "echo"}, "process": {"commandLine": "echo again"}"#,
            ),
            (
                "filesystem",
                version_and_process.as_str(),
                r#""filesystem": {"readonlyPaths": ["/first"]}, "filesystem": {"readonlyPaths": ["/second"]}"#,
            ),
            (
                "fallback",
                version_and_process.as_str(),
                r#""fallback": {"allowDaclMutation": true}, "fallback": {"allowDaclMutation": false}"#,
            ),
            (
                "network",
                version_and_process.as_str(),
                r#""network": {"defaultPolicy": "allow"}, "network": {"defaultPolicy": "block"}"#,
            ),
            (
                "ui",
                version_and_process.as_str(),
                r#""ui": {"disable": true}, "ui": {"disable": false}"#,
            ),
            (
                "processContainer",
                version_and_process.as_str(),
                r#""processContainer": {"leastPrivilege": true}, "processContainer": {"leastPrivilege": false}"#,
            ),
            (
                "lxc",
                version_and_process.as_str(),
                r#""lxc": {"distribution": "ubuntu", "release": "20.04"}, "lxc": {"distribution": "alpine", "release": "3.20"}"#,
            ),
        ],
        "duplicate root field",
    );
}

#[test]
fn rejects_unknown_nested_fields() {
    let version = r#""version": "0.9.0-alpha""#;
    let process = r#""process": {"commandLine": "echo"}"#;
    let version_and_process = format!("{version}, {process}");

    assert_invalid_cases(
        [
            (
                "lifecycle",
                version_and_process.as_str(),
                r#""lifecycle": {"unknownField": true}"#,
            ),
            (
                "process",
                version,
                r#""process": {"commandLine": "echo", "unknownField": true}"#,
            ),
            (
                "filesystem",
                version_and_process.as_str(),
                r#""filesystem": {"unknownField": true}"#,
            ),
            (
                "fallback",
                version_and_process.as_str(),
                r#""fallback": {"unknownField": true}"#,
            ),
            (
                "network",
                version_and_process.as_str(),
                r#""network": {"unknownField": true}"#,
            ),
            (
                "ui",
                version_and_process.as_str(),
                r#""ui": {"unknownField": true}"#,
            ),
            (
                "processContainer",
                version_and_process.as_str(),
                r#""processContainer": {"unknownField": true}"#,
            ),
            (
                "processContainer.ui",
                version_and_process.as_str(),
                r#""processContainer": {"ui": {"unknownField": true}}"#,
            ),
            (
                "processContainer.captureDenials",
                version_and_process.as_str(),
                r#""processContainer": {"captureDenials": {"unknownField": true}}"#,
            ),
            (
                "lxc",
                version_and_process.as_str(),
                r#""lxc": {"distribution": "ubuntu", "release": "20.04", "unknownField": true}"#,
            ),
        ],
        "unknown field in nested object",
    );
}

#[test]
fn rejects_duplicate_nested_field() {
    assert_invalid(
        r#"{
            "version": "0.9.0-alpha",
            "process": {
                "commandLine": "echo",
                "commandLine": "echo again"
            }
        }"#,
    );
}

#[test]
fn rejects_duplicate_process_container_fields() {
    let version_and_process = r#""version": "0.9.0-alpha", "process": {"commandLine": "echo"}"#;

    assert_invalid_cases(
        [
            (
                "processContainer.learningMode",
                version_and_process,
                r#""processContainer": {"learningMode": true, "learningMode": false}"#,
            ),
            (
                "processContainer.captureDenials",
                version_and_process,
                r#""processContainer": {"captureDenials": {}, "captureDenials": {}}"#,
            ),
            (
                "processContainer.captureDenials.mode",
                version_and_process,
                r#""processContainer": {"captureDenials": {"mode": "block", "mode": "allow"}}"#,
            ),
            (
                "processContainer.captureDenials.outputPath",
                version_and_process,
                r#""processContainer": {"captureDenials": {"outputPath": "/tmp/output", "outputPath": "/tmp/output2"}}"#,
            ),
            (
                "processContainer.captureDenials.retainEtl",
                version_and_process,
                r#""processContainer": {"captureDenials": {"retainEtl": true, "retainEtl": false}}"#,
            ),
        ],
        "duplicate nested field",
    );
}

// Version field tests
#[test]
fn rejects_missing_version() {
    assert_invalid(
        r#"{
            "process": {"commandLine": "echo"}
        }"#,
    );
}

#[test]
fn rejects_duplicate_version() {
    assert_invalid(
        r#"{
            "version": "0.9.0-alpha",
            "version": "0.9.0-alpha",
            "process": {"commandLine": "echo"}
        }"#,
    );
}

#[test]
fn rejects_invalid_version() {
    assert_invalid(
        r#"{
            "version": "invalid",
            "process": {"commandLine": "echo"}
        }"#,
    );
}

#[test]
fn rejects_non_exact_version() {
    assert_invalid(
        r#"{
            "version": "0.9.0",
            "process": {"commandLine": "echo"}
        }"#,
    );
}

// Required field tests
#[test]
fn rejects_missing_process() {
    assert_invalid(
        r#"{
            "version": "0.9.0-alpha"
        }"#,
    );
}

#[test]
fn rejects_null_process() {
    assert_invalid(
        r#"{
            "version": "0.9.0-alpha",
            "process": null
        }"#,
    );
}

#[test]
fn rejects_missing_process_command_line() {
    assert_invalid(
        r#"{
            "version": "0.9.0-alpha",
            "process": {}
        }"#,
    );
}

#[test]
fn rejects_null_process_command_line() {
    assert_invalid(
        r#"{
            "version": "0.9.0-alpha",
            "process": {"commandLine": null}
        }"#,
    );
}

#[test]
fn rejects_empty_process_command_line() {
    assert_invalid(
        r#"{
            "version": "0.9.0-alpha",
            "process": {"commandLine": ""}
        }"#,
    );
}

// processcontainer and appcontainer tests
#[test]
fn accepts_process_container() {
    let json = r#"{
        "version": "0.9.0-alpha",
        "processContainer": {
            "ui": {
                "isolation": "container"
            }
        },
        "process": {"commandLine": "echo"}
    }"#;

    assert_valid(json);
}

#[test]
fn accepts_app_container_section_alias() {
    let json = r#"{
        "version": "0.9.0-alpha",
        "appContainer": {
            "ui": {
                "isolation": "container"
            }
        },
        "process": {"commandLine": "echo"}
    }"#;

    assert_valid(json);
}

#[test]
fn rejects_process_container_and_app_container_section_alias_together() {
    let json = r#"{
            "version": "0.9.0-alpha",
            "processContainer": {
                "ui": {
                    "isolation": "container"
                }
            },
            "appContainer": {
                "ui": {
                    "isolation": "container"
                }
            },
            "process": {"commandLine": "echo"}
        }"#;

    assert_invalid(json);
}

#[test]
fn accepts_process_container_learning_mode_values() {
    for process_container_learning_mode in ["true", "false"] {
        let json = format!(
            r#"{{
                "version": "0.9.0-alpha",
                "processContainer": {{
                    "learningMode": {process_container_learning_mode}
                }},
                "process": {{"commandLine": "echo"}}
            }}"#
        );

        assert_valid(&json);
    }
}

#[test]
fn rejects_non_boolean_process_container_learning_mode_values() {
    for process_container_learning_mode in ["\"string\"", "123", "[]", "{}"] {
        let json = format!(
            r#"{{
                "version": "0.9.0-alpha",
                "processContainer": {{
                    "learningMode": {process_container_learning_mode}
                }},
                "process": {{"commandLine": "echo"}}
            }}"#
        );

        assert_invalid(&json);
    }
}

#[test]
fn accepts_empty_capture_denials() {
    let json = r#"{
        "version": "0.9.0-alpha",
        "processContainer": {
            "captureDenials": {}
        },
        "process": {"commandLine": "echo"}
    }"#;

    assert_valid(json);
}

#[test]
fn accepts_capture_denials_output_path() {
    for output_path in [r"c:\temp\denials.log", ""] {
        let output_path_json = serde_json::to_string(output_path).unwrap();
        let json = format!(
            r#"{{
                "version": "0.9.0-alpha",
                "processContainer": {{
                    "captureDenials": {{
                        "outputPath": {output_path_json}
                    }}
                }},
                "process": {{"commandLine": "echo"}}
            }}"#
        );

        assert_valid(&json);
    }
}

#[test]
fn rejects_non_string_capture_denials_output_path() {
    for capture_denials_output_path in ["123", "true", "[]", "{}"] {
        let json = format!(
            r#"{{
                "version": "0.9.0-alpha",
                "processContainer": {{
                    "captureDenials": {{
                        "outputPath": {capture_denials_output_path}
                    }}
                }},
                "process": {{"commandLine": "echo"}}
            }}"#
        );

        assert_invalid(&json);
    }
}

#[test]
fn accepts_capture_denials_retain_etl_values() {
    for capture_denials_retain_etl in ["true", "false"] {
        let json = format!(
            r#"{{
                "version": "0.9.0-alpha",
                "processContainer": {{
                    "captureDenials": {{
                        "retainEtl": {capture_denials_retain_etl}
                    }}
                }},
                "process": {{"commandLine": "echo"}}
            }}"#
        );

        assert_valid(&json);
    }
}

#[test]
fn rejects_non_boolean_capture_denials_retain_etl_values() {
    for capture_denials_retain_etl in ["\"string\"", "123", "[]", "{}"] {
        let json = format!(
            r#"{{
                "version": "0.9.0-alpha",
                "processContainer": {{
                    "captureDenials": {{
                        "retainEtl": {capture_denials_retain_etl}
                    }}
                }},
                "process": {{"commandLine": "echo"}}
            }}"#
        );

        assert_invalid(&json);
    }
}

// Numerics and collections
#[test]
fn rejects_negative_process_timeout() {
    let json = r#"{
        "version": "0.9.0-alpha",
        "process": {
            "commandLine": "echo",
            "timeout": -1
        }
    }"#;

    assert_invalid(json);
}

#[test]
fn rejects_process_timeout_above_u32() {
    let json = r#"{
        "version": "0.9.0-alpha",
        "process": {
            "commandLine": "echo",
            "timeout": 4294967296
        }
    }"#;

    assert_invalid(json);
}

#[test]
fn rejects_non_string_process_env_items() {
    let json = r#"{
        "version": "0.9.0-alpha",
        "process": {
            "commandLine": "echo",
            "env": ["A=1", 123]
        }
    }"#;

    assert_invalid(json);
}

#[test]
fn rejects_non_string_filesystem_readonly_path_items() {
    let json = r#"{
        "version": "0.9.0-alpha",
        "process": {
            "commandLine": "echo"
        },
        "filesystem": {
            "readonlyPaths": [123]
        }
    }"#;

    assert_invalid(json);
}

#[test]
fn rejects_non_string_filesystem_readwrite_path_items() {
    let json = r#"{
        "version": "0.9.0-alpha",
        "process": {
            "commandLine": "echo"
        },
        "filesystem": {
            "readwritePaths": [123]
        }
    }"#;

    assert_invalid(json);
}

#[test]
fn rejects_non_string_filesystem_denied_path_items() {
    let json = r#"{
        "version": "0.9.0-alpha",
        "process": {
            "commandLine": "echo"
        },
        "filesystem": {
            "deniedPaths": [123]
        }
    }"#;

    assert_invalid(json);
}

#[test]
fn rejects_non_string_process_container_capabilities() {
    let json = r#"{
        "version": "0.9.0-alpha",
        "processContainer": {
            "capabilities": [123]
        },
        "process": {"commandLine": "echo"}
    }"#;

    assert_invalid(json);
}

// Lxc tests
#[test]
fn accepts_lxc() {
    let json = r#"{
        "version": "0.9.0-alpha",
        "lxc": {
            "distribution": "ubuntu",
            "release": "20.04"
        },
        "process": {"commandLine": "echo"}
    }"#;

    assert_valid(json);
}

#[test]
fn rejects_lxc_missing_distribution() {
    let json = r#"{
        "version": "0.9.0-alpha",
        "lxc": {
            "release": "20.04"
        },
        "process": {"commandLine": "echo"}
    }"#;

    assert_invalid(json);
}

#[test]
fn rejects_lxc_missing_release() {
    let json = r#"{
        "version": "0.9.0-alpha",
        "lxc": {
            "distribution": "ubuntu"
        },
        "process": {"commandLine": "echo"}
    }"#;

    assert_invalid(json);
}

#[test]
fn rejects_lxc_null_distribution() {
    let json = r#"{
        "version": "0.9.0-alpha",
        "lxc": {
            "distribution": null,
            "release": "20.04"
        },
        "process": {"commandLine": "echo"}
    }"#;

    assert_invalid(json);
}

#[test]
fn rejects_lxc_null_release() {
    let json = r#"{
        "version": "0.9.0-alpha",
        "lxc": {
            "distribution": "ubuntu",
            "release": null
        },
        "process": {"commandLine": "echo"}
    }"#;

    assert_invalid(json);
}

// State-aware tests
#[test]
fn rejects_state_aware_fields() {
    for field in [
        r#""phase": "exec""#,
        r#""sandboxId": "someId""#,
        r#""correlationVector": "someVector""#,
    ] {
        let json = format!(
            r#"{{
                "version": "0.9.0-alpha",
                "process": {{"commandLine": "echo"}},
                {field}
            }}"#
        );

        assert_invalid(&json);
    }
}

// Runtime configuration and the ProcessContainer proxy-peer surface, added to
// the 0.8 contract alongside directional networking.
#[test]
fn accepts_runtime_config_and_process_container_network() {
    assert_valid(
        r#"{
            "version": "0.9.0-alpha",
            "containment": "processcontainer",
            "process": {"commandLine": "echo"},
            "runtimeConfig": {"networkProxy": "http://127.0.0.1:8080"},
            "processContainer": {"network": {"allowedProxyPeer": "127.0.0.1"}},
            "network": {"egress": {"default": "deny"}}
        }"#,
    );
}

#[test]
fn rejects_unknown_runtime_config_field() {
    assert_invalid(
        r#"{
            "version": "0.9.0-alpha",
            "process": {"commandLine": "echo"},
            "runtimeConfig": {"networkProxy": "http://127.0.0.1:8080", "nope": true}
        }"#,
    );
}

#[test]
fn rejects_unknown_process_container_network_field() {
    assert_invalid(
        r#"{
            "version": "0.9.0-alpha",
            "process": {"commandLine": "echo"},
            "processContainer": {"network": {"allowedProxyPeer": "127.0.0.1", "nope": true}}
        }"#,
    );
}

#[test]
fn rejects_duplicate_runtime_config() {
    assert_invalid(
        r#"{
            "version": "0.9.0-alpha",
            "process": {"commandLine": "echo"},
            "runtimeConfig": {"networkProxy": "http://127.0.0.1:8080"},
            "runtimeConfig": {"networkProxy": "http://127.0.0.1:9090"}
        }"#,
    );
}

#[test]
fn rejects_non_string_runtime_config_network_proxy() {
    assert_invalid(
        r#"{
            "version": "0.9.0-alpha",
            "process": {"commandLine": "echo"},
            "runtimeConfig": {"networkProxy": 8080}
        }"#,
    );
}
