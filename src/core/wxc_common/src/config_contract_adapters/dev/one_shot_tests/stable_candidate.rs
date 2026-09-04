// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use super::common::{
    adapt, assert_matches_current_wire_deserialization, request_with_containment, ContainmentCase,
};

const MINIMAL_REQUEST_JSON: &str = r#"{
    "version": "0.9.0-alpha",
    "process": {
        "commandLine": "echo hello"
    }
}"#;

const PROCESS_CONTAINER_REQUEST_JSON: &str = r#"{
    "version": "0.9.0-alpha",
    "containerId": "container-id",
    "containment": "processcontainer",
    "lifecycle": {
        "destroyOnExit": true,
        "preservePolicy": true
    },
    "process": {
        "commandLine": "echo hello",
        "cwd": "/home/user",
        "env": [
            "VAR1=value1", "VAR2=value2"
        ],
        "timeout": 60
    },
    "filesystem": {
        "readwritePaths": ["/path/to/readwrite"],
        "readonlyPaths": ["/path/to/readonly"],
        "deniedPaths": ["/path/to/denied"]
    },
    "fallback": {
        "allowDaclMutation": true
    },
    "network": {
        "defaultPolicy": "allow",
        "enforcementMode": "capabilities",
        "allowLocalNetwork": true,
        "allowedHosts": ["example.com"],
        "blockedHosts": ["blocked.com"],
        "proxy": {
            "localhost": 8080
        }
    },
    "ui": {
        "disable": true,
        "clipboard": "all",
        "injection": true
    },
    "processContainer": {
        "leastPrivilege": true,
        "capabilities": ["cap1", "cap2"],
        "ui": {
            "isolation": "container",
            "desktopSystemControl": true,
            "systemSettings": "none",
            "ime": true
        }
    }
}"#;

const PROCESS_CONTAINER_ADDITIONS_REQUEST_JSON: &str = r#"{
    "version": "0.9.0-alpha",
    "containment": "processcontainer",
    "process": {
        "commandLine": "echo hello"
    },
    "processContainer": {
        "learningMode": true,
        "captureDenials": {
            "mode": "block",
            "outputPath": "C:\\denials.json",
            "retainEtl": true
        }
    }
}"#;

const LXC_REQUEST_JSON: &str = r#"{
    "version": "0.9.0-alpha",
    "containerId": "container-id",
    "containment": "lxc",
    "lifecycle": {
        "destroyOnExit": true,
        "preservePolicy": true
    },
    "process": {
        "commandLine": "echo hello",
        "cwd": "/home/user",
        "env": [
            "VAR1=value1", "VAR2=value2"
        ],
        "timeout": 60
    },
    "filesystem": {
        "readwritePaths": ["/path/to/readwrite"],
        "readonlyPaths": ["/path/to/readonly"],
        "deniedPaths": ["/path/to/denied"]
    },
    "network": {
        "defaultPolicy": "allow",
        "enforcementMode": "firewall",
        "allowLocalNetwork": true,
        "allowedHosts": ["example.com"],
        "blockedHosts": ["blocked.com"]
    },
    "ui": {
        "disable": true,
        "clipboard": "all",
        "injection": true
    },
    "lxc": {
        "distribution": "ubuntu",
        "release": "20.04"
    }
}"#;

const SEATBELT_REQUEST_JSON: &str = r#"{
    "version": "0.9.0-alpha",
    "containment": "seatbelt",
    "process": {
        "commandLine": "echo hello",
        "cwd": "/home/user",
        "env": [
            "VAR1=value1", "VAR2=value2"
        ],
        "timeout": 60
    },
    "filesystem": {
        "readwritePaths": ["/path/to/readwrite"],
        "readonlyPaths": ["/path/to/readonly"],
        "deniedPaths": ["/path/to/denied"]
    },
    "network": {
        "defaultPolicy": "allow",
        "enforcementMode": "firewall",
        "allowLocalNetwork": true,
        "allowedHosts": ["example.com"],
        "blockedHosts": ["blocked.com"]
    },
    "seatbelt": {
        "profileOverride": "custom-profile.sb",
        "guiAccess": true,
        "launchMethod": "open",
        "nestedPty": true,
        "keychainAccess": true,
        "systemPowerAccess": true,
        "extraMachLookups": ["com.example.service"]
    }
}"#;

const EMPTY_OPTIONAL_SECTIONS_REQUEST_JSON: &str = r#"{
    "version": "0.9.0-alpha",
    "process": {
        "commandLine": "echo hello"
    },
    "lifecycle": {},
    "filesystem": {},
    "fallback": {},
    "network": {},
    "ui": {}
}"#;

const EMPTY_PROCESS_CONTAINER_SECTION_REQUEST_JSON: &str = r#"{
    "version": "0.9.0-alpha",
    "containment": "processcontainer",
    "process": {
        "commandLine": "echo hello"
    },
    "processContainer": {}
}"#;

const EMPTY_PROCESS_CONTAINER_UI_SECTION_REQUEST_JSON: &str = r#"{
    "version": "0.9.0-alpha",
    "containment": "processcontainer",
    "process": {
        "commandLine": "echo hello"
    },
    "processContainer": {
        "ui": {}
    }
}"#;

const EMPTY_SEATBELT_SECTION_REQUEST_JSON: &str = r#"{
    "version": "0.9.0-alpha",
    "containment": "seatbelt",
    "process": {
        "commandLine": "echo hello"
    },
    "seatbelt": {}
}"#;

const APP_CONTAINER_SECTION_ALIAS_REQUEST_JSON: &str = r#"{
    "version": "0.9.0-alpha",
    "containment": "processcontainer",
    "process": {
        "commandLine": "echo hello"
    },
    "appContainer": {
        "leastPrivilege": true,
        "capabilities": ["internetClient"]
    }
}"#;

const MACOS_SANDBOX_SECTION_ALIAS_REQUEST_JSON: &str = r#"{
    "version": "0.9.0-alpha",
    "containment": "seatbelt",
    "process": {
        "commandLine": "echo hello"
    },
    "macos_sandbox": {
        "profileOverride": "custom-profile.sb",
        "guiAccess": true,
        "launchMethod": "open",
        "nestedPty": true,
        "keychainAccess": true,
        "systemPowerAccess": true,
        "extraMachLookups": ["com.example.service"]
    }
}"#;

struct ProxyCase {
    json: &'static str,
    localhost: Option<u16>,
    builtin_test_server: Option<bool>,
    url: Option<&'static str>,
}

const PROXY_CASES: &[ProxyCase] = &[
    ProxyCase {
        json: r#"{"localhost": 8080}"#,
        localhost: Some(8080),
        builtin_test_server: None,
        url: None,
    },
    ProxyCase {
        json: r#"{"builtinTestServer": true}"#,
        localhost: None,
        builtin_test_server: Some(true),
        url: None,
    },
    ProxyCase {
        json: r#"{"url": "http://proxy.example:8080"}"#,
        localhost: None,
        builtin_test_server: None,
        url: Some("http://proxy.example:8080"),
    },
];

const STABLE_CONTAINMENT_CASES: &[ContainmentCase] = &[
    ContainmentCase {
        input: "process",
        expected: "process",
    },
    ContainmentCase {
        input: "processcontainer",
        expected: "processcontainer",
    },
    ContainmentCase {
        input: "appcontainer",
        expected: "processcontainer",
    },
    ContainmentCase {
        input: "lxc",
        expected: "lxc",
    },
    ContainmentCase {
        input: "bubblewrap",
        expected: "bubblewrap",
    },
    ContainmentCase {
        input: "seatbelt",
        expected: "seatbelt",
    },
    ContainmentCase {
        input: "macos_sandbox",
        expected: "seatbelt",
    },
];

const DEFAULT_NETWORK_POLICY_CASES: &[&str] = &["allow", "block"];

const NETWORK_ENFORCEMENT_MODE_CASES: &[&str] = &["capabilities", "firewall", "both"];

const UI_CLIPBOARD_CASES: &[&str] = &["none", "read", "write", "all"];

const PROCESS_CONTAINER_UI_ISOLATION_CASES: &[&str] = &["container", "desktop", "handles", "atoms"];

const SEATBELT_LAUNCH_METHOD_CASES: &[&str] = &["exec", "open"];

const CAPTURE_DENIALS_MODE_CASES: &[&str] = &["block", "allow"];

fn request_with_comment(comment: &str) -> String {
    format!(
        r#"{{
            "version": "0.9.0-alpha",
            "_comment": {comment},
            "process": {{"commandLine": "echo hello"}}
        }}"#
    )
}

fn request_with_proxy(proxy_json: &str) -> String {
    format!(
        r#"{{
            "version": "0.9.0-alpha",
            "process": {{"commandLine": "echo hello"}},
            "network": {{"proxy": {proxy_json}}}
        }}"#
    )
}

fn request_with_default_network_policy(default_policy: &str) -> String {
    format!(
        r#"{{
            "version": "0.9.0-alpha",
            "process": {{"commandLine": "echo hello"}},
            "network": {{"defaultPolicy": "{default_policy}"}}
        }}"#
    )
}

fn request_with_network_enforcement_mode(enforcement_mode: &str) -> String {
    format!(
        r#"{{
            "version": "0.9.0-alpha",
            "process": {{"commandLine": "echo hello"}},
            "network": {{"enforcementMode": "{enforcement_mode}"}}
        }}"#
    )
}

fn request_with_ui_clipboard(clipboard: &str) -> String {
    format!(
        r#"{{
            "version": "0.9.0-alpha",
            "process": {{"commandLine": "echo hello"}},
            "ui": {{"clipboard": "{clipboard}"}}
        }}"#
    )
}

fn request_with_process_container_ui_isolation(isolation: &str) -> String {
    format!(
        r#"{{
            "version": "0.9.0-alpha",
            "process": {{"commandLine": "echo hello"}},
            "processContainer": {{"ui": {{"isolation": "{isolation}"}}}}
        }}"#
    )
}

fn request_with_capture_denials_mode(mode: &str) -> String {
    format!(
        r#"{{
        "version": "0.9.0-alpha",
        "containment": "processcontainer",
        "process": {{"commandLine": "echo"}},
        "processContainer": {{
            "captureDenials": {{"mode": "{mode}"}}
        }}
    }}"#
    )
}

fn request_with_seatbelt_launch_method(launch_method: &str) -> String {
    format!(
        r#"{{
            "version": "0.9.0-alpha",
            "process": {{"commandLine": "echo hello"}},
            "seatbelt": {{"launchMethod": "{launch_method}"}}
        }}"#
    )
}

#[test]
fn minimal_request_maps_expected_wire_fields() {
    let json = MINIMAL_REQUEST_JSON;

    let wire = adapt(json);

    assert!(wire.schema.is_none());
    assert!(wire.comment.is_none());
    assert_eq!(wire.version, Some("0.9.0-alpha".to_string()));
    assert!(wire.phase.is_none());
    assert!(wire.sandbox_id.is_none());
    assert!(wire.correlation_vector.is_none());
    assert!(wire.container_id.is_none());
    assert!(wire.containment.is_none());

    let process = wire.process.expect("process should be populated");
    assert_eq!(process.command_line.as_deref(), Some("echo hello"));
    assert!(process.cwd.is_none());
    assert!(process.env.is_none());
    assert!(process.timeout.is_none());

    assert!(wire.lifecycle.is_none());
    assert!(wire.process_container.is_none());
    assert!(wire.lxc.is_none());
    assert!(wire.filesystem.is_none());
    assert!(wire.fallback.is_none());
    assert!(wire.network.is_none());
    assert!(wire.ui.is_none());
    assert!(wire.seatbelt.is_none());
    assert!(wire.experimental.is_none());
}

#[test]
fn process_container_request_maps_expected_wire_fields() {
    let json = PROCESS_CONTAINER_REQUEST_JSON;

    let wire = adapt(json);

    assert!(wire.schema.is_none());
    assert!(wire.comment.is_none());
    assert_eq!(wire.version, Some("0.9.0-alpha".to_string()));
    assert!(wire.phase.is_none());
    assert!(wire.sandbox_id.is_none());
    assert!(wire.correlation_vector.is_none());
    assert_eq!(wire.container_id.as_deref(), Some("container-id"));
    assert!(matches!(
        wire.containment,
        Some(super::wire::Containment::ProcessContainer)
    ));

    let process = wire.process.expect("process should be populated");
    assert_eq!(process.command_line.as_deref(), Some("echo hello"));
    assert_eq!(process.cwd.as_deref(), Some("/home/user"));
    assert_eq!(
        process.env.unwrap().as_slice(),
        &["VAR1=value1", "VAR2=value2"]
    );
    assert_eq!(process.timeout, Some(60));

    let lifecycle = wire.lifecycle.expect("lifecycle should be populated");
    assert_eq!(lifecycle.destroy_on_exit, Some(true));
    assert_eq!(lifecycle.preserve_policy, Some(true));

    let filesystem = wire.filesystem.expect("filesystem should be populated");
    assert_eq!(
        filesystem.readwrite_paths.unwrap().as_slice(),
        &["/path/to/readwrite"]
    );
    assert_eq!(
        filesystem.readonly_paths.unwrap().as_slice(),
        &["/path/to/readonly"]
    );
    assert_eq!(
        filesystem.denied_paths.unwrap().as_slice(),
        &["/path/to/denied"]
    );

    let fallback = wire.fallback.expect("fallback should be populated");
    assert_eq!(fallback.allow_dacl_mutation, Some(true));

    let network = wire.network.expect("network should be populated");
    assert!(matches!(
        network.default_policy,
        Some(super::wire::NetworkPolicy::Allow)
    ));
    assert!(matches!(
        network.enforcement_mode,
        Some(super::wire::NetworkEnforcement::Capabilities)
    ));
    assert_eq!(network.allow_local_network, Some(true));
    assert_eq!(network.allowed_hosts.unwrap().as_slice(), &["example.com"]);
    assert_eq!(network.blocked_hosts.unwrap().as_slice(), &["blocked.com"]);

    let proxy = network.proxy.expect("proxy should be populated");
    assert_eq!(proxy.localhost, Some(8080));
    assert!(proxy.builtin_test_server.is_none());
    assert!(proxy.url.is_none());

    let ui = wire.ui.expect("ui should be populated");
    assert_eq!(ui.disable, Some(true));
    assert!(matches!(
        ui.clipboard,
        Some(super::wire::ClipboardPolicy::All)
    ));
    assert_eq!(ui.injection, Some(true));

    let process_container = wire
        .process_container
        .expect("process_container should be populated");
    assert_eq!(process_container.least_privilege, Some(true));
    assert!(process_container.learning_mode.is_none());
    assert_eq!(
        process_container.capabilities.unwrap().as_slice(),
        &["cap1", "cap2"]
    );
    assert!(process_container.capture_denials.is_none());

    let process_container_ui = process_container
        .ui
        .expect("process_container.ui should be populated");
    assert!(matches!(
        process_container_ui.isolation,
        Some(super::wire::UiIsolation::Container)
    ));
    assert_eq!(process_container_ui.desktop_system_control, Some(true));
    assert_eq!(
        process_container_ui.system_settings,
        Some("none".to_string())
    );
    assert_eq!(process_container_ui.ime, Some(true));

    assert!(wire.lxc.is_none());
}

#[test]
fn lxc_request_maps_expected_wire_fields() {
    let json = LXC_REQUEST_JSON;

    let wire = adapt(json);

    assert!(wire.schema.is_none());
    assert!(wire.comment.is_none());
    assert_eq!(wire.version, Some("0.9.0-alpha".to_string()));
    assert!(wire.phase.is_none());
    assert!(wire.sandbox_id.is_none());
    assert!(wire.correlation_vector.is_none());
    assert_eq!(wire.container_id.as_deref(), Some("container-id"));
    assert!(matches!(
        wire.containment,
        Some(super::wire::Containment::Lxc)
    ));

    let process = wire.process.expect("process should be populated");
    assert_eq!(process.command_line.as_deref(), Some("echo hello"));
    assert_eq!(process.cwd.as_deref(), Some("/home/user"));
    assert_eq!(
        process.env.unwrap().as_slice(),
        &["VAR1=value1", "VAR2=value2"]
    );
    assert_eq!(process.timeout, Some(60));

    let lifecycle = wire.lifecycle.expect("lifecycle should be populated");
    assert_eq!(lifecycle.destroy_on_exit, Some(true));
    assert_eq!(lifecycle.preserve_policy, Some(true));

    let filesystem = wire.filesystem.expect("filesystem should be populated");
    assert_eq!(
        filesystem.readwrite_paths.unwrap().as_slice(),
        &["/path/to/readwrite"]
    );
    assert_eq!(
        filesystem.readonly_paths.unwrap().as_slice(),
        &["/path/to/readonly"]
    );
    assert_eq!(
        filesystem.denied_paths.unwrap().as_slice(),
        &["/path/to/denied"]
    );

    let network = wire.network.expect("network should be populated");
    assert!(matches!(
        network.default_policy,
        Some(super::wire::NetworkPolicy::Allow)
    ));
    assert!(matches!(
        network.enforcement_mode,
        Some(super::wire::NetworkEnforcement::Firewall)
    ));
    assert_eq!(network.allow_local_network, Some(true));
    assert_eq!(network.allowed_hosts.unwrap().as_slice(), &["example.com"]);
    assert_eq!(network.blocked_hosts.unwrap().as_slice(), &["blocked.com"]);
    assert!(network.proxy.is_none());

    let ui = wire.ui.expect("ui should be populated");
    assert_eq!(ui.disable, Some(true));
    assert!(matches!(
        ui.clipboard,
        Some(super::wire::ClipboardPolicy::All)
    ));
    assert_eq!(ui.injection, Some(true));

    let lxc = wire.lxc.expect("lxc should be populated");
    assert_eq!(lxc.distribution.as_deref(), Some("ubuntu"));
    assert_eq!(lxc.release.as_deref(), Some("20.04"));
}

#[test]
fn seatbelt_request_maps_expected_wire_fields() {
    let json = SEATBELT_REQUEST_JSON;

    let wire = adapt(json);

    assert!(wire.schema.is_none());
    assert!(wire.comment.is_none());
    assert_eq!(wire.version, Some("0.9.0-alpha".to_string()));
    assert!(wire.phase.is_none());
    assert!(wire.sandbox_id.is_none());
    assert!(wire.correlation_vector.is_none());
    assert!(wire.container_id.is_none());
    assert!(matches!(
        wire.containment,
        Some(super::wire::Containment::Seatbelt)
    ));

    let process = wire.process.expect("process should be populated");
    assert_eq!(process.command_line.as_deref(), Some("echo hello"));
    assert_eq!(process.cwd.as_deref(), Some("/home/user"));
    assert_eq!(
        process.env.unwrap().as_slice(),
        &["VAR1=value1", "VAR2=value2"]
    );
    assert_eq!(process.timeout, Some(60));

    let filesystem = wire.filesystem.expect("filesystem should be populated");
    assert_eq!(
        filesystem.readwrite_paths.unwrap().as_slice(),
        &["/path/to/readwrite"]
    );
    assert_eq!(
        filesystem.readonly_paths.unwrap().as_slice(),
        &["/path/to/readonly"]
    );
    assert_eq!(
        filesystem.denied_paths.unwrap().as_slice(),
        &["/path/to/denied"]
    );

    let network = wire.network.expect("network should be populated");
    assert!(matches!(
        network.default_policy,
        Some(super::wire::NetworkPolicy::Allow)
    ));
    assert_eq!(network.allow_local_network, Some(true));
    assert!(matches!(
        network.enforcement_mode,
        Some(super::wire::NetworkEnforcement::Firewall)
    ));
    assert_eq!(network.allowed_hosts.unwrap().as_slice(), &["example.com"]);
    assert_eq!(network.blocked_hosts.unwrap().as_slice(), &["blocked.com"]);
    assert!(network.proxy.is_none());

    let seatbelt = wire.seatbelt.expect("seatbelt should be populated");
    assert_eq!(
        seatbelt.profile_override.as_deref(),
        Some("custom-profile.sb")
    );
    assert_eq!(seatbelt.gui_access, Some(true));
    assert!(matches!(
        seatbelt.launch_method,
        Some(super::wire::LaunchMethod::Open)
    ));
    assert_eq!(seatbelt.nested_pty, Some(true));
    assert_eq!(seatbelt.keychain_access, Some(true));
    assert_eq!(seatbelt.system_power_access, Some(true));
    assert_eq!(
        seatbelt.extra_mach_lookups.unwrap().as_slice(),
        &["com.example.service"]
    );
}

#[test]
fn empty_optional_sections_map_to_present_empty_wire_sections() {
    let wire = adapt(EMPTY_OPTIONAL_SECTIONS_REQUEST_JSON);

    let lifecycle = wire.lifecycle.expect("lifecycle should be populated");
    assert!(lifecycle.destroy_on_exit.is_none());
    assert!(lifecycle.preserve_policy.is_none());

    let filesystem = wire.filesystem.expect("filesystem should be populated");
    assert!(filesystem.readwrite_paths.is_none());
    assert!(filesystem.readonly_paths.is_none());
    assert!(filesystem.denied_paths.is_none());

    let fallback = wire.fallback.expect("fallback should be populated");
    assert!(fallback.allow_dacl_mutation.is_none());

    let network = wire.network.expect("network should be populated");
    assert!(network.default_policy.is_none());
    assert!(network.enforcement_mode.is_none());
    assert!(network.allow_local_network.is_none());
    assert!(network.allowed_hosts.is_none());
    assert!(network.blocked_hosts.is_none());
    assert!(network.proxy.is_none());

    let ui = wire.ui.expect("ui should be populated");
    assert!(ui.disable.is_none());
    assert!(ui.clipboard.is_none());
    assert!(ui.injection.is_none());
}

#[test]
fn empty_process_container_section_maps_to_present_empty_wire_sections() {
    let wire = adapt(EMPTY_PROCESS_CONTAINER_SECTION_REQUEST_JSON);

    let process_container = wire
        .process_container
        .expect("processContainer should be populated");
    assert!(process_container.least_privilege.is_none());
    assert!(process_container.learning_mode.is_none());
    assert!(process_container.capabilities.is_none());
    assert!(process_container.capture_denials.is_none());
    assert!(process_container.ui.is_none());
}

#[test]
fn empty_process_container_ui_section_maps_to_present_empty_wire_section() {
    let wire = adapt(EMPTY_PROCESS_CONTAINER_UI_SECTION_REQUEST_JSON);

    let process_container = wire
        .process_container
        .expect("processContainer should be populated");

    assert!(process_container.least_privilege.is_none());
    assert!(process_container.learning_mode.is_none());
    assert!(process_container.capabilities.is_none());
    assert!(process_container.capture_denials.is_none());

    let ui = process_container
        .ui
        .expect("processContainer.ui should be populated");

    assert!(ui.isolation.is_none());
    assert!(ui.desktop_system_control.is_none());
    assert!(ui.system_settings.is_none());
    assert!(ui.ime.is_none());
}

#[test]
fn empty_seatbelt_section_maps_to_present_empty_wire_section() {
    let wire = adapt(EMPTY_SEATBELT_SECTION_REQUEST_JSON);

    let seatbelt = wire.seatbelt.expect("seatbelt should be populated");
    assert!(seatbelt.profile_override.is_none());
    assert!(seatbelt.gui_access.is_none());
    assert!(seatbelt.launch_method.is_none());
    assert!(seatbelt.nested_pty.is_none());
    assert!(seatbelt.keychain_access.is_none());
    assert!(seatbelt.system_power_access.is_none());
    assert!(seatbelt.extra_mach_lookups.is_none());
}

#[test]
fn annotations_map_expected_wire_fields() {
    let json = r#"{
        "$schema": "https://example.com/schema.json",
        "_comment": "This is a comment",
        "version": "0.9.0-alpha",
        "process": {"commandLine": "echo hello"}
    }"#;

    let wire = adapt(json);

    assert_eq!(
        wire.schema.as_deref(),
        Some("https://example.com/schema.json")
    );

    assert_eq!(
        wire.comment.as_ref(),
        Some(&serde_json::json!("This is a comment"))
    );
}

#[test]
fn comment_values_map_expected_wire_fields() {
    struct CommentCase {
        json: &'static str,
        expected: serde_json::Value,
    }

    let cases: &[CommentCase] = &[
        CommentCase {
            json: r#""plain comment""#,
            expected: serde_json::json!("plain comment"),
        },
        CommentCase {
            json: r#"{"purpose":"test","enabled":true}"#,
            expected: serde_json::json!({
                "purpose": "test",
                "enabled": true
            }),
        },
        CommentCase {
            json: r#"["first", 2, false]"#,
            expected: serde_json::json!(["first", 2, false]),
        },
        CommentCase {
            json: "42",
            expected: serde_json::json!(42),
        },
        CommentCase {
            json: "true",
            expected: serde_json::json!(true),
        },
    ];

    for case in cases {
        let json = request_with_comment(case.json);

        let wire = adapt(&json);

        assert_eq!(
            wire.comment.as_ref(),
            Some(&case.expected),
            "comment value did not match expected for input: {}",
            case.json
        );
    }
}

#[test]
fn null_comment_maps_expected_wire_field() {
    let json = request_with_comment("null");

    let wire = adapt(&json);

    assert_eq!(wire.comment.as_ref(), Some(&serde_json::Value::Null));
}

#[test]
fn proxy_variants_map_expected_wire_fields() {
    for case in PROXY_CASES {
        let json = request_with_proxy(case.json);

        let wire = adapt(&json);
        let proxy = wire
            .network
            .expect("network should be populated")
            .proxy
            .expect("proxy should be populated");

        assert_eq!(proxy.localhost, case.localhost);
        assert_eq!(proxy.builtin_test_server, case.builtin_test_server);
        assert_eq!(proxy.url.as_deref(), case.url);
    }
}

#[test]
fn enum_variants_map_expected_wire_values() {
    for case in STABLE_CONTAINMENT_CASES {
        let json = request_with_containment(case.input);
        let wire = adapt(&json);

        assert_eq!(
            serde_json::to_value(wire.containment.unwrap()).unwrap(),
            serde_json::json!(case.expected)
        );
    }

    for default_network_policy in DEFAULT_NETWORK_POLICY_CASES {
        let json = request_with_default_network_policy(default_network_policy);
        let wire = adapt(&json);

        assert_eq!(
            serde_json::to_value(
                wire.network
                    .unwrap()
                    .default_policy
                    .expect("defaultPolicy should be populated")
            )
            .unwrap(),
            serde_json::json!(default_network_policy)
        );
    }

    for network_enforcement_mode in NETWORK_ENFORCEMENT_MODE_CASES {
        let json = request_with_network_enforcement_mode(network_enforcement_mode);
        let wire = adapt(&json);

        assert_eq!(
            serde_json::to_value(
                wire.network
                    .unwrap()
                    .enforcement_mode
                    .expect("enforcementMode should be populated")
            )
            .unwrap(),
            serde_json::json!(network_enforcement_mode)
        );
    }

    for ui_clipboard in UI_CLIPBOARD_CASES {
        let json = request_with_ui_clipboard(ui_clipboard);
        let wire = adapt(&json);

        assert_eq!(
            serde_json::to_value(
                wire.ui
                    .unwrap()
                    .clipboard
                    .expect("clipboard should be populated")
            )
            .unwrap(),
            serde_json::json!(ui_clipboard)
        );
    }

    for process_container_ui_isolation in PROCESS_CONTAINER_UI_ISOLATION_CASES {
        let json = request_with_process_container_ui_isolation(process_container_ui_isolation);
        let wire = adapt(&json);

        assert_eq!(
            serde_json::to_value(
                wire.process_container
                    .unwrap()
                    .ui
                    .unwrap()
                    .isolation
                    .expect("isolation should be populated")
            )
            .unwrap(),
            serde_json::json!(process_container_ui_isolation)
        );
    }

    for capture_denials_mode in CAPTURE_DENIALS_MODE_CASES {
        let json = request_with_capture_denials_mode(capture_denials_mode);
        let wire = adapt(&json);

        assert_eq!(
            serde_json::to_value(
                wire.process_container
                    .unwrap()
                    .capture_denials
                    .unwrap()
                    .mode
                    .expect("mode should be populated")
            )
            .unwrap(),
            serde_json::json!(capture_denials_mode)
        );
    }

    for launch_method in SEATBELT_LAUNCH_METHOD_CASES {
        let json = request_with_seatbelt_launch_method(launch_method);
        let wire = adapt(&json);

        assert_eq!(
            serde_json::to_value(
                wire.seatbelt
                    .unwrap()
                    .launch_method
                    .expect("launchMethod should be populated")
            )
            .unwrap(),
            serde_json::json!(launch_method)
        );
    }
}

#[test]
fn app_container_section_alias_maps_expected_wire_fields() {
    let wire = adapt(APP_CONTAINER_SECTION_ALIAS_REQUEST_JSON);
    let process_container = wire
        .process_container
        .expect("appContainer should map to process_container");

    assert_eq!(process_container.least_privilege, Some(true));
    assert_eq!(
        process_container.capabilities.unwrap().as_slice(),
        &["internetClient"]
    );
    assert!(process_container.learning_mode.is_none());
    assert!(process_container.capture_denials.is_none());
    assert!(process_container.ui.is_none());
}

#[test]
fn macos_sandbox_section_alias_maps_expected_wire_fields() {
    let wire = adapt(MACOS_SANDBOX_SECTION_ALIAS_REQUEST_JSON);
    let seatbelt = wire.seatbelt.expect("macos_sandbox should map to seatbelt");

    assert_eq!(
        seatbelt.profile_override.as_deref(),
        Some("custom-profile.sb")
    );
    assert_eq!(seatbelt.gui_access, Some(true));
    assert!(matches!(
        seatbelt.launch_method,
        Some(super::wire::LaunchMethod::Open)
    ));
    assert_eq!(seatbelt.nested_pty, Some(true));
    assert_eq!(seatbelt.keychain_access, Some(true));
    assert_eq!(seatbelt.system_power_access, Some(true));
    assert_eq!(
        seatbelt.extra_mach_lookups.unwrap().as_slice(),
        &["com.example.service"]
    );
}

#[test]
fn process_container_additions_map_expected_wire_fields() {
    let wire = adapt(PROCESS_CONTAINER_ADDITIONS_REQUEST_JSON);

    assert!(matches!(
        wire.containment,
        Some(super::wire::Containment::ProcessContainer)
    ));

    let process_container = wire
        .process_container
        .expect("processContainer should be populated");

    assert_eq!(process_container.learning_mode, Some(true));
    assert!(process_container.least_privilege.is_none());
    assert!(process_container.capabilities.is_none());
    assert!(process_container.ui.is_none());

    let capture = process_container
        .capture_denials
        .expect("captureDenials should be populated");

    assert!(matches!(
        capture.mode,
        Some(super::wire::CaptureDenialsMode::Block)
    ));
    assert_eq!(capture.output_path.as_deref(), Some(r"C:\denials.json"));
    assert_eq!(capture.retain_etl, Some(true));
}

#[test]
fn minimal_request_matches_current_wire_deserialization() {
    let json = MINIMAL_REQUEST_JSON;
    assert_matches_current_wire_deserialization(json);
}

#[test]
fn process_container_request_matches_current_wire_deserialization() {
    let json = PROCESS_CONTAINER_REQUEST_JSON;
    assert_matches_current_wire_deserialization(json);
}

#[test]
fn lxc_request_matches_current_wire_deserialization() {
    let json = LXC_REQUEST_JSON;
    assert_matches_current_wire_deserialization(json);
}

#[test]
fn capture_denials_mode_variants_match_current_wire_deserialization() {
    for case in CAPTURE_DENIALS_MODE_CASES {
        let json = request_with_capture_denials_mode(case);
        assert_matches_current_wire_deserialization(&json);
    }
}

#[test]
fn process_container_additions_match_current_wire_deserialization() {
    assert_matches_current_wire_deserialization(PROCESS_CONTAINER_ADDITIONS_REQUEST_JSON);
}

#[test]
fn seatbelt_request_matches_current_wire_deserialization() {
    let json = SEATBELT_REQUEST_JSON;
    assert_matches_current_wire_deserialization(json);
}

#[test]
fn empty_optional_sections_match_current_wire_deserialization() {
    assert_matches_current_wire_deserialization(EMPTY_OPTIONAL_SECTIONS_REQUEST_JSON);
}

#[test]
fn empty_process_container_section_matches_current_wire_deserialization() {
    assert_matches_current_wire_deserialization(EMPTY_PROCESS_CONTAINER_SECTION_REQUEST_JSON);
}

#[test]
fn empty_process_container_ui_section_matches_current_wire_deserialization() {
    assert_matches_current_wire_deserialization(EMPTY_PROCESS_CONTAINER_UI_SECTION_REQUEST_JSON);
}

#[test]
fn empty_seatbelt_section_matches_current_wire_deserialization() {
    assert_matches_current_wire_deserialization(EMPTY_SEATBELT_SECTION_REQUEST_JSON);
}

#[test]
fn proxy_variants_match_current_wire_deserialization() {
    for case in PROXY_CASES {
        let json = request_with_proxy(case.json);
        assert_matches_current_wire_deserialization(&json);
    }
}

#[test]
fn enum_variants_match_current_wire_deserialization() {
    for case in STABLE_CONTAINMENT_CASES {
        let json = request_with_containment(case.input);
        assert_matches_current_wire_deserialization(&json);
    }

    for default_policy in DEFAULT_NETWORK_POLICY_CASES {
        let json = request_with_default_network_policy(default_policy);
        assert_matches_current_wire_deserialization(&json);
    }

    for enforcement_mode in NETWORK_ENFORCEMENT_MODE_CASES {
        let json = request_with_network_enforcement_mode(enforcement_mode);
        assert_matches_current_wire_deserialization(&json);
    }

    for clipboard in UI_CLIPBOARD_CASES {
        let json = request_with_ui_clipboard(clipboard);
        assert_matches_current_wire_deserialization(&json);
    }

    for isolation in PROCESS_CONTAINER_UI_ISOLATION_CASES {
        let json = request_with_process_container_ui_isolation(isolation);
        assert_matches_current_wire_deserialization(&json);
    }

    for launch_method in SEATBELT_LAUNCH_METHOD_CASES {
        let json = request_with_seatbelt_launch_method(launch_method);
        assert_matches_current_wire_deserialization(&json);
    }
}

#[test]
fn app_container_section_alias_matches_current_wire_deserialization() {
    assert_matches_current_wire_deserialization(APP_CONTAINER_SECTION_ALIAS_REQUEST_JSON);
}

#[test]
fn macos_sandbox_section_alias_matches_current_wire_deserialization() {
    assert_matches_current_wire_deserialization(MACOS_SANDBOX_SECTION_ALIAS_REQUEST_JSON);
}

#[test]
fn annotations_match_current_wire_deserialization() {
    let json = r#"{
            "$schema": "https://example.com/schema.json",
            "_comment": "This is a comment",
            "version": "0.9.0-alpha",
            "process": {"commandLine": "echo hello"}
        }"#;

    assert_matches_current_wire_deserialization(json);
}

const DIRECTIONAL_NETWORK_REQUEST_JSON: &str = r#"{
    "version": "0.9.0-alpha",
    "containment": "processcontainer",
    "process": {"commandLine": "echo hello"},
    "runtimeConfig": {"networkProxy": "http://127.0.0.1:8080"},
    "processContainer": {"network": {"allowedProxyPeer": "127.0.0.1"}},
    "network": {
        "egress": {
            "default": "deny",
            "allow": [
                {
                    "to": [
                        {"cidr": "140.82.112.0/20", "except": ["140.82.113.0/24"]},
                        {"cidr": "2606:50c0::/32"}
                    ],
                    "ports": [
                        {"port": 443, "protocol": "tcp"},
                        {"port": 30000, "endPort": 30100, "protocol": "udp"}
                    ]
                },
                {"ports": [{"protocol": "icmp"}]},
                {"to": [{"cidr": "198.51.100.0/24"}]}
            ],
            "deny": [
                {"to": [{"cidr": "10.0.0.0/8"}], "ports": [{"port": 25, "protocol": "any"}]}
            ]
        },
        "ingress": {"default": "deny", "hostLoopback": "allow"}
    }
}"#;

#[test]
fn directional_network_request_maps_expected_wire_fields() {
    let wire = adapt(DIRECTIONAL_NETWORK_REQUEST_JSON);

    let runtime_config = wire
        .runtime_config
        .expect("runtimeConfig should be populated");
    assert_eq!(
        runtime_config.network_proxy.as_deref(),
        Some("http://127.0.0.1:8080")
    );

    let process_container = wire
        .process_container
        .expect("processContainer should be populated");
    let pc_network = process_container
        .network
        .expect("processContainer.network should be populated");
    assert_eq!(pc_network.allowed_proxy_peer.as_deref(), Some("127.0.0.1"));

    let network = wire.network.expect("network should be populated");

    let egress = network.egress.expect("egress should be populated");
    assert!(matches!(
        egress.default,
        Some(super::wire::NetworkAction::Deny)
    ));

    let allow = egress.allow.expect("egress.allow should be populated");
    assert_eq!(allow.len(), 3);

    // First rule: two destinations, one carrying an exception list, and two
    // port selectors including an inclusive range.
    let first_to = allow[0].to.as_ref().expect("rule should carry to");
    assert_eq!(first_to.len(), 2);
    assert_eq!(first_to[0].cidr, "140.82.112.0/20");
    assert_eq!(
        first_to[0].except.as_deref(),
        Some(["140.82.113.0/24".to_string()].as_slice())
    );
    assert_eq!(first_to[1].cidr, "2606:50c0::/32");
    assert!(first_to[1].except.is_none());

    let first_ports = allow[0].ports.as_ref().expect("rule should carry ports");
    assert_eq!(first_ports.len(), 2);
    assert_eq!(first_ports[0].port, Some(443));
    assert!(first_ports[0].end_port.is_none());
    assert!(matches!(
        first_ports[0].protocol,
        Some(super::wire::NetworkProtocol::Tcp)
    ));
    assert_eq!(first_ports[1].port, Some(30000));
    assert_eq!(first_ports[1].end_port, Some(30100));
    assert!(matches!(
        first_ports[1].protocol,
        Some(super::wire::NetworkProtocol::Udp)
    ));

    // Second rule: ports without destinations.
    assert!(allow[1].to.is_none());
    let icmp_ports = allow[1].ports.as_ref().expect("rule should carry ports");
    assert!(matches!(
        icmp_ports[0].protocol,
        Some(super::wire::NetworkProtocol::Icmp)
    ));
    assert!(icmp_ports[0].port.is_none());

    // Third rule: destinations without ports.
    assert!(allow[2].ports.is_none());
    assert_eq!(
        allow[2].to.as_ref().expect("rule should carry to")[0].cidr,
        "198.51.100.0/24"
    );

    let deny = egress.deny.expect("egress.deny should be populated");
    assert_eq!(deny.len(), 1);
    assert_eq!(
        deny[0].to.as_ref().expect("rule should carry to")[0].cidr,
        "10.0.0.0/8"
    );
    let deny_ports = deny[0].ports.as_ref().expect("rule should carry ports");
    assert_eq!(deny_ports[0].port, Some(25));
    assert!(matches!(
        deny_ports[0].protocol,
        Some(super::wire::NetworkProtocol::Any)
    ));

    let ingress = network.ingress.expect("ingress should be populated");
    assert!(matches!(
        ingress.default,
        Some(super::wire::NetworkAction::Deny)
    ));
    assert!(matches!(
        ingress.host_loopback,
        Some(super::wire::NetworkAction::Allow)
    ));

    // The legacy fields stay absent when only directional policy is supplied.
    assert!(network.default_policy.is_none());
    assert!(network.enforcement_mode.is_none());
    assert!(network.proxy.is_none());
}

#[test]
fn directional_network_request_matches_current_wire_deserialization() {
    assert_matches_current_wire_deserialization(DIRECTIONAL_NETWORK_REQUEST_JSON);
}

#[test]
fn every_network_action_maps_to_the_expected_wire_value() {
    for declared in ["allow", "deny"] {
        let expected = declared;
        let json = format!(
            r#"{{
                "version": "0.9.0-alpha",
                "process": {{"commandLine": "echo hello"}},
                "network": {{
                    "egress": {{"default": "{declared}"}},
                    "ingress": {{"default": "{declared}", "hostLoopback": "{declared}"}}
                }}
            }}"#
        );

        let network = adapt(&json).network.expect("network should be populated");
        let egress_default = network.egress.expect("egress").default;
        assert_eq!(
            serde_json::to_value(egress_default).unwrap(),
            serde_json::json!(expected)
        );
        let ingress = network.ingress.expect("ingress");
        assert_eq!(
            serde_json::to_value(ingress.default).unwrap(),
            serde_json::json!(expected)
        );
        assert_eq!(
            serde_json::to_value(ingress.host_loopback).unwrap(),
            serde_json::json!(expected)
        );

        assert_matches_current_wire_deserialization(&json);
    }
}

#[test]
fn every_network_protocol_maps_to_the_expected_wire_value() {
    for declared in ["tcp", "udp", "icmp", "any"] {
        let expected = declared;
        let json = format!(
            r#"{{
                "version": "0.9.0-alpha",
                "process": {{"commandLine": "echo hello"}},
                "network": {{
                    "egress": {{"allow": [{{"ports": [{{"protocol": "{declared}"}}]}}]}}
                }}
            }}"#
        );

        let network = adapt(&json).network.expect("network should be populated");
        let allow = network.egress.expect("egress").allow.expect("allow");
        let ports = allow[0].ports.as_ref().expect("ports");
        assert_eq!(
            serde_json::to_value(ports[0].protocol).unwrap(),
            serde_json::json!(expected)
        );

        assert_matches_current_wire_deserialization(&json);
    }
}

#[test]
fn absent_directional_network_sections_stay_absent() {
    let wire = adapt(MINIMAL_REQUEST_JSON);

    assert!(wire.runtime_config.is_none());
    assert!(wire.network.is_none());
}
