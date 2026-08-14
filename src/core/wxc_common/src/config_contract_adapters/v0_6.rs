// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use crate::wire;
use mxc_config_contract::published::v0_6_0_alpha as contract;
use mxc_config_contract::ContractVersion;

fn convert_version(value: contract::Version) -> &'static str {
    match value {
        contract::Version::V0_6_0Alpha => ContractVersion::V0_6_0Alpha.as_str(),
    }
}

fn convert_containment(value: contract::Containment) -> wire::Containment {
    match value {
        contract::Containment::Process => wire::Containment::Process,
        contract::Containment::ProcessContainer => wire::Containment::ProcessContainer,
        contract::Containment::Lxc => wire::Containment::Lxc,
        contract::Containment::Bubblewrap => wire::Containment::Bubblewrap,
    }
}

fn convert_process(value: contract::Process) -> wire::Process {
    let contract::Process {
        command_line,
        cwd,
        env,
        timeout,
    } = value;
    wire::Process {
        command_line: Some(command_line.into_inner()),
        cwd: cwd.into_option(),
        env: env.into_option(),
        timeout: timeout.into_option(),
    }
}

fn convert_lifecycle(value: contract::Lifecycle) -> wire::Lifecycle {
    let contract::Lifecycle {
        destroy_on_exit,
        preserve_policy,
    } = value;
    wire::Lifecycle {
        destroy_on_exit: destroy_on_exit.into_option(),
        preserve_policy: preserve_policy.into_option(),
    }
}

fn convert_filesystem(value: contract::Filesystem) -> wire::Filesystem {
    let contract::Filesystem {
        readwrite_paths,
        readonly_paths,
        denied_paths,
    } = value;
    wire::Filesystem {
        readwrite_paths: readwrite_paths.into_option(),
        readonly_paths: readonly_paths.into_option(),
        denied_paths: denied_paths.into_option(),
    }
}

fn convert_fallback(value: contract::Fallback) -> wire::Fallback {
    let contract::Fallback {
        allow_dacl_mutation,
    } = value;
    wire::Fallback {
        allow_dacl_mutation: allow_dacl_mutation.into_option(),
    }
}

fn convert_default_network_policy(value: contract::DefaultNetworkPolicy) -> wire::NetworkPolicy {
    match value {
        contract::DefaultNetworkPolicy::Allow => wire::NetworkPolicy::Allow,
        contract::DefaultNetworkPolicy::Block => wire::NetworkPolicy::Block,
    }
}

fn convert_network_enforcement_mode(
    value: contract::NetworkEnforcementMode,
) -> wire::NetworkEnforcement {
    match value {
        contract::NetworkEnforcementMode::Capabilities => wire::NetworkEnforcement::Capabilities,
        contract::NetworkEnforcementMode::Firewall => wire::NetworkEnforcement::Firewall,
        contract::NetworkEnforcementMode::Both => wire::NetworkEnforcement::Both,
    }
}

fn convert_network(value: contract::Network) -> wire::Network {
    let contract::Network {
        default_policy,
        enforcement_mode,
        allow_local_network,
        allowed_hosts,
        blocked_hosts,
        proxy,
    } = value;
    wire::Network {
        default_policy: default_policy
            .into_option()
            .map(convert_default_network_policy),
        enforcement_mode: enforcement_mode
            .into_option()
            .map(convert_network_enforcement_mode),
        allow_local_network: allow_local_network.into_option(),
        allowed_hosts: allowed_hosts.into_option(),
        blocked_hosts: blocked_hosts.into_option(),
        proxy: proxy.into_option().map(convert_proxy),
    }
}

fn convert_proxy(value: contract::NetworkProxy) -> wire::Proxy {
    match value {
        contract::NetworkProxy::Localhost(port) => wire::Proxy {
            localhost: Some(port.get()),
            builtin_test_server: None,
            url: None,
        },
        contract::NetworkProxy::BuiltinTestServer(contract::True) => wire::Proxy {
            localhost: None,
            builtin_test_server: Some(true),
            url: None,
        },
        contract::NetworkProxy::Url(url) => wire::Proxy {
            localhost: None,
            builtin_test_server: None,
            url: Some(url),
        },
    }
}

fn convert_clipboard(value: contract::UiClipboard) -> wire::ClipboardPolicy {
    match value {
        contract::UiClipboard::None => wire::ClipboardPolicy::None,
        contract::UiClipboard::Read => wire::ClipboardPolicy::Read,
        contract::UiClipboard::Write => wire::ClipboardPolicy::Write,
        contract::UiClipboard::All => wire::ClipboardPolicy::All,
    }
}

fn convert_ui(value: contract::Ui) -> wire::Ui {
    let contract::Ui {
        disable,
        clipboard,
        injection,
    } = value;
    wire::Ui {
        disable: disable.into_option(),
        clipboard: clipboard.into_option().map(convert_clipboard),
        injection: injection.into_option(),
    }
}

fn convert_process_container(value: contract::ProcessContainer) -> wire::ProcessContainer {
    let contract::ProcessContainer {
        least_privilege,
        capabilities,
        ui,
    } = value;
    wire::ProcessContainer {
        least_privilege: least_privilege.into_option(),
        learning_mode: None,
        capabilities: capabilities.into_option(),
        capture_denials: None,
        ui: ui.into_option().map(convert_process_container_ui),
    }
}

fn convert_process_container_ui_isolation(
    value: contract::ProcessContainerUiIsolation,
) -> wire::UiIsolation {
    match value {
        contract::ProcessContainerUiIsolation::Container => wire::UiIsolation::Container,
        contract::ProcessContainerUiIsolation::Desktop => wire::UiIsolation::Desktop,
        contract::ProcessContainerUiIsolation::Handles => wire::UiIsolation::Handles,
        contract::ProcessContainerUiIsolation::Atoms => wire::UiIsolation::Atoms,
    }
}

fn convert_process_container_ui(value: contract::ProcessContainerUi) -> wire::BaseProcessUi {
    let contract::ProcessContainerUi {
        isolation,
        desktop_system_control,
        system_settings,
        ime,
    } = value;
    wire::BaseProcessUi {
        isolation: isolation
            .into_option()
            .map(convert_process_container_ui_isolation),
        desktop_system_control: desktop_system_control.into_option(),
        system_settings: system_settings.into_option(),
        ime: ime.into_option(),
    }
}

fn convert_lxc(value: contract::Lxc) -> wire::Lxc {
    let contract::Lxc {
        distribution,
        release,
    } = value;
    wire::Lxc {
        distribution: Some(distribution),
        release: Some(release),
    }
}

pub(crate) fn into_wire(request: contract::Request) -> wire::MxcConfig {
    let contract::Request {
        version,
        container_id,
        containment,
        lifecycle,
        process,
        filesystem,
        fallback,
        network,
        lxc,
        process_container,
        ui,
    } = request;
    wire::MxcConfig {
        schema: None,
        comment: None,
        version: Some(convert_version(version).to_owned()),
        phase: None,
        sandbox_id: None,
        correlation_vector: None,
        container_id: container_id.into_option(),
        containment: containment.into_option().map(convert_containment),
        process: Some(convert_process(process)),
        lifecycle: lifecycle.into_option().map(convert_lifecycle),
        process_container: process_container
            .into_option()
            .map(convert_process_container),
        lxc: lxc.into_option().map(convert_lxc),
        filesystem: filesystem.into_option().map(convert_filesystem),
        fallback: fallback.into_option().map(convert_fallback),
        network: network.into_option().map(convert_network),
        ui: ui.into_option().map(convert_ui),
        seatbelt: None,
        experimental: None,
    }
}

#[cfg(test)]
mod tests {

    const MINIMAL_REQUEST_JSON: &str = r#"{
        "version": "0.6.0-alpha",
        "process": {
            "commandLine": "echo hello"
        }
    }"#;

    const COMPLETE_PROCESS_CONTAINER_REQUEST_JSON: &str = r#"{
        "version": "0.6.0-alpha",
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

    const COMPLETE_LXC_REQUEST_JSON: &str = r#"{
        "version": "0.6.0-alpha",
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
            "enforcementMode": "capabilities",
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

    const EMPTY_OPTIONAL_SECTIONS_REQUEST_JSON: &str = r#"{
        "version": "0.6.0-alpha",
        "process": {
            "commandLine": "echo hello"
        },
        "lifecycle": {},
        "filesystem": {},
        "fallback": {},
        "network": {},
        "ui": {},
        "processContainer": {
            "ui": {}
        }
    }"#;

    const APP_CONTAINER_FIELD_ALIAS_REQUEST_JSON: &str = r#"{
        "version": "0.6.0-alpha",
        "process": {
            "commandLine": "echo hello"
        },
        "appContainer": {
            "leastPrivilege": true,
            "capabilities": ["internetClient"]
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

    struct ContainmentCase {
        input: &'static str,
        expected: &'static str,
    }

    const CONTAINMENT_CASES: &[ContainmentCase] = &[
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
    ];

    const DEFAULT_NETWORK_POLICY_CASES: &[&str] = &["allow", "block"];

    const NETWORK_ENFORCEMENT_MODE_CASES: &[&str] = &["capabilities", "firewall", "both"];

    const UI_CLIPBOARD_CASES: &[&str] = &["none", "read", "write", "all"];

    const PROCESS_CONTAINER_UI_ISOLATION_CASES: &[&str] =
        &["container", "desktop", "handles", "atoms"];

    fn request_with_proxy(proxy_json: &str) -> String {
        format!(
            r#"{{
                "version": "0.6.0-alpha",
                "process": {{"commandLine": "echo hello"}},
                "network": {{"proxy": {proxy_json}}}
            }}"#
        )
    }

    fn request_with_containment(containment: &str) -> String {
        format!(
            r#"{{
                "version": "0.6.0-alpha",
                "containment": "{containment}",
                "process": {{"commandLine": "echo hello"}}
            }}"#
        )
    }

    fn request_with_default_network_policy(default_policy: &str) -> String {
        format!(
            r#"{{
                "version": "0.6.0-alpha",
                "process": {{"commandLine": "echo hello"}},
                "network": {{"defaultPolicy": "{default_policy}"}}
            }}"#
        )
    }

    fn request_with_network_enforcement_mode(enforcement_mode: &str) -> String {
        format!(
            r#"{{
                "version": "0.6.0-alpha",
                "process": {{"commandLine": "echo hello"}},
                "network": {{"enforcementMode": "{enforcement_mode}"}}
            }}"#
        )
    }

    fn request_with_ui_clipboard(clipboard: &str) -> String {
        format!(
            r#"{{
                "version": "0.6.0-alpha",
                "process": {{"commandLine": "echo hello"}},
                "ui": {{"clipboard": "{clipboard}"}}
            }}"#
        )
    }

    fn request_with_process_container_ui_isolation(isolation: &str) -> String {
        format!(
            r#"{{
                "version": "0.6.0-alpha",
                "process": {{"commandLine": "echo hello"}},
                "processContainer": {{"ui": {{"isolation": "{isolation}"}}}}
            }}"#
        )
    }

    #[test]
    fn minimal_request_maps_expected_wire_fields() {
        let json = MINIMAL_REQUEST_JSON;

        let request: super::contract::Request = serde_json::from_str(json).unwrap();
        let wire = super::into_wire(request);

        assert!(wire.schema.is_none());
        assert!(wire.comment.is_none());
        assert_eq!(wire.version, Some("0.6.0-alpha".to_string()));
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
    fn complete_process_container_request_maps_expected_wire_fields() {
        let json = COMPLETE_PROCESS_CONTAINER_REQUEST_JSON;

        let request: super::contract::Request = serde_json::from_str(json).unwrap();
        let wire = super::into_wire(request);

        assert!(wire.schema.is_none());
        assert!(wire.comment.is_none());
        assert_eq!(wire.version, Some("0.6.0-alpha".to_string()));
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
    fn complete_lxc_request_maps_expected_wire_fields() {
        let json = COMPLETE_LXC_REQUEST_JSON;

        let request: super::contract::Request = serde_json::from_str(json).unwrap();
        let wire = super::into_wire(request);

        assert!(wire.schema.is_none());
        assert!(wire.comment.is_none());
        assert_eq!(wire.version, Some("0.6.0-alpha".to_string()));
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
            Some(super::wire::NetworkEnforcement::Capabilities)
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
    fn empty_optional_sections_map_to_present_empty_wire_sections() {
        let request: super::contract::Request =
            serde_json::from_str(EMPTY_OPTIONAL_SECTIONS_REQUEST_JSON).unwrap();
        let wire = super::into_wire(request);

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

        let process_container = wire
            .process_container
            .expect("processContainer should be populated");
        assert!(process_container.least_privilege.is_none());
        assert!(process_container.learning_mode.is_none());
        assert!(process_container.capabilities.is_none());
        assert!(process_container.capture_denials.is_none());

        let process_container_ui = process_container
            .ui
            .expect("processContainer.ui should be populated");
        assert!(process_container_ui.isolation.is_none());
        assert!(process_container_ui.desktop_system_control.is_none());
        assert!(process_container_ui.system_settings.is_none());
        assert!(process_container_ui.ime.is_none());
    }

    #[test]
    fn proxy_variants_map_expected_wire_fields() {
        for case in PROXY_CASES {
            let json = request_with_proxy(case.json);

            let request: super::contract::Request = serde_json::from_str(&json).unwrap();
            let wire = super::into_wire(request);
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
        for case in CONTAINMENT_CASES {
            let json = request_with_containment(case.input);
            let request: super::contract::Request = serde_json::from_str(&json).unwrap();
            let wire = super::into_wire(request);

            assert_eq!(
                serde_json::to_value(wire.containment.unwrap()).unwrap(),
                serde_json::json!(case.expected)
            );
        }

        for default_network_policy in DEFAULT_NETWORK_POLICY_CASES {
            let json = request_with_default_network_policy(default_network_policy);
            let request: super::contract::Request = serde_json::from_str(&json).unwrap();
            let wire = super::into_wire(request);

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
            let request: super::contract::Request = serde_json::from_str(&json).unwrap();
            let wire = super::into_wire(request);

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
            let request: super::contract::Request = serde_json::from_str(&json).unwrap();
            let wire = super::into_wire(request);

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
            let request: super::contract::Request = serde_json::from_str(&json).unwrap();
            let wire = super::into_wire(request);

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
    }

    #[test]
    fn app_container_field_alias_maps_expected_wire_fields() {
        let request: super::contract::Request =
            serde_json::from_str(APP_CONTAINER_FIELD_ALIAS_REQUEST_JSON).unwrap();
        let wire = super::into_wire(request);
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

    fn assert_matches_current_wire_deserialization(json: &str) {
        let current: super::wire::MxcConfig = crate::config_deserialize::from_str(json).unwrap();
        let contract: super::contract::Request = serde_json::from_str(json).unwrap();
        let adapted = super::into_wire(contract);

        assert_eq!(
            serde_json::to_value(adapted).unwrap(),
            serde_json::to_value(current).unwrap()
        );
    }

    #[test]
    fn minimal_request_matches_current_wire_deserialization() {
        let json = MINIMAL_REQUEST_JSON;
        assert_matches_current_wire_deserialization(json);
    }

    #[test]
    fn complete_process_container_request_matches_current_wire_deserialization() {
        let json = COMPLETE_PROCESS_CONTAINER_REQUEST_JSON;
        assert_matches_current_wire_deserialization(json);
    }

    #[test]
    fn complete_lxc_request_matches_current_wire_deserialization() {
        let json = COMPLETE_LXC_REQUEST_JSON;
        assert_matches_current_wire_deserialization(json);
    }

    #[test]
    fn empty_optional_sections_match_current_wire_deserialization() {
        assert_matches_current_wire_deserialization(EMPTY_OPTIONAL_SECTIONS_REQUEST_JSON);
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
        for case in CONTAINMENT_CASES {
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
    }

    #[test]
    fn app_container_field_alias_matches_current_wire_deserialization() {
        assert_matches_current_wire_deserialization(APP_CONTAINER_FIELD_ALIAS_REQUEST_JSON);
    }
}
