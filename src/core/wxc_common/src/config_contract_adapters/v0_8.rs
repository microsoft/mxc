// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use crate::wire;
use mxc_config_contract::published::v0_8_0_alpha as contract;
use mxc_config_contract::ContractVersion;

fn convert_version(value: contract::Version) -> &'static str {
    match value {
        contract::Version::V0_8_0Alpha => ContractVersion::V0_8_0Alpha.as_str(),
    }
}

fn convert_containment(value: contract::Containment) -> wire::Containment {
    match value {
        contract::Containment::Process => wire::Containment::Process,
        contract::Containment::ProcessContainer => wire::Containment::ProcessContainer,
        contract::Containment::Lxc => wire::Containment::Lxc,
        contract::Containment::Bubblewrap => wire::Containment::Bubblewrap,
        contract::Containment::Seatbelt => wire::Containment::Seatbelt,
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

fn convert_network_action(value: contract::NetworkAction) -> wire::NetworkAction {
    match value {
        contract::NetworkAction::Allow => wire::NetworkAction::Allow,
        contract::NetworkAction::Deny => wire::NetworkAction::Deny,
    }
}

fn convert_network_peer(value: contract::NetworkPeer) -> wire::NetworkPeer {
    let contract::NetworkPeer { cidr, except } = value;
    wire::NetworkPeer {
        cidr,
        except: except.into_option(),
    }
}

fn convert_network_peers(value: Vec<contract::NetworkPeer>) -> Vec<wire::NetworkPeer> {
    value.into_iter().map(convert_network_peer).collect()
}

fn convert_network_protocol(value: contract::NetworkProtocol) -> wire::NetworkProtocol {
    match value {
        contract::NetworkProtocol::Tcp => wire::NetworkProtocol::Tcp,
        contract::NetworkProtocol::Udp => wire::NetworkProtocol::Udp,
        contract::NetworkProtocol::Icmp => wire::NetworkProtocol::Icmp,
        contract::NetworkProtocol::Any => wire::NetworkProtocol::Any,
    }
}

fn convert_network_port(value: contract::NetworkPort) -> wire::NetworkPort {
    let contract::NetworkPort {
        protocol,
        port,
        end_port,
    } = value;
    wire::NetworkPort {
        protocol: protocol.into_option().map(convert_network_protocol),
        port: port.into_option().map(|p| p.get()),
        end_port: end_port.into_option().map(|p| p.get()),
    }
}

fn convert_network_ports(value: Vec<contract::NetworkPort>) -> Vec<wire::NetworkPort> {
    value.into_iter().map(convert_network_port).collect()
}

fn convert_network_rule(value: contract::NetworkRule) -> wire::NetworkRule {
    let contract::NetworkRule { to, ports } = value;
    wire::NetworkRule {
        to: to
            .into_option()
            .map(|to| convert_network_peers(to.into_inner())),
        ports: ports
            .into_option()
            .map(|ports| convert_network_ports(ports.into_inner())),
    }
}

fn convert_network_rules(value: Vec<contract::NetworkRule>) -> Vec<wire::NetworkRule> {
    value.into_iter().map(convert_network_rule).collect()
}

fn convert_network_egress(value: contract::NetworkEgress) -> wire::NetworkEgress {
    let contract::NetworkEgress {
        default,
        allow,
        deny,
    } = value;
    wire::NetworkEgress {
        default: default.into_option().map(convert_network_action),
        allow: allow.into_option().map(convert_network_rules),
        deny: deny.into_option().map(convert_network_rules),
    }
}

fn convert_network_ingress(value: contract::NetworkIngress) -> wire::NetworkIngress {
    let contract::NetworkIngress {
        default,
        host_loopback,
    } = value;
    wire::NetworkIngress {
        default: default.into_option().map(convert_network_action),
        host_loopback: host_loopback.into_option().map(convert_network_action),
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
        egress,
        ingress,
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
        egress: egress.into_option().map(convert_network_egress),
        ingress: ingress.into_option().map(convert_network_ingress),
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

fn convert_capture_denials_mode(value: contract::CaptureDenialsMode) -> wire::CaptureDenialsMode {
    match value {
        contract::CaptureDenialsMode::Allow => wire::CaptureDenialsMode::Allow,
        contract::CaptureDenialsMode::Block => wire::CaptureDenialsMode::Block,
    }
}

fn convert_capture_denials(value: contract::CaptureDenials) -> wire::CaptureDenials {
    let contract::CaptureDenials {
        mode,
        output_path,
        retain_etl,
    } = value;
    wire::CaptureDenials {
        mode: mode.into_option().map(convert_capture_denials_mode),
        output_path: output_path.into_option(),
        retain_etl: retain_etl.into_option(),
    }
}

fn convert_process_container(value: contract::ProcessContainer) -> wire::ProcessContainer {
    let contract::ProcessContainer {
        least_privilege,
        learning_mode,
        capabilities,
        capture_denials,
        network,
        ui,
    } = value;
    wire::ProcessContainer {
        least_privilege: least_privilege.into_option(),
        learning_mode: learning_mode.into_option(),
        capabilities: capabilities.into_option().map(|capabilities| {
            capabilities
                .into_iter()
                .map(contract::ProcessContainerCapability::into_inner)
                .collect()
        }),
        capture_denials: capture_denials.into_option().map(convert_capture_denials),
        network: network.into_option().map(convert_process_container_network),
        ui: ui.into_option().map(convert_process_container_ui),
    }
}

fn convert_process_container_network(
    value: contract::ProcessContainerNetwork,
) -> wire::ProcessContainerNetwork {
    let contract::ProcessContainerNetwork { allowed_proxy_peer } = value;
    wire::ProcessContainerNetwork {
        allowed_proxy_peer: allowed_proxy_peer.into_option(),
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

fn convert_launch_method(value: contract::LaunchMethod) -> wire::LaunchMethod {
    match value {
        contract::LaunchMethod::Exec => wire::LaunchMethod::Exec,
        contract::LaunchMethod::Open => wire::LaunchMethod::Open,
    }
}

fn convert_seatbelt(value: contract::Seatbelt) -> wire::Seatbelt {
    let contract::Seatbelt {
        profile_override,
        gui_access,
        launch_method,
        nested_pty,
        keychain_access,
        extra_mach_lookups,
    } = value;
    wire::Seatbelt {
        profile_override: profile_override.into_option(),
        gui_access: gui_access.into_option(),
        launch_method: launch_method.into_option().map(convert_launch_method),
        nested_pty: nested_pty.into_option(),
        keychain_access: keychain_access.into_option(),
        extra_mach_lookups: extra_mach_lookups.into_option(),
    }
}

fn convert_runtime_config(value: contract::RuntimeConfig) -> wire::RuntimeConfig {
    let contract::RuntimeConfig { network_proxy } = value;
    wire::RuntimeConfig {
        network_proxy: network_proxy.into_option(),
    }
}

pub(crate) fn into_wire(request: contract::Request) -> wire::MxcConfig {
    let contract::Request {
        schema,
        comment,
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
        seatbelt,
        runtime_config,
    } = request;
    wire::MxcConfig {
        schema: schema.into_option(),
        comment: comment.into_option(),
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
        seatbelt: seatbelt.into_option().map(convert_seatbelt),
        runtime_config: runtime_config.into_option().map(convert_runtime_config),
        experimental: None,
    }
}

#[cfg(test)]
mod tests {

    const MINIMAL_REQUEST_JSON: &str = r#"{
        "version": "0.8.0-alpha",
        "process": {
            "commandLine": "echo hello"
        }
    }"#;

    const COMPLETE_PROCESS_CONTAINER_REQUEST_JSON: &str = r#"{
        "version": "0.8.0-alpha",
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

    const DIRECTIONAL_NETWORK_REQUEST_JSON: &str = r#"{
        "$schema": "https://github.com/microsoft/mxc/blob/main/schemas/stable/mxc-config.schema.0.8.0-alpha.json",
        "_comment": "Model 1 egress: deny by default, with explicit L3/L4 allowances.",
        "version": "0.8.0-alpha",
        "containerId": "container-id",
        "containment": "processcontainer",
        "lifecycle": {
            "destroyOnExit": true,
            "preservePolicy": true
        },
        "process": {
            "commandLine": "curl -sS https://api.github.com/zen",
            "cwd": "/home/user",
            "env": [
                "VAR1=value1", "VAR2=value2"
            ],
            "timeout": 60000
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
            "egress": {
                "default": "deny",
                "allow": [
                    {
                        "to": [
                            {
                                "cidr": "140.82.112.0/20",
                                "except": ["140.82.113.0/24", "140.82.114.32/27"]
                            },
                            {"cidr": "2606:50c0::/32"}
                        ],
                        "ports": [
                            {"protocol": "tcp", "port": 443},
                            {"protocol": "tcp", "port": 8000, "endPort": 8080}
                        ]
                    },
                    {
                        "to": [{"cidr": "192.0.2.10/32"}],
                        "ports": [
                            {"protocol": "udp", "port": 30000, "endPort": 30100},
                            {"protocol": "any", "port": 22}
                        ]
                    },
                    {
                        "ports": [
                            {"protocol": "udp", "port": 53},
                            {"protocol": "tcp", "port": 53}
                        ]
                    },
                    {
                        "to": [
                            {"cidr": "198.51.100.0/24"},
                            {"cidr": "2001:db8::/32", "except": ["2001:db8:1::/48"]}
                        ]
                    },
                    {
                        "to": [{"cidr": "203.0.113.7/32"}],
                        "ports": [{"protocol": "icmp"}]
                    }
                ],
                "deny": [
                    {
                        "to": [
                            {"cidr": "10.0.0.0/8"},
                            {"cidr": "172.16.0.0/12"},
                            {"cidr": "192.168.0.0/16"}
                        ]
                    },
                    {
                        "to": [{"cidr": "0.0.0.0/0"}],
                        "ports": [
                            {"protocol": "tcp", "port": 25},
                            {"protocol": "tcp", "port": 445}
                        ]
                    }
                ]
            },
            "ingress": {
                "default": "deny",
                "hostLoopback": "allow"
            }
        },
        "ui": {
            "disable": true,
            "clipboard": "all",
            "injection": true
        },
        "processContainer": {
            "leastPrivilege": true,
            "learningMode": true,
            "capabilities": ["internetClient", "registryRead"],
            "captureDenials": {
                "mode": "block",
                "outputPath": "/path/to/denials.json",
                "retainEtl": false
            },
            "network": {
                "allowedProxyPeer": "127.0.0.1"
            },
            "ui": {
                "isolation": "container",
                "desktopSystemControl": true,
                "systemSettings": "none",
                "ime": true
            }
        },
        "runtimeConfig": {
            "networkProxy": "http://proxy.example:8080"
        }
    }"#;

    const EMPTY_DIRECTIONAL_SECTIONS_REQUEST_JSON: &str = r#"{
        "version": "0.8.0-alpha",
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
            "egress": {},
            "ingress": {}
        },
        "ui": {
            "disable": true,
            "clipboard": "all",
            "injection": true
        },
        "processContainer": {
            "leastPrivilege": true,
            "capabilities": ["cap1", "cap2"],
            "network": {},
            "ui": {
                "isolation": "container",
                "desktopSystemControl": true,
                "systemSettings": "none",
                "ime": true
            }
        },
        "runtimeConfig": {}
    }"#;

    const COMPLETE_LXC_REQUEST_JSON: &str = r#"{
        "version": "0.8.0-alpha",
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

    const COMPLETE_SEATBELT_REQUEST_JSON: &str = r#"{
        "version": "0.8.0-alpha",
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
            "extraMachLookups": ["com.example.service"]
        }
    }"#;

    const EMPTY_OPTIONAL_SECTIONS_REQUEST_JSON: &str = r#"{
        "version": "0.8.0-alpha",
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
        "version": "0.8.0-alpha",
        "containment": "processcontainer",
        "process": {
            "commandLine": "echo hello"
        },
        "processContainer": {}
    }"#;

    const EMPTY_PROCESS_CONTAINER_UI_SECTION_REQUEST_JSON: &str = r#"{
        "version": "0.8.0-alpha",
        "containment": "processcontainer",
        "process": {
            "commandLine": "echo hello"
        },
        "processContainer": {
            "ui": {}
        }
    }"#;

    const EMPTY_SEATBELT_SECTION_REQUEST_JSON: &str = r#"{
        "version": "0.8.0-alpha",
        "containment": "seatbelt",
        "process": {
            "commandLine": "echo hello"
        },
        "seatbelt": {}
    }"#;

    const APP_CONTAINER_SECTION_ALIAS_REQUEST_JSON: &str = r#"{
        "version": "0.8.0-alpha",
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
        "version": "0.8.0-alpha",
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

    const PROCESS_CONTAINER_UI_ISOLATION_CASES: &[&str] =
        &["container", "desktop", "handles", "atoms"];

    const SEATBELT_LAUNCH_METHOD_CASES: &[&str] = &["exec", "open"];

    fn request_with_comment(comment: &str) -> String {
        format!(
            r#"{{
                "version": "0.8.0-alpha",
                "_comment": {comment},
                "process": {{"commandLine": "echo hello"}}
            }}"#
        )
    }

    fn request_with_proxy(proxy_json: &str) -> String {
        format!(
            r#"{{
                "version": "0.8.0-alpha",
                "process": {{"commandLine": "echo hello"}},
                "network": {{"proxy": {proxy_json}}}
            }}"#
        )
    }

    fn request_with_containment(containment: &str) -> String {
        format!(
            r#"{{
                "version": "0.8.0-alpha",
                "containment": "{containment}",
                "process": {{"commandLine": "echo hello"}}
            }}"#
        )
    }

    fn request_with_default_network_policy(default_policy: &str) -> String {
        format!(
            r#"{{
                "version": "0.8.0-alpha",
                "process": {{"commandLine": "echo hello"}},
                "network": {{"defaultPolicy": "{default_policy}"}}
            }}"#
        )
    }

    fn request_with_network_enforcement_mode(enforcement_mode: &str) -> String {
        format!(
            r#"{{
                "version": "0.8.0-alpha",
                "process": {{"commandLine": "echo hello"}},
                "network": {{"enforcementMode": "{enforcement_mode}"}}
            }}"#
        )
    }

    fn request_with_ui_clipboard(clipboard: &str) -> String {
        format!(
            r#"{{
                "version": "0.8.0-alpha",
                "process": {{"commandLine": "echo hello"}},
                "ui": {{"clipboard": "{clipboard}"}}
            }}"#
        )
    }

    fn request_with_process_container_ui_isolation(isolation: &str) -> String {
        format!(
            r#"{{
                "version": "0.8.0-alpha",
                "process": {{"commandLine": "echo hello"}},
                "processContainer": {{"ui": {{"isolation": "{isolation}"}}}}
            }}"#
        )
    }

    fn request_with_seatbelt_launch_method(launch_method: &str) -> String {
        format!(
            r#"{{
                "version": "0.8.0-alpha",
                "containment": "seatbelt",
                "process": {{"commandLine": "echo hello"}},
                "seatbelt": {{"launchMethod": "{launch_method}"}}
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
        assert_eq!(wire.version, Some("0.8.0-alpha".to_string()));
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
        assert_eq!(wire.version, Some("0.8.0-alpha".to_string()));
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
        assert_eq!(wire.version, Some("0.8.0-alpha".to_string()));
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
    fn complete_seatbelt_request_maps_expected_wire_fields() {
        let json = COMPLETE_SEATBELT_REQUEST_JSON;

        let request: super::contract::Request = serde_json::from_str(json).unwrap();
        let wire = super::into_wire(request);

        assert!(wire.schema.is_none());
        assert!(wire.comment.is_none());
        assert_eq!(wire.version, Some("0.8.0-alpha".to_string()));
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
        assert_eq!(
            seatbelt.extra_mach_lookups.unwrap().as_slice(),
            &["com.example.service"]
        );
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
    }

    #[test]
    fn empty_process_container_section_maps_to_present_empty_wire_section() {
        let request: super::contract::Request =
            serde_json::from_str(EMPTY_PROCESS_CONTAINER_SECTION_REQUEST_JSON).unwrap();
        let wire = super::into_wire(request);

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
        let request: super::contract::Request =
            serde_json::from_str(EMPTY_PROCESS_CONTAINER_UI_SECTION_REQUEST_JSON).unwrap();
        let wire = super::into_wire(request);

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
        let request: super::contract::Request =
            serde_json::from_str(EMPTY_SEATBELT_SECTION_REQUEST_JSON).unwrap();
        let wire = super::into_wire(request);

        let seatbelt = wire.seatbelt.expect("seatbelt should be populated");
        assert!(seatbelt.profile_override.is_none());
        assert!(seatbelt.gui_access.is_none());
        assert!(seatbelt.launch_method.is_none());
        assert!(seatbelt.nested_pty.is_none());
        assert!(seatbelt.keychain_access.is_none());
        assert!(seatbelt.extra_mach_lookups.is_none());
    }

    #[test]
    fn annotations_map_expected_wire_fields() {
        let json = r#"{
            "$schema": "https://example.com/schema.json",
            "_comment": "This is a comment",
            "version": "0.8.0-alpha",
            "process": {"commandLine": "echo hello"}
        }"#;

        let request: super::contract::Request = serde_json::from_str(json).unwrap();
        let wire = super::into_wire(request);

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

            let request: super::contract::Request = serde_json::from_str(&json).unwrap();
            let wire = super::into_wire(request);

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

        let request: super::contract::Request = serde_json::from_str(&json).unwrap();
        let wire = super::into_wire(request);

        assert_eq!(wire.comment.as_ref(), Some(&serde_json::Value::Null));
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

        for launch_method in SEATBELT_LAUNCH_METHOD_CASES {
            let json = request_with_seatbelt_launch_method(launch_method);
            let request: super::contract::Request = serde_json::from_str(&json).unwrap();
            let wire = super::into_wire(request);

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
        let request: super::contract::Request =
            serde_json::from_str(APP_CONTAINER_SECTION_ALIAS_REQUEST_JSON).unwrap();
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

    #[test]
    fn macos_sandbox_section_alias_maps_expected_wire_fields() {
        let request: super::contract::Request =
            serde_json::from_str(MACOS_SANDBOX_SECTION_ALIAS_REQUEST_JSON).unwrap();
        let wire = super::into_wire(request);
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
        assert_eq!(
            seatbelt.extra_mach_lookups.unwrap().as_slice(),
            &["com.example.service"]
        );
    }
    #[test]
    fn complete_directional_network_request_maps_expected_wire_fields() {
        let request: super::contract::Request =
            serde_json::from_str(DIRECTIONAL_NETWORK_REQUEST_JSON).unwrap();
        let wire = super::into_wire(request);

        assert_eq!(wire.version, Some("0.8.0-alpha".to_string()));

        let network = wire.network.expect("network should be populated");

        // The legacy family stays absent when only directional policy is
        // supplied; both are structurally accepted at 0.8.
        assert!(network.default_policy.is_none());
        assert!(network.enforcement_mode.is_none());
        assert!(network.allow_local_network.is_none());
        assert!(network.allowed_hosts.is_none());
        assert!(network.blocked_hosts.is_none());
        assert!(network.proxy.is_none());

        let egress = network.egress.expect("egress should be populated");
        assert!(matches!(
            egress.default,
            Some(super::wire::NetworkAction::Deny)
        ));

        let allow = egress.allow.expect("egress.allow should be populated");
        assert_eq!(allow.len(), 5);

        // Rule 0: two destinations, one with multiple exceptions, and two port
        // selectors of which the second is an inclusive range.
        let to = allow[0].to.as_ref().expect("rule 0 should carry to");
        assert_eq!(to.len(), 2);
        assert_eq!(to[0].cidr, "140.82.112.0/20");
        assert_eq!(
            to[0].except.as_deref(),
            Some(
                [
                    "140.82.113.0/24".to_string(),
                    "140.82.114.32/27".to_string()
                ]
                .as_slice()
            )
        );
        assert_eq!(to[1].cidr, "2606:50c0::/32");
        assert!(to[1].except.is_none());

        let ports = allow[0].ports.as_ref().expect("rule 0 should carry ports");
        assert_eq!(ports.len(), 2);
        assert!(matches!(
            ports[0].protocol,
            Some(super::wire::NetworkProtocol::Tcp)
        ));
        assert_eq!(ports[0].port, Some(443));
        assert!(ports[0].end_port.is_none());
        assert_eq!(ports[1].port, Some(8000));
        assert_eq!(ports[1].end_port, Some(8080));

        // Rule 1: a UDP range and an any-protocol selector on one destination.
        let ports = allow[1].ports.as_ref().expect("rule 1 should carry ports");
        assert!(matches!(
            ports[0].protocol,
            Some(super::wire::NetworkProtocol::Udp)
        ));
        assert_eq!(ports[0].port, Some(30000));
        assert_eq!(ports[0].end_port, Some(30100));
        assert!(matches!(
            ports[1].protocol,
            Some(super::wire::NetworkProtocol::Any)
        ));
        assert_eq!(ports[1].port, Some(22));

        // Rule 2: ports without destinations, one port over two protocols.
        assert!(allow[2].to.is_none());
        let ports = allow[2].ports.as_ref().expect("rule 2 should carry ports");
        assert_eq!(ports.len(), 2);
        assert!(matches!(
            ports[0].protocol,
            Some(super::wire::NetworkProtocol::Udp)
        ));
        assert!(matches!(
            ports[1].protocol,
            Some(super::wire::NetworkProtocol::Tcp)
        ));
        assert_eq!(ports[0].port, Some(53));
        assert_eq!(ports[1].port, Some(53));

        // Rule 3: destinations without ports, including an IPv6 exception.
        assert!(allow[3].ports.is_none());
        let to = allow[3].to.as_ref().expect("rule 3 should carry to");
        assert_eq!(to[0].cidr, "198.51.100.0/24");
        assert!(to[0].except.is_none());
        assert_eq!(to[1].cidr, "2001:db8::/32");
        assert_eq!(
            to[1].except.as_deref(),
            Some(["2001:db8:1::/48".to_string()].as_slice())
        );

        // Rule 4: ICMP carries no port.
        let ports = allow[4].ports.as_ref().expect("rule 4 should carry ports");
        assert!(matches!(
            ports[0].protocol,
            Some(super::wire::NetworkProtocol::Icmp)
        ));
        assert!(ports[0].port.is_none());
        assert!(ports[0].end_port.is_none());

        let deny = egress.deny.expect("egress.deny should be populated");
        assert_eq!(deny.len(), 2);

        let to = deny[0].to.as_ref().expect("deny 0 should carry to");
        assert_eq!(to.len(), 3);
        assert_eq!(to[0].cidr, "10.0.0.0/8");
        assert_eq!(to[1].cidr, "172.16.0.0/12");
        assert_eq!(to[2].cidr, "192.168.0.0/16");
        assert!(deny[0].ports.is_none());

        let ports = deny[1].ports.as_ref().expect("deny 1 should carry ports");
        assert_eq!(ports[0].port, Some(25));
        assert_eq!(ports[1].port, Some(445));

        let ingress = network.ingress.expect("ingress should be populated");
        assert!(matches!(
            ingress.default,
            Some(super::wire::NetworkAction::Deny)
        ));
        assert!(matches!(
            ingress.host_loopback,
            Some(super::wire::NetworkAction::Allow)
        ));

        let runtime_config = wire
            .runtime_config
            .expect("runtimeConfig should be populated");
        assert_eq!(
            runtime_config.network_proxy.as_deref(),
            Some("http://proxy.example:8080")
        );

        let process_container = wire
            .process_container
            .expect("processContainer should be populated");
        assert_eq!(process_container.learning_mode, Some(true));
        assert_eq!(
            process_container.capabilities.as_deref(),
            Some(["internetClient".to_string(), "registryRead".to_string()].as_slice())
        );

        let capture_denials = process_container
            .capture_denials
            .expect("captureDenials should be populated");
        assert_eq!(
            capture_denials.output_path.as_deref(),
            Some("/path/to/denials.json")
        );
        assert_eq!(capture_denials.retain_etl, Some(false));

        let pc_network = process_container
            .network
            .expect("processContainer.network should be populated");
        assert_eq!(pc_network.allowed_proxy_peer.as_deref(), Some("127.0.0.1"));
    }

    #[test]
    fn empty_directional_sections_map_to_present_empty_wire_sections() {
        let request: super::contract::Request =
            serde_json::from_str(EMPTY_DIRECTIONAL_SECTIONS_REQUEST_JSON).unwrap();
        let wire = super::into_wire(request);

        let network = wire.network.expect("network should be populated");

        let egress = network.egress.expect("egress should be present");
        assert!(egress.default.is_none());
        assert!(egress.allow.is_none());
        assert!(egress.deny.is_none());

        let ingress = network.ingress.expect("ingress should be present");
        assert!(ingress.default.is_none());
        assert!(ingress.host_loopback.is_none());

        let runtime_config = wire
            .runtime_config
            .expect("runtimeConfig should be present");
        assert!(runtime_config.network_proxy.is_none());

        let pc_network = wire
            .process_container
            .expect("processContainer should be populated")
            .network
            .expect("processContainer.network should be present");
        assert!(pc_network.allowed_proxy_peer.is_none());
    }

    #[test]
    fn absent_directional_sections_map_to_absent_wire_fields() {
        let request: super::contract::Request = serde_json::from_str(MINIMAL_REQUEST_JSON).unwrap();
        let wire = super::into_wire(request);

        assert!(wire.network.is_none());
        assert!(wire.runtime_config.is_none());
    }

    #[test]
    fn network_action_variants_map_expected_wire_values() {
        for declared in ["allow", "deny"] {
            let json = format!(
                r#"{{
                    "version": "0.8.0-alpha",
                    "process": {{"commandLine": "echo hello"}},
                    "network": {{
                        "egress": {{"default": "{declared}"}},
                        "ingress": {{"default": "{declared}", "hostLoopback": "{declared}"}}
                    }}
                }}"#
            );

            let request: super::contract::Request = serde_json::from_str(&json).unwrap();
            let network = super::into_wire(request)
                .network
                .expect("network should be populated");

            let egress_default = network.egress.expect("egress").default;
            assert_eq!(
                serde_json::to_value(egress_default).unwrap(),
                serde_json::json!(declared)
            );

            let ingress = network.ingress.expect("ingress");
            assert_eq!(
                serde_json::to_value(ingress.default).unwrap(),
                serde_json::json!(declared)
            );
            assert_eq!(
                serde_json::to_value(ingress.host_loopback).unwrap(),
                serde_json::json!(declared)
            );
        }
    }

    #[test]
    fn network_protocol_variants_map_expected_wire_values() {
        for declared in ["tcp", "udp", "icmp", "any"] {
            let json = format!(
                r#"{{
                    "version": "0.8.0-alpha",
                    "process": {{"commandLine": "echo hello"}},
                    "network": {{
                        "egress": {{"allow": [{{"ports": [{{"protocol": "{declared}"}}]}}]}}
                    }}
                }}"#
            );

            let request: super::contract::Request = serde_json::from_str(&json).unwrap();
            let allow = super::into_wire(request)
                .network
                .expect("network")
                .egress
                .expect("egress")
                .allow
                .expect("allow");
            let ports = allow[0].ports.as_ref().expect("ports");

            assert_eq!(
                serde_json::to_value(ports[0].protocol).unwrap(),
                serde_json::json!(declared)
            );
        }
    }

    #[test]
    fn legacy_and_directional_network_fields_map_together() {
        // The 0.8 contract accepts both families structurally; the parser, not
        // the contract, rejects mixing them.
        let json = r#"{
            "version": "0.8.0-alpha",
            "process": {"commandLine": "echo hello"},
            "network": {
                "defaultPolicy": "block",
                "enforcementMode": "firewall",
                "allowLocalNetwork": true,
                "allowedHosts": ["allowed.example"],
                "blockedHosts": ["blocked.example"],
                "proxy": {"url": "http://proxy.example:8080"},
                "egress": {"default": "deny"},
                "ingress": {"default": "deny"}
            }
        }"#;

        let request: super::contract::Request = serde_json::from_str(json).unwrap();
        let network = super::into_wire(request)
            .network
            .expect("network should be populated");

        assert!(matches!(
            network.default_policy,
            Some(super::wire::NetworkPolicy::Block)
        ));
        assert!(matches!(
            network.enforcement_mode,
            Some(super::wire::NetworkEnforcement::Firewall)
        ));
        assert_eq!(network.allow_local_network, Some(true));
        assert!(network.proxy.is_some());
        assert!(matches!(
            network.egress.expect("egress").default,
            Some(super::wire::NetworkAction::Deny)
        ));
        assert!(matches!(
            network.ingress.expect("ingress").default,
            Some(super::wire::NetworkAction::Deny)
        ));
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
    fn complete_seatbelt_request_matches_current_wire_deserialization() {
        let json = COMPLETE_SEATBELT_REQUEST_JSON;
        assert_matches_current_wire_deserialization(json);
    }

    #[test]
    fn complete_directional_network_request_matches_current_wire_deserialization() {
        let json = DIRECTIONAL_NETWORK_REQUEST_JSON;
        assert_matches_current_wire_deserialization(json);
    }

    #[test]
    fn empty_directional_sections_request_matches_current_wire_deserialization() {
        let json = EMPTY_DIRECTIONAL_SECTIONS_REQUEST_JSON;
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
        assert_matches_current_wire_deserialization(
            EMPTY_PROCESS_CONTAINER_UI_SECTION_REQUEST_JSON,
        );
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
                "version": "0.8.0-alpha",
                "process": {"commandLine": "echo hello"}
            }"#;

        assert_matches_current_wire_deserialization(json);
    }
}
