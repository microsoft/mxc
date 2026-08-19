// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use crate::wire;
use mxc_config_contract::dev as contract;
use mxc_config_contract::ContractVersion;

pub(super) fn convert_version(value: contract::Version) -> &'static str {
    match value {
        contract::Version::V0_8_0Alpha => ContractVersion::V0_8_0Alpha.as_str(),
    }
}

pub(super) fn convert_process(value: contract::Process) -> wire::Process {
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

pub(super) fn convert_filesystem(value: contract::Filesystem) -> wire::Filesystem {
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

pub(super) fn convert_network(value: contract::Network) -> wire::Network {
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

pub(super) fn convert_telemetry(value: contract::Telemetry) -> wire::Telemetry {
    let contract::Telemetry { enabled } = value;
    wire::Telemetry {
        enabled: enabled.into_option(),
    }
}
