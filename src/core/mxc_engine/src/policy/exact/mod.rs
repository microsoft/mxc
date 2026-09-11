// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use std::num::NonZeroU16;

use mxc_config_contract::ContractVersion;
use wxc_common::config_parser::{load_one_shot_request_from_contract, ExactOneShotContract};
use wxc_common::logger::{Logger, Mode};
use wxc_common::mxc_error::MxcError;

use crate::configs::ProcessContainer;

use super::network::{select_network_format, NetworkFormat};
use super::{Containment, NetworkAction, ProxySpec, SandboxPolicy, SandboxRequest};

macro_rules! optional {
    ($module:ident, $value:expr) => {
        match $value {
            Some(value) => $module::OptionalField::present(value),
            None => $module::OptionalField::default(),
        }
    };
}

mod v0_6;
mod v0_7;
mod v0_8;
mod v0_9;

#[derive(Clone, Copy)]
enum LegacyEnforcement {
    Capabilities,
    Firewall,
    Both,
}

struct PreparedInput<'a> {
    policy: &'a SandboxPolicy,
    containment: &'a Containment,
    script: &'a str,
    container_id: String,
    network_format: NetworkFormat,
}

fn error(message: impl Into<String>) -> MxcError {
    MxcError::malformed_request(message)
}

fn non_empty_port(value: u16, field: &str) -> Result<NonZeroU16, MxcError> {
    NonZeroU16::new(value).ok_or_else(|| error(format!("{field} must be non-zero")))
}

fn validate_common(
    policy: &SandboxPolicy,
    containment: &Containment,
) -> Result<NetworkFormat, MxcError> {
    let has_process_container_network = match containment {
        Containment::ProcessContainer(process_container) => process_container
            .network
            .as_ref()
            .and_then(|network| network.allowed_proxy_peer.as_deref())
            .is_some_and(|peer| !peer.trim().is_empty()),
        _ => false,
    };
    let network_format = select_network_format(
        &policy.version,
        policy.network.as_ref(),
        has_process_container_network,
    )?;

    if let Some(network) = policy.network.as_ref() {
        if matches!(network.proxy, Some(ProxySpec::BuiltinTestServer)) {
            return Err(error(
                "network.proxy.builtinTestServer is not supported by the in-process Rust SDK; use localhost or url",
            ));
        }

        let accepts_host_rules_without_outbound = match containment {
            Containment::Process => cfg!(any(target_os = "linux", target_os = "macos")),
            Containment::ProcessContainer(_) => false,
            Containment::Wslc(_) => true,
            Containment::IsolationSession => false,
        };
        if !accepts_host_rules_without_outbound
            && (!network.allowed_hosts.is_empty() || !network.blocked_hosts.is_empty())
            && !network.allow_outbound
        {
            return Err(error(
                "allowedHosts/blockedHosts require allowOutbound to be true",
            ));
        }
    }

    Ok(network_format)
}

fn selected_process_container(containment: &Containment) -> Option<ProcessContainer> {
    match containment {
        Containment::ProcessContainer(process_container) => Some(process_container.clone()),
        Containment::Process if cfg!(target_os = "windows") => Some(ProcessContainer::default()),
        _ => None,
    }
}

fn normalized_capabilities(
    policy: &SandboxPolicy,
    process_container: &ProcessContainer,
    network_format: NetworkFormat,
) -> Vec<String> {
    let mut capabilities = process_container.capabilities.clone();
    if let Some(network) = policy.network.as_ref() {
        let (allows_internet, allows_local_network) = match network_format {
            NetworkFormat::Legacy => (network.allow_outbound, network.allow_local_network),
            NetworkFormat::Directional => {
                let allows_internet = network.egress.as_ref().is_some_and(|egress| {
                    egress.default == Some(NetworkAction::Allow)
                        || egress.allow.as_ref().is_some_and(|rules| !rules.is_empty())
                });
                let allows_local_network = network
                    .ingress
                    .as_ref()
                    .is_some_and(|ingress| ingress.default == Some(NetworkAction::Allow));
                (allows_internet, allows_local_network)
            }
        };
        if allows_internet
            && !capabilities
                .iter()
                .any(|capability| capability.eq_ignore_ascii_case("internetClient"))
        {
            capabilities.push("internetClient".to_string());
        }
        if allows_local_network
            && !capabilities
                .iter()
                .any(|capability| capability.eq_ignore_ascii_case("privateNetworkClientServer"))
        {
            capabilities.push("privateNetworkClientServer".to_string());
        }
    }
    capabilities
}

fn legacy_enforcement(
    policy: &SandboxPolicy,
    containment: &Containment,
    has_process_container: bool,
) -> Option<LegacyEnforcement> {
    let network = policy.network.as_ref()?;
    let has_host_rules = !network.allowed_hosts.is_empty() || !network.blocked_hosts.is_empty();
    if has_process_container {
        return Some(if has_host_rules {
            LegacyEnforcement::Both
        } else {
            LegacyEnforcement::Capabilities
        });
    }
    if cfg!(target_os = "linux")
        && matches!(containment, Containment::Process)
        && has_host_rules
        && network.proxy.is_none()
    {
        return Some(LegacyEnforcement::Firewall);
    }
    None
}

fn container_id(container_name: Option<&str>) -> String {
    container_name
        .map(str::to_string)
        .unwrap_or_else(wxc_common::id::mint_random_token)
}

pub(super) fn build_request(
    policy: &SandboxPolicy,
    containment: &Containment,
    script: &str,
    container_name: Option<&str>,
) -> Result<SandboxRequest, crate::Error> {
    if policy.version.is_empty() {
        return Err(error("Policy version is required").into());
    }
    let version = ContractVersion::parse_exact(&policy.version)
        .ok_or_else(|| error(format!("Invalid schema version: {}", policy.version)))?;
    if script.is_empty() {
        return Err(error("script parameter is required").into());
    }
    let prepared = PreparedInput {
        policy,
        containment,
        script,
        container_id: container_id(container_name),
        network_format: validate_common(policy, containment)?,
    };
    let contract = match version {
        ContractVersion::V0_6_0Alpha => {
            ExactOneShotContract::V0_6(Box::new(v0_6::build(&prepared)?))
        }
        ContractVersion::V0_7_0Alpha => {
            ExactOneShotContract::V0_7(Box::new(v0_7::build(&prepared)?))
        }
        ContractVersion::V0_8_0Alpha => {
            ExactOneShotContract::V0_8(Box::new(v0_8::build(&prepared)?))
        }
        ContractVersion::V0_9_0Alpha => {
            ExactOneShotContract::Dev(Box::new(v0_9::build(&prepared)?))
        }
    };
    let mut logger = Logger::new(Mode::Buffer);
    let inner = load_one_shot_request_from_contract(contract, &mut logger).map_err(|error| {
        MxcError::malformed_request(format!("failed to build request: {error}"))
    })?;
    Ok(SandboxRequest {
        inner,
        requested_sandbox_kind: containment.telemetry_kind(),
    })
}
