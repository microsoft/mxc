// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use std::num::NonZeroU16;

use wxc_common::config_parser::{load_one_shot_request_from_contract, ExactOneShotContract};
use wxc_common::logger::{Logger, Mode};
use wxc_common::mxc_error::MxcError;

use crate::configs::{Lxc, ProcessContainer, Seatbelt};

use super::{Containment, NetworkAction, SandboxPolicy, SandboxRequest};

macro_rules! optional {
    ($module:ident, $value:expr) => {
        match $value {
            Some(value) => $module::OptionalField::present(value),
            None => $module::OptionalField::default(),
        }
    };
}

mod v1_0;

struct PreparedInput<'a> {
    policy: &'a SandboxPolicy,
    containment: &'a Containment,
    script: &'a str,
    container_id: String,
}

fn error(message: impl Into<String>) -> MxcError {
    MxcError::malformed_request(message)
}

fn non_empty_port(value: u16, field: &str) -> Result<NonZeroU16, MxcError> {
    NonZeroU16::new(value).ok_or_else(|| error(format!("{field} must be non-zero")))
}

fn validate_common(containment: &Containment) -> Result<(), MxcError> {
    if let Containment::ProcessContainer(process_container) = containment {
        if process_container
            .network
            .as_ref()
            .and_then(|network| network.allowed_proxy_peer.as_deref())
            .is_some_and(str::is_empty)
        {
            return Err(error(
                "processContainer.network.allowedProxyPeer must not be empty",
            ));
        }
    }
    Ok(())
}

fn selected_process_container(containment: &Containment) -> Option<ProcessContainer> {
    match containment {
        Containment::ProcessContainer(process_container) => Some(process_container.clone()),
        Containment::Process if cfg!(target_os = "windows") => Some(ProcessContainer::default()),
        _ => None,
    }
}

fn selected_seatbelt(containment: &Containment) -> Option<Seatbelt> {
    match containment {
        Containment::Seatbelt(seatbelt) => Some(seatbelt.clone()),
        Containment::Process if cfg!(target_os = "macos") => Some(Seatbelt::default()),
        _ => None,
    }
}

fn selected_lxc(containment: &Containment) -> Option<Lxc> {
    match containment {
        Containment::Lxc(lxc) => Some(lxc.clone()),
        _ => None,
    }
}

fn normalized_capabilities(
    policy: &SandboxPolicy,
    process_container: &ProcessContainer,
) -> Vec<String> {
    let mut capabilities = process_container.capabilities.clone();
    if let Some(network) = policy.network.as_ref() {
        let allows_internet = network.egress.as_ref().is_some_and(|egress| {
            egress.default == Some(NetworkAction::Allow)
                || egress.allow.as_ref().is_some_and(|rules| !rules.is_empty())
        });
        let allows_local_network = network
            .ingress
            .as_ref()
            .is_some_and(|ingress| ingress.default == Some(NetworkAction::Allow));
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
    if script.is_empty() {
        return Err(error("script parameter is required").into());
    }
    validate_common(containment)?;
    let prepared = PreparedInput {
        policy,
        containment,
        script,
        container_id: container_id(container_name),
    };
    let contract = ExactOneShotContract::V1_0(Box::new(v1_0::build(&prepared)?));
    let mut logger = Logger::new(Mode::Buffer);
    let mut inner =
        load_one_shot_request_from_contract(contract, &mut logger).map_err(|error| {
            MxcError::malformed_request(format!("failed to build request: {error}"))
        })?;
    inner.source_contract = None;
    Ok(SandboxRequest {
        inner,
        requested_sandbox_kind: containment.telemetry_kind(),
    })
}
