// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use std::num::NonZeroU16;

use wxc_common::config_parser::{load_one_shot_request_from_contract, ExactOneShotContract};
use wxc_common::logger::{Logger, Mode};
use wxc_common::mxc_error::MxcError;

use crate::configs::{LxcConfig, ProcessContainerConfig, SeatbeltConfig};

use super::{ContainerPolicy, Containment, PreparedContainerRequest};

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
    policy: &'a ContainerPolicy,
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

fn selected_process_container(containment: &Containment) -> Option<ProcessContainerConfig> {
    match containment {
        Containment::ProcessContainer(process_container) => Some(process_container.clone()),
        _ => None,
    }
}

fn selected_seatbelt(containment: &Containment) -> Option<SeatbeltConfig> {
    match containment {
        Containment::Seatbelt(seatbelt) => Some(seatbelt.clone()),
        _ => None,
    }
}

fn selected_lxc(containment: &Containment) -> Option<LxcConfig> {
    match containment {
        Containment::Lxc(lxc) => Some(lxc.clone()),
        _ => None,
    }
}

fn container_id(container_name: Option<&str>) -> String {
    container_name
        .map(str::to_string)
        .unwrap_or_else(wxc_common::id::mint_random_token)
}

pub(super) fn build_request(
    policy: &ContainerPolicy,
    containment: &Containment,
    script: &str,
    container_name: Option<&str>,
) -> Result<PreparedContainerRequest, crate::Error> {
    if script.is_empty() {
        return Err(error("script parameter is required").into());
    }
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
    Ok(PreparedContainerRequest {
        inner,
        #[cfg(test)]
        requested_sandbox_kind: containment.telemetry_kind(),
    })
}

#[cfg(test)]
mod tests {
    use crate::configs::ProcessContainerNetwork;
    use crate::policy::{
        NetworkAction, NetworkEgressPolicy, NetworkIngressPolicy, NetworkPolicy,
        NetworkRuntimeConfig,
    };

    use super::*;

    fn process_container_with_proxy_peer(peer: &str) -> Containment {
        Containment::ProcessContainer(ProcessContainerConfig {
            network: Some(ProcessContainerNetwork {
                allowed_proxy_peer: Some(peer.to_string()),
            }),
            ..Default::default()
        })
    }

    fn assert_blank_proxy_peer_uses_shared_validation(peer: &str) {
        let policy = ContainerPolicy::default();
        let containment = process_container_with_proxy_peer(peer);
        let prepared = PreparedInput {
            policy: &policy,
            containment: &containment,
            script: "echo hello",
            container_id: "proxy-validation".to_string(),
        };
        let contract = ExactOneShotContract::V1_0(Box::new(v1_0::build(&prepared).unwrap()));
        let mut logger = Logger::new(Mode::Buffer);
        let shared_error = load_one_shot_request_from_contract(contract, &mut logger).unwrap_err();
        assert!(shared_error
            .to_string()
            .contains("processContainer.network.allowedProxyPeer must not be blank"));

        let error = build_request(&policy, &containment, "echo hello", None).unwrap_err();
        assert_eq!(error.code, crate::ErrorCode::MalformedRequest);
        assert_eq!(
            error.message,
            format!("failed to build request: {shared_error}")
        );
    }

    #[test]
    fn rejects_empty_allowed_proxy_peer() {
        assert_blank_proxy_peer_uses_shared_validation("");
    }

    #[test]
    fn rejects_whitespace_only_allowed_proxy_peer() {
        assert_blank_proxy_peer_uses_shared_validation(" \t\r\n");
    }

    #[test]
    fn preserves_nonempty_allowed_proxy_peer() {
        let policy = ContainerPolicy {
            network: Some(NetworkPolicy {
                egress: Some(NetworkEgressPolicy {
                    default: Some(NetworkAction::Deny),
                    ..Default::default()
                }),
                ingress: Some(NetworkIngressPolicy {
                    default: Some(NetworkAction::Allow),
                    host_loopback: Some(NetworkAction::Deny),
                }),
                runtime_config: Some(NetworkRuntimeConfig {
                    network_proxy: Some("http://127.0.0.1:8080".to_string()),
                }),
            }),
            ..Default::default()
        };
        let request = build_request(
            &policy,
            &process_container_with_proxy_peer(" Contoso.Proxy_123 "),
            "echo hello",
            None,
        )
        .unwrap();

        assert_eq!(
            request.inner.policy.allowed_proxy_peer.as_deref(),
            Some(" Contoso.Proxy_123 ")
        );
    }
}
