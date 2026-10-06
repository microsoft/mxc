// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use windows::Win32::Security::PSID;

use crate::mxc_common::error::WxcError;
use crate::mxc_common::logger::Logger;
use crate::mxc_common::models::{ContainerPolicy, ProxyAddress};
use crate::process_container_common::network_policy_helpers::reject_retired_network_policy;
use crate::process_container_common::proxy_coordinator::ProxyCoordinator;

#[derive(Default)]
pub struct NetworkManager {
    proxy_coordinator: ProxyCoordinator,
}

impl NetworkManager {
    pub fn new() -> Self {
        Self {
            proxy_coordinator: ProxyCoordinator::new(),
        }
    }

    pub fn proxy_address(&self) -> Option<&ProxyAddress> {
        self.proxy_coordinator.address()
    }

    /// Configure the supported runtime proxy. Directional network access on
    /// this tier is enforced by AppContainer capabilities, not firewall rules.
    pub fn start(
        &mut self,
        principal_id: &str,
        container_name: &str,
        policy: &ContainerPolicy,
        script_sid: PSID,
        logger: &mut Logger,
    ) -> Result<(), WxcError> {
        if !policy.allowed_hosts.is_empty() || !policy.blocked_hosts.is_empty() {
            return Err(WxcError::Validation(
                "network.allowedHosts / network.blockedHosts are retired; \
                 use network.egress and network.ingress"
                    .into(),
            ));
        }
        reject_retired_network_policy(policy)
            .map_err(|error| WxcError::Validation(error.error_message))?;

        if policy.network_proxy.is_enabled() {
            self.proxy_coordinator.start(
                &policy.network_proxy,
                container_name,
                principal_id,
                script_sid,
                logger,
            )?;
        }

        Ok(())
    }

    /// Stop the proxy, including when the caller preserves filesystem policy.
    pub fn stop_all(&mut self, logger: &mut Logger) -> bool {
        self.proxy_coordinator.stop(logger)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mxc_common::logger::Mode;
    use crate::mxc_common::models::{
        NetworkAction, NetworkEgressPolicy, NetworkEnforcementMode, NetworkPolicy,
    };

    #[test]
    fn proxyless_policy_has_no_network_resources_to_stop() {
        let mut logger = Logger::new(Mode::Buffer);
        let mut manager = NetworkManager::new();
        let policy = ContainerPolicy {
            network_egress: Some(NetworkEgressPolicy {
                default: NetworkAction::Allow,
                ..Default::default()
            }),
            ..Default::default()
        };
        manager
            .start(
                "principal",
                "container",
                &policy,
                PSID::default(),
                &mut logger,
            )
            .unwrap();

        assert!(manager.proxy_address().is_none());
        assert!(!manager.stop_all(&mut logger));
    }

    #[test]
    fn direct_retired_policy_is_rejected_before_proxy_setup() {
        let mut logger = Logger::new(Mode::Buffer);
        let mut manager = NetworkManager::new();
        let mut policy = ContainerPolicy::default();
        policy.network_proxy.address = Some(ProxyAddress::new("127.0.0.1".into(), 8080));
        policy.allowed_hosts.push("example.com".into());
        assert!(matches!(
            manager.start("principal", "container", &policy, PSID::default(), &mut logger),
            Err(WxcError::Validation(message)) if message.contains("allowedHosts")
        ));

        policy.allowed_hosts.clear();
        policy.blocked_hosts.push("example.com".into());
        assert!(matches!(
            manager.start("principal", "container", &policy, PSID::default(), &mut logger),
            Err(WxcError::Validation(message)) if message.contains("blockedHosts")
        ));

        policy.blocked_hosts.clear();
        policy.default_network_policy = NetworkPolicy::Allow;
        assert!(matches!(
            manager.start("principal", "container", &policy, PSID::default(), &mut logger),
            Err(WxcError::Validation(message)) if message.contains("defaultPolicy")
        ));

        policy.default_network_policy = NetworkPolicy::Block;
        policy.network_enforcement_mode = NetworkEnforcementMode::Firewall;
        assert!(matches!(
            manager.start("principal", "container", &policy, PSID::default(), &mut logger),
            Err(WxcError::Validation(message)) if message.contains("enforcementMode")
        ));

        policy.network_enforcement_mode = NetworkEnforcementMode::Capabilities;
        policy.allow_local_network = true;
        assert!(matches!(
            manager.start("principal", "container", &policy, PSID::default(), &mut logger),
            Err(WxcError::Validation(message)) if message.contains("allowLocalNetwork")
        ));
        assert!(manager.proxy_address().is_none());
    }
}
