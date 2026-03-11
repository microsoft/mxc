use std::net::{IpAddr, ToSocketAddrs};

use windows::core::BSTR;
use windows::core::VARIANT;
use windows::Win32::Foundation::VARIANT_BOOL;
use windows::Win32::NetworkManagement::WindowsFirewall::{
    INetFwPolicy2, INetFwRule3, NetFwPolicy2, NetFwRule, NET_FW_ACTION, NET_FW_ACTION_ALLOW,
    NET_FW_ACTION_BLOCK, NET_FW_RULE_DIR_OUT,
};
use windows::Win32::Networking::WinSock::{WSACleanup, WSAStartup, WSADATA};
use windows::Win32::System::Com::{
    CoCreateInstance, CoInitializeEx, CoUninitialize, CLSCTX_INPROC_SERVER,
    COINIT_APARTMENTTHREADED,
};
use windows_core::Interface;

use crate::error::WxcError;
use crate::logger::Logger;
use crate::models::{ContainerPolicy, NetworkEnforcementMode, NetworkPolicy};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DefaultPolicy {
    Allow,
    Block,
}

pub struct NetworkFirewallManager {
    fw_policy: Option<INetFwPolicy2>,
    created_rule_names: Vec<String>,
    com_initialized: bool,
    wsa_initialized: bool,
}

impl NetworkFirewallManager {
    pub fn new() -> Self {
        Self {
            fw_policy: None,
            created_rule_names: Vec::new(),
            com_initialized: false,
            wsa_initialized: false,
        }
    }

    pub fn initialize_policy(
        policy: &ContainerPolicy,
        logger: &mut Logger,
    ) -> (DefaultPolicy, bool) {
        let use_firewall_rules = matches!(
            policy.network_enforcement_mode,
            NetworkEnforcementMode::Firewall | NetworkEnforcementMode::Both
        );

        if use_firewall_rules
            && (!policy.allowed_hosts.is_empty()
                || !policy.blocked_hosts.is_empty()
                || policy.default_network_policy == NetworkPolicy::Block)
        {
            logger.log_line("Applying network firewall rules...");
            let default_policy = if policy.default_network_policy == NetworkPolicy::Block {
                DefaultPolicy::Block
            } else {
                DefaultPolicy::Allow
            };
            return (default_policy, true);
        }

        (DefaultPolicy::Allow, use_firewall_rules)
    }

    pub fn apply_firewall_rules(
        &mut self,
        principal_id: &str,
        policy: &ContainerPolicy,
        logger: &mut Logger,
    ) -> Result<bool, WxcError> {
        let (default_policy, use_firewall_rules) = Self::initialize_policy(policy, logger);
        if !use_firewall_rules {
            return Ok(true);
        }

        self.initialize_firewall(logger)?;
        self.ensure_wsa_initialized(logger)?;

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default();
        let millis = now.as_millis();
        let mut sanitized_principal_id: String = principal_id
            .chars()
            .map(|c| if c.is_ascii_alphanumeric() { c } else { '_' })
            .collect();
        const MAX_PRINCIPAL_ID_LEN: usize = 64;
        if sanitized_principal_id.len() > MAX_PRINCIPAL_ID_LEN {
            sanitized_principal_id.truncate(MAX_PRINCIPAL_ID_LEN);
        }
        let rule_prefix = format!("WXC_{}_{}", sanitized_principal_id, millis);

        if default_policy == DefaultPolicy::Block {
            let block_all_name = format!("{}_BlockAll", rule_prefix);
            if !self.create_rule(&block_all_name, principal_id, NET_FW_ACTION_BLOCK, "", logger)? {
                return Ok(false);
            }
            self.created_rule_names.push(block_all_name);
            self.process_host_list(
                &policy.allowed_hosts,
                &rule_prefix,
                principal_id,
                NET_FW_ACTION_ALLOW,
                "Allow",
                logger,
            )?;
        } else {
            let allow_all_name = format!("{}_AllowAll", rule_prefix);
            if !self.create_rule(
                &allow_all_name,
                principal_id,
                NET_FW_ACTION_ALLOW,
                "*",
                logger,
            )? {
                return Ok(false);
            }
            self.created_rule_names.push(allow_all_name);
            self.process_host_list(
                &policy.blocked_hosts,
                &rule_prefix,
                principal_id,
                NET_FW_ACTION_BLOCK,
                "Block",
                logger,
            )?;
        }

        Ok(true)
    }

    fn process_host_list(
        &mut self,
        hosts: &[String],
        rule_prefix: &str,
        principal_id: &str,
        action: NET_FW_ACTION,
        action_name: &str,
        logger: &mut Logger,
    ) -> Result<(), WxcError> {
        for (index, host) in hosts.iter().enumerate() {
            let ip_address = if validate_ip_or_cidr(host) {
                host.clone()
            } else {
                match resolve_hostname(host) {
                    Ok(ip) => ip,
                    Err(_) => {
                        logger.log_line(&format!("Warning: Could not resolve {}", host));
                        continue;
                    }
                }
            };

            let rule_name = format!("{}_{}_{}", rule_prefix, action_name, index);
            match self.create_rule(&rule_name, principal_id, action, &ip_address, logger) {
                Ok(true) => {
                    self.created_rule_names.push(rule_name);
                }
                Ok(false) | Err(_) => {
                    continue;
                }
            }
        }
        Ok(())
    }

    /// Returns `true` if any firewall rules have been created and are currently active.
    pub fn rules_applied(&self) -> bool {
        !self.created_rule_names.is_empty()
    }

    pub fn remove_firewall_rules(&mut self, logger: &mut Logger) -> Result<bool, WxcError> {
        let fw_policy = match &self.fw_policy {
            Some(p) => p.clone(),
            None => {
                logger.log_line("Firewall policy not initialized");
                return Ok(false);
            }
        };

        let rules = unsafe { fw_policy.Rules() }.map_err(|e| {
            WxcError::Firewall(format!("Failed to get firewall rules: {}", e))
        })?;

        let mut all_success = true;
        for rule_name in &self.created_rule_names {
            let bstr_name = BSTR::from(rule_name.as_str());
            if unsafe { rules.Remove(&bstr_name) }.is_err() {
                all_success = false;
            }
        }
        self.created_rule_names.clear();
        Ok(all_success)
    }

    fn initialize_firewall(&mut self, _logger: &mut Logger) -> Result<(), WxcError> {
        if self.fw_policy.is_some() {
            return Ok(());
        }

        let hr = unsafe { CoInitializeEx(None, COINIT_APARTMENTTHREADED) };
        // CoInitializeEx returns HRESULT directly in windows 0.58
        if hr.is_ok() {
            self.com_initialized = true;
        } else {
            // RPC_E_CHANGED_MODE (0x80010106) means COM is already initialized
            // with a different threading model — that's acceptable.
            let code = hr.0 as u32;
            if code == 0x80010106 {
                self.com_initialized = false;
            } else {
                return Err(WxcError::Firewall(format!(
                    "CoInitializeEx failed: 0x{:08X}",
                    code
                )));
            }
        }

        match unsafe {
            CoCreateInstance::<_, INetFwPolicy2>(&NetFwPolicy2, None, CLSCTX_INPROC_SERVER)
        } {
            Ok(policy) => {
                self.fw_policy = Some(policy);
                Ok(())
            }
            Err(e) => {
                if self.com_initialized {
                    unsafe { CoUninitialize() };
                    self.com_initialized = false;
                }
                Err(WxcError::Firewall(format!(
                    "Failed to create NetFwPolicy2: {}",
                    e
                )))
            }
        }
    }

    fn cleanup_firewall(&mut self) {
        if let Some(policy) = self.fw_policy.take() {
            drop(policy);
        }
        if self.com_initialized {
            unsafe { CoUninitialize() };
            self.com_initialized = false;
        }
    }

    fn ensure_wsa_initialized(&mut self, _logger: &mut Logger) -> Result<(), WxcError> {
        if self.wsa_initialized {
            return Ok(());
        }
        let mut wsa_data = WSADATA::default();
        let result = unsafe { WSAStartup(0x0202, &mut wsa_data) };
        if result != 0 {
            return Err(WxcError::Firewall(format!(
                "WSAStartup failed with code {}",
                result
            )));
        }
        self.wsa_initialized = true;
        Ok(())
    }

    fn cleanup_wsa(&mut self) {
        if self.wsa_initialized {
            unsafe { WSACleanup() };
            self.wsa_initialized = false;
        }
    }

    fn create_rule(
        &self,
        rule_name: &str,
        principal_id: &str,
        action: NET_FW_ACTION,
        remote_addresses: &str,
        _logger: &mut Logger,
    ) -> Result<bool, WxcError> {
        let fw_policy = self
            .fw_policy
            .as_ref()
            .ok_or_else(|| WxcError::Firewall("Firewall policy not initialized".into()))?;

        let rules = unsafe { fw_policy.Rules() }.map_err(|e| {
            WxcError::Firewall(format!("Failed to get firewall rules: {}", e))
        })?;

        let rule: windows::Win32::NetworkManagement::WindowsFirewall::INetFwRule =
            unsafe { CoCreateInstance(&NetFwRule, None, CLSCTX_INPROC_SERVER) }.map_err(|e| {
                WxcError::Firewall(format!("Failed to create NetFwRule: {}", e))
            })?;

        let rule3: INetFwRule3 = rule.cast().map_err(|e| {
            WxcError::Firewall(format!("Failed to get INetFwRule3 interface: {}", e))
        })?;

        unsafe {
            rule.SetName(&BSTR::from(rule_name))
                .map_err(|e| WxcError::Firewall(format!("put_Name failed: {}", e)))?;

            rule.SetDescription(&BSTR::from("WXC AppContainer network policy"))
                .map_err(|e| WxcError::Firewall(format!("put_Description failed: {}", e)))?;

            rule3
                .SetLocalAppPackageId(&BSTR::from(principal_id))
                .map_err(|e| {
                    WxcError::Firewall(format!("put_LocalAppPackageId failed: {}", e))
                })?;

            rule.SetDirection(NET_FW_RULE_DIR_OUT)
                .map_err(|e| WxcError::Firewall(format!("put_Direction failed: {}", e)))?;

            rule.SetAction(action)
                .map_err(|e| WxcError::Firewall(format!("put_Action failed: {}", e)))?;

            let empty_variant = VARIANT::default();
            rule.SetInterfaces(&empty_variant)
                .map_err(|e| WxcError::Firewall(format!("put_Interfaces failed: {}", e)))?;

            if !remote_addresses.is_empty() {
                rule.SetRemoteAddresses(&BSTR::from(remote_addresses))
                    .map_err(|e| {
                        WxcError::Firewall(format!("put_RemoteAddresses failed: {}", e))
                    })?;
            }

            rule.SetEnabled(VARIANT_BOOL::from(true))
                .map_err(|e| WxcError::Firewall(format!("put_Enabled failed: {}", e)))?;

            match rules.Add(&rule) {
                Ok(()) => Ok(true),
                Err(e) => {
                    _logger.log_line(&format!("Failed to add firewall rule '{}': {}", rule_name, e));
                    Ok(false)
                }
            }
        }
    }
}

impl Default for NetworkFirewallManager {
    fn default() -> Self {
        Self::new()
    }
}

impl Drop for NetworkFirewallManager {
    fn drop(&mut self) {
        self.cleanup_firewall();
        self.cleanup_wsa();
    }
}

/// Resolve a hostname to an IP address string.
pub fn resolve_hostname(hostname: &str) -> Result<String, WxcError> {
    let addr = (hostname, 0)
        .to_socket_addrs()
        .map_err(|e| WxcError::Firewall(format!("Failed to resolve '{}': {}", hostname, e)))?
        .next()
        .ok_or_else(|| {
            WxcError::Firewall(format!("No addresses found for '{}'", hostname))
        })?;

    Ok(addr.ip().to_string())
}

/// Validate whether a string is a valid IP address or CIDR notation.
pub fn validate_ip_or_cidr(address: &str) -> bool {
    let (ip_part, cidr_part) = match address.find('/') {
        Some(pos) => {
            let ip = &address[..pos];
            let cidr = &address[pos + 1..];
            if cidr.is_empty() {
                return false;
            }
            let bits: u32 = match cidr.parse() {
                Ok(b) => b,
                Err(_) => return false,
            };
            (ip, Some(bits))
        }
        None => (address, None),
    };

    if let Ok(ip) = ip_part.parse::<IpAddr>() {
        match (ip, cidr_part) {
            (IpAddr::V4(_), Some(bits)) => bits <= 32,
            (IpAddr::V6(_), Some(bits)) => bits <= 128,
            (_, None) => true,
        }
    } else {
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validate_ip_or_cidr_valid_ipv4() {
        assert!(validate_ip_or_cidr("192.168.1.1"));
        assert!(validate_ip_or_cidr("10.0.0.0/8"));
        assert!(validate_ip_or_cidr("172.16.0.0/12"));
        assert!(validate_ip_or_cidr("0.0.0.0/0"));
        assert!(validate_ip_or_cidr("255.255.255.255/32"));
    }

    #[test]
    fn test_validate_ip_or_cidr_valid_ipv6() {
        assert!(validate_ip_or_cidr("::1"));
        assert!(validate_ip_or_cidr("fe80::1/64"));
        assert!(validate_ip_or_cidr("::1/128"));
    }

    #[test]
    fn test_validate_ip_or_cidr_invalid() {
        assert!(!validate_ip_or_cidr("not_an_ip"));
        assert!(!validate_ip_or_cidr("192.168.1.1/"));
        assert!(!validate_ip_or_cidr("192.168.1.1/33"));
        assert!(!validate_ip_or_cidr("::1/129"));
        assert!(!validate_ip_or_cidr("192.168.1.1/abc"));
        assert!(!validate_ip_or_cidr(""));
    }

    #[test]
    fn test_initialize_policy_firewall_mode_block() {
        let mut logger = Logger::new(crate::logger::Mode::Buffer);
        let policy = ContainerPolicy {
            network_enforcement_mode: NetworkEnforcementMode::Firewall,
            default_network_policy: NetworkPolicy::Block,
            ..Default::default()
        };
        let (default_policy, use_fw) = NetworkFirewallManager::initialize_policy(&policy, &mut logger);
        assert!(use_fw);
        assert_eq!(default_policy, DefaultPolicy::Block);
    }

    #[test]
    fn test_initialize_policy_capabilities_mode() {
        let mut logger = Logger::new(crate::logger::Mode::Buffer);
        let policy = ContainerPolicy {
            network_enforcement_mode: NetworkEnforcementMode::Capabilities,
            ..Default::default()
        };
        let (default_policy, use_fw) = NetworkFirewallManager::initialize_policy(&policy, &mut logger);
        assert!(!use_fw);
        assert_eq!(default_policy, DefaultPolicy::Allow);
    }

    #[test]
    fn test_initialize_policy_firewall_with_allowed_hosts() {
        let mut logger = Logger::new(crate::logger::Mode::Buffer);
        let policy = ContainerPolicy {
            network_enforcement_mode: NetworkEnforcementMode::Both,
            default_network_policy: NetworkPolicy::Allow,
            allowed_hosts: vec!["example.com".to_string()],
            ..Default::default()
        };
        let (default_policy, use_fw) = NetworkFirewallManager::initialize_policy(&policy, &mut logger);
        assert!(use_fw);
        assert_eq!(default_policy, DefaultPolicy::Allow);
    }

    #[test]
    fn test_default_creates_new_manager() {
        let mgr = NetworkFirewallManager::default();
        assert!(mgr.fw_policy.is_none());
        assert!(mgr.created_rule_names.is_empty());
        assert!(!mgr.com_initialized);
        assert!(!mgr.wsa_initialized);
    }

    #[test]
    fn test_resolve_hostname_localhost() {
        let result = resolve_hostname("localhost");
        assert!(result.is_ok());
        let ip = result.unwrap();
        assert!(ip == "127.0.0.1" || ip == "::1");
    }

    #[test]
    fn test_resolve_hostname_invalid() {
        let result = resolve_hostname("this.host.definitely.does.not.exist.invalid");
        assert!(result.is_err());
    }
}
