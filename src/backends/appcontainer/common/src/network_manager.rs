// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use std::net::{IpAddr, ToSocketAddrs};

use windows::core::BSTR;
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
use windows::Win32::System::Variant::VARIANT;
use windows_core::Interface;

use crate::proxy_coordinator::ProxyCoordinator;
use wxc_common::error::WxcError;
use wxc_common::logger::Logger;
use wxc_common::models::{ContainerPolicy, NetworkEnforcementMode, NetworkPolicy};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DefaultPolicy {
    Allow,
    Block,
}

/// `RPC_E_CHANGED_MODE`: `CoInitializeEx` returns this when COM is already
/// initialized on the calling thread with a *different* apartment model. The
/// existing initialization is reused and must **not** be balanced by our own
/// `CoUninitialize`.
const RPC_E_CHANGED_MODE: u32 = 0x8001_0106;

/// RAII guard for a per-call COM apartment on the **current** thread.
///
/// Every firewall operation creates one of these, does all of its COM work
/// (`CoCreateInstance`, interface use, release) while it is alive, and lets it
/// drop — running the matching `CoUninitialize` — before returning. Because no
/// COM interface or apartment state is ever cached on [`NetworkManager`] across
/// calls, teardown (`remove_firewall_rules`) can run on a *different* thread
/// than setup (`apply_firewall_rules`) without ever using an interface from
/// another apartment or pairing `CoInitializeEx`/`CoUninitialize` across
/// threads. That self-containment is what makes the `unsafe impl Send` on the
/// owning sandbox handle sound.
struct ComApartment {
    /// Whether *this* guard performed the initialization that it must balance
    /// with `CoUninitialize`. `false` when COM was already initialized on this
    /// thread under a different model (`RPC_E_CHANGED_MODE`).
    owns_init: bool,
}

impl ComApartment {
    /// Join (or initialize) an apartment-threaded COM apartment for the current
    /// thread. `S_OK`/`S_FALSE` both count as an initialization this guard must
    /// balance; `RPC_E_CHANGED_MODE` reuses an existing apartment without
    /// taking ownership of its teardown.
    fn new() -> Result<Self, WxcError> {
        // SAFETY: `CoInitializeEx` is always safe to call; the matching
        // `CoUninitialize` runs in `Drop` on this same thread when we own it.
        let hr = unsafe { CoInitializeEx(None, COINIT_APARTMENTTHREADED) };
        if hr.is_ok() {
            Ok(Self { owns_init: true })
        } else if hr.0 as u32 == RPC_E_CHANGED_MODE {
            Ok(Self { owns_init: false })
        } else {
            Err(WxcError::Firewall(format!(
                "CoInitializeEx failed: 0x{:08X}",
                hr.0 as u32
            )))
        }
    }
}

impl Drop for ComApartment {
    fn drop(&mut self) {
        if self.owns_init {
            // SAFETY: balances the `CoInitializeEx` in `new` on the same thread.
            unsafe { CoUninitialize() };
        }
    }
}

pub struct NetworkManager {
    created_rule_names: Vec<String>,
    wsa_initialized: bool,
    proxy_coordinator: ProxyCoordinator,
}

/// Invariant context for creating firewall rules within a single
/// `apply_firewall_rules` call: the firewall interface (valid only for the
/// current COM apartment / thread) and the AppContainer principal the rules are
/// scoped to. Bundled so the rule helpers stay within the argument-count lint.
struct RuleContext<'a> {
    fw_policy: &'a INetFwPolicy2,
    principal_id: &'a str,
}

impl NetworkManager {
    pub fn new() -> Self {
        Self {
            created_rule_names: Vec::new(),
            wsa_initialized: false,
            proxy_coordinator: ProxyCoordinator::new(),
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

        // Open a COM apartment and create the firewall interface for the
        // duration of *this* call only — nothing is cached on `self`. See
        // [`ComApartment`] for why this self-containment matters.
        let _com = ComApartment::new()?;
        let fw_policy: INetFwPolicy2 =
            unsafe { CoCreateInstance(&NetFwPolicy2, None, CLSCTX_INPROC_SERVER) }
                .map_err(|e| WxcError::Firewall(format!("Failed to create NetFwPolicy2: {e}")))?;
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
        let ctx = RuleContext {
            fw_policy: &fw_policy,
            principal_id,
        };

        if default_policy == DefaultPolicy::Block {
            let block_all_name = format!("{}_BlockAll", rule_prefix);
            if !self.create_rule(&ctx, &block_all_name, NET_FW_ACTION_BLOCK, "", logger)? {
                return Ok(false);
            }
            self.created_rule_names.push(block_all_name);
            self.process_host_list(
                &ctx,
                &policy.allowed_hosts,
                &rule_prefix,
                NET_FW_ACTION_ALLOW,
                "Allow",
                logger,
            )?;
        } else {
            let allow_all_name = format!("{}_AllowAll", rule_prefix);
            if !self.create_rule(&ctx, &allow_all_name, NET_FW_ACTION_ALLOW, "*", logger)? {
                return Ok(false);
            }
            self.created_rule_names.push(allow_all_name);
            self.process_host_list(
                &ctx,
                &policy.blocked_hosts,
                &rule_prefix,
                NET_FW_ACTION_BLOCK,
                "Block",
                logger,
            )?;
        }

        Ok(true)
    }

    fn process_host_list(
        &mut self,
        ctx: &RuleContext,
        hosts: &[String],
        rule_prefix: &str,
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
            match self.create_rule(ctx, &rule_name, action, &ip_address, logger) {
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

    /// Returns the proxy address if a proxy is active.
    pub fn proxy_address(&self) -> Option<&wxc_common::models::ProxyAddress> {
        self.proxy_coordinator.address()
    }

    /// Start the proxy (if configured) and apply firewall rules.
    ///
    /// This is the single entry point for all network setup. It handles:
    /// 1. Launching the builtin test proxy or configuring the external proxy
    /// 2. Setting WinHTTP proxy policy via the elevated shim
    /// 3. Creating Windows Firewall rules for host allow/block lists
    pub fn start(
        &mut self,
        principal_id: &str,
        container_name: &str,
        policy: &ContainerPolicy,
        script_sid: windows::Win32::Security::PSID,
        logger: &mut Logger,
    ) -> Result<(), WxcError> {
        if policy.network_proxy.is_enabled() {
            self.proxy_coordinator.start(
                &policy.network_proxy,
                container_name,
                principal_id,
                script_sid,
                logger,
            )?;
        }

        if let Err(err) = self.apply_firewall_rules(principal_id, policy, logger) {
            if self.proxy_coordinator.is_active() {
                self.proxy_coordinator.stop(logger);
            }
            return Err(err);
        }

        Ok(())
    }

    /// Stop all network resources: firewall rules, proxy policy, test proxy.
    pub fn stop_all(&mut self, cleanup_policy: bool, logger: &mut Logger) {
        if self.rules_applied() && cleanup_policy {
            let _ = self.remove_firewall_rules(logger);
        }
        if self.proxy_coordinator.is_active() {
            self.proxy_coordinator.stop(logger);
        }
    }

    pub fn remove_firewall_rules(&mut self, logger: &mut Logger) -> Result<bool, WxcError> {
        if self.created_rule_names.is_empty() {
            return Ok(true);
        }

        // Re-acquire a fresh firewall interface in its own apartment on the
        // current thread. Windows Firewall rules persist by name independently
        // of the COM client that created them, so removal does not need (and
        // must not reuse) the interface or apartment `apply_firewall_rules`
        // used — which may have run on a different thread. See [`ComApartment`].
        let _com = ComApartment::new()?;
        let fw_policy: INetFwPolicy2 =
            unsafe { CoCreateInstance(&NetFwPolicy2, None, CLSCTX_INPROC_SERVER) }
                .map_err(|e| WxcError::Firewall(format!("Failed to create NetFwPolicy2: {e}")))?;

        let rules = unsafe { fw_policy.Rules() }
            .map_err(|e| WxcError::Firewall(format!("Failed to get firewall rules: {}", e)))?;

        let mut all_success = true;
        for rule_name in &self.created_rule_names {
            let bstr_name = BSTR::from(rule_name.as_str());
            if unsafe { rules.Remove(&bstr_name) }.is_err() {
                all_success = false;
            }
        }
        self.created_rule_names.clear();
        if !all_success {
            logger.log_line("Warning: some firewall rules could not be removed");
        }
        Ok(all_success)
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
        ctx: &RuleContext,
        rule_name: &str,
        action: NET_FW_ACTION,
        remote_addresses: &str,
        _logger: &mut Logger,
    ) -> Result<bool, WxcError> {
        let rules = unsafe { ctx.fw_policy.Rules() }
            .map_err(|e| WxcError::Firewall(format!("Failed to get firewall rules: {}", e)))?;

        let rule: windows::Win32::NetworkManagement::WindowsFirewall::INetFwRule =
            unsafe { CoCreateInstance(&NetFwRule, None, CLSCTX_INPROC_SERVER) }
                .map_err(|e| WxcError::Firewall(format!("Failed to create NetFwRule: {}", e)))?;

        let rule3: INetFwRule3 = rule.cast().map_err(|e| {
            WxcError::Firewall(format!("Failed to get INetFwRule3 interface: {}", e))
        })?;

        unsafe {
            rule.SetName(&BSTR::from(rule_name))
                .map_err(|e| WxcError::Firewall(format!("put_Name failed: {}", e)))?;

            rule.SetDescription(&BSTR::from("WXC AppContainer network policy"))
                .map_err(|e| WxcError::Firewall(format!("put_Description failed: {}", e)))?;

            rule3
                .SetLocalAppPackageId(&BSTR::from(ctx.principal_id))
                .map_err(|e| WxcError::Firewall(format!("put_LocalAppPackageId failed: {}", e)))?;

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
                    _logger.log_line(&format!(
                        "Failed to add firewall rule '{}': {}",
                        rule_name, e
                    ));
                    Ok(false)
                }
            }
        }
    }
}

impl Default for NetworkManager {
    fn default() -> Self {
        Self::new()
    }
}

impl Drop for NetworkManager {
    fn drop(&mut self) {
        // No COM state is cached across calls (each firewall op is
        // apartment-self-contained), so there is nothing COM-related to undo
        // here. Only the process-global Winsock refcount — which is
        // thread-agnostic — needs balancing.
        self.cleanup_wsa();
    }
}

/// Resolve a hostname to an IP address string.
pub fn resolve_hostname(hostname: &str) -> Result<String, WxcError> {
    let addr = (hostname, 0)
        .to_socket_addrs()
        .map_err(|e| WxcError::Firewall(format!("Failed to resolve '{}': {}", hostname, e)))?
        .next()
        .ok_or_else(|| WxcError::Firewall(format!("No addresses found for '{}'", hostname)))?;

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
        let mut logger = Logger::new(wxc_common::logger::Mode::Buffer);
        let policy = ContainerPolicy {
            network_enforcement_mode: NetworkEnforcementMode::Firewall,
            default_network_policy: NetworkPolicy::Block,
            ..Default::default()
        };
        let (default_policy, use_fw) = NetworkManager::initialize_policy(&policy, &mut logger);
        assert!(use_fw);
        assert_eq!(default_policy, DefaultPolicy::Block);
    }

    #[test]
    fn test_initialize_policy_capabilities_mode() {
        let mut logger = Logger::new(wxc_common::logger::Mode::Buffer);
        let policy = ContainerPolicy {
            network_enforcement_mode: NetworkEnforcementMode::Capabilities,
            ..Default::default()
        };
        let (default_policy, use_fw) = NetworkManager::initialize_policy(&policy, &mut logger);
        assert!(!use_fw);
        assert_eq!(default_policy, DefaultPolicy::Allow);
    }

    #[test]
    fn test_initialize_policy_firewall_with_allowed_hosts() {
        let mut logger = Logger::new(wxc_common::logger::Mode::Buffer);
        let policy = ContainerPolicy {
            network_enforcement_mode: NetworkEnforcementMode::Both,
            default_network_policy: NetworkPolicy::Allow,
            allowed_hosts: vec!["example.com".to_string()],
            ..Default::default()
        };
        let (default_policy, use_fw) = NetworkManager::initialize_policy(&policy, &mut logger);
        assert!(use_fw);
        assert_eq!(default_policy, DefaultPolicy::Allow);
    }

    #[test]
    fn test_default_creates_new_manager() {
        let mgr = NetworkManager::default();
        assert!(mgr.created_rule_names.is_empty());
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
