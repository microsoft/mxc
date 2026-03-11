use crate::error::WxcError;
use crate::filesystem_bfs::FileSystemBfsManager;
use crate::logger::Logger;
use crate::models::{CodexRequest, ScriptResponse};
use crate::network_firewall::NetworkFirewallManager;
use crate::validator::validate_request;

/// Trait for executing scripts within a security context.
///
/// Implements the template method pattern: `run` handles validation,
/// filesystem/network policy setup, execution, and cleanup.
/// Implementors provide `initialize`, `get_principal_id`, and `run_internal`.
pub trait ScriptRunner {
    /// Perform implementation-specific initialization (e.g. create an AppContainer SID).
    fn initialize(&mut self, request: &CodexRequest) -> Result<(), WxcError>;

    /// Return the security principal identifier used for firewall rules.
    fn get_principal_id(&self) -> String;

    /// Execute the script and return the response. Called after all policy is configured.
    fn run_internal(&mut self, request: &CodexRequest, logger: &mut Logger) -> ScriptResponse;

    /// Template method: validate → initialize → configure FS → configure network → run → cleanup.
    fn run(&mut self, request: &CodexRequest, logger: &mut Logger) -> ScriptResponse {
        if let Err(e) = validate_request(request) {
            return ScriptResponse::error(&e.to_string());
        }
        if let Err(e) = self.initialize(request) {
            return ScriptResponse::error(&e.to_string());
        }

        let principal_id = self.get_principal_id();

        let mut bfs_manager =
            FileSystemBfsManager::new(request.policy.app_container_name.clone());
        if let Err(e) = bfs_manager.configure(&request.policy, logger) {
            return ScriptResponse::error(&e.to_string());
        }

        let mut fw_manager = NetworkFirewallManager::new();
        match fw_manager.apply_firewall_rules(&principal_id, &request.policy, logger) {
            Ok(true) => {}
            Ok(false) => {
                return ScriptResponse::error("Failed to apply network firewall rules.");
            }
            Err(e) => {
                return ScriptResponse::error(&e.to_string());
            }
        }

        let response = match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            self.run_internal(request, logger)
        })) {
            Ok(r) => r,
            Err(_) => ScriptResponse::error("Unknown error during script execution."),
        };

        if fw_manager.rules_applied() && request.policy.remove_firewall_rules_on_exit {
            let _ = fw_manager.remove_firewall_rules(logger);
        }
        if bfs_manager.configured() && request.policy.clear_policy_on_exit {
            bfs_manager.remove_configuration(logger);
        }

        response
    }
}

/// Convert a timeout value to milliseconds, treating 0 as infinite (INFINITE = `u32::MAX`).
pub fn get_timeout_milliseconds(timeout: u32) -> u32 {
    if timeout == 0 { u32::MAX } else { timeout }
}

#[cfg(test)]
mod tests {
    use super::get_timeout_milliseconds;
    #[test]
    fn timeout_zero_returns_u32_max() {
        let result = get_timeout_milliseconds(0);
        assert_eq!(result, u32::MAX);
    }
    #[test]
    fn timeout_non_zero_returns_same_value() {
        let value = 1500u32;
        let result = get_timeout_milliseconds(value);
        assert_eq!(result, value);
    }
}