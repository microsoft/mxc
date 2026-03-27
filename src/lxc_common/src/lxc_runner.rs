// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! `LxcScriptRunner` — executes scripts inside LXC containers.
//!
//! Implements the `ScriptRunner` trait for LXC-based containment on Linux.

use std::fmt::Write;

use wxc_common::logger::Logger;
use wxc_common::models::{CodexRequest, LifecycleConfig, LxcConfig, ScriptResponse};
use wxc_common::script_runner::ScriptRunner;
use wxc_common::validator::validate_request;

use crate::filesystem_mounts;
use crate::lxc_bindings::LxcContainer;
use crate::network_iptables::NetworkIptablesManager;

/// Script runner that executes commands inside an LXC container.
pub struct LxcScriptRunner {
    config: LxcConfig,
    container_id: String,
    destroy_on_exit: bool,
    cleanup_policy: bool,
}

impl LxcScriptRunner {
    pub fn new(config: &LxcConfig, container_id: &str, lifecycle: &LifecycleConfig) -> Self {
        Self {
            config: config.clone(),
            container_id: container_id.to_string(),
            destroy_on_exit: lifecycle.destroy_on_exit,
            cleanup_policy: !lifecycle.preserve_policy,
        }
    }

    /// Generate a container name if one wasn't provided.
    fn resolve_container_name(&self) -> String {
        if self.container_id.is_empty() {
            format!("mxc-{}", uuid_simple())
        } else {
            self.container_id.clone()
        }
    }

    /// Core execution logic.
    fn run_internal(&self, request: &CodexRequest, logger: &mut Logger) -> ScriptResponse {
        let container_name = self.resolve_container_name();
        let _ = writeln!(logger, "Container name: {}", container_name);
        let _ = writeln!(
            logger,
            "Distribution: {}:{}",
            self.config.distribution, self.config.release
        );

        // Create container handle
        let container = LxcContainer::new(&container_name, None);
        let mut container_created = false;

        // Create the container if it doesn't exist
        if !container.is_defined() {
            let _ = writeln!(logger, "Creating LXC container...");
            if let Err(e) = container.create(&self.config.distribution, &self.config.release) {
                return ScriptResponse::error(&format!("Failed to create container: {}", e));
            }
            let _ = writeln!(logger, "Container created successfully.");
            container_created = true;
        } else {
            let _ = writeln!(logger, "Container already exists, reusing.");
        }

        // Configure filesystem mounts
        if let Err(e) =
            filesystem_mounts::configure_filesystem_mounts(&container, &request.policy, logger)
        {
            if self.destroy_on_exit || container_created {
                let _ = container.destroy();
            }
            return ScriptResponse::error(&format!("Failed to configure filesystem: {}", e));
        }

        // Ensure the container is running so that the veth interface exists
        if !container.is_running() {
            let _ = writeln!(logger, "Starting LXC container...");
            if let Err(e) = container.start() {
                let _ = container.destroy();
                return ScriptResponse::error(&format!("Failed to start container: {}", e));
            }
            let _ = writeln!(logger, "Container started successfully.");
        } else {
            let _ = writeln!(logger, "Container already running.");
        }

        // Configure network rules
        let mut fw_manager = NetworkIptablesManager::new(&container_name);

        // Try to discover the container's veth interface for scoped rules
        if let Some(veth) = NetworkIptablesManager::discover_veth_interface(&container_name) {
            let _ = writeln!(logger, "Discovered veth interface: {}", veth);
            fw_manager.set_veth_interface(&veth);
        }

        match fw_manager.apply_firewall_rules(&request.policy, logger) {
            Ok(true) => {}
            Ok(false) => {
                if self.destroy_on_exit || container_created {
                    let _ = container.destroy();
                }
                return ScriptResponse::error("Failed to apply network firewall rules.");
            }
            Err(e) => {
                if self.destroy_on_exit || container_created {
                    let _ = container.destroy();
                }
                return ScriptResponse::error(&format!("Network policy error: {}", e));
            }
        }

        // Execute the script using lxc-attach (container is already running)
        // TODO: Thread request.script_timeout through to attach_run for timeout enforcement.
        let _ = writeln!(logger, "Executing script inside container...");
        let result = container.attach_run(&request.script_code, &request.working_directory);

        let response = match result {
            Ok((exit_code, stdout, stderr)) => ScriptResponse {
                exit_code,
                standard_out: stdout,
                standard_err: stderr,
                error_message: String::new(),
            },
            Err(e) => ScriptResponse::error(&format!("Execution failed: {}", e)),
        };

        // Cleanup: remove network rules
        if fw_manager.rules_applied() && self.cleanup_policy {
            let _ = fw_manager.remove_firewall_rules(logger);
        }

        // Cleanup: destroy container if configured
        if self.destroy_on_exit {
            let _ = writeln!(logger, "Destroying container...");
            if let Err(e) = container.destroy() {
                let _ = writeln!(logger, "Warning: failed to destroy container: {}", e);
            }
        }

        response
    }
}

impl ScriptRunner for LxcScriptRunner {
    fn run(&mut self, request: &CodexRequest, logger: &mut Logger) -> ScriptResponse {
        // Validate the request first
        if let Err(e) = validate_request(request) {
            return ScriptResponse::error(&e.to_string());
        }

        // Run with panic catching for safety
        match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            self.run_internal(request, logger)
        })) {
            Ok(r) => r,
            Err(_) => ScriptResponse::error("Unknown error during LXC script execution."),
        }
    }
}

/// Generate a simple 8-character hex ID (no uuid crate dependency needed).
fn uuid_simple() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let t = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    format!("{:08x}", (t & 0xFFFF_FFFF) as u32)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn uuid_simple_is_8_chars() {
        let id = uuid_simple();
        assert_eq!(id.len(), 8);
        assert!(id.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn resolve_container_name_uses_config() {
        let config = LxcConfig::default();
        let lifecycle = LifecycleConfig::default();
        let runner = LxcScriptRunner::new(&config, "my-test", &lifecycle);
        assert_eq!(runner.resolve_container_name(), "my-test");
    }

    #[test]
    fn resolve_container_name_generates_when_empty() {
        let config = LxcConfig::default();
        let lifecycle = LifecycleConfig::default();
        let runner = LxcScriptRunner::new(&config, "", &lifecycle);
        let name = runner.resolve_container_name();
        assert!(name.starts_with("mxc-"));
    }
}
