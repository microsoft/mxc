// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! `LxcScriptRunner` — executes scripts inside LXC containers.
//!
//! Implements the `ScriptRunner` trait for LXC-based containment on Linux.

use std::fmt::Write;
use std::thread;
use std::time::{Duration, Instant};

use wxc_common::logger::Logger;
use wxc_common::models::{
    ExecutionRequest, LifecycleConfig, LxcConfig, NetworkEnforcementMode, ScriptResponse,
};
use wxc_common::script_runner::ScriptRunner;

use crate::filesystem_mounts;
use crate::lxc_bindings::LxcContainer;
use crate::network_iptables::NetworkIptablesManager;
use crate::signal_cleanup;

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

    /// Wait for the container's network stack to initialize.
    /// Polls `lxc-info` until the container has an IP address or the timeout is reached.
    fn wait_for_network(container_name: &str, timeout: Duration, logger: &mut Logger) -> bool {
        let start = Instant::now();
        let poll_interval = Duration::from_millis(500);

        let _ = writeln!(logger, "Waiting for container network to initialize...");

        while start.elapsed() < timeout {
            let output = std::process::Command::new("lxc-info")
                .arg("-n")
                .arg(container_name)
                .arg("-iH")
                .output();

            if let Ok(out) = output {
                let stdout = String::from_utf8_lossy(&out.stdout);
                let ip = stdout.trim();
                if !ip.is_empty() {
                    let _ = writeln!(
                        logger,
                        "Container network ready (IP: {}, waited {:.1}s)",
                        ip,
                        start.elapsed().as_secs_f64()
                    );
                    return true;
                }
            }

            thread::sleep(poll_interval);
        }

        let _ = writeln!(
            logger,
            "Warning: container network not ready after {:.1}s",
            timeout.as_secs_f64()
        );
        false
    }

    /// Core execution logic.
    fn run_internal(&self, request: &ExecutionRequest, logger: &mut Logger) -> ScriptResponse {
        // Object-based FS-policy normalization (D6): tighten aliases of the same
        // host object to the strictest intent (deny > ro > rw) before building
        // mounts. See `wxc_common::filesystem_object`. Only clone the request
        // when an aliasing conflict actually needs tightening; an unresolvable
        // path with deniedPaths present fails closed.
        let normalized;
        let request = match wxc_common::filesystem_object::normalize_object_conflicts(
            &request.policy,
            logger,
        ) {
            Ok(Some(policy)) => {
                normalized = ExecutionRequest {
                    policy,
                    ..request.clone()
                };
                &normalized
            }
            Ok(None) => request,
            Err(msg) => return ScriptResponse::error(&msg),
        };

        // Validate required LXC fields
        if self.config.distribution.is_empty() || self.config.release.is_empty() {
            return ScriptResponse::error(
                "LXC distribution and release are required \
                 (e.g., \"distribution\": \"alpine\", \"release\": \"3.23\")",
            );
        }

        let container_name = self.resolve_container_name();
        // Make the name visible to the signal-cleanup watchdog so a fatal
        // signal during create/start/attach still tears the container down —
        // but only when the caller actually wants the container destroyed at
        // exit. With `destroyOnExit = false` the normal completion path
        // preserves the container, so the signal path must too.
        if self.destroy_on_exit {
            signal_cleanup::set_active(&container_name);
        }
        let _ = writeln!(logger, "Container name: {}", container_name);
        let _ = writeln!(
            logger,
            "Distribution: {}:{}",
            self.config.distribution, self.config.release
        );

        // Apply experimental features when flag is set
        if request.experimental_enabled {
            if let Some(ref test) = request.experimental.test {
                let _ = writeln!(
                    logger,
                    "Experimental feature 'test' applied: {}",
                    test.message
                );
            }
        }

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
                if self.destroy_on_exit || container_created {
                    let _ = container.destroy();
                }
                return ScriptResponse::error(&format!("Failed to start container: {}", e));
            }
            let _ = writeln!(logger, "Container started successfully.");
        } else {
            let _ = writeln!(logger, "Container already running.");
        }

        // Wait for network only when the config uses network features (firewall rules
        // or allowed/blocked hosts).
        let needs_network = matches!(
            request.policy.network_enforcement_mode,
            NetworkEnforcementMode::Firewall | NetworkEnforcementMode::Both
        ) || !request.policy.allowed_hosts.is_empty()
            || !request.policy.blocked_hosts.is_empty();

        if needs_network {
            Self::wait_for_network(&container_name, Duration::from_secs(10), logger);
        }

        // Configure network rules
        let mut fw_manager = NetworkIptablesManager::new(&container_name);

        // Try to discover the container's veth interface for scoped rules
        if let Some(veth) = NetworkIptablesManager::discover_veth_interface(&container_name) {
            let _ = writeln!(logger, "Discovered veth interface: {}", veth);
            fw_manager.set_veth_interface(&veth);
            if self.destroy_on_exit {
                // Tell the watchdog about the veth so signal-time cleanup
                // can also remove the FORWARD hook, not just the chain.
                signal_cleanup::set_active_veth(&veth);
            }
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

        // Execute the script using lxc-attach (container is already running).
        // `script_timeout == 0` means "no timeout" per the SDK contract.
        let timeout = if request.script_timeout == 0 {
            None
        } else {
            Some(Duration::from_millis(u64::from(request.script_timeout)))
        };
        let _ = writeln!(logger, "Executing script inside container...");
        let result = container.attach_run(
            &request.script_code,
            &request.working_directory,
            &request.env,
            timeout,
        );

        let response = match result {
            Ok((exit_code, stdout, stderr)) => ScriptResponse {
                exit_code,
                standard_out: stdout,
                standard_err: stderr,
                error_message: String::new(),
                ..Default::default()
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
    fn execute(&mut self, request: &ExecutionRequest, logger: &mut Logger) -> ScriptResponse {
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
