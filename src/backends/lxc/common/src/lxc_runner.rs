// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use std::fmt::Write;
use std::thread;
use std::time::{Duration, Instant};

use wxc_common::logger::Logger;
use wxc_common::models::{
    ContainerPolicy, ExecutionRequest, LifecycleConfig, LxcConfig, NetworkEnforcementMode,
    ScriptResponse,
};
use wxc_common::script_runner::ScriptRunner;
use wxc_common::validator::{validate_network_policy_support, NetworkPolicySupport};

use crate::filesystem_mounts;
use crate::lxc_bindings::{LxcContainer, StartNetwork};
use crate::network_ingress::IngressManager;
use crate::network_iptables::{
    needs_network, plan_network, uses_directional_keys, EgressHookPoint, NetworkIptablesManager,
};
use crate::signal_cleanup;

const HOSTS_PIN_MARKER: &str = "#mxc-proxy-pin";

/// The `/etc/hosts` rewrites are short shell commands and must not inherit the script timeout.
const HOSTS_COMMAND_TIMEOUT: Duration = Duration::from_secs(30);

#[derive(Clone, Copy)]
enum ContainerRelease {
    Destroy,
    Stop,
}

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

    fn resolve_container_name(&self) -> String {
        if self.container_id.is_empty() {
            format!("mxc-{}", uuid_simple())
        } else {
            self.container_id.clone()
        }
    }

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

    fn release_kind(&self, container_created: bool) -> ContainerRelease {
        if self.destroy_on_exit || container_created {
            ContainerRelease::Destroy
        } else {
            ContainerRelease::Stop
        }
    }

    fn report_release_failure(
        release: ContainerRelease,
        result: Result<(), String>,
        logger: &mut Logger,
    ) {
        let Err(e) = result else {
            return;
        };
        let verb = match release {
            ContainerRelease::Destroy => "destroy",
            ContainerRelease::Stop => "stop",
        };
        let _ = writeln!(logger, "Warning: failed to {} container: {}", verb, e);
    }

    fn release_after_failure(
        &self,
        container: &LxcContainer,
        container_created: bool,
        logger: &mut Logger,
    ) {
        let release = self.release_kind(container_created);
        let result = match release {
            ContainerRelease::Destroy => container.destroy(),
            ContainerRelease::Stop => container.stop(),
        };
        Self::report_release_failure(release, result, logger);
    }

    fn set_up_network_rules_for_v07(
        &self,
        container_name: &str,
        hook_point: EgressHookPoint,
        netns_pid: Option<u32>,
        policy: &ContainerPolicy,
        logger: &mut Logger,
    ) -> Result<(NetworkIptablesManager, Option<IngressManager>), String> {
        let mut fw_manager = NetworkIptablesManager::new(container_name, hook_point);
        fw_manager.set_preserve_policy(!self.cleanup_policy);
        Self::egress_apply_outcome(fw_manager.apply_legacy_rules(policy, logger))?;

        let mut ingress_manager = None;
        if let Some(pid) = netns_pid {
            let mut mgr = IngressManager::new(container_name, pid);
            Self::ingress_apply_outcome(mgr.apply_legacy_rules(policy, logger))?;
            mgr.set_preserve_policy(!self.cleanup_policy);
            ingress_manager = Some(mgr);
        }

        Ok((fw_manager, ingress_manager))
    }

    fn set_up_network_rules_for_v08(
        &self,
        container_name: &str,
        hook_point: EgressHookPoint,
        netns_pid: Option<u32>,
        policy: &ContainerPolicy,
        logger: &mut Logger,
    ) -> Result<(NetworkIptablesManager, Option<IngressManager>), String> {
        let mut fw_manager = NetworkIptablesManager::new(container_name, hook_point);
        fw_manager.set_preserve_policy(!self.cleanup_policy);
        Self::egress_apply_outcome(fw_manager.apply_directional_rules(policy, logger))?;

        let mut ingress_manager = None;
        if let Some(pid) = netns_pid {
            let mut mgr = IngressManager::new(container_name, pid);
            Self::ingress_apply_outcome(mgr.apply_directional_rules(policy, logger))?;
            mgr.set_preserve_policy(!self.cleanup_policy);
            ingress_manager = Some(mgr);
        }

        Ok((fw_manager, ingress_manager))
    }

    fn egress_apply_outcome(result: Result<bool, String>) -> Result<(), String> {
        match result {
            Ok(true) => Ok(()),
            Ok(false) => Err("Failed to apply network firewall rules.".to_string()),
            Err(e) => Err(format!("Network policy error: {}", e)),
        }
    }

    fn ingress_apply_outcome(result: Result<bool, String>) -> Result<(), String> {
        match result {
            Ok(true) => Ok(()),
            Ok(false) => Err("Failed to apply inbound network firewall rules.".to_string()),
            Err(e) => Err(format!("Inbound network policy error: {}", e)),
        }
    }

    fn enforce_network_readiness<P, R>(
        &self,
        container_name: &str,
        container_created: bool,
        timeout: Duration,
        logger: &mut Logger,
        readiness_probe: P,
        mut release_container: R,
    ) -> Option<ScriptResponse>
    where
        P: FnOnce(&str, Duration, &mut Logger) -> bool,
        R: FnMut(ContainerRelease) -> Result<(), String>,
    {
        if readiness_probe(container_name, timeout, logger) {
            return None;
        }

        let release = self.release_kind(container_created);
        Self::report_release_failure(release, release_container(release), logger);

        Some(ScriptResponse::error(&format!(
            "Container network did not initialize within {:.0}s; \
             check that lxc-net/dnsmasq is running and able to assign an IP.",
            timeout.as_secs_f64()
        )))
    }

    fn enforce_netns_discovery<R>(
        &self,
        netns_pid: Option<u32>,
        installs_firewall: bool,
        container_created: bool,
        logger: &mut Logger,
        mut release_container: R,
    ) -> Result<EgressHookPoint, ScriptResponse>
    where
        R: FnMut(ContainerRelease) -> Result<(), String>,
    {
        if let Some(hook_point) = egress_hook_point(netns_pid, installs_firewall) {
            return Ok(hook_point);
        }

        let release = self.release_kind(container_created);
        Self::report_release_failure(release, release_container(release), logger);

        Err(ScriptResponse::error(
            "Failed to discover the container init PID; cannot enter the container \
             network namespace to enforce the requested firewall. Aborting rather \
             than running with enforcement silently disabled.",
        ))
    }

    fn run_internal(&self, request: &ExecutionRequest, logger: &mut Logger) -> ScriptResponse {
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
        if let Err(msg) = wxc_common::filesystem_access::check_delegation(&request.policy) {
            return ScriptResponse::error(&msg);
        }

        if self.config.distribution.is_empty() || self.config.release.is_empty() {
            return ScriptResponse::error(
                "LXC distribution and release are required \
                 (e.g., \"distribution\": \"alpine\", \"release\": \"3.23\")",
            );
        }

        let container_name = self.resolve_container_name();

        // A process's argv is world-readable through /proc/<pid>/cmdline.
        // Refuse credential-bearing proxy URLs before they become lxc-attach
        // `--set-var` arguments.
        if let Some(url) = request
            .policy
            .network_proxy
            .address
            .as_ref()
            .map(|address| address.to_url())
        {
            if wxc_common::proxy_env::proxy_url_has_credentials(&url) {
                return ScriptResponse::error(&format!(
                    "LXC: network.proxy.url must not carry credentials ('{}'). LXC passes the \
                     proxy URL to lxc-attach as a --set-var command-line argument, and process \
                     arguments are world-readable through /proc/<pid>/cmdline, so the password \
                     would be visible to every local user while the command runs. Use a proxy \
                     that does not require inline credentials, or supply them to the proxy \
                     itself rather than through the URL.",
                    wxc_common::proxy_env::redact_proxy_url(&url)
                ));
            }
        }

        if self.destroy_on_exit {
            signal_cleanup::set_active(&container_name);
        }
        let _ = writeln!(logger, "Container name: {}", container_name);
        let _ = writeln!(
            logger,
            "Distribution: {}:{}",
            self.config.distribution, self.config.release
        );

        if request.experimental_enabled {
            if let Some(ref test) = request.experimental.test {
                let _ = writeln!(
                    logger,
                    "Experimental feature 'test' applied: {}",
                    test.message
                );
            }
        }

        let container = LxcContainer::new(&container_name, None);
        let mut container_created = false;

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

        if let Err(e) =
            filesystem_mounts::configure_filesystem_mounts(&container, &request.policy, logger)
        {
            if self.destroy_on_exit || container_created {
                let _ = container.destroy();
            }
            return ScriptResponse::error(&format!("Failed to configure filesystem: {}", e));
        }

        // LXC reads the network section only at start.  A container an earlier
        // run left running is still on that run's topology.
        if container.is_running() {
            let _ = writeln!(
                logger,
                "Container already running; stopping it so this run's network policy applies."
            );
            if let Err(e) = container.stop() {
                if self.destroy_on_exit || container_created {
                    let _ = container.destroy();
                }
                return ScriptResponse::error(&format!(
                    "Failed to stop a container left running by an earlier run: {}. \
                     Its network policy is the earlier run's, so the script was not run.",
                    e
                ));
            }
        }

        let plan = plan_network(&request.policy);

        let network = if plan.omits_interface() {
            let _ = writeln!(
                logger,
                "Policy permits no network; starting the container with no interface."
            );
            StartNetwork::NoInterface
        } else {
            StartNetwork::FromContainerConfig
        };

        let _ = writeln!(logger, "Starting LXC container...");
        if let Err(e) = container.start(network) {
            if self.destroy_on_exit || container_created {
                let _ = container.destroy();
            }
            return ScriptResponse::error(&format!("Failed to start container: {}", e));
        }
        let _ = writeln!(logger, "Container started successfully.");

        let needs_network = needs_network(&request.policy);

        if needs_network {
            // Alpine DHCP leases can arrive at about nine seconds; thirty
            // seconds leaves margin.
            let timeout = Duration::from_secs(30);
            if let Some(response) = self.enforce_network_readiness(
                &container_name,
                container_created,
                timeout,
                logger,
                Self::wait_for_network,
                |release| match release {
                    ContainerRelease::Destroy => container.destroy(),
                    ContainerRelease::Stop => container.stop(),
                },
            ) {
                return response;
            }
        }

        // The init PID names the container's network namespace.
        let netns_pid = container.init_pid();
        let hook_point = match self.enforce_netns_discovery(
            netns_pid,
            plan.installs_firewall(),
            container_created,
            logger,
            |release| match release {
                ContainerRelease::Destroy => container.destroy(),
                ContainerRelease::Stop => container.stop(),
            },
        ) {
            Ok(hook_point) => hook_point,
            Err(response) => return response,
        };

        if let Some(pid) = netns_pid {
            let _ = writeln!(logger, "Container init PID: {}", pid);
            if self.destroy_on_exit {
                signal_cleanup::set_active_pid(pid);
            }
        }

        let setup = if uses_directional_keys(&request.policy) {
            self.set_up_network_rules_for_v08(
                &container_name,
                hook_point,
                netns_pid,
                &request.policy,
                logger,
            )
        } else {
            self.set_up_network_rules_for_v07(
                &container_name,
                hook_point,
                netns_pid,
                &request.policy,
                logger,
            )
        };

        let (mut fw_manager, mut ingress_manager) = match setup {
            Ok(managers) => managers,
            Err(e) => {
                self.release_after_failure(&container, container_created, logger);
                return ScriptResponse::error(&e);
            }
        };

        let mut pinned = false;

        // A proxied chain opens no port 53; without this pin the container has
        // no resolver to reach its proxy.
        if let Some(pin) = fw_manager.proxy_host_pin() {
            let command = Self::build_hosts_pin_command(&pin.hosts_line());
            let _ = writeln!(
                logger,
                "Pinning proxy host {} to {} in the container's /etc/hosts.",
                pin.hostname(),
                pin.ip()
            );
            let pin_outcome =
                container.attach_run(&command, "/", &[], true, Some(HOSTS_COMMAND_TIMEOUT));
            let pin_error = match pin_outcome {
                Ok((0, _, _)) => None,

                Ok((code, _, _)) => Some(Self::hosts_command_failure("writing", code)),
                Err(e) => Some(e.to_string()),
            };
            if let Some(reason) = pin_error {
                self.release_after_failure(&container, container_created, logger);
                return ScriptResponse::error(&format!(
                    "Failed to pin the network proxy host inside the container: {}. \
                     The proxy would be unreachable, so the script was not run.",
                    reason
                ));
            }
            pinned = true;
        } else if !container_created {
            let clear_stale_pin_command = Self::build_hosts_unpin_command();
            let stale_pin_error = match container.attach_run(
                &clear_stale_pin_command,
                "/",
                &[],
                true,
                Some(HOSTS_COMMAND_TIMEOUT),
            ) {
                Ok((0, _, _)) => None,
                Ok((code, _, _)) => Some(Self::hosts_command_failure("clearing", code)),
                Err(e) => Some(e.to_string()),
            };

            if let Some(reason) = stale_pin_error {
                self.release_after_failure(&container, container_created, logger);
                return ScriptResponse::error(&format!(
                    "Failed to clear a stale network proxy pin from the container's \
                     /etc/hosts: {}. The script was not run, because it could have resolved \
                     the pinned hostname to an address this policy did not authorize.",
                    reason
                ));
            }
        }

        // `script_timeout == 0` means "no timeout" per the SDK contract.
        let timeout = if request.script_timeout == 0 {
            None
        } else {
            Some(Duration::from_millis(u64::from(request.script_timeout)))
        };
        let _ = writeln!(logger, "Executing script inside container...");
        let mut exec_env = request.env.clone();
        wxc_common::proxy_env::apply_proxy_env(&mut exec_env, &request.policy.network_proxy);

        // An empty env makes `lxc-attach` inherit the host process
        // environment, proxy variables and credentials included.
        let result = container.attach_run(
            &request.script_code,
            &request.working_directory,
            &exec_env,
            true,
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

        if pinned && self.cleanup_policy {
            let clear_run_pin_command = Self::build_hosts_unpin_command();
            let unpin_error = match container.attach_run(
                &clear_run_pin_command,
                "/",
                &[],
                true,
                Some(HOSTS_COMMAND_TIMEOUT),
            ) {
                Ok((0, _, _)) => None,
                Ok((code, _, _)) => Some(Self::hosts_command_failure("clearing", code)),
                Err(e) => Some(e.to_string()),
            };

            if let Some(reason) = unpin_error {
                let _ = writeln!(
                    logger,
                    "Warning: failed to clear the proxy host pin: {}",
                    reason
                );
            }
        }

        if fw_manager.rules_applied() && self.cleanup_policy {
            let _ = fw_manager.remove_firewall_rules(logger);
        }
        if let Some(mgr) = &mut ingress_manager {
            if mgr.rules_applied() && self.cleanup_policy {
                let _ = mgr.remove_firewall_rules(logger);
            }
        }

        if self.destroy_on_exit {
            let _ = writeln!(logger, "Destroying container...");
            if let Err(e) = container.destroy() {
                let _ = writeln!(logger, "Warning: failed to destroy container: {}", e);
            }
        }

        response
    }

    fn build_hosts_pin_command(hosts_line: &str) -> String {
        // LXC may bind-mount `/etc/hosts`; rewrite it in place.  BusyBox
        // images have `grep` and `printf`, and kept lines stay in a shell
        // variable to avoid following a predictable scratch-file symlink.
        // Shell command substitution strips trailing newlines; `printf` writes
        // one back only when content survived the filter.
        format!(
            "{}{{ if [ -n \"$kept\" ]; then printf '%s\\n' \"$kept\"; fi; \
             printf '%s {marker}\\n' '{hosts_line}'; }} > /etc/hosts",
            Self::hosts_read_prologue(),
            marker = HOSTS_PIN_MARKER,
            hosts_line = hosts_line
        )
    }

    fn hosts_read_prologue() -> String {
        // Read `/etc/hosts` before the redirect opens and truncates it.  `grep`
        // status 1 means no line was selected, missing `grep` reports 127, and
        // `grep` reports absent and unreadable files as status 2.
        format!(
            "if [ -h /etc/hosts ]; then \
             printf 'mxc: refusing to rewrite /etc/hosts: it is a symbolic link\\n' >&2; \
             exit 4; \
             fi; \
             kept=''; \
             if [ -e /etc/hosts ]; then \
             kept=$(grep -v '{marker}' /etc/hosts 2>/dev/null); \
             status=$?; \
             if [ \"$status\" -gt 1 ]; then \
             printf 'mxc: refusing to rewrite /etc/hosts: reading it exited %s\\n' \
             \"$status\" >&2; \
             exit \"$status\"; \
             fi; \
             fi; ",
            marker = HOSTS_PIN_MARKER
        )
    }

    fn build_hosts_unpin_command() -> String {
        format!(
            "{}{{ if [ -n \"$kept\" ]; then printf '%s\\n' \"$kept\"; fi; }} > /etc/hosts",
            Self::hosts_read_prologue()
        )
    }

    fn hosts_command_failure(verb: &str, exit_code: i32) -> String {
        format!("{} /etc/hosts exited with {}", verb, exit_code)
    }
}

pub const LXC_CAPABILITIES_MODE_UNSUPPORTED: &str =
    "LXC: network.enforcementMode='capabilities' (the default) selects Windows AppContainer \
     capability SIDs, which LXC has no mechanism for. Accepting it would enforce the policy by \
     some means other than the one named. Set network.enforcementMode to 'firewall' or 'both', \
     or state the policy in the 0.8 network.egress / network.ingress form, which carries no \
     enforcement mode.";

fn asks_for_capabilities_enforcement(request: &ExecutionRequest) -> bool {
    !uses_directional_keys(&request.policy)
        && request.policy.network_mode_specified
        && matches!(
            request.policy.network_enforcement_mode,
            NetworkEnforcementMode::Capabilities
        )
}

fn lxc_network_policy_support() -> NetworkPolicySupport {
    NetworkPolicySupport::EGRESS_DEFAULT
        | NetworkPolicySupport::EGRESS_RULES
        | NetworkPolicySupport::INGRESS_DEFAULT
        | NetworkPolicySupport::HOST_LOOPBACK
}

impl ScriptRunner for LxcScriptRunner {
    fn validate_runner(&self, request: &ExecutionRequest) -> Result<(), ScriptResponse> {
        validate_network_policy_support(request, lxc_network_policy_support())?;
        if asks_for_capabilities_enforcement(request) {
            return Err(ScriptResponse::error(LXC_CAPABILITIES_MODE_UNSUPPORTED));
        }
        Ok(())
    }

    fn execute(&mut self, request: &ExecutionRequest, logger: &mut Logger) -> ScriptResponse {
        match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            self.run_internal(request, logger)
        })) {
            Ok(r) => r,
            Err(_) => ScriptResponse::error("Unknown error during LXC script execution."),
        }
    }
}

fn uuid_simple() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let t = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    format!("{:08x}", (t & 0xFFFF_FFFF) as u32)
}

fn egress_hook_point(netns_pid: Option<u32>, installs_firewall: bool) -> Option<EgressHookPoint> {
    match netns_pid {
        Some(pid) => Some(EgressHookPoint::ContainerNetns(pid)),
        None if installs_firewall => None,
        None => Some(EgressHookPoint::Unhooked),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use wxc_common::logger::Mode;
    use wxc_common::models::ContainerPolicy;

    fn validating_runner() -> LxcScriptRunner {
        LxcScriptRunner::new(
            &LxcConfig::default(),
            "validate-test",
            &LifecycleConfig::default(),
        )
    }

    fn request_with_policy(policy: ContainerPolicy) -> ExecutionRequest {
        ExecutionRequest {
            policy,
            ..Default::default()
        }
    }

    #[test]
    fn a_07_network_section_left_on_capabilities_is_refused() {
        let policy = ContainerPolicy {
            network_mode_specified: true,
            ..Default::default()
        };

        let refusal = validating_runner()
            .validate_runner(&request_with_policy(policy))
            .expect_err("LXC has no capability-SID mechanism to enforce through");

        assert_eq!(refusal.error_message, LXC_CAPABILITIES_MODE_UNSUPPORTED);
    }

    #[test]
    fn a_07_network_section_naming_the_firewall_is_accepted() {
        let policy = ContainerPolicy {
            network_mode_specified: true,
            network_enforcement_mode: NetworkEnforcementMode::Firewall,
            ..Default::default()
        };

        assert!(validating_runner()
            .validate_runner(&request_with_policy(policy))
            .is_ok());
    }

    #[test]
    fn a_request_with_no_network_section_is_accepted() {
        assert!(validating_runner()
            .validate_runner(&request_with_policy(ContainerPolicy::default()))
            .is_ok());
    }

    #[test]
    fn a_08_directional_network_section_is_accepted() {
        let policy = ContainerPolicy {
            network_egress: Some(NetworkEgressPolicy::default()),
            ..Default::default()
        };

        assert!(validating_runner()
            .validate_runner(&request_with_policy(policy))
            .is_ok());
    }

    #[test]
    fn a_known_netns_hooks_the_chain_inside_the_container() {
        assert!(matches!(
            egress_hook_point(Some(4242), true),
            Some(EgressHookPoint::ContainerNetns(4242))
        ));
    }

    #[test]
    fn an_unknown_netns_refuses_to_run_when_a_firewall_was_requested() {
        let mut logger = Logger::new(Mode::Buffer);

        let response = runner_for_network_readiness_tests(true)
            .enforce_netns_discovery(None, true, true, &mut logger, |_release| Ok(()))
            .expect_err("a firewall was requested and the namespace is unknown");

        assert_ne!(response.exit_code, 0);
        assert!(response.standard_out.is_empty());
    }

    #[test]
    fn a_known_netns_lets_the_run_proceed() {
        let mut logger = Logger::new(Mode::Buffer);

        assert!(matches!(
            runner_for_network_readiness_tests(true).enforce_netns_discovery(
                Some(4242),
                true,
                true,
                &mut logger,
                |_release| Ok(())
            ),
            Ok(EgressHookPoint::ContainerNetns(4242))
        ));
    }

    #[test]
    fn an_unknown_netns_is_allowed_when_no_firewall_was_requested() {
        assert!(matches!(
            egress_hook_point(None, false),
            Some(EgressHookPoint::Unhooked)
        ));
    }

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

    #[test]
    fn the_hosts_pin_command_writes_the_requested_mapping() {
        let command = LxcScriptRunner::build_hosts_pin_command("10.0.0.5 proxy.example.com");

        assert!(
            command.contains("'10.0.0.5 proxy.example.com'"),
            "the command must carry the mapping verbatim, got: {command}"
        );
        assert!(
            command.contains("/etc/hosts"),
            "the command must target /etc/hosts, got: {command}"
        );
    }

    #[test]
    fn the_hosts_pin_command_strips_its_own_previous_entries_first() {
        let command = LxcScriptRunner::build_hosts_pin_command("10.0.0.5 proxy.example.com");

        assert!(
            command.contains(&format!("grep -v '{}'", HOSTS_PIN_MARKER)),
            "the command must remove prior pins before writing; got: {command}"
        );
        assert!(
            command.matches(HOSTS_PIN_MARKER).count() >= 2,
            "the written line must carry the marker that the strip looks for; got: {command}"
        );
    }

    #[test]
    fn a_failed_hosts_command_reports_a_reason_it_can_actually_supply() {
        for verb in ["writing", "clearing"] {
            let reason = LxcScriptRunner::hosts_command_failure(verb, 1);

            assert!(
                reason.contains('1'),
                "the reason must name the exit code; got: {reason}"
            );
            assert!(
                !reason.trim_end().ends_with(':'),
                "the reason must not trail a separator promising more; got: {reason:?}"
            );
            assert_eq!(
                reason.trim_end(),
                reason,
                "the reason must not trail whitespace where a stderr used to go; got: {reason:?}"
            );
        }
    }

    #[test]
    fn a_failed_hosts_command_distinguishes_the_step_that_failed() {
        let pinning = LxcScriptRunner::hosts_command_failure("writing", 2);
        let clearing = LxcScriptRunner::hosts_command_failure("clearing", 2);

        assert_ne!(
            pinning, clearing,
            "the two steps must not produce the same reason; got: {pinning:?}"
        );
    }

    #[test]
    fn the_hosts_unpin_command_removes_the_marker_without_writing_a_new_one() {
        let command = LxcScriptRunner::build_hosts_unpin_command();

        assert!(
            command.contains(&format!("grep -v '{}'", HOSTS_PIN_MARKER)),
            "the command must filter out every marked line; got: {command}"
        );

        assert_eq!(
            command.matches(HOSTS_PIN_MARKER).count(),
            1,
            "the marker should appear only in the filter; got: {command}"
        );
    }

    #[test]
    fn the_hosts_unpin_command_rewrites_the_file_in_place_rather_than_replacing_it() {
        let command = LxcScriptRunner::build_hosts_unpin_command();

        assert!(
            command.contains("> /etc/hosts"),
            "the command must rewrite the existing file; got: {command}"
        );
        assert!(
            !command.contains("mv "),
            "the command must not replace the inode; got: {command}"
        );
    }

    #[test]
    fn the_hosts_pin_command_rewrites_the_file_in_place_rather_than_replacing_it() {
        let command = LxcScriptRunner::build_hosts_pin_command("10.0.0.5 proxy.example.com");

        assert!(
            command.contains("> /etc/hosts"),
            "the command must redirect into the existing file, got: {command}"
        );
        assert!(
            !command.contains("mv "),
            "the command must not replace the inode, got: {command}"
        );
    }

    #[test]
    fn the_hosts_pin_command_uses_only_busybox_available_tools() {
        let command = LxcScriptRunner::build_hosts_pin_command("10.0.0.5 proxy.example.com");

        for forbidden in ["sed ", "awk ", "tee ", "sponge "] {
            assert!(
                !command.contains(forbidden),
                "the command must not depend on {forbidden:?}, got: {command}"
            );
        }
    }

    #[test]
    fn the_hosts_commands_stage_nothing_in_a_container_writable_directory() {
        let commands = [
            LxcScriptRunner::build_hosts_pin_command("10.0.0.5 proxy.example.com"),
            LxcScriptRunner::build_hosts_unpin_command(),
        ];

        for command in commands {
            for scratch in ["/tmp/", "/var/tmp/", "/dev/shm/", "/run/"] {
                assert!(
                    !command.contains(scratch),
                    "the command must not stage under {scratch:?}, got: {command}"
                );
            }
            assert_eq!(
                command.matches("> /etc/hosts").count(),
                1,
                "/etc/hosts must be the only redirect target; got: {command}"
            );
        }
    }

    #[test]
    fn the_hosts_commands_build_their_content_before_truncating_the_target() {
        let commands = [
            LxcScriptRunner::build_hosts_pin_command("10.0.0.5 proxy.example.com"),
            LxcScriptRunner::build_hosts_unpin_command(),
        ];

        for command in commands {
            let capture = command.find("kept=$(").unwrap_or_else(|| {
                panic!("the command must stage into a variable; got: {command}")
            });
            let redirect = command
                .find("> /etc/hosts")
                .unwrap_or_else(|| panic!("the command must target /etc/hosts; got: {command}"));

            assert!(
                capture < redirect,
                "the content must be captured before /etc/hosts is truncated; got: {command}"
            );
            assert!(
                !command[redirect..].contains("grep"),
                "no file-reading command may run after the target is truncated; got: {command}"
            );
        }
    }

    use wxc_common::models::{
        NetworkEgressPolicy, NetworkIngressPolicy, ProxyAddress, ProxyConfig,
    };

    fn request_with_proxy_url(url: &str) -> ExecutionRequest {
        let mut request = ExecutionRequest::default();
        request.policy.network_proxy = ProxyConfig {
            address: Some(ProxyAddress::from_url(
                url,
                "proxy.example.com".to_string(),
                8080,
            )),
            builtin_test_server: false,
        };
        request
    }

    fn runner_for_guard_tests() -> LxcScriptRunner {
        let config = LxcConfig {
            distribution: "alpine".to_string(),
            release: "3.23".to_string(),
        };
        LxcScriptRunner::new(&config, "mxc-guard-test", &LifecycleConfig::default())
    }

    fn runner_for_network_readiness_tests(destroy_on_exit: bool) -> LxcScriptRunner {
        let config = LxcConfig {
            distribution: "alpine".to_string(),
            release: "3.23".to_string(),
        };
        let lifecycle = LifecycleConfig {
            destroy_on_exit,
            ..LifecycleConfig::default()
        };
        LxcScriptRunner::new(&config, "mxc-network-test", &lifecycle)
    }

    struct ReadinessFailure {
        response: ScriptResponse,
        destroyed: bool,
        stopped: bool,
    }

    fn fail_network_readiness(
        runner: &LxcScriptRunner,
        container_created: bool,
    ) -> ReadinessFailure {
        let mut logger = Logger::new(Mode::Buffer);
        let mut destroyed = false;
        let mut stopped = false;
        let response = runner
            .enforce_network_readiness(
                "mxc-network-test",
                container_created,
                Duration::from_secs(1),
                &mut logger,
                |_name, _timeout, _logger| false,
                |release| {
                    match release {
                        ContainerRelease::Destroy => destroyed = true,
                        ContainerRelease::Stop => stopped = true,
                    }
                    Ok(())
                },
            )
            .expect("a failing readiness probe should return an error response");
        ReadinessFailure {
            response,
            destroyed,
            stopped,
        }
    }

    fn egress_only_directional_request() -> ExecutionRequest {
        let mut request = ExecutionRequest::default();
        request.policy.network_mode_specified = true;
        request.policy.network_egress = Some(NetworkEgressPolicy::default());
        request.policy.network_ingress = Some(NetworkIngressPolicy::default());
        request
    }

    #[test]
    fn an_egress_only_directional_config_passes_validation() {
        let runner = runner_for_guard_tests();

        assert!(
            runner
                .validate_runner(&egress_only_directional_request())
                .is_ok(),
            "a 0.8 config stating only network.egress must reach the backend; rejecting it \
             here would make every directional egress policy unusable on LXC"
        );
    }

    #[test]
    fn claiming_only_the_egress_bits_would_reject_an_egress_only_config() {
        let egress_bits_only =
            NetworkPolicySupport::EGRESS_DEFAULT | NetworkPolicySupport::EGRESS_RULES;

        assert!(
            validate_network_policy_support(&egress_only_directional_request(), egress_bits_only)
                .is_err(),
            "expected the two-bit claim to reject an egress-only config; if this now passes, \
             the directional posture is no longer all-or-nothing and lxc_network_policy_support \
             can drop the ingress bits"
        );
    }

    #[test]
    fn a_directly_built_request_with_proxy_credentials_is_refused() {
        let runner = runner_for_guard_tests();
        let request = request_with_proxy_url("http://alice:hunter2@proxy.example.com:8080");
        let mut logger = Logger::new(wxc_common::logger::Mode::Buffer);

        let response = runner.run_internal(&request, &mut logger);

        assert!(
            response
                .error_message
                .contains("must not carry credentials"),
            "the runner must refuse a credential-bearing proxy URL even when the parser \
             never saw the request, got: {}",
            response.error_message
        );
    }

    #[test]
    fn the_runner_refusal_does_not_echo_the_password() {
        let runner = runner_for_guard_tests();
        let request = request_with_proxy_url("http://alice:hunter2@proxy.example.com:8080");
        let mut logger = Logger::new(wxc_common::logger::Mode::Buffer);

        let response = runner.run_internal(&request, &mut logger);

        assert!(
            !response.error_message.contains("hunter2"),
            "the password leaked into the refusal: {}",
            response.error_message
        );
        assert!(
            !response.error_message.contains("alice:hunter2"),
            "the userinfo leaked into the refusal: {}",
            response.error_message
        );
        assert!(
            !logger.get_buffer().contains("hunter2"),
            "the password leaked into the log buffer"
        );
    }

    #[test]
    fn a_credential_free_proxy_url_is_not_refused_by_the_credential_guard() {
        let runner = runner_for_guard_tests();
        let request = request_with_proxy_url("http://proxy.example.com:8080");
        let mut logger = Logger::new(wxc_common::logger::Mode::Buffer);

        let response = runner.run_internal(&request, &mut logger);

        assert!(
            !response
                .error_message
                .contains("must not carry credentials"),
            "a proxy URL without userinfo must clear the credential guard, got: {}",
            response.error_message
        );
    }

    #[test]
    fn the_credential_refusal_happens_before_any_container_work() {
        let runner = runner_for_guard_tests();
        let request = request_with_proxy_url("http://alice:hunter2@proxy.example.com:8080");
        let mut logger = Logger::new(wxc_common::logger::Mode::Buffer);

        let _ = runner.run_internal(&request, &mut logger);

        let log = logger.get_buffer();
        assert!(
            !log.contains("Container name:"),
            "the guard must return before the runner starts container work, log was: {log}"
        );
        assert!(
            !log.contains("Creating LXC container"),
            "the guard must return before container creation, log was: {log}"
        );
    }

    #[test]
    fn network_readiness_timeout_returns_the_fail_closed_error_response() {
        let runner = runner_for_network_readiness_tests(false);
        let response = fail_network_readiness(&runner, false).response;

        assert!(
            response
                .error_message
                .contains("Container network did not initialize within 1s"),
            "the fail-closed readiness timeout message changed unexpectedly: {}",
            response.error_message
        );
        assert_eq!(
            response.standard_err, response.error_message,
            "error responses should carry the message in stderr as well"
        );
    }

    #[test]
    fn network_readiness_timeout_preserves_a_reused_container_when_destroy_on_exit_is_false() {
        let runner = runner_for_network_readiness_tests(false);
        let destroyed = fail_network_readiness(&runner, false).destroyed;

        assert!(
            !destroyed,
            "a reused container should be preserved on readiness timeout when destroyOnExit=false"
        );
    }

    #[test]
    fn network_readiness_timeout_stops_a_reused_container_when_destroy_on_exit_is_false() {
        let runner = runner_for_network_readiness_tests(false);
        let stopped = fail_network_readiness(&runner, false).stopped;

        assert!(
            stopped,
            "a reused container this run started must be stopped on readiness timeout, \
             not left running without the rules the policy asked for"
        );
    }

    #[test]
    fn network_readiness_timeout_does_not_stop_a_container_it_destroys() {
        let runner = runner_for_network_readiness_tests(true);
        let ReadinessFailure {
            destroyed, stopped, ..
        } = fail_network_readiness(&runner, false);

        assert!(destroyed, "destroyOnExit=true must destroy the container");
        assert!(
            !stopped,
            "destroying the container already removes it; stopping it as well would act on a \
             container that no longer exists"
        );
    }

    #[test]
    fn a_failed_release_is_reported_rather_than_discarded() {
        let runner = runner_for_network_readiness_tests(false);
        let mut logger = Logger::new(Mode::Buffer);

        let _ = runner.enforce_network_readiness(
            "mxc-network-test",
            false,
            Duration::from_secs(1),
            &mut logger,
            |_name, _timeout, _logger| false,
            |_release| Err("lxc-stop exited 1".to_string()),
        );

        assert!(
            logger.get_buffer().contains("lxc-stop exited 1"),
            "a container still running because its stop failed is the fail-open this guard \
             exists to prevent, and it must be named in the log rather than discarded: {}",
            logger.get_buffer()
        );
    }

    #[test]
    fn network_readiness_timeout_destroys_newly_created_container_even_when_destroy_on_exit_is_false(
    ) {
        let runner = runner_for_network_readiness_tests(false);
        let destroyed = fail_network_readiness(&runner, true).destroyed;

        assert!(
            destroyed,
            "a newly created container must be destroyed on readiness timeout even when destroyOnExit=false"
        );
    }

    #[test]
    fn network_readiness_timeout_destroys_a_reused_container_when_destroy_on_exit_is_true() {
        let runner = runner_for_network_readiness_tests(true);
        let destroyed = fail_network_readiness(&runner, false).destroyed;

        assert!(
            destroyed,
            "a reused container must be destroyed on readiness timeout when destroyOnExit=true"
        );
    }
}

#[cfg(all(test, unix))]
mod hosts_command_execution {
    use super::*;
    use std::path::{Path, PathBuf};

    const ORIGINAL: &str = "127.0.0.1 localhost\n::1 ip6-localhost\n10.0.0.9 build.internal\n";

    const PIN_LINE: &str = "10.0.0.5 proxy.example.com";

    struct Scratch {
        dir: PathBuf,
    }

    impl Scratch {
        fn new(tag: &str) -> Self {
            let dir = std::env::temp_dir().join(format!(
                "mxc-hosts-{}-{}-{}",
                tag,
                std::process::id(),
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .expect("the system clock should be after the unix epoch")
                    .as_nanos()
            ));
            std::fs::create_dir_all(&dir).expect("the scratch directory should be creatable");
            Self { dir }
        }

        fn hosts(&self) -> PathBuf {
            self.dir.join("hosts")
        }

        fn write_hosts(&self, contents: &str) {
            std::fs::write(self.hosts(), contents).expect("the fixture should be writable");
        }

        fn read_hosts(&self) -> String {
            std::fs::read_to_string(self.hosts()).expect("the fixture should be readable")
        }

        fn path_with_failing_grep(&self, status: i32) -> String {
            use std::os::unix::fs::PermissionsExt;

            let bin = self.dir.join("bin");
            std::fs::create_dir_all(&bin).expect("the shim directory should be creatable");
            let grep = bin.join("grep");
            std::fs::write(&grep, format!("#!/bin/sh\nexit {status}\n"))
                .expect("the shim should be writable");
            std::fs::set_permissions(&grep, std::fs::Permissions::from_mode(0o755))
                .expect("the shim should be executable");

            format!(
                "{}:{}",
                bin.display(),
                std::env::var("PATH").unwrap_or_default()
            )
        }

        fn path_without_grep(&self) -> String {
            let empty = self.dir.join("empty");
            std::fs::create_dir_all(&empty).expect("the empty directory should be creatable");
            empty.display().to_string()
        }
    }

    impl Drop for Scratch {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.dir);
        }
    }

    fn retarget(command: &str, hosts: &Path) -> String {
        command.replace(
            "/etc/hosts",
            hosts.to_str().expect("the scratch path should be utf-8"),
        )
    }

    fn run(command: &str, path: Option<&str>) -> i32 {
        let mut shell = std::process::Command::new("/bin/sh");
        shell.arg("-c").arg(command);
        if let Some(path) = path {
            shell.env("PATH", path);
        }
        shell
            .output()
            .expect("/bin/sh should be executable")
            .status
            .code()
            .expect("the shell should exit rather than be signalled")
    }

    fn pin(hosts: &Path) -> String {
        retarget(&LxcScriptRunner::build_hosts_pin_command(PIN_LINE), hosts)
    }

    fn unpin(hosts: &Path) -> String {
        retarget(&LxcScriptRunner::build_hosts_unpin_command(), hosts)
    }

    #[test]
    fn pinning_adds_the_mapping_and_keeps_every_line_the_image_shipped() {
        let scratch = Scratch::new("keeps");
        scratch.write_hosts(ORIGINAL);

        let code = run(&pin(&scratch.hosts()), None);
        let after = scratch.read_hosts();

        assert_eq!(code, 0, "pinning a readable file should succeed");
        for line in ORIGINAL.lines() {
            assert!(
                after.contains(line),
                "the pin dropped {line:?}; file is now:\n{after}"
            );
        }
        assert!(
            after.contains(&format!("{PIN_LINE} {HOSTS_PIN_MARKER}")),
            "the pin never landed; file is now:\n{after}"
        );
    }

    #[test]
    fn re_pinning_replaces_the_previous_entry_instead_of_stacking_on_it() {
        let scratch = Scratch::new("repin");
        scratch.write_hosts(ORIGINAL);

        assert_eq!(run(&pin(&scratch.hosts()), None), 0);
        assert_eq!(run(&pin(&scratch.hosts()), None), 0);
        let after = scratch.read_hosts();

        assert_eq!(
            after.matches(HOSTS_PIN_MARKER).count(),
            1,
            "a second pin should replace the first, not stack; file is now:\n{after}"
        );
        assert!(
            after.contains("10.0.0.9 build.internal"),
            "re-pinning dropped an unrelated entry; file is now:\n{after}"
        );
    }

    #[test]
    fn a_failed_read_leaves_the_file_byte_for_byte_as_it_was() {
        let scratch = Scratch::new("failread");
        scratch.write_hosts(ORIGINAL);
        let path = scratch.path_with_failing_grep(2);

        let code = run(&pin(&scratch.hosts()), Some(&path));

        assert_eq!(
            scratch.read_hosts(),
            ORIGINAL,
            "a failed read truncated the file it could not read"
        );
        assert_ne!(
            code, 0,
            "a failed read must fail the command, not report a pin it never made"
        );
    }

    #[test]
    fn a_missing_grep_leaves_the_file_byte_for_byte_as_it_was() {
        let scratch = Scratch::new("nogrep");
        scratch.write_hosts(ORIGINAL);
        let path = scratch.path_without_grep();

        let code = run(&pin(&scratch.hosts()), Some(&path));

        assert_eq!(
            scratch.read_hosts(),
            ORIGINAL,
            "a missing grep truncated the file"
        );
        assert_ne!(code, 0, "a missing grep must fail the command");
    }

    #[test]
    fn a_failed_read_while_unpinning_leaves_the_file_byte_for_byte_as_it_was() {
        let scratch = Scratch::new("failunpin");
        scratch.write_hosts(ORIGINAL);
        let path = scratch.path_with_failing_grep(2);

        let code = run(&unpin(&scratch.hosts()), Some(&path));

        assert_eq!(
            scratch.read_hosts(),
            ORIGINAL,
            "a failed read emptied the file it could not read"
        );
        assert_ne!(code, 0, "a failed read must fail the unpin");
    }

    #[test]
    fn a_file_of_nothing_but_previous_pins_is_rewritten_rather_than_refused() {
        let scratch = Scratch::new("allmarked");
        scratch.write_hosts(&format!("10.0.0.4 proxy.example.com {HOSTS_PIN_MARKER}\n"));

        let code = run(&pin(&scratch.hosts()), None);
        let after = scratch.read_hosts();

        assert_eq!(
            code, 0,
            "a file of only stale pins should still be pinnable"
        );
        assert_eq!(
            after.trim(),
            format!("{PIN_LINE} {HOSTS_PIN_MARKER}"),
            "the stale pin should be gone and the new one present"
        );
    }

    #[test]
    fn an_image_with_no_hosts_file_is_pinned_rather_than_refused() {
        let scratch = Scratch::new("nofile");

        let code = run(&pin(&scratch.hosts()), None);

        assert_eq!(
            code, 0,
            "a missing hosts file should be created, not refused"
        );
        assert_eq!(
            scratch.read_hosts().trim(),
            format!("{PIN_LINE} {HOSTS_PIN_MARKER}")
        );
    }

    #[test]
    fn unpinning_removes_the_pin_and_keeps_everything_else() {
        let scratch = Scratch::new("unpin");
        scratch.write_hosts(ORIGINAL);
        assert_eq!(run(&pin(&scratch.hosts()), None), 0);

        let code = run(&unpin(&scratch.hosts()), None);
        let after = scratch.read_hosts();

        assert_eq!(code, 0, "unpinning a readable file should succeed");
        assert!(
            !after.contains(HOSTS_PIN_MARKER),
            "the pin survived the unpin; file is now:\n{after}"
        );
        for line in ORIGINAL.lines() {
            assert!(
                after.contains(line),
                "the unpin dropped {line:?}; file is now:\n{after}"
            );
        }
    }

    #[test]
    fn pinning_refuses_a_dangling_symlink_instead_of_creating_its_target() {
        let scratch = Scratch::new("dangling");
        let target = scratch.dir.join("attacker-named");
        std::os::unix::fs::symlink(&target, scratch.hosts())
            .expect("the scratch symlink should be creatable");

        let code = run(&pin(&scratch.hosts()), None);

        assert_ne!(code, 0, "writing through a symlink should be refused");
        assert!(
            !target.exists(),
            "the refused pin still created {}",
            target.display()
        );
    }

    #[test]
    fn pinning_refuses_a_symlink_rather_than_writing_through_it() {
        let scratch = Scratch::new("symlink");
        let target = scratch.dir.join("elsewhere");
        std::fs::write(&target, ORIGINAL).expect("the target should be writable");
        std::os::unix::fs::symlink(&target, scratch.hosts())
            .expect("the scratch symlink should be creatable");

        let code = run(&pin(&scratch.hosts()), None);

        assert_ne!(code, 0, "writing through a symlink should be refused");
        assert_eq!(
            std::fs::read_to_string(&target).expect("the target should still be readable"),
            ORIGINAL,
            "the refused pin still rewrote the symlink target"
        );
    }

    #[test]
    fn unpinning_refuses_a_symlink_rather_than_emptying_its_target() {
        let scratch = Scratch::new("unpinsymlink");
        let target = scratch.dir.join("elsewhere");
        std::fs::write(&target, ORIGINAL).expect("the target should be writable");
        std::os::unix::fs::symlink(&target, scratch.hosts())
            .expect("the scratch symlink should be creatable");

        let code = run(&unpin(&scratch.hosts()), None);

        assert_ne!(code, 0, "writing through a symlink should be refused");
        assert_eq!(
            std::fs::read_to_string(&target).expect("the target should still be readable"),
            ORIGINAL,
            "the refused unpin still emptied the symlink target"
        );
    }

    #[test]
    fn the_symlink_refusal_says_why() {
        let scratch = Scratch::new("symlinkmsg");
        let target = scratch.dir.join("elsewhere");
        std::os::unix::fs::symlink(&target, scratch.hosts())
            .expect("the scratch symlink should be creatable");

        let output = std::process::Command::new("/bin/sh")
            .arg("-c")
            .arg(pin(&scratch.hosts()))
            .output()
            .expect("/bin/sh should be executable");

        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            stderr.contains("symbolic link"),
            "the refusal named no reason; stderr was:\n{stderr}"
        );
    }
}
