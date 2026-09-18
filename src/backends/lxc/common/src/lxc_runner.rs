// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use std::fmt::Write;
use std::thread;
use std::time::{Duration, Instant};

#[cfg(target_os = "linux")]
use std::io::{Read, Write as IoWrite};
#[cfg(target_os = "linux")]
use wxc_common::interruptible_reader::{InterruptibleReader, ReadCanceller};
use wxc_common::logger::Logger;
use wxc_common::models::{
    ContainerPolicy, ExecutionRequest, LifecycleConfig, LxcConfig, NetworkEnforcementMode,
    ScriptResponse,
};
#[cfg(target_os = "linux")]
use wxc_common::sandbox_process::{
    boxed_closer, cancel_and_join_discard, group_kill, spawn_discard, take_boxed_read,
    take_boxed_write, wait_with_timeout, SandboxBackend, SandboxProcess, StdioMode, StreamCloser,
    WaitError,
};
use wxc_common::script_runner::ScriptRunner;
#[cfg(target_os = "linux")]
use wxc_common::validator::validate_common;
use wxc_common::validator::{validate_network_policy_support, NetworkPolicySupport};

use crate::filesystem_mounts;
use crate::lxc_bindings::{ContainerFirewall, LxcContainer, StartNetwork};
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

struct PreparedLxc {
    container: LxcContainer,
    fw_manager: NetworkIptablesManager,
    ingress_manager: Option<IngressManager>,
    pinned: bool,
    firewall: ContainerFirewall,
    cleanup_policy: bool,
    destroy_on_exit: bool,
    cleaned_up: bool,
}

impl PreparedLxc {
    fn cleanup(&mut self, logger: &mut Logger) -> Vec<String> {
        if self.cleaned_up {
            return Vec::new();
        }
        self.cleaned_up = true;
        let mut warnings = Vec::new();

        if self.pinned && self.cleanup_policy {
            let command = LxcScriptRunner::build_hosts_unpin_command();
            let result = self.container.attach_run(
                &command,
                "/",
                &[],
                true,
                Some(HOSTS_COMMAND_TIMEOUT),
                self.firewall,
            );
            let reason = match result {
                Ok((0, _, _)) => None,
                Ok((code, _, _)) => Some(LxcScriptRunner::hosts_command_failure("clearing", code)),
                Err(error) => Some(error),
            };
            if let Some(reason) = reason {
                let warning = format!("failed to clear the proxy host pin: {reason}");
                let _ = writeln!(logger, "Warning: {warning}");
                warnings.push(warning);
            }
        }

        if self.fw_manager.rules_applied() && self.cleanup_policy {
            if let Err(error) = self.fw_manager.remove_firewall_rules(logger) {
                warnings.push(format!(
                    "failed to remove LXC egress firewall rules: {error}"
                ));
            }
        }
        if let Some(manager) = &mut self.ingress_manager {
            if manager.rules_applied() && self.cleanup_policy {
                if let Err(error) = manager.remove_firewall_rules(logger) {
                    warnings.push(format!(
                        "failed to remove LXC ingress firewall rules: {error}"
                    ));
                }
            }
        }

        if self.destroy_on_exit {
            let _ = writeln!(logger, "Destroying container...");
            if let Err(error) = self.container.destroy() {
                let warning = format!("failed to destroy container: {error}");
                let _ = writeln!(logger, "Warning: {warning}");
                warnings.push(warning);
            }
        }
        warnings
    }
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
        Self::egress_apply_outcome(fw_manager.apply_legacy_rules(policy, logger))?;
        fw_manager.set_preserve_policy(!self.cleanup_policy);

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
        Self::egress_apply_outcome(fw_manager.apply_directional_rules(policy, logger))?;
        fw_manager.set_preserve_policy(!self.cleanup_policy);

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

    fn normalized_request(
        &self,
        request: &ExecutionRequest,
        logger: &mut Logger,
    ) -> Result<ExecutionRequest, ScriptResponse> {
        let mut normalized = request.clone();
        match wxc_common::filesystem_object::normalize_object_conflicts(&request.policy, logger) {
            Ok(Some(policy)) => normalized.policy = policy,
            Ok(None) => {}
            Err(message) => return Err(ScriptResponse::error(&message)),
        }
        if let Err(message) = wxc_common::filesystem_access::check_delegation(&normalized.policy) {
            return Err(ScriptResponse::error(&message));
        }
        Ok(normalized)
    }

    fn prepare(
        &self,
        request: &ExecutionRequest,
        logger: &mut Logger,
        register_signal_cleanup: bool,
    ) -> Result<PreparedLxc, ScriptResponse> {
        if self.config.distribution.is_empty() || self.config.release.is_empty() {
            return Err(ScriptResponse::error(
                "LXC distribution and release are required \
                 (e.g., \"distribution\": \"alpine\", \"release\": \"3.23\")",
            ));
        }

        let container_name = self.resolve_container_name();
        if let Some(url) = request
            .policy
            .network_proxy
            .address
            .as_ref()
            .map(|address| address.to_url())
        {
            if wxc_common::proxy_env::proxy_url_has_credentials(&url) {
                return Err(ScriptResponse::error(&format!(
                    "LXC: network.proxy.url must not carry credentials ('{}'). LXC passes the \
                     proxy URL to lxc-attach as a --set-var command-line argument, and process \
                     arguments are world-readable through /proc/<pid>/cmdline, so the password \
                     would be visible to every local user while the command runs. Use a proxy \
                     that does not require inline credentials, or supply them to the proxy \
                     itself rather than through the URL.",
                    wxc_common::proxy_env::redact_proxy_url(&url)
                )));
            }
        }

        if register_signal_cleanup && self.destroy_on_exit {
            signal_cleanup::set_active(&container_name);
        }
        let _ = writeln!(logger, "Container name: {container_name}");
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
            if let Err(error) = container.create(&self.config.distribution, &self.config.release) {
                return Err(ScriptResponse::error(&format!(
                    "Failed to create container: {error}"
                )));
            }
            let _ = writeln!(logger, "Container created successfully.");
            container_created = true;
        } else {
            let _ = writeln!(logger, "Container already exists, reusing.");
        }

        if let Err(error) =
            filesystem_mounts::configure_filesystem_mounts(&container, &request.policy, logger)
        {
            if self.destroy_on_exit || container_created {
                let _ = container.destroy();
            }
            return Err(ScriptResponse::error(&format!(
                "Failed to configure filesystem: {error}"
            )));
        }

        if container.is_running() {
            let _ = writeln!(
                logger,
                "Container already running; stopping it so this run's network policy applies."
            );
            if let Err(error) = container.stop() {
                if self.destroy_on_exit || container_created {
                    let _ = container.destroy();
                }
                return Err(ScriptResponse::error(&format!(
                    "Failed to stop a container left running by an earlier run: {error}. \
                     Its network policy is the earlier run's, so the script was not run."
                )));
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
        if let Err(error) = container.start(network) {
            if self.destroy_on_exit || container_created {
                let _ = container.destroy();
            }
            return Err(ScriptResponse::error(&format!(
                "Failed to start container: {error}"
            )));
        }
        let _ = writeln!(logger, "Container started successfully.");

        if needs_network(&request.policy) {
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
                return Err(response);
            }
        }

        let netns_pid = container.init_pid();
        let hook_point = self.enforce_netns_discovery(
            netns_pid,
            plan.installs_firewall(),
            container_created,
            logger,
            |release| match release {
                ContainerRelease::Destroy => container.destroy(),
                ContainerRelease::Stop => container.stop(),
            },
        )?;

        if let Some(pid) = netns_pid {
            let _ = writeln!(logger, "Container init PID: {pid}");
            if register_signal_cleanup && self.destroy_on_exit {
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
        let (fw_manager, ingress_manager) = match setup {
            Ok(managers) => managers,
            Err(error) => {
                self.release_after_failure(&container, container_created, logger);
                return Err(ScriptResponse::error(&error));
            }
        };
        let firewall = container_firewall(
            fw_manager.rules_applied(),
            ingress_manager
                .as_ref()
                .is_some_and(IngressManager::rules_applied),
        );
        let mut prepared = PreparedLxc {
            container,
            fw_manager,
            ingress_manager,
            pinned: false,
            firewall,
            cleanup_policy: self.cleanup_policy,
            destroy_on_exit: self.destroy_on_exit,
            cleaned_up: false,
        };

        if let Some(pin) = prepared.fw_manager.proxy_host_pin() {
            let command = Self::build_hosts_pin_command(&pin.hosts_line());
            let _ = writeln!(
                logger,
                "Pinning proxy host {} to {} in the container's /etc/hosts.",
                pin.hostname(),
                pin.ip()
            );
            let pin_error = match prepared.container.attach_run(
                &command,
                "/",
                &[],
                true,
                Some(HOSTS_COMMAND_TIMEOUT),
                prepared.firewall,
            ) {
                Ok((0, _, _)) => None,
                Ok((code, _, _)) => Some(Self::hosts_command_failure("writing", code)),
                Err(error) => Some(error),
            };
            if let Some(reason) = pin_error {
                self.release_after_failure(&prepared.container, container_created, logger);
                return Err(ScriptResponse::error(&format!(
                    "Failed to pin the network proxy host inside the container: {reason}. \
                     The proxy would be unreachable, so the script was not run."
                )));
            }
            prepared.pinned = true;
        } else if !container_created {
            let command = Self::build_hosts_unpin_command();
            let stale_pin_error = match prepared.container.attach_run(
                &command,
                "/",
                &[],
                true,
                Some(HOSTS_COMMAND_TIMEOUT),
                prepared.firewall,
            ) {
                Ok((0, _, _)) => None,
                Ok((code, _, _)) => Some(Self::hosts_command_failure("clearing", code)),
                Err(error) => Some(error),
            };
            if let Some(reason) = stale_pin_error {
                self.release_after_failure(&prepared.container, container_created, logger);
                return Err(ScriptResponse::error(&format!(
                    "Failed to clear a stale network proxy pin from the container's \
                     /etc/hosts: {reason}. The script was not run, because it could have \
                     resolved the pinned hostname to an address this policy did not authorize."
                )));
            }
        }
        Ok(prepared)
    }

    fn execution_environment(request: &ExecutionRequest) -> Vec<String> {
        let mut environment = request.env_entries().to_vec();
        wxc_common::proxy_env::apply_proxy_env(&mut environment, &request.policy.network_proxy);
        environment
    }

    fn run_internal(&self, request: &ExecutionRequest, logger: &mut Logger) -> ScriptResponse {
        let request = match self.normalized_request(request, logger) {
            Ok(request) => request,
            Err(response) => return response,
        };
        let mut prepared = match self.prepare(&request, logger, true) {
            Ok(prepared) => prepared,
            Err(response) => return response,
        };
        let timeout = (request.script_timeout != 0)
            .then(|| Duration::from_millis(u64::from(request.script_timeout)));
        let _ = writeln!(logger, "Executing script inside container...");
        let environment = Self::execution_environment(&request);
        let result = prepared.container.attach_run(
            &request.script_code,
            &request.working_directory,
            &environment,
            true,
            timeout,
            prepared.firewall,
        );
        let response = match result {
            Ok((exit_code, stdout, stderr)) => ScriptResponse {
                exit_code,
                standard_out: stdout,
                standard_err: stderr,
                ..Default::default()
            },
            Err(error) => ScriptResponse::error(&format!("Execution failed: {error}")),
        };
        prepared.cleanup(logger);
        response
    }

    #[cfg(target_os = "linux")]
    fn spawn_streaming(
        &self,
        request: &ExecutionRequest,
        logger: &mut Logger,
    ) -> Result<Box<dyn SandboxProcess>, ScriptResponse> {
        let request = self.normalized_request(request, logger)?;
        let mut prepared = self.prepare(&request, logger, false)?;
        let environment = Self::execution_environment(&request);
        let _ = writeln!(logger, "Executing script inside container...");
        let mut pty = match prepared.container.attach_spawn(
            &request.script_code,
            &request.working_directory,
            &environment,
            true,
            prepared.firewall,
        ) {
            Ok(pty) => pty,
            Err(error) => {
                prepared.cleanup(logger);
                return Err(ScriptResponse::error(&format!("Execution failed: {error}")));
            }
        };

        let stdin = pty.take_stdin();
        let stdout_file = match pty.take_stdout() {
            Some(stdout) => stdout,
            None => {
                if terminate_and_reap_pty(&mut pty) {
                    prepared.cleanup(logger);
                } else {
                    std::mem::forget(prepared);
                }
                return Err(ScriptResponse::error(
                    "Execution failed: LXC pty did not expose stdout",
                ));
            }
        };
        let stdout = match InterruptibleReader::new_blocking(stdout_file.into()) {
            Ok(stdout) => stdout,
            Err(error) => {
                if terminate_and_reap_pty(&mut pty) {
                    prepared.cleanup(logger);
                } else {
                    std::mem::forget(prepared);
                }
                return Err(ScriptResponse::error(&format!(
                    "Execution failed: could not make LXC pty output interruptible: {error}"
                )));
            }
        };
        let stdout_canceller = stdout.canceller();
        let timeout = (request.script_timeout != 0)
            .then(|| Duration::from_millis(u64::from(request.script_timeout)));
        Ok(Box::new(LxcSandboxProcess {
            pty,
            stdin,
            stdout: Some(PtyOutput(stdout)),
            stdout_canceller: Some(stdout_canceller),
            timeout,
            teardown: Some(prepared),
            warnings: Vec::new(),
        }))
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

#[cfg(target_os = "linux")]
struct PtyOutput(InterruptibleReader);

#[cfg(target_os = "linux")]
impl Read for PtyOutput {
    fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
        match self.0.read(buffer) {
            Err(error) if is_pty_eof(&error) => Ok(0),
            result => result,
        }
    }
}

#[cfg(target_os = "linux")]
fn is_pty_eof(error: &std::io::Error) -> bool {
    error.raw_os_error() == Some(libc::EIO)
}

#[cfg(target_os = "linux")]
fn terminate_and_reap_pty(pty: &mut mxc_pty::PtyChild) -> bool {
    match pty.child_mut().try_wait() {
        Ok(Some(_)) => true,
        Ok(None) => {
            let _ = group_kill(pty.child_mut());
            pty.child_mut().wait().is_ok()
        }
        Err(_) => false,
    }
}

#[cfg(target_os = "linux")]
struct LxcSandboxProcess {
    pty: mxc_pty::PtyChild,
    stdin: Option<std::fs::File>,
    stdout: Option<PtyOutput>,
    stdout_canceller: Option<ReadCanceller>,
    timeout: Option<Duration>,
    teardown: Option<PreparedLxc>,
    warnings: Vec<String>,
}

#[cfg(target_os = "linux")]
impl LxcSandboxProcess {
    fn cleanup_after_exit(&mut self) {
        let Some(mut teardown) = self.teardown.take() else {
            return;
        };
        let mut logger = Logger::new(wxc_common::logger::Mode::Buffer);
        self.warnings.extend(teardown.cleanup(&mut logger));
    }

    fn retain_teardown_on_uncertain_exit(&mut self) {
        if let Some(teardown) = self.teardown.take() {
            // Deliberately leak the enforcement owners: their Drop impls remove
            // firewall state, which is unsafe while the child may still live.
            std::mem::forget(teardown);
        }
    }
}

#[cfg(target_os = "linux")]
impl SandboxProcess for LxcSandboxProcess {
    fn warnings(&self) -> Vec<String> {
        self.warnings.clone()
    }

    fn take_stdin(&mut self) -> Option<Box<dyn IoWrite + Send>> {
        take_boxed_write(&mut self.stdin)
    }

    fn take_stdout(&mut self) -> Option<Box<dyn Read + Send>> {
        take_boxed_read(&mut self.stdout)
    }

    fn take_stderr(&mut self) -> Option<Box<dyn Read + Send>> {
        None
    }

    fn stdout_closer(&self) -> Option<Box<dyn StreamCloser>> {
        boxed_closer(&self.stdout_canceller)
    }

    fn try_wait(&mut self) -> std::io::Result<Option<i32>> {
        Ok(self
            .pty
            .child_mut()
            .try_wait()?
            .map(|status| status.code().unwrap_or(-1)))
    }

    fn id(&self) -> u32 {
        self.pty.id()
    }

    fn kill(&mut self) -> std::io::Result<()> {
        if self.pty.child_mut().try_wait()?.is_some() {
            return Ok(());
        }
        group_kill(self.pty.child_mut())
    }

    fn wait(&mut self) -> std::io::Result<i32> {
        self.stdin.take();
        let stdout_thread = spawn_discard(self.stdout.take());
        let (result, reaped) = match wait_with_timeout(self.pty.child_mut(), self.timeout) {
            Ok(status) => (Ok(status.code().unwrap_or(-1)), true),
            Err(WaitError::Timeout) => {
                let _ = self.kill();
                let reaped = self.pty.child_mut().wait().is_ok();
                (
                    Err(std::io::Error::new(
                        std::io::ErrorKind::TimedOut,
                        "LXC: script timed out",
                    )),
                    reaped,
                )
            }
            Err(WaitError::Io(error)) => {
                let _ = self.kill();
                let reaped = self.pty.child_mut().wait().is_ok();
                (
                    Err(std::io::Error::other(format!("LXC: wait failed: {error}"))),
                    reaped,
                )
            }
        };
        cancel_and_join_discard(stdout_thread, &self.stdout_canceller);
        if reaped {
            self.cleanup_after_exit();
        } else {
            self.retain_teardown_on_uncertain_exit();
        }
        result
    }
}

#[cfg(target_os = "linux")]
impl Drop for LxcSandboxProcess {
    fn drop(&mut self) {
        self.stdin.take();
        let _ = self.kill();
        if self.pty.child_mut().wait().is_ok() {
            if let Some(canceller) = &self.stdout_canceller {
                canceller.close();
            }
            self.cleanup_after_exit();
        } else {
            self.retain_teardown_on_uncertain_exit();
        }
    }
}

pub const LXC_CAPABILITIES_MODE_UNSUPPORTED: &str =
    "LXC: network.enforcementMode='capabilities' (the default) selects Windows AppContainer \
     capability SIDs, which LXC has no mechanism for. Accepting it would enforce the policy by \
     some means other than the one named. Set network.enforcementMode to 'firewall' or 'both', \
     or state the policy in the 0.8 network.egress / network.ingress form, which carries no \
     enforcement mode.";

pub const LXC_RUNTIME_PROXY_UNSUPPORTED: &str =
    "LXC: runtimeConfig.networkProxy is not supported. It must name a loopback endpoint, which \
     inside the container's own network namespace is the container rather than the host. On \
     schema 0.6-0.8, use network.proxy.url with an address routable from inside the container.";

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

fn validate_lxc_request(request: &ExecutionRequest) -> Result<(), ScriptResponse> {
    if request.policy.runtime_network_proxy_specified {
        return Err(ScriptResponse::error(LXC_RUNTIME_PROXY_UNSUPPORTED));
    }
    validate_network_policy_support(request, lxc_network_policy_support())?;
    if asks_for_capabilities_enforcement(request) {
        return Err(ScriptResponse::error(LXC_CAPABILITIES_MODE_UNSUPPORTED));
    }
    Ok(())
}

#[cfg(target_os = "linux")]
impl SandboxBackend for LxcScriptRunner {
    fn network_policy_support(&self) -> NetworkPolicySupport {
        lxc_network_policy_support()
    }

    fn validate(&self, request: &ExecutionRequest) -> Result<(), ScriptResponse> {
        validate_lxc_request(request)
    }

    fn spawn(
        &mut self,
        request: &ExecutionRequest,
        logger: &mut Logger,
        stdio: StdioMode,
    ) -> Result<Box<dyn SandboxProcess>, ScriptResponse> {
        validate_common(request)?;
        self.validate(request)?;
        if stdio != StdioMode::Pipes {
            return Err(ScriptResponse::error(
                "LXC handle-based spawning requires piped callback I/O; \
                 run-to-completion uses the existing PTY bridge",
            ));
        }
        self.spawn_streaming(request, logger)
    }
}

impl ScriptRunner for LxcScriptRunner {
    fn validate_runner(&self, request: &ExecutionRequest) -> Result<(), ScriptResponse> {
        validate_lxc_request(request)
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

/// Whether the workload must be kept away from chains in its own namespace.
fn container_firewall(egress_applied: bool, ingress_applied: bool) -> ContainerFirewall {
    if egress_applied || ingress_applied {
        ContainerFirewall::Installed
    } else {
        ContainerFirewall::Absent
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
    fn a_failed_egress_apply_tears_down_its_debris_even_under_preserve_policy() {
        let fake = crate::network_iptables::test_firewall::install();

        // Succeed through both chain creations, then refuse the first rule and
        // every command the rollback uses to undo it, so the chains survive the
        // failed apply and teardown has something left to remove.
        fake.script_results(vec![
            Ok(()),
            Ok(()),
            Ok(()),
            Err("append refused".to_string()),
            Err("flush refused".to_string()),
            Err("delete refused".to_string()),
            Err("flush refused".to_string()),
            Err("delete refused".to_string()),
        ]);

        let runner = LxcScriptRunner::new(
            &LxcConfig::default(),
            "preserve-rollback-test",
            &LifecycleConfig {
                preserve_policy: true,
                ..LifecycleConfig::default()
            },
        );
        let policy = ContainerPolicy {
            network_enforcement_mode: NetworkEnforcementMode::Firewall,
            allowed_hosts: vec!["192.0.2.10".to_string()],
            ..Default::default()
        };
        let mut logger = Logger::new(Mode::Buffer);

        let outcome = runner.set_up_network_rules_for_v07(
            "preserve-rollback-test",
            EgressHookPoint::Unhooked,
            None,
            &policy,
            &mut logger,
        );
        let failure = outcome.err();

        assert!(
            failure.is_some(),
            "a firewall apply whose rule append fails must report failure; output={failure:?}"
        );

        let issued = fake.issued();
        let chain_deletes = issued
            .iter()
            .filter(|cmd| cmd.iter().any(|arg| arg == "-X"))
            .count();
        assert!(
            chain_deletes > 2,
            "input=preservePolicy=true, rule append and rollback both refused; \
             expected the surviving chains to be deleted again after the rollback's \
             own two attempts failed, because preservePolicy preserves a policy and \
             not the debris of one that never applied; \
             chain deletes={chain_deletes}; output={issued:?}"
        );
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
    fn either_installed_chain_confines_the_workload() {
        for (egress, ingress) in [(true, false), (false, true), (true, true)] {
            assert_eq!(
                container_firewall(egress, ingress),
                ContainerFirewall::Installed,
                "egress={egress} ingress={ingress} leaves a chain the workload could flush"
            );
        }
    }

    #[test]
    fn a_policy_that_installs_no_chain_leaves_the_capability_alone() {
        // Dropping it needs CAP_SETPCAP, which an unprivileged caller lacks.
        assert_eq!(
            container_firewall(false, false),
            ContainerFirewall::Absent,
            "a run with no firewall must not be confined"
        );
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

    #[cfg(target_os = "linux")]
    #[test]
    fn pty_hangup_eio_is_reported_as_clean_eof() {
        assert!(is_pty_eof(&std::io::Error::from_raw_os_error(libc::EIO)));
        assert!(!is_pty_eof(&std::io::Error::from_raw_os_error(libc::EBADF)));
    }

    #[test]
    fn both_execution_paths_share_proxy_environment_preparation() {
        let mut request = request_with_proxy_url("http://proxy.example.com:3128");
        request.env = Some(vec!["MXC_TEST=value".to_string()]);

        let environment = LxcScriptRunner::execution_environment(&request);

        assert!(environment.iter().any(|entry| entry == "MXC_TEST=value"));
        assert!(environment
            .iter()
            .any(|entry| entry == "HTTP_PROXY=http://proxy.example.com:3128"));
        assert!(environment
            .iter()
            .any(|entry| entry == "HTTPS_PROXY=http://proxy.example.com:3128"));
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
    fn the_declared_support_set_withholds_the_runtime_proxy_bit() {
        assert!(
            !lxc_network_policy_support().contains(NetworkPolicySupport::RUNTIME_PROXY),
            "claiming the bit would accept the config and then open the container's own \
             loopback, where no proxy is listening, so the workload would fail at runtime \
             instead of at validation"
        );
    }

    #[test]
    fn a_runtime_proxy_request_is_refused_before_any_container_work() {
        let runner = runner_for_guard_tests();
        let mut request = egress_only_directional_request();
        request.policy.runtime_network_proxy_specified = true;

        let response = runner.validate_runner(&request).expect_err(
            "a loopback proxy is unreachable from the container's network namespace, so the \
             request must be refused",
        );

        assert!(
            response
                .error_message
                .contains("runtimeConfig.networkProxy"),
            "the refusal must name the field the caller wrote, got: {}",
            response.error_message
        );
        assert!(
            response.error_message.contains("LXC"),
            "the refusal must name the backend that refused, or the caller cannot tell which \
             part of the request to change, got: {}",
            response.error_message
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
