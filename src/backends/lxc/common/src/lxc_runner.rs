// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use std::collections::HashSet;
use std::fmt::Write;
use std::net::Ipv4Addr;
use std::sync::{LazyLock, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use wxc_common::logger::Logger;
use wxc_common::models::{
    ContainerPolicy, ExecutionRequest, LifecycleConfig, LxcConfig, NetworkEnforcementMode,
    ScriptResponse,
};
use wxc_common::sandbox_process::{SandboxBackend, SandboxProcess, StdioMode};
use wxc_common::script_runner::ScriptRunner;
use wxc_common::validator::{
    validate_common, validate_network_policy_support, NetworkPolicySupport,
};

#[cfg(target_os = "linux")]
use wxc_common::interruptible_reader::{wrap_pipe, InterruptibleReader, ReadCanceller};
#[cfg(target_os = "linux")]
use wxc_common::sandbox_process::{
    boxed_closer, cancel_and_join_discard, duplicate_and_take_native_stdio, spawn_discard,
    take_boxed_read, take_boxed_write, wait_with_timeout, NativeStdio, StreamCloser, WaitError,
};

use crate::filesystem_mounts;
use crate::lxc_bindings::{ContainerFirewall, LxcContainer, StartNetwork};
use crate::network_ingress::IngressManager;
use crate::network_iptables::{
    needs_network, plan_network, uses_directional_keys, EgressHookPoint, NetworkIptablesManager,
};
use crate::signal_cleanup;

const HOSTS_PIN_MARKER: &str = "#mxc-proxy-pin";

/// `PATH` for the contained child, from schema 0.9.
///
/// The script runs with `lxc-attach` in clear-env mode, which supplies a small
/// baseline of its own. Setting `PATH` explicitly makes command resolution the
/// same on every distribution instead of depending on the liblxc default, and
/// names the `sbin` directories so tools kept there resolve on RHEL too.
const DEFAULT_PATH: &str = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin";

/// `TERM` for the contained child. Curses-based tools error out when it is
/// unset; it does not make a tool believe it has a terminal, which is `isatty`.
const DEFAULT_TERM: &str = "xterm-256color";

/// The directory the child is actually started in, if any.
///
/// [`LxcContainer::attach_run`] wraps the command in a `cd` for exactly this
/// value and [`default_env`] points `HOME` at it, so the two cannot name
/// different directories — `lxc-attach` starts at the container root, so a
/// relative `process.cwd` would otherwise leave `HOME` naming a different
/// directory than the one the child landed in. Normalizing against the
/// container root is what makes them agree, so it is gated on the schema that
/// introduced `HOME`; below 0.9 the caller's spelling reaches `cd` untouched.
///
/// A policy grant is deliberately *not* consulted: with `process.cwd` omitted
/// the child starts at the container root, so treating a grant as the start
/// directory would put `HOME` somewhere it never went.
fn start_directory(request: &ExecutionRequest) -> Option<String> {
    Some(request.working_directory.as_str())
        .filter(|dir| !dir.is_empty())
        .map(|dir| {
            if request.supplies_default_env() {
                wxc_common::models::sandbox_absolute_path(dir)
            } else {
                dir.to_string()
            }
        })
}

/// The default environment, from schema 0.9: `PATH`, `TERM`, and -- when one
/// resolves -- `HOME`.
///
/// `HOME` names the directory the child actually runs in, so it is a path the
/// container has rather than a host path that was never mounted. With no start
/// directory it is left unset: a policy grant can bind a host path over the
/// container's `/tmp`, and a reused container keeps whatever its image left
/// there, so a `/tmp` fallback would not be a private home.
fn default_env(request: &ExecutionRequest) -> Vec<(String, String)> {
    let mut entries = vec![("PATH".to_string(), DEFAULT_PATH.to_string())];

    if let Some(home) = start_directory(request) {
        entries.push(("HOME".to_string(), home));
    }

    entries.push(("TERM".to_string(), DEFAULT_TERM.to_string()));
    entries
}

/// The entries the child should get, as `KEY=VALUE` strings.
///
/// The state dispatch and overlay merge are shared; see
/// [`wxc_common::default_env::resolve_env`]. Below 0.9 the caller's entries are
/// passed through untouched and the `lxc-attach` baseline is the only default.
fn resolved_env(request: &ExecutionRequest) -> Vec<String> {
    wxc_common::default_env::resolve_env(request, || default_env(request))
}

/// The `/etc/hosts` rewrites are short shell commands and must not inherit the script timeout.
const HOSTS_COMMAND_TIMEOUT: Duration = Duration::from_secs(30);

// lxcbr0 answers router solicitation in about a second while its DHCP lease
// arrives around nine, and the bridge NATs IPv4 only.  Reading the IPv6
// address as readiness starts the workload with no route to anything.
fn first_routable_ipv4(lxc_info_addresses: &str) -> Option<Ipv4Addr> {
    lxc_info_addresses
        .lines()
        .filter_map(|line| line.trim().parse::<Ipv4Addr>().ok())
        .find(|address| {
            !address.is_loopback()
                && !address.is_unspecified()
                && !address.is_link_local()
                && !address.is_multicast()
                && !address.is_broadcast()
        })
}

#[derive(Clone, Copy)]
enum ContainerRelease {
    Destroy,
    Stop,
}

impl ContainerRelease {
    fn verb(self) -> &'static str {
        match self {
            ContainerRelease::Destroy => "destroy",
            ContainerRelease::Stop => "stop",
        }
    }
}

/// The container names this process holds a live sandbox on; another process,
/// including an `lxc-exec` run, can still take the same one.
static LIVE_CONTAINER_NAMES: LazyLock<Mutex<HashSet<String>>> =
    LazyLock::new(|| Mutex::new(HashSet::new()));

const GENERATED_NAME_ATTEMPTS: usize = 8;

fn lock_live_container_names() -> std::sync::MutexGuard<'static, HashSet<String>> {
    LIVE_CONTAINER_NAMES
        .lock()
        .unwrap_or_else(|p| p.into_inner())
}

#[derive(Debug)]
struct ContainerNameClaim {
    name: String,
}

impl ContainerNameClaim {
    fn acquire(name: &str) -> Option<Self> {
        let mut live = lock_live_container_names();
        if !live.insert(name.to_owned()) {
            return None;
        }
        Some(Self {
            name: name.to_owned(),
        })
    }

    fn name(&self) -> &str {
        &self.name
    }
}

impl Drop for ContainerNameClaim {
    fn drop(&mut self) {
        lock_live_container_names().remove(&self.name);
    }
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

    fn claim_container_name(&self) -> Result<ContainerNameClaim, ScriptResponse> {
        if self.container_id.is_empty() {
            return self.claim_generated_name();
        }
        ContainerNameClaim::acquire(&self.container_id).ok_or_else(|| {
            ScriptResponse::error(&format!(
                "LXC: container '{}' is already in use by a run in this process. LXC reads a \
                 run's network section only when the container starts, so a second run would \
                 stop the first one's workload to restart it under its own policy. Let the \
                 first run finish, or give this one its own containerId.",
                self.container_id
            ))
        })
    }

    fn claim_generated_name(&self) -> Result<ContainerNameClaim, ScriptResponse> {
        // A generated name carries the low 32 bits of the clock, and two runs
        // starting together can read the same value.
        for _ in 0..GENERATED_NAME_ATTEMPTS {
            if let Some(claim) = ContainerNameClaim::acquire(&self.resolve_container_name()) {
                return Ok(claim);
            }
        }
        Err(ScriptResponse::error(
            "LXC: could not find a free container name for this run; every generated name was \
             already in use by another run in this process. Retry, or set containerId to a name \
             of your own.",
        ))
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
                if let Some(address) = first_routable_ipv4(&stdout) {
                    let _ = writeln!(
                        logger,
                        "Container network ready (IP: {}, waited {:.1}s)",
                        address,
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
        let _ = writeln!(
            logger,
            "Warning: failed to {} container: {}",
            release.verb(),
            e
        );
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

    /// Release a sandbox whose workload never got a handle to own its cleanup,
    /// reporting whatever it could not release.
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    fn abandon_prepared(&self, prepared: &mut PreparedSandbox, logger: &mut Logger) -> Vec<String> {
        // The pin and the chains are both reached through the container, so
        // they come out before it does.
        let mut failures = prepared.remove_in_container_state(self.cleanup_policy, logger);

        let release = self.release_kind(prepared.container_created);
        let result = match release {
            ContainerRelease::Destroy => prepared.container.destroy(),

            // Already down, and `lxc-stop` against a container that is not
            // running reports a failure with nothing behind it.
            ContainerRelease::Stop if prepared.force_stopped => Ok(()),

            ContainerRelease::Stop => prepared.container.stop(),
        };
        match &result {
            Ok(()) => {
                prepared.released = matches!(release, ContainerRelease::Destroy);
                prepared.note_namespace_gone();
            }
            Err(e) => {
                failures.push(format!("failed to {} container: {}", release.verb(), e));
            }
        }
        Self::report_release_failure(release, result, logger);
        failures
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
            "Container did not receive an IPv4 address within {:.0}s; \
             check that lxc-net/dnsmasq is running and able to assign one. \
             A bridge offering only IPv6 leaves the container unable to reach \
             the IPv4 destinations its policy names.",
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

    /// Everything that must succeed before a workload can launch; a failure
    /// releases whatever it had already acquired.
    fn prepare(
        &self,
        request: &ExecutionRequest,
        logger: &mut Logger,
    ) -> Result<PreparedSandbox, ScriptResponse> {
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
            Err(msg) => return Err(ScriptResponse::error(&msg)),
        };
        if let Err(msg) = wxc_common::filesystem_access::check_delegation(&request.policy) {
            return Err(ScriptResponse::error(&msg));
        }

        if self.config.distribution.is_empty() || self.config.release.is_empty() {
            return Err(ScriptResponse::error(
                "LXC distribution and release are required \
                 (e.g., \"distribution\": \"alpine\", \"release\": \"3.23\")",
            ));
        }

        let name_claim = self.claim_container_name()?;
        let container_name = name_claim.name().to_owned();

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

        // The policy lowers to the same rules with or without a container, so
        // one that cannot be programmed is refused before a container exists.
        if let Err(msg) = NetworkIptablesManager::validate_egress_lowering(
            &request.policy,
            uses_directional_keys(&request.policy),
        ) {
            return Err(ScriptResponse::error(&msg));
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
            if let Some(ref test) = request.test_feature {
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
                return Err(ScriptResponse::error(&format!(
                    "Failed to create container: {}",
                    e
                )));
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
            return Err(ScriptResponse::error(&format!(
                "Failed to configure filesystem: {}",
                e
            )));
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
                return Err(ScriptResponse::error(&format!(
                    "Failed to stop a container left running by an earlier run: {}. \
                     Its network policy is the earlier run's, so the script was not run.",
                    e
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
        if let Err(e) = container.start(network) {
            if self.destroy_on_exit || container_created {
                let _ = container.destroy();
            }
            return Err(ScriptResponse::error(&format!(
                "Failed to start container: {}",
                e
            )));
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
                return Err(response);
            }
        }

        // The init PID names the container's network namespace.
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

        let (fw_manager, ingress_manager) = match setup {
            Ok(managers) => managers,
            Err(e) => {
                self.release_after_failure(&container, container_created, logger);
                return Err(ScriptResponse::error(&e));
            }
        };

        let mut pinned = false;
        let firewall = container_firewall(
            fw_manager.rules_applied(),
            ingress_manager
                .as_ref()
                .is_some_and(|mgr| mgr.rules_applied()),
        );

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
            let pin_outcome = container.attach_capture(
                &command,
                "/",
                &[],
                true,
                Some(HOSTS_COMMAND_TIMEOUT),
                firewall,
            );
            let pin_error = match pin_outcome {
                Ok((0, _, _)) => None,

                Ok((code, _, stderr)) => {
                    Some(Self::hosts_command_failure("writing", code, &stderr))
                }
                Err(e) => Some(e.to_string()),
            };
            if let Some(reason) = pin_error {
                self.release_after_failure(&container, container_created, logger);
                return Err(ScriptResponse::error(&format!(
                    "Failed to pin the network proxy host inside the container: {}. \
                     The proxy would be unreachable, so the script was not run.",
                    reason
                )));
            }
            pinned = true;
        } else if !container_created {
            let clear_stale_pin_command = Self::build_hosts_unpin_command();
            let stale_pin_error = match container.attach_capture(
                &clear_stale_pin_command,
                "/",
                &[],
                true,
                Some(HOSTS_COMMAND_TIMEOUT),
                firewall,
            ) {
                Ok((0, _, _)) => None,
                Ok((code, _, stderr)) => {
                    Some(Self::hosts_command_failure("clearing", code, &stderr))
                }
                Err(e) => Some(e.to_string()),
            };

            if let Some(reason) = stale_pin_error {
                self.release_after_failure(&container, container_created, logger);
                return Err(ScriptResponse::error(&format!(
                    "Failed to clear a stale network proxy pin from the container's \
                     /etc/hosts: {}. The script was not run, because it could have resolved \
                     the pinned hostname to an address this policy did not authorize.",
                    reason
                )));
            }
        }

        // `script_timeout == 0` means "no timeout" per the SDK contract.
        let timeout = if request.script_timeout == 0 {
            None
        } else {
            Some(Duration::from_millis(u64::from(request.script_timeout)))
        };
        let mut exec_env = resolved_env(request);
        wxc_common::proxy_env::apply_proxy_env(&mut exec_env, &request.policy.network_proxy);

        Ok(PreparedSandbox {
            fw_manager,
            ingress_manager,
            container,
            container_created,
            firewall,
            pinned,
            released: false,
            force_stopped: false,
            stop_failed: false,
            script_code: request.script_code.clone(),
            start_directory: start_directory(request).unwrap_or_default(),
            exec_env,
            timeout,
            _name_claim: name_claim,
        })
    }

    fn run_internal(&self, request: &ExecutionRequest, logger: &mut Logger) -> ScriptResponse {
        let mut prepared = match self.prepare(request, logger) {
            Ok(prepared) => prepared,
            Err(response) => return response,
        };

        let _ = writeln!(logger, "Executing script inside container...");

        // The `true` forces `--clear-env`, without which an empty env list lets
        // `lxc-attach` inherit the host environment and its proxy credentials.
        let result = prepared.container.attach_run(
            &prepared.script_code,
            &prepared.start_directory,
            &prepared.exec_env,
            true,
            prepared.timeout,
            prepared.firewall,
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

        prepared.tear_down(self.cleanup_policy, self.destroy_on_exit, logger);

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

    fn hosts_command_failure(verb: &str, exit_code: i32, stderr: &str) -> String {
        let detail = stderr.trim();
        if detail.is_empty() {
            return format!("{} /etc/hosts exited with {}", verb, exit_code);
        }
        format!("{} /etc/hosts exited with {}: {}", verb, exit_code, detail)
    }
}

/// A started container with its network policy in place, ready to launch a
/// workload, plus everything whose teardown outlives that launch.
struct PreparedSandbox {
    fw_manager: NetworkIptablesManager,
    ingress_manager: Option<IngressManager>,
    container: LxcContainer,

    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    container_created: bool,

    firewall: ContainerFirewall,
    pinned: bool,
    released: bool,

    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    force_stopped: bool,

    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    stop_failed: bool,

    script_code: String,
    start_directory: String,
    exec_env: Vec<String>,
    timeout: Option<Duration>,

    /// Keeps this sandbox's container out of reach of a second one in this
    /// process.
    _name_claim: ContainerNameClaim,
}

impl PreparedSandbox {
    /// Remove the state that can only come out while the container is up: the
    /// pin is rewritten by a command inside it, and the chains are addressed
    /// through its init PID.
    fn remove_in_container_state(
        &mut self,
        cleanup_policy: bool,
        logger: &mut Logger,
    ) -> Vec<String> {
        let mut failures = Vec::new();

        if self.stop_failed {
            // Hooked chains are still around a workload that may be running, so
            // taking them out would leave it with no enforcement at all. Ones
            // that were never hooked filter nothing and come out below.
            let hooked = self.fw_manager.is_hooked();
            let failure = if hooked {
                self.retain_rules_past_drop();
                "the container could not be stopped, so its firewall rules were left in \
                 place rather than removed around a workload that may still be running"
            } else {
                "the container could not be stopped, so it may still be running"
            };

            let _ = writeln!(logger, "Warning: {}", failure);
            failures.push(failure.to_string());

            if hooked {
                return failures;
            }
        }

        if self.pinned && cleanup_policy {
            let clear_run_pin_command = LxcScriptRunner::build_hosts_unpin_command();
            let unpin_error = match self.container.attach_capture(
                &clear_run_pin_command,
                "/",
                &[],
                true,
                Some(HOSTS_COMMAND_TIMEOUT),
                self.firewall,
            ) {
                Ok((0, _, _)) => None,
                Ok((code, _, stderr)) => Some(LxcScriptRunner::hosts_command_failure(
                    "clearing", code, &stderr,
                )),
                Err(e) => Some(e.to_string()),
            };

            match unpin_error {
                Some(reason) => {
                    let failure = format!("failed to clear the proxy host pin: {}", reason);
                    let _ = writeln!(logger, "Warning: {}", failure);
                    failures.push(failure);
                }
                None => self.pinned = false,
            }
        }

        // These chains are addressed by the container's init PID, so they have
        // to come out before the container does.
        if self.fw_manager.rules_applied() && cleanup_policy {
            let _ = self.fw_manager.remove_firewall_rules(logger);
            if self.fw_manager.rules_applied() {
                let failure = format!(
                    "failed to remove the egress firewall chain {}",
                    self.fw_manager.chain_name()
                );
                let _ = writeln!(logger, "Warning: {}", failure);
                failures.push(failure);
            }
        }
        if let Some(mgr) = &mut self.ingress_manager {
            if mgr.rules_applied() && cleanup_policy {
                let _ = mgr.remove_firewall_rules(logger);
                if mgr.rules_applied() {
                    let failure = format!(
                        "failed to remove the ingress firewall chain {}",
                        mgr.chain_name()
                    );
                    let _ = writeln!(logger, "Warning: {}", failure);
                    failures.push(failure);
                }
            }
        }

        failures
    }

    /// Run the completion-path release — pin, then rules, then container —
    /// repeating only the steps an earlier call failed to complete.
    fn tear_down(
        &mut self,
        cleanup_policy: bool,
        destroy_on_exit: bool,
        logger: &mut Logger,
    ) -> Vec<String> {
        let mut failures = Vec::new();

        // Destroying takes the network namespace and the rootfs down with it,
        // so the chains in one and the pin in the other are already going.
        // Chains that were never hooked live on the host and still have to
        // come out below.
        let destroying = destroy_on_exit && !self.released;
        let skipped_in_container = destroying && self.fw_manager.is_hooked();
        if !skipped_in_container {
            failures.extend(self.remove_in_container_state(cleanup_policy, logger));
        }

        if destroying {
            let _ = writeln!(logger, "Destroying container...");
            match self.container.destroy() {
                Ok(()) => {
                    self.released = true;
                    self.note_namespace_gone();
                }
                Err(e) => {
                    // The container outlived the destroy, so the chains skipped
                    // above are still filtering a workload that may be alive.
                    if skipped_in_container {
                        self.retain_rules_past_drop();
                    }

                    let failure = format!("failed to destroy container: {}", e);
                    let _ = writeln!(logger, "Warning: {}", failure);
                    failures.push(failure);
                }
            }
        }

        failures
    }

    /// Keep the installed rules in place when the managers go away, for a
    /// container that may still be running behind them.
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    fn retain_rules_past_drop(&mut self) {
        self.fw_manager.set_preserve_policy(true);
        if let Some(mgr) = &mut self.ingress_manager {
            mgr.set_preserve_policy(true);
        }
    }

    /// Kill every process in the container, which is the only way to reach a
    /// workload that lives in its PID namespace.
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    fn force_stop(&mut self) -> Result<(), String> {
        if self.force_stopped {
            return Ok(());
        }
        if let Err(e) = self.container.stop() {
            self.stop_failed = true;
            return Err(e);
        }
        self.stop_failed = false;
        self.force_stopped = true;
        self.note_namespace_gone();

        Ok(())
    }

    /// Give up the state that needed the container, now that it is gone.
    fn note_namespace_gone(&mut self) {
        // Rewriting the pin takes a command inside a running container, and
        // there is no longer one; a container kept for reuse has the stale pin
        // cleared by the next run.
        self.pinned = false;

        // These chains went down with the network namespace, and the init PID
        // that addressed them can be recycled into another namespace, where the
        // same chain name may belong to a later run.
        if self.fw_manager.is_hooked() {
            self.fw_manager.forget();
        }
        if let Some(mgr) = &mut self.ingress_manager {
            mgr.forget();
        }
    }
}

pub const LXC_CAPABILITIES_MODE_UNSUPPORTED: &str =
    "LXC: network.enforcementMode='capabilities' (the default) selects Windows AppContainer \
     capability SIDs, which LXC has no mechanism for. Accepting it would enforce the policy by \
     some means other than the one named. Use the supported network.egress / network.ingress \
     fields instead; no registered LXC contract accepts network.enforcementMode.";

pub const LXC_RUNTIME_PROXY_UNSUPPORTED: &str =
    "LXC: runtimeConfig.networkProxy is not supported. It must name a loopback endpoint, which \
     inside the container's own network namespace is the container rather than the host. LXC \
     has no proxy surface in any supported contract. Select a backend that can enforce a \
     loopback proxy, or remove the proxy request.";

pub const LXC_INHERIT_STDIO_UNSUPPORTED: &str =
    "LXC: inherited stdio is not available from the in-process sandbox API. LXC gives a workload \
     the host's own stdin/stdout/stderr by allocating a pty and bridging it, which runs the \
     script to completion and cannot hand back a live handle; it also reads the host's stdin and \
     installs a process-wide window-size handler, neither of which a library may do to its \
     caller. Stream the sandbox over pipes, or run the lxc-exec binary.";

pub const LXC_STREAMING_LINUX_ONLY: &str = "LXC: sandboxes can only be launched on Linux.";

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
        if request.policy.runtime_network_proxy_specified {
            return Err(ScriptResponse::error(LXC_RUNTIME_PROXY_UNSUPPORTED));
        }
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

/// LXC's streaming half, which serves [`StdioMode::Pipes`] only.
///
/// [`StdioMode::Inherit`] is refused, so wrapping this in
/// [`wxc_common::sandbox_process::Runner`] compiles but fails at run time;
/// `lxc-exec` stays on [`ScriptRunner`] for its pty.
impl SandboxBackend for LxcScriptRunner {
    fn network_policy_support(&self) -> NetworkPolicySupport {
        lxc_network_policy_support()
    }

    fn validate(&self, request: &ExecutionRequest) -> Result<(), ScriptResponse> {
        ScriptRunner::validate_runner(self, request)
    }

    fn spawn(
        &mut self,
        request: &ExecutionRequest,
        logger: &mut Logger,
        stdio: StdioMode,
    ) -> Result<Box<dyn SandboxProcess>, ScriptResponse> {
        match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            self.spawn_internal(request, logger, stdio)
        })) {
            Ok(r) => r,
            Err(_) => Err(ScriptResponse::error(
                "Unknown error during LXC sandbox launch.",
            )),
        }
    }
}

impl LxcScriptRunner {
    fn spawn_internal(
        &self,
        request: &ExecutionRequest,
        logger: &mut Logger,
        stdio: StdioMode,
    ) -> Result<Box<dyn SandboxProcess>, ScriptResponse> {
        if stdio == StdioMode::Inherit {
            return Err(ScriptResponse::error(LXC_INHERIT_STDIO_UNSUPPORTED));
        }
        validate_common(request)?;
        SandboxBackend::validate(self, request)?;

        self.launch_piped(request, logger)
    }

    #[cfg(target_os = "linux")]
    fn launch_piped(
        &self,
        request: &ExecutionRequest,
        logger: &mut Logger,
    ) -> Result<Box<dyn SandboxProcess>, ScriptResponse> {
        let mut prepared = self.prepare(request, logger)?;

        let _ = writeln!(logger, "Launching script inside container...");

        // The `true` forces `--clear-env`, without which an empty env list lets
        // `lxc-attach` inherit the host environment and its proxy credentials.
        let launched = prepared.container.attach_spawn(
            &prepared.script_code,
            &prepared.start_directory,
            &prepared.exec_env,
            true,
            prepared.firewall,
        );

        let mut child = match launched {
            Ok(child) => child,
            Err(e) => {
                let cleanup = self.abandon_prepared(&mut prepared, logger);
                return Err(ScriptResponse::error(&launch_failure_message(
                    &format!("Execution failed: {}", e),
                    &cleanup,
                )));
            }
        };

        let stdin = child.stdin.take();

        // Wrap the pipe reads so the caller can abandon a stream a backgrounded
        // descendant is holding open without killing the workload.
        let wrapped = (
            wrap_pipe(child.stdout.take()),
            wrap_pipe(child.stderr.take()),
        );
        let (stdout, stdout_canceller, stderr, stderr_canceller) = match wrapped {
            (Ok((out, out_canceller)), Ok((err, err_canceller))) => {
                (out, out_canceller, err, err_canceller)
            }
            (out_result, err_result) => {
                // The workload is already running and no handle exists to own
                // its cleanup, so it comes down here.
                if prepared.force_stop().is_err() {
                    let _ = child.kill();
                }
                let _ = child.wait();
                let cleanup = self.abandon_prepared(&mut prepared, logger);

                let error = out_result.err().or(err_result.err());
                return Err(ScriptResponse::error(&launch_failure_message(
                    &format!(
                        "Failed to wrap the lxc-attach stdio pipes: {}",
                        error.map_or_else(|| "unknown error".to_string(), |e| e.to_string())
                    ),
                    &cleanup,
                )));
            }
        };

        Ok(Box::new(LxcSandboxProcess::new(LxcChild {
            child,
            stdin,
            stdout,
            stderr,
            stdout_canceller,
            stderr_canceller,
            timeout: prepared.timeout,
            prepared,
            cleanup_policy: self.cleanup_policy,
            destroy_on_exit: self.destroy_on_exit,
        })))
    }

    /// Stub for the workspace-wide clippy lane that runs on Windows.
    #[cfg(not(target_os = "linux"))]
    fn launch_piped(
        &self,
        _request: &ExecutionRequest,
        _logger: &mut Logger,
    ) -> Result<Box<dyn SandboxProcess>, ScriptResponse> {
        Err(ScriptResponse::error(LXC_STREAMING_LINUX_ONLY))
    }
}

/// A launched workload: the host-side `lxc-attach` process, its parent-side
/// pipe ends, and the prepared sandbox torn down once it is done.
#[cfg(target_os = "linux")]
struct LxcChild {
    child: std::process::Child,
    stdin: Option<std::process::ChildStdin>,
    stdout: Option<InterruptibleReader>,
    stderr: Option<InterruptibleReader>,

    /// Cancellers for the stdout/stderr reads, kept so the closers can still be
    /// minted after the stream is taken.
    stdout_canceller: Option<ReadCanceller>,
    stderr_canceller: Option<ReadCanceller>,

    timeout: Option<Duration>,
    prepared: PreparedSandbox,
    cleanup_policy: bool,
    destroy_on_exit: bool,
}

#[cfg(target_os = "linux")]
impl LxcChild {
    fn terminate(&mut self) -> std::io::Result<()> {
        // Killed first so the reap, and the stream drains waiting on it, are
        // never parked behind a stop that is slow or wedged. The workload is
        // orphaned for as long as the stop takes, with its chains still up.
        let _ = self.child.kill();

        // `lxc-attach` is a host process while the workload runs in the
        // container's PID namespace under container init, so nothing aimed at
        // the host process or its group reaches the workload; only stopping the
        // container does.
        self.prepared.force_stop().map_err(std::io::Error::other)
    }
}

/// A running LXC sandbox exposed as a [`SandboxProcess`].
#[cfg(target_os = "linux")]
struct LxcSandboxProcess {
    inner: LxcChild,
    teardown_done: bool,
    teardown_failures: Vec<String>,
}

#[cfg(target_os = "linux")]
impl LxcSandboxProcess {
    fn new(inner: LxcChild) -> Self {
        Self {
            inner,
            teardown_done: false,
            teardown_failures: Vec::new(),
        }
    }

    fn run_teardown(&mut self) {
        if self.teardown_done {
            return;
        }

        // A failed destroy leaks a root-owned container, and neither `wait` nor
        // `Drop` has the caller's logger to report it through.
        let mut logger = Logger::new(wxc_common::logger::Mode::Buffer);
        self.teardown_failures = self.inner.prepared.tear_down(
            self.inner.cleanup_policy,
            self.inner.destroy_on_exit,
            &mut logger,
        );

        // `tear_down` repeats only the steps an earlier call could not finish,
        // so latching unconditionally would strand the container on one
        // failure.
        self.teardown_done = self.teardown_failures.is_empty();
    }
}

#[cfg(target_os = "linux")]
impl SandboxProcess for LxcSandboxProcess {
    fn warnings(&self) -> Vec<String> {
        self.teardown_failures.clone()
    }

    fn take_native_stdio(&mut self) -> std::io::Result<Option<NativeStdio>> {
        use std::os::fd::AsFd;

        let stdio = duplicate_and_take_native_stdio(
            &mut self.inner.stdin,
            &mut self.inner.stdout,
            &mut self.inner.stderr,
            |stream| stream.as_fd().try_clone_to_owned(),
            InterruptibleReader::try_clone_owned_fd,
            InterruptibleReader::try_clone_owned_fd,
        )?;
        if stdio.is_some() {
            self.inner.stdout_canceller.take();
            self.inner.stderr_canceller.take();
        }
        Ok(stdio)
    }

    fn take_stdin(&mut self) -> Option<Box<dyn std::io::Write + Send>> {
        take_boxed_write(&mut self.inner.stdin)
    }

    fn take_stdout(&mut self) -> Option<Box<dyn std::io::Read + Send>> {
        take_boxed_read(&mut self.inner.stdout)
    }

    fn take_stderr(&mut self) -> Option<Box<dyn std::io::Read + Send>> {
        take_boxed_read(&mut self.inner.stderr)
    }

    fn stdout_closer(&self) -> Option<Box<dyn StreamCloser>> {
        boxed_closer(&self.inner.stdout_canceller)
    }

    fn stderr_closer(&self) -> Option<Box<dyn StreamCloser>> {
        boxed_closer(&self.inner.stderr_canceller)
    }

    fn try_wait(&mut self) -> std::io::Result<Option<i32>> {
        Ok(self
            .inner
            .child
            .try_wait()?
            .map(|status| status.code().unwrap_or(-1)))
    }

    /// Always `0` — the workload runs in the container's PID namespace, and the
    /// host-side `lxc-attach` pid is not a handle that reaches it.
    fn id(&self) -> u32 {
        0
    }

    fn kill(&mut self) -> std::io::Result<()> {
        // Only a clean teardown releases the container, so a failed one leaves
        // this latch open and still reaches the stop below.
        if self.teardown_done {
            return Ok(());
        }
        self.inner.terminate()
    }

    fn wait(&mut self) -> std::io::Result<i32> {
        // Close our copy of any not-taken stdin so the child sees EOF.
        self.inner.stdin.take();

        // Drain (and discard) any not-taken stdout/stderr concurrently so the
        // child can't block on a full pipe (taken streams are the caller's
        // responsibility).
        let stdout_thread = spawn_discard(self.inner.stdout.take());
        let stderr_thread = spawn_discard(self.inner.stderr.take());

        let result = match wait_with_timeout(&mut self.inner.child, self.inner.timeout) {
            Ok(status) => Ok(status.code().unwrap_or(-1)),
            Err(WaitError::Timeout) => {
                // Stopping the container releases the pipe write ends a
                // backgrounded descendant would otherwise hold past the
                // deadline, so the drains below can finish.
                let terminated = self.kill_for_timeout();
                let _ = self.inner.child.wait();
                Err(std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    match terminated {
                        Ok(()) => "LXC: script timed out".to_string(),
                        Err(e) => format!(
                            "LXC: script timed out, and the container could not be stopped, \
                             so the workload may still be running: {e}"
                        ),
                    },
                ))
            }
            Err(WaitError::Io(error)) => {
                // The workload may still be running, and teardown is about to
                // release the container it is running in.
                let _ = self.kill();
                let _ = self.inner.child.wait();
                Err(std::io::Error::other(format!("LXC: wait failed: {error}")))
            }
        };

        cancel_and_join_discard(stdout_thread, &self.inner.stdout_canceller);
        cancel_and_join_discard(stderr_thread, &self.inner.stderr_canceller);
        self.run_teardown();
        result
    }
}

#[cfg(target_os = "linux")]
impl Drop for LxcSandboxProcess {
    fn drop(&mut self) {
        // Kill and reap before teardown: a sandbox abandoned without a wait
        // would otherwise have its container destroyed while its workload was
        // still running in it, and the host-side `lxc-attach` would be left
        // unreaped.
        let _ = self.kill();
        let _ = self.inner.child.wait();
        self.run_teardown();
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

/// The launch error, plus anything the cleanup behind it could not release.
///
/// No handle exists on these paths, so `warnings` is never called and a leaked
/// root-owned container has nowhere else to surface.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
fn launch_failure_message(reason: &str, cleanup_failures: &[String]) -> String {
    if cleanup_failures.is_empty() {
        return reason.to_string();
    }
    format!(
        "{} Cleanup after the failure did not finish: {}.",
        reason,
        cleanup_failures.join("; ")
    )
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

    /// No other validation layer refuses an unnamed image, so `prepare` must.
    #[test]
    fn prepare_refuses_an_unnamed_image_before_touching_lxc() {
        let runner = LxcScriptRunner::new(
            &LxcConfig::default(),
            "prepare-image-test",
            &LifecycleConfig::default(),
        );
        let mut logger = Logger::new(Mode::Buffer);

        let refusal = runner
            .prepare(&ExecutionRequest::default(), &mut logger)
            .err()
            .expect("an empty distribution and release cannot name an image to create");

        assert!(
            refusal.error_message.contains("distribution and release"),
            "the refusal must name the missing fields; got: {:?}",
            refusal.error_message
        );
        assert!(
            !logger.get_buffer().contains("Creating LXC container"),
            "the refusal must land before any container work"
        );
    }

    /// A password in the URL would reach `lxc-attach` as an argument, and
    /// process arguments are world-readable through `/proc/<pid>/cmdline`.
    #[test]
    fn prepare_refuses_a_proxy_url_carrying_credentials() {
        let runner = LxcScriptRunner::new(
            &LxcConfig {
                distribution: "alpine".to_string(),
                release: "3.23".to_string(),
            },
            "prepare-proxy-test",
            &LifecycleConfig::default(),
        );
        let request = request_with_policy(ContainerPolicy {
            network_proxy: ProxyConfig {
                address: Some(ProxyAddress::from_url(
                    "http://user:hunter2@proxy.example.com:3128",
                    "proxy.example.com".to_string(),
                    3128,
                )),
                ..Default::default()
            },
            ..Default::default()
        });
        let mut logger = Logger::new(Mode::Buffer);

        let refusal = runner
            .prepare(&request, &mut logger)
            .err()
            .expect("a proxy URL carrying a password must not become an lxc-attach argument");

        assert!(
            refusal.error_message.contains("must not carry credentials"),
            "the refusal must name the cause; got: {:?}",
            refusal.error_message
        );
        assert!(
            !refusal.error_message.contains("hunter2"),
            "the refusal must not repeat the secret it is refusing; got: {:?}",
            refusal.error_message
        );
    }

    #[test]
    fn tear_down_removes_the_rules_before_it_releases_the_container() {
        let _fake = crate::network_iptables::test_firewall::install();
        let mut prepared = prepared_with_applied_rules("tear-down-order");
        let mut logger = Logger::new(Mode::Buffer);

        prepared.tear_down(true, true, &mut logger);

        let log = logger.get_buffer();
        let removed = log
            .find("Removing iptables")
            .unwrap_or_else(|| panic!("the applied chain must be removed; log: {log:?}"));
        let released = log
            .find("Destroying container")
            .unwrap_or_else(|| panic!("destroyOnExit must release the container; log: {log:?}"));
        assert!(
            removed < released,
            "rules must come out of the namespace before the container that owns \
             it is released; log: {log:?}"
        );
    }

    /// A step that succeeded must not run twice, and one that failed must be
    /// retried — that retry is what lets a later teardown finish a release this
    /// one could not.
    #[test]
    fn tear_down_repeats_only_the_steps_that_failed() {
        let _fake = crate::network_iptables::test_firewall::install();
        let mut prepared = prepared_with_applied_rules("tear-down-idempotent");
        prepared.pinned = true;

        let mut first = Logger::new(Mode::Buffer);
        prepared.tear_down(true, true, &mut first);
        let mut second = Logger::new(Mode::Buffer);
        prepared.tear_down(true, true, &mut second);

        assert!(
            first.get_buffer().contains("Removing iptables"),
            "the first pass must remove the applied chain; log: {:?}",
            first.get_buffer()
        );
        assert!(
            !second.get_buffer().contains("Removing iptables"),
            "the chain came out on the first pass, so the second must leave it \
             alone; log: {:?}",
            second.get_buffer()
        );

        // The fixture names a container that was never created, so the unpin and
        // the destroy both fail here and both must be attempted again.
        assert!(
            first.get_buffer().contains("proxy host pin")
                && second.get_buffer().contains("proxy host pin"),
            "an unpin that failed must be retried; logs: {:?} / {:?}",
            first.get_buffer(),
            second.get_buffer()
        );
        assert!(
            second.get_buffer().contains("Destroying container"),
            "a destroy that failed must be retried; log: {:?}",
            second.get_buffer()
        );
    }

    #[test]
    fn a_container_that_would_not_stop_keeps_its_firewall_rules() {
        let fake = crate::network_iptables::test_firewall::install();
        let mut prepared = prepared_with_applied_rules("stop-refused");
        apply_hooked_egress_rules(&mut prepared, 4242);
        prepared.pinned = true;

        // The fixture names a container that was never created, so `lxc-stop`
        // has nothing to stop and reports the failure this test needs.
        prepared
            .force_stop()
            .expect_err("a container that does not exist cannot be stopped");

        let issued_before = fake.issued().len();
        let mut logger = Logger::new(Mode::Buffer);
        let failures = prepared.remove_in_container_state(true, &mut logger);

        assert_eq!(
            fake.issued().len(),
            issued_before,
            "the workload may still be running behind these rules, so removing them would \
             leave it egressing unfiltered; issued {:?}",
            fake.issued()
        );
        assert!(
            prepared.fw_manager.rules_applied(),
            "the rules must stay owned so a later teardown can still remove them"
        );
        assert!(
            failures.iter().any(|f| f.contains("could not be stopped")),
            "a caller sampling warnings must learn the rules were left behind; got {failures:?}"
        );
    }

    /// Install a hooked egress chain on a prepared sandbox, so the
    /// netns-scoped state has something to forget. Ingress is left alone: its
    /// manager drives `nsenter` through a runner the iptables fake does not
    /// intercept, so its own module owns that coverage.
    fn apply_hooked_egress_rules(prepared: &mut PreparedSandbox, netns_pid: u32) {
        let policy = ContainerPolicy {
            network_enforcement_mode: NetworkEnforcementMode::Firewall,
            allowed_hosts: vec!["192.0.2.10".to_string()],
            ..Default::default()
        };
        let mut logger = Logger::new(Mode::Buffer);

        prepared.fw_manager = NetworkIptablesManager::new(
            prepared.container.name(),
            EgressHookPoint::ContainerNetns(netns_pid),
        );
        prepared
            .fw_manager
            .apply_legacy_rules(&policy, &mut logger)
            .expect("the fake firewall accepts every command");
    }

    #[test]
    fn a_destroyed_container_takes_its_chains_out_of_later_removals() {
        let _fake = crate::network_iptables::test_firewall::install();
        let mut prepared = prepared_with_applied_rules("namespace-gone");
        apply_hooked_egress_rules(&mut prepared, 4242);
        prepared.pinned = true;

        assert!(
            prepared.fw_manager.rules_applied(),
            "precondition: the chain is installed in the container netns"
        );

        prepared.note_namespace_gone();

        assert!(
            !prepared.fw_manager.rules_applied(),
            "the netns took the chain with it, so its dead init PID must never be nsentered"
        );
        assert!(
            !prepared.pinned,
            "the pin cannot be rewritten without a running container"
        );
    }

    #[test]
    fn abandoning_a_stopped_sandbox_forgets_the_chains_its_namespace_took() {
        let _fake = crate::network_iptables::test_firewall::install();

        // `preserve_policy` keeps the explicit removal from running, so the
        // only thing that can clear the chain here is the release itself.
        let runner = LxcScriptRunner::new(
            &LxcConfig::default(),
            "abandon-stopped",
            &LifecycleConfig {
                destroy_on_exit: false,
                preserve_policy: true,
            },
        );
        let mut prepared = prepared_with_applied_rules("abandon-stopped");
        apply_hooked_egress_rules(&mut prepared, 4242);

        // The state the wrap-pipe failure path reaches: the container was
        // stopped before the sandbox was abandoned, so `lxc-stop` must not be
        // issued against it a second time.
        prepared.force_stopped = true;

        let mut logger = Logger::new(Mode::Buffer);
        let failures = runner.abandon_prepared(&mut prepared, &mut logger);

        assert!(
            !prepared.fw_manager.rules_applied(),
            "releasing a stopped container must give up its netns chains, or a later drop \
             nsenters an init PID that is dead"
        );
        assert!(
            failures.is_empty(),
            "a container that was already stopped is released cleanly; got {failures:?}"
        );
    }

    #[test]
    fn a_failed_release_reaches_the_caller_rather_than_only_the_log() {
        let _fake = crate::network_iptables::test_firewall::install();
        let runner = LxcScriptRunner::new(
            &LxcConfig::default(),
            "abandon-failed",
            &LifecycleConfig::default(),
        );
        let mut prepared = prepared_with_applied_rules("abandon-failed");

        let mut logger = Logger::new(Mode::Buffer);
        let failures = runner.abandon_prepared(&mut prepared, &mut logger);

        assert!(
            failures.iter().any(|f| f.contains("destroy container")),
            "no handle exists on a failed launch, so a container that could not be destroyed \
             has to travel back with the error; got {failures:?}"
        );
        assert!(
            launch_failure_message("Execution failed: no", &failures).contains("destroy container"),
            "the launch error must carry the cleanup failure"
        );
    }

    #[test]
    fn a_container_that_would_not_be_destroyed_keeps_its_rules_through_the_drop() {
        let fake = crate::network_iptables::test_firewall::install();
        let mut prepared = prepared_with_applied_rules("destroy-refused-drop");
        apply_hooked_egress_rules(&mut prepared, 4242);

        // The fixture names a container that was never created, so the destroy
        // fails and leaves one that may still be running the workload.
        let mut logger = Logger::new(Mode::Buffer);
        let failures = prepared.tear_down(true, true, &mut logger);

        assert!(
            failures.iter().any(|f| f.contains("destroy container")),
            "a leaked root-owned container has to reach the caller; got {failures:?}"
        );

        let issued_before = fake.issued().len();
        drop(prepared);

        assert_eq!(
            fake.issued().len(),
            issued_before,
            "the container survived the destroy, so dropping the sandbox must not strip the \
             chains still filtering it; issued {:?}",
            fake.issued()
        );
    }

    #[test]
    fn a_container_that_would_not_stop_is_reported_even_with_nothing_hooked() {
        let fake = crate::network_iptables::test_firewall::install();
        let mut prepared = prepared_with_applied_rules("stop-refused-unhooked");

        assert!(
            !prepared.fw_manager.is_hooked(),
            "precondition: the fixture's chain is on the host, not in a netns"
        );

        prepared
            .force_stop()
            .expect_err("a container that does not exist cannot be stopped");

        let issued_before = fake.issued().len();
        let mut logger = Logger::new(Mode::Buffer);
        let failures = prepared.remove_in_container_state(true, &mut logger);

        assert!(
            failures.iter().any(|f| f.contains("could not be stopped")),
            "a container left running has to reach the caller whether or not anything was \
             hooked, and it is what keeps teardown retryable; got {failures:?}"
        );
        assert!(
            fake.issued().len() > issued_before,
            "an unhooked chain filters nothing, so it still comes out; issued {:?}",
            fake.issued()
        );
    }

    #[test]
    fn host_chains_survive_a_container_that_is_gone() {
        let fake = crate::network_iptables::test_firewall::install();
        let mut prepared = prepared_with_applied_rules("unhooked-survives");

        assert!(
            !prepared.fw_manager.is_hooked() && prepared.fw_manager.rules_applied(),
            "precondition: the fixture's chain is on the host, not in a netns"
        );

        prepared.note_namespace_gone();

        assert!(
            prepared.fw_manager.rules_applied(),
            "an unhooked chain lives on the host and outlives the container, so forgetting it \
             would leak host firewall state"
        );

        let issued_before = fake.issued().len();
        let mut logger = Logger::new(Mode::Buffer);
        prepared.remove_in_container_state(true, &mut logger);

        assert!(
            fake.issued().len() > issued_before,
            "a host chain must still be removed after the container is gone; issued {:?}",
            fake.issued()
        );
    }

    #[test]
    fn a_container_that_would_not_stop_keeps_its_rules_through_the_drop() {
        let fake = crate::network_iptables::test_firewall::install();
        let mut prepared = prepared_with_applied_rules("stop-refused-drop");
        apply_hooked_egress_rules(&mut prepared, 4242);

        prepared
            .force_stop()
            .expect_err("a container that does not exist cannot be stopped");

        let mut logger = Logger::new(Mode::Buffer);
        prepared.remove_in_container_state(true, &mut logger);

        let issued_before = fake.issued().len();
        drop(prepared);

        assert_eq!(
            fake.issued().len(),
            issued_before,
            "the workload may still be running behind these chains, so dropping the sandbox \
             must not remove them either; issued {:?}",
            fake.issued()
        );
    }

    /// A sandbox whose egress chain is installed, for the teardown tests. The
    /// container name is unique per process so the release cannot reach a real
    /// container on a host that has LXC installed.
    fn prepared_with_applied_rules(tag: &str) -> PreparedSandbox {
        let name = format!("mxc-{}-{}-{}", tag, std::process::id(), uuid_simple());
        let runner =
            LxcScriptRunner::new(&LxcConfig::default(), &name, &LifecycleConfig::default());
        let policy = ContainerPolicy {
            network_enforcement_mode: NetworkEnforcementMode::Firewall,
            allowed_hosts: vec!["192.0.2.10".to_string()],
            ..Default::default()
        };
        let mut logger = Logger::new(Mode::Buffer);

        let (fw_manager, ingress_manager) = runner
            .set_up_network_rules_for_v07(
                &name,
                EgressHookPoint::Unhooked,
                None,
                &policy,
                &mut logger,
            )
            .expect("the fake firewall accepts every command");
        assert!(
            fw_manager.rules_applied(),
            "the fixture must have rules for teardown to remove"
        );

        PreparedSandbox {
            fw_manager,
            ingress_manager,
            container: LxcContainer::new(&name, Some("/var/lib/lxc")),
            container_created: false,
            firewall: ContainerFirewall::Absent,
            pinned: false,
            released: false,
            force_stopped: false,
            stop_failed: false,
            script_code: "true".to_string(),
            start_directory: String::new(),
            exec_env: Vec::new(),
            timeout: None,
            _name_claim: ContainerNameClaim::acquire(&name)
                .expect("the fixture builds a name no other sandbox can be holding"),
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

    /// `process.env` resolution, which schema 0.9 gave a default block.
    mod env {
        use super::*;
        use wxc_common::models::DefaultEnvCompatibility;

        fn request(compatibility: DefaultEnvCompatibility) -> ExecutionRequest {
            ExecutionRequest {
                default_env_compatibility: compatibility,
                ..Default::default()
            }
        }

        fn value<'a>(entries: &'a [String], key: &str) -> Option<&'a str> {
            entries
                .iter()
                .find_map(|kv| kv.strip_prefix(&format!("{key}=")))
        }

        /// A direct typed SDK request that named no contract takes the current
        /// behavior.
        #[test]
        fn a_direct_sdk_request_gets_the_default_block() {
            let r = ExecutionRequest::default();
            assert_eq!(value(&resolved_env(&r), "PATH"), Some(DEFAULT_PATH));
        }

        #[test]
        fn an_omitted_env_gets_the_default_block() {
            let mut r = request(DefaultEnvCompatibility::DefaultBlock);
            r.env = None;
            r.working_directory = "/workspace".into();
            let entries = resolved_env(&r);
            assert_eq!(value(&entries, "PATH"), Some(DEFAULT_PATH));
            assert_eq!(value(&entries, "HOME"), Some("/workspace"));
            assert_eq!(value(&entries, "TERM"), Some(DEFAULT_TERM));
        }

        #[test]
        fn the_default_path_covers_sbin() {
            for dir in ["/usr/sbin", "/sbin", "/usr/bin", "/bin"] {
                assert!(
                    DEFAULT_PATH.split(':').any(|entry| entry == dir),
                    "{dir} must be on the default PATH"
                );
            }
        }

        #[test]
        fn an_explicitly_empty_env_stays_empty() {
            let mut r = request(DefaultEnvCompatibility::DefaultBlock);
            r.env = Some(vec![]);
            assert!(resolved_env(&r).is_empty());
        }

        #[test]
        fn a_supplied_env_is_used_verbatim() {
            let mut r = request(DefaultEnvCompatibility::DefaultBlock);
            r.env = Some(vec!["FOO=bar".into()]);
            assert_eq!(resolved_env(&r), vec!["FOO=bar".to_string()]);
        }

        #[test]
        fn inherit_default_env_layers_over_the_default_block() {
            let mut r = request(DefaultEnvCompatibility::DefaultBlock);
            r.env = Some(vec!["FOO=bar".into(), "PATH=/only/mine".into()]);
            r.inherit_default_env = true;
            let entries = resolved_env(&r);

            assert_eq!(value(&entries, "FOO"), Some("bar"));
            assert_eq!(value(&entries, "TERM"), Some(DEFAULT_TERM));
            // Replaced, not appended: `lxc-attach` takes the last -v for a
            // name, so a duplicate would silently depend on ordering.
            assert_eq!(value(&entries, "PATH"), Some("/only/mine"));
            assert_eq!(
                entries.iter().filter(|kv| kv.starts_with("PATH=")).count(),
                1
            );
        }

        #[test]
        fn home_follows_the_directory_the_child_starts_in() {
            let mut r = request(DefaultEnvCompatibility::DefaultBlock);
            r.env = None;
            r.working_directory = "/workspace".into();
            assert_eq!(value(&resolved_env(&r), "HOME"), Some("/workspace"));
        }

        #[test]
        fn a_relative_start_directory_is_anchored_to_the_container_root() {
            for (cwd, expected) in [
                ("work", "/work"),
                ("./work", "/work"),
                ("a/../b", "/b"),
                ("/x/../y/./z", "/y/z"),
            ] {
                let mut r = request(DefaultEnvCompatibility::DefaultBlock);
                r.env = None;
                r.working_directory = cwd.into();
                assert_eq!(value(&resolved_env(&r), "HOME"), Some(expected));
                assert_eq!(start_directory(&r).as_deref(), Some(expected));
            }
        }

        /// A policy grant is not a working directory: with `process.cwd`
        /// omitted the child starts at the container root, so a granted host
        /// directory -- which may not even be mounted -- must not become its
        /// `HOME`.
        #[test]
        fn a_policy_grant_alone_does_not_become_home() {
            let mut r = request(DefaultEnvCompatibility::DefaultBlock);
            r.env = None;
            r.working_directory = String::new();
            // A real directory, so the shared resolver's `is_dir` probe would
            // accept it if `HOME` consulted the policy.
            r.policy.readwrite_paths = vec![std::env::temp_dir().display().to_string()];

            assert_eq!(value(&resolved_env(&r), "HOME"), None);
            assert_eq!(start_directory(&r), None);
        }

        /// `HOME` and the directory handed to `attach_run` come from one
        /// resolution, so they cannot name different directories.
        #[test]
        fn home_and_the_attach_directory_agree() {
            for cwd in ["", "/workspace", "work", "./work", "a/../b", "/x/../y/./z"] {
                let mut r = request(DefaultEnvCompatibility::DefaultBlock);
                r.env = None;
                r.working_directory = cwd.into();
                assert_eq!(
                    value(&resolved_env(&r), "HOME"),
                    start_directory(&r).as_deref(),
                    "HOME must name the directory the child starts in (cwd {cwd:?})"
                );
            }
        }

        #[test]
        fn a_caller_entry_without_a_value_is_dropped_by_the_merge() {
            let mut r = request(DefaultEnvCompatibility::DefaultBlock);
            r.env = Some(vec!["FEATURE_FLAG".into(), "FOO=bar".into()]);

            // Verbatim: carried through, dropped when `lxc-attach` args build.
            assert!(resolved_env(&r).contains(&"FEATURE_FLAG".to_string()));

            r.inherit_default_env = true;
            let inherited = resolved_env(&r);
            assert!(!inherited.iter().any(|kv| kv.starts_with("FEATURE_FLAG")));
            assert_eq!(value(&inherited, "FOO"), Some("bar"));
        }
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

    fn runner_named(container_id: &str) -> LxcScriptRunner {
        LxcScriptRunner::new(
            &LxcConfig::default(),
            container_id,
            &LifecycleConfig::default(),
        )
    }

    #[test]
    fn a_container_a_live_sandbox_is_using_is_refused_to_the_next_one() {
        let runner = runner_named("mxc-identity-collision-test");

        let held = runner
            .claim_container_name()
            .expect("the first sandbox takes a container no other one is using");
        let refusal = runner
            .claim_container_name()
            .expect_err("a second sandbox on the same container must be refused");

        assert!(
            refusal
                .error_message
                .contains("mxc-identity-collision-test"),
            "the refusal must name the container the caller asked for, got: {}",
            refusal.error_message
        );
        assert!(
            refusal.error_message.contains("containerId"),
            "the refusal must name the field the caller can change, got: {}",
            refusal.error_message
        );

        drop(held);
        runner
            .claim_container_name()
            .expect("the container is free again once the first sandbox is gone");
    }

    #[test]
    fn prepare_refuses_a_container_another_live_sandbox_is_using() {
        let config = LxcConfig {
            distribution: "alpine".to_string(),
            release: "3.23".to_string(),
        };
        let lifecycle = LifecycleConfig::default();
        let first = LxcScriptRunner::new(&config, "mxc-prepare-collision-test", &lifecycle);
        let second = LxcScriptRunner::new(&config, "mxc-prepare-collision-test", &lifecycle);

        let _held = first
            .claim_container_name()
            .expect("the first sandbox takes a container no other one is using");

        let mut logger = Logger::new(Mode::Buffer);
        let refusal = second
            .prepare(&streamable_request(), &mut logger)
            .err()
            .expect("a second sandbox on a live container must be refused");

        assert!(
            refusal.error_message.contains("mxc-prepare-collision-test"),
            "the refusal must name the container the caller asked for, got: {}",
            refusal.error_message
        );

        let log = logger.get_buffer();
        assert!(
            !log.contains("Container name:"),
            "the refusal must land before any container work, or this run stops the \
             live sandbox's container to apply its own network policy"
        );
        assert!(
            !log.contains("Creating LXC container"),
            "the refusal must land before container creation"
        );
    }

    #[test]
    fn concurrent_sandboxes_that_name_no_container_get_different_ones() {
        let runner = runner_named("");

        let first = runner.claim_container_name().expect("a generated name");
        let second = runner.claim_container_name().expect("a generated name");

        assert_ne!(
            first.name(),
            second.name(),
            "two live sandboxes cannot share a container, so the generator must not \
             hand the same name to both"
        );
    }

    #[test]
    fn a_sandbox_that_never_launched_leaves_its_container_free() {
        let runner = LxcScriptRunner::new(
            &LxcConfig {
                distribution: "alpine".to_string(),
                release: "3.23".to_string(),
            },
            "mxc-identity-release-test",
            &LifecycleConfig::default(),
        );
        let request = request_with_proxy_url("******proxy.example.com:8080");
        let mut logger = Logger::new(Mode::Buffer);

        runner
            .prepare(&request, &mut logger)
            .err()
            .expect("a proxy URL carrying a password must not become an lxc-attach argument");

        runner
            .claim_container_name()
            .expect("a refused prepare must not go on holding the container");
    }

    /// The streaming handle owns the prepared sandbox, so this is also what
    /// frees the container for a caller who drops a sandbox without waiting.
    #[test]
    fn a_prepared_sandbox_gives_its_container_back_when_it_drops() {
        let _fake = crate::network_iptables::test_firewall::install();
        let prepared = prepared_with_applied_rules("identity-drop");
        let runner = runner_named(prepared._name_claim.name());

        runner
            .claim_container_name()
            .expect_err("the prepared sandbox is still holding its container");

        drop(prepared);
        runner
            .claim_container_name()
            .expect("a finished sandbox must give its container back");
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
            let reason = LxcScriptRunner::hosts_command_failure(verb, 1, "");

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

    /// A symlinked `/etc/hosts` and an unreadable one differ only in what the
    /// helper says on stderr.
    #[test]
    fn a_failed_hosts_command_carries_the_helpers_own_diagnosis() {
        let reason = LxcScriptRunner::hosts_command_failure(
            "writing",
            4,
            "mxc: refusing to rewrite /etc/hosts: it is a symbolic link\n",
        );

        assert!(
            reason.contains("it is a symbolic link"),
            "the reason must carry what the helper reported; got: {reason:?}"
        );
        assert!(
            reason.contains('4'),
            "the reason must still name the exit code; got: {reason:?}"
        );
        assert_eq!(
            reason.trim_end(),
            reason,
            "the helper's trailing newline must not survive into the reason; got: {reason:?}"
        );
    }

    #[test]
    fn a_failed_hosts_command_distinguishes_the_step_that_failed() {
        let pinning = LxcScriptRunner::hosts_command_failure("writing", 2, "");
        let clearing = LxcScriptRunner::hosts_command_failure("clearing", 2, "");

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

    /// A runner named for the test that uses it, because a container name two
    /// live sandboxes share is refused.
    fn runner_for_guard_tests(tag: &str) -> LxcScriptRunner {
        let config = LxcConfig {
            distribution: "alpine".to_string(),
            release: "3.23".to_string(),
        };
        LxcScriptRunner::new(
            &config,
            &format!("mxc-guard-test-{tag}"),
            &LifecycleConfig::default(),
        )
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
        let runner = runner_for_guard_tests("directional-egress");

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
        let runner = runner_for_guard_tests("runtime-proxy");
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
        assert!(
            response.error_message.contains("no proxy surface")
                && response.error_message.contains("Select a backend")
                && !response.error_message.contains("network.proxy.url"),
            "the refusal must recommend a supported alternative, got: {}",
            response.error_message
        );
    }

    #[test]
    fn a_directly_built_request_with_proxy_credentials_is_refused() {
        let runner = runner_for_guard_tests("credentials-refused");
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
        let runner = runner_for_guard_tests("password-not-echoed");
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
        let runner = runner_for_guard_tests("credential-free");
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
        let runner = runner_for_guard_tests("refusal-ordering");
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

    // `lxc-info -iH` prints one address per line, in whatever order the
    // container acquired them.
    #[test]
    fn an_ipv6_address_alone_is_not_readiness() {
        assert_eq!(
            first_routable_ipv4("fc42:5009:ba4b:5ab0:247d:98ff:fecf:c8b7\n"),
            None,
            "a SLAAC address arrives seconds before the DHCP lease; accepting it \
             starts the workload with no route to an IPv4 destination"
        );
    }

    #[test]
    fn an_ipv4_address_is_readiness() {
        assert_eq!(
            first_routable_ipv4("10.0.3.201\n"),
            Some(Ipv4Addr::new(10, 0, 3, 201))
        );
    }

    #[test]
    fn a_dual_stack_container_is_ready_on_its_ipv4_address() {
        let both = "fc42:5009:ba4b:5ab0:247d:98ff:fecf:c8b7\n10.0.3.201\n";

        assert_eq!(
            first_routable_ipv4(both),
            Some(Ipv4Addr::new(10, 0, 3, 201)),
            "the IPv4 address must be found whatever order lxc-info lists it in"
        );
    }

    #[test]
    fn no_address_is_not_readiness() {
        for empty in ["", "\n", "   \n"] {
            assert_eq!(first_routable_ipv4(empty), None, "input was {empty:?}");
        }
    }

    #[test]
    fn an_unusable_ipv4_address_is_not_readiness() {
        // 169.254/16 is what the container assigns itself when DHCP never answers.
        for unusable in [
            "127.0.0.1\n",
            "0.0.0.0\n",
            "169.254.13.7\n",
            "224.0.0.5\n",
            "239.1.2.3\n",
            "255.255.255.255\n",
        ] {
            assert_eq!(
                first_routable_ipv4(unusable),
                None,
                "{unusable:?} reaches nothing off the container"
            );
        }
    }

    #[test]
    fn a_usable_address_is_still_found_beside_an_unusable_one() {
        assert_eq!(
            first_routable_ipv4("127.0.0.1\n10.0.3.201\n"),
            Some(Ipv4Addr::new(10, 0, 3, 201))
        );
        assert_eq!(
            first_routable_ipv4("224.0.0.5\n255.255.255.255\n10.0.3.201\n"),
            Some(Ipv4Addr::new(10, 0, 3, 201)),
            "an unusable address listed first must not end the wait"
        );
    }

    #[test]
    fn network_readiness_timeout_returns_the_fail_closed_error_response() {
        let runner = runner_for_network_readiness_tests(false);
        let response = fail_network_readiness(&runner, false).response;

        assert!(
            response
                .error_message
                .contains("Container did not receive an IPv4 address within 1s"),
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

    /// A policy whose `except` entry is malformed, so lowering refuses it.
    fn request_with_unlowerable_egress() -> ExecutionRequest {
        use wxc_common::models::{NetworkAction, NetworkCidr, NetworkPeer, NetworkRule};

        let mut request = ExecutionRequest::default();
        request.policy.network_egress = Some(NetworkEgressPolicy {
            default: NetworkAction::Deny,
            allow: vec![NetworkRule {
                to: vec![NetworkPeer {
                    cidr: NetworkCidr {
                        address: "10.0.0.0".parse().expect("literal"),
                        prefix_length: 8,
                    },
                    except: vec![NetworkCidr {
                        address: "10.10.0.0".parse().expect("literal"),
                        prefix_length: 40,
                    }],
                }],
                ports: Vec::new(),
            }],
            deny: Vec::new(),
        });
        request
    }

    #[test]
    fn an_egress_policy_that_cannot_be_lowered_is_refused_before_a_container_exists() {
        let mut logger = Logger::new(Mode::Buffer);

        let response = runner_for_guard_tests("unlowerable-egress")
            .run_internal(&request_with_unlowerable_egress(), &mut logger);

        assert_ne!(
            response.exit_code, 0,
            "input=allow.to=[{{cidr:10.0.0.0/8, except:[10.10.0.0/40]}}]; expected a refusal; output={response:?}"
        );
        assert!(
            response
                .error_message
                .contains("wider than its address family"),
            "expected the lowering's refusal rather than a container failure, got: {response:?}"
        );
        assert!(
            !logger.get_buffer().contains("Creating LXC container"),
            "the refusal must land before the container is created; log={}",
            logger.get_buffer()
        );
    }

    /// A request with a script, so nothing but the checks under test refuses it.
    fn streamable_request() -> ExecutionRequest {
        ExecutionRequest {
            script_code: "echo hello".to_string(),
            ..Default::default()
        }
    }

    #[test]
    fn inherited_stdio_is_refused_rather_than_given_a_pty() {
        let mut logger = Logger::new(Mode::Buffer);

        let refusal = validating_runner()
            .spawn(&streamable_request(), &mut logger, StdioMode::Inherit)
            .err()
            .expect("the library path has no pty to hand a workload");

        assert_eq!(refusal.error_message, LXC_INHERIT_STDIO_UNSUPPORTED);
        assert!(
            !logger.get_buffer().contains("Container name:"),
            "the refusal must land before a container is named"
        );
    }

    #[test]
    fn a_request_the_backend_cannot_honor_is_refused_before_anything_launches() {
        let policy = ContainerPolicy {
            runtime_network_proxy_specified: true,
            ..Default::default()
        };
        let request = ExecutionRequest {
            script_code: "echo hello".to_string(),
            policy,
            ..Default::default()
        };
        let mut logger = Logger::new(Mode::Buffer);

        let refusal = validating_runner()
            .spawn(&request, &mut logger, StdioMode::Pipes)
            .err()
            .expect("a runtime proxy has no loopback the container shares with the host");

        assert_eq!(refusal.error_message, LXC_RUNTIME_PROXY_UNSUPPORTED);
        assert!(
            !logger.get_buffer().contains("Container name:"),
            "validation must run before the container is named"
        );
    }

    #[test]
    fn an_empty_script_is_refused_by_the_shared_checks() {
        let mut logger = Logger::new(Mode::Buffer);

        let refusal = validating_runner()
            .spawn(&ExecutionRequest::default(), &mut logger, StdioMode::Pipes)
            .err()
            .expect("there is nothing to run");

        assert!(
            refusal
                .error_message
                .contains("Script content must not be empty"),
            "expected the shared refusal, got: {refusal:?}"
        );
    }

    #[test]
    fn both_runner_personalities_declare_the_same_network_support() {
        let runner = validating_runner();

        assert_eq!(
            SandboxBackend::network_policy_support(&runner),
            lxc_network_policy_support(),
            "a policy accepted on one path and refused on the other would enforce differently \
             depending on which API the caller reached for"
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
