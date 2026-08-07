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
    ContainerPolicy, ExecutionRequest, LifecycleConfig, LxcConfig, NetworkEnforcementMode,
    ScriptResponse,
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

/// Outcome of reconciling the discovered veth against the policy's enforcement
/// needs.
///
/// Extracted from `run_internal` so the fail-closed invariant — a policy that
/// needs veth-scoped firewall enforcement but has no veth must be refused,
/// never run unenforced — is assertable without a live LXC container.
#[derive(Debug, PartialEq, Eq)]
enum VethReconcile<'a> {
    /// A veth was discovered; scope the firewall rules to it.
    Scope(&'a str),
    /// No veth, and none is required because no firewall enforcement was
    /// requested.
    ProceedUnscoped,
    /// No veth, but firewall enforcement was requested — refuse to start
    /// rather than launch a container with the firewall it asked for silently
    /// absent.
    Refuse,
}

/// What to do with the container when a setup step fails partway through.
///
/// Split out from the action so the policy is assertable without a live
/// container, in the same way [`VethReconcile`] separates the veth decision
/// from acting on it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SetupUndo {
    /// This invocation created the container, or the caller asked for it to be
    /// destroyed on exit.
    Destroy,
    /// The container already existed and this invocation started it. Stopping
    /// restores what we found without discarding a container the caller asked
    /// to preserve.
    Stop,
    /// The container was already running before this invocation touched it, so
    /// it is not ours to shut down.
    Leave,
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

    /// Whether the policy asks for veth-scoped firewall enforcement.
    ///
    /// LXC scopes every iptables hook to the container's veth, so a policy that
    /// uses `Firewall`/`Both` enforcement, or configures a network proxy,
    /// cannot be applied without a veth. Kept as a pure predicate so the
    /// fail-closed decision in [`Self::reconcile_veth`] is assertable off a
    /// live container.
    fn needs_firewall_enforcement(policy: &ContainerPolicy) -> bool {
        matches!(
            policy.network_enforcement_mode,
            NetworkEnforcementMode::Firewall | NetworkEnforcementMode::Both
        ) || policy.network_proxy.is_enabled()
    }

    /// Decide what to do with a discovered veth given the policy's needs.
    ///
    /// This is the fail-closed seam: when firewall enforcement is required but
    /// no veth is available the run is refused, never allowed to proceed with
    /// the firewall silently absent. A present veth is always scoped; a missing
    /// veth is tolerated only when no firewall enforcement was requested (the
    /// Bubblewrap-style host-namespace case handled up the stack).
    fn reconcile_veth(veth: Option<&str>, needs_firewall: bool) -> VethReconcile<'_> {
        match (veth, needs_firewall) {
            (Some(iface), _) => VethReconcile::Scope(iface),
            (None, true) => VethReconcile::Refuse,
            (None, false) => VethReconcile::ProceedUnscoped,
        }
    }

    /// Decide what a failed setup owes the container. See [`SetupUndo`].
    ///
    /// The `container_started` arm is the one that matters: before it existed,
    /// a reused container that this invocation started was left running with
    /// the firewall never applied whenever `destroyOnExit` was false, because
    /// `container_created` is false for a reused container.
    fn setup_undo_action(
        destroy_on_exit: bool,
        container_created: bool,
        container_started: bool,
    ) -> SetupUndo {
        if destroy_on_exit || container_created {
            SetupUndo::Destroy
        } else if container_started {
            SetupUndo::Stop
        } else {
            SetupUndo::Leave
        }
    }

    /// Undo whatever this invocation did to the container after a setup step
    /// failed, without undoing what the user asked to keep.
    fn undo_container_setup(
        container: &LxcContainer,
        destroy_on_exit: bool,
        container_created: bool,
        container_started: bool,
    ) {
        match Self::setup_undo_action(destroy_on_exit, container_created, container_started) {
            SetupUndo::Destroy => {
                let _ = container.destroy();
            }
            SetupUndo::Stop => {
                let _ = container.stop();
            }
            SetupUndo::Leave => {}
        }
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
        // Delegation check (D3): reject any policy path the invoking user cannot
        // access, so the sandbox never gains access the caller lacks. Runs AFTER
        // object normalization so it is evaluated against the already-tightened
        // intents.
        if let Err(msg) = wxc_common::filesystem_access::check_delegation(&request.policy) {
            return ScriptResponse::error(&msg);
        }

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
        // Tracked separately from `container_created`: a container that already
        // existed but was stopped is started by this invocation, and if a later
        // setup step fails we are responsible for putting it back. Without this,
        // `destroyOnExit: false` on a reused container left it running with no
        // firewall applied, because the destroy predicate is false in exactly
        // that case. It is bound where the start happens, so the two failure
        // paths above it pass `false` literally — nothing has been started yet.

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
            Self::undo_container_setup(&container, self.destroy_on_exit, container_created, false);
            return ScriptResponse::error(&format!("Failed to configure filesystem: {}", e));
        }

        // Pin a hostname proxy to the address the host resolved, before the
        // container is started. This is pure host-side DNS with no dependency
        // on the container, and doing it first means an unresolvable or
        // unenforceable proxy is rejected before anything is running — rather
        // than starting a container, discovering the policy cannot be applied,
        // and having to tear it down again.
        //
        // The firewall ACCEPT and the HTTP(S)_PROXY handed to the container
        // must name the same endpoint: if the container re-resolved the
        // hostname itself it could pick a different address under round-robin
        // or split-horizon DNS and be dropped by its own policy. Pinning also
        // means the container never needs a resolver, so DNS stays closed under
        // deny-all-except-proxy.
        let mut effective_policy = request.policy.clone();
        match NetworkIptablesManager::pin_proxy_to_resolved_ip(
            &effective_policy.network_proxy,
            logger,
        ) {
            Ok(pinned) => effective_policy.network_proxy = pinned,
            Err(e) => {
                Self::undo_container_setup(
                    &container,
                    self.destroy_on_exit,
                    container_created,
                    false,
                );
                return ScriptResponse::error(&format!("Network policy error: {}", e));
            }
        }

        // Ensure the container is running so that the veth interface exists.
        //
        // The ownership bit is the value of this expression rather than an
        // assignment inside the branch. Dropping an assignment would compile and
        // pass every test while silently reintroducing the leak this tracking
        // exists to prevent; dropping an arm of an if-expression will not
        // compile.
        let container_started = if !container.is_running() {
            let _ = writeln!(logger, "Starting LXC container...");
            if let Err(e) = container.start() {
                Self::undo_container_setup(
                    &container,
                    self.destroy_on_exit,
                    container_created,
                    false,
                );
                return ScriptResponse::error(&format!("Failed to start container: {}", e));
            }
            let _ = writeln!(logger, "Container started successfully.");
            true
        } else {
            let _ = writeln!(logger, "Container already running.");
            false
        };

        // Wait for network only when the config uses network features
        // (firewall rules, allowed/blocked hosts, or proxy enforcement).
        let needs_network = matches!(
            request.policy.network_enforcement_mode,
            NetworkEnforcementMode::Firewall | NetworkEnforcementMode::Both
        ) || !request.policy.allowed_hosts.is_empty()
            || !request.policy.blocked_hosts.is_empty()
            || request.policy.network_proxy.is_enabled();

        if needs_network {
            Self::wait_for_network(&container_name, Duration::from_secs(10), logger);
        }

        // Configure network rules
        let mut fw_manager = NetworkIptablesManager::new(&container_name);

        // Discover the container's veth interface for scoped rules.
        //
        // LXC enforcement is veth-scoped: every iptables hook matches
        // `-i <veth>`, so without the veth the policy cannot be scoped to this
        // container. `apply_firewall_rules` no longer rejects a missing veth
        // (Bubblewrap shares that manager and legitimately has none), so the
        // fail-closed requirement lives here, where LXC actually needs it: when
        // the policy uses firewall enforcement and the veth cannot be
        // discovered, refuse to start rather than launch an unenforced
        // container.
        let needs_firewall = Self::needs_firewall_enforcement(&effective_policy);
        let discovered_veth = NetworkIptablesManager::discover_veth_interface(&container_name);
        match Self::reconcile_veth(discovered_veth.as_deref(), needs_firewall) {
            VethReconcile::Scope(veth) => {
                let _ = writeln!(logger, "Discovered veth interface: {}", veth);
                fw_manager.set_veth_interface(veth);
                if self.destroy_on_exit {
                    // Tell the watchdog about the veth so signal-time cleanup
                    // can also remove the FORWARD hook, not just the chain.
                    signal_cleanup::set_active_veth(veth);
                }
            }
            VethReconcile::Refuse => {
                Self::undo_container_setup(
                    &container,
                    self.destroy_on_exit,
                    container_created,
                    container_started,
                );
                return ScriptResponse::error(
                    "LXC: could not discover the container's veth interface; network policy \
                     enforcement is veth-scoped and cannot be applied. Refusing to start with \
                     an unenforceable network policy.",
                );
            }
            VethReconcile::ProceedUnscoped => {
                let _ = writeln!(
                    logger,
                    "No veth interface discovered; network policy does not require firewall \
                     enforcement, continuing."
                );
            }
        }

        match fw_manager.apply_firewall_rules(&effective_policy, logger) {
            Ok(true) => {}
            Ok(false) => {
                Self::undo_container_setup(
                    &container,
                    self.destroy_on_exit,
                    container_created,
                    container_started,
                );
                return ScriptResponse::error("Failed to apply network firewall rules.");
            }
            Err(e) => {
                Self::undo_container_setup(
                    &container,
                    self.destroy_on_exit,
                    container_created,
                    container_started,
                );
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
        let mut exec_env = request.env.clone();
        let force_clear_env =
            wxc_common::proxy_env::apply_proxy_env(&mut exec_env, &effective_policy.network_proxy);
        let result = container.attach_run(
            &request.script_code,
            &request.working_directory,
            &exec_env,
            force_clear_env,
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
    use wxc_common::models::ProxyConfig;

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
    fn a_container_this_run_started_is_stopped_when_setup_fails_and_it_must_be_preserved() {
        // The defect: `container_created` is false for a reused container, so
        // with destroyOnExit false the old predicate did nothing and left a
        // container this run started running with no firewall applied.
        assert_eq!(
            LxcScriptRunner::setup_undo_action(false, false, true),
            SetupUndo::Stop,
            "a preserved container that this run started must be stopped, not left running"
        );
    }

    #[test]
    fn a_container_this_run_created_is_destroyed_however_it_was_started() {
        for started in [false, true] {
            assert_eq!(
                LxcScriptRunner::setup_undo_action(false, true, started),
                SetupUndo::Destroy,
                "a container this run created is ours to remove (started={started})"
            );
        }
    }

    #[test]
    fn destroy_on_exit_destroys_regardless_of_who_created_or_started_it() {
        for created in [false, true] {
            for started in [false, true] {
                assert_eq!(
                    LxcScriptRunner::setup_undo_action(true, created, started),
                    SetupUndo::Destroy,
                    "destroyOnExit must win (created={created}, started={started})"
                );
            }
        }
    }

    #[test]
    fn a_container_that_was_already_running_is_left_alone() {
        assert_eq!(
            LxcScriptRunner::setup_undo_action(false, false, false),
            SetupUndo::Leave,
            "a container we neither created nor started is not ours to shut down"
        );
    }

    #[test]
    fn needs_firewall_enforcement_tracks_mode_and_proxy() {
        let mut policy = ContainerPolicy::default();

        // Default is Capabilities enforcement with no proxy, so no veth-scoped
        // firewall is needed.
        assert!(!LxcScriptRunner::needs_firewall_enforcement(&policy));

        policy.network_enforcement_mode = NetworkEnforcementMode::Firewall;
        assert!(LxcScriptRunner::needs_firewall_enforcement(&policy));

        policy.network_enforcement_mode = NetworkEnforcementMode::Both;
        assert!(LxcScriptRunner::needs_firewall_enforcement(&policy));

        // A configured proxy forces firewall enforcement even under
        // Capabilities mode, because deny-all-except-proxy is enforced with the
        // same veth-scoped chain.
        policy.network_enforcement_mode = NetworkEnforcementMode::Capabilities;
        policy.network_proxy = ProxyConfig {
            address: None,
            builtin_test_server: true,
        };
        assert!(LxcScriptRunner::needs_firewall_enforcement(&policy));
    }

    #[test]
    fn missing_veth_with_firewall_policy_is_refused() {
        // The security invariant restored here: firewall enforcement requested
        // but no veth available must refuse to start, never proceed with the
        // firewall silently absent. Previously asserted by
        // `firewall_mode_without_veth_fails_fast` against the old (regressive)
        // check in `apply_firewall_rules`; that check was removed because it
        // also broke Bubblewrap, and the invariant now lives here in the LXC
        // runner's own veth reconciliation.
        assert_eq!(
            LxcScriptRunner::reconcile_veth(None, true),
            VethReconcile::Refuse
        );
    }

    #[test]
    fn missing_veth_without_firewall_proceeds_unscoped() {
        // No firewall enforcement requested, so a missing veth is tolerated
        // rather than fatal.
        assert_eq!(
            LxcScriptRunner::reconcile_veth(None, false),
            VethReconcile::ProceedUnscoped
        );
    }

    #[test]
    fn present_veth_is_scoped_regardless_of_policy() {
        assert_eq!(
            LxcScriptRunner::reconcile_veth(Some("veth1234"), true),
            VethReconcile::Scope("veth1234")
        );
        assert_eq!(
            LxcScriptRunner::reconcile_veth(Some("veth1234"), false),
            VethReconcile::Scope("veth1234")
        );
    }
}
