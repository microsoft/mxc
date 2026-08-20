// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! `LxcScriptRunner` — executes scripts inside LXC containers.
//!
//! Implements the `ScriptRunner` trait for LXC-based containment on Linux.

use std::fmt::Write;
use std::thread;
use std::time::{Duration, Instant};

use wxc_common::logger::Logger;
use wxc_common::models::{ExecutionRequest, LifecycleConfig, LxcConfig, ScriptResponse};
use wxc_common::script_runner::ScriptRunner;
use wxc_common::validator::{validate_network_policy_support, NetworkPolicySupport};

use crate::filesystem_mounts;
use crate::lxc_bindings::LxcContainer;
use crate::network_ingress::IngressManager;
use crate::network_iptables::NetworkIptablesManager;
use crate::signal_cleanup;

/// Comment marker on every `/etc/hosts` line this runner writes, so a later
/// run can strip its own previous entries without disturbing the
/// distribution's.
const HOSTS_PIN_MARKER: &str = "#mxc-proxy-pin";

/// Ceiling for the two `/etc/hosts` rewrites, which are a handful of shell
/// builtins and must never inherit the script's own timeout budget.
const HOSTS_COMMAND_TIMEOUT: Duration = Duration::from_secs(30);

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
        // Refuse a credential-bearing proxy URL here as well as at parse time.
        // The parser guard only covers requests it built; `ExecutionRequest`
        // and `ProxyAddress::from_url` are public, so a caller can hand this
        // runner a policy the parser never saw. Below, `apply_proxy_env` sets
        // HTTP(S)_PROXY to `to_url()`, which returns the original URL verbatim,
        // and `build_attach_args_with_env_control` turns every environment
        // entry into a `--set-var=KEY=VALUE` argument of the `lxc-attach`
        // process this backend spawns (lxc_bindings.rs). A process's argv is
        // readable through /proc/<pid>/cmdline by any local user for the
        // lifetime of the command. The check sits ahead of container creation
        // and firewall programming so a rejected request leaves no state
        // behind.
        if let Some(url) = request
            .policy
            .network_proxy
            .address
            .as_ref()
            .map(|address| address.to_url())
        {
            if wxc_common::proxy_env::proxy_url_has_credentials(&url) {
                // Built from the redacted form so the rejection cannot become
                // the leak it is rejecting.
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

        // Wait for network only when the policy has something for the firewall
        // to carry, or when the container must reach a proxy. Both questions
        // are `requires_firewall`.
        let needs_network = request.policy.requires_firewall();

        if needs_network {
            Self::wait_for_network(&container_name, Duration::from_secs(10), logger);
        }

        // Configure network rules
        let mut fw_manager = NetworkIptablesManager::new(&container_name);
        fw_manager.set_preserve_policy(!self.cleanup_policy);

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

        // Configure inbound (ingress) network rules inside the container's own
        // netns. This is a separate, orthogonal chain from the egress rules
        // above: it enforces `allowLocalNetwork` (inbound default-deny) via the
        // container's own iptables INPUT chain, reached with `nsenter`.
        //
        // A policy with anything for the firewall to carry means the caller is
        // owed the inbound deny chain, whichever schema stated it. LXC enforces
        // it inside the container's own netns, so it is useless without the
        // init PID that lets us enter that netns — and the ingress manager
        // cannot even be constructed without one.
        let use_firewall = request.policy.requires_firewall();

        // Kept in scope for post-execution cleanup; `None` when there is no
        // netns PID and no firewall was requested (nothing to enforce).
        let mut ingress_manager: Option<IngressManager> = None;

        match container.init_pid() {
            Some(pid) => {
                let _ = writeln!(logger, "Container init PID: {}", pid);
                if self.destroy_on_exit {
                    // Tell the watchdog about the netns PID so signal-time
                    // cleanup can remove the container's INPUT rules before it's
                    // destroyed.
                    signal_cleanup::set_active_pid(pid);
                }
                let mut mgr = IngressManager::new(&container_name, pid);
                match mgr.apply_firewall_rules(&request.policy, logger) {
                    Ok(true) => {}
                    Ok(false) => {
                        if self.destroy_on_exit || container_created {
                            let _ = container.destroy();
                        }
                        return ScriptResponse::error(
                            "Failed to apply inbound network firewall rules.",
                        );
                    }
                    Err(e) => {
                        if self.destroy_on_exit || container_created {
                            let _ = container.destroy();
                        }
                        return ScriptResponse::error(&format!(
                            "Inbound network policy error: {}",
                            e
                        ));
                    }
                }
                // Every non-success arm above returns, so the apply call
                // succeeded. Only now may the policy be marked for
                // preservation: the flag also suppresses `Drop`, and a partial
                // chain from a failed install must still be torn down. Success
                // does not imply a chain exists — a non-firewall enforcement
                // mode succeeds without installing one — but in that case no
                // ownership flag is set and `Drop` has nothing to do either way.
                mgr.set_preserve_policy(!self.cleanup_policy);
                ingress_manager = Some(mgr);
            }
            None if use_firewall => {
                // The run asked for a firewall but we could not find the
                // container netns to enforce it in. There is no legitimate
                // ingress-without-a-netns case: enforcing inbound requires
                // entering the container's namespace, so running anyway would
                // silently disable the requested inbound deny (a fail-open).
                // Abort instead. This guard is specific to the LXC ingress
                // path, which addresses its namespace by init PID; other
                // backends reach their firewall handling through their own
                // runners and never construct an `IngressManager`.
                if self.destroy_on_exit || container_created {
                    let _ = container.destroy();
                }
                return ScriptResponse::error(
                    "Failed to discover the container init PID; cannot enter the container \
                     network namespace to enforce the requested inbound firewall. Aborting \
                     rather than running with inbound enforcement silently disabled.",
                );
            }
            None => {
                // No firewall requested and no netns PID: nothing to enforce
                // inbound, so no ingress chain is installed.
            }
        }

        let mut pinned = false;

        // A proxied chain opens no port 53, so without this the container has
        // no resolver to find its proxy with.
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

                // `attach_run` streams the child's output and returns empty
                // strings, so the exit code is the whole report.
                Ok((code, _, _)) => Some(Self::hosts_command_failure("writing", code)),
                Err(e) => Some(e.to_string()),
            };
            if let Some(reason) = pin_error {
                if self.destroy_on_exit || container_created {
                    let _ = container.destroy();
                } else {
                    // A reused container this run will not destroy would
                    // otherwise be left running with a policy it cannot use.
                    let _ = container.stop();
                }
                return ScriptResponse::error(&format!(
                    "Failed to pin the network proxy host inside the container: {}. \
                     The proxy would be unreachable, so the script was not run.",
                    reason
                ));
            }
            pinned = true;
        } else if !container_created {
            // A run that pins rewrites /etc/hosts from a filtered copy, so it
            // disposes of an earlier pin on its way past.  A run that pins
            // nothing has no such side effect, and a container this run did not
            // create can still be carrying one -- left by a run interrupted
            // after pinning, or by a removal that failed and only warned.  Left
            // in place it keeps resolving a hostname to an address that only
            // some earlier policy authorized.
            let unpin = Self::build_hosts_unpin_command();
            let stale_pin_error =
                match container.attach_run(&unpin, "/", &[], true, Some(HOSTS_COMMAND_TIMEOUT)) {
                    Ok((0, _, _)) => None,
                    Ok((code, _, _)) => Some(Self::hosts_command_failure("clearing", code)),
                    Err(e) => Some(e.to_string()),
                };

            // Unlike the post-run removal, this one runs *before* the script, so
            // a failure still changes what the script would resolve. Refuse the
            // run rather than execute against a mapping this policy never made.
            if let Some(reason) = stale_pin_error {
                if self.destroy_on_exit {
                    let _ = container.destroy();
                } else {
                    let _ = container.stop();
                }
                return ScriptResponse::error(&format!(
                    "Failed to clear a stale network proxy pin from the container's \
                     /etc/hosts: {}. The script was not run, because it could have resolved \
                     the pinned hostname to an address this policy did not authorize.",
                    reason
                ));
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
        // Scrub every inherited proxy variable and, when the policy carries a
        // proxy, point HTTP(S)_PROXY at it.
        wxc_common::proxy_env::apply_proxy_env(&mut exec_env, &request.policy.network_proxy);

        // Always clear, including for an empty env: otherwise `lxc-attach`
        // falls back to keep-env mode and inherits the MXC host process
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

        // The pin names an address only this run's chain authorized, so it
        // must not outlive that chain.
        if pinned && self.cleanup_policy {
            let unpin = Self::build_hosts_unpin_command();
            let unpin_error =
                match container.attach_run(&unpin, "/", &[], true, Some(HOSTS_COMMAND_TIMEOUT)) {
                    Ok((0, _, _)) => None,
                    Ok((code, _, _)) => Some(Self::hosts_command_failure("clearing", code)),
                    Err(e) => Some(e.to_string()),
                };

            // The script has already run, so a failure here cannot change its
            // result and must not replace it.
            if let Some(reason) = unpin_error {
                let _ = writeln!(
                    logger,
                    "Warning: failed to clear the proxy host pin: {}",
                    reason
                );
            }
        }

        // Cleanup: remove network rules
        if fw_manager.rules_applied() && self.cleanup_policy {
            let _ = fw_manager.remove_firewall_rules(logger);
        }
        if let Some(mgr) = &mut ingress_manager {
            if mgr.rules_applied() && self.cleanup_policy {
                let _ = mgr.remove_firewall_rules(logger);
            }
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

    /// Build the shell command that installs `hosts_line` into the
    /// container's `/etc/hosts`.
    ///
    /// The first match wins in a hosts file, so an entry left by an earlier
    /// run on a container reused across runs (`destroy_on_exit = false`) would
    /// shadow the pin this run authorized. Marking each written line is what
    /// lets a later run recognize its own without disturbing the ones the
    /// distribution shipped.
    ///
    /// LXC may bind-mount `/etc/hosts`, so the file is rewritten in place:
    /// replacing the inode would leave the container reading the old one. The
    /// toolset is held to `grep` and `printf` because the image may be BusyBox
    /// rather than coreutils.
    ///
    /// The kept lines are staged in a shell variable because a scratch file
    /// has a name in the container's own filesystem and this command runs
    /// privileged through `lxc-attach`. A previous workload on a reused
    /// container can pre-create any predictable name as a symlink, and `>`
    /// follows symlinks, so staging in a file aims a privileged truncating
    /// write at whatever the link names -- another container file, or a host
    /// path exposed through a writable bind mount. A variable has no name to
    /// hijack.
    ///
    /// Staging must also finish before the redirect opens `/etc/hosts`,
    /// because `>` truncates on open. Past that point nothing reads the
    /// filesystem again: what remains works from text already in memory, so
    /// no read failure can strand a file that has already been emptied.
    ///
    /// Single-quoting `hosts_line` is safe by construction: `ProxyHostPin`
    /// builds it from a parsed [`std::net::IpAddr`] and a validated
    /// hostname, neither of which can carry a quote or a newline. The one
    /// space it does contain is the hosts-file separator, and single quotes
    /// render that inert.
    fn build_hosts_pin_command(hosts_line: &str) -> String {
        // `$(...)` strips trailing newlines, so the kept text is re-emitted
        // with an explicit one and the guard keeps an empty result from
        // becoming a blank first line. The group's exit status is the final
        // printf's, so a grep that matches nothing and exits 1 does not fail
        // the command.
        format!(
            "{}{{ if [ -n \"$kept\" ]; then printf '%s\\n' \"$kept\"; fi; \
             printf '%s {marker}\\n' '{hosts_line}'; }} > /etc/hosts",
            Self::hosts_read_prologue(),
            marker = HOSTS_PIN_MARKER,
            hosts_line = hosts_line
        )
    }

    /// Read the existing `/etc/hosts` into `$kept`, or abort before anything
    /// opens the file for writing.
    ///
    /// `> /etc/hosts` truncates the moment it is opened, so every reason the
    /// read could fail has to be settled before that point. Were the status
    /// left unexamined, the failure would run in the worst possible
    /// direction: `$kept` would be empty whether `grep` is absent,
    /// `/etc/hosts` is unreadable, or the binary is killed, and the closing
    /// `printf` would still exit 0 -- a successful pin reported over a hosts
    /// file emptied of every entry the image shipped.
    ///
    /// Only 0 (lines kept) and 1 (nothing kept) are outcomes rather than
    /// failures. Status 1 is legitimate and common: an empty file, or a re-pin
    /// where every existing line carries the marker. Anything above 1 is a
    /// failed read, which also catches the `127` a missing `grep` produces. A
    /// missing file is separated out ahead of the read because `grep` reports
    /// both "absent" and "unreadable" as status 2, and an image that ships no
    /// `/etc/hosts` has no content to protect.
    ///
    /// Two gaps survive this guard, and neither is closable while the command
    /// is restricted to `grep` and `printf` for BusyBox:
    ///
    /// * A successful read still loses NUL bytes, because a shell variable
    ///   cannot hold them. A hosts file containing one is rewritten truncated
    ///   at that byte with status 0, and no check here observes it. A NUL in
    ///   `/etc/hosts` is malformed to begin with, and the alternatives -- a
    ///   scratch file, `sed`, `awk` -- each cost either a filesystem name an
    ///   attacker can hijack or a tool BusyBox may not ship.
    ///
    /// * A symlink swapped in between the `-h` test and the redirect is still
    ///   followed. Closing that race needs an open-once-and-rewrite primitive
    ///   -- `openat` with `O_NOFOLLOW` inside the container's mount namespace
    ///   -- which is a Rust-side change rather than a shell one. The `-h` test
    ///   covers the unraced shape: a workload reused across runs can simply
    ///   leave `/etc/hosts` as a symlink. A dangling one is the worst of
    ///   those, because it fails `-e` as well, and a redirect onto a dangling
    ///   link creates the link's target -- a write to an attacker-named path,
    ///   which on a writable host bind mount lands outside the container.
    fn hosts_read_prologue() -> String {
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

    /// Strip every pin this runner has ever written from `/etc/hosts`.
    ///
    /// Only a run that pins something removes the previous pin on its way
    /// past, so a run that pins nothing needs its own removal. Left in place
    /// on a container kept alive across runs, a stale pin outlives the policy
    /// that authorized it: the new policy resolves the hostname fresh to build
    /// its rules, so a deny would be written against one address while the
    /// container still reaches the other.
    fn build_hosts_unpin_command() -> String {
        format!(
            "{}{{ if [ -n \"$kept\" ]; then printf '%s\\n' \"$kept\"; fi; }} > /etc/hosts",
            Self::hosts_read_prologue()
        )
    }

    /// Why a `/etc/hosts` command that ran to completion is being treated as a
    /// failure, given the verb for what it was doing and the code it exited
    /// with.
    ///
    /// The exit code is the entire report, and that is a property of how these
    /// commands are run rather than a choice about brevity. `attach_run`
    /// streams the child's output to the caller as it arrives and hands back
    /// empty strings for both streams, so a reason that appended the returned
    /// stderr would read `exited with 1: ` every single time -- a colon
    /// offering an explanation, followed by nothing. Taking only the code
    /// leaves the message true, and leaves the actual diagnostics where the
    /// child already wrote them.
    fn hosts_command_failure(verb: &str, exit_code: i32) -> String {
        format!("{} /etc/hosts exited with {}", verb, exit_code)
    }
}

/// The 0.8 network-policy surface the LXC backend promises to honor.
///
/// The four bits are not independently selectable. `validate_network_policy_support`
/// treats the directional posture as a unit: the parser fills in an ingress
/// section for every 0.8 config, and both the ingress and host-loopback checks
/// fire on `directional_posture_supplied`, which a stated `egress` alone sets.
/// Claiming only the two egress bits therefore rejects every egress-only 0.8
/// config — the directional bits have to be claimed together or not at all.
///
/// Claiming the ingress bits is honest because a bit promises to *handle* the
/// field, not to accept every value. LXC serves `deny` for both ingress
/// controls with its existing default-deny inbound chain, and refuses `allow`
/// with a not-yet-implemented error rather than ignoring it — see
/// `IngressManager::permissive_inbound_field` and AB#63505947.
///
/// `RUNTIME_PROXY` and `PROXY_PEER_IDENTITY` stay unclaimed, so a config using
/// them is still rejected up front rather than half-enforced.
fn lxc_network_policy_support() -> NetworkPolicySupport {
    NetworkPolicySupport::EGRESS_DEFAULT
        | NetworkPolicySupport::EGRESS_RULES
        | NetworkPolicySupport::INGRESS_DEFAULT
        | NetworkPolicySupport::HOST_LOOPBACK
}

impl ScriptRunner for LxcScriptRunner {
    fn validate_runner(&self, request: &ExecutionRequest) -> Result<(), ScriptResponse> {
        validate_network_policy_support(request, lxc_network_policy_support())?;
        Ok(())
    }

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

    // The pin is worthless if the mapping it was built from is not the one
    // that lands in the file.
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

    // A container reused across runs would otherwise accumulate entries, and
    // the first match in a hosts file wins -- so a stale line would shadow the
    // pin this run just authorized.
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
        // `attach_run` streams the child's output live and returns empty
        // strings for both streams, so the earlier form of this message
        // appended an empty stderr and always read "exited with 1: " -- a
        // colon offering an explanation, with nothing after it. Both verbs are
        // checked because the pin and unpin paths build this independently.
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
        // Pinning and unpinning fail for different reasons and are fixed
        // differently, so a message that named neither would send whoever
        // reads it to the wrong half of the path.
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
        // Banning `printf` outright would fail here: re-emitting the *kept*
        // lines needs one, on a command that writes no marked line. The
        // marker count states the invariant directly -- the marker's one
        // appearance is inside the filter, so no marked line can be written.
        assert_eq!(
            command.matches(HOSTS_PIN_MARKER).count(),
            1,
            "the marker should appear only in the filter; got: {command}"
        );
    }

    #[test]
    fn the_hosts_unpin_command_rewrites_the_file_in_place_rather_than_replacing_it() {
        // Same bind-mount reasoning as the pin: replacing the inode would leave
        // the container still reading the file that carries the stale pin.
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

    // LXC may bind-mount /etc/hosts. Replacing the inode with `mv` would leave
    // the container reading the file it had before.
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

    // Everything the pin needs must exist in a minimal image; a container
    // built on BusyBox has no coreutils to fall back on.
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

    // `/tmp` is the container's, and this command runs privileged through
    // `lxc-attach`. On a container reused across runs a previous workload can
    // pre-create any predictable name there as a symlink, and `>` follows
    // symlinks -- so a scratch file would let it aim a privileged truncating
    // write at another container file or at a host path exposed through a
    // writable bind mount. Neither command may stage anything in a directory
    // the container can write.
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

    // Staging in a variable is only an improvement if the content is complete
    // before the target is truncated. `>` truncates as the redirect opens, so
    // any command that still had to *produce* content after that point would
    // leave the container with an empty /etc/hosts if it failed.
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

    // The parser rejects a credential-bearing proxy URL, but `ExecutionRequest`
    // and `ProxyAddress::from_url` are public: a caller can build a request the
    // parser never saw and hand it straight to this runner.  These tests take
    // that path deliberately -- no parser anywhere in them -- because a guard
    // that only exists on the parse path does not protect the process spawn.
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

    /// What the 0.8 parser produces for a config stating only `network.egress`:
    /// the egress section as written, plus an ingress section filled in from
    /// its defaults.
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

    // The declaration cannot be trimmed to the two egress bits. The parser
    // fills in an ingress section for every 0.8 config, and the ingress and
    // host-loopback checks fire on the directional posture that a stated
    // `egress` alone supplies -- so the narrower claim rejects the very config
    // above. This pins that, and fails if the declaration is ever narrowed.
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

    // The rejection is built from the redacted URL so the guard cannot become
    // the leak it exists to prevent -- the message travels to logs and to the
    // caller.
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

    // Anti-vacuity: without this, a guard that refused every proxy would pass
    // both tests above while breaking every legitimate proxy configuration.
    // The run cannot succeed here (there is no live container), so the
    // assertion is that it does not fail *for this reason*.
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

    // The guard runs ahead of container creation and firewall programming, so a
    // rejected request leaves nothing to clean up.  A container name in the log
    // would mean the runner had already started announcing work it must not do.
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
}

/// The generated hosts commands, executed rather than pattern-matched.
///
/// Every hosts test in `tests` above asserts on the command *string*. No
/// string assertion can separate a command that preserves `/etc/hosts` from
/// one that empties it -- both contain `> /etc/hosts`, and the truncation
/// defect these tests exist to pin was invisible to all six of them. Running
/// the command under a real `/bin/sh` is what makes the difference
/// observable.
#[cfg(all(test, unix))]
mod hosts_command_execution {
    use super::*;
    use std::path::{Path, PathBuf};

    /// What a container image ships before anything pins a proxy.
    const ORIGINAL: &str = "127.0.0.1 localhost\n::1 ip6-localhost\n10.0.0.9 build.internal\n";

    const PIN_LINE: &str = "10.0.0.5 proxy.example.com";

    /// A private directory that removes itself, so a failing test cannot leave
    /// a hosts fixture behind for the next run to find.
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

        /// A `PATH` carrying a `grep` that fails with `status`, so the read
        /// can be broken without breaking the shell around it: `printf` and
        /// `[` are builtins and survive the override.
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

        /// A `PATH` with no `grep` on it at all, which is how a BusyBox image
        /// missing the applet fails: the shell cannot find the binary and
        /// reports 127.
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

    /// Point a generated command at a scratch file, so what runs is the
    /// generated text with only the path substituted. That the real target is
    /// `/etc/hosts` is not left unpinned by the substitution; the string tests
    /// above pin it.
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

    // The first match in a hosts file wins, so a pin left over from a previous
    // run on a reused container would shadow the one this run authorized.
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

    // The defect this module was written for. `> /etc/hosts` truncates the
    // instant it is opened, so a read that failed has to stop the command
    // before the redirect -- not merely produce nothing to write back.
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

    // A missing `grep` is status 127, not 2, and is the likelier failure on a
    // stripped image -- the same class, reached by a different route.
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

    // Unpinning writes back only what it read, so a failed read there empties
    // the file outright rather than reducing it to one line.
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

    // Status 1 means grep selected nothing, which is an outcome and not a
    // failure: an empty file, or a re-pin where every line carried the marker.
    // Treating it as an error would make the guard reject the ordinary case.
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

    // An image that ships no hosts file has no content to protect, and grep
    // cannot tell "absent" from "unreadable" -- both are status 2. The
    // existence check is what keeps the guard from refusing to pin here.
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
    // A dangling symlink was the worst shape the guard did not cover: `-e` is
    // false, so no read happened, and the redirect then *created* the target.
    // On a writable host bind mount that is a write outside the container, at
    // a path the workload chose.
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

    // The non-dangling case is the same write to somewhere the workload chose,
    // it just does not announce itself by leaving a broken link behind.
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

    // Unpinning takes the same prologue, so it has to refuse on the same terms
    // -- and it is the more destructive of the two, since it writes back only
    // what it read.
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

    // The refusal has to be legible in the container's stderr, or an operator
    // sees only a non-zero exit from a destroyed container.
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
