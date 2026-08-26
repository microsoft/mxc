// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! `BubblewrapScriptRunner` — executes scripts inside a Bubblewrap
//! namespace sandbox via the `bwrap` CLI.
//!
//! Bubblewrap uses Linux user namespaces to create an unprivileged sandbox.
//! The runner translates `ExecutionRequest` policy fields into `bwrap` CLI
//! arguments via [`crate::bwrap_command::build_args`], then spawns `bwrap`
//! with stdout/stderr capture and optional timeout enforcement.
//!
//! For per-host network filtering (`allowedHosts`/`blockedHosts`) the runner
//! supports two paths:
//! - **Cooperative env-var proxy** (default, no privilege required): when
//!   `network.proxy` is configured the runner launches an unprivileged HTTP
//!   proxy via [`wxc_common::unix_proxy_coordinator::UnixProxyCoordinator`]
//!   and the command builder injects `HTTP_PROXY` / `HTTPS_PROXY` /
//!   `NO_PROXY` env vars into the sandbox.
//! - **iptables firewall** (requires `CAP_NET_ADMIN` / root): when
//!   `network.enforcementMode` is `firewall` or `both`, the runner reuses
//!   [`lxc_common::network_iptables::NetworkIptablesManager`] from the LXC
//!   backend.
//!
//! When only `defaultPolicy: "block"` is set (no host lists and no proxy),
//! the runner uses `--unshare-net` for zero-overhead full isolation
//! without root.

use std::collections::HashSet;
use std::fmt::Write as FmtWrite;
use std::os::unix::process::CommandExt;
use std::path::{Component, Path, PathBuf};
use std::process::{Child, ChildStdin, Command, Stdio};
use std::time::Duration;

use lxc_common::network_iptables::NetworkIptablesManager;
use wxc_common::interruptible_reader::{wrap_pipe, InterruptibleReader, ReadCanceller};
use wxc_common::logger::Logger;
use wxc_common::models::{ExecutionRequest, ScriptResponse};
use wxc_common::sandbox_process::{
    boxed_closer, cancel_and_join_discard, group_kill, spawn_discard, take_boxed_read,
    take_boxed_write, wait_with_timeout, SandboxBackend, SandboxProcess, StdioMode, StreamCloser,
    WaitError,
};
use wxc_common::unix_proxy_coordinator::UnixProxyCoordinator;
use wxc_common::validator::{
    validate_common, validate_network_policy_support, NetworkPolicySupport,
};

use crate::{
    bwrap_command::{self, ResolvedNetworkMode},
    bwrap_version, network_rules, proxy_network,
};

/// Bubblewrap sandbox runner. Uses only shared `ContainerPolicy` fields —
/// no backend-specific config struct required.
#[derive(Default)]
pub struct BubblewrapScriptRunner;

impl BubblewrapScriptRunner {
    pub fn new() -> Self {
        Self
    }
}

impl SandboxBackend for BubblewrapScriptRunner {
    /// Bubblewrap programs the directional 0.8 posture into iptables chains in
    /// the sandbox's own network namespace, so it enforces the outbound default,
    /// the allow/deny rules, and both inbound fields.
    ///
    /// `INGRESS_DEFAULT` and `HOST_LOOPBACK` declare that the backend
    /// *understands* those fields, not that it honors both of their values:
    /// only the deny posture is reachable, and the allow posture is refused by
    /// `bwrap_command::directional_network_rejection` below. Declaring them
    /// without that refusal would be a fail-open, so the two belong together.
    ///
    /// `RUNTIME_PROXY` is declared because the parser normalizes
    /// `runtimeConfig.networkProxy` into the same `policy.network_proxy` the
    /// legacy `network.proxy` field feeds, pinned to loopback, and only under
    /// the `egress.default='deny'` with no direct rules posture. That is
    /// exactly `ResolvedNetworkMode::ProxyOnly`, which this backend already
    /// enforces via the proxy's own private-namespace egress chain, so the 0.8
    /// spelling reaches the identical enforcement as the 0.7 one.
    ///
    /// `PROXY_PEER_IDENTITY` stays undeclared: it is a ProcessContainer concept
    /// with no Bubblewrap equivalent, so shared validation refuses it here.
    fn network_policy_support(&self) -> NetworkPolicySupport {
        NetworkPolicySupport::EGRESS_DEFAULT
            | NetworkPolicySupport::EGRESS_RULES
            | NetworkPolicySupport::INGRESS_DEFAULT
            | NetworkPolicySupport::HOST_LOOPBACK
            | NetworkPolicySupport::RUNTIME_PROXY
    }

    fn validate(&self, request: &ExecutionRequest) -> Result<(), ScriptResponse> {
        self.validate_prepared(request).map(|_| ())
    }

    fn spawn(
        &mut self,
        request: &ExecutionRequest,
        logger: &mut Logger,
        stdio: StdioMode,
    ) -> Result<Box<dyn SandboxProcess>, ScriptResponse> {
        validate_common(request)?;
        // Keep the plan validation derived so the firewall path installs
        // exactly what was accepted instead of deriving it again.
        let egress_plan = self.validate_prepared(request)?;
        // Object-based FS-policy normalization (D6): tighten aliases of the same
        // host object to the strictest intent (deny > ro > rw). Done here, close
        // to mount — config_parser stays string-only and the TOCTOU window
        // between check and mount is minimized. Only clone the request when an
        // aliasing conflict actually needs tightening (the common case is none);
        // an unresolvable path with deniedPaths present fails closed.
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
        // Delegation check (D3): reject any policy path the invoking user cannot
        // access, so the sandbox never gains access the caller lacks. Runs AFTER
        // object normalization so it is evaluated against the already-tightened
        // intents (a path moved rw -> denied must not then require write access).
        if let Err(msg) = wxc_common::filesystem_access::check_delegation(&request.policy) {
            return Err(ScriptResponse::error(&msg));
        }
        // Resolve denied paths that traverse a symlink to their real host path
        // and classify each as a file/dir mask (see [`resolve_denied_paths`]).
        // Only clones the request when a path needs rewriting (common case:
        // none). See docs/bwrap-support/bubblewrap-backend.md.
        let plan = match resolve_denied_paths(&request.policy, logger) {
            Ok(plan) => plan,
            Err(msg) => return Err(ScriptResponse::error(&msg)),
        };
        let resolved;
        let request = match plan.paths {
            Some(denied_paths) => {
                let mut policy = request.policy.clone();
                policy.denied_paths = denied_paths;
                resolved = ExecutionRequest {
                    policy,
                    ..request.clone()
                };
                &resolved
            }
            None => request,
        };
        // The masks are built from the list above, not from the one the caller
        // wrote, so the pin conflict has to be judged against it too.
        if let Err(msg) = check_pin_against_denied_hosts(request) {
            return Err(ScriptResponse::error(&msg));
        }
        let child = self.spawn_bwrap(request, &plan.files, egress_plan, logger, stdio)?;
        Ok(Box::new(BubblewrapSandboxProcess::new(child)))
    }
}

impl BubblewrapScriptRunner {
    /// `validate`, plus the egress plan it derived.
    ///
    /// Returning the plan lets `spawn` install exactly what validation
    /// accepted instead of deriving it a second time on every spawn.
    fn validate_prepared(
        &self,
        request: &ExecutionRequest,
    ) -> Result<Option<network_rules::EgressPlan>, ScriptResponse> {
        validate_network_policy_support(request, self.network_policy_support())?;
        // User-input validation runs before the environmental `bwrap`
        // probe so config errors are reported deterministically even on
        // hosts without bwrap installed.
        if request.script_code.is_empty() {
            return Err(ScriptResponse::error(
                "script_code is empty — nothing to execute.",
            ));
        }

        // `network.proxy.builtinTestServer` is gated centrally in
        // `validate_common` (ahead of every `ScriptRunner::run`), so no
        // backend-local check is needed here.

        // Refuse a credential-bearing proxy URL here as well as at parse time.
        // The parser guard only covers requests it built; `ExecutionRequest`
        // and `ProxyAddress::from_url` are public, so a caller can hand this
        // runner a policy the parser never saw. `to_url` returns that URL
        // verbatim and `build_args` emits it as a `bwrap --setenv HTTP_PROXY
        // VALUE` argument (bwrap_command.rs), and a process's argv is readable
        // through /proc/<pid>/cmdline by any local user for the lifetime of the
        // command. This mirrors the same guard on the LXC runner, which reaches
        // argv by a different route (`lxc-attach --set-var`).
        //
        // It sits with the input checks, ahead of the bwrap probe, for the
        // reason above: a host without bwrap must still be told what is wrong
        // with the request.
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
                return Err(ScriptResponse::error(&format!(
                    "Bubblewrap: network.proxy.url must not carry credentials ('{}'). \
                     Bubblewrap passes the proxy URL to bwrap as a --setenv command-line \
                     argument, and process arguments are world-readable through \
                     /proc/<pid>/cmdline, so the password would be visible to every local \
                     user while the command runs. Use a proxy that does not require inline \
                     credentials, or supply them to the proxy itself rather than through \
                     the URL.",
                    wxc_common::proxy_env::redact_proxy_url(&url)
                )));
            }
        }

        // Schema 0.8+ fails closed on a network element Bubblewrap cannot
        // honor, rather than running more permissive than requested. Pre-0.8
        // keeps the warning, so existing configs are unaffected. Sits with the
        // input checks so a host without bwrap is still told what is wrong.
        //
        // This is the only layer that checks what Bubblewrap can enforce: the
        // parser validates structure, and it only sees JSON configs, while a
        // Rust caller can build an `ExecutionRequest` and reach the runner
        // directly. (The external-proxy case is the exception — the parser has
        // rejected that combination since before this backend gained its own
        // validation, so both layers refuse it.)
        if let Some(reason) = bwrap_command::external_proxy_host_rules_rejection(request) {
            return Err(ScriptResponse::error(reason));
        }
        if let Some(reason) = bwrap_command::unenforced_host_rules_rejection(request) {
            return Err(ScriptResponse::error(reason));
        }
        if let Some(reason) = bwrap_command::local_network_rejection(request) {
            return Err(ScriptResponse::error(reason));
        }
        if let Some(reason) = bwrap_command::directional_network_rejection(request) {
            return Err(ScriptResponse::error(reason));
        }

        // Proxy-only networking derives the sandbox-visible endpoint from the
        // configured one and then opens exactly that address in the egress
        // chain. That step can reject an endpoint outright (an IPv6 loopback
        // the gateway cannot reach, a routable or IPv6-only endpoint the
        // IPv4-only rules cannot express, a zero port), and those verdicts
        // follow from the configured address alone, so they are reported here
        // instead of after a proxy has been started.
        //
        // A hostname is deliberately left to `run`: its verdict needs a lookup,
        // and the answer is the pin the sandbox is given, so resolving here
        // would either resolve twice or pin an address the egress chain never
        // opened.
        //
        // The builtin test server has no address until it is started (the
        // parser leaves a port-0 placeholder), so its endpoint stays on the
        // runtime check in `run`; this only covers an operator-supplied proxy.
        let proxy_only =
            ResolvedNetworkMode::from_request(request, request.policy.network_proxy.is_enabled())
                == ResolvedNetworkMode::ProxyOnly;
        if proxy_only && !request.policy.network_proxy.builtin_test_server {
            if let Some(address) = request.policy.network_proxy.address.as_ref() {
                if let Err(error) = proxy_network::SandboxProxy::check_without_resolving(address) {
                    return Err(ScriptResponse::error(&error));
                }
                if let Err(error) =
                    proxy_network::check_hosts_pin_against_policy(address, &request.policy)
                {
                    return Err(ScriptResponse::error(&error));
                }
                // Repeated in `spawn` against the normalized policy.
            }
        }

        // Firewall enforcement builds its chain from the policy's host lists,
        // and every rule address must be an IP literal or CIDR: the sandbox
        // resolves DNS itself, so a name can be mapped to an address the chain
        // never authorized and is therefore unenforceable. Rejecting here
        // rather than in the parser covers both callers -- `validate` runs
        // ahead of every `spawn`, while a programmatic `mxc_engine` caller
        // never passes through the parser at all.
        let firewall_enforced =
            ResolvedNetworkMode::from_request(request, request.policy.network_proxy.is_enabled())
                == ResolvedNetworkMode::FirewallEnforced;
        let egress_plan = if firewall_enforced {
            match network_rules::EgressPlan::for_request(request) {
                Ok(plan) => Some(plan),
                Err(error) => return Err(ScriptResponse::error(&error)),
            }
        } else {
            None
        };

        // `bwrap` must be present *and* new enough for every flag the argument
        // builder emits — an old binary would otherwise fail at spawn time with
        // an opaque "unknown option" error.
        if let Err(err) = bwrap_version::probe_bwrap() {
            return Err(ScriptResponse::error(&err.to_string()));
        }
        if proxy_only || firewall_enforced {
            // Proxy and firewall are mutually exclusive, so this names the one
            // the caller actually asked for; the probe's advice is worded from
            // it rather than always naming network.proxy.
            let use_case = if proxy_only {
                proxy_network::PrivateNetworkUse::ProxyOnlyEgress
            } else {
                proxy_network::PrivateNetworkUse::FirewallEnforcement
            };
            if let Err(error) = proxy_network::probe_dependencies(use_case) {
                return Err(ScriptResponse::error(&error));
            }
        }

        Ok(egress_plan)
    }
}

/// Reject a hostname proxy pin that would defeat a denied `/etc/hosts`.
///
/// Runs in both `validate` (against the policy as written, so the caller hears
/// about it early) and `spawn` (against the normalized policy, which is what
/// the masks are built from). One is not enough: `resolve_denied_paths`
/// rewrites `/etc/../etc/hosts` -- or any symlinked spelling -- to
/// `/etc/hosts`, which the written form never matches, and the pin is spliced
/// after every policy mount, so it hands back the file the policy masked.
fn check_pin_against_denied_hosts(request: &ExecutionRequest) -> Result<(), String> {
    let proxy_only =
        ResolvedNetworkMode::from_request(request, request.policy.network_proxy.is_enabled())
            == ResolvedNetworkMode::ProxyOnly;
    // The builtin test server is never a hostname, so it is never pinned.
    if !proxy_only || request.policy.network_proxy.builtin_test_server {
        return Ok(());
    }
    match request.policy.network_proxy.address.as_ref() {
        Some(address) => proxy_network::check_hosts_pin_against_policy(address, &request.policy),
        None => Ok(()),
    }
}

impl BubblewrapScriptRunner {
    /// Set up networking and spawn `bwrap`, returning a [`BwrapChild`] wrapped
    /// by the [`SandboxProcess`] handle. With [`StdioMode::Pipes`] the child's
    /// stdio is piped (the caller drives it); with [`StdioMode::Inherit`] it
    /// inherits the binary's stdio (a TTY when the binary has one). bwrap is
    /// always placed in its own process group so it can be tree-terminated.
    fn spawn_bwrap(
        &self,
        request: &ExecutionRequest,
        denied_files: &HashSet<String>,
        egress_plan: Option<network_rules::EgressPlan>,
        logger: &mut Logger,
        stdio: StdioMode,
    ) -> Result<BwrapChild, ScriptResponse> {
        // 1. Start the network proxy if configured. Must happen before
        //    arg-building so the proxy's loopback address can be injected as
        //    HTTP_PROXY / HTTPS_PROXY into the sandbox environment.
        let mut proxy = UnixProxyCoordinator::new();
        if request.policy.network_proxy.is_enabled() {
            if let Err(err) = proxy.start(
                &request.policy.network_proxy,
                "127.0.0.1",
                &request.policy.allowed_hosts,
                &request.policy.blocked_hosts,
                request.policy.default_network_policy.clone(),
                logger,
            ) {
                return Err(ScriptResponse::error(&format!(
                    "Bubblewrap: failed to start network proxy: {}",
                    err
                )));
            }
        }

        let network_mode = ResolvedNetworkMode::from_request(request, proxy.is_active());
        let sandbox_proxy = if network_mode == ResolvedNetworkMode::ProxyOnly {
            match proxy.address() {
                Some(address) => match proxy_network::SandboxProxy::resolve(address) {
                    Ok(resolved) => Some(resolved),
                    Err(error) => {
                        proxy.stop(logger);
                        return Err(ScriptResponse::error(&error));
                    }
                },
                None => {
                    proxy.stop(logger);
                    return Err(ScriptResponse::error(
                        "Bubblewrap: proxy mode was selected without a resolved proxy address.",
                    ));
                }
            }
        } else {
            None
        };
        let proxy_address = sandbox_proxy
            .as_ref()
            .map(|resolved| resolved.address())
            .or_else(|| proxy.address());

        let mut proxy_network = match sandbox_proxy.as_ref() {
            // The workload dials the sandbox-visible address, so that is what
            // the egress rule must open.
            Some(resolved) => {
                let egress = resolved.egress();
                match proxy_network::ProxyNetworkNamespace::start(
                    &egress.plan(),
                    &network_rules::IngressPlan::for_policy(&request.policy),
                    egress.pin(),
                    logger,
                    request.script_timeout,
                ) {
                    Ok(network) => Some(network),
                    Err(error) => {
                        proxy.stop(logger);
                        return Err(ScriptResponse::error(&error));
                    }
                }
            }
            // Firewall enforcement without a proxy: the same private namespace,
            // programmed from the policy's host lists instead of a single
            // endpoint. There is no hostname to pin because rule addresses are
            // literals and CIDRs only.
            None if network_mode == ResolvedNetworkMode::FirewallEnforced => {
                // Reuse the validated plan. It is derived from network policy
                // only, which the filesystem normalization between the two
                // points cannot touch. Recompute only if the resolved mode
                // disagrees with validation's pre-spawn proxy reading.
                let plan = match egress_plan {
                    Some(plan) => plan,
                    None => match network_rules::EgressPlan::for_request(request) {
                        Ok(plan) => plan,
                        Err(error) => {
                            proxy.stop(logger);
                            return Err(ScriptResponse::error(&error));
                        }
                    },
                };
                match proxy_network::ProxyNetworkNamespace::start(
                    &plan,
                    &network_rules::IngressPlan::for_policy(&request.policy),
                    None,
                    logger,
                    request.script_timeout,
                ) {
                    Ok(network) => Some(network),
                    Err(error) => {
                        proxy.stop(logger);
                        return Err(ScriptResponse::error(&error));
                    }
                }
            }
            None => None,
        };

        // 2. Build the bwrap argument vector. `denied_files` is the file-mask
        //    subset classified during symlink resolution (see
        //    [`resolve_denied_paths`]).
        if let Some(warning) =
            bwrap_command::local_network_diagnostic_for_mode(request, network_mode)
        {
            let _ = writeln!(logger, "WARNING: {}", warning);
        }
        let mut args = bwrap_command::build_args_classified_with_mode(
            request,
            proxy_address,
            denied_files,
            network_mode,
        );
        let mut network_startup = match proxy_network.as_ref() {
            Some(network) => match network.configure_bwrap(&mut args, logger) {
                Ok(startup) => Some(startup),
                Err(error) => {
                    stop_proxy_network(&mut proxy_network, logger);
                    proxy.stop(logger);
                    return Err(ScriptResponse::error(&error));
                }
            },
            None => None,
        };
        let _ = writeln!(
            logger,
            "Bubblewrap: spawning bwrap with {} args",
            args.len()
        );

        // 3. Determine whether the host-side firewall manager is needed. Proxy
        //    mode does not use it: it programs its own rules inside the
        //    sandbox's network namespace instead (see proxy_network).
        let needs_iptables = network_mode.requires_host_firewall_manager();
        let container_name = if request.container_id.is_empty() {
            format!("bwrap-{:08x}", std::process::id())
        } else {
            request.container_id.clone()
        };

        let fw_manager = if needs_iptables {
            let _ = writeln!(
                logger,
                "Bubblewrap: applying iptables rules for host-level network filtering"
            );
            let mut mgr = build_firewall_manager(&container_name);
            match mgr.apply_firewall_rules(&request.policy, logger) {
                Ok(true) => {}
                Ok(false) => {
                    proxy.stop(logger);
                    return Err(ScriptResponse::error(
                        "Bubblewrap: failed to apply iptables firewall rules.",
                    ));
                }
                Err(e) => {
                    proxy.stop(logger);
                    return Err(ScriptResponse::error(&format!(
                        "Bubblewrap: network policy error: {}",
                        e
                    )));
                }
            }
            Some(mgr)
        } else {
            None
        };

        // 4. Spawn `bwrap`.
        let mut command = Command::new("bwrap");
        command.args(&args);
        match stdio {
            StdioMode::Pipes => {
                command
                    .stdin(Stdio::piped())
                    .stdout(Stdio::piped())
                    .stderr(Stdio::piped());
            }
            StdioMode::Inherit => {
                // The child (bwrap, PID 1 of the sandbox) inherits the binary's
                // stdio directly — a TTY when the binary has one.
                command
                    .stdin(Stdio::inherit())
                    .stdout(Stdio::inherit())
                    .stderr(Stdio::inherit());
            }
        }
        // Pipes mode: put bwrap in its own process group so a timeout / `kill()`
        // can tree-kill it with a single `killpg` without touching the host's
        // group. Inherit mode keeps bwrap in the executor's group (so it retains
        // the controlling terminal and can't be SIGTTIN-stopped reading it); it's
        // PID 1 of the new pid namespace (`--unshare-pid`), so killing the root
        // process alone tears the whole sandbox down.
        let group = stdio == StdioMode::Pipes;
        if group {
            command.process_group(0);
        }
        if let Some(startup) = network_startup.as_ref() {
            startup.prepare_command(&mut command);
        }

        let mut child = match command.spawn() {
            Ok(process) => process,
            Err(error) => {
                let mut fw_manager = fw_manager;
                cleanup_iptables(&mut fw_manager, logger);
                stop_proxy_network(&mut proxy_network, logger);
                proxy.stop(logger);
                return Err(ScriptResponse::error(&format!(
                    "Bubblewrap: failed to spawn bwrap: {}",
                    error
                )));
            }
        };

        if let Some(mut startup) = network_startup.take() {
            startup.child_spawned();
            if let Some(network) = proxy_network.as_mut() {
                network.userns_handed_off();
            }
            let startup_result = startup
                .child_pid(&mut child)
                .and_then(|child_pid| {
                    proxy_network
                        .as_mut()
                        .ok_or_else(|| {
                            "Bubblewrap: proxy network lifecycle disappeared during startup"
                                .to_string()
                        })?
                        .attach(child_pid, logger)
                })
                .and_then(|()| startup.release());
            if let Err(error) = startup_result {
                let _ = child.kill();
                let _ = child.wait();
                let mut fw_manager = fw_manager;
                cleanup_iptables(&mut fw_manager, logger);
                stop_proxy_network(&mut proxy_network, logger);
                proxy.stop(logger);
                return Err(ScriptResponse::error(&error));
            }
        }

        let (stdin, stdout, stderr) = match stdio {
            StdioMode::Pipes => (child.stdin.take(), child.stdout.take(), child.stderr.take()),
            StdioMode::Inherit => (None, None, None),
        };
        // Wrap the pipe reads so the caller can abandon a stream a backgrounded
        // descendant is holding open (see `SandboxProcess::stdout_closer`)
        // without killing the child. On failure, tear down the per-run network
        // state we already set up before returning the error.
        let (stdout, stdout_canceller, stderr, stderr_canceller) =
            match (wrap_pipe(stdout), wrap_pipe(stderr)) {
                (Ok((out, out_canceller)), Ok((err, err_canceller))) => {
                    (out, out_canceller, err, err_canceller)
                }
                (out_result, err_result) => {
                    let _ = child.kill();
                    let _ = child.wait();
                    let mut fw_manager = fw_manager;
                    cleanup_iptables(&mut fw_manager, logger);
                    stop_proxy_network(&mut proxy_network, logger);
                    proxy.stop(logger);
                    let error = out_result.err().or(err_result.err());
                    return Err(ScriptResponse::error(&format!(
                        "Bubblewrap: failed to wrap stdio pipes: {}",
                        error.map_or_else(|| "unknown error".to_string(), |e| e.to_string()),
                    )));
                }
            };
        let timeout = if request.script_timeout == 0 {
            None
        } else {
            Some(Duration::from_millis(u64::from(request.script_timeout)))
        };

        Ok(BwrapChild {
            child,
            stdin,
            stdout,
            stderr,
            stdout_canceller,
            stderr_canceller,
            group,
            proxy,
            proxy_network,
            fw_manager,
            timeout,
        })
    }
}

/// A spawned `bwrap` sandbox: the child process, its parent-side pipe ends,
/// and the per-run network proxy / iptables state torn down once it exits.
struct BwrapChild {
    child: Child,
    stdin: Option<ChildStdin>,
    stdout: Option<InterruptibleReader>,
    stderr: Option<InterruptibleReader>,
    /// Cancellers for the stdout/stderr reads, kept so the `SandboxProcess`
    /// closers can mint a [`StreamCloser`] even after the stream is taken.
    stdout_canceller: Option<ReadCanceller>,
    stderr_canceller: Option<ReadCanceller>,
    /// `true` when bwrap leads its own process group (`Pipes` mode), so
    /// termination signals the whole group; `false` for `Inherit` mode, where
    /// killing bwrap (pid 1 of the namespace) alone tears the sandbox down.
    group: bool,
    proxy: UnixProxyCoordinator,
    proxy_network: Option<proxy_network::ProxyNetworkNamespace>,
    fw_manager: Option<NetworkIptablesManager>,
    timeout: Option<Duration>,
}

impl BwrapChild {
    /// Tear down per-run network state (iptables rules + proxy). Idempotent at
    /// the manager level.
    fn cleanup(&mut self, logger: &mut Logger) {
        cleanup_iptables(&mut self.fw_manager, logger);
        if let Some(mut network) = self.proxy_network.take() {
            network.stop(logger);
        }
        self.proxy.stop(logger);
    }
}

/// A running `bwrap` sandbox exposed as a [`SandboxProcess`]. Wraps the spawned
/// [`BwrapChild`] (child, pipes, and per-run network state), tearing the network
/// state down once the child exits.
struct BubblewrapSandboxProcess {
    inner: BwrapChild,
    teardown_done: bool,
}

impl BubblewrapSandboxProcess {
    fn new(child: BwrapChild) -> Self {
        Self {
            inner: child,
            teardown_done: false,
        }
    }

    fn run_teardown(&mut self) {
        if self.teardown_done {
            return;
        }
        self.teardown_done = true;
        let mut logger = Logger::new(wxc_common::logger::Mode::Buffer);
        self.inner.cleanup(&mut logger);
    }
}

impl SandboxProcess for BubblewrapSandboxProcess {
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

    fn id(&self) -> u32 {
        self.inner.child.id()
    }

    fn kill(&mut self) -> std::io::Result<()> {
        // No-op once the child has exited and been reaped: its pid/pgid can be
        // recycled, so signaling it could hit an unrelated process (group). A
        // reaped `Child` returns its cached status here without a syscall.
        if self.inner.child.try_wait()?.is_some() {
            return Ok(());
        }
        if self.inner.group {
            // Pipes mode: bwrap leads its own process group — tree-kill it.
            group_kill(&mut self.inner.child)
        } else {
            // Inherit mode: bwrap shares the executor's group (no
            // `process_group(0)`), so a group-kill would hit the executor.
            // bwrap is pid 1 of the sandbox pid namespace, so killing the root
            // alone tears the whole namespace (every descendant) down.
            self.inner.child.kill()
        }
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
                // Tree-kill so descendants die too and release any stdout/stderr
                // pipe write-ends (else the drain threads below could block).
                // `kill()` group-kills in Pipes mode, and in Inherit mode kills
                // bwrap (pid 1 of the namespace), which tears the sandbox down.
                let _ = self.kill();
                let _ = self.inner.child.wait();
                Err(std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    "Bubblewrap: script timed out",
                ))
            }
            Err(WaitError::Io(error)) => {
                // The child may still be alive; kill+reap it before
                // `run_teardown()` removes the iptables/proxy enforcement out
                // from under it.
                let _ = self.kill();
                let _ = self.inner.child.wait();
                Err(std::io::Error::other(format!(
                    "Bubblewrap: wait failed: {error}"
                )))
            }
        };

        cancel_and_join_discard(stdout_thread, &self.inner.stdout_canceller);
        cancel_and_join_discard(stderr_thread, &self.inner.stderr_canceller);
        self.run_teardown();
        result
    }
}

impl Drop for BubblewrapSandboxProcess {
    fn drop(&mut self) {
        // Kill and reap the child *before* removing network enforcement —
        // otherwise an abandoned-but-running sandbox would keep egressing after
        // its iptables/proxy rules were torn down, and the child would leak as
        // a zombie. `kill()` group-kills (bwrap is PID 1 of the pid namespace),
        // then we reap.
        let _ = self.kill();
        let _ = self.inner.child.wait();
        self.run_teardown();
    }
}

/// Build the iptables manager for a Bubblewrap sandbox.
///
/// Unprivileged bwrap has no veth: the sandbox either shares the host network
/// namespace or gets a private one, and neither leaves a host-side interface
/// for a chain to match on (see `local_network_diagnostic` in
/// `bwrap_command`). The absence is structural, not a lookup that failed, and
/// that distinction is the whole of what makes it safe to accept here: there
/// is no case in this backend where a veth was expected and went missing, so
/// accepting one cannot mask a discovery that broke.
fn build_firewall_manager(container_name: &str) -> NetworkIptablesManager {
    let mut mgr = NetworkIptablesManager::new(container_name);
    mgr.allow_missing_veth_interface();
    mgr
}

/// Best-effort iptables cleanup. Called on both success and error paths.
fn cleanup_iptables(manager: &mut Option<NetworkIptablesManager>, logger: &mut Logger) {
    if let Some(ref mut mgr) = manager {
        if mgr.rules_applied() {
            let _ = mgr.remove_firewall_rules(logger);
        }
    }
}

/// Tear down the proxy network namespace against the caller's logger.
///
/// `Drop` would also stop it, but only through a throwaway in-memory logger, so
/// warnings about slirp needing forced termination are lost on exactly the
/// startup paths that already failed.
fn stop_proxy_network(
    network: &mut Option<proxy_network::ProxyNetworkNamespace>,
    logger: &mut Logger,
) {
    if let Some(mut network) = network.take() {
        network.stop(logger);
    }
}

/// Outcome of resolving and classifying `deniedPaths` in a single pass.
struct DeniedPlan {
    /// Rewritten denied-path list. `Some` only when at least one entry differs
    /// from the input (a symlink was resolved to its real target), so the caller
    /// can skip cloning the request in the common no-symlink case.
    paths: Option<Vec<String>>,
    /// Subset of the (final) denied paths that must be masked as files with
    /// `--ro-bind /dev/null`; every other denied path is masked with `--tmpfs`.
    files: HashSet<String>,
}

/// Resolve every `deniedPaths` entry that traverses a symlink to its real host
/// path **and** classify each entry as a file- or directory-mask, in a single
/// pass (one `symlink_metadata` stat per entry).
///
/// Resolution (via [`resolve_through_symlinks`]) is required because bwrap masks
/// by mounting over `DEST`; if any component of `DEST` is a host symlink bound
/// into the sandbox, bwrap aborts with an opaque `ENOENT`. Masking the resolved
/// real path avoids that and still hides the object. Classification is folded in
/// here because it must observe the *resolved* path (a symlink-to-dir must be
/// `--tmpfs`, not `/dev/null`).
///
/// Fails closed if a resolved path is not valid UTF-8: the `String`-based bwrap
/// arg pipeline can't represent it faithfully, and a lossy replacement would mask
/// the wrong path and leave the target exposed.
///
/// An entry still a symlink after resolution (dangling/unresolvable) is kept and
/// file-masked with `/dev/null` — nothing resolvable is behind it to leak, and
/// bwrap tolerates `/dev/null` over a symlink node (whereas `--tmpfs` aborts).
fn resolve_denied_paths(
    policy: &wxc_common::models::ContainerPolicy,
    logger: &mut Logger,
) -> Result<DeniedPlan, String> {
    let mut changed = false;
    let mut out = Vec::with_capacity(policy.denied_paths.len());
    let mut files = HashSet::new();
    for p in &policy.denied_paths {
        if let Some(resolved) = resolve_through_symlinks(Path::new(p)) {
            let resolved = resolved.to_str().ok_or_else(|| {
                format!(
                    "Bubblewrap: deniedPaths entry '{p}' resolves to a non-UTF-8 host path that \
                     cannot be safely masked; refusing to start."
                )
            })?;
            if resolved != p.as_str() {
                let _ = writeln!(
                    logger,
                    "Bubblewrap: deniedPaths entry '{p}' resolves through a symlink; masking \
                     its real path '{resolved}' instead."
                );
                if is_file_mask_target(resolved) {
                    files.insert(resolved.to_owned());
                }
                out.push(resolved.to_owned());
                changed = true;
                continue;
            }
        }
        // Not rewritten: a real path, a rooted not-yet-existing path, or a
        // dangling symlink. Classify by stat'ing the entry itself.
        if is_file_mask_target(p) {
            files.insert(p.clone());
        }
        out.push(p.clone());
    }
    Ok(DeniedPlan {
        paths: changed.then_some(out),
        files,
    })
}

/// Classify a denied path for masking: `true` = `--ro-bind /dev/null` (file),
/// `false` = `--tmpfs` (directory). A real directory and any path that cannot be
/// stat'd are directory-masked; regular files and symlink nodes are file-masked.
fn is_file_mask_target(path: &str) -> bool {
    std::fs::symlink_metadata(path)
        .map(|md| !md.file_type().is_dir())
        .unwrap_or(false)
}

/// Resolve every symlink in `path` (leaf and ancestors) to a real filesystem
/// path, tolerating trailing components that do not exist yet.
///
/// `std::fs::canonicalize` resolves symlinks at every level but requires the
/// **whole** path to exist. To also cover not-yet-created denied paths under a
/// symlinked ancestor, this walks the components from the root: every existing
/// prefix is canonicalized (following symlinks exactly like the kernel), while
/// `.` and `..` in the not-yet-existent tail are folded lexically. Folding `..`
/// this way is safe because a component that does not exist cannot be a symlink,
/// so the result matches the target the kernel's path resolution would reach.
/// Returns `None` only for an empty path.
///
/// A naive backward walk that collected `file_name()` silently dropped `..`
/// components (Rust returns `None` for a `..` file name) and reconstructed the
/// wrong target: `/link/missing/../secret` became `/real/missing/secret`
/// instead of `/real/secret`, so the mask landed on a bystander path and the
/// real denied target stayed exposed.
fn resolve_through_symlinks(path: &Path) -> Option<PathBuf> {
    let mut result = PathBuf::new();
    for component in path.components() {
        match component {
            Component::Prefix(_) | Component::RootDir => result.push(component.as_os_str()),
            Component::CurDir => {}
            Component::ParentDir => {
                result.pop();
            }
            Component::Normal(name) => {
                result.push(name);
                // Canonicalize the prefix so far so symlinks are followed while
                // it still exists; once a component is missing, canonicalize
                // fails and the remaining tail is folded lexically above.
                if let Ok(real) = std::fs::canonicalize(&result) {
                    result = real;
                }
            }
        }
    }
    if result.as_os_str().is_empty() {
        None
    } else {
        Some(result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use wxc_common::models::{NetworkEnforcementMode, ProxyAddress, ProxyConfig};

    fn base_request() -> ExecutionRequest {
        ExecutionRequest {
            script_code: "echo hi".into(),
            ..Default::default()
        }
    }

    /// A request carrying `alice:hunter2@` in its proxy URL, built the way a
    /// programmatic caller would rather than through the JSON parser.
    fn request_with_a_credential_bearing_proxy() -> ExecutionRequest {
        let mut req = base_request();
        req.policy.network_proxy = ProxyConfig {
            address: Some(ProxyAddress::from_url(
                "http://alice:hunter2@proxy.example.com:3128",
                "proxy.example.com".into(),
                3128,
            )),
            builtin_test_server: false,
        };
        req
    }

    /// Every declared feature must be matched by a backend-local refusal of
    /// the values it cannot honor.
    ///
    /// Declaring `INGRESS_DEFAULT`/`HOST_LOOPBACK` tells shared validation to
    /// stop checking those fields. That is the point — it is what lets the
    /// honorable deny posture through — but it also means an unsupported value
    /// now reaches the runner unchallenged. This asserts both halves at once:
    /// shared validation waves the allow posture through *because* of the
    /// declaration, and the backend gate is what stops it. Delete either half
    /// and this fails, which is the fail-open the two-part change exists to
    /// prevent.
    #[test]
    fn every_declared_inbound_feature_has_a_backend_refusal_behind_it() {
        use wxc_common::models::{NetworkAction, NetworkEgressPolicy, NetworkIngressPolicy};

        use crate::bwrap_command::{BWRAP_HOST_LOOPBACK_ALLOW, BWRAP_INGRESS_DEFAULT_ALLOW};

        let runner = BubblewrapScriptRunner::new();
        let support = runner.network_policy_support();

        for (default, host_loopback) in [
            (NetworkAction::Allow, NetworkAction::Deny),
            (NetworkAction::Deny, NetworkAction::Allow),
        ] {
            let mut request = base_request();
            request.schema_version = "0.8.0-alpha".into();
            request.policy.network_egress = Some(NetworkEgressPolicy::default());
            request.policy.network_ingress = Some(NetworkIngressPolicy {
                default,
                host_loopback,
            });

            assert!(
                validate_network_policy_support(&request, support).is_ok(),
                "shared validation should defer to the declaration \
                 (default={default:?} hostLoopback={host_loopback:?})"
            );
            // Through `validate`, not the gate function directly: this must
            // also fail if the gate is written but never wired in. The
            // rejection sits ahead of the `bwrap` probe, so the verdict is the
            // same on a host without bwrap installed.
            let refusal = runner
                .validate(&request)
                .expect_err("the backend must refuse what the declaration stopped checking");
            assert!(
                refusal.error_message == BWRAP_INGRESS_DEFAULT_ALLOW
                    || refusal.error_message == BWRAP_HOST_LOOPBACK_ALLOW,
                "unexpected refusal for default={default:?} \
                 hostLoopback={host_loopback:?}: {}",
                refusal.error_message
            );
        }
    }

    /// Every `NetworkPolicySupport` bit must be a deliberate decision, proven
    /// against a config the shared gate actually rules on.
    ///
    /// The bits are a hand-written declaration: nothing derives them from the
    /// fields this backend really consumes, so a bit that was simply never
    /// added reads exactly like one that was considered and refused. Both
    /// produce the same clean rejection. That is how `RUNTIME_PROXY` stayed
    /// undeclared while the backend had full proxy support the whole time --
    /// no test could see the difference, because there was nothing to compare
    /// the declaration against.
    ///
    /// This closes that gap from both sides. The union assertion means a newly
    /// added bit fails here until someone categorizes it, so the decision can
    /// no longer be made by omission. Each entry is then proven against a
    /// request that exercises its field: declared bits must be accepted,
    /// undeclared ones must be refused by name. Every probe is also run against
    /// `ALL`, so a probe that stops reaching its gate fails loudly instead of
    /// quietly passing for the wrong reason.
    #[test]
    fn every_network_policy_support_bit_is_a_deliberate_decision() {
        use wxc_common::models::{
            NetworkAction, NetworkEgressPolicy, NetworkIngressPolicy, NetworkRule,
        };

        use crate::network_rules::{render_filter_payloads, EgressPlan, IngressPlan, RuleFamily};

        // A directional posture makes the gates that key off it fire. Both
        // sections are always set, because that is the only shape the parser
        // produces (`apply_directional_network` fills them in together).
        fn directional() -> ExecutionRequest {
            let mut request = base_request();
            request.schema_version = "0.8.0-alpha".into();
            request.policy.network_mode_specified = true;
            request.policy.network_egress = Some(NetworkEgressPolicy::default());
            request.policy.network_ingress = Some(NetworkIngressPolicy::default());
            request
        }

        // (bit, declared, a request that exercises it, the field it names,
        //  a probe proving the field reaches enforcement)
        //
        // Acceptance alone proved nothing: `HOST_LOOPBACK` sat here declared
        // and accepted for its whole unenforced life. Each probe flips the
        // field in a copy of its request and requires the rendered chain to
        // change, so an over-declared bit fails here.
        type Probe = fn(&ExecutionRequest) -> Result<(), String>;

        /// The rendered v4 payload, exactly as the supervisor would install it.
        fn chain_payload(request: &ExecutionRequest) -> Vec<String> {
            let egress =
                EgressPlan::for_request(request).expect("the probe requests are all renderable");
            let ingress = IngressPlan::for_policy(&request.policy);
            render_filter_payloads(
                &egress,
                &ingress,
                RuleFamily::V4,
                "MXC_EGRESS",
                "MXC_INGRESS",
            )
        }

        /// Requires the rendered chain to change, naming what was flipped.
        fn must_differ(
            flipped: &str,
            before: Vec<String>,
            after: Vec<String>,
        ) -> Result<(), String> {
            if before == after {
                return Err(format!(
                    "flipping {flipped} left the rendered chain unchanged: {before:?}"
                ));
            }
            Ok(())
        }

        let egress_default: Probe = |request| {
            let mut flipped = request.clone();
            flipped.policy.network_egress = Some(NetworkEgressPolicy {
                default: NetworkAction::Allow,
                ..request.policy.network_egress.clone().unwrap_or_default()
            });
            must_differ(
                "egress.default",
                chain_payload(request),
                chain_payload(&flipped),
            )
        };

        let egress_rules: Probe = |request| {
            let mut flipped = request.clone();
            flipped.policy.network_egress = Some(NetworkEgressPolicy {
                allow: Vec::new(),
                deny: Vec::new(),
                ..request.policy.network_egress.clone().unwrap_or_default()
            });
            must_differ(
                "the egress rule lists",
                chain_payload(request),
                chain_payload(&flipped),
            )
        };

        let ingress_default: Probe = |request| {
            let mut flipped = request.clone();
            flipped.policy.network_ingress = Some(NetworkIngressPolicy {
                default: NetworkAction::Allow,
                ..request.policy.network_ingress.clone().unwrap_or_default()
            });
            must_differ(
                "ingress.default",
                chain_payload(request),
                chain_payload(&flipped),
            )
        };

        let host_loopback: Probe = |request| {
            let mut flipped = request.clone();
            flipped.policy.network_ingress = Some(NetworkIngressPolicy {
                host_loopback: NetworkAction::Allow,
                ..request.policy.network_ingress.clone().unwrap_or_default()
            });
            must_differ(
                "ingress.hostLoopback",
                chain_payload(request),
                chain_payload(&flipped),
            )
        };

        let runtime_proxy: Probe = |request| {
            let address = request
                .policy
                .network_proxy
                .address
                .clone()
                .ok_or("the runtime-proxy probe carries no proxy address")?;
            // The claim the bit makes is that a `runtimeConfig.networkProxy`
            // lands on the proxy machinery this backend already enforces:
            // the env injection, and no refusal on the way there.
            if crate::bwrap_command::external_proxy_host_rules_rejection(request).is_some() {
                return Err(
                    "the runtime-proxy shape is refused before it reaches the proxy".into(),
                );
            }
            must_differ(
                "the proxy address",
                crate::bwrap_command::build_args(request, Some(&address)),
                crate::bwrap_command::build_args(request, None),
            )
        };

        let decisions: [(
            NetworkPolicySupport,
            bool,
            ExecutionRequest,
            &str,
            Option<Probe>,
        ); 6] = [
            (
                NetworkPolicySupport::EGRESS_DEFAULT,
                true,
                directional(),
                "network.egress.default",
                Some(egress_default),
            ),
            (
                NetworkPolicySupport::EGRESS_RULES,
                true,
                {
                    let mut request = directional();
                    request.policy.network_egress = Some(NetworkEgressPolicy {
                        allow: vec![NetworkRule::default()],
                        ..Default::default()
                    });
                    request
                },
                "network.egress allow/deny rules",
                Some(egress_rules),
            ),
            (
                NetworkPolicySupport::INGRESS_DEFAULT,
                true,
                directional(),
                "network.ingress.default",
                Some(ingress_default),
            ),
            (
                NetworkPolicySupport::HOST_LOOPBACK,
                true,
                directional(),
                "network.ingress.hostLoopback",
                Some(host_loopback),
            ),
            (
                // Declared: the parser normalizes `runtimeConfig.networkProxy`
                // into the same `policy.network_proxy` the legacy field feeds,
                // so it lands on machinery this backend already enforces.
                NetworkPolicySupport::RUNTIME_PROXY,
                true,
                {
                    let mut request = directional();
                    request.policy.network_egress = Some(NetworkEgressPolicy {
                        default: NetworkAction::Deny,
                        ..Default::default()
                    });
                    request.policy.runtime_network_proxy_specified = true;
                    request.policy.network_proxy = ProxyConfig {
                        address: Some(ProxyAddress::new("127.0.0.1".to_string(), 3128)),
                        builtin_test_server: false,
                    };
                    request
                },
                "runtimeConfig.networkProxy",
                Some(runtime_proxy),
            ),
            (
                // Undeclared: a ProcessContainer concept with no Bubblewrap
                // equivalent, so shared validation must keep refusing it.
                NetworkPolicySupport::PROXY_PEER_IDENTITY,
                false,
                {
                    let mut request = base_request();
                    request.policy.allowed_proxy_peer = Some("Contoso.Proxy_123".to_string());
                    request
                },
                "processContainer.network.allowedProxyPeer",
                None,
            ),
        ];

        // A bit added to `ALL` but not categorized above fails here.
        let categorized = decisions
            .iter()
            .fold(NetworkPolicySupport::LEGACY, |acc, (bit, ..)| acc | *bit);
        assert!(
            categorized.contains(NetworkPolicySupport::ALL)
                && NetworkPolicySupport::ALL.contains(categorized),
            "a NetworkPolicySupport bit is missing from this table -- decide whether \
             Bubblewrap declares it, and prove that decision with a probe here"
        );

        let support = BubblewrapScriptRunner::new().network_policy_support();

        for (bit, declared, request, field, probe) in decisions {
            assert!(
                validate_network_policy_support(&request, NetworkPolicySupport::ALL).is_ok(),
                "the probe for {field} no longer reaches its gate, so it proves nothing"
            );
            assert_eq!(
                support.contains(bit),
                declared,
                "the declaration for {field} disagrees with this table"
            );

            match validate_network_policy_support(&request, support) {
                Ok(()) => assert!(declared, "{field} is accepted but recorded as undeclared"),
                Err(error) => {
                    assert!(
                        !declared,
                        "{field} is declared but was refused: {}",
                        error.error_message
                    );
                    assert!(
                        error.error_message.contains(field),
                        "the refusal for {field} names something else: {}",
                        error.error_message
                    );
                }
            }

            match (declared, probe) {
                (true, Some(probe)) => probe(&request)
                    .unwrap_or_else(|reason| panic!("{field} is over-declared: {reason}")),
                (true, None) => panic!(
                    "{field} is declared with no enforcement probe -- acceptance is not \
                     evidence that anything acts on the field"
                ),
                (false, Some(_)) => panic!(
                    "{field} is undeclared, so there is nothing for an enforcement probe \
                     to prove; the refusal assertion above already covers it"
                ),
                (false, None) => {}
            }
        }
    }

    #[test]
    fn the_firewall_manager_tolerates_the_veth_bubblewrap_never_has() {
        // bwrap never calls set_veth_interface, so the shared manager's
        // fail-closed path would refuse every firewall-mode sandbox at startup.
        // The manager this backend builds must therefore have declared the
        // absence up front.
        let mgr = build_firewall_manager("bwrap-cov");

        assert!(
            mgr.veth_scoping_is_optional(),
            "Bubblewrap has no veth, so the manager it builds must declare that a \
             missing one is expected -- otherwise firewall-mode sandboxes cannot start"
        );
    }

    #[test]
    fn validate_does_not_locally_gate_builtin_test_server() {
        // The builtinTestServer gate moved to `wxc_common::validator::validate_common`
        // (enforced centrally for every backend). The bwrap runner must therefore no
        // longer reject it locally — otherwise the gate would be applied twice with
        // diverging messages.
        let mut req = base_request();
        req.policy.network_proxy = ProxyConfig {
            address: None,
            builtin_test_server: true,
        };
        req.testing_features_enabled = false;

        let runner = BubblewrapScriptRunner::new();
        assert!(runner.validate(&req).is_ok());
    }

    /// Proxy-only mode rewrites the endpoint to slirp's gateway and opens
    /// exactly that address, so an endpoint neither step can express has to be
    /// refused at policy time -- before a proxy is started.
    #[test]
    fn validate_rejects_an_ipv6_loopback_proxy_endpoint_before_the_environment_probe() {
        let mut req = base_request();
        req.schema_version = "0.8.0-alpha".into();
        // An external proxy with the default 'block' would be refused earlier,
        // by the host-policy gate; this test is about the endpoint itself.
        req.policy.default_network_policy = wxc_common::models::NetworkPolicy::Allow;
        req.policy.network_proxy = ProxyConfig {
            address: Some(ProxyAddress::new("[::1]".into(), 3128)),
            builtin_test_server: false,
        };

        let runner = BubblewrapScriptRunner::new();
        let err = runner.validate(&req).unwrap_err();

        assert!(
            err.error_message.contains("IPv6 loopback"),
            "an endpoint the gateway cannot reach must be refused by validate: {}",
            err.error_message
        );
    }

    /// The runner-level twin of the proxy/directional conflict check.
    ///
    /// The helper has its own unit test, but nothing asserted that `validate`
    /// actually *calls* it: deleting the wiring left every test green while
    /// reopening the fail-open. This test fails if that call is removed.
    ///
    /// It also pins the ordering claim -- the refusal must land before the
    /// environmental `bwrap` probe, so a host without bwrap still reports the
    /// policy error rather than a missing binary.
    #[test]
    fn validate_rejects_a_directional_rule_set_combined_with_a_proxy() {
        use wxc_common::models::{NetworkAction, NetworkEgressPolicy, NetworkRule};

        let unhonorable = [
            NetworkEgressPolicy {
                default: NetworkAction::Allow,
                ..Default::default()
            },
            NetworkEgressPolicy {
                default: NetworkAction::Deny,
                allow: vec![NetworkRule::default()],
                ..Default::default()
            },
        ];

        for egress in unhonorable {
            for builtin in [false, true] {
                let mut req = base_request();
                req.schema_version = "0.8.0-alpha".into();
                req.policy.network_egress = Some(egress.clone());
                req.policy.network_proxy = ProxyConfig {
                    address: (!builtin).then(|| ProxyAddress::new("127.0.0.1".into(), 3128)),
                    builtin_test_server: builtin,
                };

                let err = BubblewrapScriptRunner::new().validate(&req).unwrap_err();
                assert_eq!(
                    err.error_message,
                    bwrap_command::BWRAP_PROXY_DIRECTIONAL_EGRESS,
                    "validate must refuse a proxy that would drop directional rules \
                     (builtin={builtin})"
                );
            }
        }
    }

    /// The proxy-only posture is the one directional shape a proxy may carry,
    /// so it must survive the guard above rather than being caught by it.
    #[test]
    fn validate_accepts_the_proxy_only_directional_posture() {
        use wxc_common::models::{NetworkAction, NetworkEgressPolicy};

        let mut req = base_request();
        req.schema_version = "0.8.0-alpha".into();
        req.policy.network_egress = Some(NetworkEgressPolicy {
            default: NetworkAction::Deny,
            ..Default::default()
        });
        req.policy.network_proxy = ProxyConfig {
            address: Some(ProxyAddress::new("127.0.0.1".into(), 3128)),
            builtin_test_server: false,
        };

        if let Err(err) = BubblewrapScriptRunner::new().validate(&req) {
            assert_ne!(
                err.error_message,
                bwrap_command::BWRAP_PROXY_DIRECTIONAL_EGRESS,
                "deny-with-no-rules is proxy-only egress and must pass this gate"
            );
        }
    }

    #[test]
    fn validate_rejects_a_routable_ipv6_proxy_endpoint_before_the_environment_probe() {
        // The egress rules are IPv4-only, so this endpoint could never be
        // opened -- `run` would discover that only after starting slirp.
        let mut req = base_request();
        req.schema_version = "0.8.0-alpha".into();
        req.policy.network_proxy = ProxyConfig {
            address: Some(ProxyAddress::new("2001:db8::1".into(), 3128)),
            builtin_test_server: false,
        };

        let runner = BubblewrapScriptRunner::new();
        let err = runner.validate(&req).unwrap_err();

        assert!(
            !err.error_message.contains("bwrap"),
            "the endpoint check must run ahead of the environment probe: {}",
            err.error_message
        );
    }

    /// The check is scoped to the private-namespace mode. A legacy-schema
    /// request shares the host's network, never translates the endpoint and
    /// installs no rules, so the same address must stay acceptable there --
    /// tightening it would break callers already on 0.6/0.7.
    #[test]
    fn validate_leaves_a_legacy_schema_proxy_endpoint_untouched() {
        let mut req = base_request();
        req.schema_version = "0.7.0-alpha".into();
        req.policy.network_proxy = ProxyConfig {
            address: Some(ProxyAddress::new("[::1]".into(), 3128)),
            builtin_test_server: false,
        };

        let runner = BubblewrapScriptRunner::new();
        let message = runner
            .validate(&req)
            .err()
            .map(|err| err.error_message)
            .unwrap_or_default();

        assert!(
            !message.contains("IPv6 loopback"),
            "legacy proxy mode does not translate the endpoint, so it must not \
             inherit the private-namespace rejection: {message}"
        );
    }

    /// The parser leaves a port-0 placeholder address on a `builtinTestServer`
    /// request; the real endpoint is only known once the server is started. The
    /// endpoint check must therefore skip it, or every builtin-proxy sandbox is
    /// rejected at validation with "requires a non-zero proxy port".
    #[test]
    fn validate_does_not_apply_the_endpoint_check_to_the_builtin_test_server() {
        let mut req = base_request();
        req.schema_version = "0.8.0-alpha".into();
        req.policy.network_proxy = ProxyConfig {
            address: Some(ProxyAddress::new("127.0.0.1".into(), 0)),
            builtin_test_server: true,
        };

        let runner = BubblewrapScriptRunner::new();
        let message = runner
            .validate(&req)
            .err()
            .map(|err| err.error_message)
            .unwrap_or_default();

        assert!(
            !message.contains("non-zero proxy port"),
            "the builtin proxy's placeholder port must not be validated as an \
             operator-supplied endpoint: {message}"
        );
    }

    /// A hostname endpoint is reached by pinning it over `/etc/hosts`, and the
    /// pin outranks every policy mount -- so a policy that denies the file must
    /// refuse the combination rather than silently hand the file back.
    #[test]
    fn validate_rejects_a_hostname_proxy_that_would_defeat_a_denied_hosts_file() {
        let mut req = base_request();
        req.schema_version = "0.8.0-alpha".into();
        req.policy.default_network_policy = wxc_common::models::NetworkPolicy::Allow;
        req.policy.denied_paths = vec!["/etc/hosts".into()];
        req.policy.network_proxy = ProxyConfig {
            address: Some(ProxyAddress::new("proxy.example.com".into(), 3128)),
            builtin_test_server: false,
        };

        let runner = BubblewrapScriptRunner::new();
        let err = runner.validate(&req).unwrap_err();

        assert!(
            err.error_message.contains("deniedPaths"),
            "the conflict must be refused at policy time: {}",
            err.error_message
        );
    }

    /// `validate` compares the denied paths as written, so a spelling that only
    /// becomes `/etc/hosts` after normalization slips past it. `spawn` builds
    /// the masks from the normalized list, so the mask lands on `/etc/hosts`
    /// and the pin -- spliced after every policy mount -- then hands the file
    /// back. Regression test: the check must also see the normalized policy.
    #[test]
    fn a_dotdot_spelling_of_a_denied_hosts_file_still_refuses_the_pin() {
        let mut req = base_request();
        req.schema_version = "0.8.0-alpha".into();
        req.policy.network_proxy = ProxyConfig {
            address: Some(ProxyAddress::new("proxy.example.com".into(), 3128)),
            builtin_test_server: false,
        };

        // As written, this matches nothing the check looks for.
        req.policy.denied_paths = vec!["/etc/../etc/hosts".into()];
        assert!(
            check_pin_against_denied_hosts(&req).is_ok(),
            "precondition: the written form is not recognized"
        );

        // Normalized -- what `spawn` actually builds the masks from.
        let mut normalized = req.clone();
        normalized.policy.denied_paths = vec!["/etc/hosts".into()];
        let err = check_pin_against_denied_hosts(&normalized)
            .expect_err("the normalized policy must refuse the pin");
        assert!(err.contains("deniedPaths"), "{err}");
    }

    /// The rejection is scoped to endpoints that actually produce a pin. An IP
    /// literal is reached without touching `/etc/hosts`, so denying the file
    /// stays compatible -- and that is the escape hatch the message offers.
    #[test]
    fn validate_accepts_an_ip_proxy_endpoint_alongside_a_denied_hosts_file() {
        let mut req = base_request();
        req.schema_version = "0.8.0-alpha".into();
        req.policy.denied_paths = vec!["/etc/hosts".into()];
        req.policy.network_proxy = ProxyConfig {
            address: Some(ProxyAddress::new("10.1.2.3".into(), 3128)),
            builtin_test_server: false,
        };

        let runner = BubblewrapScriptRunner::new();
        let message = runner
            .validate(&req)
            .err()
            .map(|err| err.error_message)
            .unwrap_or_default();

        assert!(
            !message.contains("deniedPaths"),
            "an endpoint that needs no pin must not inherit the rejection: {message}"
        );
    }

    /// A rule address the backend cannot enforce must be refused, not silently
    /// approximated. `validate` is the enforcement point rather than the parser
    /// because it runs ahead of every spawn, including the programmatic
    /// `mxc_engine` path that never sees the parser.
    #[test]
    fn validate_rejects_a_hostname_rule_address_at_0_8() {
        let mut req = base_request();
        req.schema_version = "0.8.0-alpha".into();
        req.policy.network_enforcement_mode = wxc_common::models::NetworkEnforcementMode::Firewall;
        req.policy.allowed_hosts = vec!["api.github.com".into()];

        let runner = BubblewrapScriptRunner::new();
        let message = runner
            .validate(&req)
            .err()
            .map(|err| err.error_message)
            .expect("a hostname rule address must be rejected");

        assert!(
            message.contains("api.github.com") && message.contains("not an IP address or CIDR"),
            "the rejection must name the offending entry and the reason: {message}"
        );
    }

    #[test]
    fn validate_accepts_literal_and_cidr_rule_addresses_at_0_8() {
        let mut req = base_request();
        req.schema_version = "0.8.0-alpha".into();
        req.policy.network_enforcement_mode = wxc_common::models::NetworkEnforcementMode::Firewall;
        req.policy.allowed_hosts = vec!["203.0.113.7".into(), "10.0.0.0/8".into()];
        req.policy.blocked_hosts = vec!["2001:db8::/32".into()];

        let runner = BubblewrapScriptRunner::new();
        let message = runner
            .validate(&req)
            .err()
            .map(|err| err.error_message)
            .unwrap_or_default();

        assert!(
            !message.contains("not an IP address or CIDR"),
            "literals and CIDRs must be accepted: {message}"
        );
    }

    /// The 0.8 gate must not reach back to callers already running on 0.6/0.7,
    /// whose host lists are hostnames by construction. Their runs still enforce
    /// nothing -- that is the pre-existing behavior this change deliberately
    /// leaves alone rather than the behavior it introduces.
    #[test]
    fn validate_leaves_a_pre_0_8_hostname_rule_address_untouched() {
        for version in ["0.6.0-alpha", "0.7.0-alpha"] {
            let mut req = base_request();
            req.schema_version = version.into();
            req.policy.network_enforcement_mode =
                wxc_common::models::NetworkEnforcementMode::Firewall;
            req.policy.allowed_hosts = vec!["api.github.com".into()];

            let runner = BubblewrapScriptRunner::new();
            let message = runner
                .validate(&req)
                .err()
                .map(|err| err.error_message)
                .unwrap_or_default();

            assert!(
                !message.contains("not an IP address or CIDR"),
                "schema {version} must keep parsing hostname rule addresses: {message}"
            );
        }
    }

    /// Legacy proxy mode shares the host's network, never translates the
    /// endpoint and never pins a name, so the same policy has to stay
    /// acceptable there -- rejecting it would break callers already on 0.6/0.7.
    #[test]
    fn validate_leaves_a_legacy_schema_hosts_denial_untouched() {
        let mut req = base_request();
        req.schema_version = "0.7.0-alpha".into();
        req.policy.denied_paths = vec!["/etc/hosts".into()];
        req.policy.network_proxy = ProxyConfig {
            address: Some(ProxyAddress::new("proxy.example.com".into(), 3128)),
            builtin_test_server: false,
        };

        let runner = BubblewrapScriptRunner::new();
        let message = runner
            .validate(&req)
            .err()
            .map(|err| err.error_message)
            .unwrap_or_default();

        assert!(
            !message.contains("deniedPaths"),
            "legacy proxy mode pins nothing, so it must not inherit the \
             private-namespace rejection: {message}"
        );
    }

    #[test]
    fn validate_rejects_an_unhonorable_local_network_request_at_0_8() {
        // defaultPolicy='allow' shares the host netns, so allowLocalNetwork
        // =false cannot be honored. Runs ahead of the bwrap probe, so this
        // holds on hosts without bwrap installed. Host lists are no longer a
        // vehicle for this: at 0.8 they resolve to a private namespace under
        // either enforcement mechanism.
        let mut req = base_request();
        req.schema_version = "0.8.0-alpha".into();
        req.policy.default_network_policy = wxc_common::models::NetworkPolicy::Allow;

        let err = BubblewrapScriptRunner::new().validate(&req).unwrap_err();
        assert!(
            err.error_message.contains("allowLocalNetwork=false"),
            "unexpected error: {}",
            err.error_message
        );
    }

    #[test]
    fn validate_rejects_local_network_under_a_private_netns_at_0_8() {
        // The other half of the local-network contract, and the one the
        // ingress chain depends on: IngressPlan maps allowLocalNetwork=true to
        // an inbound NEW ACCEPT, which is only unreachable because validate
        // refuses the combination. Without this test, relaxing the rejection
        // would silently open inbound rather than fail a build.
        let mut req = base_request();
        req.schema_version = "0.8.0-alpha".into();
        req.policy.network_enforcement_mode = NetworkEnforcementMode::Firewall;
        req.policy.allowed_hosts = vec!["10.0.2.2/32".into()];
        req.policy.allow_local_network = true;

        let err = BubblewrapScriptRunner::new().validate(&req).unwrap_err();
        assert!(
            err.error_message.contains("allowLocalNetwork=true"),
            "unexpected error: {}",
            err.error_message
        );
    }

    #[test]
    fn validate_accepts_the_same_request_before_0_8() {
        // Pre-0.8 warns at run time instead of failing, so existing callers are
        // unaffected. Tolerant of a host without bwrap: it only rules out the
        // local-network rejection.
        let mut req = base_request();
        req.schema_version = "0.7.0-alpha".into();
        req.policy.default_network_policy = wxc_common::models::NetworkPolicy::Allow;

        if let Err(err) = BubblewrapScriptRunner::new().validate(&req) {
            assert!(
                !err.error_message.contains("allowLocalNetwork"),
                "0.7 must not be rejected for allowLocalNetwork: {}",
                err.error_message
            );
        }
    }

    #[test]
    fn validate_accepts_firewall_enforced_host_rules_at_0_8() {
        // Firewall mode is the enforcement mechanism at 0.8, so the
        // unenforced-host-rules gate must not fire for it.
        let mut req = base_request();
        req.schema_version = "0.8.0-alpha".into();
        req.policy.network_enforcement_mode = NetworkEnforcementMode::Firewall;
        req.policy.allowed_hosts = vec!["10.0.2.2/32".into()];
        req.policy.allow_local_network = true;

        if let Err(err) = BubblewrapScriptRunner::new().validate(&req) {
            assert!(
                !err.error_message
                    .contains("require an enforcement mechanism"),
                "firewall mode enforces the lists: {}",
                err.error_message
            );
        }
    }

    #[test]
    fn validate_accepts_a_firewall_mode_request_before_0_8() {
        // GHCP consumes Bubblewrap on 0.6/0.7; the gate must not reach them.
        let mut req = base_request();
        req.schema_version = "0.7.0-alpha".into();
        req.policy.network_enforcement_mode = NetworkEnforcementMode::Firewall;
        req.policy.allowed_hosts = vec!["api.github.com".into()];
        req.policy.allow_local_network = true;

        if let Err(err) = BubblewrapScriptRunner::new().validate(&req) {
            assert!(
                !err.error_message.contains("enforcementMode"),
                "0.7 must not be rejected for enforcementMode: {}",
                err.error_message
            );
        }
    }

    #[test]
    fn validate_rejects_host_rules_no_mechanism_will_enforce_at_0_8() {
        // The gap this closes: host lists suppress --unshare-net, but under
        // 'capabilities' with no proxy nothing applies them, so a default-deny
        // policy ran with fully open egress on the host's namespace.
        let mut req = base_request();
        req.schema_version = "0.8.0-alpha".into();
        req.policy.default_network_policy = wxc_common::models::NetworkPolicy::Block;
        req.policy.allowed_hosts = vec!["api.github.com".into()];
        req.policy.allow_local_network = true;

        let err = BubblewrapScriptRunner::new().validate(&req).unwrap_err();
        assert!(
            err.error_message
                .contains("require an enforcement mechanism"),
            "unexpected error: {}",
            err.error_message
        );
    }

    #[test]
    fn validate_accepts_host_rules_when_a_proxy_enforces_them_at_0_8() {
        // The proxy is the mechanism, so the same lists are fine with one.
        let mut req = base_request();
        req.schema_version = "0.8.0-alpha".into();
        req.policy.blocked_hosts = vec!["evil.example.com".into()];
        req.policy.network_proxy = ProxyConfig {
            address: Some(ProxyAddress::new("127.0.0.1".into(), 3128)),
            builtin_test_server: false,
        };

        if let Err(err) = BubblewrapScriptRunner::new().validate(&req) {
            assert!(
                !err.error_message
                    .contains("require an enforcement mechanism"),
                "a proxy enforces the lists: {}",
                err.error_message
            );
        }
    }

    #[test]
    fn validate_accepts_host_rules_without_a_mechanism_before_0_8() {
        // GHCP consumes Bubblewrap on 0.6/0.7 with exactly this shape.
        let mut req = base_request();
        req.schema_version = "0.7.0-alpha".into();
        req.policy.default_network_policy = wxc_common::models::NetworkPolicy::Block;
        req.policy.allowed_hosts = vec!["api.github.com".into()];

        if let Err(err) = BubblewrapScriptRunner::new().validate(&req) {
            assert!(
                !err.error_message
                    .contains("require an enforcement mechanism"),
                "0.7 must not be rejected: {}",
                err.error_message
            );
        }
    }

    /// A malformed non-empty version cannot come from the parser, so it is a
    /// hand-built request; the typo must not buy pre-0.8 leniency.
    #[test]
    fn validate_rejects_unenforced_host_rules_with_a_malformed_version() {
        let mut req = base_request();
        req.schema_version = "0.8".into();
        req.policy.allowed_hosts = vec!["api.github.com".into()];
        req.policy.allow_local_network = true;

        let err = BubblewrapScriptRunner::new().validate(&req).unwrap_err();
        assert!(
            err.error_message
                .contains("require an enforcement mechanism"),
            "unexpected error: {}",
            err.error_message
        );
    }

    #[test]
    fn validate_rejects_empty_script_before_environment_probe() {
        // Empty script_code is a user-input error and must be surfaced
        // even on hosts without bwrap installed (independent of CI image).
        let mut req = base_request();
        req.script_code = String::new();

        let runner = BubblewrapScriptRunner::new();
        let err = runner.validate(&req).unwrap_err();
        assert!(err.error_message.contains("script_code is empty"));
    }

    #[test]
    fn validate_rejects_a_credential_bearing_proxy_url_before_the_environment_probe() {
        // The parser's credential guard only covers requests the parser built.
        // `ExecutionRequest` and `ProxyAddress::from_url` are both public, so a
        // caller can hand this runner a proxy URL the parser never saw --
        // `to_url` returns it verbatim and `build_args` turns it into a
        // `bwrap --setenv HTTP_PROXY <url>` argument, which any local user can
        // read out of /proc/<pid>/cmdline while the sandbox runs.
        //
        // Like the empty-script check this is user input, so it has to be
        // reported ahead of the bwrap probe: on a host with no bwrap installed
        // a later guard would return the probe's error instead of this one.
        let runner = BubblewrapScriptRunner::new();
        let err = runner
            .validate(&request_with_a_credential_bearing_proxy())
            .unwrap_err();

        assert!(
            err.error_message.contains("must not carry credentials"),
            "a credential-bearing proxy URL must be refused before it can reach \
             `bwrap --setenv`, but validate said: {}",
            err.error_message
        );
    }

    #[test]
    fn the_credential_rejection_does_not_repeat_the_password_it_rejects() {
        // An error message is logged and returned to the caller, so quoting the
        // URL verbatim would publish the secret the guard exists to protect.
        let runner = BubblewrapScriptRunner::new();
        let err = runner
            .validate(&request_with_a_credential_bearing_proxy())
            .unwrap_err();

        assert!(
            !err.error_message.contains("hunter2"),
            "the rejection leaked the password it was rejecting: {}",
            err.error_message
        );
    }

    /// A denied symlink pointing at a **directory** is rewritten to its canonical
    /// target so the mask lands on the real directory (bwrap cannot mount a mask
    /// over a symlink whose parent is bound). The resolved directory is
    /// classified as a `--tmpfs` (directory) mask, not a file mask.
    #[cfg(unix)]
    #[test]
    fn resolve_denied_paths_rewrites_symlink_to_dir() {
        use wxc_common::logger::{Logger, Mode};
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("real_dir");
        std::fs::create_dir(&target).unwrap();
        let link = dir.path().join("link_to_dir");
        std::os::unix::fs::symlink(&target, &link).unwrap();

        let policy = wxc_common::models::ContainerPolicy {
            denied_paths: vec![link.to_string_lossy().into_owned()],
            ..Default::default()
        };

        let mut logger = Logger::new(Mode::Buffer);
        let plan = resolve_denied_paths(&policy, &mut logger).expect("must not fail closed");
        let out = plan.paths.expect("symlink must be rewritten");
        let canonical = std::fs::canonicalize(&target).unwrap();
        let canonical = canonical.to_string_lossy().into_owned();
        assert_eq!(out, vec![canonical.clone()]);
        // The link path itself must no longer appear.
        assert!(!out.contains(&link.to_string_lossy().into_owned()));
        // A directory is masked with `--tmpfs`, so it is NOT a file-mask target.
        assert!(!plan.files.contains(&canonical));
    }

    /// A denied symlink pointing at a **file** is likewise rewritten to its
    /// target and classified as a `/dev/null` (file) mask.
    #[cfg(unix)]
    #[test]
    fn resolve_denied_paths_rewrites_symlink_to_file() {
        use wxc_common::logger::{Logger, Mode};
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("real_file.txt");
        std::fs::write(&target, b"secret").unwrap();
        let link = dir.path().join("link_to_file");
        std::os::unix::fs::symlink(&target, &link).unwrap();

        let policy = wxc_common::models::ContainerPolicy {
            denied_paths: vec![link.to_string_lossy().into_owned()],
            ..Default::default()
        };

        let mut logger = Logger::new(Mode::Buffer);
        let plan = resolve_denied_paths(&policy, &mut logger).expect("must not fail closed");
        let out = plan.paths.expect("symlink must be rewritten");
        let canonical = std::fs::canonicalize(&target).unwrap();
        let canonical = canonical.to_string_lossy().into_owned();
        assert_eq!(out, vec![canonical.clone()]);
        // A regular file is masked with `/dev/null`.
        assert!(plan.files.contains(&canonical));
    }

    /// A denied path whose **ancestor** directory is a symlink (not the leaf) is
    /// also rewritten to its real path — bwrap aborts on an ancestor symlink just
    /// as it does on a leaf symlink.
    #[cfg(unix)]
    #[test]
    fn resolve_denied_paths_rewrites_ancestor_symlink() {
        use wxc_common::logger::{Logger, Mode};
        let dir = tempfile::tempdir().unwrap();
        let base = std::fs::canonicalize(dir.path()).unwrap();
        let real = base.join("real");
        std::fs::create_dir_all(real.join("secret")).unwrap();
        let link = base.join("link");
        std::os::unix::fs::symlink(&real, &link).unwrap();

        // Deny .../link/secret — the leaf `secret` is a real dir, `link` is the
        // symlinked ancestor.
        let denied = link.join("secret");
        let policy = wxc_common::models::ContainerPolicy {
            denied_paths: vec![denied.to_string_lossy().into_owned()],
            ..Default::default()
        };

        let mut logger = Logger::new(Mode::Buffer);
        let plan = resolve_denied_paths(&policy, &mut logger).expect("must not fail closed");
        let out = plan.paths.expect("ancestor symlink must be rewritten");
        assert_eq!(
            out,
            vec![real.join("secret").to_string_lossy().into_owned()]
        );
    }

    /// An ancestor symlink with a **not-yet-created** leaf is resolved by
    /// canonicalizing the deepest existing ancestor and re-appending the missing
    /// tail (bwrap aborts here too, and `canonicalize` alone cannot resolve it).
    #[cfg(unix)]
    #[test]
    fn resolve_denied_paths_rewrites_ancestor_symlink_missing_leaf() {
        use wxc_common::logger::{Logger, Mode};
        let dir = tempfile::tempdir().unwrap();
        let base = std::fs::canonicalize(dir.path()).unwrap();
        let real = base.join("real");
        std::fs::create_dir(&real).unwrap();
        let link = base.join("link");
        std::os::unix::fs::symlink(&real, &link).unwrap();

        // Deny .../link/newfile — `newfile` does not exist yet.
        let denied = link.join("newfile");
        let policy = wxc_common::models::ContainerPolicy {
            denied_paths: vec![denied.to_string_lossy().into_owned()],
            ..Default::default()
        };

        let mut logger = Logger::new(Mode::Buffer);
        let plan = resolve_denied_paths(&policy, &mut logger).expect("must not fail closed");
        let out = plan
            .paths
            .expect("ancestor symlink must be rewritten even with a missing leaf");
        assert_eq!(
            out,
            vec![real.join("newfile").to_string_lossy().into_owned()]
        );
    }

    /// Regular files, directories, and missing paths with no symlink anywhere in
    /// the path are a no-op for rewriting (`paths` is `None`, avoiding an
    /// unnecessary clone), but are still classified: the file → `/dev/null`, the
    /// directory → `--tmpfs`.
    #[cfg(unix)]
    #[test]
    fn resolve_denied_paths_noop_for_non_symlinks() {
        use wxc_common::logger::{Logger, Mode};
        let dir = tempfile::tempdir().unwrap();
        // Canonicalize up front so a symlinked tempdir root (e.g. via TMPDIR)
        // doesn't spuriously trigger a rewrite — we are testing symlink-free paths.
        let base = std::fs::canonicalize(dir.path()).unwrap();
        let file = base.join("f.txt");
        std::fs::write(&file, b"x").unwrap();
        let subdir = base.join("d");
        std::fs::create_dir(&subdir).unwrap();
        let missing = base.join("does_not_exist");

        let policy = wxc_common::models::ContainerPolicy {
            denied_paths: vec![
                file.to_string_lossy().into_owned(),
                subdir.to_string_lossy().into_owned(),
                missing.to_string_lossy().into_owned(),
            ],
            ..Default::default()
        };

        let mut logger = Logger::new(Mode::Buffer);
        let plan = resolve_denied_paths(&policy, &mut logger).expect("must not fail closed");
        assert!(plan.paths.is_none());
        // Classification still happens on the no-rewrite path.
        assert!(plan.files.contains(&file.to_string_lossy().into_owned()));
        assert!(!plan.files.contains(&subdir.to_string_lossy().into_owned()));
    }

    /// A **dangling** symlink cannot be resolved to a real target, so it is kept
    /// as-is and file-masked (`/dev/null`), which bwrap tolerates over a symlink
    /// node. It must not be dropped and must not be directory-masked.
    #[cfg(unix)]
    #[test]
    fn resolve_denied_paths_masks_dangling_symlink_as_file() {
        use wxc_common::logger::{Logger, Mode};
        let dir = tempfile::tempdir().unwrap();
        let base = std::fs::canonicalize(dir.path()).unwrap();
        let link = base.join("dangling");
        std::os::unix::fs::symlink(base.join("nonexistent_target"), &link).unwrap();

        let policy = wxc_common::models::ContainerPolicy {
            denied_paths: vec![link.to_string_lossy().into_owned()],
            ..Default::default()
        };

        let mut logger = Logger::new(Mode::Buffer);
        let plan = resolve_denied_paths(&policy, &mut logger).expect("must not fail closed");
        // Nothing was rewritten (the target does not exist).
        assert!(plan.paths.is_none());
        // The dangling link is still masked, as a file.
        assert!(plan.files.contains(&link.to_string_lossy().into_owned()));
    }

    /// A denied path that traverses `..` under a symlinked ancestor with a
    /// missing intermediate directory must fold the `..` and resolve to the real
    /// target the kernel would reach. Regression test for a `..`-dropping bug
    /// that reconstructed a bystander target (`/real/missing/secret`) and left
    /// the real denied path (`/real/secret`) exposed.
    #[cfg(unix)]
    #[test]
    fn resolve_denied_paths_folds_dotdot_under_symlinked_ancestor() {
        use wxc_common::logger::{Logger, Mode};
        let dir = tempfile::tempdir().unwrap();
        let base = std::fs::canonicalize(dir.path()).unwrap();
        let real = base.join("real");
        std::fs::create_dir(&real).unwrap();
        let link = base.join("link");
        std::os::unix::fs::symlink(&real, &link).unwrap();

        // Deny .../link/missing/../secret — `missing` does not exist and the
        // `..` cancels it, so the real target is .../real/secret.
        let denied = link.join("missing").join("..").join("secret");
        let policy = wxc_common::models::ContainerPolicy {
            denied_paths: vec![denied.to_string_lossy().into_owned()],
            ..Default::default()
        };

        let mut logger = Logger::new(Mode::Buffer);
        let plan = resolve_denied_paths(&policy, &mut logger).expect("must not fail closed");
        let out = plan
            .paths
            .expect("`..` under a symlinked ancestor must be rewritten");
        assert_eq!(
            out,
            vec![real.join("secret").to_string_lossy().into_owned()],
            "`..` must fold so the mask targets the real denied path, not a bystander"
        );
    }
}
