// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! `BubblewrapScriptRunner` — executes scripts inside a Bubblewrap
//! namespace sandbox via the `bwrap` CLI.
//!
//! Bubblewrap uses Linux user namespaces to create an unprivileged sandbox.
//! The runner translates `ExecutionRequest` policy fields into `bwrap` CLI
//! arguments via [`crate::bwrap_common::bwrap_command::build_args`], then spawns `bwrap`
//! with stdout/stderr capture and optional timeout enforcement.
//!
//! Directional network rules are programmed inside a private namespace;
//! ruleless deny uses `--unshare-net` without additional network tooling.
//! A runtime proxy uses the private namespace and a caller-managed endpoint.

use std::collections::HashSet;
use std::fmt::Write as FmtWrite;
use std::os::fd::AsFd;
use std::os::unix::process::CommandExt;
use std::path::{Component, Path, PathBuf};
use std::process::{Child, ChildStdin, Command, ExitStatus, Stdio};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::{Duration, Instant};

use crate::mxc_common::interruptible_reader::{wrap_pipe, InterruptibleReader, ReadCanceller};
use crate::mxc_common::logger::Logger;
use crate::mxc_common::models::{ExecutionRequest, ScriptResponse};
use crate::mxc_common::sandbox_process::{
    boxed_closer, cancel_and_join_discard, duplicate_and_take_native_stdio, group_kill,
    spawn_discard, take_boxed_read, take_boxed_write, wait_with_timeout, NativeStdio, PtySize,
    SandboxBackend, SandboxProcess, StdioMode, StreamCloser, WaitError,
};
use crate::mxc_common::validator::{
    validate_common, validate_network_policy_support, NetworkPolicySupport,
};
use crate::mxc_pty::{LivePty, PtySize as UnixPtySize};

use crate::bwrap_common::{
    bwrap_command::{self, ResolvedNetworkMode},
    bwrap_version, network_rules,
    provider_monitor::ProviderMonitor,
    proxy_network,
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
    /// Bubblewrap programs directional policy into iptables chains in
    /// the sandbox's own network namespace, so it enforces the outbound default,
    /// the allow/deny rules, and both inbound fields.
    ///
    /// `INGRESS_DEFAULT` and `HOST_LOOPBACK` declare that the backend
    /// *understands* those fields, not that it honors both of their values:
    /// only the deny posture is reachable, and the allow posture is refused by
    /// `bwrap_command::directional_network_rejection` below. Declaring them
    /// without that refusal would be a fail-open, so the two belong together.
    ///
    /// `RUNTIME_PROXY` is declared because `runtimeConfig.networkProxy` is
    /// normalized into `policy.network_proxy` and enforced in a private
    /// namespace with only its pinned endpoint reachable.
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
        if let Some(plan) = egress_plan.as_ref() {
            warn_unreachable_v6_targets(plan, logger);
        }
        // Tighten aliases of the same host object to the strictest intent
        // (deny > ro > rw). Done here, close to mount, to minimize the TOCTOU
        // window; an unresolvable path with deniedPaths present fails closed.
        let normalized;
        let request = match crate::mxc_common::filesystem_object::normalize_object_conflicts(
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
        // Reject any policy path the invoking user cannot access, so the sandbox
        // never gains access the caller lacks. Runs after object normalization
        // so it sees the already-tightened intents.
        if let Err(msg) = crate::mxc_common::filesystem_access::check_delegation(&request.policy) {
            return Err(ScriptResponse::error(&msg));
        }
        // Resolve denied paths that traverse a symlink to their real host path
        // and classify each as a file/dir mask (see [`resolve_denied_paths`]).
        // Only clones the request when a path needs rewriting (common case:
        // none). See docs/backends/bwrap/bubblewrap-backend.md.
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
        // Execution validation deliberately bypasses the advisory success
        // cache: a prior platform-support query must not approve a different
        // executable after `PATH` or its contents change.
        self.validate_prepared_with_probe(request, bwrap_version::probe_bwrap_uncached)
    }

    /// `validate_prepared` with an injectable environment probe.
    ///
    /// Tests use this to assert that user-input validation runs *before* the
    /// environmental `bwrap` probe, and to drive every probe failure without
    /// depending on what the host happens to have installed.
    fn validate_prepared_with_probe<F>(
        &self,
        request: &ExecutionRequest,
        probe: F,
    ) -> Result<Option<network_rules::EgressPlan>, ScriptResponse>
    where
        F: FnOnce() -> Result<bwrap_version::BwrapVersion, bwrap_version::BwrapUnavailable>,
    {
        validate_network_policy_support(request, self.network_policy_support())?;

        // User-input validation runs before the environmental `bwrap`
        // probe so config errors are reported deterministically even on
        // hosts without bwrap installed.
        if request.script_code.is_empty() {
            return Err(ScriptResponse::error(
                "script_code is empty — nothing to execute.",
            ));
        }

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
            if crate::mxc_common::proxy_env::proxy_url_has_credentials(&url) {
                // Built from the redacted form so the rejection cannot become
                // the leak it is rejecting.
                return Err(ScriptResponse::error(&format!(
                    "Bubblewrap: runtimeConfig.networkProxy must not carry credentials ('{}'). \
                     Bubblewrap passes the proxy URL to bwrap as a --setenv command-line \
                     argument, and process arguments are world-readable through \
                     /proc/<pid>/cmdline, so the password would be visible to every local \
                     user while the command runs. Use a proxy that does not require inline \
                     credentials, or supply them to the proxy itself rather than through \
                     the URL.",
                    crate::mxc_common::proxy_env::redact_proxy_url(&url)
                )));
            }
        }

        // Programmatic requests also need the parser's proxy-only restriction:
        // direct egress must not be accepted and then discarded at launch.
        if let Some(reason) = bwrap_command::proxy_with_egress_rejection(request) {
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
        let proxy_only =
            ResolvedNetworkMode::from_request(request, request.policy.network_proxy.is_enabled())
                == ResolvedNetworkMode::ProxyOnly;
        if proxy_only {
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

        // Validate direct CIDR/port rules before any environment probe or
        // provisioning; reuse precisely this plan at spawn.
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
        if let Err(err) = probe() {
            return Err(ScriptResponse::error(&err.to_string()));
        }
        if proxy_only || firewall_enforced {
            // Proxy and firewall are mutually exclusive, so this names the one
            // the caller actually asked for.
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
    if !proxy_only {
        return Ok(());
    }
    match request.policy.network_proxy.address.as_ref() {
        Some(address) => proxy_network::check_hosts_pin_against_policy(address, &request.policy),
        None => Ok(()),
    }
}

/// Warn that an IPv6 allow rule installs but cannot carry traffic.
///
/// It fails closed, so this warns rather than rejects: refusing would break
/// configs the schema accepts today (see #955). Emitted from `spawn`, which has
/// a logger and which every caller reaches, so the JSON and programmatic paths
/// both hear it from one site.
///
/// Uses [`Logger::warning_line`], not `log_line`: it is the only sink both
/// paths actually read. `log_line` lands in the console/debug buffer, which
/// `mxc_engine::spawn_execution_request` never folds into `Output::warnings` and which
/// `lxc-exec` prints only on an error path (and only under `--debug`, onto
/// stdout, where it would interleave with the workload's own output).
fn warn_unreachable_v6_targets(plan: &network_rules::EgressPlan, logger: &mut Logger) {
    let targets = plan.allowed_v6_targets();
    if targets.is_empty() {
        return;
    }
    logger.warning_line(&format!(
        "WARNING: Bubblewrap allows {} IPv6 destination(s) ({}), but the sandbox \
         namespace has no IPv6 connectivity: slirp4netns is launched without \
         '--enable-ipv6', so these rules install and are never traversed. The \
         destination stays unreachable despite the rule. Use an IPv4 address, or \
         runtimeConfig.networkProxy, if the workload needs to reach it.",
        targets.len(),
        targets.join(", ")
    ));
}

impl BubblewrapScriptRunner {
    /// Set up networking and spawn `bwrap`, returning a [`BwrapChild`] wrapped
    /// by the [`SandboxProcess`] handle. With [`StdioMode::Pipes`] the child's
    /// stdio is piped (the caller drives it); with [`StdioMode::Inherit`] it
    /// inherits the binary's stdio (a TTY when the binary has one); with
    /// [`StdioMode::Pty`] it is attached to a caller-owned Unix PTY.
    fn spawn_bwrap(
        &self,
        request: &ExecutionRequest,
        denied_files: &HashSet<String>,
        egress_plan: Option<network_rules::EgressPlan>,
        logger: &mut Logger,
        stdio: StdioMode,
    ) -> Result<BwrapChild, ScriptResponse> {
        // The caller manages the proxy; pass its address into the sandbox
        // environment and restrict direct egress to that endpoint.
        let configured_proxy = request.policy.network_proxy.address.as_ref();
        if let Some(address) = configured_proxy {
            logger.log_line(&format!(
                "Unix network proxy active: {}",
                crate::mxc_common::proxy_env::redact_proxy_url(&address.to_url())
            ));
        }

        let network_mode = ResolvedNetworkMode::from_request(request, configured_proxy.is_some());
        let sandbox_proxy = if network_mode == ResolvedNetworkMode::ProxyOnly {
            let address = configured_proxy.ok_or_else(|| {
                ScriptResponse::error(
                    "Bubblewrap: proxy mode was selected without a resolved proxy address.",
                )
            })?;
            Some(
                proxy_network::SandboxProxy::resolve(address)
                    .map_err(|error| ScriptResponse::error(&error))?,
            )
        } else {
            None
        };
        let proxy_address = sandbox_proxy
            .as_ref()
            .map(|resolved| resolved.address())
            .or(configured_proxy);

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
                    Err(error) => return Err(ScriptResponse::error(&error)),
                }
            }
            // Direct directional egress uses the same private namespace.
            None if network_mode == ResolvedNetworkMode::FirewallEnforced => {
                // Reuse the validated plan. It is derived from network policy
                // only, which the filesystem normalization between the two
                // points cannot touch. Recompute only if the resolved mode
                // disagrees with validation's pre-spawn proxy reading.
                let plan = match egress_plan {
                    Some(plan) => plan,
                    None => match network_rules::EgressPlan::for_request(request) {
                        Ok(plan) => plan,
                        Err(error) => return Err(ScriptResponse::error(&error)),
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
                    Err(error) => return Err(ScriptResponse::error(&error)),
                }
            }
            None => None,
        };

        // 2. Build the bwrap argument vector. `denied_files` is the file-mask
        //    subset classified during symlink resolution (see
        //    [`resolve_denied_paths`]).
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

        // 3. Spawn `bwrap`.
        let mut command = Command::new("bwrap");
        command.args(&args);
        let pty = match stdio {
            StdioMode::Pipes => {
                command
                    .stdin(Stdio::piped())
                    .stdout(Stdio::piped())
                    .stderr(Stdio::piped());
                None
            }
            StdioMode::Inherit => {
                // The child (bwrap) inherits the binary's stdio directly — a
                // TTY when the binary has one.
                command
                    .stdin(Stdio::inherit())
                    .stdout(Stdio::inherit())
                    .stderr(Stdio::inherit());
                None
            }
            StdioMode::Pty(size) => match LivePty::attach(
                &mut command,
                UnixPtySize {
                    rows: size.rows,
                    cols: size.cols,
                    pixel_width: size.pixel_width,
                    pixel_height: size.pixel_height,
                },
                &[],
            ) {
                Ok(pty) => Some(pty),
                Err(error) => {
                    stop_proxy_network(&mut proxy_network, logger);
                    return Err(ScriptResponse::error(&format!(
                        "Bubblewrap: failed to allocate PTY: {error}"
                    )));
                }
            },
        };
        // Pipes and PTY modes put bwrap in its own process group so a timeout
        // or `kill()` can tree-kill it without touching the host's group.
        // Inherit mode keeps bwrap in the executor's group (so it retains the
        // controlling terminal); `--die-with-parent` takes its sandbox down.
        let group = stdio != StdioMode::Inherit;
        if stdio == StdioMode::Pipes {
            command.process_group(0);
        }
        if let Some(startup) = network_startup.as_ref() {
            startup.prepare_command(&mut command);
        }

        let mut child = match command.spawn() {
            Ok(process) => process,
            Err(error) => {
                stop_proxy_network(&mut proxy_network, logger);
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
                    let network = proxy_network.as_mut().ok_or_else(|| {
                        "Bubblewrap: proxy network lifecycle disappeared during startup".to_string()
                    })?;
                    network.attach(child_pid, logger)?;
                    network.check_alive()
                })
                .and_then(|()| startup.release());
            if let Err(error) = startup_result {
                let _ = child.kill();
                let _ = child.wait();
                stop_proxy_network(&mut proxy_network, logger);
                return Err(ScriptResponse::error(&error));
            }
        }

        let (stdin, stdout, stderr) = match stdio {
            StdioMode::Pipes => (child.stdin.take(), child.stdout.take(), child.stderr.take()),
            StdioMode::Inherit => (None, None, None),
            StdioMode::Pty(_) => (None, None, None),
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
                    stop_proxy_network(&mut proxy_network, logger);
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
        let started = Instant::now();

        let child = Arc::new(Mutex::new(child));
        // Armed only now: until the gate was released a dead provider surfaced
        // as a startup failure instead.
        let monitor = proxy_network
            .as_mut()
            .and_then(|network| network.take_liveness_watch())
            .map(|watch| ProviderMonitor::watch(watch, Arc::clone(&child), group));

        Ok(BwrapChild {
            child,
            stdin,
            stdout,
            stderr,
            stdout_canceller,
            stderr_canceller,
            pty,
            group,
            proxy_network,
            monitor,
            timeout,
            started,
            timed_out: false,
            termination_error: None,
        })
    }
}

/// A spawned `bwrap` sandbox: the child process, its parent-side pipe ends,
/// and the per-run private network state torn down once it exits.
struct BwrapChild {
    /// The lock is what keeps [`ProviderMonitor`]'s thread from signalling a
    /// pid this side has already reaped.
    child: Arc<Mutex<Child>>,
    stdin: Option<ChildStdin>,
    stdout: Option<InterruptibleReader>,
    stderr: Option<InterruptibleReader>,
    /// Cancellers for the stdout/stderr reads, kept so the `SandboxProcess`
    /// closers can mint a [`StreamCloser`] even after the stream is taken.
    stdout_canceller: Option<ReadCanceller>,
    stderr_canceller: Option<ReadCanceller>,
    pty: Option<LivePty>,
    /// `true` when bwrap leads its own process group (`Pipes` or `Pty`), so
    /// termination signals the whole group; `false` for `Inherit` mode, where
    /// killing bwrap relies on `--die-with-parent` to take the sandbox with it.
    group: bool,
    proxy_network: Option<proxy_network::ProxyNetworkNamespace>,
    monitor: Option<ProviderMonitor>,
    timeout: Option<Duration>,
    started: Instant,
    timed_out: bool,
    termination_error: Option<String>,
}

impl BwrapChild {
    fn lock_child(&self) -> MutexGuard<'_, Child> {
        self.child.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Tear down per-run private network state.
    fn cleanup(&mut self, logger: &mut Logger) {
        // Stopping the supervisor closes the descriptor the monitor watches, so
        // disarming first is what keeps a normal teardown from reading as a
        // provider that died.
        self.monitor.take();
        if let Some(mut network) = self.proxy_network.take() {
            network.stop(logger);
        }
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
        let mut logger = Logger::new(crate::mxc_common::logger::Mode::Buffer);
        self.inner.cleanup(&mut logger);
    }

    fn provider_lost(&self) -> bool {
        self.inner
            .monitor
            .as_ref()
            .is_some_and(ProviderMonitor::provider_lost)
    }

    /// Wait for the sandbox to exit, its deadline to pass, or its network
    /// provider to disappear.
    fn await_outcome(&mut self) -> BwrapOutcome {
        const MIN_POLL: Duration = Duration::from_millis(1);
        const MAX_POLL: Duration = Duration::from_millis(50);

        let deadline = self
            .inner
            .timeout
            .map(|timeout| self.inner.started + timeout);
        let mut interval = MIN_POLL;
        loop {
            let exited = match self.inner.lock_child().try_wait() {
                Ok(exited) => exited,
                Err(error) => return BwrapOutcome::Io(error),
            };
            // Checked after the exit rather than before it: the monitor kills
            // the sandbox, so a provider death shows up here as an ordinary
            // exit that would otherwise be reported as the workload's own.
            if self.provider_lost() {
                return BwrapOutcome::ProviderLost;
            }
            if let Some(status) = exited {
                return BwrapOutcome::Exited(status);
            }

            let now = Instant::now();
            let mut nap = interval;
            if let Some(deadline) = deadline {
                if now >= deadline {
                    return BwrapOutcome::Timeout;
                }
                nap = nap.min(deadline - now);
            }
            std::thread::sleep(nap);
            interval = (interval * 2).min(MAX_POLL);
        }
    }

    fn lost_provider_message(&mut self) -> String {
        match self.inner.proxy_network.as_mut() {
            Some(network) => network.lost_provider_detail(),
            None => "Bubblewrap: the sandbox lost its network provider while the workload \
                     was running"
                .to_string(),
        }
    }
}

/// How a `bwrap` run ended.
enum BwrapOutcome {
    Exited(ExitStatus),
    Timeout,
    ProviderLost,
    Io(std::io::Error),
}

impl SandboxProcess for BubblewrapSandboxProcess {
    fn take_native_stdio(&mut self) -> std::io::Result<Option<NativeStdio>> {
        if let Some(pty) = self.inner.pty.as_ref() {
            let stdio = pty.take_native_stdio()?;
            return Ok(Some(NativeStdio {
                stdin: Some(stdio.stdin),
                stdout: Some(stdio.stdout),
                stderr: None,
            }));
        }
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

    fn is_pty(&self) -> bool {
        self.inner.pty.is_some()
    }

    fn pty_clone_reader(&self) -> std::io::Result<Box<dyn std::io::Read + Send>> {
        self.inner
            .pty
            .as_ref()
            .ok_or_else(|| std::io::Error::other("Bubblewrap process has no PTY"))?
            .try_clone_reader()
    }

    fn pty_clone_reader_with_closer(
        &self,
    ) -> std::io::Result<crate::mxc_common::sandbox_process::PtyReaderWithCloser> {
        let (reader, closer) = self
            .inner
            .pty
            .as_ref()
            .ok_or_else(|| std::io::Error::other("Bubblewrap process has no PTY"))?
            .try_clone_reader_with_canceller()?;
        Ok((reader, Some(Box::new(closer))))
    }

    fn pty_take_writer(&self) -> std::io::Result<Box<dyn std::io::Write + Send>> {
        self.inner
            .pty
            .as_ref()
            .ok_or_else(|| std::io::Error::other("Bubblewrap process has no PTY"))?
            .take_writer()
    }

    fn pty_resize(&self, size: PtySize) -> std::io::Result<()> {
        self.inner
            .pty
            .as_ref()
            .ok_or_else(|| std::io::Error::other("Bubblewrap process has no PTY"))?
            .resize(UnixPtySize {
                rows: size.rows,
                cols: size.cols,
                pixel_width: size.pixel_width,
                pixel_height: size.pixel_height,
            })
    }

    fn pty_size(&self) -> std::io::Result<PtySize> {
        let size = self
            .inner
            .pty
            .as_ref()
            .ok_or_else(|| std::io::Error::other("Bubblewrap process has no PTY"))?
            .size();
        Ok(PtySize {
            rows: size.rows,
            cols: size.cols,
            pixel_width: size.pixel_width,
            pixel_height: size.pixel_height,
        })
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
        if let Some(error) = self.inner.termination_error.as_ref() {
            return Err(std::io::Error::other(error.clone()));
        }
        if self.inner.timed_out {
            return Err(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "Bubblewrap: script timed out",
            ));
        }
        if let Some(status) = self.inner.lock_child().try_wait()? {
            return Ok(Some(status.code().unwrap_or(-1)));
        }
        if self
            .inner
            .timeout
            .is_some_and(|timeout| self.inner.started.elapsed() >= timeout)
        {
            if let Err(error) = self.kill_for_timeout() {
                let error = format!(
                    "Bubblewrap: script timed out, and the process group could not be terminated: \
                     {error}"
                );
                self.inner.termination_error = Some(error.clone());
                return Err(std::io::Error::other(error));
            }
            self.inner.timed_out = true;
            return Err(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "Bubblewrap: script timed out",
            ));
        }
        Ok(None)
    }

    fn id(&self) -> u32 {
        self.inner.lock_child().id()
    }

    fn kill(&mut self) -> std::io::Result<()> {
        // No-op once the child has exited and been reaped: its pid/pgid can be
        // recycled, so signaling it could hit an unrelated process (group). A
        // reaped `Child` returns its cached status here without a syscall.
        let mut child = self.inner.lock_child();
        if child.try_wait()?.is_some() {
            return Ok(());
        }
        if self.inner.group {
            // Pipes and PTY modes give bwrap its own process group.
            group_kill(&mut child)
        } else {
            // Inherit mode: bwrap shares the executor's group (no
            // `process_group(0)`), so a group-kill would hit the executor.
            // Killing bwrap alone suffices because `--die-with-parent` makes
            // the sandbox die with it — bwrap is *not* pid 1 of the namespace
            // (it forks), so without that flag descendants would survive.
            child.kill()
        }
    }

    fn kill_for_timeout(&mut self) -> std::io::Result<()> {
        const REAP_TIMEOUT: Duration = Duration::from_secs(5);

        self.kill()?;
        let mut child = self.inner.lock_child();
        match wait_with_timeout(&mut child, Some(REAP_TIMEOUT)) {
            Ok(_) => {
                drop(child);
                self.inner.timed_out = true;
                Ok(())
            }
            Err(WaitError::Timeout) => Err(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "Bubblewrap: killed process did not become reapable within 5 seconds",
            )),
            Err(WaitError::Io(error)) => Err(error),
        }
    }

    fn wait(&mut self) -> std::io::Result<i32> {
        // Close our copy of any not-taken stdin so the child sees EOF.
        self.inner.stdin.take();
        if let Some(pty) = self.inner.pty.as_ref() {
            pty.close_writer();
        }

        // Drain (and discard) any not-taken stdout/stderr concurrently so the
        // child can't block on a full pipe (taken streams are the caller's
        // responsibility).
        let stdout_thread = spawn_discard(self.inner.stdout.take());
        let stderr_thread = spawn_discard(self.inner.stderr.take());
        let (pty_thread, pty_canceller, pty_setup_error) = match self.inner.pty.as_ref() {
            Some(pty) => match pty.take_unclaimed_reader() {
                Ok(Some((reader, canceller))) => {
                    (spawn_discard(Some(reader)), Some(canceller), None)
                }
                Ok(None) => (None, None, None),
                Err(error) => (None, None, Some(error)),
            },
            None => (None, None, None),
        };

        let result = if let Some(error) = pty_setup_error {
            let _ = self.kill();
            {
                let mut child = self.inner.lock_child();
                let _ = wait_with_timeout(&mut child, Some(Duration::from_secs(5)));
            }
            Err(std::io::Error::other(format!(
                "Bubblewrap: failed to prepare PTY output draining: {error}"
            )))
        } else if let Some(error) = self.inner.termination_error.as_ref() {
            Err(std::io::Error::other(error.clone()))
        } else if self.inner.timed_out {
            Err(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "Bubblewrap: script timed out",
            ))
        } else {
            match self.await_outcome() {
                BwrapOutcome::Exited(status) => Ok(status.code().unwrap_or(-1)),
                BwrapOutcome::ProviderLost => {
                    let _ = self.kill();
                    let _ = self.inner.lock_child().wait();
                    Err(std::io::Error::other(self.lost_provider_message()))
                }
                BwrapOutcome::Timeout => {
                    // Tree-kill so descendants die too and release any stdout/stderr
                    // pipe write-ends (else the drain threads below could block).
                    // `kill()` group-kills in Pipes mode; in Inherit mode it kills
                    // bwrap, which `--die-with-parent` turns into a full teardown.
                    if let Err(error) = self.kill_for_timeout() {
                        let error =
                            format!("Bubblewrap: script timed out, and teardown failed: {error}");
                        self.inner.termination_error = Some(error.clone());
                        Err(std::io::Error::other(error))
                    } else {
                        self.inner.timed_out = true;
                        Err(std::io::Error::new(
                            std::io::ErrorKind::TimedOut,
                            "Bubblewrap: script timed out",
                        ))
                    }
                }
                BwrapOutcome::Io(error) => {
                    // The child may still be alive; kill+reap it before
                    // `run_teardown()` removes the iptables/proxy enforcement out
                    // from under it.
                    let _ = self.kill();
                    let _ = self.inner.lock_child().wait();
                    Err(std::io::Error::other(format!(
                        "Bubblewrap: wait failed: {error}"
                    )))
                }
            }
        };

        cancel_and_join_discard(stdout_thread, &self.inner.stdout_canceller);
        cancel_and_join_discard(stderr_thread, &self.inner.stderr_canceller);
        if let Some(pty) = self.inner.pty.as_ref() {
            pty.finish_native_bridge();
        }
        cancel_and_join_discard(pty_thread, &pty_canceller);
        self.run_teardown();
        result
    }
}

impl Drop for BubblewrapSandboxProcess {
    fn drop(&mut self) {
        // Disarmed first so the monitor cannot be holding the child lock while
        // the reap below waits on it.
        self.inner.monitor.take();
        // Kill and reap the child *before* removing network enforcement —
        // otherwise an abandoned-but-running sandbox would keep egressing after
        // its iptables/proxy rules were torn down, and the child would leak as
        // a zombie. `kill()` group-kills in `Pipes` mode and relies on
        // `--die-with-parent` otherwise, then we reap.
        let _ = self.kill();
        let _ = self.inner.lock_child().wait();
        self.run_teardown();
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
    policy: &crate::mxc_common::models::ContainerPolicy,
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
    use crate::mxc_common::models::{ProxyAddress, ProxyConfig};

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
        use crate::mxc_common::models::{NetworkAction, NetworkEgressPolicy, NetworkIngressPolicy};

        use crate::bwrap_common::bwrap_command::{
            BWRAP_HOST_LOOPBACK_ALLOW, BWRAP_INGRESS_DEFAULT_ALLOW,
        };

        let runner = BubblewrapScriptRunner::new();
        let support = runner.network_policy_support();

        for (default, host_loopback) in [
            (NetworkAction::Allow, NetworkAction::Deny),
            (NetworkAction::Deny, NetworkAction::Allow),
        ] {
            let mut request = base_request();
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
        use crate::mxc_common::models::{
            NetworkAction, NetworkEgressPolicy, NetworkIngressPolicy, NetworkRule,
        };

        use crate::bwrap_common::network_rules::{
            render_filter_payloads, EgressPlan, IngressPlan, RuleFamily,
        };

        // A directional posture makes the gates that key off it fire. Both
        // sections are always set, because that is the only shape the parser
        // produces (`apply_directional_network` fills them in together).
        fn directional() -> ExecutionRequest {
            let mut request = base_request();
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
            if crate::bwrap_common::bwrap_command::proxy_with_egress_rejection(request).is_some() {
                return Err(
                    "the runtime-proxy shape is refused before it reaches the proxy".into(),
                );
            }
            must_differ(
                "the proxy address",
                crate::bwrap_common::bwrap_command::build_args(request, Some(&address)),
                crate::bwrap_common::bwrap_command::build_args(request, None),
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
                // The normalized runtime proxy reaches the private-namespace
                // proxy-only enforcement path.
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
            .fold(NetworkPolicySupport::default(), |acc, (bit, ..)| acc | *bit);
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
    fn an_ipv6_allow_warns_that_it_cannot_carry_traffic() {
        use crate::mxc_common::models::{NetworkEgressPolicy, NetworkPeer, NetworkRule};

        let allow = |cidr: &str| NetworkRule {
            to: vec![NetworkPeer {
                cidr: cidr.parse().expect("test CIDR"),
                except: vec![],
            }],
            ports: vec![],
        };
        let mut req = base_request();
        req.policy.network_egress = Some(NetworkEgressPolicy {
            allow: vec![allow("2001:db8::1/128"), allow("203.0.113.5/32")],
            ..Default::default()
        });
        let plan =
            network_rules::EgressPlan::for_request(&req).expect("both literals are enforceable");

        let mut logger = Logger::new(crate::mxc_common::logger::Mode::Buffer);
        warn_unreachable_v6_targets(&plan, &mut logger);
        let out = logger.warnings().join("\n");
        assert!(
            out.contains("2001:db8::1/128"),
            "must name the v6 target: {out}"
        );
        assert!(
            !out.contains("203.0.113.5"),
            "must not name the reachable v4 target: {out}"
        );
        // The retained-warning channel is the point: the debug buffer is not
        // read back by `mxc_engine::spawn_execution_request`, so a warning left
        // there is silent.
        assert!(
            logger.get_buffer().is_empty(),
            "the warning must travel as a retained warning, not as buffer output"
        );

        // Nothing unreachable, nothing to say.
        let mut v4_only = base_request();
        v4_only.policy.network_egress = Some(NetworkEgressPolicy {
            allow: vec![allow("203.0.113.5/32")],
            ..Default::default()
        });
        let plan =
            network_rules::EgressPlan::for_request(&v4_only).expect("a v4 literal is enforceable");
        let mut logger = Logger::new(crate::mxc_common::logger::Mode::Buffer);
        warn_unreachable_v6_targets(&plan, &mut logger);
        assert!(logger.warnings().is_empty(), "no v6 allow, no warning");
    }

    /// Proxy-only mode rewrites the endpoint to slirp's gateway and opens
    /// exactly that address, so an endpoint neither step can express has to be
    /// refused at policy time -- before a proxy is started.
    #[test]
    fn validate_rejects_an_ipv6_loopback_proxy_endpoint_before_the_environment_probe() {
        use crate::mxc_common::models::NetworkEgressPolicy;

        let mut req = base_request();
        req.policy.network_egress = Some(NetworkEgressPolicy::default());
        req.policy.network_proxy = ProxyConfig {
            address: Some(ProxyAddress::new("[::1]".into(), 3128)),
        };

        let runner = BubblewrapScriptRunner::new();
        let err = runner
            .validate_prepared_with_probe(&req, || {
                panic!("an invalid endpoint must be rejected before probing bwrap")
            })
            .unwrap_err();

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
        use crate::mxc_common::models::{NetworkAction, NetworkEgressPolicy, NetworkRule};

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
            let mut req = base_request();
            req.policy.network_egress = Some(egress);
            req.policy.network_proxy.address = Some(ProxyAddress::new("127.0.0.1".into(), 3128));
            let err = BubblewrapScriptRunner::new()
                .validate_prepared_with_probe(&req, || panic!("policy must fail before probe"))
                .unwrap_err();
            assert_eq!(
                err.error_message,
                bwrap_command::BWRAP_PROXY_DIRECTIONAL_EGRESS
            );
        }
    }

    /// The proxy-only posture is the one directional shape a proxy may carry,
    /// so it must survive the guard above rather than being caught by it.
    #[test]
    fn validate_accepts_the_proxy_only_directional_posture() {
        use crate::mxc_common::models::{NetworkAction, NetworkEgressPolicy};

        let mut req = base_request();
        req.policy.network_egress = Some(NetworkEgressPolicy {
            default: NetworkAction::Deny,
            ..Default::default()
        });
        req.policy.network_proxy = ProxyConfig {
            address: Some(ProxyAddress::new("127.0.0.1".into(), 3128)),
        };

        let unavailable = bwrap_version::BwrapUnavailable::NotFound;
        let expected = unavailable.to_string();
        let err = BubblewrapScriptRunner::new()
            .validate_prepared_with_probe(&req, || Err(unavailable))
            .unwrap_err();
        assert_eq!(err.error_message, expected);
    }

    #[test]
    fn validate_rejects_a_routable_ipv6_proxy_endpoint_before_the_environment_probe() {
        use crate::mxc_common::models::NetworkEgressPolicy;

        // The egress rules are IPv4-only, so this endpoint could never be
        // opened -- `run` would discover that only after starting slirp.
        let mut req = base_request();
        req.policy.network_egress = Some(NetworkEgressPolicy::default());
        req.policy.network_proxy = ProxyConfig {
            address: Some(ProxyAddress::new("2001:db8::1".into(), 3128)),
        };

        let runner = BubblewrapScriptRunner::new();
        let err = runner
            .validate_prepared_with_probe(&req, || {
                panic!("an invalid endpoint must be rejected before probing bwrap")
            })
            .unwrap_err();

        assert!(
            err.error_message.contains("IPv4 proxy endpoint"),
            "the endpoint check must explain the unsupported IPv6 address: {}",
            err.error_message
        );
    }

    /// A hostname endpoint is reached by pinning it over `/etc/hosts`, and the
    /// pin outranks every policy mount -- so a policy that denies the file must
    /// refuse the combination rather than silently hand the file back.
    #[test]
    fn validate_rejects_a_hostname_proxy_that_would_defeat_a_denied_hosts_file() {
        use crate::mxc_common::models::NetworkEgressPolicy;

        let mut req = base_request();
        req.policy.network_egress = Some(NetworkEgressPolicy::default());
        req.policy.denied_paths = vec!["/etc/hosts".into()];
        req.policy.network_proxy = ProxyConfig {
            address: Some(ProxyAddress::new("proxy.example.com".into(), 3128)),
        };

        let runner = BubblewrapScriptRunner::new();
        let err = runner
            .validate_prepared_with_probe(&req, || {
                panic!("a denied hosts file must be rejected before probing bwrap")
            })
            .unwrap_err();

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
        req.policy.network_proxy = ProxyConfig {
            address: Some(ProxyAddress::new("proxy.example.com".into(), 3128)),
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
        use crate::mxc_common::models::NetworkEgressPolicy;

        let mut req = base_request();
        req.policy.network_egress = Some(NetworkEgressPolicy::default());
        req.policy.denied_paths = vec!["/etc/hosts".into()];
        req.policy.network_proxy = ProxyConfig {
            address: Some(ProxyAddress::new("127.0.0.1".into(), 3128)),
        };

        let unavailable = bwrap_version::BwrapUnavailable::NotFound;
        let expected = unavailable.to_string();
        let err = BubblewrapScriptRunner::new()
            .validate_prepared_with_probe(&req, || Err(unavailable))
            .unwrap_err();
        assert_eq!(err.error_message, expected);
    }

    #[test]
    fn validate_accepts_programmatic_directional_cidr_rules() {
        use crate::mxc_common::models::{NetworkEgressPolicy, NetworkPeer, NetworkRule};

        let mut req = base_request();
        let rule = |cidr: &str| NetworkRule {
            to: vec![NetworkPeer {
                cidr: cidr.parse().expect("test CIDR"),
                except: vec![],
            }],
            ports: vec![],
        };
        req.policy.network_egress = Some(NetworkEgressPolicy {
            allow: vec![rule("203.0.113.7/32"), rule("10.0.0.0/8")],
            deny: vec![rule("2001:db8::/32")],
            ..Default::default()
        });

        let unavailable = bwrap_version::BwrapUnavailable::NotFound;
        let expected = unavailable.to_string();
        let err = BubblewrapScriptRunner::new()
            .validate_prepared_with_probe(&req, || Err(unavailable))
            .unwrap_err();
        assert_eq!(err.error_message, expected);
    }

    #[test]
    fn validate_rejects_empty_script_before_environment_probe() {
        // Empty script_code is a user-input error and must be surfaced
        // even on hosts without bwrap installed (independent of CI image).
        let mut req = base_request();
        req.script_code = String::new();

        let runner = BubblewrapScriptRunner::new();
        let err = runner
            .validate_prepared_with_probe(&req, || {
                panic!("environment probe must not run for invalid input")
            })
            .unwrap_err();
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

    #[test]
    fn validate_surfaces_every_environment_probe_failure() {
        let request = base_request();
        let failures = [
            bwrap_version::BwrapUnavailable::NotFound,
            bwrap_version::BwrapUnavailable::ProbeFailed {
                status: Some(126),
                detail: "permission denied".to_string(),
            },
            bwrap_version::BwrapUnavailable::UnrecognizedVersion("junk".to_string()),
            bwrap_version::BwrapUnavailable::TooOld(bwrap_version::BwrapVersion::new(0, 4, 1)),
        ];

        for failure in failures {
            let expected = failure.to_string();
            let error = BubblewrapScriptRunner::new()
                .validate_prepared_with_probe(&request, || Err(failure))
                .unwrap_err();
            assert_eq!(error.error_message, expected);
        }
    }

    /// A denied symlink pointing at a **directory** is rewritten to its canonical
    /// target so the mask lands on the real directory (bwrap cannot mount a mask
    /// over a symlink whose parent is bound). The resolved directory is
    /// classified as a `--tmpfs` (directory) mask, not a file mask.
    #[cfg(unix)]
    #[test]
    fn resolve_denied_paths_rewrites_symlink_to_dir() {
        use crate::mxc_common::logger::{Logger, Mode};
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("real_dir");
        std::fs::create_dir(&target).unwrap();
        let link = dir.path().join("link_to_dir");
        std::os::unix::fs::symlink(&target, &link).unwrap();

        let policy = crate::mxc_common::models::ContainerPolicy {
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
        use crate::mxc_common::logger::{Logger, Mode};
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("real_file.txt");
        std::fs::write(&target, b"secret").unwrap();
        let link = dir.path().join("link_to_file");
        std::os::unix::fs::symlink(&target, &link).unwrap();

        let policy = crate::mxc_common::models::ContainerPolicy {
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
        use crate::mxc_common::logger::{Logger, Mode};
        let dir = tempfile::tempdir().unwrap();
        let base = std::fs::canonicalize(dir.path()).unwrap();
        let real = base.join("real");
        std::fs::create_dir_all(real.join("secret")).unwrap();
        let link = base.join("link");
        std::os::unix::fs::symlink(&real, &link).unwrap();

        // Deny .../link/secret — the leaf `secret` is a real dir, `link` is the
        // symlinked ancestor.
        let denied = link.join("secret");
        let policy = crate::mxc_common::models::ContainerPolicy {
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
        use crate::mxc_common::logger::{Logger, Mode};
        let dir = tempfile::tempdir().unwrap();
        let base = std::fs::canonicalize(dir.path()).unwrap();
        let real = base.join("real");
        std::fs::create_dir(&real).unwrap();
        let link = base.join("link");
        std::os::unix::fs::symlink(&real, &link).unwrap();

        // Deny .../link/newfile — `newfile` does not exist yet.
        let denied = link.join("newfile");
        let policy = crate::mxc_common::models::ContainerPolicy {
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
        use crate::mxc_common::logger::{Logger, Mode};
        let dir = tempfile::tempdir().unwrap();
        // Canonicalize up front so a symlinked tempdir root (e.g. via TMPDIR)
        // doesn't spuriously trigger a rewrite — we are testing symlink-free paths.
        let base = std::fs::canonicalize(dir.path()).unwrap();
        let file = base.join("f.txt");
        std::fs::write(&file, b"x").unwrap();
        let subdir = base.join("d");
        std::fs::create_dir(&subdir).unwrap();
        let missing = base.join("does_not_exist");

        let policy = crate::mxc_common::models::ContainerPolicy {
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
        use crate::mxc_common::logger::{Logger, Mode};
        let dir = tempfile::tempdir().unwrap();
        let base = std::fs::canonicalize(dir.path()).unwrap();
        let link = base.join("dangling");
        std::os::unix::fs::symlink(base.join("nonexistent_target"), &link).unwrap();

        let policy = crate::mxc_common::models::ContainerPolicy {
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
        use crate::mxc_common::logger::{Logger, Mode};
        let dir = tempfile::tempdir().unwrap();
        let base = std::fs::canonicalize(dir.path()).unwrap();
        let real = base.join("real");
        std::fs::create_dir(&real).unwrap();
        let link = base.join("link");
        std::os::unix::fs::symlink(&real, &link).unwrap();

        // Deny .../link/missing/../secret — `missing` does not exist and the
        // `..` cancels it, so the real target is .../real/secret.
        let denied = link.join("missing").join("..").join("secret");
        let policy = crate::mxc_common::models::ContainerPolicy {
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
