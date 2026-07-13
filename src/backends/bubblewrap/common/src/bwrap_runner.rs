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
//!   proxy via [`wxc_common::linux_proxy_coordinator::LinuxProxyCoordinator`]
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

use std::collections::{HashMap, HashSet};
use std::fmt::Write as FmtWrite;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, Command, Stdio};
use std::time::Duration;

use lxc_common::network_iptables::NetworkIptablesManager;
use wxc_common::interruptible_reader::{wrap_pipe, InterruptibleReader, ReadCanceller};
use wxc_common::linux_proxy_coordinator::LinuxProxyCoordinator;
use wxc_common::logger::Logger;
use wxc_common::models::{ExecutionRequest, NetworkEnforcementMode, PathKind, ScriptResponse};
use wxc_common::sandbox_process::{
    boxed_closer, cancel_and_join_discard, group_kill, spawn_discard, take_boxed_read,
    take_boxed_write, wait_with_timeout, SandboxBackend, SandboxProcess, StdioMode, StreamCloser,
    WaitError,
};
use wxc_common::validator::validate_common;

use crate::bwrap_command;

/// Bubblewrap sandbox runner. Uses only shared `ContainerPolicy` fields —
/// no backend-specific config struct required.
#[derive(Default)]
pub struct BubblewrapScriptRunner;

impl BubblewrapScriptRunner {
    pub fn new() -> Self {
        Self
    }

    /// Check whether `bwrap` is available on PATH.
    fn is_bwrap_available() -> bool {
        Command::new("bwrap")
            .arg("--version")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .map(|s| s.success())
            .unwrap_or(false)
    }
}

impl SandboxBackend for BubblewrapScriptRunner {
    fn validate(&self, request: &ExecutionRequest) -> Result<(), ScriptResponse> {
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

        if !Self::is_bwrap_available() {
            return Err(ScriptResponse::error(
                "Bubblewrap (bwrap) is not installed or not on PATH. \
                 Install it via your package manager (e.g., apt install bubblewrap).",
            ));
        }

        Ok(())
    }

    fn spawn(
        &mut self,
        request: &ExecutionRequest,
        logger: &mut Logger,
        stdio: StdioMode,
    ) -> Result<Box<dyn SandboxProcess>, ScriptResponse> {
        validate_common(request)?;
        self.validate(request)?;
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
                policy.denied_path_kinds = plan.kinds;
                resolved = ExecutionRequest {
                    policy,
                    ..request.clone()
                };
                &resolved
            }
            None => request,
        };
        let child = self.spawn_bwrap(request, &plan.files, logger, stdio)?;
        Ok(Box::new(BubblewrapSandboxProcess::new(child)))
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
        logger: &mut Logger,
        stdio: StdioMode,
    ) -> Result<BwrapChild, ScriptResponse> {
        // 1. Start the network proxy if configured. Must happen before
        //    arg-building so the proxy's loopback address can be injected as
        //    HTTP_PROXY / HTTPS_PROXY into the sandbox environment.
        let mut proxy = LinuxProxyCoordinator::new();
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

        // 2. Warn when a declared `type` contradicts an existing host path (host
        //    reality wins so the mount stays valid), and record missing denied
        //    paths under a read-write parent whose host stubs we must reclaim
        //    once the sandbox tears down. Symlinks are already resolved above.
        warn_denied_kind_mismatches(&request.policy, logger);
        let stub_candidates = missing_denied_stub_candidates(&request.policy);

        // 3. Build the bwrap argument vector. `denied_files` is the file-mask
        //    subset classified during symlink resolution (see
        //    [`resolve_denied_paths`]).
        let args = bwrap_command::build_args_classified(request, proxy.address(), denied_files);
        let _ = writeln!(
            logger,
            "Bubblewrap: spawning bwrap with {} args",
            args.len()
        );

        // 4. Determine whether iptables network rules are needed. When the
        //    cooperative proxy is active we skip iptables entirely (host
        //    enforcement happens at the proxy layer).
        let needs_iptables = needs_iptables_rules(request) && !proxy.is_active();
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
            let mut mgr = NetworkIptablesManager::new(&container_name);
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

        // 5. Spawn `bwrap`.
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

        let mut child = match command.spawn() {
            Ok(process) => process,
            Err(error) => {
                let mut fw_manager = fw_manager;
                cleanup_iptables(&mut fw_manager, logger);
                proxy.stop(logger);
                return Err(ScriptResponse::error(&format!(
                    "Bubblewrap: failed to spawn bwrap: {}",
                    error
                )));
            }
        };

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
            fw_manager,
            timeout,
            stub_candidates,
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
    proxy: LinuxProxyCoordinator,
    fw_manager: Option<NetworkIptablesManager>,
    timeout: Option<Duration>,
    /// Missing denied paths under a read-write parent whose empty host stubs
    /// bwrap materializes as mount points; reclaimed in [`BwrapChild::cleanup`]
    /// once the sandbox has exited (see [`missing_denied_stub_candidates`]).
    stub_candidates: Vec<String>,
}

impl BwrapChild {
    /// Tear down per-run state: iptables rules + proxy, then reclaim any empty
    /// host stubs bwrap left behind for missing denied paths. Idempotent at the
    /// manager level; stub removal is best-effort.
    fn cleanup(&mut self, logger: &mut Logger) {
        cleanup_iptables(&mut self.fw_manager, logger);
        self.proxy.stop(logger);
        cleanup_denied_stubs(&self.stub_candidates, logger);
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

/// Returns `true` when the request has per-host network rules that require
/// iptables. Pure `"block"` with no host lists uses `--unshare-net` instead.
fn needs_iptables_rules(request: &ExecutionRequest) -> bool {
    let uses_firewall = matches!(
        request.policy.network_enforcement_mode,
        NetworkEnforcementMode::Firewall | NetworkEnforcementMode::Both
    );
    let has_host_rules =
        !request.policy.allowed_hosts.is_empty() || !request.policy.blocked_hosts.is_empty();

    // Only invoke iptables when there are actual per-host rules to apply and
    // the enforcement mode includes firewall.
    uses_firewall && has_host_rules
}

/// Best-effort iptables cleanup. Called on both success and error paths.
fn cleanup_iptables(manager: &mut Option<NetworkIptablesManager>, logger: &mut Logger) {
    if let Some(ref mut mgr) = manager {
        if mgr.rules_applied() {
            let _ = mgr.remove_firewall_rules(logger);
        }
    }
}

/// Outcome of resolving and classifying `deniedPaths` in a single pass.
struct DeniedPlan {
    /// Rewritten denied-path list. `Some` only when at least one entry differs
    /// from the input (a symlink was resolved to its real target), so the caller
    /// can skip cloning the request in the common no-symlink case.
    paths: Option<Vec<String>>,
    /// `denied_path_kinds` re-keyed to match the resolved `paths` (a symlink
    /// entry's declared `type` moves to its real path). Applied to the policy
    /// alongside `paths` whenever `paths` is `Some`.
    kinds: HashMap<String, PathKind>,
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
/// Any `denied_path_kinds` entry is re-keyed from the original path to its
/// resolved path so the map stays keyed by the path as it now appears in
/// `denied_paths` (its documented invariant).
///
/// An entry still a symlink after resolution (dangling/unresolvable) is kept and
/// file-masked with `/dev/null` — nothing resolvable is behind it to leak, and
/// bwrap tolerates `/dev/null` over a symlink node (whereas `--tmpfs` aborts).
fn resolve_denied_paths(
    policy: &wxc_common::models::ContainerPolicy,
    logger: &mut Logger,
) -> Result<DeniedPlan, String> {
    let mut out = Vec::with_capacity(policy.denied_paths.len());
    let mut files = HashSet::new();
    // Cloned lazily on the first rewrite so the common no-symlink path pays
    // nothing; `Some` also doubles as the "something changed" flag.
    let mut kinds: Option<HashMap<String, PathKind>> = None;
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
                // Keep denied_path_kinds keyed by the path as it now appears.
                let kinds = kinds.get_or_insert_with(|| policy.denied_path_kinds.clone());
                if let Some(kind) = kinds.remove(p) {
                    kinds.insert(resolved.to_owned(), kind);
                }
                // Classify by declared kind (looked up under the original key
                // `p`, since re-keying changes only the key) + host stat of the
                // resolved path.
                if denied_masks_as_file(resolved, policy.denied_path_kinds.get(p)) {
                    files.insert(resolved.to_owned());
                }
                out.push(resolved.to_owned());
                continue;
            }
        }
        // Not rewritten: a real path, a rooted not-yet-existing path, or a
        // dangling symlink. Classify by declared kind + host stat of the entry.
        if denied_masks_as_file(p, policy.denied_path_kinds.get(p)) {
            files.insert(p.clone());
        }
        out.push(p.clone());
    }
    let changed = kinds.is_some();
    Ok(DeniedPlan {
        paths: changed.then_some(out),
        kinds: kinds.unwrap_or_default(),
        files,
    })
}

/// Decide whether one denied path must be masked as a **file**
/// (`--ro-bind /dev/null`) rather than a directory (`--tmpfs`).
///
/// Host reality is authoritative whenever the path **exists**: a declared kind
/// that contradicts an existing path cannot be honored, because bwrap can
/// neither bind `/dev/null` over a real directory nor mount a `--tmpfs` over a
/// real file — either produces a hard mount failure that aborts the whole
/// sandbox. The declared kind (`denied_path_kinds`) is therefore consulted only
/// when the host path is **absent or unreadable** — exactly the case the
/// runtime probe cannot classify — so masking is deterministic for not-yet-
/// present paths while staying valid for existing ones. `symlink_metadata` does
/// not follow symlinks, so a denied symlink is judged by its own type (a
/// non-directory, masked with `/dev/null`). Missing/unreadable paths with no
/// declared kind fall back to a directory (`--tmpfs`).
fn denied_masks_as_file(path: &str, declared: Option<&PathKind>) -> bool {
    match std::fs::symlink_metadata(path) {
        Ok(md) => !md.file_type().is_dir(),
        Err(_) => matches!(declared, Some(PathKind::File)),
    }
}

/// Log a warning for each denied path whose declared `type` contradicts the
/// actual host type. The host type wins (so the bwrap mount stays valid — see
/// [`denied_masks_as_file`]), but the mismatch usually signals a misconfigured
/// policy worth surfacing to the caller.
fn warn_denied_kind_mismatches(policy: &wxc_common::models::ContainerPolicy, logger: &mut Logger) {
    for (path, declared) in &policy.denied_path_kinds {
        let Ok(md) = std::fs::symlink_metadata(path) else {
            continue; // missing/unreadable: the declared kind is honored, no conflict
        };
        let host_is_dir = md.file_type().is_dir();
        let declared_is_dir = matches!(declared, PathKind::Directory);
        if host_is_dir != declared_is_dir {
            let (declared_name, host_name) = if declared_is_dir {
                ("directory", "non-directory")
            } else {
                ("file", "directory")
            };
            let _ = writeln!(
                logger,
                "Bubblewrap: deniedPaths entry {path:?} declared type \"{declared_name}\" but \
                 the host path is a {host_name}; masking it as the host type so the bwrap mount \
                 stays valid."
            );
        }
    }
}

/// Denied paths that do **not** exist on the host and live under a
/// `readwritePaths` bind. To mount a mask, bwrap must first materialize a mount
/// point (an empty file for `--ro-bind /dev/null`, an empty directory for
/// `--tmpfs`); because the parent is a writable bind of a real host directory,
/// that mount point is created on the host and left behind as an empty stub
/// once the sandbox tears down. These are the paths [`cleanup_denied_stubs`]
/// removes post-run to keep the host free of side effects.
fn missing_denied_stub_candidates(policy: &wxc_common::models::ContainerPolicy) -> Vec<String> {
    policy
        .denied_paths
        .iter()
        // Only a genuine NotFound means the path is absent — treat other errors
        // (e.g. a transient PermissionDenied) as "present" so we never enroll,
        // and later reclaim, a real host path we did not create.
        .filter(|p| {
            matches!(
                std::fs::symlink_metadata(p),
                Err(e) if e.kind() == std::io::ErrorKind::NotFound
            )
        })
        .filter(|p| path_is_within_any(p, &policy.readwrite_paths))
        .cloned()
        .collect()
}

/// `true` when `path` is equal to or nested under any of `parents`, compared
/// component-wise (so `/a/bc` is not considered "within" `/a/b`).
fn path_is_within_any(path: &str, parents: &[String]) -> bool {
    let child = std::path::Path::new(path);
    parents
        .iter()
        .any(|parent| child.starts_with(std::path::Path::new(parent)))
}

/// Best-effort removal of the empty host stubs bwrap created for missing denied
/// paths (see [`missing_denied_stub_candidates`]). Only empty regular files and
/// empty directories are removed, and symlinks are never followed, so a path
/// that gained real content — or was swapped for a symlink — after the run is
/// left untouched. The mask (`/dev/null` / tmpfs) was mounted *over* each stub
/// during the run, so the sandbox's writes never reached the underlying node:
/// it is still empty and safe to reclaim.
fn cleanup_denied_stubs(paths: &[String], logger: &mut Logger) {
    for path in paths {
        let Ok(md) = std::fs::symlink_metadata(path) else {
            continue; // already gone / unreadable
        };
        let ft = md.file_type();
        let removed = if ft.is_symlink() {
            // A symlink is not the empty node we created; never follow or delete it.
            false
        } else if ft.is_file() {
            md.len() == 0 && std::fs::remove_file(path).is_ok()
        } else if ft.is_dir() {
            // `remove_dir` (atomic rmdir) only succeeds on an empty directory.
            std::fs::remove_dir(path).is_ok()
        } else {
            false
        };
        if removed {
            let _ = writeln!(
                logger,
                "Bubblewrap: removed leftover denied-path stub {path:?}"
            );
        }
    }
}

/// Resolve every symlink in `path` (leaf and ancestors) to a real filesystem
/// path, tolerating trailing components that do not exist yet.
///
/// `std::fs::canonicalize` resolves symlinks at every level but requires the
/// **whole** path to exist. To also cover not-yet-created denied paths under a
/// symlinked ancestor, this walks up to the deepest existing ancestor,
/// canonicalizes it, then re-appends the non-existent tail. Returns `None` only
/// when no ancestor can be canonicalized (e.g. a relative path with no existing
/// root).
fn resolve_through_symlinks(path: &Path) -> Option<PathBuf> {
    // Fast path: the whole path exists, so canonicalize resolves every component.
    if let Ok(real) = std::fs::canonicalize(path) {
        return Some(real);
    }
    // Otherwise find the deepest existing ancestor, canonicalize it, and
    // re-append the components below it that do not exist on the host yet.
    let mut tail: Vec<&std::ffi::OsStr> = Vec::new();
    let mut cur = path;
    while let Some(parent) = cur.parent() {
        if let Some(name) = cur.file_name() {
            tail.push(name);
        }
        if let Ok(real_parent) = std::fs::canonicalize(parent) {
            let mut result = real_parent;
            for name in tail.iter().rev() {
                result.push(name);
            }
            return Some(result);
        }
        cur = parent;
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use wxc_common::models::ProxyConfig;

    fn base_request() -> ExecutionRequest {
        ExecutionRequest {
            script_code: "echo hi".into(),
            ..Default::default()
        }
    }

    /// Test shim: the file-mask classification is folded into [`resolve_denied_paths`]
    /// (as [`DeniedPlan::files`]); these tests exercise that classification directly.
    fn classify_denied_files(policy: &wxc_common::models::ContainerPolicy) -> HashSet<String> {
        let mut logger = wxc_common::logger::Logger::new(wxc_common::logger::Mode::Buffer);
        resolve_denied_paths(policy, &mut logger)
            .expect("must not fail closed")
            .files
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

    /// When a denied symlink carries an explicit `type`, resolution re-keys the
    /// `denied_path_kinds` entry from the link path to its target so the map
    /// stays keyed by the path as it now appears in `denied_paths`.
    #[cfg(unix)]
    #[test]
    fn resolve_denied_symlinks_rekeys_declared_kind_to_target() {
        use wxc_common::logger::{Logger, Mode};
        use wxc_common::models::PathKind;
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("real_dir");
        std::fs::create_dir(&target).unwrap();
        let link = dir.path().join("link_to_dir");
        std::os::unix::fs::symlink(&target, &link).unwrap();
        let link_str = link.to_string_lossy().into_owned();
        let target_str = std::fs::canonicalize(&target)
            .unwrap()
            .to_string_lossy()
            .into_owned();

        let mut kinds = std::collections::HashMap::new();
        kinds.insert(link_str.clone(), PathKind::Directory);
        let policy = wxc_common::models::ContainerPolicy {
            denied_paths: vec![link_str.clone()],
            denied_path_kinds: kinds,
            ..Default::default()
        };

        let mut logger = Logger::new(Mode::Buffer);
        let plan = resolve_denied_paths(&policy, &mut logger).expect("must not fail closed");
        let out = plan.paths.expect("symlink must be rewritten");
        let kinds = plan.kinds;
        assert_eq!(out, vec![target_str.clone()]);
        // Kind moved from the link key to the target key.
        assert!(!kinds.contains_key(&link_str));
        assert_eq!(kinds.get(&target_str), Some(&PathKind::Directory));
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

    // --- classify_denied_files (masking primitive selection) ---

    #[test]
    fn explicit_file_kind_masks_as_file_even_when_missing() {
        // The headline win: a denied path declared `file` is masked with
        // /dev/null even if it does not exist on the host (the runtime probe
        // alone would fall back to tmpfs/dir).
        let mut req = base_request();
        let p = "/nonexistent/secret.txt".to_string();
        req.policy.denied_paths = vec![p.clone()];
        req.policy
            .denied_path_kinds
            .insert(p.clone(), PathKind::File);

        let files = classify_denied_files(&req.policy);
        assert!(files.contains(&p), "explicit file kind must mask as a file");
    }

    #[test]
    fn explicit_directory_kind_masks_as_directory_even_when_missing() {
        let mut req = base_request();
        let p = "/nonexistent/vault".to_string();
        req.policy.denied_paths = vec![p.clone()];
        req.policy
            .denied_path_kinds
            .insert(p.clone(), PathKind::Directory);

        let files = classify_denied_files(&req.policy);
        assert!(
            !files.contains(&p),
            "explicit directory kind must mask as a directory (tmpfs)"
        );
    }

    #[test]
    fn declared_file_reconciles_to_existing_host_directory() {
        // Fix ③: when the host path exists and is a directory, its real type
        // wins over a contradictory declared `file` kind — otherwise bwrap would
        // hard-fail trying to bind /dev/null over a directory. The path is still
        // denied, just masked with the valid primitive (tmpfs).
        let dir = std::env::temp_dir();
        let p = dir.to_string_lossy().into_owned();
        let mut req = base_request();
        req.policy.denied_paths = vec![p.clone()];
        req.policy
            .denied_path_kinds
            .insert(p.clone(), PathKind::File);

        let files = classify_denied_files(&req.policy);
        assert!(
            !files.contains(&p),
            "an existing host directory must mask as a directory even when declared file"
        );
    }

    #[test]
    fn declared_directory_reconciles_to_existing_host_file() {
        // Fix ③, reverse direction: an existing host *file* declared `directory`
        // must mask as a file (/dev/null), not tmpfs — a tmpfs over a real file
        // is an equally impossible mount.
        let mut p = std::env::temp_dir();
        p.push(format!("mxc_bwrap_recon_{}", std::process::id()));
        std::fs::write(&p, b"secret").expect("create temp file");
        let path = p.to_string_lossy().into_owned();

        let mut req = base_request();
        req.policy.denied_paths = vec![path.clone()];
        req.policy
            .denied_path_kinds
            .insert(path.clone(), PathKind::Directory);

        let files = classify_denied_files(&req.policy);
        let is_file = files.contains(&path);
        let _ = std::fs::remove_file(&p);
        assert!(
            is_file,
            "an existing host file must mask as a file even when declared directory"
        );
    }

    #[test]
    fn no_kind_probes_host_directory_as_directory() {
        // Without a declared kind, an existing host directory falls back to
        // tmpfs masking (not in the file set).
        let dir = std::env::temp_dir();
        let p = dir.to_string_lossy().into_owned();
        let mut req = base_request();
        req.policy.denied_paths = vec![p.clone()];

        let files = classify_denied_files(&req.policy);
        assert!(
            !files.contains(&p),
            "an undeclared host directory must probe as a directory"
        );
    }

    #[test]
    fn no_kind_missing_path_falls_back_to_directory() {
        // Without a declared kind, a missing path cannot be probed and falls
        // back to tmpfs (directory) masking.
        let mut req = base_request();
        let p = "/nonexistent/whatever".to_string();
        req.policy.denied_paths = vec![p.clone()];

        let files = classify_denied_files(&req.policy);
        assert!(
            !files.contains(&p),
            "an undeclared missing path must fall back to directory masking"
        );
    }

    // --- missing-denied-path host-stub cleanup (fix ②) ---

    #[test]
    fn path_is_within_any_is_component_wise() {
        let parents = vec!["/a/b".to_string()];
        assert!(path_is_within_any("/a/b", &parents), "equal path is within");
        assert!(
            path_is_within_any("/a/b/c", &parents),
            "nested path is within"
        );
        assert!(
            !path_is_within_any("/a/bc", &parents),
            "sibling prefix must not be treated as within"
        );
        assert!(
            !path_is_within_any("/a", &parents),
            "parent is not within child"
        );
    }

    #[test]
    fn stub_candidates_only_missing_paths_under_readwrite() {
        let mut req = base_request();
        req.policy.readwrite_paths = vec!["/mnt/work".into()];
        req.policy.denied_paths = vec![
            "/mnt/work/ghost".into(), // missing + under rw → candidate
            "/etc/shadow".into(),     // outside rw → not a candidate
            std::env::temp_dir().to_string_lossy().into_owned(), // exists → not a candidate
        ];

        let candidates = missing_denied_stub_candidates(&req.policy);
        assert_eq!(candidates, vec!["/mnt/work/ghost".to_string()]);
    }

    #[test]
    fn cleanup_removes_empty_stubs_but_not_populated_ones() {
        let base = std::env::temp_dir().join(format!("mxc_bwrap_stub_{}", std::process::id()));
        std::fs::create_dir_all(&base).expect("create test base");

        let empty_file = base.join("empty_file");
        let empty_dir = base.join("empty_dir");
        let full_file = base.join("full_file");
        let full_dir = base.join("full_dir");
        std::fs::write(&empty_file, b"").expect("empty file");
        std::fs::create_dir(&empty_dir).expect("empty dir");
        std::fs::write(&full_file, b"data").expect("full file");
        std::fs::create_dir(&full_dir).expect("full dir");
        std::fs::write(full_dir.join("child"), b"x").expect("dir child");

        let paths: Vec<String> = [&empty_file, &empty_dir, &full_file, &full_dir]
            .iter()
            .map(|p| p.to_string_lossy().into_owned())
            .collect();
        let mut logger = Logger::new(wxc_common::logger::Mode::Buffer);
        cleanup_denied_stubs(&paths, &mut logger);

        assert!(!empty_file.exists(), "empty stub file must be reclaimed");
        assert!(!empty_dir.exists(), "empty stub dir must be reclaimed");
        assert!(full_file.exists(), "a non-empty file must be preserved");
        assert!(full_dir.exists(), "a non-empty dir must be preserved");

        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn cleanup_never_follows_symlink_stubs() {
        use std::os::unix::fs::symlink;
        let base = std::env::temp_dir().join(format!("mxc_bwrap_symlink_{}", std::process::id()));
        std::fs::create_dir_all(&base).expect("create test base");

        let target = base.join("real_target");
        std::fs::write(&target, b"important").expect("target");
        let link = base.join("stub_link");
        symlink(&target, &link).expect("symlink");

        let mut logger = Logger::new(wxc_common::logger::Mode::Buffer);
        cleanup_denied_stubs(&[link.to_string_lossy().into_owned()], &mut logger);

        assert!(link.exists(), "a symlink stub must be left untouched");
        assert!(target.exists(), "a symlink's target must never be deleted");

        let _ = std::fs::remove_dir_all(&base);
    }
}
