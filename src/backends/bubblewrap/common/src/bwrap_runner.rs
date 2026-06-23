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

use std::fmt::Write as FmtWrite;
use std::os::unix::process::CommandExt;
use std::process::{Child, ChildStdin, Command, Stdio};
use std::time::Duration;

use lxc_common::network_iptables::NetworkIptablesManager;
use wxc_common::interruptible_reader::{wrap_pipe, InterruptibleReader, ReadCanceller};
use wxc_common::linux_proxy_coordinator::LinuxProxyCoordinator;
use wxc_common::logger::Logger;
use wxc_common::models::{ExecutionRequest, NetworkEnforcementMode, ScriptResponse};
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

        // The bundled `linux-test-proxy` is a testing-only HTTP proxy with
        // a deliberately permissive feature set (no auth, no body limits,
        // no hop-by-hop header handling). Gate it behind --experimental so
        // it cannot be enabled from a stock production config.
        if request.policy.network_proxy.builtin_test_server && !request.experimental_enabled {
            return Err(ScriptResponse::error(
                "network.proxy.builtinTestServer is a testing-only feature and requires \
                 --experimental. For production, point network.proxy at a real HTTP \
                 proxy via 'localhost' or 'url'.",
            ));
        }

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
        let child = self.spawn_bwrap(request, logger, stdio)?;
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

        // 2. Build the bwrap argument vector.
        let args = bwrap_command::build_args(request, proxy.address());
        let _ = writeln!(
            logger,
            "Bubblewrap: spawning bwrap with {} args",
            args.len()
        );

        // 3. Determine whether iptables network rules are needed. When the
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
}

impl BwrapChild {
    /// Tear down per-run network state (iptables rules + proxy). Idempotent at
    /// the manager level.
    fn cleanup(&mut self, logger: &mut Logger) {
        cleanup_iptables(&mut self.fw_manager, logger);
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

    #[test]
    fn validate_rejects_builtin_test_server_without_experimental() {
        let mut req = base_request();
        req.policy.network_proxy = ProxyConfig {
            address: None,
            builtin_test_server: true,
        };
        req.experimental_enabled = false;

        let runner = BubblewrapScriptRunner::new();
        let err = runner.validate(&req).unwrap_err();
        assert!(
            err.error_message.contains("builtinTestServer")
                && err.error_message.contains("--experimental"),
            "expected experimental-gate error, got: {}",
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
}
