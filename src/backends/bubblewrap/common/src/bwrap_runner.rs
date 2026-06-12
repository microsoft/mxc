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
use std::process::{Child, ChildStderr, ChildStdin, ChildStdout, Command, Stdio};
use std::time::{Duration, Instant};

use lxc_common::network_iptables::NetworkIptablesManager;
use wxc_common::linux_proxy_coordinator::LinuxProxyCoordinator;
use wxc_common::logger::Logger;
use wxc_common::models::{ExecutionRequest, NetworkEnforcementMode, ScriptResponse};
use wxc_common::sandbox_process::{SandboxProcess, StreamingRunner};
use wxc_common::script_runner::ScriptRunner;

use crate::bwrap_command;

/// Polling interval for timeout enforcement.
const POLL_INTERVAL_MS: u64 = 500;

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

impl ScriptRunner for BubblewrapScriptRunner {
    fn validate_runner(&self, request: &ExecutionRequest) -> Result<(), ScriptResponse> {
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

        // Reject timeouts smaller than our polling interval.
        if request.script_timeout > 0 && u64::from(request.script_timeout) < POLL_INTERVAL_MS {
            return Err(ScriptResponse::error(&format!(
                "script_timeout {}ms is below the minimum of {}ms",
                request.script_timeout, POLL_INTERVAL_MS
            )));
        }

        if !Self::is_bwrap_available() {
            return Err(ScriptResponse::error(
                "Bubblewrap (bwrap) is not installed or not on PATH. \
                 Install it via your package manager (e.g., apt install bubblewrap).",
            ));
        }

        Ok(())
    }

    fn execute(&mut self, request: &ExecutionRequest, logger: &mut Logger) -> ScriptResponse {
        match self.spawn_bwrap(request, logger, false) {
            Ok(child) => child.run_to_completion(logger),
            Err(resp) => resp,
        }
    }
}

impl BubblewrapScriptRunner {
    /// Set up networking and spawn `bwrap`, returning a [`BwrapChild`] the
    /// caller runs to completion (blocking) or wraps in a streaming handle.
    /// When `stream` is set, stdin is piped (so the caller can write to it) and
    /// the child is placed in its own process group so it can be tree-killed.
    fn spawn_bwrap(
        &self,
        request: &ExecutionRequest,
        logger: &mut Logger,
        stream: bool,
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
        command
            .stdin(if stream {
                Stdio::piped()
            } else {
                Stdio::null()
            })
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        if stream {
            // Put bwrap in its own process group so the streaming handle can
            // tree-kill it with a single `killpg` (bwrap is PID 1 of the new
            // pid namespace via `--unshare-pid`, so this takes the whole
            // sandbox down) without touching the host's process group.
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

        let stdin = child.stdin.take();
        let stdout = child.stdout.take();
        let stderr = child.stderr.take();
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
    stdout: Option<ChildStdout>,
    stderr: Option<ChildStderr>,
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

    /// Blocking run: drain captured output on threads, wait, tear down, and
    /// collect into a [`ScriptResponse`] (mirrors the original `execute`).
    fn run_to_completion(mut self, logger: &mut Logger) -> ScriptResponse {
        let stdout_handle = self
            .stdout
            .take()
            .map(|r| std::thread::spawn(move || read_to_string(r)));
        let stderr_handle = self
            .stderr
            .take()
            .map(|r| std::thread::spawn(move || read_to_string(r)));

        let exit_status = match wait_with_timeout(&mut self.child, self.timeout) {
            Ok(status) => status,
            Err(WaitError::Timeout) => {
                let _ = self.child.kill();
                let _ = self.child.wait();
                self.cleanup(logger);
                return ScriptResponse {
                    exit_code: -1,
                    standard_out: join_reader(stdout_handle),
                    standard_err: join_reader(stderr_handle),
                    error_message: "Bubblewrap: script timed out".to_string(),
                    ..Default::default()
                };
            }
            Err(WaitError::Io(error)) => {
                self.cleanup(logger);
                return ScriptResponse::error(&format!("Bubblewrap: wait failed: {}", error));
            }
        };

        self.cleanup(logger);

        ScriptResponse {
            exit_code: exit_status.code().unwrap_or(-1),
            standard_out: join_reader(stdout_handle),
            standard_err: join_reader(stderr_handle),
            error_message: String::new(),
            ..Default::default()
        }
    }
}

impl StreamingRunner for BubblewrapScriptRunner {
    fn spawn_streaming(
        &mut self,
        request: &ExecutionRequest,
        logger: &mut Logger,
    ) -> Result<Box<dyn SandboxProcess>, ScriptResponse> {
        use wxc_common::validator::validate_common;

        validate_common(request)?;
        self.validate_runner(request)?;

        let child = self.spawn_bwrap(request, logger, true)?;
        Ok(Box::new(BubblewrapSandboxProcess::new(child)))
    }
}

/// A running `bwrap` sandbox exposed as a [`SandboxProcess`]. Owns the child,
/// its pipes, and the per-run network state, torn down once the child exits.
struct BubblewrapSandboxProcess {
    child: Child,
    stdin: Option<ChildStdin>,
    stdout: Option<ChildStdout>,
    stderr: Option<ChildStderr>,
    proxy: LinuxProxyCoordinator,
    fw_manager: Option<NetworkIptablesManager>,
    timeout: Option<Duration>,
    teardown_done: bool,
}

impl BubblewrapSandboxProcess {
    fn new(mut child: BwrapChild) -> Self {
        Self {
            stdin: child.stdin.take(),
            stdout: child.stdout.take(),
            stderr: child.stderr.take(),
            proxy: std::mem::take(&mut child.proxy),
            fw_manager: child.fw_manager.take(),
            timeout: child.timeout,
            child: child.child,
            teardown_done: false,
        }
    }

    fn run_teardown(&mut self) {
        if self.teardown_done {
            return;
        }
        self.teardown_done = true;
        let mut logger = Logger::new(wxc_common::logger::Mode::Buffer);
        cleanup_iptables(&mut self.fw_manager, &mut logger);
        self.proxy.stop(&mut logger);
    }
}

impl SandboxProcess for BubblewrapSandboxProcess {
    fn take_stdin(&mut self) -> Option<Box<dyn std::io::Write + Send>> {
        self.stdin
            .take()
            .map(|s| Box::new(s) as Box<dyn std::io::Write + Send>)
    }

    fn take_stdout(&mut self) -> Option<Box<dyn std::io::Read + Send>> {
        self.stdout
            .take()
            .map(|s| Box::new(s) as Box<dyn std::io::Read + Send>)
    }

    fn take_stderr(&mut self) -> Option<Box<dyn std::io::Read + Send>> {
        self.stderr
            .take()
            .map(|s| Box::new(s) as Box<dyn std::io::Read + Send>)
    }

    fn try_wait(&mut self) -> std::io::Result<Option<i32>> {
        Ok(self
            .child
            .try_wait()?
            .map(|status| status.code().unwrap_or(-1)))
    }

    fn id(&self) -> u32 {
        self.child.id()
    }

    fn kill(&mut self) -> std::io::Result<()> {
        use nix::sys::signal::{killpg, Signal};
        use nix::unistd::Pid;

        if self.child.try_wait()?.is_some() {
            return Ok(());
        }
        // The child (bwrap) leads its own process group (`process_group(0)`),
        // and is PID 1 of the sandbox's pid namespace, so signalling the group
        // tears the whole sandbox down. Safe even if the group is gone — it
        // only targets this pgid, never the host's group.
        let pgid = Pid::from_raw(self.child.id() as i32);
        let _ = killpg(pgid, Signal::SIGTERM);
        let deadline = Instant::now() + Duration::from_secs(2);
        loop {
            if self.child.try_wait()?.is_some() {
                return Ok(());
            }
            if Instant::now() >= deadline {
                break;
            }
            std::thread::sleep(Duration::from_millis(50));
        }
        let _ = killpg(pgid, Signal::SIGKILL);
        Ok(())
    }

    fn wait(&mut self) -> ScriptResponse {
        // Close our copy of any not-taken stdin so the child sees EOF.
        self.stdin.take();

        let stdout_handle = self
            .stdout
            .take()
            .map(|r| std::thread::spawn(move || read_to_string(r)));
        let stderr_handle = self
            .stderr
            .take()
            .map(|r| std::thread::spawn(move || read_to_string(r)));

        let result = match wait_with_timeout(&mut self.child, self.timeout) {
            Ok(status) => ScriptResponse {
                exit_code: status.code().unwrap_or(-1),
                standard_out: join_reader(stdout_handle),
                standard_err: join_reader(stderr_handle),
                ..Default::default()
            },
            Err(WaitError::Timeout) => {
                // Tree-kill (process group) so descendants die too and release
                // any stdout/stderr pipe write-ends, matching `kill()`'s
                // contract; terminating only the root could leave the drain
                // threads blocked. bwrap is PID 1 of the pid namespace.
                let _ = self.kill();
                let _ = self.child.wait();
                ScriptResponse {
                    exit_code: -1,
                    standard_out: join_reader(stdout_handle),
                    standard_err: join_reader(stderr_handle),
                    error_message: "Bubblewrap: script timed out".to_string(),
                    ..Default::default()
                }
            }
            Err(WaitError::Io(error)) => {
                ScriptResponse::error(&format!("Bubblewrap: wait failed: {}", error))
            }
        };

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
        let _ = self.child.wait();
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

// -- I/O helpers (mirrors seatbelt_runner) --------------------------------

fn read_to_string<R: std::io::Read>(reader: R) -> String {
    wxc_common::capture_io::read_capped_lossy(reader)
}

fn join_reader(handle: Option<std::thread::JoinHandle<String>>) -> String {
    match handle {
        Some(h) => h.join().unwrap_or_default(),
        None => String::new(),
    }
}

enum WaitError {
    Timeout,
    Io(std::io::Error),
}

fn wait_with_timeout(
    child: &mut std::process::Child,
    timeout: Option<Duration>,
) -> Result<std::process::ExitStatus, WaitError> {
    let Some(deadline) = timeout.map(|d| Instant::now() + d) else {
        return child.wait().map_err(WaitError::Io);
    };

    loop {
        match child.try_wait() {
            Ok(Some(status)) => return Ok(status),
            Ok(None) => {
                if Instant::now() >= deadline {
                    return Err(WaitError::Timeout);
                }
                std::thread::sleep(Duration::from_millis(POLL_INTERVAL_MS));
            }
            Err(e) => return Err(WaitError::Io(e)),
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
        let err = runner.validate_runner(&req).unwrap_err();
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
        let err = runner.validate_runner(&req).unwrap_err();
        assert!(err.error_message.contains("script_code is empty"));
    }
}
