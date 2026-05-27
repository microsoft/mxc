// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! `BubblewrapScriptRunner` — executes scripts inside a Bubblewrap
//! namespace sandbox via the `bwrap` CLI.
//!
//! Bubblewrap uses Linux user namespaces to create an unprivileged sandbox.
//! The runner translates `CodexRequest` policy fields into `bwrap` CLI
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
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use lxc_common::network_iptables::NetworkIptablesManager;
use wxc_common::linux_proxy_coordinator::LinuxProxyCoordinator;
use wxc_common::logger::Logger;
use wxc_common::models::{CodexRequest, NetworkEnforcementMode, ScriptResponse};
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
    fn validate_runner(&self, request: &CodexRequest) -> Result<(), ScriptResponse> {
        if !Self::is_bwrap_available() {
            return Err(ScriptResponse::error(
                "Bubblewrap (bwrap) is not installed or not on PATH. \
                 Install it via your package manager (e.g., apt install bubblewrap).",
            ));
        }

        if request.script_code.is_empty() {
            return Err(ScriptResponse::error(
                "script_code is empty — nothing to execute.",
            ));
        }

        // Reject timeouts smaller than our polling interval.
        if request.script_timeout > 0 && u64::from(request.script_timeout) < POLL_INTERVAL_MS {
            return Err(ScriptResponse::error(&format!(
                "script_timeout {}ms is below the minimum of {}ms",
                request.script_timeout, POLL_INTERVAL_MS
            )));
        }

        Ok(())
    }

    fn execute(&mut self, request: &CodexRequest, logger: &mut Logger) -> ScriptResponse {
        // 1. Start the network proxy if configured. Must happen before
        //    arg-building so the proxy's loopback address can be injected as
        //    HTTP_PROXY / HTTPS_PROXY into the sandbox environment.
        //
        //    Pass the request's `default_network_policy` through so that a
        //    config of `{ defaultPolicy: "block", proxy: {...}, allowedHosts:
        //    [] }` actually denies-by-default at the proxy layer (otherwise
        //    the empty allow list + no iptables + no --unshare-net would let
        //    everything through).
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
                return ScriptResponse::error(&format!(
                    "Bubblewrap: failed to start network proxy: {}",
                    err
                ));
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

        let mut fw_manager = if needs_iptables {
            let _ = writeln!(
                logger,
                "Bubblewrap: applying iptables rules for host-level network filtering"
            );
            let mut mgr = NetworkIptablesManager::new(&container_name);
            match mgr.apply_firewall_rules(&request.policy, logger) {
                Ok(true) => {}
                Ok(false) => {
                    proxy.stop(logger);
                    return ScriptResponse::error(
                        "Bubblewrap: failed to apply iptables firewall rules.",
                    );
                }
                Err(e) => {
                    proxy.stop(logger);
                    return ScriptResponse::error(&format!(
                        "Bubblewrap: network policy error: {}",
                        e
                    ));
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
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());

        let mut child = match command.spawn() {
            Ok(process) => process,
            Err(error) => {
                cleanup_iptables(&mut fw_manager, logger);
                proxy.stop(logger);
                return ScriptResponse::error(&format!(
                    "Bubblewrap: failed to spawn bwrap: {}",
                    error
                ));
            }
        };

        // 5. Drain stdout/stderr in background threads to avoid pipe-buffer
        //    deadlock.
        let stdout_handle = child
            .stdout
            .take()
            .map(|r| std::thread::spawn(move || read_to_string(r)));
        let stderr_handle = child
            .stderr
            .take()
            .map(|r| std::thread::spawn(move || read_to_string(r)));

        // 6. Wait with optional timeout.
        let timeout = if request.script_timeout == 0 {
            None
        } else {
            Some(Duration::from_millis(u64::from(request.script_timeout)))
        };

        let exit_status = match wait_with_timeout(&mut child, timeout) {
            Ok(status) => status,
            Err(WaitError::Timeout) => {
                let _ = child.kill();
                let _ = child.wait();
                cleanup_iptables(&mut fw_manager, logger);
                proxy.stop(logger);
                return ScriptResponse {
                    exit_code: -1,
                    standard_out: join_reader(stdout_handle),
                    standard_err: join_reader(stderr_handle),
                    error_message: format!(
                        "Bubblewrap: script timed out after {}ms",
                        request.script_timeout
                    ),
                    ..Default::default()
                };
            }
            Err(WaitError::Io(error)) => {
                cleanup_iptables(&mut fw_manager, logger);
                proxy.stop(logger);
                return ScriptResponse::error(&format!("Bubblewrap: wait failed: {}", error));
            }
        };

        // 7. Collect output and clean up.
        cleanup_iptables(&mut fw_manager, logger);
        proxy.stop(logger);

        ScriptResponse {
            exit_code: exit_status.code().unwrap_or(-1),
            standard_out: join_reader(stdout_handle),
            standard_err: join_reader(stderr_handle),
            error_message: String::new(),
            ..Default::default()
        }
    }
}

/// Returns `true` when the request has per-host network rules that require
/// iptables. Pure `"block"` with no host lists uses `--unshare-net` instead.
fn needs_iptables_rules(request: &CodexRequest) -> bool {
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

fn read_to_string<R: std::io::Read>(mut reader: R) -> String {
    let mut buffer = String::new();
    let _ = reader.read_to_string(&mut buffer);
    buffer
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
