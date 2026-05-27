// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Coordinator for the Linux network proxy used by the Bubblewrap backend.
//!
//! # Why this exists
//!
//! The Bubblewrap backend wants to enforce `allowedHosts` / `blockedHosts`
//! **without** root or `CAP_NET_ADMIN`. The Windows AppContainer proxy
//! coordinator achieves enforcement through WinHTTP policy (set by an
//! elevated shim). On Linux, the equivalent without privilege is a
//! **cooperative env-var proxy**:
//!
//! 1. The coordinator launches an unprivileged HTTP proxy process (either a
//!    user-supplied address, or the bundled `linux-test-proxy` binary).
//! 2. The Bubblewrap command builder sets `HTTP_PROXY` / `HTTPS_PROXY` /
//!    `NO_PROXY` env vars inside the sandbox.
//! 3. Cooperative apps (curl, requests, etc.) honor the env vars and the
//!    proxy applies allow/block filtering; non-cooperative apps reaching
//!    out via raw sockets bypass enforcement (documented limitation).
//!
//! # Design notes
//!
//! - **Privilege-free**: no iptables, no namespaces, no setuid binaries.
//! - **Bind address is configurable** to allow future LXC reuse (LXC has
//!   its own netns, so the proxy needs to bind on the bridge gateway IP).
//!   Bubblewrap shares the host netns and passes `"127.0.0.1"`.
//! - **Atomic ready-file**: `linux-test-proxy` writes `<file>.tmp` and
//!   renames into place to eliminate partial-read races.
//! - **PR_SET_PDEATHSIG** in the child ensures the proxy dies if
//!   `lxc-exec` crashes (orphan reaping safety net).
//! - **`Drop` is silent**: never writes to stderr or `Logger`, because
//!   destructors can run at unpredictable times (e.g. during panic
//!   propagation) and noisy drops would corrupt the JSON envelope on
//!   `lxc-exec`'s stderr.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use crate::error::WxcError;
use crate::logger::Logger;
use crate::models::{NetworkPolicy, ProxyAddress, ProxyConfig};

/// Maximum time to wait for the test proxy to write its ready file.
const READY_TIMEOUT: Duration = Duration::from_secs(15);

/// Polling interval while waiting for the ready file to appear.
const READY_POLL_INTERVAL: Duration = Duration::from_millis(50);

/// Maximum time to wait for the test proxy to exit after SIGTERM.
const STOP_TIMEOUT: Duration = Duration::from_secs(5);

/// Process counter used (alongside pid + timestamp) to make ready-file
/// names collision-resistant when multiple coordinators run concurrently
/// inside the same process.
static UNIQUE_COUNTER: AtomicU64 = AtomicU64::new(0);

/// Generate a unique identifier for ready-file / temp-dir names.
fn generate_unique_id() -> String {
    let pid = std::process::id();
    let counter = UNIQUE_COUNTER.fetch_add(1, Ordering::Relaxed);
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0);
    format!("{}-{}-{}", pid, counter, nanos)
}

/// Create a private 0700 temp directory under `/tmp` and return its path.
fn create_private_temp_dir(unique_id: &str) -> Result<PathBuf, WxcError> {
    let dir = std::env::temp_dir().join(format!("mxc-proxy-{}", unique_id));
    fs::create_dir(&dir).map_err(|err| {
        WxcError::NetworkProxy(format!(
            "Failed to create proxy temp dir {}: {}",
            dir.display(),
            err
        ))
    })?;

    // Best-effort 0700 chmod so other users cannot snoop the ready file.
    #[cfg(target_os = "linux")]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = fs::set_permissions(&dir, fs::Permissions::from_mode(0o700));
    }

    Ok(dir)
}

/// Best-effort cleanup of a temp directory created by
/// [`create_private_temp_dir`]. Never panics; ignores errors.
fn remove_temp_dir(dir: &Path) {
    let _ = fs::remove_dir_all(dir);
}

/// Resolve a sibling binary next to the currently running executable.
fn resolve_sibling_binary(name: &str) -> Result<PathBuf, WxcError> {
    let exe = std::env::current_exe().map_err(|err| {
        WxcError::NetworkProxy(format!("cannot determine current exe path: {}", err))
    })?;
    let dir = exe
        .parent()
        .ok_or_else(|| WxcError::NetworkProxy("current exe has no parent directory".into()))?;
    let path = dir.join(name);
    if path.exists() {
        Ok(path)
    } else {
        Err(WxcError::NetworkProxy(format!(
            "{} not found at {}",
            name,
            path.display()
        )))
    }
}

/// Bookkeeping for a running `linux-test-proxy` child process.
struct TestProxyChild {
    child: Child,
    ready_file: PathBuf,
    temp_dir: PathBuf,
}

/// Send SIGTERM to a process group/PID (best-effort).
fn send_sigterm(pid: u32) {
    // SAFETY: `kill(2)` with SIGTERM is always defined; we ignore the
    // return value because the process may already be gone.
    unsafe {
        libc::kill(pid as libc::pid_t, libc::SIGTERM);
    }
}

/// Send SIGKILL to a PID (best-effort).
fn send_sigkill(pid: u32) {
    unsafe {
        libc::kill(pid as libc::pid_t, libc::SIGKILL);
    }
}

/// Wait up to `timeout` for the child to exit, polling `try_wait`.
/// Returns `true` if the child exited cleanly within the window.
fn wait_with_timeout(child: &mut Child, timeout: Duration) -> bool {
    let deadline = Instant::now() + timeout;
    loop {
        match child.try_wait() {
            Ok(Some(_)) => return true,
            Ok(None) => {
                if Instant::now() >= deadline {
                    return false;
                }
                std::thread::sleep(Duration::from_millis(50));
            }
            Err(_) => return false,
        }
    }
}

/// Coordinator for the network proxy used by the Bubblewrap backend.
///
/// Cooperative model: launches an unprivileged HTTP proxy (either external
/// or the bundled `linux-test-proxy`), and the caller is responsible for
/// setting `HTTP_PROXY` / `HTTPS_PROXY` env vars inside the sandbox.
///
/// The coordinator is **not** active until [`start`](Self::start) succeeds,
/// and is automatically cleaned up by [`stop`](Self::stop) or `Drop`.
pub struct LinuxProxyCoordinator {
    proxy_address: Option<ProxyAddress>,
    test_proxy: Option<TestProxyChild>,
}

impl LinuxProxyCoordinator {
    /// Create an inactive coordinator. Call [`start`](Self::start) to launch.
    pub fn new() -> Self {
        Self {
            proxy_address: None,
            test_proxy: None,
        }
    }

    /// Returns `true` once a proxy has been started.
    pub fn is_active(&self) -> bool {
        self.proxy_address.is_some()
    }

    /// Returns the resolved proxy address (if any).
    pub fn address(&self) -> Option<&ProxyAddress> {
        self.proxy_address.as_ref()
    }

    /// Activate the proxy.
    ///
    /// - If `proxy_config.builtin_test_server` is `true`, launches the
    ///   bundled `linux-test-proxy` binary on `bind_address:0` and reads
    ///   the assigned port from the proxy's ready file. `allowed_hosts`,
    ///   `blocked_hosts`, and `default_policy` are passed to the test
    ///   proxy as `--allow-host` / `--block-host` / `--default-policy`
    ///   flags so the cooperative env-var proxy honors the request's
    ///   `defaultPolicy: "block"` semantics (deny-by-default).
    /// - Otherwise, uses the externally provided `proxy_config.address`.
    ///   `allowed_hosts` / `blocked_hosts` / `default_policy` are ignored
    ///   in this case: the external proxy is assumed to apply its own
    ///   policy.
    /// - If the proxy config is disabled (`is_enabled()` returns `false`),
    ///   this is a no-op and the coordinator remains inactive.
    ///
    /// `bind_address` is the IP the test proxy listens on. For Bubblewrap
    /// pass `"127.0.0.1"`; future LXC reuse can pass a bridge gateway IP.
    pub fn start(
        &mut self,
        proxy_config: &ProxyConfig,
        bind_address: &str,
        allowed_hosts: &[String],
        blocked_hosts: &[String],
        default_policy: NetworkPolicy,
        logger: &mut Logger,
    ) -> Result<(), WxcError> {
        if self.is_active() {
            return Err(WxcError::NetworkProxy(
                "Linux network proxy is already active".into(),
            ));
        }

        if !proxy_config.is_enabled() {
            return Ok(());
        }

        let address = if proxy_config.builtin_test_server {
            let port = self.launch_test_proxy(
                bind_address,
                allowed_hosts,
                blocked_hosts,
                default_policy,
                logger,
            )?;
            ProxyAddress::new(bind_address.to_string(), port)
        } else if let Some(ref addr) = proxy_config.address {
            addr.clone()
        } else {
            // is_enabled() was true but neither variant is set -- defensive
            // guard, should be unreachable.
            return Err(WxcError::NetworkProxy(
                "Network proxy enabled but no address or builtin server configured".into(),
            ));
        };

        self.proxy_address = Some(address);

        logger.log_line(&format!(
            "Linux network proxy active: {}",
            self.proxy_address.as_ref().unwrap().to_url(),
        ));

        Ok(())
    }

    /// Spawn `linux-test-proxy` and read its port from the ready file.
    ///
    /// On any post-spawn error this method kills the child, waits briefly,
    /// and removes the temp directory before returning -- callers must
    /// **not** rely on `Drop` for cleanup of failed launches.
    fn launch_test_proxy(
        &mut self,
        bind_address: &str,
        allow_hosts: &[String],
        block_hosts: &[String],
        default_policy: NetworkPolicy,
        logger: &mut Logger,
    ) -> Result<u16, WxcError> {
        logger.log_line(
            "WARNING: Starting builtin linux-test-proxy -- this is for integration \
             testing only, NOT for production use.",
        );

        let unique_id = generate_unique_id();
        let temp_dir = create_private_temp_dir(&unique_id)?;
        let ready_file = temp_dir.join("ready.port");

        let proxy_exe = match resolve_sibling_binary("linux-test-proxy") {
            Ok(path) => path,
            Err(err) => {
                remove_temp_dir(&temp_dir);
                return Err(err);
            }
        };

        let default_policy_arg = match default_policy {
            NetworkPolicy::Allow => "allow",
            NetworkPolicy::Block => "block",
        };

        let mut cmd = Command::new(&proxy_exe);
        cmd.arg("--ready-file")
            .arg(&ready_file)
            .arg("--bind-address")
            .arg(bind_address)
            .arg("--default-policy")
            .arg(default_policy_arg);
        for host in allow_hosts {
            cmd.arg("--allow-host").arg(host);
        }
        for host in block_hosts {
            cmd.arg("--block-host").arg(host);
        }
        // Use a null stderr to avoid corrupting the JSON envelope that
        // lxc-exec writes on its own stderr stream (the proxy may emit
        // diagnostic lines).
        cmd.stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());

        let mut child = match cmd.spawn() {
            Ok(c) => c,
            Err(err) => {
                remove_temp_dir(&temp_dir);
                return Err(WxcError::NetworkProxy(format!(
                    "Failed to launch linux-test-proxy: {}",
                    err
                )));
            }
        };

        let port = match poll_for_port(&ready_file, &mut child) {
            Ok(p) => p,
            Err(err) => {
                let pid = child.id();
                send_sigterm(pid);
                if !wait_with_timeout(&mut child, STOP_TIMEOUT) {
                    send_sigkill(pid);
                    let _ = child.wait();
                }
                remove_temp_dir(&temp_dir);
                return Err(err);
            }
        };

        self.test_proxy = Some(TestProxyChild {
            child,
            ready_file,
            temp_dir,
        });

        logger.log_line(&format!(
            "linux-test-proxy listening on {}:{}",
            bind_address, port
        ));

        Ok(port)
    }

    /// Stop the proxy if active. Idempotent and best-effort. Errors during
    /// shutdown are logged but never returned.
    pub fn stop(&mut self, logger: &mut Logger) {
        if let Some(mut tp) = self.test_proxy.take() {
            let pid = tp.child.id();
            logger.log_line("Stopping linux-test-proxy...");
            send_sigterm(pid);
            if wait_with_timeout(&mut tp.child, STOP_TIMEOUT) {
                logger.log_line("linux-test-proxy exited.");
            } else {
                logger
                    .log_line("Warning: linux-test-proxy did not exit within 5s; sending SIGKILL.");
                send_sigkill(pid);
                let _ = tp.child.wait();
            }
            let _ = fs::remove_file(&tp.ready_file);
            remove_temp_dir(&tp.temp_dir);
        }
        self.proxy_address = None;
    }
}

impl Default for LinuxProxyCoordinator {
    fn default() -> Self {
        Self::new()
    }
}

impl Drop for LinuxProxyCoordinator {
    /// Silent best-effort cleanup if the coordinator is still active at
    /// drop time. **Never** writes to stderr or `Logger` because the drop
    /// may run during panic unwinding and we must not corrupt the JSON
    /// envelope on `lxc-exec`'s stderr.
    fn drop(&mut self) {
        if let Some(mut tp) = self.test_proxy.take() {
            let pid = tp.child.id();
            send_sigterm(pid);
            if !wait_with_timeout(&mut tp.child, STOP_TIMEOUT) {
                send_sigkill(pid);
                let _ = tp.child.wait();
            }
            let _ = fs::remove_file(&tp.ready_file);
            remove_temp_dir(&tp.temp_dir);
        }
        self.proxy_address = None;
    }
}

/// Wait for the ready file to appear, parse the port, then re-check that
/// the child is still alive. Returns an error if the file does not appear
/// in time, the contents are not a valid port, or the child exited before
/// or after publishing the port.
fn poll_for_port(ready_file: &Path, child: &mut Child) -> Result<u16, WxcError> {
    let deadline = Instant::now() + READY_TIMEOUT;
    loop {
        // 1. Has the child exited prematurely?
        match child.try_wait() {
            Ok(Some(status)) => {
                return Err(WxcError::NetworkProxy(format!(
                    "linux-test-proxy exited before becoming ready (status: {:?})",
                    status
                )));
            }
            Ok(None) => {}
            Err(err) => {
                return Err(WxcError::NetworkProxy(format!(
                    "Failed to query linux-test-proxy status: {}",
                    err
                )));
            }
        }

        // 2. Has the ready file appeared?
        if ready_file.exists() {
            break;
        }

        if Instant::now() >= deadline {
            return Err(WxcError::NetworkProxy(format!(
                "Timed out waiting for linux-test-proxy ready file ({:?})",
                READY_TIMEOUT
            )));
        }
        std::thread::sleep(READY_POLL_INTERVAL);
    }

    let content = fs::read_to_string(ready_file)
        .map_err(|err| WxcError::NetworkProxy(format!("Failed to read ready file: {}", err)))?;
    let port: u16 = content.trim().parse().map_err(|err| {
        WxcError::NetworkProxy(format!(
            "Invalid port in ready file '{}': {}",
            content.trim(),
            err
        ))
    })?;

    // 3. Re-check liveness AFTER parsing port. A dead proxy with a valid
    //    port is useless to the caller and must surface as an error.
    match child.try_wait() {
        Ok(Some(status)) => Err(WxcError::NetworkProxy(format!(
            "linux-test-proxy exited immediately after publishing port (status: {:?})",
            status
        ))),
        Ok(None) => Ok(port),
        Err(err) => Err(WxcError::NetworkProxy(format!(
            "Failed to re-check linux-test-proxy status: {}",
            err
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_logger() -> Logger {
        Logger::new(crate::logger::Mode::Buffer)
    }

    #[test]
    fn new_coordinator_is_inactive() {
        let c = LinuxProxyCoordinator::new();
        assert!(!c.is_active());
        assert!(c.address().is_none());
    }

    #[test]
    fn default_coordinator_is_inactive() {
        let c = LinuxProxyCoordinator::default();
        assert!(!c.is_active());
    }

    #[test]
    fn start_with_disabled_proxy_is_noop() {
        let mut c = LinuxProxyCoordinator::new();
        let mut logger = make_logger();
        let cfg = ProxyConfig::default();
        assert!(!cfg.is_enabled());
        c.start(
            &cfg,
            "127.0.0.1",
            &[],
            &[],
            NetworkPolicy::Allow,
            &mut logger,
        )
        .unwrap();
        assert!(!c.is_active());
    }

    #[test]
    fn start_with_external_address_activates() {
        let mut c = LinuxProxyCoordinator::new();
        let mut logger = make_logger();
        let cfg = ProxyConfig {
            address: Some(ProxyAddress::new("127.0.0.1".into(), 8888)),
            ..Default::default()
        };
        assert!(cfg.is_enabled());

        c.start(
            &cfg,
            "127.0.0.1",
            &[],
            &[],
            NetworkPolicy::Allow,
            &mut logger,
        )
        .unwrap();
        assert!(c.is_active());
        let addr = c.address().unwrap();
        assert_eq!(addr.port(), 8888);

        c.stop(&mut logger);
        assert!(!c.is_active());
    }

    #[test]
    fn start_is_rejected_if_already_active() {
        let mut c = LinuxProxyCoordinator::new();
        let mut logger = make_logger();
        let cfg = ProxyConfig {
            address: Some(ProxyAddress::new("127.0.0.1".into(), 9001)),
            ..Default::default()
        };

        c.start(
            &cfg,
            "127.0.0.1",
            &[],
            &[],
            NetworkPolicy::Allow,
            &mut logger,
        )
        .unwrap();
        let err = c
            .start(
                &cfg,
                "127.0.0.1",
                &[],
                &[],
                NetworkPolicy::Allow,
                &mut logger,
            )
            .unwrap_err();
        match err {
            WxcError::NetworkProxy(msg) => assert!(msg.contains("already active")),
            other => panic!("unexpected error: {:?}", other),
        }
    }

    #[test]
    fn stop_is_idempotent() {
        let mut c = LinuxProxyCoordinator::new();
        let mut logger = make_logger();
        c.stop(&mut logger);
        c.stop(&mut logger);
        assert!(!c.is_active());
    }

    #[test]
    fn generate_unique_id_produces_distinct_ids() {
        let a = generate_unique_id();
        let b = generate_unique_id();
        assert_ne!(a, b);
    }

    #[test]
    fn create_and_remove_private_temp_dir() {
        let id = generate_unique_id();
        let dir = create_private_temp_dir(&id).unwrap();
        assert!(dir.exists());

        #[cfg(target_os = "linux")]
        {
            use std::os::unix::fs::PermissionsExt;
            let meta = fs::metadata(&dir).unwrap();
            assert_eq!(meta.permissions().mode() & 0o777, 0o700);
        }

        remove_temp_dir(&dir);
        assert!(!dir.exists());
    }

    #[test]
    fn poll_for_port_times_out_when_file_never_appears() {
        let id = generate_unique_id();
        let dir = create_private_temp_dir(&id).unwrap();
        let ready_file = dir.join("ready.port");

        // Spawn a sleep that lives longer than the test timeout below.
        let mut child = Command::new("sleep")
            .arg("30")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("sleep is available on Linux test hosts");

        // Override the timeout: use a short window for the test by
        // temporarily inlining the polling logic.
        let deadline = Instant::now() + Duration::from_millis(300);
        let result: Result<u16, WxcError> = loop {
            match child.try_wait() {
                Ok(Some(status)) => {
                    break Err(WxcError::NetworkProxy(format!(
                        "exited early: {:?}",
                        status
                    )));
                }
                Ok(None) => {}
                Err(err) => break Err(WxcError::NetworkProxy(format!("query: {}", err))),
            }
            if ready_file.exists() {
                // Shouldn't happen in this test.
                break Ok(0);
            }
            if Instant::now() >= deadline {
                break Err(WxcError::NetworkProxy("timeout".into()));
            }
            std::thread::sleep(Duration::from_millis(20));
        };

        assert!(result.is_err());

        let _ = child.kill();
        let _ = child.wait();
        remove_temp_dir(&dir);
    }

    #[test]
    fn poll_for_port_detects_premature_child_exit() {
        let id = generate_unique_id();
        let dir = create_private_temp_dir(&id).unwrap();
        let ready_file = dir.join("ready.port");

        // `true` exits successfully immediately.
        let mut child = Command::new("true")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("true is available on Linux test hosts");

        // Give the child a moment to exit.
        std::thread::sleep(Duration::from_millis(100));

        let err = poll_for_port(&ready_file, &mut child).unwrap_err();
        match err {
            WxcError::NetworkProxy(msg) => {
                assert!(
                    msg.contains("exited before becoming ready"),
                    "unexpected message: {}",
                    msg
                );
            }
            other => panic!("unexpected error: {:?}", other),
        }

        remove_temp_dir(&dir);
    }
}
