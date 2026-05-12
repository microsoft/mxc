// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Safe Rust wrappers around the liblxc C API.
//!
//! liblxc exposes container management through a `struct lxc_container` with
//! function pointer fields. This module provides an RAII `LxcContainer` wrapper
//! that calls the appropriate function pointers and handles cleanup.

/// Resolve the default LXC storage path the way liblxc does.
///
/// Replicates the algorithm liblxc applies when no explicit `-P <lxcpath>` is
/// provided to its CLI tools, using the supplied environment lookup and
/// effective-uid hooks. Extracted into a free function so unit tests can
/// exercise every branch deterministically.
///
/// Resolution order:
///  1. `LXC_PATH` env var (if non-empty).
///  2. `/var/lib/lxc` when running as root (EUID 0).
///  3. `$XDG_DATA_HOME/lxc` if `XDG_DATA_HOME` is set and non-empty.
///  4. `$HOME/.local/share/lxc` if `HOME` is set and non-empty.
///  5. `/var/lib/lxc` as a last-resort fallback.
fn resolve_lxcpath_with_env<F, G>(get_env: F, geteuid: G) -> String
where
    F: Fn(&str) -> Option<String>,
    G: Fn() -> u32,
{
    if let Some(p) = get_env("LXC_PATH") {
        if !p.is_empty() {
            return p;
        }
    }
    if geteuid() == 0 {
        return "/var/lib/lxc".to_string();
    }
    if let Some(xdg) = get_env("XDG_DATA_HOME") {
        if !xdg.is_empty() {
            return format!("{}/lxc", xdg.trim_end_matches('/'));
        }
    }
    if let Some(home) = get_env("HOME") {
        if !home.is_empty() {
            return format!("{}/.local/share/lxc", home.trim_end_matches('/'));
        }
    }
    "/var/lib/lxc".to_string()
}

/// Resolve the default LXC storage path for the current process.
///
/// See [`resolve_lxcpath_with_env`] for the exact algorithm. This wrapper
/// reads the real environment and effective UID.
pub fn resolve_default_lxcpath() -> String {
    // lxc-exec is Linux-only at runtime, but the crate has to compile
    // workspace-wide (clippy runs on windows-latest, and macOS dev builds
    // pull lxc_common in transitively). On non-Linux targets the function
    // is never invoked in production, so fall back to a non-root EUID.
    #[cfg(target_os = "linux")]
    // SAFETY: `geteuid` is a thread-safe, side-effect-free libc call.
    fn current_euid() -> u32 {
        unsafe { libc::geteuid() as u32 }
    }
    #[cfg(not(target_os = "linux"))]
    fn current_euid() -> u32 {
        1
    }

    resolve_lxcpath_with_env(|k| std::env::var(k).ok(), current_euid)
}

/// Safe wrapper around an LXC container.
pub struct LxcContainer {
    name: String,
    /// Resolved LXC storage path (the "lxcpath"). Always populated — either
    /// from an explicit caller override or from [`resolve_default_lxcpath`].
    /// Passed via `-P <path>` to every `lxc-*` shell-out so behavior is
    /// identical regardless of how the binary is launched (e.g. cron, systemd
    /// units with non-default `HOME`).
    lxc_path: String,
}

impl LxcContainer {
    /// Create a new LXC container handle.
    ///
    /// `lxc_path`, when `Some`, overrides liblxc's default path resolution.
    /// When `None`, the default is resolved via [`resolve_default_lxcpath`].
    pub fn new(name: &str, lxc_path: Option<&str>) -> Self {
        Self {
            name: name.to_string(),
            lxc_path: lxc_path
                .map(|s| s.to_string())
                .unwrap_or_else(resolve_default_lxcpath),
        }
    }

    /// Get the container name.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Get the resolved LXC storage path (the "lxcpath") used by this handle.
    pub fn lxc_path(&self) -> &str {
        &self.lxc_path
    }

    /// Build a `Command` for an `lxc-*` tool with `-P <lxc_path> -n <name>`
    /// already populated. Centralizes the argv prefix so we can't accidentally
    /// drop `-P` again (see #274).
    fn lxc_command(&self, tool: &str) -> std::process::Command {
        let mut cmd = std::process::Command::new(tool);
        cmd.arg("-P").arg(&self.lxc_path).arg("-n").arg(&self.name);
        cmd
    }

    /// Run a prepared `lxc-*` command, mapping spawn / non-zero-exit failures
    /// to a `String` error tagged with the tool name.
    fn run_status(mut cmd: std::process::Command, tool: &str) -> Result<(), String> {
        let output = cmd
            .output()
            .map_err(|e| format!("Failed to run {}: {}", tool, e))?;
        if !output.status.success() {
            return Err(format!(
                "{} failed: {}",
                tool,
                String::from_utf8_lossy(&output.stderr)
            ));
        }
        Ok(())
    }

    /// Check if the container exists.
    pub fn is_defined(&self) -> bool {
        let output = self.lxc_command("lxc-info").output();
        matches!(output, Ok(o) if o.status.success())
    }

    /// Check if the container is running.
    pub fn is_running(&self) -> bool {
        let output = self.lxc_command("lxc-info").arg("-s").output();
        match output {
            Ok(o) => String::from_utf8_lossy(&o.stdout).contains("RUNNING"),
            Err(_) => false,
        }
    }

    /// Create the container from a template/distribution.
    pub fn create(&self, distribution: &str, release: &str) -> Result<(), String> {
        let mut cmd = self.lxc_command("lxc-create");
        cmd.args(["-t", "download", "--", "-d"])
            .arg(distribution)
            .arg("-r")
            .arg(release)
            .arg("-a")
            .arg(Self::current_arch());
        Self::run_status(cmd, "lxc-create")
    }

    /// Set a configuration item on the container.
    ///
    /// Appends `key = value` to the container's config file. The error
    /// message includes the key, value, and target path so users can tell at
    /// a glance whether the failure is about the entry contents (e.g. a
    /// nonexistent mount source) or about the config file itself.
    pub fn set_config_item(&self, key: &str, value: &str) -> Result<(), String> {
        let config_path = self.config_file_path();
        let entry = format!("{} = {}\n", key, value);

        std::fs::OpenOptions::new()
            .append(true)
            .open(&config_path)
            .and_then(|mut f| {
                use std::io::Write;
                f.write_all(entry.as_bytes())
            })
            .map_err(|e| {
                format!(
                    "Failed to set config item {} = {}: {} (config file: {})",
                    key, value, e, config_path
                )
            })
    }

    /// Start the container.
    pub fn start(&self) -> Result<(), String> {
        Self::run_status(self.lxc_command("lxc-start"), "lxc-start")
    }

    /// Execute a command inside the container, capturing stdout/stderr.
    /// Returns (exit_code, stdout, stderr).
    pub fn exec(
        &self,
        command: &str,
        _working_directory: &str,
        _timeout_ms: u32,
    ) -> Result<(i32, String, String), String> {
        // TODO: Implement timeout and working directory support.
        let mut cmd = self.lxc_command("lxc-execute");
        cmd.args(["--", "/bin/sh", "-c", command]);

        let output = cmd
            .output()
            .map_err(|e| format!("Failed to run lxc-execute: {}", e))?;

        Ok((
            output.status.code().unwrap_or(-1),
            String::from_utf8_lossy(&output.stdout).to_string(),
            String::from_utf8_lossy(&output.stderr).to_string(),
        ))
    }

    /// Execute a command inside a running container using lxc-attach, with
    /// the inner process attached to a freshly-allocated pty.
    ///
    /// This bridges the host's stdin/stdout/stderr to the inner pty, but
    /// **defers forwarding host stdin to the inner process until bash has
    /// produced its first output byte**. That delay is essential: an
    /// interactive shell calls `tcsetattr` on its stdin during readline
    /// init, which can flush any bytes the parent buffered into the pty
    /// before the shell got there. Without the delay, anything the CLI
    /// pre-buffers (e.g. its shell-init wrapper) is silently swallowed.
    ///
    /// Stdout/stderr are streamed live via the master fd; the returned
    /// strings are always empty. Callers needing captured output should run
    /// a self-contained `commandLine` and read it back from a file.
    ///
    /// Only built on Linux — the implementation depends on `pre_exec`,
    /// `openpty`, and `TIOCSCTTY`. The crate still has to compile
    /// workspace-wide on Windows (the `wxc-exec-lint` CI job runs
    /// `cargo clippy --workspace` on `windows-latest`) and on macOS dev
    /// machines, so a stub is provided below for non-Linux targets.
    #[cfg(target_os = "linux")]
    pub fn attach_run(
        &self,
        command: &str,
        _working_directory: &str,
    ) -> Result<(i32, String, String), String> {
        use nix::pty::openpty;
        use std::io::{Read, Write};
        use std::process::Stdio;
        use std::sync::mpsc;
        use std::thread;
        use std::time::Duration;

        // Allocate an inner pty pair. The slave goes to lxc-attach (and thus
        // bash inside the container) so the inner process sees a real tty;
        // we keep the master and bridge it to our own stdio.
        let pty_pair = openpty(None, None).map_err(|e| format!("openpty failed: {}", e))?;

        // Three fd duplicates of the slave so each Stdio takes ownership of
        // its own handle; otherwise std::process::Stdio::from would consume
        // the single OwnedFd and the rest of the spawn calls would fail.
        let slave_in: Stdio = pty_pair
            .slave
            .try_clone()
            .map_err(|e| format!("dup slave for stdin: {}", e))?
            .into();
        let slave_out: Stdio = pty_pair
            .slave
            .try_clone()
            .map_err(|e| format!("dup slave for stdout: {}", e))?
            .into();
        let slave_err: Stdio = pty_pair.slave.into();

        let mut cmd = self.lxc_command("lxc-attach");
        cmd.args(["--", "/bin/sh", "-c", command]);
        cmd.stdin(slave_in).stdout(slave_out).stderr(slave_err);

        // Drop the inherited controlling terminal in the child and make the
        // slave end of our pty its new controlling tty. Without this,
        // lxc-attach detects that it has a controlling tty (the outer pty
        // from node-pty) and forwards the inner pty's I/O to `/dev/tty`
        // directly, bypassing the slave fds we wired into stdio. Our master
        // would then see no data at all.
        unsafe {
            use std::os::unix::process::CommandExt;
            cmd.pre_exec(|| {
                // Become a new session leader, detaching from the inherited
                // controlling terminal.
                nix::unistd::setsid().map_err(std::io::Error::from)?;
                // SAFETY: ioctl on fd 0 (the slave we just dup2'd in via
                // stdin) to make it the new controlling tty. Errors are
                // non-fatal because setsid above already cleared the ctty
                // state, which is what actually matters for lxc-attach.
                let _ = libc::ioctl(0, libc::TIOCSCTTY as _, 0);
                Ok(())
            });
        }

        let mut child = cmd
            .spawn()
            .map_err(|e| format!("Failed to spawn lxc-attach: {}", e))?;

        // The child inherited all three slave handles and the parent's
        // copies have been moved into Stdio. The slave will be fully closed
        // when the child exits, which makes our master read return EOF.

        // OwnedFd -> File via std::convert::From; no `unsafe` needed.
        let master: std::fs::File = pty_pair.master.into();
        let mut master_writer = master
            .try_clone()
            .map_err(|e| format!("dup master: {}", e))?;
        let mut master_reader = master;

        // Output forwarder: master -> host stdout. Signals "ready" on the
        // first byte from inside the container — at that point bash has
        // finished its readline/tcsetattr init and is safe to feed.
        let (ready_tx, ready_rx) = mpsc::channel::<()>();
        let output_thread = thread::spawn(move || {
            let mut buf = [0u8; 4096];
            let mut signaled = false;
            let mut stdout = std::io::stdout();
            loop {
                match master_reader.read(&mut buf) {
                    Ok(0) => break,
                    Ok(n) => {
                        if !signaled {
                            let _ = ready_tx.send(());
                            signaled = true;
                        }
                        let _ = stdout.write_all(&buf[..n]);
                        let _ = stdout.flush();
                    }
                    Err(_) => break,
                }
            }
        });

        // Wait for bash to print its first byte before forwarding host stdin.
        // Cap the wait so a wedged container doesn't block forever; if the
        // shell never produces output the caller's higher-level timeout
        // catches it.
        let _ = ready_rx.recv_timeout(Duration::from_secs(5));

        // Input forwarder: host stdin -> master. Detached; exits when stdin
        // closes (which happens when our parent process closes the pty).
        thread::spawn(move || {
            let mut buf = [0u8; 4096];
            let mut stdin = std::io::stdin();
            loop {
                match stdin.read(&mut buf) {
                    Ok(0) => break,
                    Ok(n) => {
                        if master_writer.write_all(&buf[..n]).is_err() {
                            break;
                        }
                    }
                    Err(_) => break,
                }
            }
        });

        let status = child
            .wait()
            .map_err(|e| format!("wait on lxc-attach: {}", e))?;

        // Drain remaining output before returning. The slave fds are closed
        // on child exit, so master_reader will hit EOF and the thread exits.
        let _ = output_thread.join();

        Ok((status.code().unwrap_or(-1), String::new(), String::new()))
    }

    /// Non-Linux stub. `lxc-exec` is Linux-only at runtime, but the
    /// workspace still builds on Windows (clippy CI) and macOS (dev), so
    /// the signature has to exist on every target.
    #[cfg(not(target_os = "linux"))]
    pub fn attach_run(
        &self,
        _command: &str,
        _working_directory: &str,
    ) -> Result<(i32, String, String), String> {
        Err("LxcContainer::attach_run is only supported on Linux".to_string())
    }

    /// Stop the container.
    pub fn stop(&self) -> Result<(), String> {
        Self::run_status(self.lxc_command("lxc-stop"), "lxc-stop")
    }

    /// Destroy the container (removes rootfs and config).
    ///
    /// `lxc-destroy -f` already force-stops a running container; we used to
    /// call `lxc-stop` first, but plain `lxc-stop` waits up to 60 s for a
    /// graceful shutdown — fatal for distros with systemd as PID 1 in
    /// unprivileged userns where init never cleanly responds to SIGPWR.
    /// Forcing the stop via destroy keeps this fast for both alpine and
    /// ubuntu-class images.
    pub fn destroy(&self) -> Result<(), String> {
        let mut cmd = self.lxc_command("lxc-destroy");
        cmd.arg("-f");
        Self::run_status(cmd, "lxc-destroy")
    }

    /// Get the path to the container's config file.
    fn config_file_path(&self) -> String {
        format!("{}/{}/config", self.lxc_path, self.name)
    }

    /// Get the current system architecture string for LXC templates.
    fn current_arch() -> &'static str {
        #[cfg(target_arch = "x86_64")]
        {
            "amd64"
        }
        #[cfg(target_arch = "aarch64")]
        {
            "arm64"
        }
        #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
        {
            "amd64"
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn no_env(_: &str) -> Option<String> {
        None
    }

    #[test]
    fn lxcpath_honors_lxc_path_env() {
        let p = resolve_lxcpath_with_env(
            |k| {
                if k == "LXC_PATH" {
                    Some("/custom/lxc".into())
                } else {
                    None
                }
            },
            || 1000,
        );
        assert_eq!(p, "/custom/lxc");
    }

    #[test]
    fn lxcpath_lxc_path_takes_precedence_over_root_default() {
        // Even as root, LXC_PATH wins, matching liblxc's behavior.
        let p = resolve_lxcpath_with_env(
            |k| {
                if k == "LXC_PATH" {
                    Some("/srv/lxc".into())
                } else {
                    None
                }
            },
            || 0,
        );
        assert_eq!(p, "/srv/lxc");
    }

    #[test]
    fn lxcpath_root_default() {
        let p = resolve_lxcpath_with_env(no_env, || 0);
        assert_eq!(p, "/var/lib/lxc");
    }

    #[test]
    fn lxcpath_user_uses_xdg_data_home() {
        let p = resolve_lxcpath_with_env(
            |k| match k {
                "XDG_DATA_HOME" => Some("/home/u/.data".into()),
                "HOME" => Some("/home/u".into()),
                _ => None,
            },
            || 1000,
        );
        // XDG_DATA_HOME wins over HOME for unprivileged users.
        assert_eq!(p, "/home/u/.data/lxc");
    }

    #[test]
    fn lxcpath_user_strips_trailing_slash_on_xdg() {
        let p = resolve_lxcpath_with_env(
            |k| {
                if k == "XDG_DATA_HOME" {
                    Some("/home/u/.data/".into())
                } else {
                    None
                }
            },
            || 1000,
        );
        assert_eq!(p, "/home/u/.data/lxc");
    }

    #[test]
    fn lxcpath_user_falls_back_to_home() {
        let p = resolve_lxcpath_with_env(
            |k| {
                if k == "HOME" {
                    Some("/home/u".into())
                } else {
                    None
                }
            },
            || 1000,
        );
        assert_eq!(p, "/home/u/.local/share/lxc");
    }

    #[test]
    fn lxcpath_user_strips_trailing_slash_on_home() {
        let p = resolve_lxcpath_with_env(
            |k| {
                if k == "HOME" {
                    Some("/home/u/".into())
                } else {
                    None
                }
            },
            || 1000,
        );
        assert_eq!(p, "/home/u/.local/share/lxc");
    }

    #[test]
    fn lxcpath_empty_env_values_are_ignored() {
        // Empty LXC_PATH/XDG_DATA_HOME must not be used as the path; resolution
        // should fall through to the next candidate.
        let p = resolve_lxcpath_with_env(
            |k| match k {
                "LXC_PATH" | "XDG_DATA_HOME" => Some(String::new()),
                "HOME" => Some("/h".into()),
                _ => None,
            },
            || 1000,
        );
        assert_eq!(p, "/h/.local/share/lxc");
    }

    #[test]
    fn lxcpath_user_with_no_env_has_safe_fallback() {
        // Highly unusual: unprivileged process with neither HOME nor
        // XDG_DATA_HOME. We still return a deterministic path rather than
        // panicking; callers will surface the resulting filesystem error.
        let p = resolve_lxcpath_with_env(no_env, || 1000);
        assert_eq!(p, "/var/lib/lxc");
    }

    #[test]
    fn lxc_container_uses_resolved_lxcpath_when_none_provided() {
        // We can't easily mock libc::geteuid() in the real ctor, but we can
        // assert the contract: lxc_path() always returns a non-empty path,
        // even when the caller passes None.
        let c = LxcContainer::new("any", None);
        assert!(!c.lxc_path().is_empty());
    }

    #[test]
    fn lxc_container_honors_explicit_lxc_path() {
        let c = LxcContainer::new("my-box", Some("/opt/lxc"));
        assert_eq!(c.lxc_path(), "/opt/lxc");
        assert_eq!(c.config_file_path(), "/opt/lxc/my-box/config");
    }

    #[test]
    fn config_file_path_uses_resolved_path() {
        let c = LxcContainer::new("box", Some("/var/lib/lxc"));
        assert_eq!(c.config_file_path(), "/var/lib/lxc/box/config");
    }

    #[test]
    fn set_config_item_error_includes_key_value_and_path() {
        // Point the container at a path that does not exist so the open()
        // call reliably fails. The error message must include all three
        // diagnostic details so users can pinpoint the failure.
        let bogus_base = std::env::temp_dir().join(format!(
            "mxc-nonexistent-lxc-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0)
        ));
        let container = LxcContainer::new("ghost", Some(bogus_base.to_str().unwrap()));
        let key = "lxc.mount.entry";
        let value = "/host /target none bind,create=dir 0 0";

        let err = container
            .set_config_item(key, value)
            .expect_err("set_config_item should fail when config file is missing");

        assert!(err.contains(key), "error must mention key, got: {}", err);
        assert!(
            err.contains(value),
            "error must mention value, got: {}",
            err
        );
        assert!(
            err.contains("ghost/config"),
            "error must mention container config path, got: {}",
            err
        );
    }
}
