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
    // `geteuid` only exists on Unix; on other targets the function is never
    // invoked in production (lxc-exec is Linux-only) but the crate still
    // needs to compile workspace-wide, so fall back to a non-root EUID.
    #[cfg(unix)]
    // SAFETY: `geteuid` is a thread-safe, side-effect-free libc call.
    fn current_euid() -> u32 {
        unsafe { libc::geteuid() as u32 }
    }
    #[cfg(not(unix))]
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

    /// Execute a command inside a running container using lxc-attach.
    ///
    /// Inherits the parent process's stdin/stdout/stderr so that the inner
    /// process is wired straight to whatever drives lxc-exec — typically a
    /// pty owned by node-pty on the host. This matches the AppContainer
    /// runner on Windows, where the sandboxed child shares the parent's
    /// ConPTY (see `wxc_common::appcontainer_runner`). Without this, the
    /// inner process gets a closed stdin and exits immediately on EOF,
    /// breaking interactive shells.
    ///
    /// Stdout/stderr are streamed live; the returned strings are always
    /// empty. Callers that need captured output should run a self-contained
    /// `commandLine` (e.g. `echo ... > file`) and read the file separately.
    pub fn attach_run(
        &self,
        command: &str,
        _working_directory: &str,
    ) -> Result<(i32, String, String), String> {
        use std::process::Stdio;

        let mut cmd = self.lxc_command("lxc-attach");
        cmd.args(["--", "/bin/sh", "-c", command]);
        cmd.stdin(Stdio::inherit())
            .stdout(Stdio::inherit())
            .stderr(Stdio::inherit());

        let status = cmd
            .status()
            .map_err(|e| format!("Failed to run lxc-attach: {}", e))?;

        Ok((status.code().unwrap_or(-1), String::new(), String::new()))
    }

    /// Stop the container.
    pub fn stop(&self) -> Result<(), String> {
        Self::run_status(self.lxc_command("lxc-stop"), "lxc-stop")
    }

    /// Destroy the container (removes rootfs and config).
    pub fn destroy(&self) -> Result<(), String> {
        if self.is_running() {
            let _ = self.stop();
        }
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
