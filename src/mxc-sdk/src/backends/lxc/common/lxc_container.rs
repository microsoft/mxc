// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#[cfg(target_os = "linux")]
use super::{
    build_attach_args_with_env_control, joined_capture, read_to_end_on_thread,
    unblock_fatal_signals, wait_for_drain,
};
use super::{resolve_default_lxcpath, StartNetwork, MANAGED_MOUNTS_BEGIN, MANAGED_MOUNTS_END};

pub struct LxcContainer {
    name: String,
    lxc_path: String,
}

impl LxcContainer {
    pub fn new(name: &str, lxc_path: Option<&str>) -> Self {
        Self {
            name: name.to_string(),
            lxc_path: lxc_path
                .map(|s| s.to_string())
                .unwrap_or_else(resolve_default_lxcpath),
        }
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn lxc_path(&self) -> &str {
        &self.lxc_path
    }

    fn lxc_command(&self, tool: &str) -> std::process::Command {
        let mut cmd = std::process::Command::new(tool);
        cmd.arg("-P").arg(&self.lxc_path).arg("-n").arg(&self.name);
        cmd
    }

    fn run_tool(mut cmd: std::process::Command) -> Result<(), String> {
        let tool = cmd.get_program().to_string_lossy().into_owned();
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

    /// Run a tool that releases the container, under a deadline.
    ///
    /// `lxc-stop` and `lxc-destroy` do not return until the container is fully
    /// gone, which a task wedged in uninterruptible sleep can hold open.
    #[cfg(target_os = "linux")]
    fn run_release_tool(mut cmd: std::process::Command) -> Result<(), String> {
        use crate::mxc_common::interruptible_reader::wrap_pipe;
        use crate::mxc_common::sandbox_process::{wait_with_timeout, StreamCloser, WaitError};
        use std::process::Stdio;

        // Generous enough to delete a large rootfs on slow storage.
        const RELEASE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(120);

        let tool = cmd.get_program().to_string_lossy().into_owned();
        cmd.stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::piped());

        let mut child = cmd
            .spawn()
            .map_err(|e| format!("Failed to run {}: {}", tool, e))?;

        let (stderr, stderr_canceller) = match wrap_pipe(child.stderr.take()) {
            Ok(pipe) => pipe,
            Err(e) => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(format!("Failed to wrap the {} stderr pipe: {}", tool, e));
            }
        };
        let stderr = read_to_end_on_thread(stderr);

        let outcome = wait_with_timeout(&mut child, Some(RELEASE_TIMEOUT));
        if outcome.is_err() {
            let _ = child.kill();
            let _ = child.wait();
        } else {
            wait_for_drain(&None, &stderr);
        }

        // A descendant holding the pipe open would park the join below
        // indefinitely.
        if let Some(canceller) = stderr_canceller {
            canceller.close();
        }
        let captured = joined_capture(stderr);

        let status = match outcome {
            Ok(status) => status,
            Err(WaitError::Timeout) => {
                return Err(format!(
                    "{} did not finish within {}s",
                    tool,
                    RELEASE_TIMEOUT.as_secs()
                ));
            }
            Err(WaitError::Io(e)) => return Err(format!("Failed to wait for {}: {}", tool, e)),
        };

        if !status.success() {
            return Err(format!("{} failed: {}", tool, captured.trim()));
        }
        Ok(())
    }

    /// Stub for the workspace-wide clippy lane that runs on Windows.
    #[cfg(not(target_os = "linux"))]
    fn run_release_tool(cmd: std::process::Command) -> Result<(), String> {
        Self::run_tool(cmd)
    }

    pub fn is_defined(&self) -> bool {
        let output = self.lxc_command("lxc-info").output();
        matches!(output, Ok(o) if o.status.success())
    }

    pub fn is_running(&self) -> bool {
        let output = self.lxc_command("lxc-info").arg("-s").output();
        match output {
            Ok(o) => String::from_utf8_lossy(&o.stdout).contains("RUNNING"),
            Err(_) => false,
        }
    }

    pub fn init_pid(&self) -> Option<u32> {
        let output = self.lxc_command("lxc-info").arg("-p").output().ok()?;
        if !output.status.success() {
            return None;
        }
        let stdout = String::from_utf8_lossy(&output.stdout);
        for line in stdout.lines() {
            let token = line.trim();
            let token = token.strip_prefix("PID:").map(str::trim).unwrap_or(token);
            if let Ok(pid) = token.parse::<u32>() {
                if pid > 0 {
                    return Some(pid);
                }
            }
        }
        None
    }

    pub fn create(&self, distribution: &str, release: &str) -> Result<(), String> {
        let mut cmd = self.lxc_command("lxc-create");
        cmd.args(["-t", "download", "--", "-d"])
            .arg(distribution)
            .arg("-r")
            .arg(release)
            .arg("-a")
            .arg(Self::current_arch());
        Self::run_tool(cmd)
    }

    pub(crate) fn config_value(&self, key: &str) -> Result<String, String> {
        let mut cmd = self.lxc_command("lxc-info");
        cmd.args(["-H", "-c", key]);
        let output = cmd
            .output()
            .map_err(|error| format!("Failed to read LXC config {key}: {error}"))?;
        if !output.status.success() {
            return Err(format!(
                "Failed to read LXC config {key}: {}",
                String::from_utf8_lossy(&output.stderr)
            ));
        }
        Ok(String::from_utf8_lossy(&output.stdout).trim().to_owned())
    }

    fn config_uses_capability_keep_list(
        path: &std::path::Path,
        mut keep: bool,
    ) -> Result<bool, String> {
        if path.is_dir() || path.to_string_lossy().ends_with('/') {
            let entries = match std::fs::read_dir(path) {
                Ok(entries) => entries,
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(keep),
                Err(error) => return Err(format!("Failed to read LXC config directory: {error}")),
            };
            for entry in entries {
                let path = entry
                    .map_err(|error| format!("Failed to read LXC config entry: {error}"))?
                    .path();
                if path
                    .extension()
                    .is_some_and(|extension| extension == "conf")
                {
                    keep = Self::config_uses_capability_keep_list(&path, keep)?;
                }
            }
            return Ok(keep);
        }
        let config = std::fs::read_to_string(path)
            .map_err(|error| format!("Failed to read LXC capability mode: {error}"))?;
        for line in config.lines() {
            let Some((key, value)) = line.trim().split_once('=') else {
                continue;
            };
            let value = value.trim();
            let value = value
                .strip_prefix('"')
                .and_then(|value| value.strip_suffix('"'))
                .or_else(|| {
                    value
                        .strip_prefix('\'')
                        .and_then(|value| value.strip_suffix('\''))
                })
                .unwrap_or(value);
            match key.trim() {
                "lxc.include" if !value.is_empty() => {
                    keep =
                        Self::config_uses_capability_keep_list(std::path::Path::new(value), keep)?;
                }
                "lxc.cap.keep" => keep = !value.is_empty(),
                "lxc.cap.drop" => keep = false,
                _ => {}
            }
        }
        Ok(keep)
    }

    fn format_network_capability_removal(keep: &str, drop: &str) -> String {
        let capability_number = |value: &str| match value {
            "net_admin" => Some(12),
            "net_raw" => Some(13),
            _ => {
                let value = value.strip_prefix('+').unwrap_or(value);
                if let Some(hex) = value
                    .strip_prefix("0x")
                    .or_else(|| value.strip_prefix("0X"))
                {
                    u32::from_str_radix(hex, 16).ok()
                } else if value.starts_with('0') {
                    u32::from_str_radix(value, 8).ok()
                } else {
                    value.parse::<u32>().ok()
                }
            }
        };
        if !keep.trim().is_empty() {
            if !keep
                .split_whitespace()
                .any(|cap| matches!(capability_number(cap), Some(12 | 13)))
            {
                return String::new();
            }
            let retained = keep
                .split_whitespace()
                .filter(|cap| !matches!(capability_number(cap), Some(12 | 13)))
                .collect::<Vec<_>>()
                .join(" ");
            let retained = if retained.is_empty() {
                "none"
            } else {
                &retained
            };
            return format!("lxc.cap.keep =\nlxc.cap.keep = {retained}\n");
        }
        let missing: Vec<_> = [("net_admin", 12), ("net_raw", 13)]
            .into_iter()
            .filter(|(_, number)| {
                !drop
                    .split_whitespace()
                    .any(|existing| capability_number(existing) == Some(*number))
            })
            .map(|(cap, _)| cap)
            .collect();
        if missing.is_empty() {
            String::new()
        } else {
            format!("lxc.cap.drop = {}\n", missing.join(" "))
        }
    }

    pub(crate) fn drop_network_capabilities(&self) -> Result<(), String> {
        let path = self.config_file_path();
        let capabilities = self.config_value("lxc.cap.drop")?;
        let keep = Self::config_uses_capability_keep_list(std::path::Path::new(&path), false)?;
        let entries = if keep {
            let retained = if capabilities.is_empty() {
                "none"
            } else {
                &capabilities
            };
            Self::format_network_capability_removal(retained, "")
        } else {
            Self::format_network_capability_removal("", &capabilities)
        };
        if entries.is_empty() {
            return Ok(());
        }
        let mut config = std::fs::read_to_string(&path)
            .map_err(|error| format!("Failed to read LXC capability config: {error}"))?;
        config.push('\n');
        config.push_str(&entries);
        self.write_config(&config)
    }

    pub(crate) fn set_network_mac_address(&self, mac: &str) -> Result<(), String> {
        let config = std::fs::read_to_string(self.config_file_path())
            .map_err(|error| format!("Failed to read LXC network config: {error}"))?;
        let mut out = String::new();
        for line in config.lines() {
            if line
                .split_once('=')
                .is_some_and(|(key, _)| key.trim() == "lxc.net.0.hwaddr")
            {
                continue;
            }
            out.push_str(line);
            out.push('\n');
        }
        out.push_str(&format!("lxc.net.0.hwaddr = {mac}\n"));
        self.write_config(&out)
    }

    pub(crate) fn set_network_startup_config(&self, entries: &[String]) -> Result<(), String> {
        const BEGIN: &str = "# BEGIN MXC network startup";
        const END: &str = "# END MXC network startup";

        let path = self.config_file_path();
        let config = std::fs::read_to_string(&path)
            .map_err(|error| format!("Failed to read LXC network config: {error}"))?;
        let mut out = String::new();
        let mut inside = false;
        for line in config.lines() {
            if line.trim() == BEGIN {
                inside = true;
            } else if line.trim() == END {
                inside = false;
            } else if !inside {
                out.push_str(line);
                out.push('\n');
            }
        }
        out.push_str(BEGIN);
        out.push('\n');
        for entry in entries {
            out.push_str(entry);
            out.push('\n');
        }
        out.push_str(END);
        out.push('\n');
        self.write_config(&out)
    }

    fn write_config(&self, contents: &str) -> Result<(), String> {
        use std::io::Write;
        let path = self.config_file_path();
        let directory = std::path::Path::new(&path)
            .parent()
            .expect("container config has a parent directory");
        let mut staging = tempfile::NamedTempFile::new_in(directory)
            .map_err(|error| format!("Failed to stage LXC config: {error}"))?;
        staging
            .write_all(contents.as_bytes())
            .map_err(|error| format!("Failed to write LXC config: {error}"))?;
        staging
            .persist(&path)
            .map_err(|error| format!("Failed to replace LXC config: {error}"))?;
        Ok(())
    }

    /// Removes existing mount points so they do not accumulate on a reused
    /// container.
    pub fn set_filesystem_access_points(&self, entries: &[String]) -> Result<(), String> {
        let config_path = self.config_file_path();
        let existing = std::fs::read_to_string(&config_path).map_err(|e| {
            format!(
                "Failed to read container config to replace its mount entries: {} (config file: {})",
                e, config_path
            )
        })?;

        let mut out = Self::strip_managed_mount_entries(&existing);
        if !entries.is_empty() {
            if !out.is_empty() && !out.ends_with('\n') {
                out.push('\n');
            }
            out.push_str(MANAGED_MOUNTS_BEGIN);
            out.push('\n');
            for entry in entries {
                out.push_str("lxc.mount.entry = ");
                out.push_str(entry);
                out.push('\n');
            }
            out.push_str(MANAGED_MOUNTS_END);
            out.push('\n');
        }

        let temp_path = format!("{}.mxc-tmp", config_path);
        std::fs::write(&temp_path, out.as_bytes()).map_err(|e| {
            format!(
                "Failed to stage rewritten container config: {} (temp file: {})",
                e, temp_path
            )
        })?;
        std::fs::rename(&temp_path, &config_path).map_err(|e| {
            let _ = std::fs::remove_file(&temp_path);
            format!(
                "Failed to install rewritten container config: {} (config file: {})",
                e, config_path
            )
        })
    }

    fn strip_managed_mount_entries(config: &str) -> String {
        let mut out = String::with_capacity(config.len());
        let mut inside = false;
        for line in config.lines() {
            let trimmed = line.trim();
            if trimmed == MANAGED_MOUNTS_BEGIN {
                inside = true;
                continue;
            }
            if trimmed == MANAGED_MOUNTS_END {
                inside = false;
                continue;
            }
            if inside {
                continue;
            }
            out.push_str(line);
            out.push('\n');
        }
        out
    }

    fn validate_unprivileged(&self) -> Result<(), String> {
        let validation = (|| {
            let pid = self.init_pid().ok_or_else(|| {
                format!(
                    "Failed to get container '{}' init PID to inspect UID map",
                    self.name
                )
            })?;
            let mapping =
                std::fs::read_to_string(format!("/proc/{pid}/uid_map")).map_err(|error| {
                    format!(
                        "Failed to read container '{}' UID map for init PID {pid}: {error}",
                        self.name
                    )
                })?;
            let root_is_shifted = mapping.lines().any(|line| {
                let columns = line
                    .split_whitespace()
                    .map(str::parse::<u32>)
                    .collect::<Result<Vec<_>, _>>();
                matches!(
                    columns.as_deref(),
                    Ok([0, outside, count]) if *outside != 0 && *count != 0
                )
            });
            if !root_is_shifted {
                return Err(format!(
                    "Container '{}' has no unprivileged root UID mapping.  MXC will not run the requested command.",
                    self.name
                ));
            }
            Ok(())
        })();

        if let Err(error) = validation {
            return match self.stop() {
                Ok(()) => Err(error),
                Err(stop_error) => Err(format!(
                    "{error}; failed to stop rejected container: {stop_error}"
                )),
            };
        }
        Ok(())
    }

    pub fn start(&self, network: StartNetwork) -> Result<(), String> {
        let mut cmd = self.lxc_command("lxc-start");
        cmd.args(network.to_start_args(self.configured_interface_count()));
        Self::run_tool(cmd)?;
        self.validate_unprivileged()
    }

    /// How many `lxc.net.N` interfaces the container's config declares.
    fn configured_interface_count(&self) -> usize {
        let Ok(config) = std::fs::read_to_string(self.config_file_path()) else {
            return 0;
        };
        Self::highest_interface_index(&config).map_or(0, |index| index + 1)
    }

    fn highest_interface_index(config: &str) -> Option<usize> {
        config
            .lines()
            .filter_map(|line| {
                let key = line.split('=').next()?.trim();
                let index = key.strip_prefix("lxc.net.")?.split('.').next()?;
                index.parse::<usize>().ok()
            })
            .max()
    }

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

    /// Output streams go straight to the host; both returned strings are always
    /// empty.
    #[cfg(target_os = "linux")]
    pub fn attach_run(
        &self,
        command: &str,
        working_directory: &str,
        env: &[String],
        force_clear_env: bool,
        timeout: Option<std::time::Duration>,
    ) -> Result<(i32, String, String), String> {
        use crate::mxc_pty::{run_with_pty, PtyOptions, PtyOutcome, Signal};

        // This process blocks these for its cleanup watchdog; left blocked, the
        // inner shell would ignore Ctrl-C.
        const UNBLOCK: &[Signal] = &[Signal::SIGHUP, Signal::SIGTERM, Signal::SIGINT];

        let mut cmd = self.lxc_command("lxc-attach");
        cmd.args(build_attach_args_with_env_control(
            env,
            working_directory,
            command,
            force_clear_env,
        ));

        let options = PtyOptions {
            unblock_signals: UNBLOCK,
            timeout,
            ..PtyOptions::default()
        };

        match run_with_pty(cmd, options)? {
            PtyOutcome::Exited(status) => {
                Ok((status.code().unwrap_or(-1), String::new(), String::new()))
            }

            PtyOutcome::TimedOut => {
                let ms = timeout.map(|d| d.as_millis()).unwrap_or(0);
                Err(format!("script timed out after {}ms", ms))
            }
        }
    }

    /// Stub for the workspace-wide clippy lane that runs on Windows.
    #[cfg(not(target_os = "linux"))]
    pub fn attach_run(
        &self,
        _command: &str,
        _working_directory: &str,
        _env: &[String],
        _force_clear_env: bool,
        _timeout: Option<std::time::Duration>,
    ) -> Result<(i32, String, String), String> {
        Err("LxcContainer::attach_run is only supported on Linux".to_string())
    }

    /// Run a command in the container and return its output, with no pty and no
    /// path from that output to this process's own stdio.
    #[cfg(target_os = "linux")]
    pub fn attach_capture(
        &self,
        command: &str,
        working_directory: &str,
        env: &[String],
        force_clear_env: bool,
        timeout: Option<std::time::Duration>,
    ) -> Result<(i32, String, String), String> {
        use crate::mxc_common::interruptible_reader::wrap_pipe;
        use crate::mxc_common::sandbox_process::{wait_with_timeout, StreamCloser, WaitError};
        use std::process::Stdio;

        let mut cmd = self.lxc_command("lxc-attach");
        cmd.args(build_attach_args_with_env_control(
            env,
            working_directory,
            command,
            force_clear_env,
        ));
        cmd.stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());

        unblock_fatal_signals(&mut cmd);

        let mut child = cmd
            .spawn()
            .map_err(|e| format!("Failed to run lxc-attach: {}", e))?;

        let wrapped = wrap_pipe(child.stdout.take())
            .and_then(|out| wrap_pipe(child.stderr.take()).map(|err| (out, err)));
        let ((stdout, stdout_canceller), (stderr, stderr_canceller)) = match wrapped {
            Ok(pipes) => pipes,

            // Without this the helper keeps running, and can still rewrite
            // `/etc/hosts` after this call has reported failure.
            Err(e) => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(format!("Failed to wrap an lxc-attach pipe: {}", e));
            }
        };
        let stdout = read_to_end_on_thread(stdout);
        let stderr = read_to_end_on_thread(stderr);

        let outcome = wait_with_timeout(&mut child, timeout);
        if outcome.is_err() {
            let _ = child.kill();
            let _ = child.wait();
        } else {
            wait_for_drain(&stdout, &stderr);
        }

        // A descendant holding either pipe open would park the joins below
        // indefinitely.
        for canceller in [stdout_canceller, stderr_canceller].into_iter().flatten() {
            canceller.close();
        }
        let captured_out = joined_capture(stdout);
        let captured_err = joined_capture(stderr);

        let status = match outcome {
            Ok(status) => status,
            Err(WaitError::Timeout) => {
                let ms = timeout.map(|d| d.as_millis()).unwrap_or(0);
                return Err(format!("lxc-attach timed out after {}ms", ms));
            }
            Err(WaitError::Io(e)) => {
                return Err(format!("Failed to wait for lxc-attach: {}", e));
            }
        };

        Ok((status.code().unwrap_or(-1), captured_out, captured_err))
    }

    /// Stub for the workspace-wide clippy lane that runs on Windows.
    #[cfg(not(target_os = "linux"))]
    pub fn attach_capture(
        &self,
        _command: &str,
        _working_directory: &str,
        _env: &[String],
        _force_clear_env: bool,
        _timeout: Option<std::time::Duration>,
    ) -> Result<(i32, String, String), String> {
        Err("LxcContainer::attach_capture is only supported on Linux".to_string())
    }

    /// Launch a command in the container on pipes the caller owns, and hand
    /// back the handle without waiting for it.
    ///
    /// The child's signal mask is left alone: in a host application it belongs
    /// to the application, not to `lxc-exec`'s watchdog.
    #[cfg(target_os = "linux")]
    pub fn attach_spawn(
        &self,
        command: &str,
        working_directory: &str,
        env: &[String],
        force_clear_env: bool,
    ) -> Result<std::process::Child, String> {
        use std::process::Stdio;

        let mut cmd = self.attach_command(command, working_directory, env, force_clear_env);
        cmd.stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());

        cmd.spawn()
            .map_err(|e| format!("Failed to run lxc-attach: {}", e))
    }

    /// Launch a command in the container attached to a caller-owned PTY.
    #[cfg(target_os = "linux")]
    pub fn attach_spawn_pty(
        &self,
        command: &str,
        working_directory: &str,
        env: &[String],
        force_clear_env: bool,
        size: crate::mxc_pty::PtySize,
    ) -> Result<(std::process::Child, crate::mxc_pty::LivePty), String> {
        use crate::mxc_pty::Signal;

        const UNBLOCK: &[Signal] = &[Signal::SIGHUP, Signal::SIGTERM, Signal::SIGINT];

        let mut cmd = self.attach_command(command, working_directory, env, force_clear_env);
        let pty = crate::mxc_pty::LivePty::attach_forwarded(&mut cmd, size, UNBLOCK)
            .map_err(|error| format!("Failed to allocate lxc-attach PTY: {error}"))?;
        let mut child = cmd
            .spawn()
            .map_err(|error| format!("Failed to run lxc-attach: {error}"))?;

        // lxc-attach switches the host terminal to noncanonical mode with
        // TCSAFLUSH before starting its forwarding loop. Returning earlier can
        // let callers write input that lxc-attach then discards during setup.
        const READY_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);
        const READY_POLL: std::time::Duration = std::time::Duration::from_millis(10);
        let deadline = std::time::Instant::now() + READY_TIMEOUT;
        loop {
            match pty.is_canonical_mode() {
                Ok(false) => break,
                Ok(true) => {}
                Err(error) => {
                    let _ = child.kill();
                    let _ = child.wait();
                    return Err(format!(
                        "Failed to inspect lxc-attach terminal readiness: {error}"
                    ));
                }
            }
            match child.try_wait() {
                Ok(Some(_)) => break,
                Ok(None) => {}
                Err(error) => {
                    let _ = child.kill();
                    let _ = child.wait();
                    return Err(format!(
                        "Failed to poll lxc-attach terminal readiness: {error}"
                    ));
                }
            }
            if std::time::Instant::now() >= deadline {
                let _ = child.kill();
                let _ = child.wait();
                return Err(format!(
                    "lxc-attach terminal forwarding was not ready within {}ms",
                    READY_TIMEOUT.as_millis()
                ));
            }
            std::thread::sleep(READY_POLL);
        }
        Ok((child, pty))
    }

    #[cfg(target_os = "linux")]
    fn attach_command(
        &self,
        command: &str,
        working_directory: &str,
        env: &[String],
        force_clear_env: bool,
    ) -> std::process::Command {
        let mut cmd = self.lxc_command("lxc-attach");
        cmd.args(build_attach_args_with_env_control(
            env,
            working_directory,
            command,
            force_clear_env,
        ));
        cmd
    }

    /// Stub for the workspace-wide clippy lane that runs on Windows.
    #[cfg(not(target_os = "linux"))]
    pub fn attach_spawn(
        &self,
        _command: &str,
        _working_directory: &str,
        _env: &[String],
        _force_clear_env: bool,
    ) -> Result<std::process::Child, String> {
        Err("LxcContainer::attach_spawn is only supported on Linux".to_string())
    }

    /// Stop the container by killing it, not by asking it to exit.
    pub fn stop(&self) -> Result<(), String> {
        Self::run_release_tool(self.stop_command())
    }

    fn stop_command(&self) -> std::process::Command {
        let mut cmd = self.lxc_command("lxc-stop");

        // -k kills outright.  Asking it to exit instead waits 60 seconds for a
        // SIGPWR reply that systemd as PID 1 in an unprivileged userns never
        // sends.
        cmd.arg("-k");
        cmd
    }

    pub fn destroy(&self) -> Result<(), String> {
        self.destroy_with_reporter(|warning| eprintln!("{warning}"))
    }

    pub(crate) fn destroy_with_reporter(
        &self,
        report_warning: impl FnOnce(&str),
    ) -> Result<(), String> {
        let mac = self.config_value("lxc.net.0.hwaddr").ok();
        let mut cmd = self.lxc_command("lxc-destroy");

        cmd.arg("-f");
        Self::run_release_tool(cmd)?;
        if let Some(mac) = mac.filter(|mac| !mac.is_empty()) {
            if let Err(error) = crate::lxc_common::network_address::release(&mac) {
                report_warning(&format!(
                    "Failed to release destroyed container's DHCP reservation: {error}"
                ));
            }
        }
        Ok(())
    }

    pub(crate) fn config_file_path(&self) -> String {
        format!("{}/{}/config", self.lxc_path, self.name)
    }

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
#[path = "lxc_network_startup_spec.rs"]
mod network_startup_spec;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stop_kills_rather_than_waiting_for_a_clean_shutdown() {
        let container = LxcContainer::new("mxc-stop-test", Some("/var/lib/lxc"));
        let args: Vec<String> = container
            .stop_command()
            .get_args()
            .map(|a| a.to_string_lossy().into_owned())
            .collect();

        assert!(
            args.iter().any(|a| a == "mxc-stop-test"),
            "the command must address this container, got {args:?}"
        );
        assert!(
            args.iter().any(|a| a == "-k"),
            "stop must kill the container: a clean shutdown waits 60 seconds for an \
             init that may never answer, got {args:?}"
        );
    }

    #[test]
    fn the_interface_count_comes_from_the_highest_index_the_config_names() {
        for (config, expected) in [
            ("", None),
            ("lxc.net.0.type = veth\n", Some(0)),
            ("lxc.net.0.type = veth\nlxc.net.1.type = veth\n", Some(1)),
            ("lxc.net.4.type = veth\nlxc.net.1.type = veth\n", Some(4)),
            ("  lxc.net.2.link = lxcbr0\n", Some(2)),
            // Keys that only look like an interface entry.
            ("lxc.network.0.type = veth\n", None),
            ("lxc.net.x.type = veth\n", None),
        ] {
            assert_eq!(
                LxcContainer::highest_interface_index(config),
                expected,
                "config {config:?}"
            );
        }
    }

    #[test]
    fn lxc_container_uses_resolved_lxcpath_when_none_provided() {
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

    fn container_with_config(body: &str) -> (tempfile::TempDir, LxcContainer, std::path::PathBuf) {
        let base = tempfile::Builder::new()
            .prefix("mxc-lxc-cfg-")
            .tempdir()
            .expect("create temp LXC directory");
        let dir = base.path().join("box");
        std::fs::create_dir_all(&dir).expect("temp container dir");
        let config = dir.join("config");
        std::fs::write(&config, body).expect("seed config");
        let container = LxcContainer::new(
            "box",
            Some(base.path().to_str().expect("temp path must be UTF-8")),
        );
        (base, container, config)
    }

    const TEMPLATE_CONFIG: &str = "# Template used to create this container\n\
                                   lxc.include = /usr/share/lxc/config/common.conf\n\
                                   lxc.rootfs.path = dir:/var/lib/lxc/box/rootfs\n\
                                   lxc.mount.entry = /opt/handwritten opt none bind 0 0\n";

    #[test]
    fn a_reused_container_does_not_inherit_an_earlier_runs_mounts() {
        let (_temp_dir, container, config) = container_with_config(TEMPLATE_CONFIG);

        container
            .set_filesystem_access_points(&[
                "/tmp/secret tmp/secret none bind,create=dir 0 0".into()
            ])
            .expect("first run programs its mount");
        let after_first = std::fs::read_to_string(&config).expect("read config");
        assert!(
            after_first.contains("/tmp/secret"),
            "the first run's mount must be programmed; got:\n{after_first}"
        );

        container
            .set_filesystem_access_points(&[])
            .expect("second run grants nothing");
        let after_second = std::fs::read_to_string(&config).expect("read config");
        assert!(
            !after_second.contains("/tmp/secret"),
            "a run granting no filesystem policy must not inherit the earlier mount; got:\n{after_second}"
        );
    }

    #[test]
    fn rewriting_mounts_preserves_every_line_the_backend_does_not_own() {
        let (_temp_dir, container, config) = container_with_config(TEMPLATE_CONFIG);

        container
            .set_filesystem_access_points(&["/data data none bind,create=dir 0 0".into()])
            .expect("program mounts");
        container
            .set_filesystem_access_points(&[])
            .expect("clear mounts");

        let body = std::fs::read_to_string(&config).expect("read config");
        for line in [
            "# Template used to create this container",
            "lxc.include = /usr/share/lxc/config/common.conf",
            "lxc.rootfs.path = dir:/var/lib/lxc/box/rootfs",
            "lxc.mount.entry = /opt/handwritten opt none bind 0 0",
        ] {
            assert!(
                body.contains(line),
                "{line:?} must survive the rewrite; got:\n{body}"
            );
        }
    }

    #[test]
    fn an_unmarked_mount_is_left_to_its_author() {
        // Containers predating the managed block carry MXC's own mounts as
        // unmarked lines, but so does anyone who wrote one by hand, and the two
        // are indistinguishable. Deleting a user's mount is worse than leaving
        // a stale grant on a container MXC has not rewritten since.
        let unmarked = "lxc.rootfs.path = dir:/var/lib/lxc/box/rootfs\n\
                        lxc.mount.entry = /srv/mydata srv/mydata none bind,create=dir 0 0\n";
        let (_temp_dir, container, config) = container_with_config(unmarked);

        container
            .set_filesystem_access_points(&[])
            .expect("a run granting nothing rewrites the config");

        let body = std::fs::read_to_string(&config).expect("read config");
        assert!(
            body.contains("lxc.mount.entry = /srv/mydata srv/mydata none bind,create=dir 0 0"),
            "an unmarked mount must survive; got:\n{body}"
        );
        assert!(
            body.contains("lxc.rootfs.path = dir:/var/lib/lxc/box/rootfs"),
            "the rewrite must keep the lines it does not own; got:\n{body}"
        );
    }

    #[test]
    fn repeated_runs_do_not_accumulate_managed_blocks() {
        let (_temp_dir, container, config) = container_with_config(TEMPLATE_CONFIG);

        for _ in 0..3 {
            container
                .set_filesystem_access_points(&["/data data none bind,create=dir 0 0".into()])
                .expect("program mounts");
        }

        let body = std::fs::read_to_string(&config).expect("read config");
        assert_eq!(
            body.matches("lxc.mount.entry = /data").count(),
            1,
            "the block must be replaced, not appended; got:\n{body}"
        );
        assert_eq!(
            body.matches(MANAGED_MOUNTS_BEGIN).count(),
            1,
            "exactly one managed block may exist; got:\n{body}"
        );
    }

    #[test]
    fn an_unterminated_managed_block_is_cleared_rather_than_inherited() {
        let truncated = format!(
            "lxc.rootfs.path = dir:/var/lib/lxc/box/rootfs\n{}\nlxc.mount.entry = /tmp/secret tmp/secret none bind 0 0\n",
            MANAGED_MOUNTS_BEGIN
        );
        let (_temp_dir, container, config) = container_with_config(&truncated);

        container
            .set_filesystem_access_points(&[])
            .expect("clear mounts");

        let body = std::fs::read_to_string(&config).expect("read config");
        assert!(
            !body.contains("/tmp/secret"),
            "an unterminated block must not survive; got:\n{body}"
        );
        assert!(
            body.contains("lxc.rootfs.path"),
            "lines before the marker must survive; got:\n{body}"
        );
    }

    #[test]
    fn a_failed_rewrite_leaves_no_temporary_file_behind() {
        let (_temp_dir, container, config) = container_with_config(TEMPLATE_CONFIG);
        let err = LxcContainer::new("ghost", Some("/nonexistent-mxc-base"))
            .set_filesystem_access_points(&[])
            .expect_err("a missing config must fail loudly");
        assert!(
            err.contains("ghost/config"),
            "error must name the config file, got: {err}"
        );

        container
            .set_filesystem_access_points(&["/data data none bind,create=dir 0 0".into()])
            .expect("program mounts");
        let temp = format!("{}.mxc-tmp", config.display());
        assert!(
            !std::path::Path::new(&temp).exists(),
            "the staging file must not outlive a successful rewrite"
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn a_failed_release_carries_the_tools_own_diagnosis() {
        let mut cmd = std::process::Command::new("/bin/sh");
        cmd.arg("-c")
            .arg("printf 'mxc: container is not running\\n' >&2; exit 3");

        let failure = LxcContainer::run_release_tool(cmd)
            .expect_err("a tool exiting non-zero must be reported as a failure");

        assert!(
            failure.contains("container is not running"),
            "the tool's stderr is the only account of why the release failed, so it has to \
             reach the caller; got {failure:?}"
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn a_release_that_succeeds_is_not_reported_as_a_failure() {
        let mut cmd = std::process::Command::new("/bin/sh");
        cmd.arg("-c").arg("printf 'noise\\n'; exit 0");

        assert!(
            LxcContainer::run_release_tool(cmd).is_ok(),
            "a tool that exited cleanly released the container"
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn a_release_waits_for_stderr_a_descendant_writes_after_the_tool_exits() {
        let mut cmd = std::process::Command::new("/bin/sh");

        // The subshell holds the stderr pipe open past the tool's own exit and
        // writes only after it, which is the ordering a prompt cancel drops.
        cmd.arg("-c")
            .arg("( sleep 0.2; printf 'late diagnosis\\n' >&2 ) & exit 3");

        let failure = LxcContainer::run_release_tool(cmd)
            .expect_err("a tool exiting non-zero must be reported as a failure");

        assert!(
            failure.contains("late diagnosis"),
            "stderr that lands after the tool exits still explains the failure; got {failure:?}"
        );
    }
}
