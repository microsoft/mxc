// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Safe Rust wrappers around the liblxc C API.
//!
//! liblxc exposes container management through a `struct lxc_container` with
//! function pointer fields. This module provides an RAII `LxcContainer` wrapper
//! that calls the appropriate function pointers and handles cleanup.

/// Safe wrapper around an LXC container.
pub struct LxcContainer {
    name: String,
    config_path: Option<String>,
}

impl LxcContainer {
    /// Create a new LXC container handle.
    pub fn new(name: &str, config_path: Option<&str>) -> Self {
        Self {
            name: name.to_string(),
            config_path: config_path.map(|s| s.to_string()),
        }
    }

    /// Get the container name.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Get the config path (LXC storage path), if set.
    pub fn config_path(&self) -> Option<&str> {
        self.config_path.as_deref()
    }

    /// Check if the container exists.
    pub fn is_defined(&self) -> bool {
        let output = std::process::Command::new("lxc-info")
            .arg("-n")
            .arg(&self.name)
            .output();
        matches!(output, Ok(o) if o.status.success())
    }

    /// Check if the container is running.
    pub fn is_running(&self) -> bool {
        let output = std::process::Command::new("lxc-info")
            .arg("-n")
            .arg(&self.name)
            .arg("-s")
            .output();
        match output {
            Ok(o) => {
                let stdout = String::from_utf8_lossy(&o.stdout);
                stdout.contains("RUNNING")
            }
            Err(_) => false,
        }
    }

    /// Create the container from a template/distribution.
    pub fn create(&self, distribution: &str, release: &str) -> Result<(), String> {
        let mut cmd = std::process::Command::new("lxc-create");
        cmd.arg("-n")
            .arg(&self.name)
            .arg("-t")
            .arg("download")
            .arg("--")
            .arg("-d")
            .arg(distribution)
            .arg("-r")
            .arg(release)
            .arg("-a")
            .arg(Self::current_arch());

        if let Some(ref path) = self.config_path {
            cmd.arg("-P").arg(path);
        }

        let output = cmd
            .output()
            .map_err(|e| format!("Failed to run lxc-create: {}", e))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(format!("lxc-create failed: {}", stderr));
        }

        Ok(())
    }

    /// Set a configuration item on the container.
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
            .map_err(|e| format!("Failed to set config item {}: {}", key, e))
    }

    /// Start the container.
    pub fn start(&self) -> Result<(), String> {
        let mut cmd = std::process::Command::new("lxc-start");
        cmd.arg("-n").arg(&self.name);

        if let Some(ref path) = self.config_path {
            cmd.arg("-P").arg(path);
        }

        let output = cmd
            .output()
            .map_err(|e| format!("Failed to run lxc-start: {}", e))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(format!("lxc-start failed: {}", stderr));
        }

        Ok(())
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

        let mut cmd = std::process::Command::new("lxc-execute");
        cmd.arg("-n").arg(&self.name);

        if let Some(ref path) = self.config_path {
            cmd.arg("-P").arg(path);
        }

        cmd.arg("--").arg("/bin/sh").arg("-c").arg(command);

        let output = cmd
            .output()
            .map_err(|e| format!("Failed to run lxc-execute: {}", e))?;

        let stdout = String::from_utf8_lossy(&output.stdout).to_string();
        let stderr = String::from_utf8_lossy(&output.stderr).to_string();
        let exit_code = output.status.code().unwrap_or(-1);

        Ok((exit_code, stdout, stderr))
    }

    /// Execute a command inside a running container using lxc-attach.
    pub fn attach_run(
        &self,
        command: &str,
        _working_directory: &str,
    ) -> Result<(i32, String, String), String> {
        let mut cmd = std::process::Command::new("lxc-attach");
        cmd.arg("-n").arg(&self.name);

        if let Some(ref path) = self.config_path {
            cmd.arg("-P").arg(path);
        }

        cmd.arg("--").arg("/bin/sh").arg("-c").arg(command);

        let output = cmd
            .output()
            .map_err(|e| format!("Failed to run lxc-attach: {}", e))?;

        let stdout = String::from_utf8_lossy(&output.stdout).to_string();
        let stderr = String::from_utf8_lossy(&output.stderr).to_string();
        let exit_code = output.status.code().unwrap_or(-1);

        Ok((exit_code, stdout, stderr))
    }

    /// Stop the container.
    pub fn stop(&self) -> Result<(), String> {
        let mut cmd = std::process::Command::new("lxc-stop");
        cmd.arg("-n").arg(&self.name);

        if let Some(ref path) = self.config_path {
            cmd.arg("-P").arg(path);
        }

        let output = cmd
            .output()
            .map_err(|e| format!("Failed to run lxc-stop: {}", e))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(format!("lxc-stop failed: {}", stderr));
        }

        Ok(())
    }

    /// Destroy the container (removes rootfs and config).
    pub fn destroy(&self) -> Result<(), String> {
        if self.is_running() {
            let _ = self.stop();
        }

        let mut cmd = std::process::Command::new("lxc-destroy");
        cmd.arg("-n").arg(&self.name).arg("-f");

        if let Some(ref path) = self.config_path {
            cmd.arg("-P").arg(path);
        }

        let output = cmd
            .output()
            .map_err(|e| format!("Failed to run lxc-destroy: {}", e))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(format!("lxc-destroy failed: {}", stderr));
        }

        Ok(())
    }

    /// Get the path to the container's config file.
    fn config_file_path(&self) -> String {
        let base = self.config_path.as_deref().unwrap_or("/var/lib/lxc");
        format!("{}/{}/config", base, self.name)
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
