// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use serde::{Deserialize, Serialize};

/// Selects which containment backend to use for script execution.
#[derive(Debug, Default, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum ContainmentBackend {
    #[default]
    /// Windows AppContainer — process-level isolation on the host.
    AppContainer,
    /// Windows Sandbox — full VM isolation via a long-lived sandbox daemon.
    Sandbox,
    /// Linux container via WSL Container SDK (WSLC SDK).
    Wslc,
    /// LXC — Linux container isolation.
    Lxc,
    /// VM-based isolation.
    Vm,
    /// MicroVM-based isolation.
    #[serde(rename = "microvm")]
    MicroVm,
}

/// Configuration specific to the Windows Sandbox backend.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct SandboxConfig {
    /// Idle timeout in milliseconds before the daemon tears down the sandbox VM.
    /// Default: 300 000 (5 minutes). 0 = no timeout.
    pub idle_timeout_ms: u32,
    /// Named pipe name the daemon listens on (without `\\.\pipe\` prefix).
    pub daemon_pipe_name: String,
}

impl Default for SandboxConfig {
    fn default() -> Self {
        Self {
            idle_timeout_ms: 300_000,
            daemon_pipe_name: "wxc-sandbox".to_string(),
        }
    }
}

/// Configuration specific to the LXC container backend.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct LxcConfig {
    /// Container name. Default: auto-generated.
    pub container_name: String,
    /// Linux distribution for the container rootfs (e.g., "alpine", "ubuntu").
    pub distribution: String,
    /// Distribution release version (e.g., "3.19", "24.04").
    pub release: String,
    /// Whether to destroy the container after execution. Default: true.
    pub destroy_on_exit: bool,
}

impl Default for LxcConfig {
    fn default() -> Self {
        Self {
            container_name: String::new(),
            distribution: "alpine".to_string(),
            release: "3.19".to_string(),
            destroy_on_exit: true,
        }
    }
}

#[derive(Debug, Default, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum NetworkPolicy {
    #[default]
    Allow,
    Block,
}

#[derive(Debug, Default, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum NetworkEnforcementMode {
    #[default]
    Capabilities,
    Firewall,
    Both,
}

#[derive(Debug, Clone)]
pub struct ProxyAddress {
    pub address: String,
    pub port: u16,
    pub is_localhost: bool,
}

impl ProxyAddress {
    pub fn new(address: String, port: u16, is_localhost: bool) -> Self {
        Self {
            address,
            port,
            is_localhost,
        }
    }

    pub fn host(&self) -> &str {
        &self.address
    }

    pub fn port(&self) -> u16 {
        self.port
    }

    pub fn to_url(&self) -> String {
        if self.is_localhost {
            format!("http://127.0.0.1:{}", self.port)
        } else {
            // For non-localhost proxies, return in "host:port" format since
            // the scheme is not implied.
            format!("{}:{}", self.address, self.port)
        }
    }
}

/// Proxy configuration parsed from the `network.proxy` JSON field.
#[derive(Debug, Default, Clone)]
pub struct ProxyConfig {
    pub address: Option<ProxyAddress>,
    pub builtin_test_server: bool,
}

impl ProxyConfig {
    pub fn is_enabled(&self) -> bool {
        self.address.is_some() || self.builtin_test_server
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct ContainerPolicy {
    pub app_container_name: String,
    pub least_privilege_mode: bool,
    pub capabilities: Vec<String>,
    pub readwrite_paths: Vec<String>,
    pub readonly_paths: Vec<String>,
    pub denied_paths: Vec<String>,
    pub clear_policy_on_exit: bool,
    pub default_network_policy: NetworkPolicy,
    pub network_enforcement_mode: NetworkEnforcementMode,
    pub allowed_hosts: Vec<String>,
    pub blocked_hosts: Vec<String>,
    pub remove_firewall_rules_on_exit: bool,
    #[serde(skip)]
    pub network_proxy: ProxyConfig,
}

impl Default for ContainerPolicy {
    fn default() -> Self {
        Self {
            app_container_name: "CLI".to_string(),
            least_privilege_mode: false,
            capabilities: Vec::new(),
            readwrite_paths: Vec::new(),
            readonly_paths: Vec::new(),
            denied_paths: Vec::new(),
            clear_policy_on_exit: true,
            default_network_policy: NetworkPolicy::default(),
            network_enforcement_mode: NetworkEnforcementMode::default(),
            allowed_hosts: Vec::new(),
            blocked_hosts: Vec::new(),
            remove_firewall_rules_on_exit: true,
            network_proxy: ProxyConfig::default(),
        }
    }
}

/// Port mapping for host↔container port forwarding.
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct PortMapping {
    /// Port on the Windows host.
    pub windows_port: u16,
    /// Port inside the Linux container.
    pub container_port: u16,
    /// Protocol: "tcp" or "udp". Default: "tcp".
    pub protocol: String,
}

/// Configuration for the WSL Container (WSLC SDK) backend.
/// Used when containment == Wslc.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct ContainerConfig {
    /// Target OS for the container. Currently only "linux" is supported.
    pub target_os: String,
    /// Container image name (e.g., "alpine:latest", "python:3.12").
    pub image: String,
    /// Number of CPUs allocated to the session. None = host-determined.
    pub cpu_count: Option<u32>,
    /// Memory in MB allocated to the session. None = host-determined.
    pub memory_mb: Option<u64>,
    /// Enable GPU passthrough via WSLC_CONTAINER_FLAG_ENABLE_GPU.
    pub gpu: bool,
    /// Storage path for WSLC session image store. None = SDK default.
    pub storage_path: Option<String>,
    /// Host↔container port mappings.
    pub port_mappings: Vec<PortMapping>,
}

impl Default for ContainerConfig {
    fn default() -> Self {
        Self {
            target_os: "linux".to_string(),
            image: "alpine:latest".to_string(),
            cpu_count: None,
            memory_mb: None,
            gpu: false,
            storage_path: None,
            port_mappings: Vec::new(),
        }
    }
}

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct CodexRequest {
    /// Schema version for the config format.
    pub schema_version: String,
    /// Externally assigned container identifier.
    pub container_id: String,
    /// Target platform: "linux" or "windows". Default: "windows".
    pub platform: String,
    /// Environment variables as "KEY=VALUE" strings (from process.env).
    pub env: Vec<String>,
    pub script_code: String,
    pub working_directory: String,
    pub script_timeout: u32,
    /// Which containment backend to use. Default: AppContainer.
    pub containment: ContainmentBackend,
    /// AppContainer-specific policy (used when containment == AppContainer).
    pub policy: ContainerPolicy,
    /// Sandbox-specific configuration (used when containment == Sandbox).
    pub sandbox_config: SandboxConfig,
    /// Container configuration (used when containment == Wslc).
    pub container_config: ContainerConfig,
    /// LXC-specific configuration (used when containment == Lxc).
    pub lxc_config: LxcConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct ScriptResponse {
    pub exit_code: i32,
    pub standard_out: String,
    pub standard_err: String,
    pub error_message: String,
}

impl Default for ScriptResponse {
    fn default() -> Self {
        Self {
            exit_code: -1,
            standard_out: String::new(),
            standard_err: String::new(),
            error_message: String::new(),
        }
    }
}

impl ScriptResponse {
    /// Create an error response with the given message and exit code -1.
    pub fn error(msg: &str) -> Self {
        ScriptResponse {
            exit_code: -1,
            standard_err: msg.to_string(),
            error_message: msg.to_string(),
            ..Default::default()
        }
    }
}
