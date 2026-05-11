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
    /// Linux container via WSL Container SDK (WSLC SDK).
    Wslc,
    /// LXC — Linux container isolation.
    Lxc,
    /// VM-based isolation.
    Vm,
    /// MicroVM isolation via Windows Hypervisor Platform (internally powered by NanVix).
    #[serde(rename = "microvm")]
    MicroVm,
    /// Windows Sandbox — full VM isolation (experimental, requires --experimental flag).
    WindowsSandbox,
    /// Isolation Session — process isolation via IsoEnvBroker Session API (experimental).
    #[serde(rename = "isolation_session")]
    IsolationSession,
    /// macOS sandbox — experimental backend (requires --experimental).
    /// Implemented on top of the OS-bundled sandbox facility (Apple
    /// internal codename: "Seatbelt").
    #[serde(rename = "seatbelt")]
    Seatbelt,
}

/// Configuration specific to the Seatbelt backend (experimental).
/// Used under `experimental.seatbelt` when `containment == Seatbelt`.
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct SeatbeltConfig {
    /// Optional override of the generated TinyScheme profile.
    #[serde(rename = "profileOverride", skip_serializing_if = "Option::is_none")]
    pub profile_override: Option<String>,
}

/// Configuration specific to the Windows Sandbox backend.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct WindowsSandboxConfig {
    /// Idle timeout in milliseconds before the daemon tears down the sandbox VM.
    /// Default: 300 000 (5 minutes). 0 = no timeout.
    pub idle_timeout_ms: u32,
    /// Named pipe name the daemon listens on (without `\\.\pipe\` prefix).
    pub daemon_pipe_name: String,
}

impl Default for WindowsSandboxConfig {
    fn default() -> Self {
        Self {
            idle_timeout_ms: 300_000,
            daemon_pipe_name: "wxc-windows-sandbox".to_string(),
        }
    }
}

/// Session configuration size for the Isolation Session backend.
/// Maps to `IsoSessionConfigId` in the in-proc `Windows.AI.IsolationSession`
/// `IsoSessionOps` APIs, whose values must in turn match `ISOLATION_CONFIG_ID`
/// in `winsta.h`.
#[derive(Debug, Default, Copy, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum IsolationSessionConfigurationId {
    /// `Small` (1) — smallest pre-defined configuration.
    Small,
    /// `Medium` (2) — middle pre-defined configuration.
    Medium,
    /// `Large` (3) — largest pre-defined configuration.
    Large,
    /// `Composable` (4) — lightweight configuration with UI subsystems
    /// stripped, intended for command-line workloads. The default.
    #[default]
    Composable,
}

/// Configuration specific to the Isolation Session backend.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct IsolationSessionConfig {
    /// Session size/weight. Default: Composable.
    #[serde(rename = "configurationId")]
    pub configuration_id: IsolationSessionConfigurationId,
    /// Optional Entra cloud-agent credentials. Honored on the state-aware
    /// `start` phase; rejected by the one-shot path.
    pub user: Option<IsolationSessionUser>,
}

/// Entra cloud-agent credentials. Both fields are required when the bundle
/// is supplied. `wam_token` is a short-lived bearer token passed verbatim to
/// the OS-side service; MXC stores nothing.
#[derive(Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct IsolationSessionUser {
    pub upn: String,
    pub wam_token: String,
}

impl std::fmt::Debug for IsolationSessionUser {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("IsolationSessionUser")
            .field("upn", &self.upn)
            .field("wam_token", &"<redacted>")
            .finish()
    }
}

/// State-aware provision-phase config for the Isolation Session backend.
/// Nested under `experimental.isolation_session.provision`. Carries Entra
/// credentials when the caller wants a cloud-agent sandbox; absent for
/// local sandboxes.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct IsolationSessionProvisionConfig {
    pub user: Option<IsolationSessionUser>,
}

/// Configuration specific to the LXC container backend.
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct LxcConfig {
    /// Linux distribution for the container rootfs (e.g., "alpine", "ubuntu"). Required.
    pub distribution: String,
    /// Distribution release version (e.g., "3.20", "24.04"). Required.
    pub release: String,
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
    /// Original URL string if provided via `{ "url": "..." }`.
    pub original_url: Option<String>,
}

impl ProxyAddress {
    pub fn new(address: String, port: u16) -> Self {
        Self {
            address,
            port,
            original_url: None,
        }
    }

    /// Create a ProxyAddress from a parsed URL, preserving the original string.
    pub fn from_url(url: &str, host: String, port: u16) -> Self {
        Self {
            address: host,
            port,
            original_url: Some(url.to_string()),
        }
    }

    pub fn host(&self) -> &str {
        &self.address
    }

    pub fn port(&self) -> u16 {
        self.port
    }

    /// Returns the proxy URL. Uses the original URL if one was provided,
    /// otherwise constructs `http://127.0.0.1:{port}` for localhost proxies.
    pub fn to_url(&self) -> String {
        if let Some(url) = &self.original_url {
            return url.clone();
        }
        format!("http://127.0.0.1:{}", self.port)
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

/// Clipboard access policy for UI restrictions.
#[derive(Debug, Default, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum ClipboardPolicy {
    #[default]
    None,
    Read,
    Write,
    #[serde(rename = "all")]
    All,
}

/// Cross-platform UI policy parsed from the `ui` JSON section.
/// Default-deny: UI is disabled, no clipboard, no injection.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct UiPolicy {
    /// When true, the sandbox cannot create visible windows (disables Win32k).
    pub disable: bool,
    /// Clipboard access level.
    pub clipboard: ClipboardPolicy,
    /// Whether input injection (keyboard/mouse) is allowed.
    pub injection: bool,
}

impl Default for UiPolicy {
    fn default() -> Self {
        Self {
            disable: true,
            clipboard: ClipboardPolicy::None,
            injection: false,
        }
    }
}

/// BaseProcessContainer-specific UI configuration (Windows only).
/// Parsed from `appContainer.ui` in the JSON config.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct BaseProcessUiConfig {
    /// UI isolation level for the desktop.
    pub isolation: String,
    /// Whether desktop system control is allowed.
    #[serde(rename = "desktopSystemControl")]
    pub desktop_system_control: bool,
    /// System settings access level.
    #[serde(rename = "systemSettings")]
    pub system_settings: String,
    /// Whether IME (Input Method Editor) is allowed.
    pub ime: bool,
}

impl Default for BaseProcessUiConfig {
    fn default() -> Self {
        Self {
            isolation: "container".to_string(),
            desktop_system_control: false,
            system_settings: "none".to_string(),
            ime: false,
        }
    }
}

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct ContainerPolicy {
    pub least_privilege_mode: bool,
    pub capabilities: Vec<String>,
    pub readwrite_paths: Vec<String>,
    pub readonly_paths: Vec<String>,
    pub denied_paths: Vec<String>,
    pub default_network_policy: NetworkPolicy,
    pub network_enforcement_mode: NetworkEnforcementMode,
    pub allowed_hosts: Vec<String>,
    pub blocked_hosts: Vec<String>,
    #[serde(skip)]
    pub network_proxy: ProxyConfig,
    /// Cross-platform UI policy.
    pub ui: UiPolicy,
    /// BaseProcessContainer-specific UI config (Windows only, from appContainer.ui).
    pub base_process_ui: BaseProcessUiConfig,
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
pub struct WslcConfig {
    /// Target OS for the container. Currently only "linux" is supported.
    pub target_os: String,
    /// Container image name (e.g., "alpine:latest", "python:3.12").
    pub image: String,
    /// Path to a local tar file to import as the container image.
    /// When set, the image is imported from this file instead of pulling from a registry.
    pub image_tar_path: Option<String>,
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

impl Default for WslcConfig {
    fn default() -> Self {
        Self {
            target_os: "linux".to_string(),
            image: "alpine:latest".to_string(),
            image_tar_path: None,
            cpu_count: None,
            memory_mb: None,
            gpu: false,
            storage_path: None,
            port_mappings: Vec::new(),
        }
    }
}

/// Container lifecycle settings shared across all backends.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct LifecycleConfig {
    /// Destroy the container after execution completes. Default: true.
    pub destroy_on_exit: bool,
    /// If true, retain filesystem and network policies after execution. Default: false.
    pub preserve_policy: bool,
}

impl Default for LifecycleConfig {
    fn default() -> Self {
        Self {
            destroy_on_exit: true,
            preserve_policy: false,
        }
    }
}

/// Placeholder experimental feature for testing the experimental infrastructure.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct TestFeatureConfig {
    /// Message to log when the feature is applied.
    pub message: String,
}

impl TestFeatureConfig {
    pub fn from_raw(message: Option<String>) -> Self {
        Self {
            message: message.unwrap_or_default(),
        }
    }
}

/// Container for all experimental feature configs.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct ExperimentalConfig {
    /// Placeholder feature for testing experimental infrastructure.
    pub test: Option<TestFeatureConfig>,
    /// Windows Sandbox backend (experimental).
    #[serde(rename = "windows_sandbox")]
    pub windows_sandbox: Option<WindowsSandboxConfig>,
    /// WSL Container (WSLC SDK) backend (experimental).
    pub wslc: Option<WslcConfig>,
    /// Isolation Session backend (experimental).
    #[serde(rename = "isolation_session")]
    pub isolation_session: Option<IsolationSessionConfig>,
    /// Seatbelt backend (experimental).
    #[serde(rename = "seatbelt")]
    pub seatbelt: Option<SeatbeltConfig>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
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
    /// Shared lifecycle settings.
    pub lifecycle: LifecycleConfig,
    /// AppContainer-specific policy (used when containment == AppContainer).
    pub policy: ContainerPolicy,
    /// LXC-specific configuration (used when containment == Lxc).
    pub lxc_config: LxcConfig,
    /// Whether the --experimental flag was passed.
    pub experimental_enabled: bool,
    /// Experimental feature configs (only applied when experimental_enabled is true).
    pub experimental: ExperimentalConfig,
    /// Dry-run mode: validate config and runner setup then return success
    /// without executing the sandboxed process.
    pub dry_run: bool,
}

impl Default for CodexRequest {
    fn default() -> Self {
        Self {
            schema_version: String::new(),
            container_id: String::new(),
            platform: "windows".to_string(),
            env: Vec::new(),
            script_code: String::new(),
            working_directory: String::new(),
            script_timeout: 0,
            containment: ContainmentBackend::default(),
            lifecycle: LifecycleConfig::default(),
            policy: ContainerPolicy::default(),
            lxc_config: LxcConfig::default(),
            experimental_enabled: false,
            experimental: ExperimentalConfig::default(),
            dry_run: false,
        }
    }
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

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn isolation_session_user_serde_round_trips_camel_case() {
        let wire = json!({"upn": "alice@contoso.com", "wamToken": "tok"});
        let parsed: IsolationSessionUser = serde_json::from_value(wire.clone()).unwrap();
        assert_eq!(parsed.upn, "alice@contoso.com");
        assert_eq!(parsed.wam_token, "tok");
        let serialised = serde_json::to_value(&parsed).unwrap();
        assert_eq!(serialised, wire);
    }

    #[test]
    fn isolation_session_user_debug_redacts_wam_token() {
        let user = IsolationSessionUser {
            upn: "alice@contoso.com".to_string(),
            wam_token: "super-secret-token".to_string(),
        };
        let s = format!("{:?}", user);
        assert!(s.contains("alice@contoso.com"), "got {}", s);
        assert!(s.contains("<redacted>"), "got {}", s);
        assert!(!s.contains("super-secret-token"), "got {}", s);
    }

    #[test]
    fn isolation_session_provision_config_accepts_user_field() {
        let wire = json!({"user": {"upn": "alice@contoso.com", "wamToken": "tok"}});
        let parsed: IsolationSessionProvisionConfig = serde_json::from_value(wire).unwrap();
        let u = parsed.user.unwrap();
        assert_eq!(u.upn, "alice@contoso.com");
        assert_eq!(u.wam_token, "tok");
    }

    #[test]
    fn isolation_session_provision_config_defaults_to_no_user() {
        let parsed: IsolationSessionProvisionConfig = serde_json::from_value(json!({})).unwrap();
        assert!(parsed.user.is_none());
    }

    #[test]
    fn isolation_session_config_carries_optional_user() {
        let wire = json!({
            "configurationId": "medium",
            "user": {"upn": "alice@contoso.com", "wamToken": "tok"}
        });
        let parsed: IsolationSessionConfig = serde_json::from_value(wire).unwrap();
        assert_eq!(
            parsed.configuration_id,
            IsolationSessionConfigurationId::Medium
        );
        assert!(parsed.user.is_some());
    }
}
