// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Phase 2 **option B2**: a dedicated, well-typed wire model that is the single
//! source of truth for the MXC config shape.
//!
//! Unlike the permissive `Raw*` deserialization structs in `config_parser`,
//! these types describe the config *contract* precisely:
//!
//! * real `enum`s for closed value sets (`Containment`, `NetworkPolicy`, …)
//!   instead of `Option<String>`,
//! * `#[serde(rename_all = "camelCase")]` so field names match the wire without
//!   per-field `#[serde(rename)]` noise,
//! * `#[serde(deny_unknown_fields)]` so the generated schema is closed
//!   (`additionalProperties: false`),
//! * `///` doc-comments that schemars turns into schema `description`s.
//!
//! In a full integration these types replace the `Raw*` structs as the parse
//! target (serde deserializes into them, then they map to the domain
//! `ExecutionRequest`). For this spike they exist behind the `schema-gen`
//! feature so we can compare the generated schema and the type ergonomics.

#![cfg(feature = "schema-gen")]

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// MXC sandbox execution configuration (one-shot request).
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MxcConfig {
    /// MXC config schema version (semver), e.g. `"0.8.0-alpha"`.
    pub version: Option<String>,

    /// Externally assigned container identifier.
    pub container_id: Option<String>,

    /// Containment backend to use for execution. Accepts abstract intents
    /// (`process`, `vm`) and concrete backends; the binary resolves intents to
    /// a concrete backend per host at run time.
    pub containment: Option<Containment>,

    /// Process to execute and its environment.
    pub process: Option<Process>,

    /// Container lifecycle settings.
    pub lifecycle: Option<Lifecycle>,

    /// ProcessContainer-specific settings (Windows). Used when containment is
    /// `processcontainer`.
    pub process_container: Option<ProcessContainer>,

    /// LXC container settings (Linux). Used when containment is `lxc`.
    pub lxc: Option<Lxc>,

    /// Filesystem access policy. Shared across all backends.
    pub filesystem: Option<Filesystem>,

    /// AppContainer DACL-mutation fallback policy (Windows).
    pub fallback: Option<Fallback>,

    /// Network access policy. Shared across all backends.
    pub network: Option<Network>,

    /// Cross-platform UI isolation policy.
    pub ui: Option<Ui>,

    /// macOS Seatbelt backend configuration. Used when containment is
    /// `seatbelt`.
    pub seatbelt: Option<Seatbelt>,

    /// Experimental features. Only honored when `--experimental` is passed.
    pub experimental: Option<Experimental>,
}

/// Containment backend (abstract intent or concrete backend).
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum Containment {
    /// OS-native process sandbox (resolved per host).
    Process,
    /// Windows AppContainer / BaseContainer.
    #[serde(rename = "processcontainer")]
    ProcessContainer,
    /// VM-class isolation (resolved per host).
    Vm,
    /// Windows Sandbox (experimental).
    WindowsSandbox,
    /// Full Linux container.
    Lxc,
    /// NanVix micro-VM (experimental).
    Microvm,
    /// Hyperlight micro-VM (experimental).
    Hyperlight,
    /// WSL container (experimental).
    Wslc,
    /// macOS Seatbelt.
    Seatbelt,
    /// Windows IsolationSession (experimental).
    IsolationSession,
    /// Unprivileged Linux bubblewrap sandbox.
    Bubblewrap,
}

/// Process execution settings.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Process {
    /// Command line (or script) to execute.
    pub command_line: Option<String>,
    /// Working directory for the process.
    pub cwd: Option<String>,
    /// Environment variables as `"KEY=VALUE"` strings.
    pub env: Option<Vec<String>>,
    /// Wall-clock timeout in milliseconds.
    pub timeout: Option<u32>,
}

/// Container lifecycle settings.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Lifecycle {
    /// Destroy the container when the process exits (default true).
    pub destroy_on_exit: Option<bool>,
    /// Preserve the applied policy after exit (default false).
    pub preserve_policy: Option<bool>,
}

/// ProcessContainer-specific settings.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ProcessContainer {
    /// Enforce least-privilege mode.
    pub least_privilege: Option<bool>,
    /// AppContainer permissive learning mode.
    pub learning_mode: Option<bool>,
    /// AppContainer capabilities (e.g. `internetClient`, `registryRead`).
    pub capabilities: Option<Vec<String>>,
    /// BaseProcessContainer UI settings (Windows).
    pub ui: Option<BaseProcessUi>,
}

/// BaseProcessContainer UI isolation settings.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct BaseProcessUi {
    /// UI isolation level.
    pub isolation: Option<UiIsolation>,
    /// Whether desktop system control is allowed.
    pub desktop_system_control: Option<bool>,
    /// System settings access level.
    pub system_settings: Option<String>,
    /// Whether the IME (Input Method Editor) is allowed.
    pub ime: Option<bool>,
}

/// Desktop UI isolation level.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "lowercase")]
pub enum UiIsolation {
    Desktop,
    Handles,
    Atoms,
    Container,
}

/// LXC container settings.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Lxc {
    /// Distribution image (e.g. `alpine`).
    pub distribution: Option<String>,
    /// Distribution release (e.g. `3.23`).
    pub release: Option<String>,
}

/// Filesystem access policy.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Filesystem {
    /// Paths the process can read and write.
    pub readwrite_paths: Option<Vec<String>>,
    /// Paths the process can read but not write.
    pub readonly_paths: Option<Vec<String>>,
    /// Paths explicitly denied (override broader allow rules).
    pub denied_paths: Option<Vec<String>>,
}

/// AppContainer DACL-mutation fallback policy.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Fallback {
    /// Allow the runner to mutate DACLs as a fallback.
    pub allow_dacl_mutation: Option<bool>,
}

/// Network access policy.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Network {
    /// Default outbound policy when no host rule matches.
    pub default_policy: Option<NetworkPolicy>,
    /// How the policy is enforced.
    pub enforcement_mode: Option<NetworkEnforcement>,
    /// Allow binding/listening on local IPs and accepting inbound connections.
    pub allow_local_network: Option<bool>,
    /// Hosts explicitly allowed.
    pub allowed_hosts: Option<Vec<String>>,
    /// Hosts explicitly blocked.
    pub blocked_hosts: Option<Vec<String>>,
    /// Proxy configuration (one of localhost / builtinTestServer / url).
    pub proxy: Option<Proxy>,
}

/// Default network policy.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "lowercase")]
pub enum NetworkPolicy {
    Allow,
    Block,
}

/// Network enforcement mechanism.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "lowercase")]
pub enum NetworkEnforcement {
    Proxy,
    Firewall,
}

/// Proxy configuration. Exactly one variant applies.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Proxy {
    /// External localhost proxy port.
    pub localhost: Option<u16>,
    /// Have wxc launch its own built-in test proxy.
    pub builtin_test_server: Option<bool>,
    /// Proxy URL (parsed into host:port).
    pub url: Option<String>,
}

/// Cross-platform UI isolation policy.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Ui {
    /// Disable all UI access (default true).
    pub disable: Option<bool>,
    /// Clipboard access level.
    pub clipboard: Option<ClipboardPolicy>,
    /// Allow UI injection.
    pub injection: Option<bool>,
}

/// Clipboard access level.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "lowercase")]
pub enum ClipboardPolicy {
    None,
    Read,
    Write,
    All,
}

/// macOS Seatbelt backend configuration.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Seatbelt {
    /// Replace the generated profile entirely (advanced/testing escape hatch).
    pub profile_override: Option<String>,
    /// Allow GUI (WindowServer) access.
    pub gui_access: Option<bool>,
    /// Inner process launch method.
    pub launch_method: Option<LaunchMethod>,
    /// Attach the inner process to a nested pty (default true).
    pub nested_pty: Option<bool>,
    /// Allow Keychain access.
    pub keychain_access: Option<bool>,
    /// Additional Mach service global-names the inner process may resolve.
    pub extra_mach_lookups: Option<Vec<String>>,
}

/// Seatbelt inner-process launch method.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "lowercase")]
pub enum LaunchMethod {
    /// Direct fork → sandbox_init() → exec.
    Direct,
    /// Re-exec via sandbox-exec.
    SandboxExec,
}

/// Experimental features (only honored with `--experimental`).
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Experimental {
    /// Placeholder feature for testing experimental infrastructure.
    pub test: Option<TestFeature>,
    /// Windows Sandbox backend config.
    pub windows_sandbox: Option<WindowsSandbox>,
    /// WSL container backend config.
    pub wslc: Option<Wslc>,
    /// IsolationSession backend config (Windows).
    pub isolation_session: Option<IsolationSession>,
    /// Seatbelt backend config (pre-promotion alias).
    pub seatbelt: Option<Seatbelt>,
}

/// Placeholder experimental feature.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TestFeature {
    /// Message to log when the feature is applied.
    pub message: Option<String>,
}

/// Windows Sandbox backend config.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct WindowsSandbox {
    /// Idle timeout before teardown (ms).
    pub idle_timeout_ms: Option<u32>,
    /// Idle timeout (legacy seconds field).
    pub idle_timeout: Option<u32>,
    /// Daemon named-pipe override.
    pub daemon_pipe_name: Option<String>,
}

/// WSL container backend config.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Wslc {
    /// OS inside the WSL container.
    pub target_os: Option<String>,
    /// Container image reference.
    pub image: Option<String>,
    /// Path to a local image tarball.
    pub image_tar_path: Option<String>,
    /// vCPU count.
    pub cpu_count: Option<u32>,
    /// Memory limit (MB).
    pub memory_mb: Option<u64>,
    /// Enable GPU passthrough.
    pub gpu: Option<bool>,
    /// Storage path override.
    pub storage_path: Option<String>,
    /// Host → container port forwards.
    pub port_mappings: Option<Vec<PortMapping>>,
}

/// A single host → container port forward.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PortMapping {
    /// Host (Windows) port.
    pub windows_port: u16,
    /// Container port.
    pub container_port: u16,
    /// Protocol (`tcp` or `udp`; default `tcp`).
    pub protocol: Option<TransportProtocol>,
}

/// Port-forward transport protocol.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "lowercase")]
pub enum TransportProtocol {
    Tcp,
    Udp,
}

/// IsolationSession backend config.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct IsolationSession {
    /// Sizing profile.
    pub configuration_id: Option<IsolationConfigurationId>,
    /// Optional Entra cloud-agent user bundle.
    pub user: Option<IsolationUser>,
}

/// IsolationSession sizing profile.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "lowercase")]
pub enum IsolationConfigurationId {
    Small,
    Medium,
    Large,
    Composable,
}

/// Entra cloud-agent user bundle.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct IsolationUser {
    /// User principal name.
    pub upn: String,
    /// Short-lived WAM bearer token (passed verbatim to the OS service).
    pub wam_token: String,
}

/// Generate the JSON Schema for the one-shot wire config from the dedicated
/// `MxcConfig` model (Phase 2 **option B2**).
pub fn generate_config_schema_json() -> String {
    let schema = schemars::schema_for!(MxcConfig);
    serde_json::to_string_pretty(&schema).expect("schema serialises to JSON")
}
