// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Reusable configuration DTOs shared by exact-contract adapters and typed SDK
//! builders. These are normalization inputs, not an externally deserializable
//! whole-request contract.

use serde::Serialize;

/// State-aware lifecycle phase.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Phase {
    Provision,
    Start,
    Exec,
    Stop,
    Deprovision,
}

/// Containment backend (abstract intent or concrete backend).
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Containment {
    /// OS-native process sandbox (resolved per host).
    Process,
    /// Windows AppContainer / BaseContainer.
    #[serde(rename = "processcontainer", alias = "appcontainer")]
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
    /// WSL container.
    Wslc,
    /// macOS Seatbelt.
    #[serde(alias = "macos_sandbox")]
    Seatbelt,
    /// Windows IsolationSession.
    IsolationSession,
    /// Unprivileged Linux bubblewrap sandbox.
    Bubblewrap,
}

impl Containment {
    pub(crate) fn parse_wire_name(value: &str) -> Option<Self> {
        Some(match value {
            "process" => Self::Process,
            "processcontainer" | "appcontainer" => Self::ProcessContainer,
            "vm" => Self::Vm,
            "windows_sandbox" => Self::WindowsSandbox,
            "lxc" => Self::Lxc,
            "microvm" => Self::Microvm,
            "hyperlight" => Self::Hyperlight,
            "wslc" => Self::Wslc,
            "seatbelt" | "macos_sandbox" => Self::Seatbelt,
            "isolation_session" => Self::IsolationSession,
            "bubblewrap" => Self::Bubblewrap,
            _ => return None,
        })
    }
}

/// Process execution settings.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Process {
    /// Command line (or script) to execute.
    pub command_line: Option<String>,
    /// Working directory for the process. When omitted, backends substitute a
    /// directory the sandbox can use rather than inheriting the launcher's cwd:
    /// Windows ProcessContainer picks the first `readwritePaths` entry that is
    /// an existing directory, else the first such `readonlyPaths` entry, else
    /// the system drive root; Seatbelt applies the same precedence with a `/`
    /// fallback; LXC/WSL use the container root; NanVix and Hyperlight reject a
    /// working directory outright. See `docs/schema.md` ("Working Directory").
    pub cwd: Option<String>,
    /// Environment variables as `"KEY=VALUE"` strings.
    ///
    /// Omit the field to give the child the backend's default environment (on
    /// Windows, the user's profile block). Supply it — including as an empty
    /// array — and it is used verbatim; MXC adds nothing to it unless
    /// `inheritDefaultEnv` is set.
    pub env: Option<Vec<String>>,
    /// Start from the backend's default environment and layer `env` on top of
    /// it, rather than replacing it (default false).
    ///
    /// This exists because the default environment is not something a caller
    /// can assemble: on Windows it is the user's profile block, which only the
    /// OS can produce. Entries in `env` override same-named defaults. Has no
    /// effect on backends whose default environment is empty, and none when
    /// `env` is omitted (that already yields the default).
    pub inherit_default_env: Option<bool>,
    /// Wall-clock timeout in milliseconds.
    pub timeout: Option<u32>,
}

/// Container lifecycle settings.
#[derive(Debug, Clone, Default, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Lifecycle {
    /// Destroy the container when the process exits (default true).
    pub destroy_on_exit: Option<bool>,
    /// Preserve the applied policy after exit (default false).
    pub preserve_policy: Option<bool>,
}

/// ProcessContainer-specific settings.
#[derive(Debug, Clone, Default, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ProcessContainer {
    /// Enforce least-privilege mode.
    pub least_privilege: Option<bool>,
    /// AppContainer learning mode (deny-and-record): failed access checks are
    /// logged for diagnostics while the accesses stay denied; containment is
    /// unchanged. Distinct from the allow-all `permissiveLearningMode`
    /// capability, which is injected internally by the `--audit` CLI flag or
    /// dedicated denial-capture configuration.
    pub learning_mode: Option<bool>,
    /// AppContainer capabilities (e.g. `internetClient`, `registryRead`).
    /// Each array entry must contain exactly one capability name; commas are
    /// rejected because BaseContainer uses commas as its wire delimiter.
    /// `learningModeLogging` and `permissiveLearningMode` are reserved and
    /// rejected here; use `learningMode`, `--audit`, or the dedicated denial
    /// capture configuration instead.
    pub capabilities: Option<Vec<String>>,
    /// Windows denial capture. When present, the runner records the sandboxed
    /// process's access attempts to a learning-mode ETL trace for later
    /// inspection. MXC prefers native PSEC plus V2 Learning Mode when that API
    /// set can fully honor the request. Otherwise it retains the highest
    /// compatible legacy containment tier and uses guarded WPR capture, so
    /// `leastPrivilege`, `network.proxy`, and deny-path policies can remain
    /// enforced without weakening the request.
    pub capture_denials: Option<CaptureDenials>,
    /// BaseProcessContainer UI settings (Windows).
    pub ui: Option<BaseProcessUi>,
    /// ProcessContainer-specific filesystem configuration.
    pub filesystem: Option<ProcessContainerFilesystem>,
    /// ProcessContainer-specific network configuration.
    pub network: Option<ProcessContainerNetwork>,
}

/// ProcessContainer-specific filesystem configuration.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ProcessContainerFilesystem {
    /// Paths the process can query or enumerate without reading file contents.
    pub enumerate_paths: Option<Vec<String>>,
}

/// ProcessContainer-specific network configuration.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ProcessContainerNetwork {
    /// Installed package family name or AppContainer profile allowed to host
    /// the configured loopback proxy.
    pub allowed_proxy_peer: Option<String>,
}

/// Windows denial-capture settings. The presence of the `captureDenials`
/// object enables capture; all fields are optional. Native capture requires
/// the complete compatible PSEC plus V2 Learning Mode API set. Requests that
/// native capture cannot represent use guarded WPR with a compatible
/// AppContainer containment tier.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CaptureDenials {
    /// How each ungranted access check is handled while it is recorded. Both
    /// modes log every access the policy does not grant to the ETL trace; the
    /// mode only decides whether that access is blocked or allowed. Defaults to
    /// `block` when omitted.
    pub mode: Option<CaptureDenialsMode>,
    /// Absolute path where the JSON denials output file is written — the
    /// deliverable a consuming application reads to learn what the workload
    /// was denied. It is a single JSON document `{ "denials": [...],
    /// "summary": {...} }`. A per-run identifier (process id plus random
    /// suffix) is inserted into the file stem (e.g. `denials.json` ->
    /// `denials.<run-id>.json`) so concurrent and sequential captures do not
    /// collide; the actual path is reported on stderr. When omitted, MXC
    /// writes it to a managed per-run temporary file and prints its path on
    /// stderr. The parent directory must already exist. (The intermediate ETL
    /// trace is an internal, runner-managed file in a protected per-run
    /// directory. Retained traces use
    /// `%LOCALAPPDATA%\Microsoft\MXC\capture-denials\retained`; non-retained
    /// traces use the system temporary directory.)
    pub output_path: Option<String>,
    /// Keep the sealed ETL trace after analysis and report its path in output
    /// metadata. Defaults to `false`, which deletes the trace after analysis.
    /// Retention requires a terminal wait; abandoning the process handle
    /// deletes the internal trace. If post-seal analysis fails, the failure and
    /// retained path are exposed through `captureDenialsError` output metadata.
    /// Retained traces can contain sensitive resource paths and identifiers;
    /// callers are responsible for deleting them.
    pub retain_etl: Option<bool>,
}

/// How `captureDenials` handles each ungranted access check while recording it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum CaptureDenialsMode {
    /// `block` — the access stays **denied** and the denial is recorded.
    /// Deny-by-default containment is preserved; this is the safe default.
    Block,
    /// `allow` — the access is **allowed** and recorded (audit mode).
    /// This relaxes deny-by-default for the run, so it is a security-sensitive
    /// choice and the runner emits a security warning.
    Allow,
}

/// BaseProcessContainer UI isolation settings.
#[derive(Debug, Clone, Serialize)]
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
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum UiIsolation {
    Desktop,
    Handles,
    Atoms,
    Container,
}

impl UiIsolation {
    /// Lowercase wire-format string matching the schema enum values.
    pub fn as_str(&self) -> &'static str {
        match self {
            UiIsolation::Desktop => "desktop",
            UiIsolation::Handles => "handles",
            UiIsolation::Atoms => "atoms",
            UiIsolation::Container => "container",
        }
    }
}

/// LXC container settings.
#[derive(Debug, Clone, Default, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Lxc {
    /// Distribution image (e.g. `alpine`).
    pub distribution: Option<String>,
    /// Distribution release (e.g. `3.23`).
    pub release: Option<String>,
}

/// Filesystem access policy.
#[derive(Debug, Clone, Serialize)]
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
#[derive(Debug, Clone, Default, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Fallback {
    /// Allow the runner to mutate DACLs as a fallback.
    pub allow_dacl_mutation: Option<bool>,
}

/// Network access policy.
#[derive(Debug, Clone, Serialize)]
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
    /// Outbound network policy.
    pub egress: Option<NetworkEgress>,
    /// Inbound and host-loopback network policy.
    pub ingress: Option<NetworkIngress>,
}

/// Outbound network policy.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct NetworkEgress {
    /// Action used when no explicit rule matches. Defaults to `deny`.
    pub default: Option<NetworkAction>,
    /// Explicit allow rules.
    pub allow: Option<Vec<NetworkRule>>,
    /// Explicit deny rules. Deny rules take precedence over allow rules.
    pub deny: Option<Vec<NetworkRule>>,
}

/// Inbound and host-loopback network policy.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct NetworkIngress {
    /// Default action for LAN/private-network inbound traffic.
    pub default: Option<NetworkAction>,
    /// Bidirectional host-loopback connectivity action.
    pub host_loopback: Option<NetworkAction>,
}

/// Allow or deny network action.
#[derive(Debug, Clone, Copy, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum NetworkAction {
    Allow,
    Deny,
}

/// Outbound network rule.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct NetworkRule {
    /// Destination CIDRs. Omission matches both IP families.
    pub to: Option<Vec<NetworkPeer>>,
    /// Destination protocols and ports. Omission matches all.
    pub ports: Option<Vec<NetworkPort>>,
}

/// CIDR network peer.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct NetworkPeer {
    /// IPv4 or IPv6 CIDR.
    pub cidr: String,
    /// CIDRs excluded from this peer.
    pub except: Option<Vec<String>>,
}

/// Protocol and destination-port selector.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct NetworkPort {
    /// Transport protocol. Defaults to `any`.
    pub protocol: Option<NetworkProtocol>,
    /// Destination port. Omission matches every port.
    pub port: Option<u16>,
    /// Inclusive end of a destination-port range. Requires `port`.
    pub end_port: Option<u16>,
}

/// Transport protocol selector.
#[derive(Debug, Clone, Copy, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum NetworkProtocol {
    Tcp,
    Udp,
    Icmp,
    Any,
}

/// Runtime values supplied alongside, but separate from, sandbox policy.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RuntimeConfig {
    /// HTTP/S loopback proxy URL.
    pub network_proxy: Option<String>,
}

/// Default network policy.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum NetworkPolicy {
    Allow,
    Block,
}

/// Network enforcement mechanism.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum NetworkEnforcement {
    /// Per-process capability-based filtering.
    Capabilities,
    /// Host firewall rules.
    Firewall,
    /// Both capability and firewall enforcement.
    Both,
}

/// Proxy configuration. Exactly one variant applies.
#[derive(Debug, Clone, Serialize)]
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
#[derive(Debug, Clone, Serialize)]
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
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum ClipboardPolicy {
    None,
    Read,
    Write,
    All,
}

/// macOS Seatbelt backend configuration.
#[derive(Debug, Clone, Default, Serialize)]
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
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum LaunchMethod {
    /// sandbox_init() + exec (default). Works for third-party GUI apps.
    Exec,
    /// Launch via macOS LaunchServices (`open`), then apply the sandbox to the
    /// inner shell via sandbox-exec. Required for apps with launch constraints.
    Open,
}

/// Telemetry configuration (`telemetry`).
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Telemetry {
    /// Explicit telemetry opt-in for this invocation. `true` = opt in (still
    /// subject to the user's consent and to administrative policy — it can
    /// never turn telemetry on for someone who has not consented), `false` =
    /// force off, omitted = off.
    pub enabled: Option<bool>,
}

/// Placeholder experimental feature.
#[derive(Debug, Clone, Default, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TestFeature {
    /// Message to log when the feature is applied.
    pub message: Option<String>,
}

/// Windows Sandbox backend config.
#[derive(Debug, Clone, Default, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct WindowsSandbox {
    /// Idle timeout before teardown (ms).
    pub idle_timeout_ms: Option<u32>,
    /// Idle timeout (legacy seconds field).
    pub idle_timeout: Option<u32>,
    /// Daemon named-pipe override.
    pub daemon_pipe_name: Option<String>,
}

/// WSL container backend config.
#[derive(Debug, Clone, Default, Serialize)]
#[serde(rename_all = "camelCase")]
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
    /// Host → container port forwards. Only TCP is currently supported; the
    /// parser rejects `udp` because the WSLC SDK runtime returns `E_NOTIMPL`
    /// for UDP port mappings.
    pub port_mappings: Option<Vec<PortMapping>>,
    /// State-aware provision-phase normalization input constructed from the
    /// exact `wslc.provision` contract. Carries the container-creation knobs for
    /// the state-aware lifecycle; the flat sibling fields above remain the
    /// one-shot surface. Absent on one-shot configs and non-provision phases.
    pub provision: Option<WslcProvisionPhase>,
}

/// Per-phase WSLc **provision** normalization input, constructed from the exact
/// `wslc.provision` contract. Carries only what the amortized daemon session
/// honors: the container image (or a local tarball to import).
///
/// Filesystem mounts and network mode derive from the top-level `policy`
/// section (readwrite / readonly paths, network), not from here. The
/// one-shot-only sizing knobs (`cpuCount` / `memoryMb` / `gpu` / `storagePath`
/// / `portMappings`) are deliberately absent: the daemon shares a single session
/// across sandboxes and does not apply per-sandbox sizing. start / exec / stop /
/// deprovision carry no backend-specific config (the exec command flows through
/// the top-level `process` section), so they have no phase struct.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct WslcProvisionPhase {
    /// Container image reference (e.g. `alpine:latest`). Defaults to
    /// `alpine:latest` when omitted.
    pub image: Option<String>,
    /// Path to a local image tarball to import instead of pulling.
    pub image_tar_path: Option<String>,
}

/// A single host → container port forward retained in normalized WSLC settings.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PortMapping {
    /// Host (Windows) port.
    pub windows_port: u16,
    /// Container port.
    pub container_port: u16,
    /// Transport protocol for the mapping. Only `tcp` is currently supported.
    pub protocol: Option<TransportProtocol>,
}

/// Port-forward transport protocol. Only `tcp` is currently supported by the
/// vendored WSLC SDK runtime; `udp` is rejected at parse time.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum TransportProtocol {
    Tcp,
}

#[cfg(test)]
mod tests {
    use super::Containment;
    use crate::models::ContainmentBackend;

    const BACKENDS: &[ContainmentBackend] = &[
        ContainmentBackend::ProcessContainer,
        ContainmentBackend::Wslc,
        ContainmentBackend::Lxc,
        ContainmentBackend::Hyperlight,
        ContainmentBackend::WindowsSandbox,
        ContainmentBackend::IsolationSession,
        ContainmentBackend::Seatbelt,
        ContainmentBackend::Bubblewrap,
    ];

    #[test]
    fn runtime_backend_names_are_accepted_by_the_raw_containment_parser() {
        for backend in BACKENDS {
            let parsed = Containment::parse_wire_name(backend.wire_name())
                .unwrap_or_else(|| panic!("unrecognized backend name: {}", backend.wire_name()));
            assert_eq!(
                crate::config_parser::map_wire_containment(Some(&parsed)),
                backend.clone(),
                "{backend:?}"
            );
        }
    }
}
