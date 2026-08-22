// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use serde::{Deserialize, Serialize};
use std::net::IpAddr;

use crate::error::WxcError;

/// Selects which containment backend to use for script execution.
#[derive(Debug, Default, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum ContainmentBackend {
    #[default]
    /// Windows process-level containment. Resolves at runtime to either
    /// AppContainer (legacy OS API) or BaseContainer (newer Windows
    /// sandbox API exposed via `Experimental_CreateProcessInSandbox`)
    /// based purely on host capability — BaseContainer is preferred when
    /// the OS supports it, AppContainer is the downlevel fallback. The
    /// schema version does not influence this choice.
    /// Selected on the wire as `"processcontainer"`.
    ProcessContainer,
    /// Linux container via WSL Container SDK (WSLC SDK).
    Wslc,
    /// LXC — Linux container isolation.
    Lxc,
    /// VM-based isolation.
    Vm,
    /// MicroVM isolation via Windows Hypervisor Platform (internally powered by NanVix).
    #[serde(rename = "microvm")]
    MicroVm,
    /// MicroVM isolation via Hyperlight + Unikraft, using an embedded
    /// warmed-up CPython snapshot. ~100 ms cold start per invocation,
    /// hermetic via snapshot restore. Experimental — requires
    /// --experimental. Cross-platform (Linux KVM, Windows WHP).
    Hyperlight,
    /// Windows Sandbox — full VM isolation (experimental, requires --experimental flag).
    WindowsSandbox,
    /// Isolation Session — process isolation via the IsolationSession API (experimental).
    #[serde(rename = "isolation_session")]
    IsolationSession,
    /// macOS Seatbelt sandbox backend.
    /// Implemented on top of the OS-bundled sandbox facility (Apple's
    /// internal codename for the App Sandbox / `sandbox-exec` machinery
    /// is "Seatbelt"); selected on the wire as `"seatbelt"`.
    Seatbelt,
    /// Bubblewrap — unprivileged Linux sandboxing via user namespaces.
    /// Experimental — requires `--experimental` flag. Uses `bwrap` to
    /// create namespace-isolated processes without root privileges.
    /// Selected on the wire as `"bubblewrap"`.
    Bubblewrap,
}

impl ContainmentBackend {
    /// Canonical wire string matching the JSON schema `containment` enum.
    pub fn wire_name(&self) -> &'static str {
        match self {
            ContainmentBackend::ProcessContainer => "processcontainer",
            ContainmentBackend::Wslc => "wslc",
            ContainmentBackend::Lxc => "lxc",
            ContainmentBackend::Vm => "vm",
            ContainmentBackend::MicroVm => "microvm",
            ContainmentBackend::Hyperlight => "hyperlight",
            ContainmentBackend::WindowsSandbox => "windows_sandbox",
            ContainmentBackend::IsolationSession => "isolation_session",
            ContainmentBackend::Seatbelt => "seatbelt",
            ContainmentBackend::Bubblewrap => "bubblewrap",
        }
    }

    /// JSON path of this backend's per-backend config section, if any.
    /// Backends without a section return `None` and reject any backend
    /// section paired with them.
    pub fn section_path(&self) -> Option<&'static str> {
        match self {
            ContainmentBackend::ProcessContainer => Some("processContainer"),
            ContainmentBackend::Lxc => Some("lxc"),
            ContainmentBackend::WindowsSandbox => Some("experimental.windows_sandbox"),
            ContainmentBackend::Wslc => Some("experimental.wslc"),
            ContainmentBackend::Seatbelt => Some("seatbelt"),
            ContainmentBackend::IsolationSession => Some("experimental.isolation_session"),
            ContainmentBackend::Bubblewrap
            | ContainmentBackend::Hyperlight
            | ContainmentBackend::MicroVm
            | ContainmentBackend::Vm => None,
        }
    }
}

impl From<crate::wire::Containment> for ContainmentBackend {
    /// Resolve a `containment` wire value to a concrete domain backend.
    ///
    /// The abstract intents resolve per host: `process` → the OS-native process
    /// sandbox, `vm` → the host's VM-class backend. Concrete backends map
    /// verbatim. Deprecated spellings (`appcontainer`, `macos_sandbox`) are
    /// accepted via `#[serde(alias)]` on the wire enum and arrive here already
    /// mapped to the canonical variant.
    fn from(c: crate::wire::Containment) -> Self {
        use crate::wire::Containment as W;
        match c {
            W::Process => {
                #[cfg(target_os = "linux")]
                {
                    Self::Bubblewrap
                }
                #[cfg(target_os = "macos")]
                {
                    Self::Seatbelt
                }
                #[cfg(not(any(target_os = "linux", target_os = "macos")))]
                {
                    Self::ProcessContainer
                }
            }
            W::ProcessContainer => Self::ProcessContainer,
            W::Vm => {
                #[cfg(target_os = "windows")]
                {
                    Self::WindowsSandbox
                }
                #[cfg(not(target_os = "windows"))]
                {
                    Self::Vm
                }
            }
            W::WindowsSandbox => Self::WindowsSandbox,
            W::Lxc => Self::Lxc,
            W::Microvm => Self::MicroVm,
            W::Hyperlight => Self::Hyperlight,
            W::Wslc => Self::Wslc,
            W::Seatbelt => Self::Seatbelt,
            W::IsolationSession => Self::IsolationSession,
            W::Bubblewrap => Self::Bubblewrap,
        }
    }
}

/// Configuration specific to the Seatbelt backend.
/// Used under the top-level `seatbelt` key when `containment == Seatbelt`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct SeatbeltConfig {
    /// Optional override of the generated TinyScheme profile.
    #[serde(rename = "profileOverride", skip_serializing_if = "Option::is_none")]
    pub profile_override: Option<String>,

    /// Allow the Mach IPC services that GUI applications need to draw
    /// windows, composite frames, resolve fonts, and register with the Dock.
    /// When `false` (default), these services are blocked and GUI apps will
    /// be killed by the system on launch.
    #[serde(rename = "guiAccess", default)]
    pub gui_access: bool,

    /// How to launch the sandboxed process.
    ///
    /// - `"exec"` (default): fork → sandbox_init() → exec. Stdio is inherited
    ///   when `guiAccess` is true, piped otherwise. Works for most
    ///   third-party GUI apps and all CLI commands.
    /// - `"open"`: launch via macOS LaunchServices (`open -n -W`). Required
    ///   for Apple system apps (e.g. Terminal.app) that have Launch
    ///   Constraints preventing direct exec from third-party processes.
    ///   The sandbox is applied to the shell/command running *inside* the
    ///   launched app via the `sandbox-exec` CLI tool, not to the app itself.
    #[serde(rename = "launchMethod", default)]
    pub launch_method: LaunchMethod,

    /// Allow the inner process to allocate its own pseudo-terminals via
    /// `posix_openpt`. Defaults to `true` because most agent-style
    /// workloads spawn shells (tests, `git`, `gh`, REPLs) that fail
    /// without this. Adds `(allow pseudo-tty)`, `(allow iokit-open)`, and
    /// read/write/ioctl on `/dev/ptmx`. Set to `false` for the tightest
    /// possible sandbox when the inner command does not need to allocate
    /// new ttys.
    #[serde(rename = "nestedPty", default = "default_true")]
    pub nested_pty: bool,

    /// Allow Mach IPC + filesystem access required for `keytar` /
    /// `Security.framework` to actually use the macOS Keychain
    /// end-to-end (Mach: securityd, SecurityServer, cfprefsd.daemon,
    /// xpcd, lsd.*; FS read: `/Library/Keychains`, `/private/var/db/mds`;
    /// FS read+write: `~/Library/Keychains`, `/private/var/folders`;
    /// plus `iokit-open` for crypto accelerators). Defaults to `false`;
    /// opt in only when the inner workload genuinely needs Keychain
    /// access.
    #[serde(rename = "keychainAccess", default)]
    pub keychain_access: bool,

    /// Additional Mach service global-names to allow `mach-lookup` for.
    /// Escape hatch for callers that need to talk to a system service
    /// the baseline doesn't cover (e.g. opt-in agent integrations).
    /// Each entry is rendered verbatim as a `(global-name "...")`
    /// inside a single `(allow mach-lookup ...)` form.
    #[serde(
        rename = "extraMachLookups",
        default,
        skip_serializing_if = "Vec::is_empty"
    )]
    pub extra_mach_lookups: Vec<String>,
}

fn default_true() -> bool {
    true
}

impl Default for SeatbeltConfig {
    fn default() -> Self {
        Self {
            profile_override: None,
            gui_access: false,
            launch_method: LaunchMethod::default(),
            nested_pty: true,
            keychain_access: false,
            extra_mach_lookups: Vec::new(),
        }
    }
}

/// How to launch the sandboxed process in the Seatbelt backend.
#[derive(Debug, Default, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum LaunchMethod {
    /// Direct fork → sandbox_init() → exec (default).
    #[default]
    Exec,
    /// Launch via macOS LaunchServices (`open`). The sandbox is applied to
    /// the command running inside the launched terminal app via sandbox-exec.
    Open,
}

impl From<crate::wire::LaunchMethod> for LaunchMethod {
    fn from(m: crate::wire::LaunchMethod) -> Self {
        match m {
            crate::wire::LaunchMethod::Exec => Self::Exec,
            crate::wire::LaunchMethod::Open => Self::Open,
        }
    }
}

/// Configuration specific to the Windows Sandbox backend.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct WindowsSandboxConfig {
    /// Legacy daemon idle timeout. Parsed for compatibility and ignored by the
    /// one-shot backend.
    pub idle_timeout_ms: u32,
    /// Legacy daemon endpoint name. Parsed for compatibility and ignored by the
    /// one-shot backend.
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

/// State-aware provision-phase config for the Isolation Session backend.
/// Nested under `experimental.isolation_session.provision`. The one-shot
/// surface takes no backend configuration.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default, rename_all = "camelCase")]
pub struct IsolationSessionProvisionConfig {
    /// Optional identifier for the calling application — the Package Family
    /// Name for a packaged app, any string otherwise. Carried verbatim into
    /// the `sandboxId`; MXC does not interpret or verify it.
    ///
    /// An explicitly-supplied empty string is a **distinct** value from an
    /// absent one and round-trips as such. A JSON `null` is a second spelling
    /// of absent.
    pub app_id: Option<String>,
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
    Allow,
    #[default]
    Block,
}

impl From<crate::wire::NetworkPolicy> for NetworkPolicy {
    fn from(p: crate::wire::NetworkPolicy) -> Self {
        match p {
            crate::wire::NetworkPolicy::Allow => Self::Allow,
            crate::wire::NetworkPolicy::Block => Self::Block,
        }
    }
}

#[derive(Debug, Default, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum NetworkEnforcementMode {
    #[default]
    Capabilities,
    Firewall,
    Both,
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum NetworkAction {
    Allow,
    #[default]
    Deny,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum NetworkProtocol {
    Tcp,
    Udp,
    Icmp,
    Any,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NetworkCidr {
    pub address: IpAddr,
    pub prefix_length: u8,
}

impl std::str::FromStr for NetworkCidr {
    type Err = cidr::errors::NetworkParseError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let network = value.parse::<cidr::IpCidr>()?;

        Ok(Self {
            address: network.first_address(),
            prefix_length: network.network_length(),
        })
    }
}

impl NetworkCidr {
    pub fn contains_cidr(&self, other: &Self) -> bool {
        let Ok(parent) = cidr::IpCidr::new(self.address, self.prefix_length) else {
            return false;
        };
        let Ok(child) = cidr::IpCidr::new(other.address, other.prefix_length) else {
            return false;
        };
        parent.network_length() <= child.network_length() && parent.contains(&child.first_address())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NetworkPeer {
    pub cidr: NetworkCidr,
    pub except: Vec<NetworkCidr>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NetworkPort {
    pub protocol: NetworkProtocol,
    pub port: Option<u16>,
    pub end_port: Option<u16>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct NetworkRule {
    pub to: Vec<NetworkPeer>,
    pub ports: Vec<NetworkPort>,
}

#[derive(Debug, Default, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NetworkEgressPolicy {
    pub default: NetworkAction,
    pub allow: Vec<NetworkRule>,
    pub deny: Vec<NetworkRule>,
}

#[derive(Debug, Default, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NetworkIngressPolicy {
    pub default: NetworkAction,
    pub host_loopback: NetworkAction,
}

impl From<crate::wire::NetworkEnforcement> for NetworkEnforcementMode {
    fn from(m: crate::wire::NetworkEnforcement) -> Self {
        match m {
            crate::wire::NetworkEnforcement::Capabilities => Self::Capabilities,
            crate::wire::NetworkEnforcement::Firewall => Self::Firewall,
            crate::wire::NetworkEnforcement::Both => Self::Both,
        }
    }
}

/// A hostname-to-IP mapping that makes a sandbox resolve the proxy to exactly
/// the address the firewall authorized.
///
/// This exists instead of rewriting the proxy URL's host to the resolved IP.
/// Rewriting the host breaks TLS for an `https://`-scheme proxy: the client
/// then contacts an IP literal, so SNI and certificate validation fail unless
/// the proxy certificate carries an IP SAN. Pinning the name resolution
/// instead keeps the hostname in the URL, so TLS identity is preserved, while
/// still guaranteeing the sandbox and the firewall agree on one endpoint.
///
/// Without a pin the sandbox re-resolves the hostname itself, and under
/// round-robin or split-horizon DNS it can select an address the firewall
/// never allowed.
///
/// The fields are private and the address is an [`IpAddr`], so a pin that does
/// not denote exactly one mapping cannot be constructed. This matters because
/// [`Self::hosts_line`] is written to a hosts file: a newline or space in
/// either field would inject additional entries, letting an attacker redirect
/// names the policy never mentioned. Construct one with
/// [`ProxyAddress::host_pin`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProxyHostPin {
    hostname: String,
    ip: IpAddr,
}

impl ProxyHostPin {
    /// The proxy hostname as it appears in the URL handed to the sandbox.
    pub fn hostname(&self) -> &str {
        &self.hostname
    }

    /// The address the hostname is pinned to, and the only address the
    /// firewall authorizes for it.
    pub fn ip(&self) -> IpAddr {
        self.ip
    }

    /// Render this pin as a `/etc/hosts` line.
    ///
    /// The address is written bare. A hosts file takes an unbracketed IPv6
    /// literal where a URL host component requires brackets, so this rendering
    /// and [`ProxyAddress::to_url`] differ on the same address by design.
    pub fn hosts_line(&self) -> String {
        format!("{} {}", self.ip, self.hostname)
    }
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
    /// otherwise constructs one from this address and port.
    ///
    /// The address is never assumed to be loopback. The URL the sandbox is
    /// given and the endpoint the firewall authorized have to name the same
    /// proxy, so a fixed `127.0.0.1` would be wrong for a proxy not bound
    /// there.
    pub fn to_url(&self) -> String {
        if let Some(url) = &self.original_url {
            return url.clone();
        }
        format!(
            "http://{}:{}",
            Self::bracket_if_ipv6(&self.address),
            self.port
        )
    }

    /// Returns the pin required for a sandbox to resolve this proxy's hostname
    /// to `ip`.
    ///
    /// `Ok(None)` means no pin is needed, because the address is already an IP
    /// literal: there is nothing to resolve, and so nothing a sandbox could
    /// resolve differently.
    ///
    /// `Err` means a pin is needed and cannot be produced -- the address is
    /// empty, or holds characters a hostname cannot. That is an error rather
    /// than `None` because `None` reads as "no hosts entry required", which
    /// would let a malformed address silently skip the pin and leave the
    /// sandbox free to re-resolve the name. A proxy whose endpoint cannot be
    /// pinned must not run.
    ///
    /// The [`IpAddr`] parameter puts resolution on the caller and leaves an
    /// unparseable address unrepresentable here.
    ///
    /// The URL keeps its hostname; [`ProxyHostPin`] carries the reason.
    pub fn host_pin(&self, ip: IpAddr) -> Result<Option<ProxyHostPin>, WxcError> {
        let hostname = unbracket_host(&self.address);

        // An IP literal needs no pin. Unbracket first so a bracketed IPv6
        // literal is recognized as a literal rather than mistaken for a
        // hostname: `IpAddr::from_str` rejects brackets, so `[::1]` would
        // otherwise be pinned as though it were a name.
        if hostname.parse::<IpAddr>().is_ok() {
            return Ok(None);
        }

        if !Self::is_pinnable_hostname(hostname) {
            return Err(WxcError::NetworkProxy(format!(
                "proxy address {:?} cannot be pinned to {}: not a valid hostname",
                self.address, ip
            )));
        }

        Ok(Some(ProxyHostPin {
            hostname: hostname.to_string(),
            ip,
        }))
    }

    /// Whether `host` is safe to write as the name column of a hosts file
    /// entry.
    ///
    /// What matters about the allowed set is what it leaves out: a space or a
    /// newline would end the record, so a hostname carrying one would write
    /// further mappings for names the policy never authorized.
    fn is_pinnable_hostname(host: &str) -> bool {
        !host.is_empty()
            && host
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '.')
    }

    /// Wraps `host` in `[` `]` when it is a bare IPv6 literal, so it is valid
    /// as a URL host component.
    ///
    /// Double bracketing needs no guard: `IpAddr::from_str` rejects brackets,
    /// so an already-bracketed literal fails to parse and passes through
    /// unchanged.
    fn bracket_if_ipv6(host: &str) -> std::borrow::Cow<'_, str> {
        match host.parse::<IpAddr>() {
            Ok(IpAddr::V6(_)) => std::borrow::Cow::Owned(format!("[{host}]")),
            _ => std::borrow::Cow::Borrowed(host),
        }
    }
}

/// Strips one pair of surrounding `[` `]` from a bracketed IPv6 literal.
///
/// A URL host component keeps the brackets, but `IpAddr::from_str`, hosts
/// files, and iptables all reject them.
pub fn unbracket_host(host: &str) -> &str {
    host.strip_prefix('[')
        .and_then(|rest| rest.strip_suffix(']'))
        .unwrap_or(host)
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

impl From<crate::wire::ClipboardPolicy> for ClipboardPolicy {
    fn from(c: crate::wire::ClipboardPolicy) -> Self {
        match c {
            crate::wire::ClipboardPolicy::None => Self::None,
            crate::wire::ClipboardPolicy::Read => Self::Read,
            crate::wire::ClipboardPolicy::Write => Self::Write,
            crate::wire::ClipboardPolicy::All => Self::All,
        }
    }
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
/// Parsed from `processContainer.ui` in the JSON config.
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

/// Operator consent for host-impacting containment fallbacks. Each flag gates
/// a specific fallback the runner may otherwise pick when the preferred
/// primitive is unavailable. Defaults preserve the pre-fallback-section
/// behavior (all permitted).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct FallbackPolicy {
    /// When neither the in-process BaseContainer API nor the OS-side
    /// filesystem broker helper is available, allow MXC to apply DACL ACEs
    /// on policy paths (Tier 3 fallback). This modifies host filesystem
    /// security descriptors; original DACLs are restored on exit. Defaults
    /// to `true`. Set to `false` to refuse the fallback (the run will fail
    /// on machines that require Tier 3).
    pub allow_dacl_mutation: bool,
}

impl Default for FallbackPolicy {
    fn default() -> Self {
        Self {
            allow_dacl_mutation: true,
        }
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct ContainerPolicy {
    pub least_privilege_mode: bool,
    pub capabilities: Vec<String>,
    pub readwrite_paths: Vec<String>,
    pub readonly_paths: Vec<String>,
    pub denied_paths: Vec<String>,
    pub fallback: FallbackPolicy,
    pub default_network_policy: NetworkPolicy,
    pub network_enforcement_mode: NetworkEnforcementMode,
    /// When true, the sandboxed process may bind() + listen() on local IPs
    /// and accept incoming connections. Independent of `default_network_policy`
    /// (which governs outbound traffic).
    pub allow_local_network: bool,
    pub allowed_hosts: Vec<String>,
    pub blocked_hosts: Vec<String>,
    /// Outbound CIDR, protocol, and port policy.
    pub network_egress: Option<NetworkEgressPolicy>,
    /// Inbound and host-loopback policy.
    pub network_ingress: Option<NetworkIngressPolicy>,
    /// ProcessContainer proxy peer identity.
    pub allowed_proxy_peer: Option<String>,
    #[serde(skip)]
    pub network_proxy: ProxyConfig,
    /// Whether the caller supplied a `network` block on the wire (any field
    /// present), captured at parse time. Distinguishes an absent network policy
    /// from an explicit one whose values equal the defaults — the other fields
    /// here cannot, since `default_network_policy` defaults to `Block` either
    /// way. Used by backends (e.g. IsolationSession) that must reject a network
    /// policy supplied on a phase where the posture is immutable. Parse-derived,
    /// never on the wire.
    #[serde(skip)]
    pub network_specified: bool,
    /// Whether the caller supplied network posture fields: the legacy mode
    /// fields (`defaultPolicy`, `enforcementMode`, `allowLocalNetwork`,
    /// `allowedHosts`, `blockedHosts`) or directional `egress`/`ingress`.
    /// Runtime proxy data is excluded. This lets state-aware backends reject a
    /// post-provision posture change by presence while still accepting a
    /// proxy-only exec request. Parse-derived, never on the wire.
    #[serde(skip)]
    pub network_mode_specified: bool,
    /// Whether `runtimeConfig.networkProxy` was supplied. Distinguishes the
    /// schema 0.8 runtime field from the legacy `network.proxy` shape after
    /// both have been normalized into `network_proxy`.
    #[serde(skip)]
    pub runtime_network_proxy_specified: bool,
    /// Whether the parser filled the directional (0.8) network fields rather
    /// than the legacy (0.7) ones. A run carries exactly one schema, and
    /// version alone does not answer this: 0.8 still accepts a legacy `network`
    /// block. Backends read this to apply the rules of the schema they were
    /// actually given. Parse-derived, never on the wire.
    #[serde(skip)]
    pub uses_directional_network: bool,
    /// Cross-platform UI policy.
    pub ui: UiPolicy,
    /// Whether the caller supplied a `ui` block on the wire (any field
    /// present), captured at parse time. The twin of `network_specified`, and
    /// necessary for the same reason: `UiPolicy::default()` is full lockdown,
    /// so an absent `ui` and an explicitly-supplied lockdown `ui` are
    /// indistinguishable from the other fields here. Parse-derived, never on
    /// the wire.
    ///
    /// Consumed only by IsolationSession today, which has no UI-restriction
    /// primitive and refuses a supplied UI policy rather than accepting and
    /// dropping it. The other backends that do not enforce `policy.ui` — LXC
    /// and Bubblewrap on Linux, Seatbelt on macOS, Windows Sandbox — still
    /// accept and ignore it, so this flag being set does not mean a UI policy
    /// was honored anywhere; it means only that the caller supplied one.
    #[serde(skip)]
    pub ui_specified: bool,
    /// BaseProcessContainer-specific UI config (Windows only, from processContainer.ui).
    pub base_process_ui: BaseProcessUiConfig,
    /// Windows denial capture (from `processContainer.captureDenials`). When
    /// `Some`, the runner records the sandboxed process's ungranted access
    /// attempts to a learning-mode ETL trace. `None` disables capture.
    pub capture_denials: Option<CaptureDenialsConfig>,
}

/// Do the host lists refine the default egress policy (i.e. require per-host
/// filtering)? Only the list that can tighten the default matters:
/// `Block` → allowlist; `Allow` → blocklist. Shared by the config parser and
/// the WSLc backend so both agree on what "host filtering" means.
pub fn needs_host_filtering(
    is_default_block: bool,
    allowed_hosts: &[String],
    blocked_hosts: &[String],
) -> bool {
    if is_default_block {
        !allowed_hosts.is_empty()
    } else {
        !blocked_hosts.is_empty()
    }
}

impl ContainerPolicy {
    /// True when this policy's host lists require per-host egress filtering.
    pub fn needs_host_filtering(&self) -> bool {
        needs_host_filtering(
            self.default_network_policy == NetworkPolicy::Block,
            &self.allowed_hosts,
            &self.blocked_hosts,
        )
    }
}

/// Windows denial-capture settings (from `processContainer.captureDenials`).
/// The presence of this struct on [`ContainerPolicy::capture_denials`] enables
/// capture; the runner records the sandboxed process's ungranted access
/// attempts to a learning-mode ETL trace. [`CaptureDenialsConfig::mode`]
/// decides whether each recorded access is blocked (default) or allowed.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct CaptureDenialsConfig {
    /// How each ungranted access check is handled while it is recorded.
    /// Defaults to [`CaptureDenialsMode::Block`].
    pub mode: CaptureDenialsMode,
    /// Absolute path where the JSON denials output file is written. This is the
    /// application-facing deliverable, not the runner-managed intermediate ETL.
    /// The runner inserts a per-run identifier into the file stem (`denials.json` ->
    /// `denials.<run-id>.json`) so concurrent and sequential captures don't
    /// collide, and reports the actual path on stderr. When `None`, the runner
    /// falls back to a managed per-run temporary file and prints its path on
    /// stderr.
    pub output_path: Option<String>,
    /// Whether to preserve the sealed ETL trace after analysis. Defaults to
    /// `false`, which deletes the internal trace. Retention is honored only by
    /// a terminal wait that leaves structured output observable; abandoning the
    /// process handle deletes the trace.
    pub retain_etl: bool,
}

/// How `captureDenials` handles each ungranted access check while recording it.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub enum CaptureDenialsMode {
    /// The access stays denied and the denial is recorded; deny-by-default
    /// containment is preserved. Safe default.
    #[default]
    Block,
    /// The access is allowed and recorded (audit mode); deny-by-default is
    /// relaxed for the run. Security-sensitive — the runner warns.
    Allow,
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
    /// Telemetry configuration (experimental).
    pub telemetry: Option<TelemetryConfig>,
}

/// Telemetry configuration parsed from the JSON config `experimental.telemetry` section.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct TelemetryConfig {
    /// Explicit telemetry override.
    /// `Some(true)` = force on, `Some(false)` = force off, `None` = disabled (default off).
    pub enabled: Option<bool>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct ExecutionRequest {
    /// Schema version for the config format.
    pub schema_version: String,
    /// Externally assigned container identifier.
    pub container_id: String,
    /// Environment variables as "KEY=VALUE" strings (from process.env).
    pub env: Vec<String>,
    pub script_code: String,
    pub working_directory: String,
    pub script_timeout: u32,
    /// Which containment backend to use. Default: ProcessContainer.
    pub containment: ContainmentBackend,
    /// Shared lifecycle settings.
    pub lifecycle: LifecycleConfig,
    /// ProcessContainer-specific policy (used when containment == ProcessContainer).
    pub policy: ContainerPolicy,
    /// LXC-specific configuration (used when containment == Lxc).
    pub lxc_config: LxcConfig,
    /// Seatbelt (macOS) backend configuration (used when containment == Seatbelt).
    pub seatbelt: Option<SeatbeltConfig>,
    /// Whether the --experimental flag was passed.
    pub experimental_enabled: bool,
    /// Whether the --allow-testing-features flag was passed. Gates testing-only,
    /// deliberately-permissive helpers (currently `network.proxy.builtinTestServer`)
    /// that must never activate from a stock production config. This is a distinct
    /// axis from `experimental_enabled`: "experimental" means unstable/new, whereas
    /// this means "not-for-production testing scaffolding".
    pub testing_features_enabled: bool,
    /// Experimental feature configs (only applied when experimental_enabled is true).
    pub experimental: ExperimentalConfig,
    /// Dry-run mode: validate config and runner setup then return success
    /// without executing the sandboxed process.
    pub dry_run: bool,
}

/// Where a [`ResolvedWorkingDirectory`] came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WorkingDirectorySource {
    /// The caller's explicit `process.cwd`.
    Explicit,
    /// Derived from the filesystem policy because `process.cwd` was omitted.
    Policy,
}

/// The working directory a backend should launch the sandboxed child in,
/// together with where it came from (for logging and error context).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ResolvedWorkingDirectory<'a> {
    /// The selected directory. Never empty.
    pub path: &'a str,
    /// Whether `path` is the caller's `process.cwd` or a policy fallback.
    pub source: WorkingDirectorySource,
}

impl ExecutionRequest {
    /// Resolve the working directory for the sandboxed child: an explicit
    /// `working_directory`, else the first filesystem-policy grant that is an
    /// existing directory (`readwrite` paths before `readonly` ones), else
    /// `None`.
    ///
    /// Backends that must not let the child inherit the host process's cwd use
    /// this to fall back to a policy-granted path. It matters most on Windows:
    /// a `NULL` current directory makes `CreateProcessW` inherit the parent's
    /// cwd, and when the AppContainer token can't open it the kernel silently
    /// resets the child to the drive root (`C:\`) instead of failing the launch.
    ///
    /// Policy grants may name individual *files* or directories that do not
    /// exist yet, neither of which a process can be launched in, so only
    /// existing directories are considered. An explicit `working_directory` is
    /// returned unchecked — the caller asked for it, so a bad one must fail the
    /// launch loudly rather than be silently replaced.
    ///
    /// Callers whose policy paths need normalizing before they can be probed
    /// (e.g. Seatbelt's `~` expansion) should use
    /// [`ExecutionRequest::resolved_working_directory_with`].
    pub fn resolved_working_directory(&self) -> Option<ResolvedWorkingDirectory<'_>> {
        self.resolved_working_directory_with(|path| std::path::Path::new(path).is_dir())
    }

    /// [`ExecutionRequest::resolved_working_directory`] with an injectable
    /// "is this an existing directory?" probe, so backends can normalize a
    /// policy path before testing it and unit tests can run without touching
    /// the filesystem. The returned path is always the *unnormalized* policy
    /// entry; normalize it again if `is_dir` did.
    pub fn resolved_working_directory_with(
        &self,
        is_dir: impl Fn(&str) -> bool,
    ) -> Option<ResolvedWorkingDirectory<'_>> {
        if !self.working_directory.trim().is_empty() {
            return Some(ResolvedWorkingDirectory {
                path: self.working_directory.as_str(),
                source: WorkingDirectorySource::Explicit,
            });
        }
        self.policy
            .readwrite_paths
            .iter()
            .chain(self.policy.readonly_paths.iter())
            .map(String::as_str)
            .filter(|path| !path.trim().is_empty())
            .find(|path| is_dir(path))
            .map(|path| ResolvedWorkingDirectory {
                path,
                source: WorkingDirectorySource::Policy,
            })
    }
}

/// Distinguishes whether an error occurred during process creation (launch)
/// or after the process started but exited with a failure code.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub enum FailurePhase {
    /// No failure (process exited successfully, or has not been evaluated yet).
    #[default]
    None,
    /// The launch attempt failed: the CreateProcess (or equivalent) API call,
    /// the VM/sandbox bring-up, or a transient resource contention (e.g. a
    /// single-instance backend already running). Generally worth retrying.
    LaunchFailed,
    /// The request cannot be honored and will not succeed on a blind retry
    /// without changing the input or host: a policy rejection, or a missing
    /// host prerequisite (backend/runtime not installed).
    Rejected,
    /// The launch command succeeded but the guest/sandbox infrastructure failed
    /// before or while running user code (agent rendezvous, channel connect, or
    /// the execution relay) — i.e. the process never ran to a clean exit.
    PostLaunchFailed,
    /// The process was created and ran, but exited with a non-zero code.
    ProcessExited,
    /// The process was force-terminated because it exceeded `scriptTimeout`.
    /// Distinct from [`ProcessExited`] (it did not exit on its own) so callers
    /// can detect a timeout uniformly across backends rather than inferring it
    /// from `exit_code == -1` (which collides with other failures).
    Timeout,
    /// The selected containment backend is unavailable on this host: the API is
    /// missing, or present but not usable (e.g. feature-disabled). Distinct from
    /// [`LaunchFailed`] so callers can fall back to a lower tier rather than
    /// hard-fail.
    BackendUnavailable,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct ScriptResponse {
    pub exit_code: i32,
    pub standard_out: String,
    pub standard_err: String,
    pub error_message: String,
    /// Raw system/API error detail intended for developers and diagnostics
    /// (e.g. "Experimental_CreateProcessInSandbox failed: WIN32_ERROR(1920)").
    /// Kept separate from `error_message` which holds user-friendly text.
    #[serde(skip_serializing_if = "String::is_empty")]
    pub extended_error: String,
    /// Indicates at what phase the failure occurred.
    #[serde(default)]
    pub failure_phase: FailurePhase,
    /// Structured metadata produced after the sandboxed process exits.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub output_metadata: Option<Box<SandboxOutputMetadata>>,
}

impl Default for ScriptResponse {
    fn default() -> Self {
        Self {
            exit_code: -1,
            standard_out: String::new(),
            standard_err: String::new(),
            error_message: String::new(),
            extended_error: String::new(),
            failure_phase: FailurePhase::None,
            output_metadata: None,
        }
    }
}

/// Structured outputs produced by optional sandbox features.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SandboxOutputMetadata {
    /// Location and summary of a captureDenials output document.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub capture_denials: Option<CaptureDenialsOutput>,
    /// Failure details and retained ETL location when capture finalization fails.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub capture_denials_error: Option<CaptureDenialsErrorOutput>,
}

/// Structured diagnostics for a failed captureDenials finalization.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CaptureDenialsErrorOutput {
    /// Human-readable finalization failure.
    pub message: String,
    /// Absolute path to the retained ETL trace.
    pub etl_path: String,
}

/// Location and summary of a captureDenials output document.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CaptureDenialsOutput {
    /// Discriminator used by line-oriented CLI consumers.
    #[serde(rename = "type")]
    pub kind: String,
    /// Absolute path to the JSON denials output file.
    pub output_path: String,
    /// Exit code of the sandboxed child.
    pub exit_code: i32,
    /// Count of unique denials written.
    pub total_denials: usize,
    /// Whether the emitted denial set was truncated.
    pub denied_resources_truncated: bool,
    /// Absolute path to the retained ETL trace, when retention was requested.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub etl_path: Option<String>,
}

impl CaptureDenialsOutput {
    /// The fixed `type` discriminator value.
    pub const KIND: &'static str = "captureDenials";
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

    #[test]
    fn directional_network_defaults_deny() {
        assert_eq!(NetworkAction::default(), NetworkAction::Deny);

        let egress = NetworkEgressPolicy::default();
        assert_eq!(egress.default, NetworkAction::Deny);
        assert!(egress.allow.is_empty());
        assert!(egress.deny.is_empty());

        let ingress = NetworkIngressPolicy::default();
        assert_eq!(ingress.default, NetworkAction::Deny);
        assert_eq!(ingress.host_loopback, NetworkAction::Deny);
    }

    fn request_with_paths(readwrite: &[&str], readonly: &[&str]) -> ExecutionRequest {
        ExecutionRequest {
            policy: ContainerPolicy {
                readwrite_paths: readwrite.iter().map(|s| s.to_string()).collect(),
                readonly_paths: readonly.iter().map(|s| s.to_string()).collect(),
                ..Default::default()
            },
            ..Default::default()
        }
    }

    /// Resolve against a fake filesystem: every path in `dirs` is an existing
    /// directory, everything else is not (a file, or nonexistent).
    fn resolve<'a>(
        req: &'a ExecutionRequest,
        dirs: &'a [&'a str],
    ) -> Option<ResolvedWorkingDirectory<'a>> {
        req.resolved_working_directory_with(|path| dirs.contains(&path))
    }

    #[test]
    fn resolved_working_directory_prefers_explicit_value() {
        let mut req = request_with_paths(&["C:\\rw"], &["C:\\ro"]);
        req.working_directory = "C:\\explicit".to_string();
        let resolved = resolve(&req, &["C:\\rw", "C:\\ro"]).expect("explicit cwd");
        assert_eq!(resolved.path, "C:\\explicit");
        assert_eq!(resolved.source, WorkingDirectorySource::Explicit);
    }

    /// An explicit cwd is the caller's own choice, so it is returned unchecked
    /// rather than silently swapped for a policy path when it does not exist.
    #[test]
    fn resolved_working_directory_returns_explicit_value_unchecked() {
        let mut req = request_with_paths(&["C:\\rw"], &[]);
        req.working_directory = "C:\\does-not-exist".to_string();
        let resolved = resolve(&req, &["C:\\rw"]).expect("explicit cwd");
        assert_eq!(resolved.path, "C:\\does-not-exist");
        assert_eq!(resolved.source, WorkingDirectorySource::Explicit);
    }

    #[test]
    fn resolved_working_directory_falls_back_to_first_readwrite() {
        let req = request_with_paths(&["C:\\rw1", "C:\\rw2"], &["C:\\ro"]);
        let resolved = resolve(&req, &["C:\\rw1", "C:\\rw2", "C:\\ro"]).expect("policy path");
        assert_eq!(resolved.path, "C:\\rw1");
        assert_eq!(resolved.source, WorkingDirectorySource::Policy);
    }

    #[test]
    fn resolved_working_directory_falls_back_to_first_readonly() {
        let req = request_with_paths(&[], &["C:\\ro1", "C:\\ro2"]);
        let resolved = resolve(&req, &["C:\\ro1", "C:\\ro2"]).expect("policy path");
        assert_eq!(resolved.path, "C:\\ro1");
        assert_eq!(resolved.source, WorkingDirectorySource::Policy);
    }

    #[test]
    fn resolved_working_directory_none_when_no_dir_and_no_paths() {
        let req = request_with_paths(&[], &[]);
        assert_eq!(resolve(&req, &[]), None);
    }

    /// Policy grants may name individual files; `CreateProcessW` fails with
    /// `ERROR_DIRECTORY` on one, so files must be skipped.
    #[test]
    fn resolved_working_directory_skips_policy_files() {
        let req = request_with_paths(&["C:\\inputs\\config.json", "C:\\workspace"], &[]);
        let resolved = resolve(&req, &["C:\\workspace"]).expect("policy path");
        assert_eq!(resolved.path, "C:\\workspace");
    }

    /// A grant for a directory the caller intends to create later must not be
    /// used as the cwd — the launch would fail before it could be created.
    #[test]
    fn resolved_working_directory_skips_nonexistent_policy_paths() {
        let req = request_with_paths(&["C:\\not-yet"], &["C:\\ro"]);
        let resolved = resolve(&req, &["C:\\ro"]).expect("policy path");
        assert_eq!(resolved.path, "C:\\ro");
    }

    #[test]
    fn resolved_working_directory_skips_blank_entries() {
        let req = request_with_paths(&["", "   "], &[]);
        assert_eq!(resolve(&req, &["", "   "]), None);
    }

    /// A whitespace-only `process.cwd` is not a caller choice; fall through to
    /// the policy rather than treating it as an explicit directory.
    #[test]
    fn resolved_working_directory_ignores_blank_explicit_value() {
        let mut req = request_with_paths(&["C:\\rw"], &[]);
        req.working_directory = "   ".to_string();
        let resolved = resolve(&req, &["C:\\rw"]).expect("policy path");
        assert_eq!(resolved.path, "C:\\rw");
        assert_eq!(resolved.source, WorkingDirectorySource::Policy);
    }

    #[test]
    fn resolved_working_directory_none_when_no_policy_path_is_a_directory() {
        let req = request_with_paths(&["C:\\a.txt"], &["C:\\b.txt"]);
        assert_eq!(resolve(&req, &[]), None);
    }

    /// Covers the real (non-injected) filesystem probe used in production.
    #[test]
    fn resolved_working_directory_probes_the_real_filesystem() {
        let temp_dir = std::env::temp_dir().to_string_lossy().into_owned();
        let missing = std::env::temp_dir()
            .join("mxc-resolver-nonexistent-4f1c9a")
            .to_string_lossy()
            .into_owned();
        let req = request_with_paths(&[&missing], &[&temp_dir]);
        let resolved = req.resolved_working_directory().expect("policy path");
        assert_eq!(resolved.path, temp_dir);
        assert_eq!(resolved.source, WorkingDirectorySource::Policy);
    }

    #[test]
    fn script_response_backend_unavailable_round_trips() {
        let r = ScriptResponse {
            failure_phase: FailurePhase::BackendUnavailable,
            ..Default::default()
        };
        let json = serde_json::to_string(&r).unwrap();
        let back: ScriptResponse = serde_json::from_str(&json).unwrap();
        assert_eq!(back.failure_phase, FailurePhase::BackendUnavailable);
        // An omitted failure_phase still defaults to None.
        let defaulted: ScriptResponse = serde_json::from_str("{}").unwrap();
        assert_eq!(defaulted.failure_phase, FailurePhase::None);
    }

    #[test]
    fn failure_phase_serde_round_trips_all_variants() {
        let cases = [
            (FailurePhase::None, "\"None\""),
            (FailurePhase::LaunchFailed, "\"LaunchFailed\""),
            (FailurePhase::Rejected, "\"Rejected\""),
            (FailurePhase::PostLaunchFailed, "\"PostLaunchFailed\""),
            (FailurePhase::ProcessExited, "\"ProcessExited\""),
            (FailurePhase::Timeout, "\"Timeout\""),
            (FailurePhase::BackendUnavailable, "\"BackendUnavailable\""),
        ];
        for (variant, wire) in cases {
            let s = serde_json::to_string(&variant).unwrap();
            assert_eq!(s, wire, "serialize {variant:?}");
            let back: FailurePhase = serde_json::from_str(wire).unwrap();
            assert_eq!(back, variant, "round-trip {wire}");
        }
    }
    #[test]
    fn capture_denials_output_omits_unretained_etl_path() {
        let output = CaptureDenialsOutput {
            kind: CaptureDenialsOutput::KIND.to_string(),
            output_path: "denials.json".to_string(),
            exit_code: 0,
            total_denials: 1,
            denied_resources_truncated: false,
            etl_path: None,
        };

        let value = serde_json::to_value(output).unwrap();
        assert!(value.get("etlPath").is_none());
    }

    #[test]
    fn capture_denials_output_serializes_retained_etl_path() {
        let output = CaptureDenialsOutput {
            kind: CaptureDenialsOutput::KIND.to_string(),
            output_path: "denials.json".to_string(),
            exit_code: 0,
            total_denials: 1,
            denied_resources_truncated: false,
            etl_path: Some("capture.etl".to_string()),
        };

        let value = serde_json::to_value(output).unwrap();
        assert_eq!(value["etlPath"], "capture.etl");
    }

    #[test]
    fn capture_denials_error_serializes_retained_etl_path() {
        let metadata = SandboxOutputMetadata {
            capture_denials: None,
            capture_denials_error: Some(CaptureDenialsErrorOutput {
                message: "decode failed".to_string(),
                etl_path: "capture.etl".to_string(),
            }),
        };

        let value = serde_json::to_value(metadata).expect("serialize metadata");
        assert_eq!(value["captureDenialsError"]["message"], "decode failed");
        assert_eq!(value["captureDenialsError"]["etlPath"], "capture.etl");
    }
}
