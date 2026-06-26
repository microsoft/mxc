// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Dedicated, well-typed wire model — the single source of truth for the MXC
//! config shape. The JSON Schema (`schemas/dev/mxc-config.schema.<dev>.json`) is
//! **generated** from these types via `mxc_schema_gen`; CI fails if the
//! committed schema drifts (see `scripts/versioning/check-schema-codegen.js`).
//!
//! These types describe the config *contract* precisely:
//!
//! * real `enum`s for closed value sets (`Containment`, `NetworkPolicy`, …)
//!   instead of `Option<String>`,
//! * `#[serde(rename_all = "camelCase")]` so field names match the wire without
//!   per-field `#[serde(rename)]` noise,
//! * `#[serde(deny_unknown_fields)]` on the **stable** surface so the generated
//!   schema is closed (`additionalProperties: false`); the `experimental` block
//!   is intentionally left permissive (in-flux features),
//! * `///` doc-comments that schemars turns into schema `description`s.
//!
//! These types are the parser's actual deserialization target: `serde_json`
//! deserializes JSON into them, then `config_parser` maps them to the domain
//! `ExecutionRequest` / state-aware request. The `JsonSchema` derive is gated
//! behind the `schema-gen` feature so normal builds don't carry `schemars`; the
//! schema generator (`mxc_schema_gen`) enables it.
//!
//! Cross-field constraints (single-backend-section, phase-scoping) are NOT
//! expressed in the generated schema; they are enforced by the parser, which is
//! the trust boundary. The schema is an editor/CI convenience, never the gate.

use serde::{Deserialize, Serialize};

/// MXC container execution configuration. Defines the recommended config format
/// for both one-shot and state-aware sandbox lifecycle requests. A few
/// deprecated field spellings not listed here are also accepted via serde aliases.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "schema-gen", derive(schemars::JsonSchema))]
#[cfg_attr(feature = "schema-gen", schemars(title = "MXC Configuration"))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MxcConfig {
    /// Optional JSON Schema reference for editor validation. Accepted but
    /// ignored by the parser.
    #[serde(rename = "$schema")]
    pub schema: Option<String>,

    /// Optional human-readable annotation. Accepted but ignored by the parser.
    #[serde(rename = "_comment")]
    pub comment: Option<serde_json::Value>,

    /// MXC config schema version (semver), e.g. `"0.8.0-alpha"`.
    pub version: Option<String>,

    /// State-aware lifecycle phase. When present, the request is a state-aware
    /// request (`sandboxId` is required for non-provision phases); when absent,
    /// the request is one-shot.
    pub phase: Option<Phase>,

    /// Sandbox identifier returned by a prior provision request. Required for
    /// non-provision state-aware phases.
    pub sandbox_id: Option<String>,

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
    #[serde(alias = "appContainer")]
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
    #[serde(alias = "macos_sandbox")]
    pub seatbelt: Option<Seatbelt>,

    /// Experimental features. Only honored when `--experimental` is passed.
    pub experimental: Option<Experimental>,
}

/// State-aware lifecycle phase.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "schema-gen", derive(schemars::JsonSchema))]
#[serde(rename_all = "lowercase")]
pub enum Phase {
    Provision,
    Start,
    Exec,
    Stop,
    Deprovision,
}

/// Containment backend (abstract intent or concrete backend).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "schema-gen", derive(schemars::JsonSchema))]
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
    /// WSL container (experimental).
    Wslc,
    /// macOS Seatbelt.
    #[serde(alias = "macos_sandbox")]
    Seatbelt,
    /// Windows IsolationSession (experimental).
    IsolationSession,
    /// Unprivileged Linux bubblewrap sandbox.
    Bubblewrap,
}

/// Process execution settings.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "schema-gen", derive(schemars::JsonSchema))]
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
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "schema-gen", derive(schemars::JsonSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Lifecycle {
    /// Destroy the container when the process exits (default true).
    pub destroy_on_exit: Option<bool>,
    /// Preserve the applied policy after exit (default false).
    pub preserve_policy: Option<bool>,
}

/// ProcessContainer-specific settings.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "schema-gen", derive(schemars::JsonSchema))]
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
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "schema-gen", derive(schemars::JsonSchema))]
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
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "schema-gen", derive(schemars::JsonSchema))]
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
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "schema-gen", derive(schemars::JsonSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Lxc {
    /// Distribution image (e.g. `alpine`).
    pub distribution: Option<String>,
    /// Distribution release (e.g. `3.23`).
    pub release: Option<String>,
}

/// Filesystem access policy.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "schema-gen", derive(schemars::JsonSchema))]
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
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "schema-gen", derive(schemars::JsonSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Fallback {
    /// Allow the runner to mutate DACLs as a fallback.
    pub allow_dacl_mutation: Option<bool>,
}

/// Network access policy.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "schema-gen", derive(schemars::JsonSchema))]
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
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "schema-gen", derive(schemars::JsonSchema))]
#[serde(rename_all = "lowercase")]
pub enum NetworkPolicy {
    Allow,
    Block,
}

/// Network enforcement mechanism.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "schema-gen", derive(schemars::JsonSchema))]
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
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "schema-gen", derive(schemars::JsonSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Proxy {
    /// External localhost proxy port.
    #[cfg_attr(feature = "schema-gen", schemars(range(min = 1, max = 65535)))]
    pub localhost: Option<u16>,
    /// Have wxc launch its own built-in test proxy.
    pub builtin_test_server: Option<bool>,
    /// Proxy URL (parsed into host:port).
    pub url: Option<String>,
}

/// Cross-platform UI isolation policy.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "schema-gen", derive(schemars::JsonSchema))]
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
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "schema-gen", derive(schemars::JsonSchema))]
#[serde(rename_all = "lowercase")]
pub enum ClipboardPolicy {
    None,
    Read,
    Write,
    All,
}

/// macOS Seatbelt backend configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "schema-gen", derive(schemars::JsonSchema))]
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
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "schema-gen", derive(schemars::JsonSchema))]
#[serde(rename_all = "lowercase")]
pub enum LaunchMethod {
    /// sandbox_init() + exec (default). Works for third-party GUI apps.
    Exec,
    /// Launch via macOS LaunchServices (`open`), then apply the sandbox to the
    /// inner shell via sandbox-exec. Required for apps with launch constraints.
    Open,
}

/// Experimental features (only honored with `--experimental`). This block is
/// intentionally **permissive** (no `deny_unknown_fields`): experimental
/// backends are in flux, so the schema documents the known shapes for editor
/// help without rejecting in-progress fields. The strict, closed contract is
/// the stable (top-level) surface.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "schema-gen", derive(schemars::JsonSchema))]
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
    #[serde(alias = "macos_sandbox")]
    pub seatbelt: Option<Seatbelt>,
}

/// Placeholder experimental feature.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "schema-gen", derive(schemars::JsonSchema))]
#[serde(rename_all = "camelCase")]
pub struct TestFeature {
    /// Message to log when the feature is applied.
    pub message: Option<String>,
}

/// Windows Sandbox backend config.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "schema-gen", derive(schemars::JsonSchema))]
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
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "schema-gen", derive(schemars::JsonSchema))]
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
    /// Host → container port forwards. Only TCP is currently supported by the
    /// vendored WSLC SDK runtime (Microsoft.WSL.Containers 2.8.1); the parser
    /// rejects `udp` because the shipped runtime returns `E_NOTIMPL`.
    pub port_mappings: Option<Vec<PortMapping>>,
}

/// A single host → container port forward. Reachable only under the permissive
/// `experimental` surface, so unknown fields are tolerated (forward-compat).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "schema-gen", derive(schemars::JsonSchema))]
#[serde(rename_all = "camelCase")]
pub struct PortMapping {
    /// Host (Windows) port.
    #[cfg_attr(feature = "schema-gen", schemars(range(min = 1, max = 65535)))]
    pub windows_port: u16,
    /// Container port.
    #[cfg_attr(feature = "schema-gen", schemars(range(min = 1, max = 65535)))]
    pub container_port: u16,
    /// Transport protocol for the mapping. Only `tcp` is currently supported.
    pub protocol: Option<TransportProtocol>,
}

/// Port-forward transport protocol. Only `tcp` is currently supported by the
/// vendored WSLC SDK runtime; `udp` is rejected at parse time.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "schema-gen", derive(schemars::JsonSchema))]
#[serde(rename_all = "lowercase")]
pub enum TransportProtocol {
    Tcp,
}

/// IsolationSession backend config. Carries both the one-shot fields
/// (`configurationId`, `user`) and the per-phase state-aware nesting
/// (`provision` / `start` / `stop` / `deprovision`).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "schema-gen", derive(schemars::JsonSchema))]
#[serde(rename_all = "camelCase")]
pub struct IsolationSession {
    /// Sizing profile (one-shot).
    pub configuration_id: Option<IsolationConfigurationId>,
    /// Optional Entra cloud-agent user bundle (one-shot).
    pub user: Option<IsolationUser>,
    /// State-aware provision-phase configuration.
    pub provision: Option<IsolationSessionPhase>,
    /// State-aware start-phase configuration.
    pub start: Option<IsolationSessionPhase>,
    /// State-aware stop-phase configuration.
    pub stop: Option<IsolationSessionPhase>,
    /// State-aware deprovision-phase configuration.
    pub deprovision: Option<IsolationSessionPhase>,
}

/// Per-phase IsolationSession configuration (state-aware lifecycle).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "schema-gen", derive(schemars::JsonSchema))]
#[serde(rename_all = "camelCase")]
pub struct IsolationSessionPhase {
    /// Sizing profile for this phase.
    pub configuration_id: Option<IsolationConfigurationId>,
    /// Entra cloud-agent user bundle for this phase.
    pub user: Option<IsolationUser>,
}

/// IsolationSession sizing profile.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "schema-gen", derive(schemars::JsonSchema))]
#[serde(rename_all = "lowercase")]
pub enum IsolationConfigurationId {
    Small,
    Medium,
    Large,
    Composable,
}

/// Entra cloud-agent user bundle. Reachable only under the permissive
/// `experimental` surface, so unknown fields are tolerated (forward-compat).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "schema-gen", derive(schemars::JsonSchema))]
#[serde(rename_all = "camelCase")]
pub struct IsolationUser {
    /// User principal name.
    pub upn: String,
    /// Short-lived WAM bearer token (passed verbatim to the OS service).
    pub wam_token: String,
}

/// JSON Schema generation from the wire model, gated behind `schema-gen` so
/// production builds don't carry `schemars`. The single public entry point is
/// re-exported below as `generate_config_schema_json`.
#[cfg(feature = "schema-gen")]
mod schema_gen {
    use super::MxcConfig;

    /// Canonical `$id` for the generated dev schema. Bump alongside the dev schema
    /// version/filename (see `schemas/schema-version.json`).
    const SCHEMA_ID: &str =
        "https://github.com/microsoft/mxc/schemas/dev/mxc-config.schema.0.8.0-dev.json";

    /// Generate the JSON Schema for the MXC config from the dedicated `MxcConfig`
    /// model. The schema is post-processed to (a) inject the canonical `$id`,
    /// (b) replace schemars' Rust-specific integer `format` strings (`uint32`,
    /// `int64`, …) — which JSON Schema draft-07 does not define — with standard
    /// constraints (`minimum: 0` for unsigned), so the committed artifact validates
    /// cleanly under standard tooling, and (c) emit the root metadata keys
    /// (`$schema`, `$id`, `title`, `description`) first for readability. `title` and
    /// `description` come from the `MxcConfig` schemars attribute / doc comment
    /// respectively.
    pub fn generate_config_schema_json() -> String {
        let schema = schemars::schema_for!(MxcConfig);
        let mut value = serde_json::to_value(&schema).expect("schema serialises to JSON value");
        normalize_integer_formats(&mut value);
        if let serde_json::Value::Object(map) = &mut value {
            map.insert(
                "$id".to_string(),
                serde_json::Value::String(SCHEMA_ID.to_string()),
            );
            return render_root_ordered(map);
        }
        serde_json::to_string_pretty(&value).expect("schema serialises to JSON")
    }

    /// Render the root object as pretty JSON with a fixed key order — the schema
    /// metadata (`$schema`, `$id`, `title`, `description`) first, then the
    /// structural keys — without disturbing nested key order.
    ///
    /// `serde_json`'s default `Map` is a `BTreeMap`, so it emits every object's keys
    /// alphabetically and gives no control over root order. Rather than switch the
    /// whole crate to `preserve_order` (which would reorder every nested object too),
    /// only the root is rendered here: each value is pretty-printed with the standard
    /// serializer (so nested objects stay alphabetical, byte-for-byte as before) and
    /// re-indented one level. Any key not in `ORDER` keeps its alphabetical position
    /// after the listed ones.
    fn render_root_ordered(map: &serde_json::Map<String, serde_json::Value>) -> String {
        // Only the metadata keys are floated to the front; every other key keeps its
        // natural (alphabetical) position, so the rest of the file is unchanged.
        const ORDER: &[&str] = &["$schema", "$id", "title", "description"];
        let rank = |key: &str| ORDER.iter().position(|k| *k == key).unwrap_or(ORDER.len());

        // `map` is a BTreeMap, so `keys()` is already alphabetical; a stable sort by
        // rank floats the listed keys to the front and leaves the rest alphabetical.
        let mut keys: Vec<&String> = map.keys().collect();
        keys.sort_by_key(|k| rank(k));

        let mut out = String::from("{\n");
        for (i, key) in keys.iter().enumerate() {
            let value_pretty =
                serde_json::to_string_pretty(&map[*key]).expect("schema value serialises to JSON");
            // The value sits one level deep: keep its first line in place after the
            // key, and indent every following line by two spaces.
            let mut lines = value_pretty.lines();
            let mut indented = lines.next().unwrap_or("").to_string();
            for line in lines {
                indented.push_str("\n  ");
                indented.push_str(line);
            }
            let key_json = serde_json::to_string(key).expect("object key serialises to JSON");
            out.push_str("  ");
            out.push_str(&key_json);
            out.push_str(": ");
            out.push_str(&indented);
            if i + 1 < keys.len() {
                out.push(',');
            }
            out.push('\n');
        }
        out.push('}');
        out
    }

    /// Recursively rewrite non-standard schemars integer `format`s into draft-07
    /// constructs: unsigned types (`uint*`) gain `minimum: 0` and drop `format`;
    /// signed types (`int*`) just drop `format`. Standard string formats
    /// (`date-time`, `uri`, …) are left untouched.
    fn normalize_integer_formats(value: &mut serde_json::Value) {
        use serde_json::Value;
        match value {
            Value::Object(map) => {
                if let Some(Value::String(fmt)) = map.get("format") {
                    let fmt = fmt.clone();
                    let is_unsigned = fmt.starts_with("uint");
                    let is_signed = fmt.starts_with("int");
                    if is_unsigned || is_signed {
                        map.remove("format");
                        if is_unsigned {
                            map.entry("minimum").or_insert(Value::Number(0.into()));
                        }
                    }
                }
                for v in map.values_mut() {
                    normalize_integer_formats(v);
                }
            }
            Value::Array(items) => {
                for v in items {
                    normalize_integer_formats(v);
                }
            }
            _ => {}
        }
    }
}

#[cfg(feature = "schema-gen")]
pub use schema_gen::generate_config_schema_json;
