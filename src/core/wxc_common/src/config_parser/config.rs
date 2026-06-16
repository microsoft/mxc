// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Typed wire config — the public face of the SDK's `ContainerConfig`.
//!
//! [`Config`] mirrors the wire-format `ContainerConfig` as a clean,
//! constructible Rust type. It is the typed input to the `mxc` library: build
//! one programmatically, then convert it straight to an [`ExecutionRequest`]
//! via [`execution_request_from_config`] — no JSON anywhere.
//!
//! It maps 1:1 onto the crate-internal parse representation and reuses the same
//! validation/wire→model conversion the executor binaries use, so behaviour
//! matches production. There is deliberately no JSON (de)serialisation here:
//! callers that hold wire JSON parse it through the normal config parser
//! instead. Only the fields the supported backends use are modelled.

use super::{
    convert_raw_config_inner, RawBaseProcessUi, RawConfig, RawFallback, RawFilesystem,
    RawLifecycle, RawNetwork, RawProcess, RawProcessContainer, RawSeatbelt, RawUi,
};
use crate::error::WxcError;
use crate::logger::Logger;
use crate::models::{ExecutionRequest, LaunchMethod};

/// Typed mirror of the SDK wire-format `ContainerConfig`.
#[derive(Debug, Clone, Default)]
pub struct Config {
    /// Schema version (e.g. `"0.7.0-alpha"`). Required by the parser.
    pub version: Option<String>,
    /// Externally-assigned container identifier.
    pub container_id: Option<String>,
    /// Containment backend wire name (`"seatbelt"`, `"bubblewrap"`,
    /// `"processcontainer"`, …). When omitted the host default is used.
    pub containment: Option<String>,
    pub process: Option<ProcessConfig>,
    pub filesystem: Option<FilesystemConfig>,
    pub network: Option<NetworkConfig>,
    pub ui: Option<UiConfig>,
    pub lifecycle: Option<LifecycleConfig>,
    /// Seatbelt (macOS) backend configuration.
    pub seatbelt: Option<SeatbeltConfig>,
    /// ProcessContainer (Windows) backend configuration.
    pub process_container: Option<ProcessContainerConfig>,
    /// AppContainer DACL-fallback knob (Windows).
    pub fallback: Option<FallbackConfig>,
}

/// Process section: the command to run and its environment.
#[derive(Debug, Clone, Default)]
pub struct ProcessConfig {
    pub command_line: Option<String>,
    pub cwd: Option<String>,
    /// Environment entries as `KEY=VALUE` strings.
    pub env: Option<Vec<String>>,
    /// Execution timeout in milliseconds (`0` / `None` = no timeout).
    pub timeout: Option<u32>,
}

/// Filesystem section: paths exposed to the sandbox.
#[derive(Debug, Clone, Default)]
pub struct FilesystemConfig {
    pub readwrite_paths: Option<Vec<String>>,
    pub readonly_paths: Option<Vec<String>>,
    pub denied_paths: Option<Vec<String>>,
}

/// Network section.
#[derive(Debug, Clone, Default)]
pub struct NetworkConfig {
    /// `"allow"` or `"block"`.
    pub default_policy: Option<String>,
    pub enforcement_mode: Option<String>,
    pub allow_local_network: Option<bool>,
    pub allowed_hosts: Option<Vec<String>>,
    pub blocked_hosts: Option<Vec<String>>,
    /// Proxy union (`{ builtinTestServer: true } | { localhost: u16 } | { url:
    /// string }`), kept as raw JSON so the shape is preserved verbatim.
    pub proxy: Option<serde_json::Value>,
}

/// UI section.
#[derive(Debug, Clone, Default)]
pub struct UiConfig {
    /// Disable windowing entirely.
    pub disable: Option<bool>,
    /// Clipboard access level (`"none" | "read" | "write" | "all"`).
    pub clipboard: Option<String>,
    /// Allow input injection.
    pub injection: Option<bool>,
}

/// Lifecycle section.
#[derive(Debug, Clone, Default)]
pub struct LifecycleConfig {
    pub destroy_on_exit: Option<bool>,
    pub preserve_policy: Option<bool>,
}

/// Seatbelt (macOS) backend section.
#[derive(Debug, Clone, Default)]
pub struct SeatbeltConfig {
    pub profile_override: Option<String>,
    pub gui_access: Option<bool>,
    pub launch_method: Option<LaunchMethod>,
    pub nested_pty: Option<bool>,
    pub keychain_access: Option<bool>,
    pub extra_mach_lookups: Option<Vec<String>>,
}

/// ProcessContainer (Windows) backend section.
#[derive(Debug, Clone, Default)]
pub struct ProcessContainerConfig {
    pub least_privilege: Option<bool>,
    pub learning_mode: Option<bool>,
    pub capabilities: Option<Vec<String>>,
    pub ui: Option<ProcessContainerUiConfig>,
}

/// ProcessContainer UI policy.
#[derive(Debug, Clone, Default)]
pub struct ProcessContainerUiConfig {
    pub isolation: Option<String>,
    pub desktop_system_control: Option<bool>,
    pub system_settings: Option<String>,
    pub ime: Option<bool>,
}

/// AppContainer DACL-fallback section (Windows).
#[derive(Debug, Clone, Default)]
pub struct FallbackConfig {
    pub allow_dacl_mutation: Option<bool>,
}

impl Config {
    /// Map this public config 1:1 onto the crate-internal parse representation.
    fn into_raw(self) -> RawConfig {
        RawConfig {
            version: self.version,
            container_id: self.container_id,
            process: self.process.map(|p| RawProcess {
                command_line: p.command_line,
                cwd: p.cwd,
                env: p.env,
                timeout: p.timeout,
            }),
            lifecycle: self.lifecycle.map(|l| RawLifecycle {
                destroy_on_exit: l.destroy_on_exit,
                preserve_policy: l.preserve_policy,
            }),
            containment: self.containment,
            process_container: self.process_container.map(|pc| RawProcessContainer {
                least_privilege: pc.least_privilege,
                learning_mode: pc.learning_mode,
                capabilities: pc.capabilities,
                ui: pc.ui.map(|u| RawBaseProcessUi {
                    isolation: u.isolation,
                    desktop_system_control: u.desktop_system_control,
                    system_settings: u.system_settings,
                    ime: u.ime,
                }),
            }),
            lxc: None,
            filesystem: self.filesystem.map(|f| RawFilesystem {
                readwrite_paths: f.readwrite_paths,
                readonly_paths: f.readonly_paths,
                denied_paths: f.denied_paths,
            }),
            fallback: self.fallback.map(|f| RawFallback {
                allow_dacl_mutation: f.allow_dacl_mutation,
            }),
            network: self.network.map(|n| RawNetwork {
                default_policy: n.default_policy,
                enforcement_mode: n.enforcement_mode,
                allow_local_network: n.allow_local_network,
                allowed_hosts: n.allowed_hosts,
                blocked_hosts: n.blocked_hosts,
                proxy: n.proxy,
            }),
            ui: self.ui.map(|u| RawUi {
                disable: u.disable,
                clipboard: u.clipboard,
                injection: u.injection,
            }),
            experimental: None,
            seatbelt: self.seatbelt.map(|s| RawSeatbelt {
                profile_override: s.profile_override,
                gui_access: s.gui_access,
                launch_method: s.launch_method,
                nested_pty: s.nested_pty,
                keychain_access: s.keychain_access,
                extra_mach_lookups: s.extra_mach_lookups,
            }),
            unknown: std::collections::HashMap::new(),
        }
    }
}

/// Convert a typed [`Config`] straight into an [`ExecutionRequest`], running the
/// same validation and wire→model mapping as the executor binaries but without
/// any JSON round-trip. `allow_missing_command` tolerates an absent
/// `process.commandLine` (the caller supplies it later).
pub fn execution_request_from_config(
    config: Config,
    logger: &mut Logger,
    allow_missing_command: bool,
) -> Result<ExecutionRequest, WxcError> {
    convert_raw_config_inner(config.into_raw(), logger, true, allow_missing_command)
}
