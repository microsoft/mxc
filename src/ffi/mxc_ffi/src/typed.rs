// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Co-versioned typed C ABI requests.
//!
//! Inputs are borrowed for the duration of the call. No request pointer or
//! slice is retained after an entry point returns.

use std::ptr;
use std::slice;
use std::str;

use mxc_sdk::configs::{
    CaptureDenials, CaptureDenialsMode, Lxc, ProcessContainer, ProcessContainerFilesystem,
    ProcessContainerNetwork, ProcessContainerSystemSettings, ProcessContainerUi,
    ProcessContainerUiIsolation, Seatbelt,
};
use mxc_sdk::policy::{
    ClipboardPolicy, FilesystemSection, NetworkAction, NetworkEgressSection, NetworkIngressSection,
    NetworkPeerSection, NetworkPortSection, NetworkProtocol, NetworkRuleSection, NetworkSection,
    RuntimeConfigSection, SandboxPolicy, UiSection,
};
use mxc_sdk::{
    build_request_with_containment, spawn_sandbox, Containment, Error, ErrorCode, SandboxRequest,
    WslcSection,
};

use crate::streaming::{finish_spawn, MxcSandbox};
use crate::{
    execute_request, report_panic, status_from_error_code, MxcErrorDetail, MxcRunResult,
    MXC_STATUS_NULL_ARGUMENT, MXC_STATUS_PANIC,
};

/// Current revision of the typed request ABI.
pub const MXC_TYPED_ABI_VERSION_1: u32 = 1;

/// Abstract host-native process containment.
pub const MXC_CONTAINMENT_PROCESS: i32 = 0;
/// Windows ProcessContainer.
pub const MXC_CONTAINMENT_PROCESS_CONTAINER: i32 = 1;
/// Linux Bubblewrap.
pub const MXC_CONTAINMENT_BUBBLEWRAP: i32 = 2;
/// Linux LXC.
pub const MXC_CONTAINMENT_LXC: i32 = 3;
/// macOS Seatbelt.
pub const MXC_CONTAINMENT_SEATBELT: i32 = 4;
/// Windows-hosted WSL Container.
pub const MXC_CONTAINMENT_WSLC: i32 = 5;
/// Windows IsolationSession.
pub const MXC_CONTAINMENT_ISOLATION_SESSION: i32 = 6;

/// Deny a network action.
pub const MXC_NETWORK_ACTION_DENY: i32 = 0;
/// Allow a network action.
pub const MXC_NETWORK_ACTION_ALLOW: i32 = 1;

/// TCP network protocol.
pub const MXC_NETWORK_PROTOCOL_TCP: i32 = 0;
/// UDP network protocol.
pub const MXC_NETWORK_PROTOCOL_UDP: i32 = 1;
/// ICMP network protocol.
pub const MXC_NETWORK_PROTOCOL_ICMP: i32 = 2;
/// Any supported network protocol.
pub const MXC_NETWORK_PROTOCOL_ANY: i32 = 3;

/// Block clipboard access.
pub const MXC_CLIPBOARD_NONE: i32 = 0;
/// Permit clipboard reads.
pub const MXC_CLIPBOARD_READ: i32 = 1;
/// Permit clipboard writes.
pub const MXC_CLIPBOARD_WRITE: i32 = 2;
/// Permit clipboard reads and writes.
pub const MXC_CLIPBOARD_ALL: i32 = 3;

/// ProcessContainer denial capture keeps denials blocked.
pub const MXC_CAPTURE_DENIALS_BLOCK: i32 = 0;
/// ProcessContainer denial capture allows and records denials.
pub const MXC_CAPTURE_DENIALS_ALLOW: i32 = 1;

/// ProcessContainer desktop isolation.
pub const MXC_PROCESS_UI_DESKTOP: i32 = 0;
/// ProcessContainer handle isolation.
pub const MXC_PROCESS_UI_HANDLES: i32 = 1;
/// ProcessContainer atom isolation.
pub const MXC_PROCESS_UI_ATOMS: i32 = 2;
/// ProcessContainer container isolation.
pub const MXC_PROCESS_UI_CONTAINER: i32 = 3;

/// Permit all ProcessContainer system settings.
pub const MXC_PROCESS_SYSTEM_SETTINGS_ALL: i32 = 0;
/// Permit system parameters only.
pub const MXC_PROCESS_SYSTEM_SETTINGS_PARAMETERS: i32 = 1;
/// Permit display settings only.
pub const MXC_PROCESS_SYSTEM_SETTINGS_DISPLAY: i32 = 2;
/// Permit no ProcessContainer system settings.
pub const MXC_PROCESS_SYSTEM_SETTINGS_NONE: i32 = 3;

/// A borrowed UTF-8 byte string. It need not be NUL-terminated.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct MxcUtf8Slice {
    pub data: *const u8,
    pub len: usize,
}

/// A borrowed array of UTF-8 strings.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct MxcUtf8SliceList {
    pub items: *const MxcUtf8Slice,
    pub len: usize,
}

/// An optional boolean with explicit presence.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct MxcOptionalBool {
    pub is_set: i32,
    pub value: i32,
}

/// An optional 16-bit unsigned integer with explicit presence.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct MxcOptionalU16 {
    pub is_set: i32,
    pub value: u16,
}

/// An optional 32-bit unsigned integer with explicit presence.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct MxcOptionalU32 {
    pub is_set: i32,
    pub value: u32,
}

/// An optional 64-bit unsigned integer with explicit presence.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct MxcOptionalU64 {
    pub is_set: i32,
    pub value: u64,
}

/// An optional integer enum value with explicit presence.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct MxcOptionalI32 {
    pub is_set: i32,
    pub value: i32,
}

/// One borrowed environment key/value pair.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct MxcEnvironmentEntry {
    pub key: MxcUtf8Slice,
    pub value: MxcUtf8Slice,
}

/// A presence-sensitive borrowed environment list.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct MxcEnvironment {
    pub is_set: i32,
    pub entries: *const MxcEnvironmentEntry,
    pub len: usize,
}

/// Filesystem policy.
#[repr(C)]
pub struct MxcTypedFilesystemPolicy {
    pub readwrite_paths: MxcUtf8SliceList,
    pub readonly_paths: MxcUtf8SliceList,
    pub denied_paths: MxcUtf8SliceList,
    pub clear_policy_on_exit: MxcOptionalBool,
}

/// One CIDR peer in a directional network rule.
#[repr(C)]
pub struct MxcTypedNetworkPeer {
    pub cidr: MxcUtf8Slice,
    pub except_is_set: i32,
    pub except: MxcUtf8SliceList,
}

/// One port selector in a directional network rule.
#[repr(C)]
pub struct MxcTypedNetworkPort {
    pub protocol: MxcOptionalI32,
    pub port: MxcOptionalU16,
    pub end_port: MxcOptionalU16,
}

/// One directional network rule.
#[repr(C)]
pub struct MxcTypedNetworkRule {
    pub to_is_set: i32,
    pub to: *const MxcTypedNetworkPeer,
    pub to_len: usize,
    pub ports_is_set: i32,
    pub ports: *const MxcTypedNetworkPort,
    pub ports_len: usize,
}

/// Directional egress policy.
#[repr(C)]
pub struct MxcTypedNetworkEgress {
    pub default_action: MxcOptionalI32,
    pub allow_is_set: i32,
    pub allow: *const MxcTypedNetworkRule,
    pub allow_len: usize,
    pub deny_is_set: i32,
    pub deny: *const MxcTypedNetworkRule,
    pub deny_len: usize,
}

/// Directional ingress and host-loopback policy.
#[repr(C)]
pub struct MxcTypedNetworkIngress {
    pub default_action: MxcOptionalI32,
    pub host_loopback: MxcOptionalI32,
}

/// Directional network policy and runtime values.
#[repr(C)]
pub struct MxcTypedNetworkPolicy {
    pub egress: *const MxcTypedNetworkEgress,
    pub ingress: *const MxcTypedNetworkIngress,
    pub network_proxy: *const MxcUtf8Slice,
}

/// UI policy.
#[repr(C)]
pub struct MxcTypedUiPolicy {
    pub allow_windows: i32,
    pub clipboard: i32,
    pub allow_input_injection: i32,
}

/// High-level typed sandbox policy.
#[repr(C)]
pub struct MxcTypedSandboxPolicy {
    pub filesystem: *const MxcTypedFilesystemPolicy,
    pub network: *const MxcTypedNetworkPolicy,
    pub ui: *const MxcTypedUiPolicy,
    pub timeout_ms: MxcOptionalU32,
    pub telemetry_enabled: MxcOptionalBool,
}

/// ProcessContainer denial-capture settings.
#[repr(C)]
pub struct MxcTypedCaptureDenials {
    pub mode: i32,
    pub output_path: *const MxcUtf8Slice,
    pub retain_etl: i32,
}

/// ProcessContainer UI settings.
#[repr(C)]
pub struct MxcTypedProcessContainerUi {
    pub isolation: i32,
    pub desktop_system_control: i32,
    pub system_settings: i32,
    pub ime: i32,
}

/// ProcessContainer-specific settings.
#[repr(C)]
pub struct MxcTypedProcessContainer {
    pub least_privilege: i32,
    pub learning_mode: i32,
    pub capabilities: MxcUtf8SliceList,
    pub capture_denials: *const MxcTypedCaptureDenials,
    pub ui: *const MxcTypedProcessContainerUi,
    pub enumerate_paths: MxcUtf8SliceList,
    pub allowed_proxy_peer: *const MxcUtf8Slice,
}

/// Seatbelt settings.
#[repr(C)]
pub struct MxcTypedSeatbelt {
    pub profile_override: *const MxcUtf8Slice,
    pub gui_access: i32,
    pub nested_pty: i32,
    pub keychain_access: i32,
    pub extra_mach_lookups: MxcUtf8SliceList,
}

/// LXC settings.
#[repr(C)]
pub struct MxcTypedLxc {
    pub distribution: *const MxcUtf8Slice,
    pub release: *const MxcUtf8Slice,
}

/// One WSLC host-to-container TCP port mapping.
#[repr(C)]
pub struct MxcTypedWslcPortMapping {
    pub windows_port: u16,
    pub container_port: u16,
}

/// WSLC settings.
#[repr(C)]
pub struct MxcTypedWslc {
    pub image: *const MxcUtf8Slice,
    pub image_tar_path: *const MxcUtf8Slice,
    pub cpu_count: MxcOptionalU32,
    pub memory_mb: MxcOptionalU64,
    pub gpu: i32,
    pub storage_path: *const MxcUtf8Slice,
    pub port_mappings: *const MxcTypedWslcPortMapping,
    pub port_mappings_len: usize,
}

/// Versioned typed one-shot request.
#[repr(C)]
pub struct MxcTypedOneShotRequest {
    pub abi_version: u32,
    pub struct_size: usize,
    pub policy: *const MxcTypedSandboxPolicy,
    pub command: MxcUtf8Slice,
    pub containment: i32,
    pub process_container: *const MxcTypedProcessContainer,
    pub seatbelt: *const MxcTypedSeatbelt,
    pub lxc: *const MxcTypedLxc,
    pub wslc: *const MxcTypedWslc,
    pub container_name: *const MxcUtf8Slice,
    pub working_directory: *const MxcUtf8Slice,
    pub environment: MxcEnvironment,
    pub inherit_default_env: i32,
    pub experimental: i32,
}

fn malformed(message: impl Into<String>) -> Error {
    Error::new(ErrorCode::MalformedRequest, message)
}

pub(crate) fn flag(value: i32, field: &str) -> Result<bool, Error> {
    match value {
        0 => Ok(false),
        1 => Ok(true),
        _ => Err(malformed(format!("{field} must be 0 or 1"))),
    }
}

pub(crate) fn presence(value: i32, field: &str) -> Result<bool, Error> {
    flag(value, field)
}

pub(crate) unsafe fn borrowed_slice<'a, T>(
    data: *const T,
    len: usize,
    field: &str,
) -> Result<&'a [T], Error> {
    if len == 0 {
        return Ok(&[]);
    }
    if data.is_null() {
        return Err(malformed(format!(
            "{field} pointer is null with non-zero length"
        )));
    }
    // SAFETY: the caller promises `data` is valid for `len` elements for the
    // duration of the call; null with non-zero length was rejected above.
    Ok(unsafe { slice::from_raw_parts(data, len) })
}

pub(crate) unsafe fn utf8(value: MxcUtf8Slice, field: &str) -> Result<String, Error> {
    // SAFETY: delegated to `borrowed_slice` under this entry point's caller contract.
    let bytes = unsafe { borrowed_slice(value.data, value.len, field)? };
    str::from_utf8(bytes)
        .map(str::to_owned)
        .map_err(|_| malformed(format!("{field} is not valid UTF-8")))
}

pub(crate) unsafe fn optional_utf8(
    value: *const MxcUtf8Slice,
    field: &str,
) -> Result<Option<String>, Error> {
    if value.is_null() {
        return Ok(None);
    }
    // SAFETY: non-null pointer is caller-guaranteed readable.
    unsafe { utf8(*value, field) }.map(Some)
}

unsafe fn utf8_list(value: MxcUtf8SliceList, field: &str) -> Result<Vec<String>, Error> {
    // SAFETY: caller contract covers the borrowed array.
    let values = unsafe { borrowed_slice(value.items, value.len, field)? };
    values
        .iter()
        .enumerate()
        .map(|(index, value)| {
            // SAFETY: each list element follows the same borrowed-string contract.
            unsafe { utf8(*value, &format!("{field}[{index}]")) }
        })
        .collect()
}

pub(crate) fn optional_bool(value: MxcOptionalBool, field: &str) -> Result<Option<bool>, Error> {
    if !presence(value.is_set, &format!("{field}.is_set"))? {
        return Ok(None);
    }
    flag(value.value, field).map(Some)
}

fn optional_u16(value: MxcOptionalU16, field: &str) -> Result<Option<u16>, Error> {
    presence(value.is_set, &format!("{field}.is_set")).map(|set| set.then_some(value.value))
}

pub(crate) fn optional_u32(value: MxcOptionalU32, field: &str) -> Result<Option<u32>, Error> {
    presence(value.is_set, &format!("{field}.is_set")).map(|set| set.then_some(value.value))
}

fn optional_u64(value: MxcOptionalU64, field: &str) -> Result<Option<u64>, Error> {
    presence(value.is_set, &format!("{field}.is_set")).map(|set| set.then_some(value.value))
}

fn optional_i32(value: MxcOptionalI32, field: &str) -> Result<Option<i32>, Error> {
    presence(value.is_set, &format!("{field}.is_set")).map(|set| set.then_some(value.value))
}

fn network_action(value: i32, field: &str) -> Result<NetworkAction, Error> {
    match value {
        MXC_NETWORK_ACTION_DENY => Ok(NetworkAction::Deny),
        MXC_NETWORK_ACTION_ALLOW => Ok(NetworkAction::Allow),
        _ => Err(malformed(format!("{field} has an unknown network action"))),
    }
}

fn network_protocol(value: i32, field: &str) -> Result<NetworkProtocol, Error> {
    match value {
        MXC_NETWORK_PROTOCOL_TCP => Ok(NetworkProtocol::Tcp),
        MXC_NETWORK_PROTOCOL_UDP => Ok(NetworkProtocol::Udp),
        MXC_NETWORK_PROTOCOL_ICMP => Ok(NetworkProtocol::Icmp),
        MXC_NETWORK_PROTOCOL_ANY => Ok(NetworkProtocol::Any),
        _ => Err(malformed(format!(
            "{field} has an unknown network protocol"
        ))),
    }
}

unsafe fn network_rules(
    data: *const MxcTypedNetworkRule,
    len: usize,
    field: &str,
) -> Result<Vec<NetworkRuleSection>, Error> {
    // SAFETY: caller contract covers the borrowed rule array.
    let rules = unsafe { borrowed_slice(data, len, field)? };
    rules
        .iter()
        .enumerate()
        .map(|(index, rule)| {
            let rule_field = format!("{field}[{index}]");
            let to = if presence(rule.to_is_set, &format!("{rule_field}.to_is_set"))? {
                // SAFETY: presence says the caller authored this borrowed array.
                let peers =
                    unsafe { borrowed_slice(rule.to, rule.to_len, &format!("{rule_field}.to"))? };
                Some(
                    peers
                        .iter()
                        .enumerate()
                        .map(|(peer_index, peer)| {
                            let peer_field = format!("{rule_field}.to[{peer_index}]");
                            // SAFETY: peer strings follow the borrowed request contract.
                            let cidr = unsafe { utf8(peer.cidr, &format!("{peer_field}.cidr"))? };
                            let except = if presence(
                                peer.except_is_set,
                                &format!("{peer_field}.except_is_set"),
                            )? {
                                // SAFETY: exception strings follow the borrowed request contract.
                                Some(unsafe {
                                    utf8_list(peer.except, &format!("{peer_field}.except"))?
                                })
                            } else {
                                None
                            };
                            let mut mapped = NetworkPeerSection::new(cidr);
                            mapped.except = except;
                            Ok(mapped)
                        })
                        .collect::<Result<Vec<_>, Error>>()?,
                )
            } else {
                None
            };
            let ports = if presence(rule.ports_is_set, &format!("{rule_field}.ports_is_set"))? {
                // SAFETY: presence says the caller authored this borrowed array.
                let values = unsafe {
                    borrowed_slice(rule.ports, rule.ports_len, &format!("{rule_field}.ports"))?
                };
                Some(
                    values
                        .iter()
                        .enumerate()
                        .map(|(port_index, port)| {
                            let port_field = format!("{rule_field}.ports[{port_index}]");
                            let mut mapped = NetworkPortSection::default();
                            mapped.protocol =
                                optional_i32(port.protocol, &format!("{port_field}.protocol"))?
                                    .map(|value| {
                                        network_protocol(value, &format!("{port_field}.protocol"))
                                    })
                                    .transpose()?;
                            mapped.port = optional_u16(port.port, &format!("{port_field}.port"))?;
                            mapped.end_port =
                                optional_u16(port.end_port, &format!("{port_field}.end_port"))?;
                            Ok(mapped)
                        })
                        .collect::<Result<Vec<_>, Error>>()?,
                )
            } else {
                None
            };
            let mut mapped = NetworkRuleSection::default();
            mapped.to = to;
            mapped.ports = ports;
            Ok(mapped)
        })
        .collect()
}

pub(crate) unsafe fn policy(
    value: *const MxcTypedSandboxPolicy,
) -> Result<(SandboxPolicy, Option<bool>), Error> {
    if value.is_null() {
        return Ok((SandboxPolicy::default(), None));
    }
    // SAFETY: non-null pointer is caller-guaranteed readable.
    let value = unsafe { &*value };
    let filesystem = if value.filesystem.is_null() {
        None
    } else {
        // SAFETY: non-null nested pointer is caller-guaranteed readable.
        let filesystem = unsafe { &*value.filesystem };
        Some(FilesystemSection {
            // SAFETY: list storage follows the borrowed request contract.
            readwrite_paths: unsafe {
                utf8_list(
                    filesystem.readwrite_paths,
                    "policy.filesystem.readwrite_paths",
                )?
            },
            // SAFETY: list storage follows the borrowed request contract.
            readonly_paths: unsafe {
                utf8_list(
                    filesystem.readonly_paths,
                    "policy.filesystem.readonly_paths",
                )?
            },
            // SAFETY: list storage follows the borrowed request contract.
            denied_paths: unsafe {
                utf8_list(filesystem.denied_paths, "policy.filesystem.denied_paths")?
            },
            clear_policy_on_exit: optional_bool(
                filesystem.clear_policy_on_exit,
                "policy.filesystem.clear_policy_on_exit",
            )?,
        })
    };
    let network = if value.network.is_null() {
        None
    } else {
        // SAFETY: non-null nested pointer is caller-guaranteed readable.
        let network = unsafe { &*value.network };
        let egress = if network.egress.is_null() {
            None
        } else {
            // SAFETY: non-null nested pointer is caller-guaranteed readable.
            let egress = unsafe { &*network.egress };
            let mut mapped = NetworkEgressSection::default();
            mapped.default = optional_i32(egress.default_action, "policy.network.egress.default")?
                .map(|value| network_action(value, "policy.network.egress.default"))
                .transpose()?;
            mapped.allow = if presence(egress.allow_is_set, "policy.network.egress.allow_is_set")? {
                // SAFETY: authored rule array follows the borrowed request contract.
                Some(unsafe {
                    network_rules(
                        egress.allow,
                        egress.allow_len,
                        "policy.network.egress.allow",
                    )?
                })
            } else {
                None
            };
            mapped.deny = if presence(egress.deny_is_set, "policy.network.egress.deny_is_set")? {
                // SAFETY: authored rule array follows the borrowed request contract.
                Some(unsafe {
                    network_rules(egress.deny, egress.deny_len, "policy.network.egress.deny")?
                })
            } else {
                None
            };
            Some(mapped)
        };
        let ingress = if network.ingress.is_null() {
            None
        } else {
            // SAFETY: non-null nested pointer is caller-guaranteed readable.
            let ingress = unsafe { &*network.ingress };
            let mut mapped = NetworkIngressSection::default();
            mapped.default =
                optional_i32(ingress.default_action, "policy.network.ingress.default")?
                    .map(|value| network_action(value, "policy.network.ingress.default"))
                    .transpose()?;
            mapped.host_loopback = optional_i32(
                ingress.host_loopback,
                "policy.network.ingress.host_loopback",
            )?
            .map(|value| network_action(value, "policy.network.ingress.host_loopback"))
            .transpose()?;
            Some(mapped)
        };
        let mut mapped = NetworkSection::default();
        mapped.egress = egress;
        mapped.ingress = ingress;
        mapped.runtime_config =
            unsafe { optional_utf8(network.network_proxy, "policy.network.network_proxy")? }.map(
                |network_proxy| {
                    let mut runtime = RuntimeConfigSection::default();
                    runtime.network_proxy = Some(network_proxy);
                    runtime
                },
            );
        Some(mapped)
    };
    let ui = if value.ui.is_null() {
        None
    } else {
        // SAFETY: non-null nested pointer is caller-guaranteed readable.
        let ui = unsafe { &*value.ui };
        Some(UiSection {
            allow_windows: flag(ui.allow_windows, "policy.ui.allow_windows")?,
            clipboard: match ui.clipboard {
                MXC_CLIPBOARD_NONE => ClipboardPolicy::None,
                MXC_CLIPBOARD_READ => ClipboardPolicy::Read,
                MXC_CLIPBOARD_WRITE => ClipboardPolicy::Write,
                MXC_CLIPBOARD_ALL => ClipboardPolicy::All,
                _ => return Err(malformed("policy.ui.clipboard has an unknown value")),
            },
            allow_input_injection: flag(
                ui.allow_input_injection,
                "policy.ui.allow_input_injection",
            )?,
        })
    };
    let mut mapped = SandboxPolicy::default();
    mapped.filesystem = filesystem;
    mapped.network = network;
    mapped.ui = ui;
    mapped.timeout_ms = optional_u32(value.timeout_ms, "policy.timeout_ms")?;
    Ok((
        mapped,
        optional_bool(value.telemetry_enabled, "policy.telemetry_enabled")?,
    ))
}

unsafe fn containment(request: &MxcTypedOneShotRequest) -> Result<Containment, Error> {
    match request.containment {
        MXC_CONTAINMENT_PROCESS => Ok(Containment::Process),
        MXC_CONTAINMENT_PROCESS_CONTAINER => {
            let mut config = ProcessContainer::default();
            if !request.process_container.is_null() {
                // SAFETY: non-null selected config is caller-guaranteed readable.
                let value = unsafe { &*request.process_container };
                config.least_privilege =
                    flag(value.least_privilege, "process_container.least_privilege")?;
                config.learning_mode =
                    flag(value.learning_mode, "process_container.learning_mode")?;
                // SAFETY: list storage follows the borrowed request contract.
                config.capabilities =
                    unsafe { utf8_list(value.capabilities, "process_container.capabilities")? };
                config.capture_denials = if value.capture_denials.is_null() {
                    None
                } else {
                    // SAFETY: non-null nested pointer is caller-guaranteed readable.
                    let capture = unsafe { &*value.capture_denials };
                    let mut mapped = CaptureDenials::default();
                    mapped.mode = match capture.mode {
                        MXC_CAPTURE_DENIALS_BLOCK => CaptureDenialsMode::Block,
                        MXC_CAPTURE_DENIALS_ALLOW => CaptureDenialsMode::Allow,
                        _ => {
                            return Err(malformed(
                                "process_container.capture_denials.mode has an unknown value",
                            ))
                        }
                    };
                    // SAFETY: optional string follows the borrowed request contract.
                    mapped.output_path = unsafe {
                        optional_utf8(
                            capture.output_path,
                            "process_container.capture_denials.output_path",
                        )?
                    };
                    mapped.retain_etl = flag(
                        capture.retain_etl,
                        "process_container.capture_denials.retain_etl",
                    )?;
                    Some(mapped)
                };
                config.ui = if value.ui.is_null() {
                    None
                } else {
                    // SAFETY: non-null nested pointer is caller-guaranteed readable.
                    let ui = unsafe { &*value.ui };
                    let mut mapped = ProcessContainerUi::default();
                    mapped.isolation = match ui.isolation {
                        MXC_PROCESS_UI_DESKTOP => ProcessContainerUiIsolation::Desktop,
                        MXC_PROCESS_UI_HANDLES => ProcessContainerUiIsolation::Handles,
                        MXC_PROCESS_UI_ATOMS => ProcessContainerUiIsolation::Atoms,
                        MXC_PROCESS_UI_CONTAINER => ProcessContainerUiIsolation::Container,
                        _ => {
                            return Err(malformed(
                                "process_container.ui.isolation has an unknown value",
                            ))
                        }
                    };
                    mapped.desktop_system_control = flag(
                        ui.desktop_system_control,
                        "process_container.ui.desktop_system_control",
                    )?;
                    mapped.system_settings = match ui.system_settings {
                        MXC_PROCESS_SYSTEM_SETTINGS_ALL => ProcessContainerSystemSettings::All,
                        MXC_PROCESS_SYSTEM_SETTINGS_PARAMETERS => {
                            ProcessContainerSystemSettings::Parameters
                        }
                        MXC_PROCESS_SYSTEM_SETTINGS_DISPLAY => {
                            ProcessContainerSystemSettings::Display
                        }
                        MXC_PROCESS_SYSTEM_SETTINGS_NONE => ProcessContainerSystemSettings::None,
                        _ => {
                            return Err(malformed(
                                "process_container.ui.system_settings has an unknown value",
                            ))
                        }
                    };
                    mapped.ime = flag(ui.ime, "process_container.ui.ime")?;
                    Some(mapped)
                };
                // SAFETY: list storage follows the borrowed request contract.
                let enumerate_paths = unsafe {
                    utf8_list(
                        value.enumerate_paths,
                        "process_container.filesystem.enumerate_paths",
                    )?
                };
                if !enumerate_paths.is_empty() {
                    let mut filesystem = ProcessContainerFilesystem::default();
                    filesystem.enumerate_paths = enumerate_paths;
                    config.filesystem = Some(filesystem);
                }
                // SAFETY: optional string follows the borrowed request contract.
                config.network = unsafe {
                    optional_utf8(
                        value.allowed_proxy_peer,
                        "process_container.network.allowed_proxy_peer",
                    )?
                }
                .map(|allowed_proxy_peer| {
                    let mut network = ProcessContainerNetwork::default();
                    network.allowed_proxy_peer = Some(allowed_proxy_peer);
                    network
                });
            }
            Ok(Containment::ProcessContainer(config))
        }
        MXC_CONTAINMENT_BUBBLEWRAP => Ok(Containment::Bubblewrap),
        MXC_CONTAINMENT_LXC => {
            let mut config = Lxc::default();
            if !request.lxc.is_null() {
                // SAFETY: non-null selected config is caller-guaranteed readable.
                let value = unsafe { &*request.lxc };
                if let Some(distribution) =
                    // SAFETY: optional string follows the borrowed request contract.
                    unsafe { optional_utf8(value.distribution, "lxc.distribution")? }
                {
                    config.distribution = distribution;
                }
                if let Some(release) =
                    // SAFETY: optional string follows the borrowed request contract.
                    unsafe { optional_utf8(value.release, "lxc.release")? }
                {
                    config.release = release;
                }
            }
            Ok(Containment::Lxc(config))
        }
        MXC_CONTAINMENT_SEATBELT => {
            let mut config = Seatbelt::default();
            if !request.seatbelt.is_null() {
                // SAFETY: non-null selected config is caller-guaranteed readable.
                let value = unsafe { &*request.seatbelt };
                // SAFETY: optional string follows the borrowed request contract.
                config.profile_override =
                    unsafe { optional_utf8(value.profile_override, "seatbelt.profile_override")? };
                config.gui_access = flag(value.gui_access, "seatbelt.gui_access")?;
                config.nested_pty = flag(value.nested_pty, "seatbelt.nested_pty")?;
                config.keychain_access = flag(value.keychain_access, "seatbelt.keychain_access")?;
                // SAFETY: list storage follows the borrowed request contract.
                config.extra_mach_lookups =
                    unsafe { utf8_list(value.extra_mach_lookups, "seatbelt.extra_mach_lookups")? };
            }
            Ok(Containment::Seatbelt(config))
        }
        MXC_CONTAINMENT_WSLC => {
            let mut config = WslcSection::default();
            if !request.wslc.is_null() {
                // SAFETY: non-null selected config is caller-guaranteed readable.
                let value = unsafe { &*request.wslc };
                if let Some(image) =
                    // SAFETY: optional string follows the borrowed request contract.
                    unsafe { optional_utf8(value.image, "wslc.image")? }
                {
                    config.image = image;
                }
                // SAFETY: optional strings follow the borrowed request contract.
                config.image_tar_path =
                    unsafe { optional_utf8(value.image_tar_path, "wslc.image_tar_path")? };
                config.cpu_count = optional_u32(value.cpu_count, "wslc.cpu_count")?;
                config.memory_mb = optional_u64(value.memory_mb, "wslc.memory_mb")?;
                config.gpu = flag(value.gpu, "wslc.gpu")?;
                // SAFETY: optional string follows the borrowed request contract.
                config.storage_path =
                    unsafe { optional_utf8(value.storage_path, "wslc.storage_path")? };
                // SAFETY: port mappings follow the borrowed request contract.
                config.port_mappings = unsafe {
                    borrowed_slice(
                        value.port_mappings,
                        value.port_mappings_len,
                        "wslc.port_mappings",
                    )?
                }
                .iter()
                .map(|mapping| (mapping.windows_port, mapping.container_port))
                .collect();
            }
            Ok(Containment::Wslc(config))
        }
        MXC_CONTAINMENT_ISOLATION_SESSION => Ok(Containment::IsolationSession),
        _ => Err(malformed("containment has an unknown value")),
    }
}

/// Convert a typed ABI request into the public Rust SDK request.
///
/// # Safety
/// Every non-null pointer reachable from `request` must be readable for the
/// duration of the call and every array must contain the advertised number of
/// elements.
pub(crate) unsafe fn build_one_shot_request(
    request: *const MxcTypedOneShotRequest,
) -> Result<SandboxRequest, Error> {
    if request.is_null() {
        return Err(malformed("typed request pointer is null"));
    }
    // SAFETY: non-null top-level pointer is caller-guaranteed readable.
    let request = unsafe { &*request };
    if request.abi_version != MXC_TYPED_ABI_VERSION_1 {
        return Err(malformed(format!(
            "unsupported typed request ABI version {}",
            request.abi_version
        )));
    }
    if request.struct_size < std::mem::size_of::<MxcTypedOneShotRequest>() {
        return Err(malformed(format!(
            "typed request struct_size {} is smaller than required {}",
            request.struct_size,
            std::mem::size_of::<MxcTypedOneShotRequest>()
        )));
    }
    // SAFETY: nested pointers follow the top-level caller contract.
    let (policy, telemetry) = unsafe { policy(request.policy)? };
    // SAFETY: command bytes follow the top-level caller contract.
    let command = unsafe { utf8(request.command, "command")? };
    // SAFETY: selected containment config follows the top-level caller contract.
    let containment = unsafe { containment(request)? };
    // SAFETY: optional string follows the top-level caller contract.
    let container_name = unsafe { optional_utf8(request.container_name, "container_name")? };
    let mut built =
        build_request_with_containment(&policy, &containment, &command, container_name.as_deref())?;
    if let Some(working_directory) =
        // SAFETY: optional string follows the top-level caller contract.
        unsafe { optional_utf8(request.working_directory, "working_directory")? }
    {
        built.set_working_directory(working_directory);
    }
    if presence(request.environment.is_set, "environment.is_set")? {
        // SAFETY: environment entries follow the top-level caller contract.
        let entries = unsafe {
            borrowed_slice(
                request.environment.entries,
                request.environment.len,
                "environment.entries",
            )?
        };
        let mut environment = Vec::with_capacity(entries.len());
        for (index, entry) in entries.iter().enumerate() {
            // SAFETY: key/value bytes follow the borrowed request contract.
            let key = unsafe { utf8(entry.key, &format!("environment[{index}].key"))? };
            if key.is_empty() || key.contains('=') {
                return Err(malformed(format!(
                    "environment[{index}].key must be non-empty and contain no '='"
                )));
            }
            // SAFETY: key/value bytes follow the borrowed request contract.
            let value = unsafe { utf8(entry.value, &format!("environment[{index}].value"))? };
            environment.push((key, value));
        }
        if flag(request.inherit_default_env, "inherit_default_env")? {
            built.inherit_default_env(environment);
        } else {
            built.set_env(environment);
        }
    } else if flag(request.inherit_default_env, "inherit_default_env")? {
        return Err(malformed(
            "inherit_default_env requires an authored environment list",
        ));
    }
    built.set_experimental(flag(request.experimental, "experimental")?);
    if let Some(enabled) = telemetry {
        built.set_telemetry_opt_in(enabled);
    }
    Ok(built)
}

/// Run a typed one-shot request to completion.
///
/// # Safety
/// - `request` must satisfy [`build_one_shot_request`]'s pointer contract.
/// - `out` must point to writable [`MxcRunResult`] storage.
/// - Release the result with [`crate::mxc_run_result_free`].
#[no_mangle]
pub unsafe extern "C" fn mxc_run_typed(
    request: *const MxcTypedOneShotRequest,
    out: *mut MxcRunResult,
) -> i32 {
    if out.is_null() {
        return MXC_STATUS_NULL_ARGUMENT;
    }
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        // SAFETY: caller contract is forwarded to the conversion helper.
        match unsafe { build_one_shot_request(request) } {
            Ok(request) => execute_request(request),
            Err(error) => MxcRunResult::from_sdk_error(&error),
        }
    }))
    .unwrap_or_else(|panic| {
        report_panic("mxc_run_typed", &*panic);
        MxcRunResult::error(MXC_STATUS_PANIC, "the mxc engine panicked")
    });
    let status = result.status;
    // SAFETY: `out` is non-null and caller-guaranteed writable.
    unsafe { ptr::write(out, result) };
    status
}

/// Spawn a typed one-shot request as a live streaming sandbox.
///
/// # Safety
/// - `request` must satisfy [`build_one_shot_request`]'s pointer contract.
/// - `out_handle` must point to writable pointer storage containing no live
///   handle.
/// - `out_error` must be null or point to fresh writable detail storage.
#[no_mangle]
pub unsafe extern "C" fn mxc_spawn_typed(
    request: *const MxcTypedOneShotRequest,
    out_handle: *mut *mut MxcSandbox,
    out_error: *mut MxcErrorDetail,
) -> i32 {
    if !out_handle.is_null() {
        // SAFETY: caller-guaranteed writable pointer storage.
        unsafe { *out_handle = ptr::null_mut() };
    }
    if !out_error.is_null() {
        // SAFETY: caller-guaranteed writable detail storage.
        unsafe { ptr::write(out_error, MxcErrorDetail::none()) };
    }
    if out_handle.is_null() {
        return MXC_STATUS_NULL_ARGUMENT;
    }
    let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        // SAFETY: caller contract is forwarded to the conversion helper.
        let request = unsafe { build_one_shot_request(request) }.map_err(|error| {
            (
                status_from_error_code(error.code),
                MxcErrorDetail::from_error(&error),
            )
        })?;
        spawn_sandbox(request).map_err(|error| {
            (
                status_from_error_code(error.code),
                MxcErrorDetail::from_error(&error),
            )
        })
    }))
    .unwrap_or_else(|panic| {
        report_panic("mxc_spawn_typed", &*panic);
        Err((
            MXC_STATUS_PANIC,
            MxcErrorDetail::from_message("the mxc engine panicked"),
        ))
    });
    // SAFETY: out-parameter contracts were checked above.
    unsafe { finish_spawn(outcome, out_handle, out_error) }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn text(value: &str) -> MxcUtf8Slice {
        MxcUtf8Slice {
            data: value.as_ptr(),
            len: value.len(),
        }
    }

    fn minimal(command: &str) -> MxcTypedOneShotRequest {
        MxcTypedOneShotRequest {
            abi_version: MXC_TYPED_ABI_VERSION_1,
            struct_size: std::mem::size_of::<MxcTypedOneShotRequest>(),
            policy: ptr::null(),
            command: text(command),
            containment: MXC_CONTAINMENT_PROCESS,
            process_container: ptr::null(),
            seatbelt: ptr::null(),
            lxc: ptr::null(),
            wslc: ptr::null(),
            container_name: ptr::null(),
            working_directory: ptr::null(),
            environment: MxcEnvironment {
                is_set: 0,
                entries: ptr::null(),
                len: 0,
            },
            inherit_default_env: 0,
            experimental: 0,
        }
    }

    #[test]
    fn minimal_typed_request_builds_without_json() {
        let request = minimal("echo hello");
        // SAFETY: every pointer in `request` is valid for the call.
        unsafe { build_one_shot_request(&request) }.expect("typed request builds");
    }

    #[test]
    fn typed_request_rejects_unsupported_abi_revision() {
        let mut request = minimal("echo hello");
        request.abi_version = 99;
        // SAFETY: every pointer in `request` is valid for the call.
        let error = unsafe { build_one_shot_request(&request) }.unwrap_err();
        assert!(error
            .message
            .contains("unsupported typed request ABI version"));
    }

    #[test]
    fn typed_request_preserves_present_empty_environment() {
        let mut request = minimal("echo hello");
        request.environment.is_set = 1;
        // SAFETY: every pointer in `request` is valid for the call.
        let built = unsafe { build_one_shot_request(&request) }.expect("request builds");
        assert_eq!(built.env(), Some(&[][..]));
    }

    #[cfg(feature = "test-support")]
    #[test]
    fn typed_and_exact_json_produce_equivalent_one_shot_intent() {
        let readonly = [text("/input")];
        let filesystem = MxcTypedFilesystemPolicy {
            readwrite_paths: MxcUtf8SliceList {
                items: ptr::null(),
                len: 0,
            },
            readonly_paths: MxcUtf8SliceList {
                items: readonly.as_ptr(),
                len: readonly.len(),
            },
            denied_paths: MxcUtf8SliceList {
                items: ptr::null(),
                len: 0,
            },
            clear_policy_on_exit: MxcOptionalBool {
                is_set: 0,
                value: 0,
            },
        };
        let egress = MxcTypedNetworkEgress {
            default_action: MxcOptionalI32 {
                is_set: 1,
                value: MXC_NETWORK_ACTION_DENY,
            },
            allow_is_set: 0,
            allow: ptr::null(),
            allow_len: 0,
            deny_is_set: 0,
            deny: ptr::null(),
            deny_len: 0,
        };
        let ingress = MxcTypedNetworkIngress {
            default_action: MxcOptionalI32 {
                is_set: 1,
                value: MXC_NETWORK_ACTION_DENY,
            },
            host_loopback: MxcOptionalI32 {
                is_set: 1,
                value: MXC_NETWORK_ACTION_DENY,
            },
        };
        let network = MxcTypedNetworkPolicy {
            egress: &egress,
            ingress: &ingress,
            network_proxy: ptr::null(),
        };
        let policy = MxcTypedSandboxPolicy {
            filesystem: &filesystem,
            network: &network,
            ui: ptr::null(),
            timeout_ms: MxcOptionalU32 {
                is_set: 1,
                value: 5000,
            },
            telemetry_enabled: MxcOptionalBool {
                is_set: 0,
                value: 0,
            },
        };
        let container_name = text("ffi-equivalence");
        let working_directory = text("/work");
        let mut request = minimal("echo hello");
        request.policy = &policy;
        request.containment = MXC_CONTAINMENT_BUBBLEWRAP;
        request.container_name = &container_name;
        request.working_directory = &working_directory;
        request.environment.is_set = 1;

        // SAFETY: every pointer remains valid for projection.
        let typed = unsafe { build_one_shot_request(&request) }.expect("typed request builds");
        let typed_intent = mxc_sdk::typed_one_shot_intent(&typed).expect("typed intent projects");
        let exact_intent = mxc_sdk::json_one_shot_intent(
            r#"{
                "version":"1.0.0",
                "containerId":"ffi-equivalence",
                "containment":"bubblewrap",
                "process":{
                    "commandLine":"echo hello",
                    "cwd":"/work",
                    "env":[],
                    "timeout":5000
                },
                "filesystem":{"readonlyPaths":["/input"]},
                "network":{
                    "egress":{"default":"deny"},
                    "ingress":{"default":"deny","hostLoopback":"deny"}
                }
            }"#,
        )
        .expect("exact intent projects");

        assert_eq!(typed_intent, exact_intent);
    }
}
