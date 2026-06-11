// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use std::collections::HashMap;
use std::fmt::Write;
use std::fs;

use serde::de::IgnoredAny;
use serde::Deserialize;

use crate::encoding::base64_decode;
use crate::error::WxcError;
use crate::logger::Logger;
use crate::models::{
    ClipboardPolicy, ContainerPolicy, ContainmentBackend, ExecutionRequest, ExperimentalConfig,
    IsolationSessionConfig, IsolationSessionUser, LifecycleConfig, LxcConfig,
    NetworkEnforcementMode, NetworkPolicy, PortMapping, ProxyAddress, ProxyConfig, SeatbeltConfig,
    TestFeatureConfig, UiPolicy, WindowsSandboxConfig, WslcConfig,
};
use crate::mxc_error::MxcError;
use crate::state_aware_request::{MxcRequest, ParsedStateAwareRequest, Phase};

/// Categorised error from `load_mxc_request`. The `wxc-exec` driver uses the
/// variant to choose the failure-output convention: state-aware failures
/// emit a JSON `{"error": ...}` envelope on stdout, while one-shot and
/// pre-discrimination failures keep the existing diagnostic-on-stderr path.
#[derive(Debug)]
pub enum ParseError {
    /// I/O, base64-decode, or top-level JSON parse failure — the input could
    /// not be discriminated as state-aware vs one-shot.
    Decode(WxcError),
    /// Discriminated as one-shot; conversion to `ExecutionRequest` failed.
    OneShot(WxcError),
    /// Discriminated as state-aware; conversion to `ParsedStateAwareRequest`
    /// failed. Carries an `MxcError` so the driver can emit a typed envelope.
    StateAware(MxcError),
}

// ---------- Intermediate serde structs matching the JSON schema ----------

#[derive(Deserialize, Default)]
#[serde(default)]
struct RawProcessContainer {
    #[serde(rename = "leastPrivilege")]
    least_privilege: Option<bool>,
    #[serde(rename = "learningMode")]
    learning_mode: Option<bool>,
    capabilities: Option<Vec<String>>,
    ui: Option<RawBaseProcessUi>,
}

#[derive(Deserialize, Default)]
#[serde(default)]
struct RawBaseProcessUi {
    isolation: Option<String>,
    #[serde(rename = "desktopSystemControl")]
    desktop_system_control: Option<bool>,
    #[serde(rename = "systemSettings")]
    system_settings: Option<String>,
    ime: Option<bool>,
}

#[derive(Deserialize, Default)]
#[serde(default)]
struct RawFilesystem {
    #[serde(rename = "readwritePaths")]
    readwrite_paths: Option<Vec<String>>,
    #[serde(rename = "readonlyPaths")]
    readonly_paths: Option<Vec<String>>,
    #[serde(rename = "deniedPaths")]
    denied_paths: Option<Vec<String>>,
}

#[derive(Deserialize, Default)]
#[serde(default)]
struct RawFallback {
    #[serde(rename = "allowDaclMutation")]
    allow_dacl_mutation: Option<bool>,
}

#[derive(Deserialize, Default)]
#[serde(default)]
struct RawNetwork {
    #[serde(rename = "defaultPolicy")]
    default_policy: Option<String>,
    #[serde(rename = "enforcementMode")]
    enforcement_mode: Option<String>,
    #[serde(rename = "allowLocalNetwork")]
    allow_local_network: Option<bool>,
    #[serde(rename = "allowedHosts")]
    allowed_hosts: Option<Vec<String>>,
    #[serde(rename = "blockedHosts")]
    blocked_hosts: Option<Vec<String>>,
    proxy: Option<serde_json::Value>,
}

#[derive(Deserialize, Default)]
#[serde(default)]
struct RawSandbox {
    #[serde(rename = "idleTimeout")]
    idle_timeout: Option<u32>,
    #[serde(rename = "idleTimeoutMs")]
    idle_timeout_ms: Option<u32>,
    #[serde(rename = "daemonPipeName")]
    daemon_pipe_name: Option<String>,
}

#[derive(Deserialize)]
struct RawPortMapping {
    #[serde(rename = "windowsPort")]
    windows_port: u16,
    #[serde(rename = "containerPort")]
    container_port: u16,
    #[serde(default)]
    protocol: Option<String>,
}

#[derive(Deserialize, Default)]
#[serde(default)]
struct RawContainerConfig {
    #[serde(rename = "targetOs")]
    target_os: Option<String>,
    image: Option<String>,
    #[serde(rename = "imageTarPath")]
    image_tar_path: Option<String>,
    #[serde(rename = "cpuCount")]
    cpu_count: Option<u32>,
    #[serde(rename = "memoryMb")]
    memory_mb: Option<u64>,
    gpu: Option<bool>,
    #[serde(rename = "storagePath")]
    storage_path: Option<String>,
    #[serde(rename = "portMappings")]
    port_mappings: Option<Vec<RawPortMapping>>,
}

#[derive(Deserialize, Default)]
#[serde(default)]
struct RawLxc {
    distribution: Option<String>,
    release: Option<String>,
}

#[derive(Deserialize, Default)]
#[serde(default)]
struct RawProcess {
    #[serde(rename = "commandLine")]
    command_line: Option<String>,
    cwd: Option<String>,
    env: Option<Vec<String>>,
    timeout: Option<u32>,
}

#[derive(Deserialize, Default)]
#[serde(default)]
struct RawLifecycle {
    #[serde(rename = "destroyOnExit")]
    destroy_on_exit: Option<bool>,
    #[serde(rename = "preservePolicy")]
    preserve_policy: Option<bool>,
}

#[derive(Deserialize, Default)]
#[serde(default)]
struct RawTestFeature {
    message: Option<String>,
}

#[derive(Deserialize, Default)]
#[serde(default)]
struct RawIsolationSession {
    #[serde(rename = "configurationId")]
    configuration_id: Option<String>,
    user: Option<IsolationSessionUser>,
}

#[derive(Deserialize, Default)]
#[serde(default)]
struct RawSeatbelt {
    #[serde(rename = "profileOverride")]
    profile_override: Option<String>,
    #[serde(rename = "guiAccess")]
    gui_access: Option<bool>,
    #[serde(rename = "launchMethod")]
    launch_method: Option<crate::models::LaunchMethod>,
    #[serde(rename = "nestedPty")]
    nested_pty: Option<bool>,
    #[serde(rename = "keychainAccess")]
    keychain_access: Option<bool>,
    #[serde(rename = "extraMachLookups")]
    extra_mach_lookups: Option<Vec<String>>,
}

#[derive(Deserialize, Default)]
#[serde(default)]
struct RawExperimental {
    test: Option<RawTestFeature>,
    #[serde(rename = "windows_sandbox")]
    windows_sandbox: Option<RawSandbox>,
    wslc: Option<RawContainerConfig>,
    #[serde(rename = "isolation_session")]
    isolation_session: Option<RawIsolationSession>,
    #[serde(alias = "macos_sandbox")]
    seatbelt: Option<RawSeatbelt>,
}

#[derive(Deserialize, Default)]
#[serde(default)]
struct RawUi {
    disable: Option<bool>,
    clipboard: Option<String>,
    injection: Option<bool>,
}

#[derive(Deserialize, Default)]
#[serde(default)]
struct RawConfig {
    version: Option<String>,
    #[serde(rename = "containerId")]
    container_id: Option<String>,
    process: Option<RawProcess>,
    lifecycle: Option<RawLifecycle>,
    containment: Option<String>,
    #[serde(rename = "processContainer", alias = "appContainer")]
    process_container: Option<RawProcessContainer>,
    lxc: Option<RawLxc>,
    filesystem: Option<RawFilesystem>,
    fallback: Option<RawFallback>,
    network: Option<RawNetwork>,
    ui: Option<RawUi>,
    experimental: Option<RawExperimental>,
    /// Top-level seatbelt config.
    #[serde(alias = "macos_sandbox")]
    seatbelt: Option<RawSeatbelt>,
    // Captures any top-level key not matched above so unrecognised fields can
    // be rejected at the trust boundary instead of being silently dropped.
    // `IgnoredAny` discards each value during deserialisation, so a large or
    // complex unknown section costs nothing beyond its key. Allowed annotation
    // keys ($schema, _comment) are filtered out in
    // `reject_unknown_top_level_fields`.
    #[serde(flatten)]
    unknown: HashMap<String, IgnoredAny>,
}

// State-aware request shape. `phase` is required (no `#[serde(default)]` on
// the struct, no field-level default) and acts as the discriminator against
// `RawConfig`; the other fields mirror `RawConfig`'s wire shape so
// cross-cutting fields (filesystem/network/ui/process) populate the inner
// `ExecutionRequest` via the same conversion path. The `experimental` block stays
// raw — typed deserialisation happens at dispatch time keyed by backend.
#[derive(Deserialize)]
struct RawStateAwareRequest {
    #[serde(default)]
    version: Option<String>,
    #[serde(rename = "containerId", default)]
    container_id: Option<String>,
    #[serde(default)]
    containment: Option<String>,
    phase: String,
    #[serde(rename = "sandboxId", default)]
    sandbox_id: Option<String>,
    #[serde(default)]
    process: Option<RawProcess>,
    #[serde(default)]
    filesystem: Option<RawFilesystem>,
    #[serde(default)]
    fallback: Option<RawFallback>,
    #[serde(default)]
    network: Option<RawNetwork>,
    #[serde(default)]
    ui: Option<RawUi>,
    #[serde(default)]
    experimental: Option<serde_json::Value>,
    // See `RawConfig::unknown`. Mirrored here so unrecognised top-level keys are
    // rejected on the state-aware path too.
    #[serde(flatten)]
    unknown: HashMap<String, IgnoredAny>,
}

// Untagged enum: serde tries `StateAware` first (requires `phase`), falls
// through to `OneShot` when `phase` is absent. Order matters — `OneShot` is
// permissive enough to accept arbitrary wire shapes. Both variants are boxed
// so the enum stays a single tagged pointer regardless of inner growth.
#[derive(Deserialize)]
#[serde(untagged)]
enum RawMxcRequest {
    StateAware(Box<RawStateAwareRequest>),
    OneShot(Box<RawConfig>),
}

// ---------- Public API ----------

/// Parse the `proxy` field.
///
/// Accepts either `{ "localhost": <port> }` for an external localhost proxy,
/// `{ "builtinTestServer": true }` to have wxc launch its own test proxy,
/// or `{ "url": "<url>" }` for a proxy URL (parsed into host:port).
/// When `builtinTestServer` is set it must be the only key in the object.
fn parse_proxy_config(value: &serde_json::Value) -> Result<ProxyConfig, WxcError> {
    let obj = value
        .as_object()
        .ok_or_else(|| WxcError::ConfigParse("network.proxy must be an object".to_string()))?;

    let mut proxy_addr = ProxyAddress::new("127.0.0.1".to_string(), 0);

    if let Some(builtin_value) = obj.get("builtinTestServer") {
        if builtin_value.as_bool() != Some(true) {
            return Err(WxcError::ConfigParse(
                "network.proxy.builtinTestServer must be true when present".to_string(),
            ));
        }
        if obj.len() != 1 {
            return Err(WxcError::ConfigParse(
                "When builtinTestServer is true, no other proxy options may be set".to_string(),
            ));
        }

        return Ok(ProxyConfig {
            address: Some(proxy_addr),
            builtin_test_server: true,
        });
    }

    if let Some(localhost) = obj.get("localhost") {
        let port_val = if let Some(port) = localhost.as_u64() {
            port
        } else {
            return Err(WxcError::ConfigParse(
                "network.proxy.localhost must be a number".to_string(),
            ));
        };

        if port_val == 0 || port_val > 65535 {
            return Err(WxcError::ConfigParse(
                "network.proxy.localhost must be a port between 1 and 65535".to_string(),
            ));
        }

        // Non builtin proxy with localhost and port specified
        proxy_addr.port = port_val as u16;
        return Ok(ProxyConfig {
            address: Some(proxy_addr),
            builtin_test_server: false,
        });
    }

    if let Some(url_value) = obj.get("url") {
        let url_str = url_value.as_str().ok_or_else(|| {
            WxcError::ConfigParse("network.proxy.url must be a string".to_string())
        })?;

        let parsed = url::Url::parse(url_str)
            .map_err(|e| WxcError::ConfigParse(format!("network.proxy.url is invalid: {e}")))?;

        let host = parsed.host_str().ok_or_else(|| {
            WxcError::ConfigParse(format!(
                "network.proxy.url must include a host (e.g., http://localhost:8080), got: {url_str}"
            ))
        })?.to_string();
        let port = parsed.port().ok_or_else(|| {
            WxcError::ConfigParse(format!(
                "network.proxy.url must include a port (e.g., http://localhost:8080), got: {url_str}"
            ))
        })?;

        return Ok(ProxyConfig {
            address: Some(ProxyAddress::from_url(url_str, host, port)),
            builtin_test_server: false,
        });
    }

    Err(WxcError::ConfigParse(
        "network.proxy must specify builtinTestServer, localhost, or url".to_string(),
    ))
}

/// Options for [`load_mxc_request_with_options`].
///
/// Kept as a struct (rather than additional positional arguments) so future
/// loader-tuning knobs can be threaded through without re-spinning every
/// caller.
#[derive(Debug, Clone, Copy, Default)]
pub struct LoadOptions {
    /// Treat `input` as a base64-encoded JSON blob rather than a file path.
    pub is_base64: bool,
    /// Allow `process.commandLine` to be absent or empty in the policy.
    ///
    /// The driver sets this when it has a CLI-provided command-line
    /// override to splice into `script_code` after parsing. Without it,
    /// missing/empty `commandLine` is a hard parse error in one-shot
    /// and state-aware exec requests (matching the legacy contract).
    pub allow_missing_command: bool,
}

/// Loads and parses a JSON-based code execution request.
///
/// If `is_base64` is true, `input` is treated as a base64-encoded JSON string.
/// Otherwise `input` is treated as a file path.
pub fn load_request(
    input: &str,
    logger: &mut Logger,
    is_base64: bool,
) -> Result<ExecutionRequest, WxcError> {
    load_request_with_options(
        input,
        logger,
        LoadOptions {
            is_base64,
            allow_missing_command: false,
        },
    )
}

/// Options-aware variant of [`load_request`] used by drivers that may
/// override `process.commandLine` from the CLI. See [`LoadOptions`].
pub fn load_request_with_options(
    input: &str,
    logger: &mut Logger,
    opts: LoadOptions,
) -> Result<ExecutionRequest, WxcError> {
    let json_str = decode_request_input(input, logger, opts.is_base64)?;

    let raw: RawConfig = serde_json::from_str(&json_str).map_err(|e| {
        logger.log_line("Error parsing JSON");
        WxcError::ConfigParse(format!("JSON parse error: {}", e))
    })?;

    convert_raw_config_inner(raw, logger, true, opts.allow_missing_command)
}

/// Loads a request and routes to the one-shot or state-aware path based on
/// presence of the wire-format `phase` field. Errors are categorised so the
/// driver can pick the right output convention per path (envelope on stdout
/// for state-aware, diagnostic on stderr for one-shot and pre-discrimination
/// failures).
pub fn load_mxc_request(
    input: &str,
    logger: &mut Logger,
    is_base64: bool,
) -> Result<MxcRequest, ParseError> {
    load_mxc_request_with_options(
        input,
        logger,
        LoadOptions {
            is_base64,
            allow_missing_command: false,
        },
    )
}

/// Options-aware variant of [`load_mxc_request`]. When
/// `LoadOptions::allow_missing_command` is set, a missing or empty
/// `process.commandLine` in the policy is tolerated and `script_code`
/// is left empty for the driver to fill in from a CLI override.
pub fn load_mxc_request_with_options(
    input: &str,
    logger: &mut Logger,
    opts: LoadOptions,
) -> Result<MxcRequest, ParseError> {
    let json_str =
        decode_request_input(input, logger, opts.is_base64).map_err(ParseError::Decode)?;

    let raw: RawMxcRequest = serde_json::from_str(&json_str).map_err(|e| {
        logger.log_line("Error parsing JSON");
        ParseError::Decode(WxcError::ConfigParse(format!("JSON parse error: {}", e)))
    })?;

    match raw {
        RawMxcRequest::StateAware(state_aware) => {
            convert_raw_state_aware(*state_aware, logger, opts.allow_missing_command)
                .map(MxcRequest::StateAware)
                .map_err(|e| ParseError::StateAware(MxcError::malformed_request(e.to_string())))
        }
        RawMxcRequest::OneShot(one_shot) => {
            convert_raw_config_inner(*one_shot, logger, true, opts.allow_missing_command)
                .map(MxcRequest::OneShot)
                .map_err(ParseError::OneShot)
        }
    }
}

/// Reads a request from disk or decodes it from base64. Public so the driver
/// can decode once and reuse the JSON across multiple parse attempts; the
/// internal `load_request` and `load_mxc_request` use it too.
pub fn decode_request_input(
    input: &str,
    logger: &mut Logger,
    is_base64: bool,
) -> Result<String, WxcError> {
    if is_base64 {
        let bytes = base64_decode(input).map_err(|_| {
            let msg = "Failed to decode base64 configuration";
            logger.log_line(msg);
            WxcError::ConfigParse(msg.to_string())
        })?;
        String::from_utf8(bytes).map_err(|_| {
            let msg = "Base64 decoded content is not valid UTF-8";
            logger.log_line(msg);
            WxcError::ConfigParse(msg.to_string())
        })
    } else {
        if !std::path::Path::new(input).exists() {
            let _ = write!(logger, "Configuration file not found: {}", input);
            return Err(WxcError::ConfigParse(format!(
                "Configuration file not found: {}",
                input
            )));
        }
        fs::read_to_string(input).map_err(|e| {
            let _ = write!(logger, "Failed to open configuration file: {}", input);
            WxcError::ConfigParse(format!("Failed to read configuration file: {}", e))
        })
    }
}

// ---------- Cross-field validation ----------

/// Maximum supported schema version (major.minor). Configs with a higher major.minor are rejected.
const SUPPORTED_VERSION: &str = ">=0.4, <=0.7";

/// Canonical "latest" schema version string used in samples and tests. Bump
/// alongside `SUPPORTED_VERSION`'s upper bound when a new dev schema lands.
#[cfg(test)]
const CURRENT_SCHEMA_VERSION: &str = "0.7.0-alpha";

/// The minimum schema version that implies BaseContainer backend usage.
const BASE_CONTAINER_MIN_VERSION: &str = "0.5.0";

/// Known `experimental.<backend>` keys. Used by validation code to flag
/// experimental backend sections that don't match the selected
/// `containment`. Add a new entry when promoting a backend to a top-level
/// section or graduating one from experimental.
const KNOWN_EXPERIMENTAL_BACKENDS: &[&str] = &["windows_sandbox", "wslc", "isolation_session"];

/// Returns `true` if `version` is a BaseContainer-era schema version (>= 0.5.0).
///
/// Pre-release labels are stripped before comparison, so `"0.5.0-alpha"` is
/// treated identically to `"0.5.0"`.  Returns `false` for empty or
/// unparseable version strings.
pub fn is_base_container_version(version: &str) -> bool {
    if version.is_empty() {
        return false;
    }
    let parsed = match semver::Version::parse(version) {
        Ok(v) => v,
        Err(_) => return false,
    };
    let comparable = semver::Version::new(parsed.major, parsed.minor, parsed.patch);
    let threshold = semver::Version::parse(BASE_CONTAINER_MIN_VERSION).unwrap();
    comparable >= threshold
}

/// Validate that the schema version (semver) is supported by this binary.
/// Compares major.minor only — patch and pre-release labels are ignored.
fn validate_schema_version(version: &str, logger: &mut Logger) -> Result<(), WxcError> {
    if version.is_empty() {
        return Ok(());
    }

    // Parse the version, stripping pre-release suffix for comparison
    // (e.g., "0.4.0-alpha" is treated as "0.4.0")
    let parsed = semver::Version::parse(version).map_err(|_| {
        let msg = format!(
            "Invalid schema version '{}': must be semver (e.g., 'X.Y.Z' or 'X.Y.Z-alpha')",
            version
        );
        logger.log_line(&msg);
        WxcError::ConfigParse(msg)
    })?;

    let req = semver::VersionReq::parse(SUPPORTED_VERSION).unwrap();

    // semver crate treats pre-release as lower precedence, so we compare
    // against a version without the pre-release label for major.minor check.
    let comparable = semver::Version::new(parsed.major, parsed.minor, parsed.patch);
    if !req.matches(&comparable) {
        let min = semver::VersionReq::parse(">=0.4").unwrap();
        let msg = if !min.matches(&comparable) {
            format!(
                "Config schema version '{}' is older than supported (supported: {}). Update your config.",
                version, SUPPORTED_VERSION
            )
        } else {
            format!(
                "Config schema version '{}' is newer than supported (supported: {}). Upgrade wxc-exec.",
                version, SUPPORTED_VERSION
            )
        };
        logger.log_line(&msg);
        return Err(WxcError::ConfigParse(msg));
    }
    Ok(())
}

fn validate_filesystem_paths(
    policy: &ContainerPolicy,
    logger: &mut Logger,
) -> Result<(), WxcError> {
    validate_paths(&policy.readonly_paths, logger)?;
    validate_paths(&policy.readwrite_paths, logger)?;
    validate_paths(&policy.denied_paths, logger)?;
    Ok(())
}

fn validate_paths(paths: &[String], logger: &mut Logger) -> Result<(), WxcError> {
    for path in paths {
        if path.contains('"') {
            let msg = format!("Filesystem path '{}' contains invalid character '\"'", path);
            logger.log_line(&msg);
            return Err(WxcError::ConfigParse(msg));
        }
    }
    Ok(())
}

// ---------- Conversion from raw JSON to domain model ----------

/// Top-level keys that are permitted but carry no semantic meaning: `$schema`
/// (editor hint) and `_comment` (human annotation). They are accepted at the
/// trust boundary but ignored by the model.
const ALLOWED_TOP_LEVEL_ANNOTATIONS: &[&str] = &["$schema", "_comment"];

/// Rejects unrecognised top-level fields captured by a `#[serde(flatten)]` map.
///
/// This is the structural half of schema enforcement at the trust boundary:
/// typos and silently-dropped fields (for example `fileSystem` instead of
/// `filesystem`, or a stray `policy` block) now fail loudly with a precise
/// error instead of being ignored, which previously meant the associated
/// policy was never applied.
fn reject_unknown_top_level_fields<V>(
    unknown: &HashMap<String, V>,
    logger: &mut Logger,
) -> Result<(), WxcError> {
    let mut keys: Vec<&str> = unknown
        .keys()
        .map(String::as_str)
        .filter(|k| !ALLOWED_TOP_LEVEL_ANNOTATIONS.contains(k))
        .collect();
    if keys.is_empty() {
        return Ok(());
    }
    keys.sort_unstable();
    let msg = format!(
        "Unknown top-level field(s) in config: {}. Remove them or check for typos \
         (field names are case-sensitive, e.g. 'filesystem' not 'fileSystem').",
        keys.join(", ")
    );
    logger.log_line(&msg);
    Err(WxcError::ConfigParse(msg))
}

fn present_backend_sections(raw: &RawConfig) -> Vec<&'static str> {
    let mut sections: Vec<&'static str> = Vec::new();
    let mut push = |backend: ContainmentBackend| {
        if let Some(path) = backend.section_path() {
            sections.push(path);
        }
    };
    if raw.process_container.is_some() {
        push(ContainmentBackend::ProcessContainer);
    }
    if raw.lxc.is_some() {
        push(ContainmentBackend::Lxc);
    }
    if raw.seatbelt.is_some() {
        push(ContainmentBackend::Seatbelt);
    }
    if let Some(experimental) = raw.experimental.as_ref() {
        if experimental.windows_sandbox.is_some() {
            push(ContainmentBackend::WindowsSandbox);
        }
        if experimental.wslc.is_some() {
            push(ContainmentBackend::Wslc);
        }
        if experimental.isolation_session.is_some() {
            push(ContainmentBackend::IsolationSession);
        }
    }
    sections
}

fn validate_single_backend_section(
    containment: ContainmentBackend,
    present_sections: &[&'static str],
    logger: &mut Logger,
) -> Result<(), WxcError> {
    let allowed_section = containment.section_path();
    let extras: Vec<&'static str> = present_sections
        .iter()
        .copied()
        .filter(|section| Some(*section) != allowed_section)
        .collect();
    if extras.is_empty() {
        return Ok(());
    }

    let containment_wire = containment.wire_name();
    let msg = match allowed_section {
        Some(name) => format!(
            "Multiple containment backends configured: 'containment' is '{containment_wire}' \
             (allows the '{name}' section), but the config also includes unrelated \
             backend section(s): {}. Only one backend section is allowed; remove the unused \
             section(s).",
            extras.join(", "),
        ),
        None => format!(
            "Multiple containment backends configured: 'containment' is '{containment_wire}' \
             (no per-backend section is defined for this backend), but the config includes \
             backend section(s): {}. Only one backend section is allowed; remove the unused \
             section(s).",
            extras.join(", "),
        ),
    };
    logger.log_line(&msg);
    Err(WxcError::ConfigParse(msg))
}

/// Rejects `experimental.<backend>` keys that don't match the resolved
/// `containment`. When `containment` is `None` (state-aware non-provision
/// phases can resolve the backend from `sandboxId`), a single key is
/// allowed; two or more is unambiguously wrong.
fn validate_experimental_backend_keys(
    containment: Option<&ContainmentBackend>,
    experimental_raw: Option<&serde_json::Value>,
    logger: &mut Logger,
) -> Result<(), WxcError> {
    let Some(serde_json::Value::Object(map)) = experimental_raw else {
        return Ok(());
    };

    let matching_key = containment
        .and_then(|c| c.section_path())
        .and_then(|path| path.strip_prefix("experimental."));

    let present: Vec<&'static str> = KNOWN_EXPERIMENTAL_BACKENDS
        .iter()
        .copied()
        .filter(|key| map.contains_key(*key))
        .collect();

    let rejected: Vec<&'static str> = match matching_key {
        Some(allowed) => present.into_iter().filter(|k| *k != allowed).collect(),
        None if present.len() > 1 => present,
        None => return Ok(()),
    };

    if rejected.is_empty() {
        return Ok(());
    }

    let qualified: Vec<String> = rejected
        .iter()
        .map(|k| format!("experimental.{k}"))
        .collect();
    let msg = format!(
        "Multiple containment backends configured: request includes \
         experimental backend section(s) {}. Only one backend section is allowed; \
         remove the unused section(s).",
        qualified.join(", "),
    );
    logger.log_line(&msg);
    Err(WxcError::ConfigParse(msg))
}

// `require_process = false` allows state-aware non-exec phases to omit the
// `process` block entirely; those phases leave `script_code` / `working_directory`
// / `script_timeout` / `env` at their defaults and never read them.
//
/// Convert a raw seatbelt JSON block into the validated domain struct.
fn make_seatbelt_config(raw_sb: RawSeatbelt) -> SeatbeltConfig {
    SeatbeltConfig {
        profile_override: raw_sb.profile_override,
        gui_access: raw_sb.gui_access.unwrap_or(false),
        launch_method: raw_sb.launch_method.unwrap_or_default(),
        nested_pty: raw_sb.nested_pty.unwrap_or(true),
        keychain_access: raw_sb.keychain_access.unwrap_or(false),
        extra_mach_lookups: raw_sb.extra_mach_lookups.unwrap_or_default(),
    }
}

// `allow_missing_command` further relaxes the `require_process == true` arms
// so that a CLI command-line override (provided by the driver after parsing)
// can stand in for `process.commandLine`. When set, a missing or empty
// `commandLine` is silently accepted and `script_code` is left empty.
fn convert_raw_config_inner(
    raw: RawConfig,
    logger: &mut Logger,
    require_process: bool,
    allow_missing_command: bool,
) -> Result<ExecutionRequest, WxcError> {
    // Reject unrecognised top-level fields before anything else, so typos and
    // stray sections fail loudly instead of being silently ignored.
    reject_unknown_top_level_fields(&raw.unknown, logger)?;

    // Captured before `raw` fields are moved out below.
    let present_backend_sections = present_backend_sections(&raw);

    // New top-level fields
    let schema_version = raw.version.unwrap_or_default();

    // Validate the schema version up front so an unsupported version fails fast,
    // before any of the per-section conversion work below.
    validate_schema_version(&schema_version, logger)?;

    let container_id = raw.container_id.unwrap_or_default();

    // Process section: required for one-shot and for state-aware exec; absent
    // is allowed for state-aware non-exec phases (require_process == false)
    // or when the driver has signalled a CLI command-line override is
    // present via `allow_missing_command`.
    let command_required = require_process && !allow_missing_command;
    let (script_code, working_directory, script_timeout, env) = match raw.process {
        Some(process) => {
            let script_code = match process.command_line {
                Some(s) if !s.is_empty() => s,
                Some(_) if command_required => {
                    logger.log_line("process.commandLine cannot be empty");
                    return Err(WxcError::ConfigParse(
                        "process.commandLine cannot be empty".to_string(),
                    ));
                }
                None if command_required => {
                    logger.log_line("Missing required field: process.commandLine");
                    return Err(WxcError::ConfigParse(
                        "Missing required field: process.commandLine".to_string(),
                    ));
                }
                _ => String::new(),
            };

            // Null bytes can be used to hide malicious payloads from audit logs or
            // other inspection.
            if script_code.contains('\0') {
                return Err(WxcError::ConfigParse(
                    "process.commandLine must not contain null bytes".to_string(),
                ));
            }

            (
                script_code,
                process.cwd.unwrap_or_default(),
                process.timeout.unwrap_or(0),
                process.env.unwrap_or_default(),
            )
        }
        None if command_required => {
            return Err(WxcError::ConfigParse(
                "'process' section is required".into(),
            ));
        }
        None => (String::new(), String::new(), 0, Vec::new()),
    };

    // Containment backend selection.
    //
    // The `containment` wire field is dual-purpose: callers may pass either
    //   (a) an abstract intent (e.g. "process") that names a *kind* of
    //       isolation and lets the binary pick the host-appropriate runner,
    //   or
    //   (b) a concrete backend id (e.g. "processcontainer", "lxc", "seatbelt")
    //       that pins the runner explicitly.
    //
    // Both forms target the same internal `ContainmentBackend` enum. The
    // match below recognises every concrete id verbatim and resolves the
    // abstract intents into the appropriate concrete variant per
    // target_os. Any future concrete-only backend just needs an arm; any
    // future abstract intent should resolve here (and likewise in
    // `parse_containment_str` below for the state-aware path).
    //
    // Default resolution (omitted `containment`) and the abstract intent
    // `"process"` map to the OS-native process sandbox on each platform:
    //   * Windows -> ProcessContainer (AppContainer)
    //   * macOS   -> Seatbelt
    //   * Linux   -> Bubblewrap (lightweight, unprivileged process sandbox)
    // LXC is treated as a full Linux container and is only selected when
    // explicitly requested via `"lxc"`; `"processcontainer"` continues to
    // route to ProcessContainer (which `lxc-exec` falls back to LXC for).
    let containment = match raw.containment.as_deref() {
        None => {
            #[cfg(target_os = "linux")]
            {
                ContainmentBackend::Bubblewrap
            }
            #[cfg(target_os = "macos")]
            {
                ContainmentBackend::Seatbelt
            }
            #[cfg(not(any(target_os = "linux", target_os = "macos")))]
            {
                ContainmentBackend::ProcessContainer
            }
        }
        Some("processcontainer") => ContainmentBackend::ProcessContainer,
        Some("appcontainer") => {
            logger.log_line(
                "[deprecated] containment value 'appcontainer' is a legacy alias for 'processcontainer'; \
                 update your config to use 'processcontainer' (the 'appcontainer' alias may be removed in a future schema version).",
            );
            ContainmentBackend::ProcessContainer
        }
        Some("process") => {
            // Abstract intent: the caller wants the OS-native process
            // sandbox. Resolves to ProcessContainer on Windows, Bubblewrap
            // on Linux, and Seatbelt on macOS. Callers who want LXC (a
            // full container) must request it explicitly via "lxc".
            #[cfg(target_os = "linux")]
            {
                ContainmentBackend::Bubblewrap
            }
            #[cfg(target_os = "macos")]
            {
                ContainmentBackend::Seatbelt
            }
            #[cfg(not(any(target_os = "linux", target_os = "macos")))]
            {
                ContainmentBackend::ProcessContainer
            }
        }
        Some("windows_sandbox") => ContainmentBackend::WindowsSandbox,
        Some("wslc") => ContainmentBackend::Wslc,
        Some("lxc") => ContainmentBackend::Lxc,
        Some("vm") => {
            // Abstract intent: full hardware-virtualised VM isolation.
            // Today the only concrete VM backend is Windows Sandbox; on
            // non-Windows targets we fall through to the historical
            // `Vm` variant which the host binaries surface as an
            // explicit "not implemented" error.
            #[cfg(target_os = "windows")]
            {
                ContainmentBackend::WindowsSandbox
            }
            #[cfg(not(target_os = "windows"))]
            {
                ContainmentBackend::Vm
            }
        }
        Some("microvm") => ContainmentBackend::MicroVm,
        Some("isolation_session") => ContainmentBackend::IsolationSession,
        Some("seatbelt") => ContainmentBackend::Seatbelt,
        Some("macos_sandbox") => {
            logger.log_line(
                "[deprecated] containment value 'macos_sandbox' is a legacy alias for 'seatbelt'; \
                 update your config to use 'seatbelt' (the 'macos_sandbox' alias may be removed in a future schema version).",
            );
            ContainmentBackend::Seatbelt
        }
        Some("hyperlight") => ContainmentBackend::Hyperlight,
        Some("bubblewrap") => ContainmentBackend::Bubblewrap,
        Some(other) => {
            let msg = format!(
                "Invalid containment value '{}' (must be 'process', 'processcontainer', 'windows_sandbox', 'isolation_session', 'wslc', 'lxc', 'vm', 'microvm', 'seatbelt', 'hyperlight', or 'bubblewrap')",
                other
            );
            logger.log_line(&msg);
            return Err(WxcError::ConfigParse(msg));
        }
    };

    validate_single_backend_section(containment.clone(), &present_backend_sections, logger)?;

    // LXC configuration
    let lxc_config = {
        let raw_lxc = raw.lxc.unwrap_or_default();
        LxcConfig {
            distribution: raw_lxc.distribution.unwrap_or_default(),
            release: raw_lxc.release.unwrap_or_default(),
        }
    };

    let mut policy = ContainerPolicy::default();

    // ProcessContainer section. Holds settings that apply to the Windows
    // process-level backend regardless of whether the runner picks the
    // legacy AppContainer implementation (which honors `capabilities`,
    // `learningMode`, `leastPrivilege`) or the newer BaseContainer
    // implementation (which honors `ui`).
    if let Some(ac) = raw.process_container {
        if let Some(lp) = ac.least_privilege {
            policy.least_privilege_mode = lp;
        }

        // learningMode handling differs between debug and release
        if ac.learning_mode.unwrap_or(false) {
            #[cfg(debug_assertions)]
            {
                policy
                    .capabilities
                    .push("permissiveLearningMode".to_string());
                logger.log("WARNING: 'learningMode' enabled - AppContainer restrictions will NOT be enforced (DEBUG BUILD ONLY)\n");
            }
            #[cfg(not(debug_assertions))]
            {
                logger.log("SECURITY: 'learningMode' is disabled in release builds. This capability has been removed.\n");
            }
        }

        // Add explicit capabilities
        if let Some(caps) = ac.capabilities {
            policy.capabilities.extend(caps);
        }

        // SECURITY: Strip permissiveLearningMode in release builds
        #[cfg(not(debug_assertions))]
        {
            policy.capabilities.retain(|cap| {
                if cap == "permissiveLearningMode" {
                    logger.log("SECURITY: Removed 'permissiveLearningMode' capability (not allowed in release builds)\n");
                    false
                } else {
                    true
                }
            });
        }

        // BaseProcessContainer-specific UI config
        if let Some(raw_ui) = ac.ui {
            policy.base_process_ui.isolation =
                raw_ui.isolation.unwrap_or_else(|| "container".to_string());
            policy.base_process_ui.desktop_system_control =
                raw_ui.desktop_system_control.unwrap_or(false);
            policy.base_process_ui.system_settings =
                raw_ui.system_settings.unwrap_or_else(|| "none".to_string());
            policy.base_process_ui.ime = raw_ui.ime.unwrap_or(false);
        }
    }

    // Filesystem section
    if let Some(fscfg) = raw.filesystem {
        if let Some(v) = fscfg.denied_paths {
            policy.denied_paths = v;
        }
        if let Some(v) = fscfg.readwrite_paths {
            policy.readwrite_paths = v;
        }
        if let Some(v) = fscfg.readonly_paths {
            policy.readonly_paths = v;
        }
    }
    validate_filesystem_paths(&policy, logger)?;

    // Fallback section
    if let Some(fbcfg) = raw.fallback {
        if let Some(v) = fbcfg.allow_dacl_mutation {
            policy.fallback.allow_dacl_mutation = v;
        }
    }

    // Network section
    if let Some(net) = raw.network {
        if let Some(proxy_value) = net.proxy {
            let proxy_config = parse_proxy_config(&proxy_value)?;
            if proxy_config.is_enabled()
                && containment != ContainmentBackend::ProcessContainer
                && containment != ContainmentBackend::Bubblewrap
            {
                let msg = "Network proxy is only supported with the 'processcontainer' \
                           or 'bubblewrap' containment backends";
                logger.log_line(msg);
                return Err(WxcError::ConfigParse(msg.to_string()));
            }
            policy.network_proxy = proxy_config;
        }

        if let Some(p) = net.default_policy {
            policy.default_network_policy = match p.as_str() {
                "allow" => NetworkPolicy::Allow,
                "block" => NetworkPolicy::Block,
                other => {
                    let msg = format!(
                        "Invalid network.defaultPolicy value '{}' (must be 'allow' or 'block')",
                        other
                    );
                    logger.log_line(&msg);
                    return Err(WxcError::ConfigParse(msg));
                }
            };
        }

        if let Some(m) = net.enforcement_mode {
            policy.network_enforcement_mode = match m.as_str() {
                "capabilities" => NetworkEnforcementMode::Capabilities,
                "firewall" => NetworkEnforcementMode::Firewall,
                "both" => NetworkEnforcementMode::Both,
                other => {
                    let msg = format!(
                        "Invalid network.enforcementMode value '{}' (must be 'capabilities', 'firewall', or 'both')",
                        other
                    );
                    logger.log_line(&msg);
                    return Err(WxcError::ConfigParse(msg));
                }
            };
        }

        if let Some(v) = net.allow_local_network {
            policy.allow_local_network = v;
        }

        if let Some(v) = net.allowed_hosts {
            policy.allowed_hosts = v;
        }
        if let Some(v) = net.blocked_hosts {
            policy.blocked_hosts = v;
        }

        // Bubblewrap is unprivileged by design; iptables-based enforcement
        // (firewall / both) requires CAP_NET_ADMIN, which defeats the
        // backend's privilege story. Reject the combination explicitly so
        // users get a clear error instead of an opaque runtime failure.
        if containment == ContainmentBackend::Bubblewrap
            && policy.network_proxy.is_enabled()
            && matches!(
                policy.network_enforcement_mode,
                NetworkEnforcementMode::Firewall | NetworkEnforcementMode::Both
            )
        {
            let msg = "Bubblewrap: network.proxy cannot be combined with \
                       network.enforcementMode='firewall' or 'both'. The cooperative \
                       env-var proxy enforces hosts at the proxy layer; iptables-based \
                       enforcement requires privilege and is mutually exclusive.";
            logger.log_line(msg);
            return Err(WxcError::ConfigParse(msg.to_string()));
        }

        // External proxy (`network.proxy.url` / `network.proxy.localhost`)
        // enforces its own policy — the runner does NOT forward
        // `allowedHosts` / `blockedHosts` / `defaultPolicy` to it. Reject
        // configs that combine an external proxy with host lists or a
        // restrictive default, otherwise users get a silently weaker
        // enforcement than a no-proxy `defaultPolicy: "block"` config
        // would have produced.
        if containment == ContainmentBackend::Bubblewrap
            && policy.network_proxy.is_enabled()
            && !policy.network_proxy.builtin_test_server
            && (!policy.allowed_hosts.is_empty()
                || !policy.blocked_hosts.is_empty()
                || policy.default_network_policy == NetworkPolicy::Block)
        {
            let msg = "Bubblewrap: an external network.proxy (url/localhost) cannot be \
                       combined with allowedHosts, blockedHosts, or defaultPolicy='block'. \
                       The external proxy is expected to enforce its own host policy; \
                       MXC does not forward host lists to it. Use \
                       'network.proxy.builtinTestServer: true' (testing only) for \
                       MXC-enforced host filtering, or remove the host policy.";
            logger.log_line(msg);
            return Err(WxcError::ConfigParse(msg.to_string()));
        }

        // Cooperative-model warning: when the builtin test proxy is paired
        // with `defaultPolicy: "block"` and no allowlist, well-behaved
        // HTTP clients are denied at the proxy, but raw-socket clients
        // (anything that ignores HTTP_PROXY/HTTPS_PROXY) still reach the
        // host network because the sandbox shares the host netns in proxy
        // mode. Surface this at config-validation time so users porting a
        // working hard-block config don't silently lose enforcement when
        // they add a proxy block.
        if containment == ContainmentBackend::Bubblewrap
            && policy.network_proxy.is_enabled()
            && policy.default_network_policy == NetworkPolicy::Block
            && policy.allowed_hosts.is_empty()
            && policy.blocked_hosts.is_empty()
        {
            logger.log_line(
                "WARNING: Bubblewrap network.proxy with defaultPolicy='block' is \
                 cooperative. HTTP_PROXY-aware clients (curl, requests, etc.) are \
                 denied at the proxy, but raw-socket clients that ignore HTTP_PROXY \
                 bypass the proxy and reach the host network. For strict isolation \
                 of all clients, remove network.proxy so --unshare-net applies; for \
                 host-list enforcement, add allowedHosts (cooperative tools only).",
            );
        }
    }

    // Lifecycle section
    let lifecycle = {
        let lc = raw.lifecycle.unwrap_or_default();
        let destroy_on_exit = lc.destroy_on_exit.unwrap_or(true);
        let preserve_policy = lc.preserve_policy.unwrap_or(false);

        LifecycleConfig {
            destroy_on_exit,
            preserve_policy,
        }
    };

    // Experimental section (parsed but only applied when --experimental flag is set)
    let experimental = if let Some(raw_exp) = raw.experimental {
        let test = raw_exp.test.map(|t| TestFeatureConfig::from_raw(t.message));
        let windows_sandbox = raw_exp.windows_sandbox.map(|sb| {
            let mut config = WindowsSandboxConfig::default();
            if let Some(t) = sb.idle_timeout_ms.or(sb.idle_timeout) {
                config.idle_timeout_ms = t;
            }
            if let Some(name) = sb.daemon_pipe_name {
                config.daemon_pipe_name = name;
            }
            config
        });
        let wslc = if let Some(cc) = raw_exp.wslc {
            let mut config = WslcConfig::default();
            if let Some(os) = cc.target_os {
                config.target_os = os;
            }
            if let Some(img) = cc.image {
                config.image = img;
            }
            config.image_tar_path = cc.image_tar_path;
            config.cpu_count = cc.cpu_count;
            config.memory_mb = cc.memory_mb;
            if let Some(gpu) = cc.gpu {
                config.gpu = gpu;
            }
            config.storage_path = cc.storage_path;
            if let Some(mappings) = cc.port_mappings {
                let mut converted = Vec::with_capacity(mappings.len());
                for m in mappings {
                    if m.windows_port == 0 || m.container_port == 0 {
                        return Err(WxcError::ConfigParse(format!(
                            "experimental.wslc.portMappings: port 0 is not a valid forward (windowsPort={}, containerPort={})",
                            m.windows_port, m.container_port
                        )));
                    }
                    let protocol = m.protocol.unwrap_or_else(|| "tcp".to_string());
                    if protocol != "tcp" && protocol != "udp" {
                        return Err(WxcError::ConfigParse(format!(
                            "experimental.wslc.portMappings: protocol must be 'tcp' or 'udp', got '{}'",
                            protocol
                        )));
                    }
                    converted.push(PortMapping {
                        windows_port: m.windows_port,
                        container_port: m.container_port,
                        protocol,
                    });
                }
                config.port_mappings = converted;
            }
            Some(config)
        } else {
            None
        };
        let isolation_session = raw_exp.isolation_session.map(|as_cfg| {
            let mut config = IsolationSessionConfig::default();
            if let Some(id) = as_cfg.configuration_id {
                use crate::models::IsolationSessionConfigurationId;
                config.configuration_id = match id.as_str() {
                    "small" => IsolationSessionConfigurationId::Small,
                    "medium" => IsolationSessionConfigurationId::Medium,
                    "large" => IsolationSessionConfigurationId::Large,
                    "composable" => IsolationSessionConfigurationId::Composable,
                    _ => {
                        logger.log_line(&format!(
                            "Unknown isolation_session configurationId '{}', defaulting to 'composable'",
                            id
                        ));
                        IsolationSessionConfigurationId::Composable
                    }
                };
            }
            config.user = as_cfg.user;
            config
        });
        let seatbelt = raw_exp.seatbelt;
        if seatbelt.is_some() {
            let msg = "'experimental.seatbelt' has moved to the stable section; \
                       use top-level 'seatbelt' instead."
                .to_string();
            logger.log_line(&msg);
            return Err(WxcError::ConfigParse(msg));
        }
        ExperimentalConfig {
            test,
            windows_sandbox,
            wslc,
            isolation_session,
        }
    } else {
        ExperimentalConfig::default()
    };

    // Top-level `seatbelt` config. Configs using `experimental.seatbelt` are
    // rejected above.
    let seatbelt = raw.seatbelt.map(make_seatbelt_config);

    // UI section
    if let Some(raw_ui) = raw.ui {
        let clipboard = match raw_ui.clipboard.as_deref() {
            Some("read") => ClipboardPolicy::Read,
            Some("write") => ClipboardPolicy::Write,
            Some("all") => ClipboardPolicy::All,
            _ => ClipboardPolicy::None,
        };
        policy.ui = UiPolicy {
            disable: raw_ui.disable.unwrap_or(true),
            clipboard,
            injection: raw_ui.injection.unwrap_or(false),
        };
    }

    Ok(ExecutionRequest {
        schema_version,
        container_id,
        env,
        script_code,
        working_directory,
        script_timeout,
        containment,
        lifecycle,
        policy,
        lxc_config,
        seatbelt,
        experimental_enabled: false,
        experimental,
        dry_run: false,
    })
}

fn convert_raw_state_aware(
    raw: RawStateAwareRequest,
    logger: &mut Logger,
    allow_missing_command: bool,
) -> Result<ParsedStateAwareRequest, WxcError> {
    // Reject unrecognised top-level fields on the state-aware envelope before
    // building the one-shot surrogate (whose `unknown` map is always empty).
    reject_unknown_top_level_fields(&raw.unknown, logger)?;

    let phase = Phase::from_wire(&raw.phase).map_err(|e| {
        let msg = e.message.clone();
        logger.log_line(&msg);
        WxcError::ConfigParse(msg)
    })?;

    let containment = match raw.containment.as_deref() {
        None => None,
        Some(wire) => Some(parse_containment_str(wire, logger)?),
    };

    validate_experimental_backend_keys(containment.as_ref(), raw.experimental.as_ref(), logger)?;

    // Build a RawConfig surrogate so the inner ExecutionRequest is populated by the
    // same conversion path one-shot uses for cross-cutting wire fields.
    let surrogate = RawConfig {
        version: raw.version,
        container_id: raw.container_id,
        process: raw.process,
        lifecycle: None,
        containment: raw.containment,
        process_container: None,
        lxc: None,
        filesystem: raw.filesystem,
        fallback: raw.fallback,
        network: raw.network,
        ui: raw.ui,
        // The state-aware experimental block has a different shape from the
        // one-shot RawExperimental; it is preserved separately on
        // ParsedStateAwareRequest as raw JSON.
        experimental: None,
        seatbelt: None,
        unknown: HashMap::new(),
    };

    let require_process = phase == Phase::Exec;
    let request =
        convert_raw_config_inner(surrogate, logger, require_process, allow_missing_command)?;

    Ok(ParsedStateAwareRequest {
        request,
        phase,
        containment,
        sandbox_id: raw.sandbox_id,
        experimental_raw: raw.experimental,
    })
}

/// State-aware path: parse the `containment` wire field on a per-phase
/// request envelope.
///
/// Mirrors the dual-acceptance contract of the one-shot match in
/// `convert_raw_config_inner`: the input may be either an abstract intent
/// (resolved per `target_os`) or a concrete backend id. Keep the two
/// match expressions in lockstep when adding new values.
fn parse_containment_str(s: &str, logger: &mut Logger) -> Result<ContainmentBackend, WxcError> {
    match s {
        "processcontainer" => Ok(ContainmentBackend::ProcessContainer),
        "appcontainer" => {
            logger.log_line(
                "[deprecated] containment value 'appcontainer' is a legacy alias for 'processcontainer'; \
                 update your config to use 'processcontainer' (the 'appcontainer' alias may be removed in a future schema version).",
            );
            Ok(ContainmentBackend::ProcessContainer)
        }
        "process" => {
            // Abstract intent: the caller wants the OS-native process
            // sandbox. Resolves to ProcessContainer on Windows, Bubblewrap
            // on Linux, and Seatbelt on macOS. Callers who want LXC (a
            // full container) must request it explicitly via "lxc".
            #[cfg(target_os = "linux")]
            {
                Ok(ContainmentBackend::Bubblewrap)
            }
            #[cfg(target_os = "macos")]
            {
                Ok(ContainmentBackend::Seatbelt)
            }
            #[cfg(not(any(target_os = "linux", target_os = "macos")))]
            {
                Ok(ContainmentBackend::ProcessContainer)
            }
        }
        "windows_sandbox" => Ok(ContainmentBackend::WindowsSandbox),
        "wslc" => Ok(ContainmentBackend::Wslc),
        "lxc" => Ok(ContainmentBackend::Lxc),
        "vm" => {
            #[cfg(target_os = "windows")]
            {
                Ok(ContainmentBackend::WindowsSandbox)
            }
            #[cfg(not(target_os = "windows"))]
            {
                Ok(ContainmentBackend::Vm)
            }
        }
        "microvm" => Ok(ContainmentBackend::MicroVm),
        "isolation_session" => Ok(ContainmentBackend::IsolationSession),
        "seatbelt" => Ok(ContainmentBackend::Seatbelt),
        "hyperlight" => Ok(ContainmentBackend::Hyperlight),
        "bubblewrap" => Ok(ContainmentBackend::Bubblewrap),
        "macos_sandbox" => {
            logger.log_line(
                "[deprecated] containment value 'macos_sandbox' is a legacy alias for 'seatbelt'; \
                 update your config to use 'seatbelt' (the 'macos_sandbox' alias may be removed in a future schema version).",
            );
            Ok(ContainmentBackend::Seatbelt)
        }
        other => {
            let msg = format!(
                "Invalid containment value '{}' (must be 'process', 'processcontainer', 'windows_sandbox', 'isolation_session', 'wslc', 'lxc', 'vm', 'microvm', 'seatbelt', 'hyperlight', or 'bubblewrap')",
                other
            );
            logger.log_line(&msg);
            Err(WxcError::ConfigParse(msg))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::encoding::base64_encode;
    use crate::logger::Mode;

    fn test_logger() -> Logger {
        Logger::new(Mode::Buffer)
    }

    fn load_mxc(json: &str) -> Result<MxcRequest, ParseError> {
        let encoded = base64_encode(json.as_bytes());
        let mut logger = test_logger();
        load_mxc_request(&encoded, &mut logger, true)
    }

    fn load_mxc_with_opts(json: &str, opts: LoadOptions) -> Result<MxcRequest, ParseError> {
        let encoded = base64_encode(json.as_bytes());
        let mut logger = test_logger();
        load_mxc_request_with_options(
            &encoded,
            &mut logger,
            LoadOptions {
                is_base64: true,
                ..opts
            },
        )
    }

    #[test]
    fn allow_missing_command_lets_one_shot_skip_command_line() {
        // No process.commandLine in the policy — without the flag this would
        // be a parse error; with allow_missing_command set the parser yields
        // an empty script_code for the driver to fill in.
        let json = r#"{"process": {"cwd": "C:\\tmp"}}"#;
        let opts = LoadOptions {
            is_base64: true,
            allow_missing_command: true,
        };
        match load_mxc_with_opts(json, opts).unwrap() {
            MxcRequest::OneShot(req) => {
                assert!(req.script_code.is_empty());
                assert_eq!(req.working_directory, "C:\\tmp");
            }
            MxcRequest::StateAware(_) => panic!("expected one-shot"),
        }
    }

    #[test]
    fn allow_missing_command_lets_one_shot_skip_process_block_entirely() {
        let json = r#"{"containment": "processcontainer"}"#;
        let opts = LoadOptions {
            is_base64: true,
            allow_missing_command: true,
        };
        match load_mxc_with_opts(json, opts).unwrap() {
            MxcRequest::OneShot(req) => assert!(req.script_code.is_empty()),
            MxcRequest::StateAware(_) => panic!("expected one-shot"),
        }
    }

    #[test]
    fn allow_missing_command_lets_state_aware_exec_skip_command_line() {
        let json = r#"{
            "phase": "exec",
            "sandboxId": "iso:abcd1234",
            "process": {"cwd": "C:\\tmp"}
        }"#;
        let opts = LoadOptions {
            is_base64: true,
            allow_missing_command: true,
        };
        match load_mxc_with_opts(json, opts).unwrap() {
            MxcRequest::StateAware(p) => {
                assert_eq!(p.phase, Phase::Exec);
                assert!(p.request.script_code.is_empty());
            }
            MxcRequest::OneShot(_) => panic!("expected state-aware"),
        }
    }

    #[test]
    fn default_options_still_reject_missing_command_line() {
        // Sanity: without the flag, the legacy contract holds — missing
        // commandLine is a hard parse error.
        let json = r#"{"process": {"cwd": "C:\\tmp"}}"#;
        let opts = LoadOptions {
            is_base64: true,
            allow_missing_command: false,
        };
        assert!(load_mxc_with_opts(json, opts).is_err());
    }

    #[test]
    fn one_shot_routes_via_load_mxc_request() {
        let json = r#"{"process": {"commandLine": "echo hello"}}"#;
        match load_mxc(json).unwrap() {
            MxcRequest::OneShot(req) => assert_eq!(req.script_code, "echo hello"),
            MxcRequest::StateAware(_) => panic!("expected one-shot"),
        }
    }

    #[test]
    fn state_aware_provision_request_routes_to_state_aware_arm() {
        let json = r#"{
            "phase": "provision",
            "containment": "isolation_session",
            "filesystem": {"readwritePaths": ["C:\\workspace"]}
        }"#;
        match load_mxc(json).unwrap() {
            MxcRequest::StateAware(p) => {
                assert_eq!(p.phase, Phase::Provision);
                assert_eq!(p.containment, Some(ContainmentBackend::IsolationSession));
                assert!(p.sandbox_id.is_none());
                assert!(p.experimental_raw.is_none());
                assert_eq!(p.request.policy.readwrite_paths, vec!["C:\\workspace"]);
                // Non-exec phase: process-related fields stay default.
                assert!(p.request.script_code.is_empty());
            }
            MxcRequest::OneShot(_) => panic!("expected state-aware"),
        }
    }

    #[test]
    fn state_aware_start_request_carries_sandbox_id_and_experimental() {
        let json = r#"{
            "phase": "start",
            "sandboxId": "iso:abcd1234",
            "experimental": {
                "isolation_session": {"start": {"configurationId": "small"}}
            }
        }"#;
        match load_mxc(json).unwrap() {
            MxcRequest::StateAware(p) => {
                assert_eq!(p.phase, Phase::Start);
                assert_eq!(p.sandbox_id.as_deref(), Some("iso:abcd1234"));
                assert!(p.experimental_raw.is_some());
            }
            MxcRequest::OneShot(_) => panic!("expected state-aware"),
        }
    }

    #[test]
    fn state_aware_exec_request_requires_command_line() {
        let json = r#"{
            "phase": "exec",
            "sandboxId": "iso:abcd1234",
            "process": {"commandLine": "echo hello"}
        }"#;
        match load_mxc(json).unwrap() {
            MxcRequest::StateAware(p) => {
                assert_eq!(p.phase, Phase::Exec);
                assert_eq!(p.request.script_code, "echo hello");
            }
            MxcRequest::OneShot(_) => panic!("expected state-aware"),
        }
    }

    #[test]
    fn state_aware_exec_without_process_is_rejected() {
        // Exec phase still requires the process.commandLine wire field.
        let json = r#"{ "phase": "exec", "sandboxId": "iso:abcd1234" }"#;
        let r = load_mxc(json);
        assert!(matches!(r, Err(ParseError::StateAware(_))), "got {:?}", r);
    }

    #[test]
    fn state_aware_unknown_phase_is_rejected() {
        let json = r#"{"phase": "teleport"}"#;
        let r = load_mxc(json);
        assert!(matches!(r, Err(ParseError::StateAware(_))), "got {:?}", r);
    }

    #[test]
    fn state_aware_unknown_containment_is_rejected() {
        let json = r#"{"phase": "provision", "containment": "totally_made_up"}"#;
        let r = load_mxc(json);
        assert!(matches!(r, Err(ParseError::StateAware(_))), "got {:?}", r);
    }

    #[test]
    fn state_aware_provision_works_with_no_containment() {
        // Containment is optional at parse time; the dispatcher enforces it
        // (provision needs containment, non-provision uses sandbox_id prefix).
        let json = r#"{"phase": "provision"}"#;
        match load_mxc(json).unwrap() {
            MxcRequest::StateAware(p) => {
                assert_eq!(p.phase, Phase::Provision);
                assert!(p.containment.is_none());
            }
            MxcRequest::OneShot(_) => panic!("expected state-aware"),
        }
    }

    #[test]
    fn minimal_config() {
        let json = r#"{"process": {"commandLine": "echo hello"}}"#;
        let encoded = base64_encode(json.as_bytes());
        let mut logger = test_logger();

        let req = load_request(&encoded, &mut logger, true).unwrap();
        assert_eq!(req.script_code, "echo hello");
        assert_eq!(req.script_timeout, 0);
        assert!(req.working_directory.is_empty());
    }

    #[test]
    fn missing_process_section() {
        let json = r#"{"containment": "processcontainer"}"#;
        let encoded = base64_encode(json.as_bytes());
        let mut logger = test_logger();

        let result = load_request(&encoded, &mut logger, true);
        assert!(result.is_err());
    }

    #[test]
    fn missing_command_line() {
        let json = r#"{"process": {"cwd": "/tmp"}}"#;
        let encoded = base64_encode(json.as_bytes());
        let mut logger = test_logger();

        let result = load_request(&encoded, &mut logger, true);
        assert!(result.is_err());
    }

    #[test]
    fn empty_command_line() {
        let json = r#"{"process": {"commandLine": ""}}"#;
        let encoded = base64_encode(json.as_bytes());
        let mut logger = test_logger();

        let result = load_request(&encoded, &mut logger, true);
        assert!(result.is_err());
    }

    #[test]
    fn malicious_command_line() {
        let json = r#"{"process": {"commandLine": "echo hello\0world"}}"#;
        let encoded = base64_encode(json.as_bytes());
        let mut logger = test_logger();

        let result = load_request(&encoded, &mut logger, true);
        assert!(result.is_err());
    }

    #[test]
    fn full_config() {
        let json = r#"{
            "containerId": "TestProfile",
            "containment": "processcontainer",
            "process": {
                "commandLine": "dir",
                "cwd": "C:\\temp",
                "timeout": 3000
            },
            "processContainer": {
                "leastPrivilege": true,
                "capabilities": ["internetClient"]
            },
            "filesystem": {
                "readwritePaths": ["C:\\rw"],
                "readonlyPaths": ["C:\\ro"],
                "deniedPaths": ["C:\\denied"]
            },
            "network": {
                "defaultPolicy": "block",
                "enforcementMode": "firewall",
                "allowedHosts": ["example.com"],
                "blockedHosts": ["evil.com"]
            }
        }"#;
        let encoded = base64_encode(json.as_bytes());
        let mut logger = test_logger();

        let req = load_request(&encoded, &mut logger, true).unwrap();
        assert_eq!(req.script_code, "dir");
        assert_eq!(req.working_directory, "C:\\temp");
        assert_eq!(req.script_timeout, 3000);
        assert_eq!(req.container_id, "TestProfile");
        assert!(req.policy.least_privilege_mode);
        assert!(req
            .policy
            .capabilities
            .contains(&"internetClient".to_string()));
        assert_eq!(req.policy.readwrite_paths, vec!["C:\\rw"]);
        assert_eq!(req.policy.readonly_paths, vec!["C:\\ro"]);
        assert_eq!(req.policy.denied_paths, vec!["C:\\denied"]);
        assert_eq!(req.policy.default_network_policy, NetworkPolicy::Block);
        assert_eq!(
            req.policy.network_enforcement_mode,
            NetworkEnforcementMode::Firewall
        );
        assert_eq!(req.policy.allowed_hosts, vec!["example.com"]);
        assert_eq!(req.policy.blocked_hosts, vec!["evil.com"]);
    }

    #[test]
    fn invalid_network_policy() {
        let json =
            r#"{"process": {"commandLine": "echo x"}, "network": {"defaultPolicy": "invalid"}}"#;
        let encoded = base64_encode(json.as_bytes());
        let mut logger = test_logger();

        let result = load_request(&encoded, &mut logger, true);
        assert!(result.is_err());
    }

    #[test]
    fn invalid_enforcement_mode() {
        let json =
            r#"{"process": {"commandLine": "echo x"}, "network": {"enforcementMode": "invalid"}}"#;
        let encoded = base64_encode(json.as_bytes());
        let mut logger = test_logger();

        let result = load_request(&encoded, &mut logger, true);
        assert!(result.is_err());
    }

    #[test]
    fn load_from_file() {
        let dir = tempfile::tempdir().unwrap();
        let file_path = dir.path().join("config.json");
        std::fs::write(&file_path, r#"{"process": {"commandLine": "whoami"}}"#).unwrap();

        let mut logger = test_logger();
        let req = load_request(file_path.to_str().unwrap(), &mut logger, false).unwrap();
        assert_eq!(req.script_code, "whoami");
    }

    #[test]
    fn file_not_found() {
        let mut logger = test_logger();
        let result = load_request("nonexistent.json", &mut logger, false);
        assert!(result.is_err());
    }

    #[test]
    fn invalid_base64() {
        let mut logger = test_logger();
        let result = load_request("not-valid-base64!!!", &mut logger, true);
        assert!(result.is_err());
    }

    #[test]
    fn invalid_json() {
        let encoded = base64_encode(b"{ not json }");
        let mut logger = test_logger();
        let result = load_request(&encoded, &mut logger, true);
        assert!(result.is_err());
    }

    #[cfg(debug_assertions)]
    #[test]
    fn learning_mode_adds_capability_in_debug() {
        let json = r#"{"process": {"commandLine": "echo x"}, "containment": "processcontainer", "processContainer": {"learningMode": true}}"#;
        let encoded = base64_encode(json.as_bytes());
        let mut logger = test_logger();

        let req = load_request(&encoded, &mut logger, true).unwrap();
        assert!(req
            .policy
            .capabilities
            .contains(&"permissiveLearningMode".to_string()));
        assert!(logger.get_buffer().contains("WARNING"));
    }

    #[cfg(not(debug_assertions))]
    #[test]
    fn learning_mode_stripped_in_release() {
        let json = r#"{"process": {"commandLine": "echo x"}, "containment": "processcontainer", "processContainer": {"capabilities": ["permissiveLearningMode"]}}"#;
        let encoded = base64_encode(json.as_bytes());
        let mut logger = test_logger();

        let req = load_request(&encoded, &mut logger, true).unwrap();
        assert!(!req
            .policy
            .capabilities
            .contains(&"permissiveLearningMode".to_string()));
        assert!(logger.get_buffer().contains("SECURITY"));
    }

    // ====== Tests ported from C++ ConfigurationParserTests.cpp ======

    #[test]
    fn script_with_timeout() {
        let json =
            r#"{"process": {"commandLine": "import sys\nprint(sys.version)", "timeout": 60000}}"#;
        let encoded = base64_encode(json.as_bytes());
        let mut logger = test_logger();

        let req = load_request(&encoded, &mut logger, true).unwrap();
        assert_eq!(req.script_timeout, 60000);
    }

    #[test]
    fn process_container_capabilities() {
        let json = r#"{
            "process": {"commandLine": "print('test')"},
            "containment": "processcontainer",
            "processContainer": {
                "capabilities": ["internetClient", "privateNetworkClientServer", "documentsLibrary"]
            }
        }"#;
        let encoded = base64_encode(json.as_bytes());
        let mut logger = test_logger();

        let req = load_request(&encoded, &mut logger, true).unwrap();
        assert_eq!(req.policy.capabilities.len(), 3);
        assert_eq!(req.policy.capabilities[0], "internetClient");
        assert_eq!(req.policy.capabilities[1], "privateNetworkClientServer");
        assert_eq!(req.policy.capabilities[2], "documentsLibrary");
    }

    #[test]
    fn least_privilege_mode() {
        let json = r#"{"process": {"commandLine": "print('test')"}, "containment": "processcontainer", "processContainer": {"leastPrivilege": true}}"#;
        let encoded = base64_encode(json.as_bytes());
        let mut logger = test_logger();

        let req = load_request(&encoded, &mut logger, true).unwrap();
        assert!(req.policy.least_privilege_mode);
    }

    #[test]
    fn network_default_policy_allow() {
        let json = r#"{"process": {"commandLine": "print('test')"}, "network": {"defaultPolicy": "allow"}}"#;
        let encoded = base64_encode(json.as_bytes());
        let mut logger = test_logger();

        let req = load_request(&encoded, &mut logger, true).unwrap();
        assert_eq!(req.policy.default_network_policy, NetworkPolicy::Allow);
    }

    #[test]
    fn network_default_policy_block() {
        let json = r#"{"process": {"commandLine": "print('test')"}, "network": {"defaultPolicy": "block"}}"#;
        let encoded = base64_encode(json.as_bytes());
        let mut logger = test_logger();

        let req = load_request(&encoded, &mut logger, true).unwrap();
        assert_eq!(req.policy.default_network_policy, NetworkPolicy::Block);
    }

    #[test]
    fn network_default_policy_absent_defaults_to_block_on_any_version() {
        // wxc-exec is the trust boundary -- absent `defaultPolicy`
        // resolves to `Block` regardless of declared schema version.
        for version in ["0.4.0-alpha", "0.5.0-alpha", "0.6.0-alpha"] {
            let json = format!(
                r#"{{"version": "{}", "process": {{"commandLine": "echo x"}}}}"#,
                version
            );
            let encoded = base64_encode(json.as_bytes());
            let mut logger = test_logger();
            let req = load_request(&encoded, &mut logger, true).unwrap();
            assert_eq!(
                req.policy.default_network_policy,
                NetworkPolicy::Block,
                "version {} should default to Block",
                version
            );
        }
    }

    #[test]
    fn network_enforcement_mode_capabilities() {
        let json = r#"{"process": {"commandLine": "print('test')"}, "network": {"enforcementMode": "capabilities"}}"#;
        let encoded = base64_encode(json.as_bytes());
        let mut logger = test_logger();

        let req = load_request(&encoded, &mut logger, true).unwrap();
        assert_eq!(
            req.policy.network_enforcement_mode,
            NetworkEnforcementMode::Capabilities
        );
    }

    #[test]
    fn network_enforcement_mode_firewall() {
        let json = r#"{"process": {"commandLine": "print('test')"}, "network": {"enforcementMode": "firewall"}}"#;
        let encoded = base64_encode(json.as_bytes());
        let mut logger = test_logger();

        let req = load_request(&encoded, &mut logger, true).unwrap();
        assert_eq!(
            req.policy.network_enforcement_mode,
            NetworkEnforcementMode::Firewall
        );
    }

    #[test]
    fn network_enforcement_mode_both() {
        let json = r#"{"process": {"commandLine": "print('test')"}, "network": {"enforcementMode": "both"}}"#;
        let encoded = base64_encode(json.as_bytes());
        let mut logger = test_logger();

        let req = load_request(&encoded, &mut logger, true).unwrap();
        assert_eq!(
            req.policy.network_enforcement_mode,
            NetworkEnforcementMode::Both
        );
    }

    #[test]
    fn network_hosts() {
        let json = r#"{
            "process": {"commandLine": "print('test')"},
            "network": {
                "allowedHosts": ["example.com", "api.trusted.com"],
                "blockedHosts": ["malicious.com", "tracker.net"]
            }
        }"#;
        let encoded = base64_encode(json.as_bytes());
        let mut logger = test_logger();

        let req = load_request(&encoded, &mut logger, true).unwrap();
        assert_eq!(req.policy.allowed_hosts.len(), 2);
        assert_eq!(req.policy.allowed_hosts[0], "example.com");
        assert_eq!(req.policy.allowed_hosts[1], "api.trusted.com");
        assert_eq!(req.policy.blocked_hosts.len(), 2);
        assert_eq!(req.policy.blocked_hosts[0], "malicious.com");
        assert_eq!(req.policy.blocked_hosts[1], "tracker.net");
    }

    #[test]
    fn network_allow_local_network() {
        let json = r#"{
            "process": {"commandLine": "print('test')"},
            "network": {"allowLocalNetwork": true}
        }"#;
        let encoded = base64_encode(json.as_bytes());
        let mut logger = test_logger();

        let req = load_request(&encoded, &mut logger, true).unwrap();
        assert!(req.policy.allow_local_network);
    }

    #[test]
    fn network_allow_local_network_defaults_false() {
        let json = r#"{
            "process": {"commandLine": "print('test')"},
            "network": {}
        }"#;
        let encoded = base64_encode(json.as_bytes());
        let mut logger = test_logger();

        let req = load_request(&encoded, &mut logger, true).unwrap();
        assert!(!req.policy.allow_local_network);
    }

    #[test]
    fn filesystem_paths() {
        let json = r#"{
            "process": {"commandLine": "print('test')"},
            "filesystem": {
                "readwritePaths": ["C:\\Users\\Public", "C:\\Temp\\Data"],
                "deniedPaths": ["C:\\Windows\\System32", "C:\\Program Files"]
            }
        }"#;
        let encoded = base64_encode(json.as_bytes());
        let mut logger = test_logger();

        let req = load_request(&encoded, &mut logger, true).unwrap();
        assert_eq!(req.policy.readwrite_paths.len(), 2);
        assert_eq!(req.policy.readwrite_paths[0], "C:\\Users\\Public");
        assert_eq!(req.policy.readwrite_paths[1], "C:\\Temp\\Data");
        assert_eq!(req.policy.denied_paths.len(), 2);
        assert_eq!(req.policy.denied_paths[0], "C:\\Windows\\System32");
        assert_eq!(req.policy.denied_paths[1], "C:\\Program Files");
    }

    #[test]
    fn block_evil_filesystem_paths() {
        let json = r#"{
            "process": {"commandLine": "print('test')"},
            "filesystem": {
                "readwritePaths": ["C:\\My \"Evil\\Path"]
            }
        }"#;
        let encoded = base64_encode(json.as_bytes());
        let mut logger = test_logger();

        let result = load_request(&encoded, &mut logger, true);
        assert!(result.is_err());
    }

    #[test]
    fn base64_complex_config() {
        let json = r#"{
            "containerId": "TestContainer",
            "containment": "processcontainer",
            "process": {
                "commandLine": "import sys\nprint(sys.version)",
                "timeout": 10000
            },
            "processContainer": {
                "capabilities": ["internetClient", "privateNetworkClientServer"]
            }
        }"#;
        let encoded = base64_encode(json.as_bytes());
        let mut logger = test_logger();

        let req = load_request(&encoded, &mut logger, true).unwrap();
        assert_eq!(req.script_code, "import sys\nprint(sys.version)");
        assert_eq!(req.script_timeout, 10000);
        assert_eq!(req.container_id, "TestContainer");
        assert_eq!(req.policy.capabilities.len(), 2);
    }

    #[test]
    fn invalid_json_syntax() {
        let json = r#"{"process": {"commandLine": "print('test')"}, INVALID_JSON}"#;
        let encoded = base64_encode(json.as_bytes());
        let mut logger = test_logger();

        let result = load_request(&encoded, &mut logger, true);
        assert!(result.is_err());
    }

    #[test]
    fn default_timeout_is_zero() {
        let json = r#"{"process": {"commandLine": "echo hello"}}"#;
        let encoded = base64_encode(json.as_bytes());
        let mut logger = test_logger();

        let req = load_request(&encoded, &mut logger, true).unwrap();
        assert_eq!(req.script_timeout, 0);
    }

    #[test]
    fn allow_dacl_mutation_default_true() {
        let json = r#"{"process": {"commandLine": "echo hi"}}"#;
        let encoded = base64_encode(json.as_bytes());
        let mut logger = test_logger();
        let req = load_request(&encoded, &mut logger, true).unwrap();
        assert!(req.policy.fallback.allow_dacl_mutation);
    }

    #[test]
    fn allow_dacl_mutation_explicit_false() {
        let json = r#"{
            "process": {"commandLine": "echo hi"},
            "fallback": {"allowDaclMutation": false}
        }"#;
        let encoded = base64_encode(json.as_bytes());
        let mut logger = test_logger();
        let req = load_request(&encoded, &mut logger, true).unwrap();
        assert!(!req.policy.fallback.allow_dacl_mutation);
    }

    #[test]
    fn allow_dacl_mutation_explicit_true() {
        let json = r#"{
            "process": {"commandLine": "echo hi"},
            "fallback": {"allowDaclMutation": true}
        }"#;
        let encoded = base64_encode(json.as_bytes());
        let mut logger = test_logger();
        let req = load_request(&encoded, &mut logger, true).unwrap();
        assert!(req.policy.fallback.allow_dacl_mutation);
    }

    // ====== Containment backend selection tests ======

    #[test]
    fn default_containment_resolves_per_target() {
        // Omitted `containment` resolves to the OS-native process sandbox:
        // ProcessContainer on Windows, Bubblewrap on Linux, Seatbelt on macOS.
        let json = r#"{"process": {"commandLine": "echo hello"}}"#;
        let encoded = base64_encode(json.as_bytes());
        let mut logger = test_logger();

        let req = load_request(&encoded, &mut logger, true).unwrap();

        #[cfg(target_os = "linux")]
        assert_eq!(req.containment, ContainmentBackend::Bubblewrap);
        #[cfg(target_os = "macos")]
        assert_eq!(req.containment, ContainmentBackend::Seatbelt);
        #[cfg(not(any(target_os = "linux", target_os = "macos")))]
        assert_eq!(req.containment, ContainmentBackend::ProcessContainer);
    }

    #[test]
    fn explicit_processcontainer_containment() {
        let json =
            r#"{"process": {"commandLine": "echo hello"}, "containment": "processcontainer"}"#;
        let encoded = base64_encode(json.as_bytes());
        let mut logger = test_logger();

        let req = load_request(&encoded, &mut logger, true).unwrap();
        assert_eq!(req.containment, ContainmentBackend::ProcessContainer);
    }

    #[test]
    fn process_containment_resolves_per_target() {
        // Abstract intent "process" resolves to the OS-native process sandbox:
        // ProcessContainer on Windows, Bubblewrap on Linux, Seatbelt on macOS.
        // Callers who want LXC (a full container) must request it explicitly
        // via `"containment": "lxc"`.
        let json = r#"{"process": {"commandLine": "echo hello"}, "containment": "process"}"#;
        let encoded = base64_encode(json.as_bytes());
        let mut logger = test_logger();

        let req = load_request(&encoded, &mut logger, true).unwrap();

        #[cfg(target_os = "linux")]
        assert_eq!(req.containment, ContainmentBackend::Bubblewrap);
        #[cfg(target_os = "macos")]
        assert_eq!(req.containment, ContainmentBackend::Seatbelt);
        #[cfg(not(any(target_os = "linux", target_os = "macos")))]
        assert_eq!(req.containment, ContainmentBackend::ProcessContainer);
    }

    #[test]
    fn explicit_lxc_containment_unaffected_by_default_shift() {
        // Regression guard: making bubblewrap the Linux default for the
        // abstract `"process"` intent must NOT change how explicit `"lxc"`
        // resolves. LXC remains available to any caller that asks for it.
        let json = r#"{"process": {"commandLine": "echo hello"}, "containment": "lxc"}"#;
        let encoded = base64_encode(json.as_bytes());
        let mut logger = test_logger();

        let req = load_request(&encoded, &mut logger, true).unwrap();
        assert_eq!(req.containment, ContainmentBackend::Lxc);
    }

    #[test]
    fn explicit_bubblewrap_containment_parses_cleanly() {
        // Bubblewrap no longer requires gating in the parser/SDK; explicit
        // `"bubblewrap"` should parse to the concrete backend on every
        // target without error. (Host availability is checked at runtime by
        // the runner, not here.)
        let json = r#"{"process": {"commandLine": "echo hello"}, "containment": "bubblewrap"}"#;
        let encoded = base64_encode(json.as_bytes());
        let mut logger = test_logger();

        let req = load_request(&encoded, &mut logger, true).unwrap();
        assert_eq!(req.containment, ContainmentBackend::Bubblewrap);
    }

    #[test]
    fn hyperlight_containment_value_parses() {
        // Lock in that `"hyperlight"` is accepted by the parser (mirrors
        // the `convert_raw_config_inner` arm and keeps `parse_containment_str`
        // in sync for the state-aware path).
        let json = r#"{"process": {"commandLine": "echo hello"}, "containment": "hyperlight"}"#;
        let encoded = base64_encode(json.as_bytes());
        let mut logger = test_logger();

        let req = load_request(&encoded, &mut logger, true).unwrap();
        assert_eq!(req.containment, ContainmentBackend::Hyperlight);
    }

    #[test]
    fn vm_containment_resolves_per_target() {
        // Abstract intent "vm" resolves to Windows Sandbox on Windows. On
        // other targets there is no concrete VM backend yet, so the parser
        // returns the historical `Vm` placeholder variant which the host
        // binaries surface as a "not implemented" error.
        let json = r#"{"process": {"commandLine": "echo hello"}, "containment": "vm"}"#;
        let encoded = base64_encode(json.as_bytes());
        let mut logger = test_logger();

        let req = load_request(&encoded, &mut logger, true).unwrap();

        #[cfg(target_os = "windows")]
        assert_eq!(req.containment, ContainmentBackend::WindowsSandbox);
        #[cfg(not(target_os = "windows"))]
        assert_eq!(req.containment, ContainmentBackend::Vm);
    }

    #[test]
    fn sandbox_containment() {
        let json =
            r#"{"process": {"commandLine": "echo hello"}, "containment": "windows_sandbox"}"#;
        let encoded = base64_encode(json.as_bytes());
        let mut logger = test_logger();

        let req = load_request(&encoded, &mut logger, true).unwrap();
        assert_eq!(req.containment, ContainmentBackend::WindowsSandbox);
    }

    #[test]
    fn invalid_containment_value() {
        let json = r#"{"process": {"commandLine": "echo hello"}, "containment": "docker"}"#;
        let encoded = base64_encode(json.as_bytes());
        let mut logger = test_logger();

        let result = load_request(&encoded, &mut logger, true);
        assert!(result.is_err());
    }

    #[test]
    fn sandbox_config_defaults() {
        let json = r#"{"process": {"commandLine": "echo hello"}, "containment": "windows_sandbox", "experimental": {"windows_sandbox": {}}}"#;
        let encoded = base64_encode(json.as_bytes());
        let mut logger = test_logger();

        let req = load_request(&encoded, &mut logger, true).unwrap();
        let sandbox = req.experimental.windows_sandbox.unwrap();
        assert_eq!(sandbox.idle_timeout_ms, 300_000);
        assert_eq!(sandbox.daemon_pipe_name, "wxc-windows-sandbox");
    }

    #[test]
    fn sandbox_config_custom_values() {
        let json = r#"{
            "process": {"commandLine": "echo hello"},
            "containment": "windows_sandbox",
            "experimental": {
                "windows_sandbox": {
                    "idleTimeoutMs": 60000,
                    "daemonPipeName": "my-custom-pipe"
                }
            }
        }"#;
        let encoded = base64_encode(json.as_bytes());
        let mut logger = test_logger();

        let req = load_request(&encoded, &mut logger, true).unwrap();
        let sandbox = req.experimental.windows_sandbox.unwrap();
        assert_eq!(sandbox.idle_timeout_ms, 60000);
        assert_eq!(sandbox.daemon_pipe_name, "my-custom-pipe");
    }

    // ====== Network proxy configuration tests ======

    #[test]
    fn no_proxy_leaves_default() {
        let json =
            r#"{"process": {"commandLine": "echo test"}, "network": {"defaultPolicy": "block"}}"#;
        let encoded = base64_encode(json.as_bytes());
        let mut logger = test_logger();

        let req = load_request(&encoded, &mut logger, true).unwrap();
        assert!(!req.policy.network_proxy.is_enabled());
    }

    #[test]
    fn proxy_localhost_port() {
        let json = r#"{
            "process": {"commandLine": "echo test"},
            "containment": "processcontainer",
            "network": {
                "proxy": { "localhost": 8080 }
            }
        }"#;
        let encoded = base64_encode(json.as_bytes());
        let mut logger = test_logger();

        let req = load_request(&encoded, &mut logger, true).unwrap();
        assert!(req.policy.network_proxy.is_enabled());
        assert_eq!(
            req.policy.network_proxy.address.as_ref().unwrap().port(),
            8080
        );
    }

    #[test]
    fn proxy_url_parsed() {
        let json = r#"{
            "process": {"commandLine": "echo test"},
            "containment": "processcontainer",
            "network": {
                "proxy": { "url": "http://localhost:3128" }
            }
        }"#;
        let encoded = base64_encode(json.as_bytes());
        let mut logger = test_logger();

        let req = load_request(&encoded, &mut logger, true).unwrap();
        assert!(req.policy.network_proxy.is_enabled());
        let addr = req.policy.network_proxy.address.as_ref().unwrap();
        assert_eq!(addr.port(), 3128);
        assert_eq!(addr.host(), "localhost");
    }

    #[test]
    fn proxy_url_non_localhost() {
        let json = r#"{
            "process": {"commandLine": "echo test"},
            "containment": "processcontainer",
            "network": {
                "proxy": { "url": "http://proxy.example.com:8080" }
            }
        }"#;
        let encoded = base64_encode(json.as_bytes());
        let mut logger = test_logger();

        let req = load_request(&encoded, &mut logger, true).unwrap();
        let addr = req.policy.network_proxy.address.as_ref().unwrap();
        assert_eq!(addr.port(), 8080);
        assert_eq!(addr.host(), "proxy.example.com");
    }

    #[test]
    fn proxy_url_missing_port() {
        let json =
            r#"{"process":{"commandLine":"x"},"network":{"proxy":{"url":"http://localhost"}}}"#;
        let encoded = base64_encode(json.as_bytes());
        let mut logger = test_logger();

        let result = load_request(&encoded, &mut logger, true);
        assert!(result.is_err());
    }

    #[test]
    fn proxy_url_ipv6_loopback() {
        let json = r#"{
            "process": {"commandLine": "echo test"},
            "containment": "processcontainer",
            "network": {
                "proxy": { "url": "http://[::1]:8080" }
            }
        }"#;
        let encoded = base64_encode(json.as_bytes());
        let mut logger = test_logger();

        let req = load_request(&encoded, &mut logger, true).unwrap();
        let addr = req.policy.network_proxy.address.as_ref().unwrap();
        assert_eq!(addr.port(), 8080);
        assert_eq!(addr.host(), "[::1]");
    }

    #[test]
    fn proxy_with_firewall_fields() {
        let json = r#"{
            "process": {"commandLine": "echo test"},
            "containment": "processcontainer",
            "network": {
                "defaultPolicy": "block",
                "allowedHosts": ["api.github.com"],
                "proxy": { "localhost": 9090 }
            }
        }"#;
        let encoded = base64_encode(json.as_bytes());
        let mut logger = test_logger();

        let req = load_request(&encoded, &mut logger, true).unwrap();
        assert_eq!(
            req.policy.network_proxy.address.as_ref().unwrap().port(),
            9090
        );
        assert_eq!(req.policy.default_network_policy, NetworkPolicy::Block);
    }

    #[test]
    fn proxy_rejected_with_non_processcontainer() {
        let json = r#"{"process":{"commandLine":"x"},"containment":"lxc","network":{"proxy":{"localhost":8080}}}"#;
        let encoded = base64_encode(json.as_bytes());
        let mut logger = test_logger();

        let result = load_request(&encoded, &mut logger, true);
        assert!(result.is_err());
    }

    #[test]
    fn proxy_rejects_port_zero() {
        let json = r#"{"process":{"commandLine":"x"},"network":{"proxy":{"localhost":0}}}"#;
        let encoded = base64_encode(json.as_bytes());
        let mut logger = test_logger();

        let result = load_request(&encoded, &mut logger, true);
        assert!(result.is_err());
    }

    #[test]
    fn proxy_rejects_missing_localhost() {
        let json = r#"{"process":{"commandLine":"x"},"network":{"proxy":{}}}"#;
        let encoded = base64_encode(json.as_bytes());
        let mut logger = test_logger();

        let result = load_request(&encoded, &mut logger, true);
        assert!(result.is_err());
    }

    #[test]
    fn proxy_rejects_non_object() {
        let json = r#"{"process":{"commandLine":"x"},"network":{"proxy":true}}"#;
        let encoded = base64_encode(json.as_bytes());
        let mut logger = test_logger();

        let result = load_request(&encoded, &mut logger, true);
        assert!(result.is_err());
    }

    #[test]
    fn proxy_builtin_test_server() {
        let json = r#"{
            "process": {"commandLine": "echo test"},
            "containment": "processcontainer",
            "network": {
                "proxy": { "builtinTestServer": true }
            }
        }"#;
        let encoded = base64_encode(json.as_bytes());
        let mut logger = test_logger();

        let req = load_request(&encoded, &mut logger, true).unwrap();
        assert!(req.policy.network_proxy.is_enabled());
        assert!(req.policy.network_proxy.builtin_test_server);
        assert!(req.policy.network_proxy.address.is_some());
    }

    #[test]
    fn proxy_builtin_test_server_rejects_extra_keys() {
        let json = r#"{"process":{"commandLine":"x"},"network":{"proxy":{"builtinTestServer":true,"localhost":8080}}}"#;
        let encoded = base64_encode(json.as_bytes());
        let mut logger = test_logger();

        let result = load_request(&encoded, &mut logger, true);
        assert!(result.is_err());
    }

    #[test]
    fn proxy_builtin_test_server_rejects_false() {
        let json =
            r#"{"process":{"commandLine":"x"},"network":{"proxy":{"builtinTestServer":false}}}"#;
        let encoded = base64_encode(json.as_bytes());
        let mut logger = test_logger();

        let result = load_request(&encoded, &mut logger, true);
        assert!(result.is_err());
    }

    #[test]
    fn proxy_builtin_test_server_rejected_with_non_processcontainer() {
        // lxc is not allowed -- proxy is gated to processcontainer + bubblewrap.
        let json = r#"{"process":{"commandLine":"x"},"containment":"lxc","network":{"proxy":{"builtinTestServer":true}}}"#;
        let encoded = base64_encode(json.as_bytes());
        let mut logger = test_logger();

        let result = load_request(&encoded, &mut logger, true);
        assert!(result.is_err());
    }

    #[test]
    fn proxy_accepted_with_bubblewrap() {
        let json = r#"{
            "version": "0.6.0-alpha",
            "containment": "bubblewrap",
            "process": {"commandLine": "echo hi"},
            "network": {"proxy": {"builtinTestServer": true}}
        }"#;
        let encoded = base64_encode(json.as_bytes());
        let mut logger = test_logger();

        let req = load_request(&encoded, &mut logger, true).unwrap();
        assert!(req.policy.network_proxy.is_enabled());
        assert!(req.policy.network_proxy.builtin_test_server);
    }

    #[test]
    fn proxy_with_bubblewrap_and_firewall_enforcement_is_rejected() {
        let json = r#"{
            "version": "0.6.0-alpha",
            "containment": "bubblewrap",
            "process": {"commandLine": "echo hi"},
            "network": {
                "proxy": {"builtinTestServer": true},
                "enforcementMode": "firewall",
                "allowedHosts": ["example.com"]
            }
        }"#;
        let encoded = base64_encode(json.as_bytes());
        let mut logger = test_logger();

        let err = load_request(&encoded, &mut logger, true).unwrap_err();
        let msg = format!("{}", err);
        assert!(
            msg.contains("network.proxy cannot be combined with"),
            "unexpected error message: {}",
            msg
        );
    }

    #[test]
    fn proxy_with_bubblewrap_and_both_enforcement_is_rejected() {
        let json = r#"{
            "version": "0.6.0-alpha",
            "containment": "bubblewrap",
            "process": {"commandLine": "echo hi"},
            "network": {
                "proxy": {"builtinTestServer": true},
                "enforcementMode": "both",
                "blockedHosts": ["evil.example"]
            }
        }"#;
        let encoded = base64_encode(json.as_bytes());
        let mut logger = test_logger();

        assert!(load_request(&encoded, &mut logger, true).is_err());
    }

    #[test]
    fn proxy_with_bubblewrap_and_capabilities_enforcement_is_accepted() {
        // Capabilities mode never invokes iptables, so combining it with a
        // proxy is fine and must NOT trigger the conflict guard.
        let json = r#"{
            "version": "0.6.0-alpha",
            "containment": "bubblewrap",
            "process": {"commandLine": "echo hi"},
            "network": {
                "proxy": {"builtinTestServer": true},
                "enforcementMode": "capabilities",
                "allowedHosts": ["example.com"]
            }
        }"#;
        let encoded = base64_encode(json.as_bytes());
        let mut logger = test_logger();

        let req = load_request(&encoded, &mut logger, true).unwrap();
        assert!(req.policy.network_proxy.is_enabled());
        assert_eq!(req.policy.allowed_hosts, vec!["example.com".to_string()]);
    }

    #[test]
    fn external_proxy_url_with_bubblewrap_and_allowed_hosts_is_rejected() {
        // The external proxy enforces its own policy; the runner does not
        // forward host lists to it. Combining the two is a silent
        // policy-weakening trap and must be rejected at parse time.
        let json = r#"{
            "version": "0.6.0-alpha",
            "containment": "bubblewrap",
            "process": {"commandLine": "echo hi"},
            "network": {
                "proxy": {"url": "http://127.0.0.1:8080"},
                "allowedHosts": ["api.github.com"]
            }
        }"#;
        let encoded = base64_encode(json.as_bytes());
        let mut logger = test_logger();

        let err = load_request(&encoded, &mut logger, true).unwrap_err();
        let msg = format!("{}", err);
        assert!(
            msg.contains("external network.proxy") && msg.contains("allowedHosts"),
            "unexpected error message: {}",
            msg
        );
    }

    #[test]
    fn external_proxy_localhost_with_bubblewrap_and_blocked_hosts_is_rejected() {
        let json = r#"{
            "version": "0.6.0-alpha",
            "containment": "bubblewrap",
            "process": {"commandLine": "echo hi"},
            "network": {
                "proxy": {"localhost": 8080},
                "blockedHosts": ["evil.example.com"]
            }
        }"#;
        let encoded = base64_encode(json.as_bytes());
        let mut logger = test_logger();

        let err = load_request(&encoded, &mut logger, true).unwrap_err();
        assert!(format!("{}", err).contains("external network.proxy"));
    }

    #[test]
    fn external_proxy_with_bubblewrap_and_default_block_is_rejected() {
        // defaultPolicy=block is a hard-block intent; pairing it with an
        // external proxy whose policy we don't control silently weakens
        // enforcement.
        let json = r#"{
            "version": "0.6.0-alpha",
            "containment": "bubblewrap",
            "process": {"commandLine": "echo hi"},
            "network": {
                "proxy": {"url": "http://127.0.0.1:8080"},
                "defaultPolicy": "block"
            }
        }"#;
        let encoded = base64_encode(json.as_bytes());
        let mut logger = test_logger();

        let err = load_request(&encoded, &mut logger, true).unwrap_err();
        assert!(format!("{}", err).contains("defaultPolicy"));
    }

    #[test]
    fn external_proxy_with_bubblewrap_and_no_host_policy_is_accepted() {
        // Pure delegate-to-external-proxy with no MXC-side host policy is
        // the supported external-proxy use case. Under deny-by-default,
        // callers must explicitly set `defaultPolicy: "allow"` to opt
        // into trusting the external proxy with full policy delegation.
        let json = r#"{
            "version": "0.6.0-alpha",
            "containment": "bubblewrap",
            "process": {"commandLine": "echo hi"},
            "network": {
                "proxy": {"url": "http://127.0.0.1:8080"},
                "defaultPolicy": "allow"
            }
        }"#;
        let encoded = base64_encode(json.as_bytes());
        let mut logger = test_logger();

        let req = load_request(&encoded, &mut logger, true).unwrap();
        assert!(req.policy.network_proxy.is_enabled());
        assert!(!req.policy.network_proxy.builtin_test_server);
    }

    #[test]
    fn builtin_proxy_with_bubblewrap_and_host_policy_is_accepted() {
        // The builtin proxy DOES enforce host lists at the proxy layer, so
        // combining it with allowedHosts is fine.
        let json = r#"{
            "version": "0.6.0-alpha",
            "containment": "bubblewrap",
            "process": {"commandLine": "echo hi"},
            "network": {
                "proxy": {"builtinTestServer": true},
                "allowedHosts": ["api.github.com"],
                "defaultPolicy": "block"
            }
        }"#;
        let encoded = base64_encode(json.as_bytes());
        let mut logger = test_logger();

        let req = load_request(&encoded, &mut logger, true).unwrap();
        assert!(req.policy.network_proxy.builtin_test_server);
        assert_eq!(req.policy.allowed_hosts, vec!["api.github.com".to_string()]);
    }

    #[test]
    fn bubblewrap_proxy_with_default_block_and_empty_allowlist_warns() {
        // Cooperative mode with no allowlist denies HTTP_PROXY-aware clients
        // but raw-socket clients still reach the host network. Parser must
        // surface a warning (does not reject).
        let json = r#"{
            "version": "0.6.0-alpha",
            "containment": "bubblewrap",
            "process": {"commandLine": "echo hi"},
            "network": {
                "proxy": {"builtinTestServer": true},
                "defaultPolicy": "block"
            }
        }"#;
        let encoded = base64_encode(json.as_bytes());
        let mut logger = test_logger();

        let req = load_request(&encoded, &mut logger, true).unwrap();
        assert!(req.policy.network_proxy.is_enabled());
        assert_eq!(req.policy.default_network_policy, NetworkPolicy::Block);
        // Warning is best-effort surfaced via the logger; the request still
        // succeeds.
    }

    #[test]
    fn new_toplevel_fields_parsed() {
        let json = r#"{"version": "0.4.0-alpha", "containerId": "abc-123", "containment": "lxc", "process": {"commandLine": "echo hi"}}"#;
        let encoded = base64_encode(json.as_bytes());
        let mut logger = test_logger();

        let req = load_request(&encoded, &mut logger, true).unwrap();
        assert_eq!(req.schema_version, "0.4.0-alpha");
        assert_eq!(req.container_id, "abc-123");
    }

    #[test]
    fn new_toplevel_fields_default_when_absent() {
        let json = r#"{"process": {"commandLine": "echo hi"}}"#;
        let encoded = base64_encode(json.as_bytes());
        let mut logger = test_logger();

        let req = load_request(&encoded, &mut logger, true).unwrap();
        assert_eq!(req.schema_version, "");
        assert_eq!(req.container_id, "");
    }

    #[test]
    fn process_section_env_parsed() {
        let json = r#"{
            "process": {
                "commandLine": "echo hi",
                "env": ["FOO=bar", "BAZ=qux"]
            }
        }"#;
        let encoded = base64_encode(json.as_bytes());
        let mut logger = test_logger();

        let req = load_request(&encoded, &mut logger, true).unwrap();
        assert_eq!(req.env, vec!["FOO=bar", "BAZ=qux"]);
    }

    #[test]
    fn process_section_cwd_parsed() {
        let json = r#"{
            "process": {
                "commandLine": "echo hi",
                "cwd": "/workspace"
            }
        }"#;
        let encoded = base64_encode(json.as_bytes());
        let mut logger = test_logger();

        let req = load_request(&encoded, &mut logger, true).unwrap();
        assert_eq!(req.working_directory, "/workspace");
    }

    #[test]
    fn process_section_timeout_parsed() {
        let json = r#"{
            "process": {
                "commandLine": "echo hi",
                "timeout": 9000
            }
        }"#;
        let encoded = base64_encode(json.as_bytes());
        let mut logger = test_logger();

        let req = load_request(&encoded, &mut logger, true).unwrap();
        assert_eq!(req.script_timeout, 9000);
    }

    #[test]
    fn containment_microvm_accepted() {
        let json = r#"{"process": {"commandLine": "echo hi"}, "containment": "microvm"}"#;
        let encoded = base64_encode(json.as_bytes());
        let mut logger = test_logger();

        let req = load_request(&encoded, &mut logger, true).unwrap();
        assert_eq!(req.containment, ContainmentBackend::MicroVm);
    }

    #[test]
    fn schema_version_too_new_rejected() {
        let json = r#"{"process": {"commandLine": "echo hi"}, "version": "0.8.0"}"#;
        let encoded = base64_encode(json.as_bytes());
        let mut logger = test_logger();

        let result = load_request(&encoded, &mut logger, true);
        assert!(result.is_err());
    }

    #[test]
    fn schema_version_0_7_alpha_accepted() {
        let json = r#"{"process": {"commandLine": "echo hi"}, "version": "0.7.0-alpha"}"#;
        let encoded = base64_encode(json.as_bytes());
        let mut logger = test_logger();

        let req = load_request(&encoded, &mut logger, true).unwrap();
        assert_eq!(req.schema_version, "0.7.0-alpha");
    }

    #[test]
    fn unknown_top_level_field_rejected() {
        let json = r#"{"process": {"commandLine": "echo hi"}, "bogusField": true}"#;
        let encoded = base64_encode(json.as_bytes());
        let mut logger = test_logger();

        let result = load_request(&encoded, &mut logger, true);
        assert!(
            result.is_err(),
            "unknown top-level field should be rejected"
        );
    }

    #[test]
    fn filesystem_typo_rejected() {
        // `fileSystem` (capital S) used to be silently dropped, so the policy
        // never applied. It must now be rejected as an unknown field.
        let json = r#"{"process": {"commandLine": "echo hi"}, "fileSystem": {"readwritePaths": ["C:\\x"]}}"#;
        let encoded = base64_encode(json.as_bytes());
        let mut logger = test_logger();

        let result = load_request(&encoded, &mut logger, true);
        assert!(result.is_err(), "fileSystem typo should be rejected");
    }

    #[test]
    fn top_level_annotations_allowed() {
        // `$schema` and `_comment` are permitted but ignored.
        let json = r#"{
            "$schema": "../schemas/dev/mxc-config.schema.0.7.0-dev.json",
            "_comment": "annotation that the parser ignores",
            "version": "0.7.0-alpha",
            "process": {"commandLine": "echo hi"}
        }"#;
        let encoded = base64_encode(json.as_bytes());
        let mut logger = test_logger();

        let req = load_request(&encoded, &mut logger, true).unwrap();
        assert_eq!(req.script_code, "echo hi");
    }

    #[test]
    fn state_aware_unknown_top_level_field_rejected() {
        let json = r#"{
            "phase": "provision",
            "containment": "isolation_session",
            "bogusField": true
        }"#;
        let result = load_mxc(json);
        assert!(
            result.is_err(),
            "unknown top-level field on a state-aware request should be rejected"
        );
    }

    #[test]
    fn state_aware_top_level_annotation_allowed() {
        let json = r#"{
            "$schema": "../schemas/dev/mxc-config.schema.0.7.0-dev.json",
            "phase": "provision",
            "containment": "isolation_session"
        }"#;
        match load_mxc(json).unwrap() {
            MxcRequest::StateAware(p) => assert_eq!(p.phase, Phase::Provision),
            _ => panic!("expected state-aware request"),
        }
    }

    #[test]
    fn state_aware_forwards_container_id() {
        // `containerId` is a documented top-level field and must be preserved
        // into the inner ExecutionRequest for state-aware requests, not dropped.
        let json = r#"{
            "phase": "provision",
            "containerId": "sa-container-1",
            "containment": "isolation_session"
        }"#;
        match load_mxc(json).unwrap() {
            MxcRequest::StateAware(p) => {
                assert_eq!(p.phase, Phase::Provision);
                assert_eq!(p.request.container_id, "sa-container-1");
            }
            _ => panic!("expected state-aware request"),
        }
    }

    #[test]
    fn schema_version_current_accepted() {
        let json = format!(
            r#"{{"process": {{"commandLine": "echo hi"}}, "version": "{}"}}"#,
            CURRENT_SCHEMA_VERSION
        );
        let encoded = base64_encode(json.as_bytes());
        let mut logger = test_logger();

        let req = load_request(&encoded, &mut logger, true).unwrap();
        assert_eq!(req.schema_version, CURRENT_SCHEMA_VERSION);
    }

    #[test]
    fn schema_version_0_5_still_accepted() {
        let json = r#"{"process": {"commandLine": "echo hi"}, "version": "0.5.0-alpha"}"#;
        let encoded = base64_encode(json.as_bytes());
        let mut logger = test_logger();

        let req = load_request(&encoded, &mut logger, true).unwrap();
        assert_eq!(req.schema_version, "0.5.0-alpha");
    }

    #[test]
    fn schema_version_state_aware_06_accepted() {
        // 0.6 is the state-aware schema version (SDK side bumps to it for
        // provision/start/exec/stop/deprovision envelopes); the parser must
        // accept it on the same path used for one-shot 0.5 requests.
        let json = r#"{"process": {"commandLine": "echo hi"}, "version": "0.6.0-alpha"}"#;
        let encoded = base64_encode(json.as_bytes());
        let mut logger = test_logger();

        let req = load_request(&encoded, &mut logger, true).unwrap();
        assert_eq!(req.schema_version, "0.6.0-alpha");
    }

    #[test]
    fn schema_version_older_accepted() {
        let json = r#"{"process": {"commandLine": "echo hi"}, "version": "0.4.0-alpha"}"#;
        let encoded = base64_encode(json.as_bytes());
        let mut logger = test_logger();

        let req = load_request(&encoded, &mut logger, true).unwrap();
        assert_eq!(req.schema_version, "0.4.0-alpha");
    }

    #[test]
    fn schema_version_too_old_rejected() {
        let json = r#"{"process": {"commandLine": "echo hi"}, "version": "0.3.0-alpha"}"#;
        let encoded = base64_encode(json.as_bytes());
        let mut logger = test_logger();

        let result = load_request(&encoded, &mut logger, true);
        assert!(result.is_err());
    }

    #[test]
    fn full_config_with_0_5_0_alpha_accepted() {
        let json = r#"{
            "version": "0.5.0-alpha",
            "containerId": "test-050",
            "containment": "processcontainer",
            "process": { "commandLine": "echo hello", "timeout": 5000 },
            "filesystem": { "readwritePaths": ["C:\\workspace"] },
            "network": { "defaultPolicy": "block" }
        }"#;
        let encoded = base64_encode(json.as_bytes());
        let mut logger = test_logger();

        let req = load_request(&encoded, &mut logger, true).unwrap();
        assert_eq!(req.schema_version, "0.5.0-alpha");
        assert_eq!(req.container_id, "test-050");
        assert_eq!(req.script_timeout, 5000);
        assert_eq!(req.policy.readwrite_paths, vec!["C:\\workspace"]);
    }

    #[test]
    fn schema_version_absent_accepted() {
        let json = r#"{"process": {"commandLine": "echo hi"}}"#;
        let encoded = base64_encode(json.as_bytes());
        let mut logger = test_logger();

        let req = load_request(&encoded, &mut logger, true).unwrap();
        assert_eq!(req.schema_version, "");
    }

    #[test]
    fn schema_version_non_semver_rejected() {
        let json = r#"{"process": {"commandLine": "echo hi"}, "version": "x"}"#;
        let encoded = base64_encode(json.as_bytes());
        let mut logger = test_logger();

        let result = load_request(&encoded, &mut logger, true);
        assert!(result.is_err());
    }

    #[test]
    fn schema_version_major_only_rejected() {
        let json = r#"{"process": {"commandLine": "echo hi"}, "version": "2"}"#;
        let encoded = base64_encode(json.as_bytes());
        let mut logger = test_logger();

        let result = load_request(&encoded, &mut logger, true);
        assert!(result.is_err());
    }

    #[test]
    fn schema_version_future_major_rejected() {
        let json = r#"{"process": {"commandLine": "echo hi"}, "version": "1.0.0"}"#;
        let encoded = base64_encode(json.as_bytes());
        let mut logger = test_logger();

        let result = load_request(&encoded, &mut logger, true);
        assert!(result.is_err());
    }

    #[test]
    fn sandbox_idle_timeout_ms_accepted() {
        let json = r#"{"process": {"commandLine": "echo hi"}, "containment": "windows_sandbox", "experimental": {"windows_sandbox": {"idleTimeoutMs": 60000}}}"#;
        let encoded = base64_encode(json.as_bytes());
        let mut logger = test_logger();

        let req = load_request(&encoded, &mut logger, true).unwrap();
        assert_eq!(
            req.experimental.windows_sandbox.unwrap().idle_timeout_ms,
            60000
        );
    }

    #[test]
    fn sandbox_idle_timeout_ms_overrides_idle_timeout() {
        let json = r#"{"process": {"commandLine": "echo hi"}, "containment": "windows_sandbox", "experimental": {"windows_sandbox": {"idleTimeout": 10000, "idleTimeoutMs": 60000}}}"#;
        let encoded = base64_encode(json.as_bytes());
        let mut logger = test_logger();

        let req = load_request(&encoded, &mut logger, true).unwrap();
        assert_eq!(
            req.experimental.windows_sandbox.unwrap().idle_timeout_ms,
            60000
        );
    }

    #[test]
    fn container_id_parsed() {
        let json = r#"{"process": {"commandLine": "echo hi"}, "containerId": "my-container"}"#;
        let encoded = base64_encode(json.as_bytes());
        let mut logger = test_logger();

        let req = load_request(&encoded, &mut logger, true).unwrap();
        assert_eq!(req.container_id, "my-container");
    }

    #[test]
    fn lifecycle_destroy_on_exit_parsed() {
        let json =
            r#"{"process": {"commandLine": "echo hi"}, "lifecycle": {"destroyOnExit": false}}"#;
        let encoded = base64_encode(json.as_bytes());
        let mut logger = test_logger();

        let req = load_request(&encoded, &mut logger, true).unwrap();
        assert!(!req.lifecycle.destroy_on_exit);
    }

    #[test]
    fn lifecycle_preserve_policy_parsed() {
        let json =
            r#"{"process": {"commandLine": "echo hi"}, "lifecycle": {"preservePolicy": true}}"#;
        let encoded = base64_encode(json.as_bytes());
        let mut logger = test_logger();

        let req = load_request(&encoded, &mut logger, true).unwrap();
        assert!(req.lifecycle.preserve_policy);
    }

    #[test]
    fn lifecycle_defaults_when_absent() {
        let json = r#"{"process": {"commandLine": "echo hi"}}"#;
        let encoded = base64_encode(json.as_bytes());
        let mut logger = test_logger();

        let req = load_request(&encoded, &mut logger, true).unwrap();
        assert!(req.lifecycle.destroy_on_exit);
        assert!(!req.lifecycle.preserve_policy);
    }

    #[test]
    fn wslc_section_parsed() {
        let json = r#"{"process": {"commandLine": "echo hi"}, "containment": "wslc", "experimental": {"wslc": {"image": "python:3.12"}}}"#;
        let encoded = base64_encode(json.as_bytes());
        let mut logger = test_logger();

        let req = load_request(&encoded, &mut logger, true).unwrap();
        let wslc = req.experimental.wslc.unwrap();
        assert_eq!(wslc.image, "python:3.12");
        assert!(wslc.image_tar_path.is_none());
    }

    #[test]
    fn wslc_image_tar_path_parsed() {
        let json = r#"{"process": {"commandLine": "echo hi"}, "containment": "wslc", "experimental": {"wslc": {"image": "my-image:latest", "imageTarPath": "C:\\images\\alpine.tar"}}}"#;
        let encoded = base64_encode(json.as_bytes());
        let mut logger = test_logger();

        let req = load_request(&encoded, &mut logger, true).unwrap();
        let wslc = req.experimental.wslc.unwrap();
        assert_eq!(wslc.image, "my-image:latest");
        assert_eq!(
            wslc.image_tar_path.as_deref(),
            Some("C:\\images\\alpine.tar")
        );
    }

    #[test]
    fn wslc_port_mappings_parsed() {
        let json = r#"{"process": {"commandLine": "echo hi"}, "containment": "wslc", "experimental": {"wslc": {"image": "python:3.12", "portMappings": [{"windowsPort": 8080, "containerPort": 80, "protocol": "tcp"}, {"windowsPort": 5353, "containerPort": 53, "protocol": "udp"}]}}}"#;
        let encoded = base64_encode(json.as_bytes());
        let mut logger = test_logger();

        let req = load_request(&encoded, &mut logger, true).unwrap();
        let wslc = req.experimental.wslc.unwrap();
        assert_eq!(wslc.port_mappings.len(), 2);
        assert_eq!(wslc.port_mappings[0].windows_port, 8080);
        assert_eq!(wslc.port_mappings[0].container_port, 80);
        assert_eq!(wslc.port_mappings[0].protocol, "tcp");
        assert_eq!(wslc.port_mappings[1].protocol, "udp");
    }

    #[test]
    fn wslc_port_mappings_default_protocol_is_tcp() {
        let json = r#"{"process": {"commandLine": "echo hi"}, "containment": "wslc", "experimental": {"wslc": {"image": "python:3.12", "portMappings": [{"windowsPort": 8080, "containerPort": 80}]}}}"#;
        let encoded = base64_encode(json.as_bytes());
        let mut logger = test_logger();

        let req = load_request(&encoded, &mut logger, true).unwrap();
        let wslc = req.experimental.wslc.unwrap();
        assert_eq!(wslc.port_mappings[0].protocol, "tcp");
    }

    #[test]
    fn wslc_port_mappings_missing_windows_port_rejected() {
        let json = r#"{"process": {"commandLine": "echo hi"}, "containment": "wslc", "experimental": {"wslc": {"image": "python:3.12", "portMappings": [{"containerPort": 80}]}}}"#;
        let encoded = base64_encode(json.as_bytes());
        let mut logger = test_logger();

        assert!(load_request(&encoded, &mut logger, true).is_err());
    }

    #[test]
    fn wslc_port_mappings_zero_port_rejected() {
        let json = r#"{"process": {"commandLine": "echo hi"}, "containment": "wslc", "experimental": {"wslc": {"image": "python:3.12", "portMappings": [{"windowsPort": 0, "containerPort": 80}]}}}"#;
        let encoded = base64_encode(json.as_bytes());
        let mut logger = test_logger();

        assert!(load_request(&encoded, &mut logger, true).is_err());
    }

    #[test]
    fn wslc_port_mappings_invalid_protocol_rejected() {
        let json = r#"{"process": {"commandLine": "echo hi"}, "containment": "wslc", "experimental": {"wslc": {"image": "python:3.12", "portMappings": [{"windowsPort": 8080, "containerPort": 80, "protocol": "sctp"}]}}}"#;
        let encoded = base64_encode(json.as_bytes());
        let mut logger = test_logger();

        assert!(load_request(&encoded, &mut logger, true).is_err());
    }

    // ---------- Experimental feature tests ----------

    #[test]
    fn experimental_section_parsed_when_present() {
        let json = r#"{"process": {"commandLine": "echo hi"}, "experimental": {"test": {"message": "world"}}}"#;
        let encoded = base64_encode(json.as_bytes());
        let mut logger = test_logger();

        let req = load_request(&encoded, &mut logger, true).unwrap();
        assert!(req.experimental.test.is_some());
        assert_eq!(req.experimental.test.unwrap().message, "world");
    }

    #[test]
    fn experimental_section_absent_is_ok() {
        let json = r#"{"process": {"commandLine": "echo hi"}}"#;
        let encoded = base64_encode(json.as_bytes());
        let mut logger = test_logger();

        let req = load_request(&encoded, &mut logger, true).unwrap();
        assert!(req.experimental.test.is_none());
    }

    #[test]
    fn experimental_enabled_defaults_to_false() {
        let json = r#"{"process": {"commandLine": "echo hi"}, "experimental": {"test": {"message": "check"}}}"#;
        let encoded = base64_encode(json.as_bytes());
        let mut logger = test_logger();

        let req = load_request(&encoded, &mut logger, true).unwrap();
        assert!(!req.experimental_enabled);
    }

    #[test]
    fn unknown_experimental_fields_ignored() {
        let json = r#"{"process": {"commandLine": "echo hi"}, "experimental": {"futureFeature": {"x": 1}, "test": {"message": "hi"}}}"#;
        let encoded = base64_encode(json.as_bytes());
        let mut logger = test_logger();

        let req = load_request(&encoded, &mut logger, true).unwrap();
        assert!(req.experimental.test.is_some());
    }

    #[test]
    fn experimental_test_message_parsed() {
        let json = r#"{"process": {"commandLine": "echo hi"}, "experimental": {"test": {"message": "greetings"}}}"#;
        let encoded = base64_encode(json.as_bytes());
        let mut logger = test_logger();

        let req = load_request(&encoded, &mut logger, true).unwrap();
        let test = req.experimental.test.unwrap();
        assert_eq!(test.message, "greetings");
    }

    #[test]
    fn experimental_test_default_message() {
        let json = r#"{"process": {"commandLine": "echo hi"}, "experimental": {"test": {}}}"#;
        let encoded = base64_encode(json.as_bytes());
        let mut logger = test_logger();

        let req = load_request(&encoded, &mut logger, true).unwrap();
        let test = req.experimental.test.unwrap();
        assert!(test.message.is_empty());
    }

    #[test]
    fn ui_section_parsed() {
        let json = r#"{"process": {"commandLine": "echo hi"}, "ui": {"disable": false, "clipboard": "read", "injection": true}}"#;
        let encoded = base64_encode(json.as_bytes());
        let mut logger = test_logger();

        let req = load_request(&encoded, &mut logger, true).unwrap();
        assert!(!req.policy.ui.disable);
        assert_eq!(req.policy.ui.clipboard, ClipboardPolicy::Read);
        assert!(req.policy.ui.injection);
    }

    #[test]
    fn ui_section_defaults_when_omitted() {
        let json = r#"{"process": {"commandLine": "echo hi"}}"#;
        let encoded = base64_encode(json.as_bytes());
        let mut logger = test_logger();

        let req = load_request(&encoded, &mut logger, true).unwrap();
        assert!(req.policy.ui.disable); // default-deny: UI disabled
        assert_eq!(req.policy.ui.clipboard, ClipboardPolicy::None);
        assert!(!req.policy.ui.injection);
    }

    #[test]
    fn ui_clipboard_all_parsed() {
        let json = r#"{"process": {"commandLine": "echo hi"}, "ui": {"clipboard": "all"}}"#;
        let encoded = base64_encode(json.as_bytes());
        let mut logger = test_logger();

        let req = load_request(&encoded, &mut logger, true).unwrap();
        assert_eq!(req.policy.ui.clipboard, ClipboardPolicy::All);
    }

    #[test]
    fn is_base_container_version_recognizes_050() {
        assert!(is_base_container_version("0.5.0-alpha"));
        assert!(is_base_container_version("0.5.0"));
        assert!(is_base_container_version("0.5.1"));
        assert!(is_base_container_version("0.6.0"));
        assert!(is_base_container_version("1.0.0"));
    }

    #[test]
    fn is_base_container_version_rejects_040() {
        assert!(!is_base_container_version("0.4.0-alpha"));
        assert!(!is_base_container_version("0.4.0"));
        assert!(!is_base_container_version("0.4.9"));
        assert!(!is_base_container_version(""));
        assert!(!is_base_container_version("not-a-version"));
    }

    // ====== Isolation Session containment and config tests ======

    #[test]
    fn containment_isolation_session_accepted() {
        let json = r#"{"process": {"commandLine": "echo hi"}, "containment": "isolation_session"}"#;
        let encoded = base64_encode(json.as_bytes());
        let mut logger = test_logger();

        let req = load_request(&encoded, &mut logger, true).unwrap();
        assert_eq!(req.containment, ContainmentBackend::IsolationSession);
    }

    #[test]
    fn isolation_session_config_defaults() {
        let json = r#"{"process": {"commandLine": "echo hi"}, "containment": "isolation_session", "experimental": {"isolation_session": {}}}"#;
        let encoded = base64_encode(json.as_bytes());
        let mut logger = test_logger();

        let req = load_request(&encoded, &mut logger, true).unwrap();
        let cfg = req.experimental.isolation_session.unwrap();
        assert_eq!(
            cfg.configuration_id,
            crate::models::IsolationSessionConfigurationId::Composable
        );
    }

    #[test]
    fn isolation_session_config_small() {
        let json = r#"{"process": {"commandLine": "echo hi"}, "containment": "isolation_session", "experimental": {"isolation_session": {"configurationId": "small"}}}"#;
        let encoded = base64_encode(json.as_bytes());
        let mut logger = test_logger();

        let req = load_request(&encoded, &mut logger, true).unwrap();
        let cfg = req.experimental.isolation_session.unwrap();
        assert_eq!(
            cfg.configuration_id,
            crate::models::IsolationSessionConfigurationId::Small
        );
    }

    #[test]
    fn isolation_session_config_medium() {
        let json = r#"{"process": {"commandLine": "echo hi"}, "containment": "isolation_session", "experimental": {"isolation_session": {"configurationId": "medium"}}}"#;
        let encoded = base64_encode(json.as_bytes());
        let mut logger = test_logger();

        let req = load_request(&encoded, &mut logger, true).unwrap();
        let cfg = req.experimental.isolation_session.unwrap();
        assert_eq!(
            cfg.configuration_id,
            crate::models::IsolationSessionConfigurationId::Medium
        );
    }

    #[test]
    fn isolation_session_config_large() {
        let json = r#"{"process": {"commandLine": "echo hi"}, "containment": "isolation_session", "experimental": {"isolation_session": {"configurationId": "large"}}}"#;
        let encoded = base64_encode(json.as_bytes());
        let mut logger = test_logger();

        let req = load_request(&encoded, &mut logger, true).unwrap();
        let cfg = req.experimental.isolation_session.unwrap();
        assert_eq!(
            cfg.configuration_id,
            crate::models::IsolationSessionConfigurationId::Large
        );
    }

    #[test]
    fn isolation_session_config_composable() {
        let json = r#"{"process": {"commandLine": "echo hi"}, "containment": "isolation_session", "experimental": {"isolation_session": {"configurationId": "composable"}}}"#;
        let encoded = base64_encode(json.as_bytes());
        let mut logger = test_logger();

        let req = load_request(&encoded, &mut logger, true).unwrap();
        let cfg = req.experimental.isolation_session.unwrap();
        assert_eq!(
            cfg.configuration_id,
            crate::models::IsolationSessionConfigurationId::Composable
        );
    }

    #[test]
    fn isolation_session_config_unknown_defaults_to_composable() {
        let json = r#"{"process": {"commandLine": "echo hi"}, "containment": "isolation_session", "experimental": {"isolation_session": {"configurationId": "xlarge"}}}"#;
        let encoded = base64_encode(json.as_bytes());
        let mut logger = test_logger();

        let req = load_request(&encoded, &mut logger, true).unwrap();
        let cfg = req.experimental.isolation_session.unwrap();
        assert_eq!(
            cfg.configuration_id,
            crate::models::IsolationSessionConfigurationId::Composable
        );
    }

    #[test]
    fn isolation_session_absent_from_experimental() {
        let json = r#"{"process": {"commandLine": "echo hi"}, "experimental": {}}"#;
        let encoded = base64_encode(json.as_bytes());
        let mut logger = test_logger();

        let req = load_request(&encoded, &mut logger, true).unwrap();
        assert!(req.experimental.isolation_session.is_none());
    }

    #[test]
    fn isolation_session_user_field_round_trips_through_one_shot_parser() {
        let json = r#"{"process": {"commandLine": "echo hi"}, "containment": "isolation_session", "experimental": {"isolation_session": {"user": {"upn": "alice@contoso.com", "wamToken": "tok"}}}}"#;
        let encoded = base64_encode(json.as_bytes());
        let mut logger = test_logger();

        let req = load_request(&encoded, &mut logger, true).unwrap();
        let cfg = req.experimental.isolation_session.unwrap();
        let user = cfg
            .user
            .expect("user field should round-trip through the one-shot parser");
        assert_eq!(user.upn, "alice@contoso.com");
        assert_eq!(user.wam_token, "tok");
    }

    #[test]
    fn isolation_session_user_absent_when_field_omitted() {
        let json = r#"{"process": {"commandLine": "echo hi"}, "containment": "isolation_session", "experimental": {"isolation_session": {"configurationId": "medium"}}}"#;
        let encoded = base64_encode(json.as_bytes());
        let mut logger = test_logger();

        let req = load_request(&encoded, &mut logger, true).unwrap();
        let cfg = req.experimental.isolation_session.unwrap();
        assert!(cfg.user.is_none());
    }

    #[test]
    fn containment_seatbelt_accepted() {
        let json = r#"{"process": {"commandLine": "echo hi"}, "containment": "seatbelt"}"#;
        let encoded = base64_encode(json.as_bytes());
        let mut logger = test_logger();

        let req = load_request(&encoded, &mut logger, true).unwrap();
        assert_eq!(req.containment, ContainmentBackend::Seatbelt);
    }

    #[test]
    fn seatbelt_config_defaults() {
        // When no seatbelt block is provided the parser leaves it unset.
        let json = r#"{"process": {"commandLine": "echo hi"}, "containment": "seatbelt"}"#;
        let encoded = base64_encode(json.as_bytes());
        let mut logger = test_logger();

        let req = load_request(&encoded, &mut logger, true).unwrap();
        assert!(req.seatbelt.is_none());
    }

    #[test]
    fn seatbelt_profile_override_passed_through() {
        let json = r#"{"process": {"commandLine": "echo hi"}, "containment": "seatbelt", "seatbelt": {"profileOverride": "(version 1)(deny default)"}}"#;
        let encoded = base64_encode(json.as_bytes());
        let mut logger = test_logger();

        let req = load_request(&encoded, &mut logger, true).unwrap();
        let cfg = req.seatbelt.expect("seatbelt should be populated");
        assert_eq!(
            cfg.profile_override.as_deref(),
            Some("(version 1)(deny default)")
        );
    }

    #[test]
    fn seatbelt_nested_pty_defaults_to_true_when_block_present_but_field_absent() {
        // seatbelt block is present but nestedPty is not specified;
        // the parser should fill in true to match the schema default.
        let json =
            r#"{"process": {"commandLine": "echo hi"}, "containment": "seatbelt", "seatbelt": {}}"#;
        let encoded = base64_encode(json.as_bytes());
        let mut logger = test_logger();

        let req = load_request(&encoded, &mut logger, true).unwrap();
        let cfg = req.seatbelt.expect("seatbelt should be populated");
        assert!(cfg.nested_pty);
        assert!(!cfg.keychain_access);
    }

    #[test]
    fn seatbelt_nested_pty_and_keychain_access_pass_through() {
        let json = r#"{"process": {"commandLine": "echo hi"}, "containment": "seatbelt", "seatbelt": {"nestedPty": false, "keychainAccess": true}}"#;
        let encoded = base64_encode(json.as_bytes());
        let mut logger = test_logger();

        let req = load_request(&encoded, &mut logger, true).unwrap();
        let cfg = req.seatbelt.expect("seatbelt should be populated");
        assert!(!cfg.nested_pty);
        assert!(cfg.keychain_access);
    }

    #[test]
    fn top_level_seatbelt_config_accepted() {
        let json = r#"{"process": {"commandLine": "echo hi"}, "containment": "seatbelt", "seatbelt": {"nestedPty": false, "keychainAccess": true}}"#;
        let encoded = base64_encode(json.as_bytes());
        let mut logger = test_logger();

        let req = load_request(&encoded, &mut logger, true).unwrap();
        let cfg = req.seatbelt.expect("seatbelt should be populated");
        assert!(!cfg.nested_pty);
        assert!(cfg.keychain_access);
    }

    #[test]
    fn experimental_seatbelt_errors_with_migration_message() {
        // After promotion, configs using experimental.seatbelt must error.
        let json = r#"{"process": {"commandLine": "echo hi"}, "containment": "seatbelt", "experimental": {"seatbelt": {"nestedPty": true}}}"#;
        let encoded = base64_encode(json.as_bytes());
        let mut logger = test_logger();

        let err = load_request(&encoded, &mut logger, true).unwrap_err();
        let msg = format!("{:?}", err);
        assert!(
            msg.contains("has moved to the stable section"),
            "expected migration error, got: {}",
            msg
        );
    }

    // Legacy wire-name aliases. The parser accepts the pre-0.6 wire vocabulary
    // (`appcontainer`, `macos_sandbox`, and the `appContainer` /
    // `experimental.macos_sandbox` sub-block keys) so that configs declaring
    // earlier stable schemas (0.4.0-alpha, 0.5.0-alpha) continue to parse.
    // Each alias maps to the canonical backend / sub-block and emits a
    // deprecation log so callers know to migrate.

    #[test]
    fn legacy_appcontainer_wire_value_aliases_processcontainer() {
        let json = r#"{"process": {"commandLine": "echo hi"}, "containment": "appcontainer"}"#;
        let encoded = base64_encode(json.as_bytes());
        let mut logger = test_logger();

        let req = load_request(&encoded, &mut logger, true).unwrap();
        assert_eq!(req.containment, ContainmentBackend::ProcessContainer);
    }

    #[test]
    fn legacy_macos_sandbox_wire_value_aliases_seatbelt() {
        let json = r#"{"process": {"commandLine": "echo hi"}, "containment": "macos_sandbox"}"#;
        let encoded = base64_encode(json.as_bytes());
        let mut logger = test_logger();

        let req = load_request(&encoded, &mut logger, true).unwrap();
        assert_eq!(req.containment, ContainmentBackend::Seatbelt);
    }

    #[test]
    fn legacy_app_container_subblock_alias_accepted() {
        // Configs written against 0.4.0-alpha / 0.5.0-alpha still use the
        // `appContainer` JSON key; serde's alias routes it to the same
        // `processContainer` parsing path.
        let json = r#"{
            "process": {"commandLine": "print('test')"},
            "containment": "processcontainer",
            "appContainer": {
                "leastPrivilege": true,
                "capabilities": ["internetClient"]
            }
        }"#;
        let encoded = base64_encode(json.as_bytes());
        let mut logger = test_logger();

        let req = load_request(&encoded, &mut logger, true).unwrap();
        assert!(req.policy.least_privilege_mode);
        assert_eq!(req.policy.capabilities, vec!["internetClient".to_string()]);
    }

    #[test]
    fn legacy_experimental_macos_sandbox_subblock_alias_rejected() {
        // `experimental.macos_sandbox` is the pre-rename key; after promotion
        // it should be rejected with a migration error.
        let json = r#"{
            "process": {"commandLine": "echo hi"},
            "containment": "macos_sandbox",
            "experimental": {"macos_sandbox": {"profileOverride": "(version 1)(allow default)"}}
        }"#;
        let encoded = base64_encode(json.as_bytes());
        let mut logger = test_logger();

        let err = load_request(&encoded, &mut logger, true).unwrap_err();
        let msg = format!("{:?}", err);
        assert!(
            msg.contains("has moved to the stable section"),
            "expected migration error, got: {}",
            msg
        );
    }

    // ---- Single-backend-section enforcement ----

    fn make_multi_backend_config(containment: &str, extra_json: &str) -> String {
        let json = format!(
            r#"{{ "containment": "{containment}", "process": {{"commandLine": "echo hi"}}, {extra_json} }}"#
        );
        base64_encode(json.as_bytes())
    }

    fn assert_multi_backend_rejected(containment: &str, extra_json: &str, expected_extra: &str) {
        let encoded = make_multi_backend_config(containment, extra_json);
        let mut logger = test_logger();
        let err =
            load_request(&encoded, &mut logger, true).expect_err("expected rejection but got Ok");
        let msg = format!("{err:?}");
        assert!(
            msg.contains("Multiple containment backends configured"),
            "error did not mention multi-backend rejection: {msg}"
        );
        assert!(
            msg.contains(expected_extra),
            "error did not name the foreign section '{expected_extra}': {msg}"
        );
    }

    fn assert_config_accepted(containment: &str, extra_json: &str) {
        let encoded = make_multi_backend_config(containment, extra_json);
        let mut logger = test_logger();
        load_request(&encoded, &mut logger, true)
            .unwrap_or_else(|err| panic!("expected accept, got error: {err:?}"));
    }

    #[test]
    fn lxc_containment_with_processcontainer_section_rejected() {
        assert_multi_backend_rejected(
            "lxc",
            r#""lxc": {"distribution": "alpine", "release": "3.20"}, "processContainer": {"leastPrivilege": true}"#,
            "processContainer",
        );
    }

    // appContainer is a deprecated alias for processContainer.
    #[test]
    fn lxc_containment_with_legacy_app_container_alias_rejected() {
        assert_multi_backend_rejected(
            "lxc",
            r#""lxc": {"distribution": "alpine", "release": "3.20"}, "appContainer": {"leastPrivilege": true}"#,
            "processContainer",
        );
    }

    #[test]
    fn processcontainer_containment_with_lxc_section_rejected() {
        assert_multi_backend_rejected(
            "processcontainer",
            r#""lxc": {"distribution": "alpine", "release": "3.20"}"#,
            "lxc",
        );
    }

    // Per-backend blocks nested under `experimental` are subject to the same
    // check as top-level blocks.
    #[test]
    fn experimental_backend_section_for_other_containment_rejected() {
        // seatbelt is now top-level, so use it to test cross-backend rejection
        assert_multi_backend_rejected(
            "processcontainer",
            r#""seatbelt": {"guiAccess": true}"#,
            "seatbelt",
        );
    }

    // Sectionless backend: bubblewrap doesn't own any per-backend block, so
    // any backend block is foreign.
    #[test]
    fn bubblewrap_containment_with_lxc_section_rejected() {
        assert_multi_backend_rejected(
            "bubblewrap",
            r#""lxc": {"distribution": "alpine", "release": "3.20"}"#,
            "lxc",
        );
    }

    #[test]
    fn bubblewrap_containment_with_process_container_section_rejected() {
        assert_multi_backend_rejected(
            "bubblewrap",
            r#""processContainer": {"leastPrivilege": true}"#,
            "processContainer",
        );
    }

    #[test]
    fn lxc_containment_with_matching_lxc_section_accepted() {
        assert_config_accepted(
            "lxc",
            r#""lxc": {"distribution": "alpine", "release": "3.20"}"#,
        );
    }

    // `experimental.test` is a generic test feature, not a backend block,
    // so it should not trigger the multi-backend check.
    #[test]
    fn experimental_test_section_does_not_count_as_backend() {
        assert_config_accepted(
            "lxc",
            r#""lxc": {"distribution": "alpine", "release": "3.20"}, "experimental": {"test": {"message": "hello"}}"#,
        );
    }

    // State-aware path: an `experimental` block whose backend key doesn't
    // match the resolved `containment` is rejected the same way as in the
    // one-shot path.
    #[test]
    fn state_aware_foreign_experimental_backend_rejected() {
        let json = r#"{
            "phase": "provision",
            "containment": "isolation_session",
            "experimental": {
                "isolation_session": {},
                "wslc": {"image": "alpine:latest"}
            }
        }"#;
        let encoded = base64_encode(json.as_bytes());
        let mut logger = test_logger();
        let err = load_mxc_request(&encoded, &mut logger, true)
            .expect_err("state-aware config with foreign experimental backend should be rejected");
        let msg = format!("{err:?}");
        assert!(
            msg.contains("Multiple containment backends configured"),
            "error did not mention multi-backend rejection: {msg}"
        );
        assert!(
            msg.contains("experimental.wslc"),
            "error did not name the foreign section: {msg}"
        );
    }

    // ---- Abstract-intent coverage ----
    // Backend sections paired with `containment: "process"` / "vm" must be
    // accepted iff the intent resolves to the owning backend on this OS.

    #[cfg(target_os = "windows")]
    #[test]
    fn abstract_process_with_process_container_accepted_on_windows() {
        let json = r#"{
            "process": {"commandLine": "echo hi"},
            "containment": "process",
            "processContainer": {}
        }"#;
        let encoded = base64_encode(json.as_bytes());
        let mut logger = test_logger();
        load_request(&encoded, &mut logger, true)
            .expect("process resolves to ProcessContainer on Windows");
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn abstract_process_with_seatbelt_accepted_on_macos() {
        let json = r#"{
            "process": {"commandLine": "echo hi"},
            "containment": "process",
            "seatbelt": {}
        }"#;
        let encoded = base64_encode(json.as_bytes());
        let mut logger = test_logger();
        load_request(&encoded, &mut logger, true).expect("process resolves to Seatbelt on macOS");
    }

    #[cfg(not(any(target_os = "windows", target_os = "macos")))]
    #[test]
    fn abstract_process_with_process_container_rejected_off_windows() {
        let json = r#"{
            "process": {"commandLine": "echo hi"},
            "containment": "process",
            "processContainer": {}
        }"#;
        let encoded = base64_encode(json.as_bytes());
        let mut logger = test_logger();
        load_request(&encoded, &mut logger, true)
            .expect_err("processContainer is foreign when process resolves off Windows");
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn abstract_vm_with_windows_sandbox_accepted_on_windows() {
        let json = r#"{
            "process": {"commandLine": "echo hi"},
            "containment": "vm",
            "experimental": {"windows_sandbox": {}}
        }"#;
        let encoded = base64_encode(json.as_bytes());
        let mut logger = test_logger();
        load_request(&encoded, &mut logger, true)
            .expect("vm resolves to WindowsSandbox on Windows");
    }

    #[cfg(not(target_os = "windows"))]
    #[test]
    fn abstract_vm_with_windows_sandbox_rejected_off_windows() {
        let json = r#"{
            "process": {"commandLine": "echo hi"},
            "containment": "vm",
            "experimental": {"windows_sandbox": {}}
        }"#;
        let encoded = base64_encode(json.as_bytes());
        let mut logger = test_logger();
        load_request(&encoded, &mut logger, true).expect_err("vm has no resolver off Windows");
    }
}
