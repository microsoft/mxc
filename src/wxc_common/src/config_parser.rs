// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use std::fmt::Write;
use std::fs;

use serde::Deserialize;

use crate::encoding::base64_decode;
use crate::error::WxcError;
use crate::logger::Logger;
use crate::models::{
    IsolationSessionConfig, ClipboardPolicy, CodexRequest, ContainerPolicy, ContainmentBackend,
    ExperimentalConfig, LifecycleConfig, LxcConfig, NetworkEnforcementMode, NetworkPolicy,
    PortMapping, ProxyAddress, ProxyConfig, TestFeatureConfig, UiPolicy, WindowsSandboxConfig,
    WslcConfig,
};

// ---------- Intermediate serde structs matching the JSON schema ----------

#[derive(Deserialize, Default)]
#[serde(default)]
struct RawAppContainer {
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
struct RawNetwork {
    #[serde(rename = "defaultPolicy")]
    default_policy: Option<String>,
    #[serde(rename = "enforcementMode")]
    enforcement_mode: Option<String>,
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

#[derive(Deserialize, Default)]
#[serde(default)]
struct RawPortMapping {
    #[serde(rename = "windowsPort")]
    windows_port: Option<u16>,
    #[serde(rename = "containerPort")]
    container_port: Option<u16>,
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
    platform: Option<String>,
    process: Option<RawProcess>,
    lifecycle: Option<RawLifecycle>,
    containment: Option<String>,
    #[serde(rename = "appContainer")]
    app_container: Option<RawAppContainer>,
    lxc: Option<RawLxc>,
    filesystem: Option<RawFilesystem>,
    network: Option<RawNetwork>,
    ui: Option<RawUi>,
    experimental: Option<RawExperimental>,
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

/// Loads and parses a JSON-based code execution request.
///
/// If `is_base64` is true, `input` is treated as a base64-encoded JSON string.
/// Otherwise `input` is treated as a file path.
pub fn load_request(
    input: &str,
    logger: &mut Logger,
    is_base64: bool,
) -> Result<CodexRequest, WxcError> {
    let json_str = if is_base64 {
        let bytes = base64_decode(input).map_err(|_| {
            let msg = "Failed to decode base64 configuration";
            logger.log_line(msg);
            WxcError::ConfigParse(msg.to_string())
        })?;
        String::from_utf8(bytes).map_err(|_| {
            let msg = "Base64 decoded content is not valid UTF-8";
            logger.log_line(msg);
            WxcError::ConfigParse(msg.to_string())
        })?
    } else {
        // Treat input as a file path
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
        })?
    };

    let raw: RawConfig = serde_json::from_str(&json_str).map_err(|e| {
        logger.log_line("Error parsing JSON");
        WxcError::ConfigParse(format!("JSON parse error: {}", e))
    })?;

    convert_raw_config(raw, logger)
}

// ---------- Cross-field validation ----------

/// Maximum supported schema version (major.minor). Configs with a higher major.minor are rejected.
const SUPPORTED_VERSION: &str = ">=0.4, <=0.5";

/// The minimum schema version that implies BaseContainer backend usage.
const BASE_CONTAINER_MIN_VERSION: &str = "0.5.0";

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

fn convert_raw_config(raw: RawConfig, logger: &mut Logger) -> Result<CodexRequest, WxcError> {
    // New top-level fields
    let schema_version = raw.version.unwrap_or_default();
    let container_id = raw.container_id.unwrap_or_default();
    let platform = raw.platform.unwrap_or_else(|| "windows".to_string());

    // Process section is required
    let process = raw
        .process
        .ok_or_else(|| WxcError::ConfigParse("'process' section is required".into()))?;

    let script_code = match process.command_line {
        Some(s) if !s.is_empty() => s,
        Some(_) => {
            logger.log_line("process.commandLine cannot be empty");
            return Err(WxcError::ConfigParse(
                "process.commandLine cannot be empty".to_string(),
            ));
        }
        None => {
            logger.log_line("Missing required field: process.commandLine");
            return Err(WxcError::ConfigParse(
                "Missing required field: process.commandLine".to_string(),
            ));
        }
    };

    // Script should not have embedded null bytes
    // Null bytes can be used to hide malicious payloads from audit logs or other inspection
    if script_code.contains('\0') {
        return Err(WxcError::ConfigParse(
            "process.commandLine must not contain null bytes".to_string(),
        ));
    }

    let working_directory = process.cwd.unwrap_or_default();
    let script_timeout = process.timeout.unwrap_or(0);
    let env = process.env.unwrap_or_default();

    // Containment backend selection
    let containment = match raw.containment.as_deref() {
        None | Some("appcontainer") => ContainmentBackend::AppContainer,
        Some("windows_sandbox") => ContainmentBackend::WindowsSandbox,
        Some("wslc") => ContainmentBackend::Wslc,
        Some("lxc") => ContainmentBackend::Lxc,
        Some("vm") => ContainmentBackend::Vm,
        Some("microvm") => ContainmentBackend::MicroVm,
        Some("isolation_session") => ContainmentBackend::IsolationSession,
        Some(other) => {
            let msg = format!(
                "Invalid containment value '{}' (must be 'appcontainer', 'windows_sandbox', 'isolation_session', 'wslc', 'lxc', 'vm', or 'microvm')",
                other
            );
            logger.log_line(&msg);
            return Err(WxcError::ConfigParse(msg));
        }
    };

    // LXC configuration
    let lxc_config = {
        let raw_lxc = raw.lxc.unwrap_or_default();
        LxcConfig {
            distribution: raw_lxc.distribution.unwrap_or_default(),
            release: raw_lxc.release.unwrap_or_default(),
        }
    };

    let mut policy = ContainerPolicy::default();

    // AppContainer section
    if let Some(ac) = raw.app_container {
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

    // Network section
    if let Some(net) = raw.network {
        if let Some(proxy_value) = net.proxy {
            let proxy_config = parse_proxy_config(&proxy_value)?;
            if proxy_config.is_enabled() && containment != ContainmentBackend::AppContainer {
                let msg =
                    "Network proxy is only supported with the 'appcontainer' containment backend";
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

        if let Some(v) = net.allowed_hosts {
            policy.allowed_hosts = v;
        }
        if let Some(v) = net.blocked_hosts {
            policy.blocked_hosts = v;
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

    // Schema version check
    validate_schema_version(&schema_version, logger)?;

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
        let wslc = raw_exp.wslc.map(|cc| {
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
                config.port_mappings = mappings
                    .into_iter()
                    .map(|m| PortMapping {
                        windows_port: m.windows_port.unwrap_or(0),
                        container_port: m.container_port.unwrap_or(0),
                        protocol: m.protocol.unwrap_or_else(|| "tcp".to_string()),
                    })
                    .collect();
            }
            config
        });
        let isolation_session = raw_exp.isolation_session.map(|as_cfg| {
            let mut config = IsolationSessionConfig::default();
            if let Some(id) = as_cfg.configuration_id {
                use crate::models::IsolationSessionConfigurationId;
                config.configuration_id = match id.as_str() {
                    "small" => IsolationSessionConfigurationId::Small,
                    "medium" => IsolationSessionConfigurationId::Medium,
                    "large" => IsolationSessionConfigurationId::Large,
                    "commandline" => IsolationSessionConfigurationId::CommandLine,
                    _ => {
                        logger.log_line(&format!(
                            "Unknown isolation_session configurationId '{}', defaulting to 'small'",
                            id
                        ));
                        IsolationSessionConfigurationId::Small
                    }
                };
            }
            config
        });
        ExperimentalConfig {
            test,
            windows_sandbox,
            wslc,
            isolation_session,
        }
    } else {
        ExperimentalConfig::default()
    };

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

    Ok(CodexRequest {
        schema_version,
        container_id,
        platform,
        env,
        script_code,
        working_directory,
        script_timeout,
        containment,
        lifecycle,
        policy,
        lxc_config,
        experimental_enabled: false,
        experimental,
        dry_run: false,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::encoding::base64_encode;
    use crate::logger::Mode;

    fn test_logger() -> Logger {
        Logger::new(Mode::Buffer)
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
        let json = r#"{"containment": "appcontainer"}"#;
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
            "process": {
                "commandLine": "dir",
                "cwd": "C:\\temp",
                "timeout": 3000
            },
            "appContainer": {
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
        let json =
            r#"{"process": {"commandLine": "echo x"}, "appContainer": {"learningMode": true}}"#;
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
        let json = r#"{"process": {"commandLine": "echo x"}, "appContainer": {"capabilities": ["permissiveLearningMode"]}}"#;
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
    fn app_container_capabilities() {
        let json = r#"{
            "process": {"commandLine": "print('test')"},
            "appContainer": {
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
        let json = r#"{"process": {"commandLine": "print('test')"}, "appContainer": {"leastPrivilege": true}}"#;
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
            "process": {
                "commandLine": "import sys\nprint(sys.version)",
                "timeout": 10000
            },
            "appContainer": {
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

    // ====== Containment backend selection tests ======

    #[test]
    fn default_containment_is_appcontainer() {
        let json = r#"{"process": {"commandLine": "echo hello"}}"#;
        let encoded = base64_encode(json.as_bytes());
        let mut logger = test_logger();

        let req = load_request(&encoded, &mut logger, true).unwrap();
        assert_eq!(req.containment, ContainmentBackend::AppContainer);
    }

    #[test]
    fn explicit_appcontainer_containment() {
        let json = r#"{"process": {"commandLine": "echo hello"}, "containment": "appcontainer"}"#;
        let encoded = base64_encode(json.as_bytes());
        let mut logger = test_logger();

        let req = load_request(&encoded, &mut logger, true).unwrap();
        assert_eq!(req.containment, ContainmentBackend::AppContainer);
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
        let json = r#"{"process": {"commandLine": "echo hello"}, "experimental": {"windows_sandbox": {}}}"#;
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
    fn proxy_rejected_with_non_appcontainer() {
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
    fn proxy_builtin_test_server_rejected_with_non_appcontainer() {
        let json = r#"{"process":{"commandLine":"x"},"containment":"lxc","network":{"proxy":{"builtinTestServer":true}}}"#;
        let encoded = base64_encode(json.as_bytes());
        let mut logger = test_logger();

        let result = load_request(&encoded, &mut logger, true);
        assert!(result.is_err());
    }

    #[test]
    fn new_toplevel_fields_parsed() {
        let json = r#"{"version": "0.4.0-alpha", "containerId": "abc-123", "platform": "linux", "containment": "lxc", "process": {"commandLine": "echo hi"}}"#;
        let encoded = base64_encode(json.as_bytes());
        let mut logger = test_logger();

        let req = load_request(&encoded, &mut logger, true).unwrap();
        assert_eq!(req.schema_version, "0.4.0-alpha");
        assert_eq!(req.container_id, "abc-123");
        assert_eq!(req.platform, "linux");
    }

    #[test]
    fn new_toplevel_fields_default_when_absent() {
        let json = r#"{"process": {"commandLine": "echo hi"}}"#;
        let encoded = base64_encode(json.as_bytes());
        let mut logger = test_logger();

        let req = load_request(&encoded, &mut logger, true).unwrap();
        assert_eq!(req.schema_version, "");
        assert_eq!(req.container_id, "");
        assert_eq!(req.platform, "windows");
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
    fn containment_vm_accepted() {
        let json = r#"{"process": {"commandLine": "echo hi"}, "containment": "vm"}"#;
        let encoded = base64_encode(json.as_bytes());
        let mut logger = test_logger();

        let req = load_request(&encoded, &mut logger, true).unwrap();
        assert_eq!(req.containment, ContainmentBackend::Vm);
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
        let json = r#"{"process": {"commandLine": "echo hi"}, "version": "0.6.0"}"#;
        let encoded = base64_encode(json.as_bytes());
        let mut logger = test_logger();

        let result = load_request(&encoded, &mut logger, true);
        assert!(result.is_err());
    }

    #[test]
    fn schema_version_current_accepted() {
        let json = r#"{"process": {"commandLine": "echo hi"}, "version": "0.5.0-alpha"}"#;
        let encoded = base64_encode(json.as_bytes());
        let mut logger = test_logger();

        let req = load_request(&encoded, &mut logger, true).unwrap();
        assert_eq!(req.schema_version, "0.5.0-alpha");
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
            "containment": "appcontainer",
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
        let json = r#"{"process": {"commandLine": "echo hi"}, "experimental": {"windows_sandbox": {"idleTimeoutMs": 60000}}}"#;
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
        let json = r#"{"process": {"commandLine": "echo hi"}, "experimental": {"windows_sandbox": {"idleTimeout": 10000, "idleTimeoutMs": 60000}}}"#;
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
        let json =
            r#"{"process": {"commandLine": "echo hi"}, "experimental": {"isolation_session": {}}}"#;
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
    fn isolation_session_config_small() {
        let json = r#"{"process": {"commandLine": "echo hi"}, "experimental": {"isolation_session": {"configurationId": "small"}}}"#;
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
        let json = r#"{"process": {"commandLine": "echo hi"}, "experimental": {"isolation_session": {"configurationId": "medium"}}}"#;
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
        let json = r#"{"process": {"commandLine": "echo hi"}, "experimental": {"isolation_session": {"configurationId": "large"}}}"#;
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
    fn isolation_session_config_commandline() {
        let json = r#"{"process": {"commandLine": "echo hi"}, "experimental": {"isolation_session": {"configurationId": "commandline"}}}"#;
        let encoded = base64_encode(json.as_bytes());
        let mut logger = test_logger();

        let req = load_request(&encoded, &mut logger, true).unwrap();
        let cfg = req.experimental.isolation_session.unwrap();
        assert_eq!(
            cfg.configuration_id,
            crate::models::IsolationSessionConfigurationId::CommandLine
        );
    }

    #[test]
    fn isolation_session_config_unknown_defaults_to_small() {
        let json = r#"{"process": {"commandLine": "echo hi"}, "experimental": {"isolation_session": {"configurationId": "xlarge"}}}"#;
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
    fn isolation_session_absent_from_experimental() {
        let json = r#"{"process": {"commandLine": "echo hi"}, "experimental": {}}"#;
        let encoded = base64_encode(json.as_bytes());
        let mut logger = test_logger();

        let req = load_request(&encoded, &mut logger, true).unwrap();
        assert!(req.experimental.isolation_session.is_none());
    }

}
