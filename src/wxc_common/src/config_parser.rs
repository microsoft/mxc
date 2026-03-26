// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use std::fmt::Write;
use std::fs;

use serde::Deserialize;

use crate::encoding::base64_decode;
use crate::error::WxcError;
use crate::logger::Logger;
use crate::models::{
    CodexRequest, ContainerConfig, ContainerPolicy, ContainmentBackend, LxcConfig,
    NetworkEnforcementMode, NetworkPolicy, PortMapping, ProxyAddress, ProxyConfig, SandboxConfig,
};

// ---------- Intermediate serde structs matching the JSON schema ----------

#[derive(Deserialize, Default)]
#[serde(default)]
struct RawAppContainer {
    name: Option<String>,
    #[serde(rename = "leastPrivilege")]
    least_privilege: Option<bool>,
    #[serde(rename = "learningMode")]
    learning_mode: Option<bool>,
    capabilities: Option<Vec<String>>,
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
    #[serde(rename = "clearPolicyOnExit")]
    clear_policy_on_exit: Option<bool>,
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
    #[serde(rename = "removeRulesOnExit")]
    remove_rules_on_exit: Option<bool>,
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
    #[serde(rename = "containerName")]
    container_name: Option<String>,
    distribution: Option<String>,
    release: Option<String>,
    #[serde(rename = "destroyOnExit")]
    destroy_on_exit: Option<bool>,
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
struct RawConfig {
    version: Option<String>,
    #[serde(rename = "containerId")]
    container_id: Option<String>,
    platform: Option<String>,
    process: Option<RawProcess>,
    script: Option<String>,
    containment: Option<String>,
    #[serde(rename = "workingDirectory")]
    working_directory: Option<String>,
    timeout: Option<u32>,
    #[serde(rename = "appContainer")]
    app_container: Option<RawAppContainer>,
    sandbox: Option<RawSandbox>,
    container: Option<RawContainerConfig>,
    lxc: Option<RawLxc>,
    filesystem: Option<RawFilesystem>,
    network: Option<RawNetwork>,
}

// ---------- Public API ----------

/// Parse the `proxy` field.
///
/// Accepts either `{ "localhost": <port> }` for an external localhost proxy,
/// or `{ "builtinTestServer": true }` to have wxc launch its own test proxy.
/// When `builtinTestServer` is set it must be the only key in the object.
fn parse_proxy_config(value: &serde_json::Value) -> Result<ProxyConfig, WxcError> {
    let obj = value
        .as_object()
        .ok_or_else(|| WxcError::ConfigParse("network.proxy must be an object".to_string()))?;

    let mut proxy_addr = ProxyAddress::new("127.0.0.1".to_string(), 0, true);

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

    Err(WxcError::ConfigParse(
        "network.proxy must specify either builtinTestServer or localhost".to_string(),
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

/// Maximum supported schema major version.
const SUPPORTED_MAJOR_VERSION: u32 = 1;

/// Validate that platform and containment backend are compatible.
fn validate_platform_containment(
    containment: &ContainmentBackend,
    platform: &str,
    logger: &mut Logger,
) -> Result<(), WxcError> {
    let err = match (containment, platform) {
        (ContainmentBackend::AppContainer, "linux") => {
            Some("AppContainer requires platform 'windows'")
        }
        (ContainmentBackend::Sandbox, "linux") => Some("Sandbox requires platform 'windows'"),
        (ContainmentBackend::Wslc, "linux") => {
            Some("WSLC runs Linux containers from a Windows host; platform should be 'windows'")
        }
        (ContainmentBackend::Lxc, "windows") => Some("LXC requires platform 'linux'"),
        _ => None,
    };
    if let Some(msg) = err {
        logger.log_line(msg);
        return Err(WxcError::ConfigParse(msg.to_string()));
    }
    Ok(())
}

/// Validate that the schema version is supported by this binary.
fn validate_schema_version(version: &str, logger: &mut Logger) -> Result<(), WxcError> {
    if version.is_empty() {
        return Ok(());
    }
    let major_str = version.split('.').next().unwrap_or("");
    let major: u32 = match major_str.parse() {
        Ok(0) => {
            let msg = format!(
                "Invalid schema version '{}': major version must be >= 1",
                version
            );
            logger.log_line(&msg);
            return Err(WxcError::ConfigParse(msg));
        }
        Ok(v) => v,
        Err(_) => {
            let msg = format!(
                "Invalid schema version '{}': must start with a positive integer (e.g., '1' or '1.0')",
                version
            );
            logger.log_line(&msg);
            return Err(WxcError::ConfigParse(msg));
        }
    };
    if major > SUPPORTED_MAJOR_VERSION {
        let msg = format!(
            "Config schema version '{}' is newer than supported (max: {}.x). Upgrade wxc-exec.",
            version, SUPPORTED_MAJOR_VERSION
        );
        logger.log_line(&msg);
        return Err(WxcError::ConfigParse(msg));
    }
    Ok(())
}

// ---------- Conversion from raw JSON to domain model ----------

fn convert_raw_config(raw: RawConfig, logger: &mut Logger) -> Result<CodexRequest, WxcError> {
    // New top-level fields
    let schema_version = raw.version.unwrap_or_default();
    let container_id = raw.container_id.unwrap_or_default();
    let platform = raw.platform.unwrap_or_else(|| "windows".to_string());

    // Validate platform
    match platform.as_str() {
        "linux" | "windows" => {}
        other => {
            let msg = format!(
                "Invalid platform value '{}' (must be 'linux' or 'windows')",
                other
            );
            logger.log_line(&msg);
            return Err(WxcError::ConfigParse(msg));
        }
    }

    // Process section with dual-read fallback (new location wins, old is fallback)
    let (process_script, process_cwd, process_timeout, env) = if let Some(ref p) = raw.process {
        (
            p.command_line.clone().or(raw.script.clone()),
            p.cwd.clone().or(raw.working_directory.clone()),
            p.timeout.or(raw.timeout),
            p.env.clone().unwrap_or_default(),
        )
    } else {
        (
            raw.script.clone(),
            raw.working_directory.clone(),
            raw.timeout,
            vec![],
        )
    };

    // Script is required and must be non-empty
    let script_code = match process_script {
        Some(s) if !s.is_empty() => s,
        Some(_) => {
            logger.log_line("script cannot be empty");
            return Err(WxcError::ConfigParse("script cannot be empty".to_string()));
        }
        None => {
            logger.log_line("Missing required script execution fields");
            return Err(WxcError::ConfigParse(
                "Missing required script execution fields".to_string(),
            ));
        }
    };

    let working_directory = process_cwd.unwrap_or_default();
    let script_timeout = process_timeout.unwrap_or(0);

    // Containment backend selection
    let containment = match raw.containment.as_deref() {
        None | Some("appcontainer") => ContainmentBackend::AppContainer,
        Some("sandbox") => ContainmentBackend::Sandbox,
        Some("wslc") => ContainmentBackend::Wslc,
        Some("lxc") => ContainmentBackend::Lxc,
        Some("vm") => ContainmentBackend::Vm,
        Some("microvm") => ContainmentBackend::MicroVm,
        Some(other) => {
            let msg = format!(
                "Invalid containment value '{}' (must be 'appcontainer', 'sandbox', 'wslc', 'lxc', 'vm', or 'microvm')",
                other
            );
            logger.log_line(&msg);
            return Err(WxcError::ConfigParse(msg));
        }
    };

    // Sandbox configuration
    let mut sandbox_config = SandboxConfig::default();
    if let Some(sb) = raw.sandbox {
        if let Some(t) = sb.idle_timeout_ms.or(sb.idle_timeout) {
            sandbox_config.idle_timeout_ms = t;
        }
        if let Some(name) = sb.daemon_pipe_name {
            sandbox_config.daemon_pipe_name = name;
        }
    }

    // LXC configuration
    let mut lxc_config = {
        let raw_lxc = raw.lxc.unwrap_or_default();
        LxcConfig {
            container_name: raw_lxc.container_name.unwrap_or_default(),
            distribution: raw_lxc.distribution.unwrap_or_else(|| "alpine".to_string()),
            release: raw_lxc.release.unwrap_or_else(|| "3.19".to_string()),
            destroy_on_exit: raw_lxc.destroy_on_exit.unwrap_or(true),
        }
    };

    let mut policy = ContainerPolicy::default();

    // AppContainer section
    if let Some(ac) = raw.app_container {
        if let Some(name) = ac.name {
            policy.app_container_name = name;
        }
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
        if let Some(b) = fscfg.clear_policy_on_exit {
            policy.clear_policy_on_exit = b;
        }
    }

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
        if let Some(b) = net.remove_rules_on_exit {
            policy.remove_firewall_rules_on_exit = b;
        }
    }

    // Container configuration (WSLC SDK)
    let mut container_config = ContainerConfig::default();
    if let Some(cc) = raw.container {
        if let Some(os) = cc.target_os {
            container_config.target_os = os;
        }
        if let Some(img) = cc.image {
            container_config.image = img;
        }
        container_config.cpu_count = cc.cpu_count;
        container_config.memory_mb = cc.memory_mb;
        if let Some(gpu) = cc.gpu {
            container_config.gpu = gpu;
        }
        container_config.storage_path = cc.storage_path;
        if let Some(mappings) = cc.port_mappings {
            container_config.port_mappings = mappings
                .into_iter()
                .map(|m| PortMapping {
                    windows_port: m.windows_port.unwrap_or(0),
                    container_port: m.container_port.unwrap_or(0),
                    protocol: m.protocol.unwrap_or_else(|| "tcp".to_string()),
                })
                .collect();
        }
    }

    // containerId takes precedence over backend-specific container names
    if !container_id.is_empty() {
        policy.app_container_name = container_id.clone();
        lxc_config.container_name = container_id.clone();
    }

    // Cross-field validation: platform must be compatible with containment backend
    validate_platform_containment(&containment, &platform, logger)?;

    // Schema version check
    validate_schema_version(&schema_version, logger)?;

    Ok(CodexRequest {
        schema_version,
        container_id,
        platform,
        env,
        script_code,
        working_directory,
        script_timeout,
        containment,
        policy,
        sandbox_config,
        container_config,
        lxc_config,
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
        let json = r#"{"script": "echo hello"}"#;
        let encoded = base64_encode(json.as_bytes());
        let mut logger = test_logger();

        let req = load_request(&encoded, &mut logger, true).unwrap();
        assert_eq!(req.script_code, "echo hello");
        assert_eq!(req.script_timeout, 0);
        assert!(req.working_directory.is_empty());
    }

    #[test]
    fn missing_script_field() {
        let json = r#"{"timeout": 5000}"#;
        let encoded = base64_encode(json.as_bytes());
        let mut logger = test_logger();

        let result = load_request(&encoded, &mut logger, true);
        assert!(result.is_err());
    }

    #[test]
    fn empty_script_field() {
        let json = r#"{"script": ""}"#;
        let encoded = base64_encode(json.as_bytes());
        let mut logger = test_logger();

        let result = load_request(&encoded, &mut logger, true);
        assert!(result.is_err());
    }

    #[test]
    fn full_config() {
        let json = r#"{
            "script": "dir",
            "workingDirectory": "C:\\temp",
            "timeout": 3000,
            "appContainer": {
                "name": "TestProfile",
                "leastPrivilege": true,
                "capabilities": ["internetClient"]
            },
            "filesystem": {
                "readwritePaths": ["C:\\rw"],
                "readonlyPaths": ["C:\\ro"],
                "deniedPaths": ["C:\\denied"],
                "clearPolicyOnExit": false
            },
            "network": {
                "defaultPolicy": "block",
                "enforcementMode": "firewall",
                "allowedHosts": ["example.com"],
                "blockedHosts": ["evil.com"],
                "removeRulesOnExit": false
            }
        }"#;
        let encoded = base64_encode(json.as_bytes());
        let mut logger = test_logger();

        let req = load_request(&encoded, &mut logger, true).unwrap();
        assert_eq!(req.script_code, "dir");
        assert_eq!(req.working_directory, "C:\\temp");
        assert_eq!(req.script_timeout, 3000);
        assert_eq!(req.policy.app_container_name, "TestProfile");
        assert!(req.policy.least_privilege_mode);
        assert!(req
            .policy
            .capabilities
            .contains(&"internetClient".to_string()));
        assert_eq!(req.policy.readwrite_paths, vec!["C:\\rw"]);
        assert_eq!(req.policy.readonly_paths, vec!["C:\\ro"]);
        assert_eq!(req.policy.denied_paths, vec!["C:\\denied"]);
        assert!(!req.policy.clear_policy_on_exit);
        assert_eq!(req.policy.default_network_policy, NetworkPolicy::Block);
        assert_eq!(
            req.policy.network_enforcement_mode,
            NetworkEnforcementMode::Firewall
        );
        assert_eq!(req.policy.allowed_hosts, vec!["example.com"]);
        assert_eq!(req.policy.blocked_hosts, vec!["evil.com"]);
        assert!(!req.policy.remove_firewall_rules_on_exit);
    }

    #[test]
    fn invalid_network_policy() {
        let json = r#"{"script": "echo x", "network": {"defaultPolicy": "invalid"}}"#;
        let encoded = base64_encode(json.as_bytes());
        let mut logger = test_logger();

        let result = load_request(&encoded, &mut logger, true);
        assert!(result.is_err());
    }

    #[test]
    fn invalid_enforcement_mode() {
        let json = r#"{"script": "echo x", "network": {"enforcementMode": "invalid"}}"#;
        let encoded = base64_encode(json.as_bytes());
        let mut logger = test_logger();

        let result = load_request(&encoded, &mut logger, true);
        assert!(result.is_err());
    }

    #[test]
    fn load_from_file() {
        let dir = tempfile::tempdir().unwrap();
        let file_path = dir.path().join("config.json");
        std::fs::write(&file_path, r#"{"script": "whoami"}"#).unwrap();

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
        let json = r#"{"script": "echo x", "appContainer": {"learningMode": true}}"#;
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
        let json =
            r#"{"script": "echo x", "appContainer": {"capabilities": ["permissiveLearningMode"]}}"#;
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
        let json = r#"{"script": "import sys\nprint(sys.version)", "timeout": 60000}"#;
        let encoded = base64_encode(json.as_bytes());
        let mut logger = test_logger();

        let req = load_request(&encoded, &mut logger, true).unwrap();
        assert_eq!(req.script_timeout, 60000);
    }

    #[test]
    fn app_container_name_standalone() {
        let json = r#"{"script": "print('test')", "appContainer": {"name": "CustomAppContainer"}}"#;
        let encoded = base64_encode(json.as_bytes());
        let mut logger = test_logger();

        let req = load_request(&encoded, &mut logger, true).unwrap();
        assert_eq!(req.policy.app_container_name, "CustomAppContainer");
    }

    #[test]
    fn app_container_capabilities() {
        let json = r#"{
            "script": "print('test')",
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
        let json = r#"{"script": "print('test')", "appContainer": {"leastPrivilege": true}}"#;
        let encoded = base64_encode(json.as_bytes());
        let mut logger = test_logger();

        let req = load_request(&encoded, &mut logger, true).unwrap();
        assert!(req.policy.least_privilege_mode);
    }

    #[test]
    fn network_default_policy_allow() {
        let json = r#"{"script": "print('test')", "network": {"defaultPolicy": "allow"}}"#;
        let encoded = base64_encode(json.as_bytes());
        let mut logger = test_logger();

        let req = load_request(&encoded, &mut logger, true).unwrap();
        assert_eq!(req.policy.default_network_policy, NetworkPolicy::Allow);
    }

    #[test]
    fn network_default_policy_block() {
        let json = r#"{"script": "print('test')", "network": {"defaultPolicy": "block"}}"#;
        let encoded = base64_encode(json.as_bytes());
        let mut logger = test_logger();

        let req = load_request(&encoded, &mut logger, true).unwrap();
        assert_eq!(req.policy.default_network_policy, NetworkPolicy::Block);
    }

    #[test]
    fn network_enforcement_mode_capabilities() {
        let json = r#"{"script": "print('test')", "network": {"enforcementMode": "capabilities"}}"#;
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
        let json = r#"{"script": "print('test')", "network": {"enforcementMode": "firewall"}}"#;
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
        let json = r#"{"script": "print('test')", "network": {"enforcementMode": "both"}}"#;
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
            "script": "print('test')",
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
            "script": "print('test')",
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
    fn filesystem_clear_policy_on_exit_false() {
        let json = r#"{
            "script": "print('test')",
            "filesystem": {"clearPolicyOnExit": false}
        }"#;
        let encoded = base64_encode(json.as_bytes());
        let mut logger = test_logger();

        let req = load_request(&encoded, &mut logger, true).unwrap();
        assert!(!req.policy.clear_policy_on_exit);
    }

    #[test]
    fn base64_complex_config() {
        let json = r#"{
            "script": "import sys\nprint(sys.version)",
            "timeout": 10000,
            "appContainer": {
                "name": "TestContainer",
                "capabilities": ["internetClient", "privateNetworkClientServer"]
            }
        }"#;
        let encoded = base64_encode(json.as_bytes());
        let mut logger = test_logger();

        let req = load_request(&encoded, &mut logger, true).unwrap();
        assert_eq!(req.script_code, "import sys\nprint(sys.version)");
        assert_eq!(req.script_timeout, 10000);
        assert_eq!(req.policy.app_container_name, "TestContainer");
        assert_eq!(req.policy.capabilities.len(), 2);
    }

    #[test]
    fn network_remove_rules_on_exit() {
        let json = r#"{
            "script": "print('test')",
            "network": {"removeRulesOnExit": true}
        }"#;
        let encoded = base64_encode(json.as_bytes());
        let mut logger = test_logger();

        let req = load_request(&encoded, &mut logger, true).unwrap();
        assert!(req.policy.remove_firewall_rules_on_exit);
    }

    #[test]
    fn invalid_json_syntax() {
        let json = r#"{"script": "print('test')", INVALID_JSON}"#;
        let encoded = base64_encode(json.as_bytes());
        let mut logger = test_logger();

        let result = load_request(&encoded, &mut logger, true);
        assert!(result.is_err());
    }

    #[test]
    fn default_timeout_is_zero() {
        let json = r#"{"script": "echo hello"}"#;
        let encoded = base64_encode(json.as_bytes());
        let mut logger = test_logger();

        let req = load_request(&encoded, &mut logger, true).unwrap();
        assert_eq!(req.script_timeout, 0);
    }

    // ====== Containment backend selection tests ======

    #[test]
    fn default_containment_is_appcontainer() {
        let json = r#"{"script": "echo hello"}"#;
        let encoded = base64_encode(json.as_bytes());
        let mut logger = test_logger();

        let req = load_request(&encoded, &mut logger, true).unwrap();
        assert_eq!(req.containment, ContainmentBackend::AppContainer);
    }

    #[test]
    fn explicit_appcontainer_containment() {
        let json = r#"{"script": "echo hello", "containment": "appcontainer"}"#;
        let encoded = base64_encode(json.as_bytes());
        let mut logger = test_logger();

        let req = load_request(&encoded, &mut logger, true).unwrap();
        assert_eq!(req.containment, ContainmentBackend::AppContainer);
    }

    #[test]
    fn sandbox_containment() {
        let json = r#"{"script": "echo hello", "containment": "sandbox"}"#;
        let encoded = base64_encode(json.as_bytes());
        let mut logger = test_logger();

        let req = load_request(&encoded, &mut logger, true).unwrap();
        assert_eq!(req.containment, ContainmentBackend::Sandbox);
    }

    #[test]
    fn invalid_containment_value() {
        let json = r#"{"script": "echo hello", "containment": "docker"}"#;
        let encoded = base64_encode(json.as_bytes());
        let mut logger = test_logger();

        let result = load_request(&encoded, &mut logger, true);
        assert!(result.is_err());
    }

    #[test]
    fn sandbox_config_defaults() {
        let json = r#"{"script": "echo hello", "containment": "sandbox"}"#;
        let encoded = base64_encode(json.as_bytes());
        let mut logger = test_logger();

        let req = load_request(&encoded, &mut logger, true).unwrap();
        assert_eq!(req.sandbox_config.idle_timeout_ms, 300_000);
        assert_eq!(req.sandbox_config.daemon_pipe_name, "wxc-sandbox");
    }

    #[test]
    fn sandbox_config_custom_values() {
        let json = r#"{
            "script": "echo hello",
            "containment": "sandbox",
            "sandbox": {
                "idleTimeout": 60000,
                "daemonPipeName": "my-custom-pipe"
            }
        }"#;
        let encoded = base64_encode(json.as_bytes());
        let mut logger = test_logger();

        let req = load_request(&encoded, &mut logger, true).unwrap();
        assert_eq!(req.containment, ContainmentBackend::Sandbox);
        assert_eq!(req.sandbox_config.idle_timeout_ms, 60000);
        assert_eq!(req.sandbox_config.daemon_pipe_name, "my-custom-pipe");
    }

    // ====== Network proxy configuration tests ======

    #[test]
    fn no_proxy_leaves_default() {
        let json = r#"{"script": "echo test", "network": {"defaultPolicy": "block"}}"#;
        let encoded = base64_encode(json.as_bytes());
        let mut logger = test_logger();

        let req = load_request(&encoded, &mut logger, true).unwrap();
        assert!(!req.policy.network_proxy.is_enabled());
    }

    #[test]
    fn proxy_localhost_port() {
        let json = r#"{
            "script": "echo test",
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
    fn proxy_with_firewall_fields() {
        let json = r#"{
            "script": "echo test",
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
    fn proxy_rejected_with_sandbox() {
        let json =
            r#"{"script":"x","containment":"sandbox","network":{"proxy":{"localhost":8080}}}"#;
        let encoded = base64_encode(json.as_bytes());
        let mut logger = test_logger();

        let result = load_request(&encoded, &mut logger, true);
        assert!(result.is_err());
    }

    #[test]
    fn proxy_rejects_port_zero() {
        let json = r#"{"script":"x","network":{"proxy":{"localhost":0}}}"#;
        let encoded = base64_encode(json.as_bytes());
        let mut logger = test_logger();

        let result = load_request(&encoded, &mut logger, true);
        assert!(result.is_err());
    }

    #[test]
    fn proxy_rejects_missing_localhost() {
        let json = r#"{"script":"x","network":{"proxy":{}}}"#;
        let encoded = base64_encode(json.as_bytes());
        let mut logger = test_logger();

        let result = load_request(&encoded, &mut logger, true);
        assert!(result.is_err());
    }

    #[test]
    fn proxy_rejects_non_object() {
        let json = r#"{"script":"x","network":{"proxy":true}}"#;
        let encoded = base64_encode(json.as_bytes());
        let mut logger = test_logger();

        let result = load_request(&encoded, &mut logger, true);
        assert!(result.is_err());
    }

    #[test]
    fn proxy_builtin_test_server() {
        let json = r#"{
            "script": "echo test",
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
        let json =
            r#"{"script":"x","network":{"proxy":{"builtinTestServer":true,"localhost":8080}}}"#;
        let encoded = base64_encode(json.as_bytes());
        let mut logger = test_logger();

        let result = load_request(&encoded, &mut logger, true);
        assert!(result.is_err());
    }

    #[test]
    fn proxy_builtin_test_server_rejects_false() {
        let json = r#"{"script":"x","network":{"proxy":{"builtinTestServer":false}}}"#;
        let encoded = base64_encode(json.as_bytes());
        let mut logger = test_logger();

        let result = load_request(&encoded, &mut logger, true);
        assert!(result.is_err());
    }

    #[test]
    fn proxy_builtin_test_server_rejected_with_sandbox() {
        let json = r#"{"script":"x","containment":"sandbox","network":{"proxy":{"builtinTestServer":true}}}"#;
        let encoded = base64_encode(json.as_bytes());
        let mut logger = test_logger();

        let result = load_request(&encoded, &mut logger, true);
        assert!(result.is_err());
    }

    #[test]
    fn new_toplevel_fields_parsed() {
        let json = r#"{"version": "1", "containerId": "abc-123", "platform": "linux", "containment": "lxc", "script": "echo hi"}"#;
        let encoded = base64_encode(json.as_bytes());
        let mut logger = test_logger();

        let req = load_request(&encoded, &mut logger, true).unwrap();
        assert_eq!(req.schema_version, "1");
        assert_eq!(req.container_id, "abc-123");
        assert_eq!(req.platform, "linux");
    }

    #[test]
    fn invalid_platform_rejected() {
        let json = r#"{"script": "echo hi", "platform": "Windwos"}"#;
        let encoded = base64_encode(json.as_bytes());
        let mut logger = test_logger();

        let result = load_request(&encoded, &mut logger, true);
        assert!(result.is_err());
    }

    #[test]
    fn new_toplevel_fields_default_when_absent() {
        let json = r#"{"script": "echo hi"}"#;
        let encoded = base64_encode(json.as_bytes());
        let mut logger = test_logger();

        let req = load_request(&encoded, &mut logger, true).unwrap();
        assert_eq!(req.schema_version, "");
        assert_eq!(req.container_id, "");
        assert_eq!(req.platform, "windows");
    }

    #[test]
    fn process_section_overrides_toplevel() {
        let json = r#"{
            "script": "old command",
            "process": { "commandLine": "new command" }
        }"#;
        let encoded = base64_encode(json.as_bytes());
        let mut logger = test_logger();

        let req = load_request(&encoded, &mut logger, true).unwrap();
        assert_eq!(req.script_code, "new command");
    }

    #[test]
    fn process_section_cwd_overrides_working_directory() {
        let json = r#"{
            "script": "echo hi",
            "workingDirectory": "C:\\old",
            "process": { "cwd": "/new" }
        }"#;
        let encoded = base64_encode(json.as_bytes());
        let mut logger = test_logger();

        let req = load_request(&encoded, &mut logger, true).unwrap();
        assert_eq!(req.working_directory, "/new");
    }

    #[test]
    fn process_section_timeout_overrides_toplevel() {
        let json = r#"{
            "script": "echo hi",
            "timeout": 5000,
            "process": { "timeout": 9000 }
        }"#;
        let encoded = base64_encode(json.as_bytes());
        let mut logger = test_logger();

        let req = load_request(&encoded, &mut logger, true).unwrap();
        assert_eq!(req.script_timeout, 9000);
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
    fn toplevel_fallback_when_no_process_section() {
        let json = r#"{
            "script": "echo hello",
            "workingDirectory": "C:\\temp",
            "timeout": 3000
        }"#;
        let encoded = base64_encode(json.as_bytes());
        let mut logger = test_logger();

        let req = load_request(&encoded, &mut logger, true).unwrap();
        assert_eq!(req.script_code, "echo hello");
        assert_eq!(req.working_directory, "C:\\temp");
        assert_eq!(req.script_timeout, 3000);
        assert!(req.env.is_empty());
    }

    #[test]
    fn process_section_falls_back_to_toplevel_script() {
        let json = r#"{
            "script": "echo fallback",
            "process": { "cwd": "/workspace" }
        }"#;
        let encoded = base64_encode(json.as_bytes());
        let mut logger = test_logger();

        let req = load_request(&encoded, &mut logger, true).unwrap();
        assert_eq!(req.script_code, "echo fallback");
        assert_eq!(req.working_directory, "/workspace");
    }

    #[test]
    fn containment_vm_accepted() {
        let json = r#"{"script": "echo hi", "containment": "vm"}"#;
        let encoded = base64_encode(json.as_bytes());
        let mut logger = test_logger();

        let req = load_request(&encoded, &mut logger, true).unwrap();
        assert_eq!(req.containment, ContainmentBackend::Vm);
    }

    #[test]
    fn containment_microvm_accepted() {
        let json = r#"{"script": "echo hi", "containment": "microvm"}"#;
        let encoded = base64_encode(json.as_bytes());
        let mut logger = test_logger();

        let req = load_request(&encoded, &mut logger, true).unwrap();
        assert_eq!(req.containment, ContainmentBackend::MicroVm);
    }

    #[test]
    fn appcontainer_rejects_linux_platform() {
        let json = r#"{"script": "echo hi", "containment": "appcontainer", "platform": "linux"}"#;
        let encoded = base64_encode(json.as_bytes());
        let mut logger = test_logger();

        let result = load_request(&encoded, &mut logger, true);
        assert!(result.is_err());
    }

    #[test]
    fn sandbox_rejects_linux_platform() {
        let json = r#"{"script": "echo hi", "containment": "sandbox", "platform": "linux"}"#;
        let encoded = base64_encode(json.as_bytes());
        let mut logger = test_logger();

        let result = load_request(&encoded, &mut logger, true);
        assert!(result.is_err());
    }

    #[test]
    fn wslc_rejects_linux_platform() {
        let json = r#"{"script": "echo hi", "containment": "wslc", "platform": "linux"}"#;
        let encoded = base64_encode(json.as_bytes());
        let mut logger = test_logger();

        let result = load_request(&encoded, &mut logger, true);
        assert!(result.is_err());
    }

    #[test]
    fn lxc_rejects_windows_platform() {
        let json = r#"{"script": "echo hi", "containment": "lxc", "platform": "windows"}"#;
        let encoded = base64_encode(json.as_bytes());
        let mut logger = test_logger();

        let result = load_request(&encoded, &mut logger, true);
        assert!(result.is_err());
    }

    #[test]
    fn valid_platform_containment_accepted() {
        let json = r#"{"script": "echo hi", "containment": "appcontainer", "platform": "windows"}"#;
        let encoded = base64_encode(json.as_bytes());
        let mut logger = test_logger();

        let req = load_request(&encoded, &mut logger, true).unwrap();
        assert_eq!(req.containment, ContainmentBackend::AppContainer);
        assert_eq!(req.platform, "windows");
    }

    #[test]
    fn schema_version_too_new_rejected() {
        let json = r#"{"script": "echo hi", "version": "2"}"#;
        let encoded = base64_encode(json.as_bytes());
        let mut logger = test_logger();

        let result = load_request(&encoded, &mut logger, true);
        assert!(result.is_err());
    }

    #[test]
    fn schema_version_current_accepted() {
        let json = r#"{"script": "echo hi", "version": "1"}"#;
        let encoded = base64_encode(json.as_bytes());
        let mut logger = test_logger();

        let req = load_request(&encoded, &mut logger, true).unwrap();
        assert_eq!(req.schema_version, "1");
    }

    #[test]
    fn schema_version_absent_accepted() {
        let json = r#"{"script": "echo hi"}"#;
        let encoded = base64_encode(json.as_bytes());
        let mut logger = test_logger();

        let req = load_request(&encoded, &mut logger, true).unwrap();
        assert_eq!(req.schema_version, "");
    }

    #[test]
    fn schema_version_non_numeric_rejected() {
        let json = r#"{"script": "echo hi", "version": "x"}"#;
        let encoded = base64_encode(json.as_bytes());
        let mut logger = test_logger();

        let result = load_request(&encoded, &mut logger, true);
        assert!(result.is_err());
    }

    #[test]
    fn schema_version_zero_rejected() {
        let json = r#"{"script": "echo hi", "version": "0"}"#;
        let encoded = base64_encode(json.as_bytes());
        let mut logger = test_logger();

        let result = load_request(&encoded, &mut logger, true);
        assert!(result.is_err());
    }

    #[test]
    fn schema_version_beta_suffix_rejected() {
        let json = r#"{"script": "echo hi", "version": "2-beta"}"#;
        let encoded = base64_encode(json.as_bytes());
        let mut logger = test_logger();

        let result = load_request(&encoded, &mut logger, true);
        assert!(result.is_err());
    }

    #[test]
    fn sandbox_idle_timeout_ms_accepted() {
        let json = r#"{"script": "echo hi", "containment": "sandbox", "sandbox": {"idleTimeoutMs": 60000}}"#;
        let encoded = base64_encode(json.as_bytes());
        let mut logger = test_logger();

        let req = load_request(&encoded, &mut logger, true).unwrap();
        assert_eq!(req.sandbox_config.idle_timeout_ms, 60000);
    }

    #[test]
    fn sandbox_idle_timeout_ms_overrides_idle_timeout() {
        let json = r#"{"script": "echo hi", "containment": "sandbox", "sandbox": {"idleTimeout": 10000, "idleTimeoutMs": 60000}}"#;
        let encoded = base64_encode(json.as_bytes());
        let mut logger = test_logger();

        let req = load_request(&encoded, &mut logger, true).unwrap();
        assert_eq!(req.sandbox_config.idle_timeout_ms, 60000);
    }

    #[test]
    fn container_id_overrides_app_container_name() {
        let json = r#"{"script": "echo hi", "containerId": "my-container", "appContainer": {"name": "old-name"}}"#;
        let encoded = base64_encode(json.as_bytes());
        let mut logger = test_logger();

        let req = load_request(&encoded, &mut logger, true).unwrap();
        assert_eq!(req.policy.app_container_name, "my-container");
    }

    #[test]
    fn container_id_overrides_lxc_container_name() {
        let json = r#"{"script": "echo hi", "containment": "lxc", "platform": "linux", "containerId": "my-lxc", "lxc": {"containerName": "old-name"}}"#;
        let encoded = base64_encode(json.as_bytes());
        let mut logger = test_logger();

        let req = load_request(&encoded, &mut logger, true).unwrap();
        assert_eq!(req.lxc_config.container_name, "my-lxc");
    }

    #[test]
    fn container_id_fallback_to_app_container_name() {
        let json = r#"{"script": "echo hi", "appContainer": {"name": "old-name"}}"#;
        let encoded = base64_encode(json.as_bytes());
        let mut logger = test_logger();

        let req = load_request(&encoded, &mut logger, true).unwrap();
        assert_eq!(req.policy.app_container_name, "old-name");
    }
}
