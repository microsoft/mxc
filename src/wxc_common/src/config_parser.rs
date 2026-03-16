// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use std::fmt::Write;
use std::fs;

use serde::Deserialize;

use crate::error::WxcError;
use crate::logger::Logger;
use crate::models::{CodexRequest, ContainerPolicy, NetworkEnforcementMode, NetworkPolicy};
use crate::string_util::base64_decode;

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
}

#[derive(Deserialize, Default)]
#[serde(default)]
struct RawConfig {
    script: Option<String>,
    #[serde(rename = "workingDirectory")]
    working_directory: Option<String>,
    timeout: Option<u32>,
    #[serde(rename = "appContainer")]
    app_container: Option<RawAppContainer>,
    filesystem: Option<RawFilesystem>,
    network: Option<RawNetwork>,
}

// ---------- Public API ----------

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

// ---------- Conversion from raw JSON to domain model ----------

fn convert_raw_config(raw: RawConfig, logger: &mut Logger) -> Result<CodexRequest, WxcError> {
    // Script is required and must be non-empty
    let script_code = match raw.script {
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

    let working_directory = raw.working_directory.unwrap_or_default();
    let script_timeout = raw.timeout.unwrap_or(0);

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

    Ok(CodexRequest {
        script_code,
        working_directory,
        script_timeout,
        policy,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::logger::Mode;
    use crate::string_util::base64_encode;

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
        assert!(req.policy.capabilities.contains(&"internetClient".to_string()));
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
        let json =
            r#"{"script": "print('test')", "network": {"enforcementMode": "capabilities"}}"#;
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
}
