use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum NetworkPolicy {
    Allow,
    Block,
}

impl Default for NetworkPolicy {
    fn default() -> Self {
        NetworkPolicy::Allow
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum NetworkEnforcementMode {
    Capabilities,
    Firewall,
    Both,
}

impl Default for NetworkEnforcementMode {
    fn default() -> Self {
        NetworkEnforcementMode::Capabilities
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct ContainerPolicy {
    pub app_container_name: String,
    pub least_privilege_mode: bool,
    pub capabilities: Vec<String>,
    pub readwrite_paths: Vec<String>,
    pub readonly_paths: Vec<String>,
    pub denied_paths: Vec<String>,
    pub clear_policy_on_exit: bool,
    pub default_network_policy: NetworkPolicy,
    pub network_enforcement_mode: NetworkEnforcementMode,
    pub allowed_hosts: Vec<String>,
    pub blocked_hosts: Vec<String>,
    pub remove_firewall_rules_on_exit: bool,
}

impl Default for ContainerPolicy {
    fn default() -> Self {
        Self {
            app_container_name: "CLI".to_string(),
            least_privilege_mode: false,
            capabilities: Vec::new(),
            readwrite_paths: Vec::new(),
            readonly_paths: Vec::new(),
            denied_paths: Vec::new(),
            clear_policy_on_exit: true,
            default_network_policy: NetworkPolicy::default(),
            network_enforcement_mode: NetworkEnforcementMode::default(),
            allowed_hosts: Vec::new(),
            blocked_hosts: Vec::new(),
            remove_firewall_rules_on_exit: true,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct CodexRequest {
    pub script_code: String,
    pub working_directory: String,
    pub script_timeout: u32,
    pub policy: ContainerPolicy,
}

impl Default for CodexRequest {
    fn default() -> Self {
        Self {
            script_code: String::new(),
            working_directory: String::new(),
            script_timeout: 0,
            policy: ContainerPolicy::default(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct ScriptResponse {
    pub exit_code: i32,
    pub standard_out: String,
    pub standard_err: String,
    pub error_message: String,
}

impl Default for ScriptResponse {
    fn default() -> Self {
        Self {
            exit_code: -1,
            standard_out: String::new(),
            standard_err: String::new(),
            error_message: String::new(),
        }
    }
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
