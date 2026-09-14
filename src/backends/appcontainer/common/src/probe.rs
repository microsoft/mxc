// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Read-only native ProcessContainer capability probe.

use serde::Serialize;

use wxc_common::models::ExecutionRequest;
use wxc_common::ui_policy::EffectiveUiRestrictions;

use crate::base_container_runner::BaseContainerRunner;

/// JSON output emitted by `wxc-exec --probe`.
#[derive(Serialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct ProbeOutput {
    /// Native ProcessContainer implementation, omitted when unavailable.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tier: Option<&'static str>,
    /// Reserved for operator-visible capability warnings.
    pub warnings: Vec<String>,
    /// Raw machine probes.
    pub probes: ProbeFacts,
    /// Availability error, only set when neither PSEC nor SBOX is usable.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

/// Raw machine facts gathered without launching a sandbox.
#[derive(Serialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct ProbeFacts {
    /// `Experimental_CreateProcessInSandbox` is resolvable.
    pub base_container_api_present: bool,
    /// At least one native BaseContainer contract is usable.
    pub base_container_usable: bool,
    /// The PSEC create/close contract is usable.
    pub process_security_environment_usable: bool,
    /// Transitional SBOX advertises native denied-path support.
    pub base_container_supports_deny_paths: bool,
    /// Whether BaseContainer can honor
    /// `network.ingress.hostLoopback = "allow"`.
    pub base_container_supports_ingress_host_loopback_allow: bool,
    /// Whether the in-proc IsolationSession service can be activated.
    pub isolation_session_available: bool,
    /// Whether Hyperlight is available on this host.
    pub hyperlight_available: bool,
    /// Platform-agnostic UI restrictions this host can enforce.
    pub ui_capabilities: UiCapabilitySupport,
}

/// Host support for enforcing sandbox UI restrictions.
#[derive(Serialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub struct UiCapabilitySupport {
    pub can_block_clipboard_read: bool,
    pub can_block_clipboard_write: bool,
    pub can_block_input_injection: bool,
    pub can_block_input_method_changes: bool,
    pub can_block_external_ui_objects: bool,
    pub can_block_global_ui_namespace: bool,
    pub can_block_desktop_switching: bool,
    pub can_block_logoff_or_shutdown: bool,
    pub can_block_system_parameter_changes: bool,
    pub can_block_display_settings_changes: bool,
}

impl From<EffectiveUiRestrictions> for UiCapabilitySupport {
    fn from(value: EffectiveUiRestrictions) -> Self {
        Self {
            can_block_clipboard_read: value.block_clipboard_read,
            can_block_clipboard_write: value.block_clipboard_write,
            can_block_input_injection: value.block_input_injection,
            can_block_input_method_changes: value.block_input_method_changes,
            can_block_external_ui_objects: value.block_external_ui_objects,
            can_block_global_ui_namespace: value.block_global_ui_namespace,
            can_block_desktop_switching: value.block_desktop_switching,
            can_block_logoff_or_shutdown: value.block_logoff_or_shutdown,
            can_block_system_parameter_changes: value.block_system_parameter_changes,
            can_block_display_settings_changes: value.block_display_settings_changes,
        }
    }
}

/// Probe native ProcessContainer availability.
///
/// `request` is retained in the API because `wxc-exec --probe` accepts a config,
/// but native request compatibility is finalized by dispatch using the complete
/// execution request.
pub fn run_probe(_request: &ExecutionRequest) -> ProbeOutput {
    let base_container_usable = BaseContainerRunner::is_base_container_usable();
    ProbeOutput {
        tier: base_container_usable.then_some("base-container"),
        warnings: Vec::new(),
        probes: ProbeFacts {
            base_container_api_present: BaseContainerRunner::is_base_container_api_present()
                .is_ok(),
            base_container_usable,
            process_security_environment_usable:
                BaseContainerRunner::is_process_security_environment_usable(),
            base_container_supports_deny_paths: BaseContainerRunner::supports_native_denied_paths(),
            base_container_supports_ingress_host_loopback_allow:
                BaseContainerRunner::supports_ingress_host_loopback_allow(),
            isolation_session_available: false,
            hyperlight_available: false,
            ui_capabilities: crate::job_object::supported_ui_restrictions().into(),
        },
        error: (!base_container_usable).then(|| {
            "Windows ProcessContainer is unavailable: neither PSEC nor SBOX is enabled".to_string()
        }),
    }
}

/// Serialize probe output as pretty-printed JSON.
pub fn to_json_pretty(output: &ProbeOutput) -> Result<String, serde_json::Error> {
    serde_json::to_string_pretty(output)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unavailable_probe_omits_tier_and_reports_error() {
        let output = ProbeOutput {
            tier: None,
            warnings: Vec::new(),
            probes: ProbeFacts {
                base_container_api_present: false,
                base_container_usable: false,
                process_security_environment_usable: false,
                base_container_supports_deny_paths: false,
                base_container_supports_ingress_host_loopback_allow: false,
                isolation_session_available: false,
                hyperlight_available: false,
                ui_capabilities: EffectiveUiRestrictions::default().into(),
            },
            error: Some("unavailable".to_string()),
        };
        let json = to_json_pretty(&output).expect("probe serializes");
        assert!(!json.contains("\"tier\""));
        assert!(json.contains("\"error\": \"unavailable\""));
    }
}
