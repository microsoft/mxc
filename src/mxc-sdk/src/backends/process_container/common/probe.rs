// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Read-only native ProcessContainer capability probe.

use serde::Serialize;

use crate::mxc_common::models::ExecutionRequest;
use crate::mxc_common::ui_policy::EffectiveUiRestrictions;

use crate::process_container_common::base_container_runner::BaseContainerRunner;

/// JSON output emitted by `wxc-exec --probe`.
#[derive(Serialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct ProbeOutput {
    /// Native ProcessContainer implementation, omitted when unavailable.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tier: Option<&'static str>,
    /// Retained for probe wire compatibility; native PSEC never augments DACLs.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub needs_dacl_augmentation: Option<bool>,
    /// Reserved for operator-visible capability warnings.
    pub warnings: Vec<String>,
    /// Raw machine probes.
    pub probes: ProbeFacts,
    /// Availability error, only set when PSEC is unavailable.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

/// Raw machine facts gathered without launching a sandbox.
#[derive(Serialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct ProbeFacts {
    /// `Experimental_CreateProcessInSandbox` is resolvable.
    pub base_container_api_present: bool,
    /// Native PSEC plus Learning Mode capture is available.
    pub native_capture_available: bool,
    /// Retired fallback capability, retained for probe wire compatibility.
    pub guarded_capture_available: bool,
    /// Retired fallback capability, retained for probe wire compatibility.
    pub bfscfg_present: bool,
    /// Retired fallback capability, retained for probe wire compatibility.
    pub bfs_compiled_in: bool,
    /// PSEC advertises native denied-path support.
    pub base_container_supports_deny_paths: bool,
    /// PSEC advertises native enumeration-only access.
    pub base_container_supports_enumerate_paths: bool,
    /// Whether BaseContainer can honor
    /// `network.ingress.hostLoopback = "allow"`.
    pub base_container_supports_ingress_host_loopback_allow: bool,
    /// Whether BaseContainer supports an identity-less proxy on loopback.
    /// Requires explicit host-loopback allow; not general ingress support.
    pub base_container_supports_identityless_loopback_proxy: bool,
    /// Whether the in-proc IsolationSession service can be activated on this
    /// host. Always `false` here — `process_container_common` has no dependency on
    /// the isolation-session backend; `wxc-exec --probe` overrides it when
    /// that backend is compiled in.
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
    let base_container_usable = BaseContainerRunner::is_base_container_api_present();
    let mut warnings = Vec::new();
    let identityless_loopback_proxy =
        match BaseContainerRunner::supports_identityless_loopback_proxy() {
            Ok(supported) => supported,
            Err(error) => {
                warnings.push(format!(
                    "failed to query identity-less loopback proxy support: {error}"
                ));
                false
            }
        };
    ProbeOutput {
        tier: base_container_usable.then_some("base-container"),
        needs_dacl_augmentation: base_container_usable.then_some(false),
        warnings,
        probes: ProbeFacts {
            base_container_api_present: base_container_usable,
            native_capture_available: BaseContainerRunner::is_native_capture_available(),
            guarded_capture_available: false,
            bfscfg_present: false,
            bfs_compiled_in: false,
            base_container_supports_deny_paths: BaseContainerRunner::supports_native_denied_paths(),
            base_container_supports_enumerate_paths: BaseContainerRunner::supports_enumerate_paths(
            ),
            base_container_supports_ingress_host_loopback_allow:
                BaseContainerRunner::supports_ingress_host_loopback_allow(),
            base_container_supports_identityless_loopback_proxy: identityless_loopback_proxy,
            isolation_session_available: false,
            hyperlight_available: false,
            ui_capabilities:
                crate::process_container_common::job_object::supported_ui_restrictions().into(),
        },
        error: (!base_container_usable)
            .then(|| "Windows ProcessContainer is unavailable: PSEC is not enabled".to_string()),
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
            needs_dacl_augmentation: None,
            warnings: Vec::new(),
            probes: ProbeFacts {
                base_container_api_present: false,
                native_capture_available: false,
                guarded_capture_available: false,
                bfscfg_present: false,
                bfs_compiled_in: false,
                base_container_supports_deny_paths: false,
                base_container_supports_enumerate_paths: false,
                base_container_supports_ingress_host_loopback_allow: false,
                base_container_supports_identityless_loopback_proxy: false,
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
