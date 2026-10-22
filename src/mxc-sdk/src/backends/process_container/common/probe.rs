// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Read-only native ProcessContainer capability probe.

use serde::Serialize;

use crate::mxc_common::models::ExecutionRequest;
use crate::mxc_common::ui_policy::EffectiveUiRestrictions;

use crate::process_container_common::base_container_runner::BaseContainerRunner;

/// Host capabilities and request compatibility for Windows ProcessContainer.
#[derive(Serialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct ProbeOutput {
    /// Native ProcessContainer implementation, omitted when it cannot serve the request.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tier: Option<&'static str>,
    /// Retained for probe wire compatibility; native PSEC never augments DACLs.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub needs_dacl_augmentation: Option<bool>,
    /// Reserved for operator-visible capability warnings.
    pub warnings: Vec<String>,
    /// Raw machine probes.
    pub probes: ProbeFacts,
    /// Why native ProcessContainer cannot serve the request.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

/// Raw machine facts gathered without launching a sandbox.
#[derive(Serialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct ProbeFacts {
    /// The native process security-environment API set is present.
    pub base_container_api_present: bool,
    /// Native PSEC plus Learning Mode capture is available.
    pub native_capture_available: bool,
    /// Always `false`; kept in the probe output for compatibility.
    pub guarded_capture_available: bool,
    /// Always `false`; kept in the probe output for compatibility.
    pub bfscfg_present: bool,
    /// Always `false`; kept in the probe output for compatibility.
    pub bfs_compiled_in: bool,
    /// PSEC advertises native denied-path support.
    pub base_container_supports_deny_paths: bool,
    /// PSEC advertises native enumeration-only access.
    pub base_container_supports_enumerate_paths: bool,
    /// With explicit host-loopback allow, the baseline is policy-permitted stateful outbound
    /// loopback. Native Windows ingress support adds bidirectional access, including
    /// container-hosted loopback servers.
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

/// Report native host-capability serviceability without creating a container.
/// This does not replace launch-time environment, network, or PSEC-version validation.
/// Host facts remain available when the request is rejected.
pub fn run_probe(request: &ExecutionRequest) -> ProbeOutput {
    let base_container_usable = BaseContainerRunner::is_base_container_api_present();
    let decision = BaseContainerRunner::can_backend_service_request(request);
    let error = decision.rejection_message().map(str::to_string);
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
        tier: decision.can_service_request().then_some("base-container"),
        needs_dacl_augmentation: decision.can_service_request().then_some(false),
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
        error,
    }
}

/// Serialize probe output as pretty-printed JSON.
pub fn to_json_pretty(output: &ProbeOutput) -> Result<String, serde_json::Error> {
    serde_json::to_string_pretty(output)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mxc_common::models::{ProxyAddress, ProxyConfig};
    use crate::process_container_common::test_env::CaptureCapabilityGuard;

    #[test]
    fn unavailable_probe_omits_tier_and_reports_error() {
        let _guard = CaptureCapabilityGuard::set(false, false);
        let output = run_probe(&ExecutionRequest::default());
        assert!(output
            .error
            .as_deref()
            .is_some_and(|error| error.contains("PSEC")));
        assert!(!output.probes.base_container_api_present);
        let json = to_json_pretty(&output).expect("probe serializes");
        assert!(!json.contains("\"tier\""));
        assert!(!json.contains("\"needsDaclAugmentation\""));
        assert!(json.contains("\"error\""));
    }

    #[test]
    fn serviceable_request_selects_native_processcontainer() {
        let _guard = CaptureCapabilityGuard::set(true, true);
        let output = run_probe(&ExecutionRequest::default());
        assert_eq!(output.tier, Some("base-container"));
        assert_eq!(output.needs_dacl_augmentation, Some(false));
        assert!(output.error.is_none());
    }

    #[test]
    fn incompatible_policies_preserve_host_facts_without_selecting_a_tier() {
        let _guard = CaptureCapabilityGuard::set(true, true);
        let mut lpac_request = ExecutionRequest::default();
        lpac_request.policy.least_privilege_mode = true;
        let mut legacy_proxy_request = ExecutionRequest::default();
        legacy_proxy_request.policy.network_proxy = ProxyConfig {
            address: Some(ProxyAddress::new("127.0.0.1".to_string(), 8080)),
        };
        for request in [lpac_request, legacy_proxy_request] {
            let output = run_probe(&request);
            assert_eq!(output.tier, None);
            assert_eq!(output.needs_dacl_augmentation, None);
            assert!(output
                .error
                .as_deref()
                .is_some_and(|error| error.contains("policy")));
            assert!(output.probes.base_container_api_present);
        }
    }

    #[test]
    fn capture_request_requires_native_capture_support() {
        let _guard = CaptureCapabilityGuard::set(true, false);
        let mut request = ExecutionRequest::default();
        request.policy.capture_denials = Some(Default::default());
        let output = run_probe(&request);
        assert_eq!(output.tier, None);
        assert_eq!(output.needs_dacl_augmentation, None);
        assert!(output
            .error
            .as_deref()
            .is_some_and(|error| error.contains("native Learning Mode capture")));
        assert!(output.probes.base_container_api_present);
    }
}
