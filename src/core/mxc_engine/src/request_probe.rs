// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Request-aware Windows ProcessContainer probe.
//!
//! The backend owns tier detection. This module owns the public engine
//! projection and the engine-level capability overrides shared by the CLI and
//! SDK surfaces.

use serde::Serialize;
use wxc_common::models::ExecutionRequest;

#[cfg(target_os = "windows")]
use wxc_common::models::ContainmentBackend;

use crate::policy::SandboxRequest;
use crate::Error;

/// JSON-compatible result of probing a one-shot ProcessContainer request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ProbeOutput {
    /// Selected tier, omitted when detection failed.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tier: Option<String>,
    /// Whether the selected tier needs DACL deny augmentation.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub needs_dacl_augmentation: Option<bool>,
    /// Operator-visible tier degradation warnings.
    pub warnings: Vec<String>,
    /// Raw host facts used by the detector.
    pub probes: ProbeFacts,
    /// Detector error, omitted when detection succeeded.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

/// Facts gathered before request tier selection.
///
/// Optional-backend fields describe what the current engine build can probe on
/// this host. They remain `false` when that backend was not compiled in.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ProbeFacts {
    pub base_container_api_present: bool,
    pub native_capture_available: bool,
    pub guarded_capture_available: bool,
    pub bfscfg_present: bool,
    pub bfs_compiled_in: bool,
    pub base_container_supports_deny_paths: bool,
    pub base_container_supports_enumerate_paths: bool,
    pub base_container_supports_ingress_host_loopback_allow: bool,
    /// Whether this build includes IsolationSession and the service is
    /// activatable on this host.
    pub isolation_session_available: bool,
    /// Whether this build includes Hyperlight and WHP is available on this
    /// host.
    pub hyperlight_available: bool,
    pub ui_capabilities: UiCapabilitySupport,
}

/// Host support for enforcing sandbox UI restrictions.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
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

/// Probe an optional public SDK request without creating a sandbox.
///
/// `None` probes the default empty request, matching `wxc-exec --probe` with no
/// configuration input.
pub fn probe(request: Option<&SandboxRequest>) -> Result<ProbeOutput, Error> {
    probe_execution_request(request.map(|request| &request.inner))
}

/// Probe an optional runtime request without creating a sandbox.
///
/// This is public so the executor can use the same orchestration as the SDK.
/// Public SDK consumers should call [`probe`] with a [`SandboxRequest`].
#[doc(hidden)]
pub fn probe_execution_request(request: Option<&ExecutionRequest>) -> Result<ProbeOutput, Error> {
    #[cfg(target_os = "windows")]
    {
        let default_request;
        let request = match request {
            Some(request) => request,
            None => {
                default_request = ExecutionRequest::default();
                &default_request
            }
        };

        if request.containment != ContainmentBackend::ProcessContainer {
            return Err(Error::new(
                crate::ErrorCode::UnsupportedContainment,
                format!(
                    "request-aware probe supports only ProcessContainer containment; got {}",
                    request.containment.wire_name()
                ),
            ));
        }

        let output = process_container_common::probe::run_probe(
            request,
            crate::guarded_capture::is_available(),
        );
        let output = ProbeOutput::from(output);

        #[cfg(feature = "isolation_session")]
        let output = {
            let mut output = output;
            output.probes.isolation_session_available = crate::isolation_session_available();
            output
        };

        #[cfg(all(feature = "hyperlight", target_arch = "x86_64"))]
        let output = {
            let mut output = output;
            output.probes.hyperlight_available = hyperlight_common::is_whp_available();
            output
        };

        Ok(output)
    }

    #[cfg(not(target_os = "windows"))]
    {
        let _ = request;
        Err(Error::new(
            crate::ErrorCode::UnsupportedContainment,
            "the request-aware probe is available only for Windows ProcessContainer",
        ))
    }
}

#[cfg(target_os = "windows")]
impl From<process_container_common::probe::ProbeOutput> for ProbeOutput {
    fn from(value: process_container_common::probe::ProbeOutput) -> Self {
        let process_container_common::probe::ProbeOutput {
            tier,
            needs_dacl_augmentation,
            warnings,
            probes,
            error,
        } = value;
        Self {
            tier: tier.map(str::to_string),
            needs_dacl_augmentation,
            warnings,
            probes: probes.into(),
            error,
        }
    }
}

#[cfg(target_os = "windows")]
impl From<process_container_common::probe::ProbeFacts> for ProbeFacts {
    fn from(value: process_container_common::probe::ProbeFacts) -> Self {
        let process_container_common::probe::ProbeFacts {
            base_container_api_present,
            native_capture_available,
            guarded_capture_available,
            bfscfg_present,
            bfs_compiled_in,
            base_container_supports_deny_paths,
            base_container_supports_enumerate_paths,
            base_container_supports_ingress_host_loopback_allow,
            isolation_session_available,
            hyperlight_available,
            ui_capabilities,
        } = value;
        Self {
            base_container_api_present,
            native_capture_available,
            guarded_capture_available,
            bfscfg_present,
            bfs_compiled_in,
            base_container_supports_deny_paths,
            base_container_supports_enumerate_paths,
            base_container_supports_ingress_host_loopback_allow,
            isolation_session_available,
            hyperlight_available,
            ui_capabilities: ui_capabilities.into(),
        }
    }
}

#[cfg(target_os = "windows")]
impl From<process_container_common::probe::UiCapabilitySupport> for UiCapabilitySupport {
    fn from(value: process_container_common::probe::UiCapabilitySupport) -> Self {
        let process_container_common::probe::UiCapabilitySupport {
            can_block_clipboard_read,
            can_block_clipboard_write,
            can_block_input_injection,
            can_block_input_method_changes,
            can_block_external_ui_objects,
            can_block_global_ui_namespace,
            can_block_desktop_switching,
            can_block_logoff_or_shutdown,
            can_block_system_parameter_changes,
            can_block_display_settings_changes,
        } = value;
        Self {
            can_block_clipboard_read,
            can_block_clipboard_write,
            can_block_input_injection,
            can_block_input_method_changes,
            can_block_external_ui_objects,
            can_block_global_ui_namespace,
            can_block_desktop_switching,
            can_block_logoff_or_shutdown,
            can_block_system_parameter_changes,
            can_block_display_settings_changes,
        }
    }
}

#[cfg(test)]
impl ProbeFacts {
    fn all_false() -> Self {
        Self {
            base_container_api_present: false,
            native_capture_available: false,
            guarded_capture_available: false,
            bfscfg_present: false,
            bfs_compiled_in: false,
            base_container_supports_deny_paths: false,
            base_container_supports_enumerate_paths: false,
            base_container_supports_ingress_host_loopback_allow: false,
            isolation_session_available: false,
            hyperlight_available: false,
            ui_capabilities: UiCapabilitySupport {
                can_block_clipboard_read: false,
                can_block_clipboard_write: false,
                can_block_input_injection: false,
                can_block_input_method_changes: false,
                can_block_external_ui_objects: false,
                can_block_global_ui_namespace: false,
                can_block_desktop_switching: false,
                can_block_logoff_or_shutdown: false,
                can_block_system_parameter_changes: false,
                can_block_display_settings_changes: false,
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn probe_output_serializes_with_the_cli_field_names() {
        let output = ProbeOutput {
            tier: Some("appcontainer-dacl".to_string()),
            needs_dacl_augmentation: Some(true),
            warnings: vec!["fell through".to_string()],
            probes: ProbeFacts::all_false(),
            error: None,
        };

        let value = serde_json::to_value(output).unwrap();
        assert_eq!(value["tier"], "appcontainer-dacl");
        assert_eq!(value["needsDaclAugmentation"], true);
        assert!(value.get("error").is_none());
        assert!(value.get("probes").is_some());
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn request_probe_accepts_process_container_containment() {
        let request = ExecutionRequest::default();
        let output = probe_execution_request(Some(&request))
            .expect("the default request resolves to ProcessContainer");

        let value = serde_json::to_value(output).expect("probe output serializes");
        assert!(value.get("warnings").is_some());
        assert!(value.get("probes").is_some());
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn request_probe_rejects_non_process_container_containment() {
        let request = ExecutionRequest {
            containment: ContainmentBackend::Wslc,
            ..Default::default()
        };

        let error = probe_execution_request(Some(&request))
            .expect_err("WSLC requests must not be projected onto ProcessContainer");

        assert_eq!(error.code, crate::ErrorCode::UnsupportedContainment);
        assert_eq!(
            error.message,
            "request-aware probe supports only ProcessContainer containment; got wslc"
        );
    }

    #[cfg(not(target_os = "windows"))]
    #[test]
    fn request_probe_is_explicitly_unsupported_off_windows() {
        let error = probe_execution_request(None).unwrap_err();
        assert_eq!(error.code, crate::ErrorCode::UnsupportedContainment);
        assert!(error.message.contains("Windows ProcessContainer"));
    }
}
