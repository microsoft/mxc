// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Read-only fallback-detector probe.
//!
//! This module wraps [`crate::fallback_detector`] in a serde-friendly
//! surface so the SDK can invoke `wxc-exec --probe` and learn which
//! isolation tier would be selected on the current machine without
//! actually spawning a sandbox.
//!
//! The probe must have no side effects: it does not write logs, modify
//! the filesystem, or spawn child processes.

use serde::Serialize;

use crate::fallback_detector::{self, FallbackError};
use wxc_common::models::ContainerPolicy;
use wxc_common::ui_policy::EffectiveUiRestrictions;

/// JSON output emitted by `wxc-exec --probe`.
#[derive(Serialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct ProbeOutput {
    /// Selected tier (omitted when the detector returned an error).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tier: Option<&'static str>,
    /// True when the selected tier needs DACL deny-augmentation on host
    /// paths. Omitted when the detector returned an error.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub needs_dacl_augmentation: Option<bool>,
    /// Operator-visible degradation warnings — one per tier fall-through.
    pub warnings: Vec<String>,
    /// Raw machine probes, independent of the policy argument.
    pub probes: ProbeFacts,
    /// Detector error message (only set when detection failed).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

/// Raw machine facts gathered prior to running tier selection.
#[derive(Serialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct ProbeFacts {
    /// `Experimental_CreateProcessInSandbox` is resolvable.
    pub base_container_api_present: bool,
    /// `bfscfg.exe` is on disk in `%SystemRoot%\System32`.
    ///
    /// Always `false` when [`Self::bfs_compiled_in`] is `false`, because
    /// `find_bfscfg_exe` returns `Ok(None)` unconditionally with the
    /// `tier2_bfs` feature off — i.e. this field reports what the
    /// detector itself would see, not what is on disk.
    pub bfscfg_present: bool,
    /// Whether this binary was compiled with the `tier2_bfs` Cargo
    /// feature. When `false`, Tier 2 (AppContainer + BFS) is
    /// unreachable: the detector falls through to Tier 3 on any host
    /// that would otherwise select T2, and the `bfscfg.exe` spawn site
    /// is itself gated. Harnesses on hang-prone hosts (e.g. Windows
    /// 11 25H2 where `bfscfg.exe` locks `bfs.sys`) should refuse to
    /// run a binary that reports `true` here.
    pub bfs_compiled_in: bool,
    /// Whether the BaseContainer (Tier 1) tier can enforce
    /// `filesystem.deniedPaths` on this host (the `SANDBOX_CAP_DENY_PATHS` bit
    /// from `Experimental_QuerySandboxSupport`). `false` on builds where deny
    /// support has not yet shipped, where `deniedPaths` is rejected at launch.
    /// Tier 3 (AppContainer + DACL) enforces `deniedPaths` via DENY ACEs
    /// regardless of this bit; it is meaningful only for the BaseContainer tier.
    pub base_container_supports_deny_paths: bool,
    /// Platform-agnostic UI restrictions this host can enforce.
    pub ui_capabilities: UiCapabilitySupport,
}

/// Host support for enforcing sandbox UI restrictions.
#[derive(Serialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub struct UiCapabilitySupport {
    /// Whether the host can block reads from the clipboard.
    pub can_block_clipboard_read: bool,
    /// Whether the host can block writes to the clipboard.
    pub can_block_clipboard_write: bool,
    /// Whether the host can block synthetic keyboard/mouse input.
    pub can_block_input_injection: bool,
    /// Whether the host can block input method / IME changes.
    pub can_block_input_method_changes: bool,
    /// Whether the host can block access to external UI object handles.
    pub can_block_external_ui_objects: bool,
    /// Whether the host can block access to global UI namespaces.
    pub can_block_global_ui_namespace: bool,
    /// Whether the host can block desktop switching.
    pub can_block_desktop_switching: bool,
    /// Whether the host can block logoff or shutdown requests.
    pub can_block_logoff_or_shutdown: bool,
    /// Whether the host can block system parameter changes.
    pub can_block_system_parameter_changes: bool,
    /// Whether the host can block display settings changes.
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

/// Run the fallback detector against `policy` and return a JSON-shaped
/// summary. The detector is always asked to prefer BaseContainer (Tier 1).
pub fn run_probe(policy: &ContainerPolicy) -> ProbeOutput {
    let probes = ProbeFacts {
        base_container_api_present:
            crate::base_container_runner::BaseContainerRunner::is_base_container_api_present()
                .is_ok(),
        bfscfg_present: fallback_detector::find_bfscfg_exe()
            .ok()
            .flatten()
            .is_some(),
        bfs_compiled_in: cfg!(feature = "tier2_bfs"),
        base_container_supports_deny_paths:
            crate::base_container_runner::BaseContainerRunner::base_container_supports_deny_paths(),
        ui_capabilities: crate::job_object::supported_ui_restrictions().into(),
    };
    match fallback_detector::detect(policy, /* prefer_base_container */ true) {
        Ok(decision) => ProbeOutput {
            tier: Some(decision.tier.as_str()),
            needs_dacl_augmentation: Some(decision.needs_dacl_augmentation),
            warnings: decision.warnings,
            probes,
            error: None,
        },
        Err(e) => ProbeOutput {
            tier: None,
            needs_dacl_augmentation: None,
            warnings: vec![],
            probes,
            error: Some(format_fallback_error(&e)),
        },
    }
}

fn format_fallback_error(e: &FallbackError) -> String {
    match e {
        FallbackError::DaclFallbackDisabled => {
            "DACL fallback required but fallback.allowDaclMutation is false".to_string()
        }
        FallbackError::WriteDacUnavailable { path, reason } => {
            format!("WRITE_DAC unavailable on path {}: {reason}", path.display())
        }
        FallbackError::SystemRootUnresolved { reason } => {
            format!("Could not resolve Windows system directory: {reason}")
        }
    }
}

/// Serialize a [`ProbeOutput`] as pretty-printed JSON.
///
/// Returns `Err` only if the underlying serializer fails — in practice
/// this should be infallible for the well-formed `ProbeOutput` we
/// produce, but we surface the error rather than panic.
pub fn to_json_pretty(output: &ProbeOutput) -> Result<String, serde_json::Error> {
    serde_json::to_string_pretty(output)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fallback_detector::IsolationTier;
    use crate::test_env::ForceTierGuard;

    fn all_ui_capabilities() -> UiCapabilitySupport {
        UiCapabilitySupport {
            can_block_clipboard_read: true,
            can_block_clipboard_write: true,
            can_block_input_injection: true,
            can_block_input_method_changes: true,
            can_block_external_ui_objects: true,
            can_block_global_ui_namespace: true,
            can_block_desktop_switching: true,
            can_block_logoff_or_shutdown: true,
            can_block_system_parameter_changes: true,
            can_block_display_settings_changes: true,
        }
    }

    #[test]
    fn probe_output_serializes() {
        let out = ProbeOutput {
            tier: Some("base-container"),
            needs_dacl_augmentation: Some(false),
            warnings: vec!["a warning".to_string()],
            probes: ProbeFacts {
                base_container_api_present: true,
                bfscfg_present: false,
                bfs_compiled_in: false,
                base_container_supports_deny_paths: false,
                ui_capabilities: all_ui_capabilities(),
            },
            error: None,
        };
        let json = serde_json::to_string(&out).expect("serialize");
        let v: serde_json::Value = serde_json::from_str(&json).expect("parse");
        assert_eq!(v["tier"], "base-container");
        assert_eq!(v["needsDaclAugmentation"], false);
        assert_eq!(v["warnings"][0], "a warning");
        assert_eq!(v["probes"]["baseContainerApiPresent"], true);
        assert_eq!(v["probes"]["bfscfgPresent"], false);
        assert_eq!(v["probes"]["bfsCompiledIn"], false);
        assert_eq!(v["probes"]["uiCapabilities"]["canBlockClipboardRead"], true);
        assert_eq!(
            v["probes"]["uiCapabilities"]["canBlockInputInjection"],
            true
        );
        assert_eq!(
            v["probes"]["uiCapabilities"]["canBlockInputMethodChanges"],
            true
        );
        assert!(v.get("error").is_none());
    }

    #[test]
    fn probe_serializes_partial_ui_capabilities() {
        let out = ProbeOutput {
            tier: Some("appcontainer-dacl"),
            needs_dacl_augmentation: Some(true),
            warnings: vec![],
            probes: ProbeFacts {
                base_container_api_present: false,
                bfscfg_present: false,
                bfs_compiled_in: false,
                base_container_supports_deny_paths: false,
                ui_capabilities: UiCapabilitySupport {
                    can_block_input_injection: false,
                    can_block_input_method_changes: false,
                    ..all_ui_capabilities()
                },
            },
            error: None,
        };
        let v = serde_json::to_value(&out).expect("to_value");
        let probes = v["probes"].as_object().expect("probes object");
        assert!(probes.contains_key("uiCapabilities"));
        assert_eq!(
            v["probes"]["uiCapabilities"]["canBlockInputInjection"],
            false
        );
        assert_eq!(
            v["probes"]["uiCapabilities"]["canBlockInputMethodChanges"],
            false
        );
        assert_eq!(v["probes"]["uiCapabilities"]["canBlockClipboardRead"], true);
    }

    #[test]
    fn tier_strings_stable() {
        assert_eq!(IsolationTier::BaseContainer.as_str(), "base-container");
        assert_eq!(IsolationTier::AppContainerBfs.as_str(), "appcontainer-bfs");
        assert_eq!(
            IsolationTier::AppContainerDacl.as_str(),
            "appcontainer-dacl"
        );
    }

    #[test]
    fn run_probe_with_force_tier() {
        let _g = ForceTierGuard::set("appcontainer-bfs");
        let policy = ContainerPolicy::default();
        let out = run_probe(&policy);
        assert_eq!(out.tier, Some("appcontainer-bfs"));
        assert_eq!(out.needs_dacl_augmentation, Some(false));
        assert!(out.error.is_none());
    }

    #[test]
    fn run_probe_handles_dacl_disabled_error() {
        let _g = ForceTierGuard::set("appcontainer-dacl");
        let mut policy = ContainerPolicy::default();
        policy.fallback.allow_dacl_mutation = false;
        let out = run_probe(&policy);
        assert!(out.tier.is_none());
        assert!(out.needs_dacl_augmentation.is_none());
        assert!(out.error.is_some());
        let msg = out.error.unwrap();
        assert!(
            msg.contains("DACL fallback"),
            "expected DACL fallback message, got: {msg}"
        );
    }

    #[test]
    fn omitted_fields_when_error() {
        let _g = ForceTierGuard::set("appcontainer-dacl");
        let mut policy = ContainerPolicy::default();
        policy.fallback.allow_dacl_mutation = false;
        let out = run_probe(&policy);
        let v = serde_json::to_value(&out).expect("to_value");
        let obj = v.as_object().expect("object");
        assert!(
            !obj.contains_key("tier"),
            "tier key should be absent on error, got: {v}"
        );
        assert!(
            !obj.contains_key("needsDaclAugmentation"),
            "needsDaclAugmentation key should be absent on error, got: {v}"
        );
        assert!(obj.contains_key("error"));
        assert!(obj.contains_key("warnings"));
        assert!(obj.contains_key("probes"));
    }
}
