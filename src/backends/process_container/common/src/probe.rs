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
use wxc_common::models::ExecutionRequest;
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
    /// Machine facts, including policy-result diagnostics only when requested.
    pub probes: ProbeFacts,
    /// Detector error message (only set when detection failed).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

/// Raw machine facts gathered prior to running tier selection.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ProbeFacts {
    /// The process security environment API set is resolvable.
    pub base_container_api_present: bool,
    /// The CPSE2 export exists and the support query advertises PSE_SUPPORT_POLICY_RESULT.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub base_container_policy_results_available: Option<bool>,
    /// Whether the CPSE2 export resolves, independently of feature availability.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub base_container_create2_export_present: Option<bool>,
    /// Raw PSEC capability bits, present only when the support query succeeds.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub base_container_support_flags: Option<u32>,
    /// HRESULT from the non-creating support query, when it could be invoked.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub base_container_support_query_hresult: Option<String>,
    /// Whether the preferred native PSEC plus Learning Mode capture path is usable.
    ///
    /// A false value does not mean `captureDenials` is unsupported: the executor
    /// can use guarded WPR on a compatible fallback tier. A true value reports
    /// host capability, not request compatibility; a request can still require
    /// guarded WPR when its policy cannot be represented by PSEC.
    pub native_capture_available: bool,
    /// Whether the guarded WPR capture fallback is available.
    pub guarded_capture_available: bool,
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
    /// Whether PSEC can enforce `filesystem.deniedPaths` at Tier 1.
    pub base_container_supports_deny_paths: bool,
    /// Whether PSEC 1.1 can enforce `processContainer.filesystem.enumeratePaths` at Tier 1.
    pub base_container_supports_enumerate_paths: bool,
    /// Whether BaseContainer can honor
    /// `network.ingress.hostLoopback = "allow"`.
    pub base_container_supports_ingress_host_loopback_allow: bool,
    /// Whether the in-proc IsolationSession service can be activated on this
    /// host. Always `false` here — `process_container_common` has no dependency on
    /// the isolation-session backend; `wxc-exec --probe` overrides it when
    /// that backend is compiled in.
    pub isolation_session_available: bool,
    /// Whether Hyperlight (WHP micro-VM) is available on this host. Always
    /// `false` here — overridden by `wxc-exec --probe` when the hyperlight
    /// feature is compiled in and WHP is loadable.
    pub hyperlight_available: bool,
    /// Platform-agnostic UI restrictions this host can enforce.
    pub ui_capabilities: UiCapabilitySupport,
}

impl std::fmt::Debug for ProbeFacts {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut debug = f.debug_struct("ProbeFacts");
        debug.field(
            "base_container_api_present",
            &self.base_container_api_present,
        );
        if self.base_container_policy_results_available.is_some() {
            debug.field(
                "base_container_policy_results_available",
                &self.base_container_policy_results_available,
            );
        }
        if self.base_container_create2_export_present.is_some() {
            debug.field(
                "base_container_create2_export_present",
                &self.base_container_create2_export_present,
            );
        }
        if self.base_container_support_flags.is_some() {
            debug.field(
                "base_container_support_flags",
                &self.base_container_support_flags,
            );
        }
        if self.base_container_support_query_hresult.is_some() {
            debug.field(
                "base_container_support_query_hresult",
                &self.base_container_support_query_hresult,
            );
        }
        debug
            .field("native_capture_available", &self.native_capture_available)
            .field("guarded_capture_available", &self.guarded_capture_available)
            .field("bfscfg_present", &self.bfscfg_present)
            .field("bfs_compiled_in", &self.bfs_compiled_in)
            .field(
                "base_container_supports_deny_paths",
                &self.base_container_supports_deny_paths,
            )
            .field(
                "base_container_supports_enumerate_paths",
                &self.base_container_supports_enumerate_paths,
            )
            .field(
                "base_container_supports_ingress_host_loopback_allow",
                &self.base_container_supports_ingress_host_loopback_allow,
            )
            .field(
                "isolation_session_available",
                &self.isolation_session_available,
            )
            .field("hyperlight_available", &self.hyperlight_available)
            .field("ui_capabilities", &self.ui_capabilities)
            .finish()
    }
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

/// Run the probe with the availability of the guarded WPR capture fallback.
///
/// The concrete guarded-capture implementation lives above this crate in
/// `mxc_engine`, which supplies this capability to the executor probe.
pub fn run_probe(request: &ExecutionRequest, guarded_capture_available: bool) -> ProbeOutput {
    use crate::base_container_runner::BaseContainerRunner;

    let exports = policy_exports(request, crate::secenv::probe_policy_result_exports);
    let probes = ProbeFacts {
        base_container_api_present: BaseContainerRunner::is_base_container_api_present(),
        base_container_policy_results_available: exports
            .as_ref()
            .map(|exports| exports.policy_results_available()),
        base_container_create2_export_present: exports
            .as_ref()
            .map(|exports| exports.create2.is_some()),
        base_container_support_flags: exports.and_then(|exports| exports.support_flags),
        base_container_support_query_hresult: exports
            .and_then(|exports| exports.support_query_hresult)
            .map(|code| format!("0x{:08X}", code as u32)),
        native_capture_available: BaseContainerRunner::is_native_capture_available(),
        guarded_capture_available,
        bfscfg_present: fallback_detector::find_bfscfg_exe()
            .ok()
            .flatten()
            .is_some(),
        bfs_compiled_in: cfg!(feature = "tier2_bfs"),
        base_container_supports_deny_paths: BaseContainerRunner::supports_native_denied_paths(),
        base_container_supports_enumerate_paths: BaseContainerRunner::supports_enumerate_paths(),
        base_container_supports_ingress_host_loopback_allow:
            BaseContainerRunner::supports_ingress_host_loopback_allow(),
        isolation_session_available: false,
        hyperlight_available: false,
        ui_capabilities: crate::job_object::supported_ui_restrictions().into(),
    };

    run_probe_with_tier_decision(
        request,
        probes,
        fallback_detector::choose_backend_tier(request),
    )
}

fn policy_exports(
    request: &ExecutionRequest,
    probe: impl FnOnce() -> crate::secenv::PolicyResultExportReport,
) -> Option<crate::secenv::PolicyResultExportReport> {
    request.policy.policy_enforcement.as_ref().map(|_| probe())
}

fn run_probe_with_tier_decision(
    request: &ExecutionRequest,
    probes: ProbeFacts,
    tier_decision: Result<fallback_detector::TierDecision, FallbackError>,
) -> ProbeOutput {
    match tier_decision {
        Ok(decision)
            if request.policy.capture_denials.is_some()
                && decision.tier != fallback_detector::IsolationTier::BaseContainer
                && !probes.guarded_capture_available =>
        {
            ProbeOutput {
                tier: None,
                needs_dacl_augmentation: None,
                warnings: decision.warnings,
                probes,
                error: Some("guarded WPR captureDenials fallback is unavailable".to_string()),
            }
        }
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
        FallbackError::EnumeratePathsUnsupported | FallbackError::IngressUnsupported => {
            e.to_string()
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
    use crate::test_env::{CaptureCapabilityGuard, ForceTierGuard};
    use wxc_common::models::{
        ContainerPolicy, ExecutionRequest, NetworkAction, NetworkIngressPolicy,
    };

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

    fn request_with_policy(policy: ContainerPolicy) -> ExecutionRequest {
        ExecutionRequest {
            policy,
            ..Default::default()
        }
    }

    fn test_probe_facts(
        native_capture_available: bool,
        guarded_capture_available: bool,
    ) -> ProbeFacts {
        ProbeFacts {
            base_container_api_present: true,
            base_container_policy_results_available: None,
            base_container_create2_export_present: None,
            base_container_support_flags: None,
            base_container_support_query_hresult: None,
            native_capture_available,
            guarded_capture_available,
            bfscfg_present: false,
            bfs_compiled_in: false,
            base_container_supports_deny_paths: false,
            base_container_supports_enumerate_paths: false,
            base_container_supports_ingress_host_loopback_allow: false,
            isolation_session_available: false,
            hyperlight_available: false,
            ui_capabilities: all_ui_capabilities(),
        }
    }

    #[test]
    fn legacy_probe_debug_preserves_compact_and_pretty_fields() {
        let facts = test_probe_facts(false, false);
        let expected = format!(
            concat!(
                "ProbeFacts {{ base_container_api_present: true, ",
                "native_capture_available: false, guarded_capture_available: false, ",
                "bfscfg_present: false, bfs_compiled_in: false, ",
                "base_container_supports_deny_paths: false, ",
                "base_container_supports_enumerate_paths: false, ",
                "base_container_supports_ingress_host_loopback_allow: false, ",
                "isolation_session_available: false, hyperlight_available: false, ",
                "ui_capabilities: {:?} }}"
            ),
            facts.ui_capabilities
        );
        assert_eq!(format!("{facts:?}"), expected);
        let ui = format!("{:#?}", facts.ui_capabilities).replace('\n', "\n    ");
        let expected = format!(
            concat!(
                "ProbeFacts {{\n    base_container_api_present: true,\n",
                "    native_capture_available: false,\n    guarded_capture_available: false,\n",
                "    bfscfg_present: false,\n    bfs_compiled_in: false,\n",
                "    base_container_supports_deny_paths: false,\n",
                "    base_container_supports_enumerate_paths: false,\n",
                "    base_container_supports_ingress_host_loopback_allow: false,\n",
                "    isolation_session_available: false,\n    hyperlight_available: false,\n",
                "    ui_capabilities: {},\n}}"
            ),
            ui
        );
        assert_eq!(format!("{facts:#?}"), expected);
        let mut reported = facts;
        reported.base_container_policy_results_available = Some(false);
        reported.base_container_create2_export_present = Some(true);
        reported.base_container_support_flags = Some(0x0f);
        reported.base_container_support_query_hresult = Some("0x00000000".into());
        let debug = format!("{reported:?}");
        assert!(debug.contains("base_container_policy_results_available: Some(false)"));
        assert!(debug.contains("base_container_create2_export_present: Some(true)"));
        assert!(debug.contains("base_container_support_flags: Some(15)"));
        assert!(debug.contains("base_container_support_query_hresult: Some(\"0x00000000\")"));
    }

    #[test]
    fn policy_enforcement_probe_is_absent_and_unqueried_without_controls() {
        let mut request = ExecutionRequest::default();
        let calls = std::cell::Cell::new(0);
        let probe = || {
            calls.set(calls.get() + 1);
            crate::secenv::PolicyResultExportReport::default()
        };
        assert!(policy_exports(&request, probe).is_none());
        assert_eq!(calls.get(), 0);
        let json = serde_json::to_value(test_probe_facts(false, false)).unwrap();
        for name in [
            "baseContainerPolicyResultsAvailable",
            "baseContainerCreate2ExportPresent",
            "baseContainerSupportFlags",
            "baseContainerSupportQueryHresult",
        ] {
            assert!(json.get(name).is_none());
        }
        request.policy.policy_enforcement =
            Some(wxc_common::policy_enforcement::PolicyEnforcementOptions::default());
        assert!(policy_exports(&request, probe).is_some());
        assert_eq!(calls.get(), 1);
    }

    #[test]
    fn probe_output_serializes() {
        let out = ProbeOutput {
            tier: Some("base-container"),
            needs_dacl_augmentation: Some(false),
            warnings: vec!["a warning".to_string()],
            probes: ProbeFacts {
                base_container_api_present: true,
                base_container_policy_results_available: Some(true),
                base_container_create2_export_present: Some(true),
                base_container_support_flags: Some(0x1f),
                base_container_support_query_hresult: Some("0x00000000".into()),
                native_capture_available: true,
                guarded_capture_available: true,
                bfscfg_present: false,
                bfs_compiled_in: false,
                base_container_supports_deny_paths: false,
                base_container_supports_enumerate_paths: false,
                base_container_supports_ingress_host_loopback_allow: false,
                isolation_session_available: true,
                hyperlight_available: false,
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
        assert_eq!(v["probes"]["baseContainerPolicyResultsAvailable"], true);
        assert_eq!(v["probes"]["baseContainerCreate2ExportPresent"], true);
        assert_eq!(v["probes"]["baseContainerSupportFlags"], 0x1f);
        assert_eq!(
            v["probes"]["baseContainerSupportQueryHresult"],
            "0x00000000"
        );
        assert_eq!(v["probes"]["nativeCaptureAvailable"], true);
        assert_eq!(v["probes"]["guardedCaptureAvailable"], true);
        assert_eq!(v["probes"]["bfscfgPresent"], false);
        assert_eq!(v["probes"]["bfsCompiledIn"], false);
        assert_eq!(v["probes"]["baseContainerSupportsDenyPaths"], false);
        assert_eq!(v["probes"]["baseContainerSupportsEnumeratePaths"], false);
        assert_eq!(
            v["probes"]["baseContainerSupportsIngressHostLoopbackAllow"],
            false
        );
        assert_eq!(v["probes"]["isolationSessionAvailable"], true);
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
                base_container_policy_results_available: None,
                base_container_create2_export_present: None,
                base_container_support_flags: None,
                base_container_support_query_hresult: None,
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
    fn request_capabilities_control_base_container_selection() {
        let _lock = crate::test_env::lock();
        // SAFETY: env-var mutation is serialized by the shared test lock.
        unsafe {
            std::env::set_var("MXC_FORCE_BC_USABLE", "1");
        }
        let request = ExecutionRequest::default();
        let selected = run_probe(&request, false);
        // SAFETY: env-var mutation is serialized by the shared test lock.
        unsafe {
            std::env::remove_var("MXC_FORCE_BC_USABLE");
        }

        assert_eq!(selected.tier, Some("base-container"));
        assert!(selected.error.is_none());
    }

    #[test]
    fn capture_denials_remains_launchable_on_appcontainer_fallback() {
        let _guard = ForceTierGuard::set_tier(IsolationTier::AppContainerDacl);
        let policy = ContainerPolicy {
            capture_denials: Some(Default::default()),
            ..Default::default()
        };
        let request = request_with_policy(policy);

        let output = run_probe_with_tier_decision(
            &request,
            test_probe_facts(false, true),
            fallback_detector::choose_backend_tier(&request),
        );

        assert_eq!(output.tier, Some("appcontainer-dacl"));
        assert!(!output.probes.native_capture_available);
        assert!(output.error.is_none());
    }

    #[test]
    fn capture_denials_requires_guarded_capture_on_appcontainer_fallback() {
        let _guard = ForceTierGuard::set_tier(IsolationTier::AppContainerDacl);
        let policy = ContainerPolicy {
            capture_denials: Some(Default::default()),
            ..Default::default()
        };
        let request = request_with_policy(policy);
        let output = run_probe_with_tier_decision(
            &request,
            test_probe_facts(false, false),
            fallback_detector::choose_backend_tier(&request),
        );

        assert!(output.tier.is_none());
        assert!(output.needs_dacl_augmentation.is_none());
        assert!(!output.probes.guarded_capture_available);
        assert_eq!(
            output.error.as_deref(),
            Some("guarded WPR captureDenials fallback is unavailable")
        );
    }

    #[test]
    fn native_capture_does_not_require_guarded_capture_on_base_container() {
        let _guard = ForceTierGuard::set_tier(IsolationTier::BaseContainer);
        let policy = ContainerPolicy {
            capture_denials: Some(Default::default()),
            ..Default::default()
        };
        let request = request_with_policy(policy);
        let output = run_probe_with_tier_decision(
            &request,
            test_probe_facts(true, false),
            fallback_detector::choose_backend_tier(&request),
        );

        assert_eq!(output.tier, Some("base-container"));
        assert!(!output.probes.guarded_capture_available);
        assert!(output.error.is_none());
    }

    #[test]
    fn public_probe_reports_native_capture_and_selects_base_container() {
        let _guard = CaptureCapabilityGuard::set(true, true);
        let policy = ContainerPolicy {
            capture_denials: Some(Default::default()),
            ..Default::default()
        };

        let output = run_probe(&request_with_policy(policy), true);

        assert_eq!(output.tier, Some("base-container"));
        assert!(output.probes.native_capture_available);
        assert!(output.error.is_none());
    }

    #[test]
    fn public_probe_keeps_capture_launchable_without_native_capture() {
        let _guard = CaptureCapabilityGuard::set(false, false);
        let policy = ContainerPolicy {
            capture_denials: Some(Default::default()),
            ..Default::default()
        };

        let output = run_probe(&request_with_policy(policy), true);

        assert_ne!(output.tier, Some("base-container"));
        assert!(!output.probes.native_capture_available);
        assert!(output.error.is_none());
    }

    #[test]
    fn public_probe_rejects_unavailable_guarded_capture() {
        let _guard = CaptureCapabilityGuard::set(false, false);
        let policy = ContainerPolicy {
            capture_denials: Some(Default::default()),
            ..Default::default()
        };

        let output = run_probe(&request_with_policy(policy), false);

        assert!(output.tier.is_none());
        assert!(!output.probes.native_capture_available);
        assert!(!output.probes.guarded_capture_available);
        assert_eq!(
            output.error.as_deref(),
            Some("guarded WPR captureDenials fallback is unavailable")
        );
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
        let _g = ForceTierGuard::set_tier(IsolationTier::AppContainerBfs);
        let request = ExecutionRequest::default();
        let out = run_probe(&request, true);
        assert_eq!(out.tier, Some("appcontainer-bfs"));
        assert_eq!(out.needs_dacl_augmentation, Some(false));
        assert!(out.error.is_none());
    }

    #[test]
    fn run_probe_handles_dacl_disabled_error() {
        let _g = ForceTierGuard::set_tier(IsolationTier::AppContainerDacl);
        let mut policy = ContainerPolicy::default();
        policy.fallback.allow_dacl_mutation = false;
        let out = run_probe(&request_with_policy(policy), true);
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
        let _g = ForceTierGuard::set_tier(IsolationTier::AppContainerDacl);
        let mut policy = ContainerPolicy::default();
        policy.fallback.allow_dacl_mutation = false;
        let out = run_probe(&request_with_policy(policy), true);
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

    #[test]
    fn probe_always_emits_isolation_session_available() {
        // The SDK's isolation-session gate reads this non-optional field, so
        // it must always serialize (never omitted), even when false.
        let out = run_probe(&ExecutionRequest::default(), true);
        let v = serde_json::to_value(&out).expect("to_value");
        let probes = v["probes"].as_object().expect("probes object");
        assert!(
            probes.contains_key("isolationSessionAvailable"),
            "isolationSessionAvailable must always be present, got: {v}"
        );
    }

    #[test]
    fn request_detector_keeps_supported_denied_paths_on_base_container() {
        let _guard = crate::test_env::lock();
        // SAFETY: env-var mutation is serialized by the shared test lock.
        unsafe {
            std::env::set_var("MXC_FORCE_BC_USABLE", "1");
            std::env::set_var("MXC_FORCE_DENY_PATHS", "1");
        }
        let mut request = ExecutionRequest::default();
        request.policy.denied_paths = vec!["C:\\secret".to_string()];

        let decision = fallback_detector::choose_backend_tier(&request)
            .expect("BaseContainer should be selected");
        // SAFETY: env-var mutation is serialized by the shared test lock.
        unsafe {
            std::env::remove_var("MXC_FORCE_BC_USABLE");
            std::env::remove_var("MXC_FORCE_DENY_PATHS");
        }

        assert_eq!(decision.tier, IsolationTier::BaseContainer);
    }

    #[test]
    fn request_detector_rejects_enumerate_paths_without_compatible_base_container() {
        let _guard = crate::test_env::BcUsableGuard::set(false);
        let mut request = ExecutionRequest::default();
        request.policy.enumerate_paths = vec!["C:\\tools".to_string()];

        let error = fallback_detector::choose_backend_tier(&request)
            .expect_err("enumeratePaths must not fall through to AppContainer");

        assert!(matches!(error, FallbackError::EnumeratePathsUnsupported));
    }

    #[test]
    fn request_detector_rejects_host_loopback_without_compatible_base_container() {
        let _guard = crate::test_env::BcUsableGuard::set(false);
        let mut request = ExecutionRequest::default();
        request.policy.network_ingress = Some(NetworkIngressPolicy {
            default: NetworkAction::Deny,
            host_loopback: NetworkAction::Allow,
        });

        let error = fallback_detector::choose_backend_tier(&request)
            .expect_err("host-loopback ingress must not fall through to AppContainer");

        assert!(matches!(error, FallbackError::IngressUnsupported));
    }
}
