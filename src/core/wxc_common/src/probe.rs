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
use crate::models::ContainerPolicy;

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
}

/// Run the fallback detector against `policy` and return a JSON-shaped
/// summary. The detector is always asked to prefer BaseContainer (Tier 1).
pub fn run_probe(policy: &ContainerPolicy) -> ProbeOutput {
    let probes = ProbeFacts {
        base_container_api_present: fallback_detector::is_base_container_api_present(),
        bfscfg_present: fallback_detector::find_bfscfg_exe()
            .ok()
            .flatten()
            .is_some(),
        bfs_compiled_in: cfg!(feature = "tier2_bfs"),
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
        assert!(v.get("error").is_none());
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
