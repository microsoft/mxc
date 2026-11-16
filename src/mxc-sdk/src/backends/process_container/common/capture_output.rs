// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Native `processContainer.captureDenials` output. Generic path and error
//! helpers live in [`crate::learning_mode_core::capture_output`]; retained ETLs
//! use the runner's protected managed-capture store.

use std::path::Path;

use crate::learning_mode_core::capture_diagnostics::CaptureAnalysis;
use crate::mxc_common::models::CaptureDenialsOutput;

/// Directory name of the protected retained-ETL store. Sealed ETLs are promoted
/// out of working storage into a per-run directory beneath a sibling directory
/// with this name (`.../capture-denials/retained/<run>/`). Owned here so
/// consumers that need to recognize a promoted retained-capture directory —
/// e.g. `wxc-exec --audit` relocating and pruning the run directory — do not
/// duplicate the literal.
pub const RETAINED_CAPTURE_DIR_NAME: &str = "retained";

/// Whether `directory` is a per-run directory sitting directly beneath the
/// retained-capture store (`.../retained/<run>`). Recognizes the promoted
/// location produced by the BaseContainer capture path so callers can safely
/// prune it once its ETL has moved out, without hard-coding the store name.
pub fn is_retained_capture_run_dir(directory: &Path) -> bool {
    directory
        .parent()
        .and_then(Path::file_name)
        .is_some_and(|name| name.eq_ignore_ascii_case(RETAINED_CAPTURE_DIR_NAME))
}

/// Writes native capture analysis with the complete internal v5 diagnostics.
pub(crate) fn write_capture_denials_document(
    analysis: CaptureAnalysis,
    exit_code: i32,
    output_path: &Path,
) -> std::io::Result<CaptureDenialsOutput> {
    crate::learning_mode_core::capture_output::write_capture_denials_document(
        analysis,
        exit_code,
        output_path,
    )
    .map(CaptureDenialsOutput::from)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::learning_mode_core::capture_diagnostics::{
        CaptureVerboseLoggingOutcomeReason, CaptureVerboseLoggingProvider,
        CaptureVerboseLoggingSignature, CaptureVerboseLoggingSummary, ConfigurationRecommendation,
        NetworkDecisionReason, NetworkEndpoint, CAPTURE_VERBOSE_LOGGING_VERSION,
    };
    use crate::learning_mode_core::capture_output::verbose_logging_output_path;
    use crate::learning_mode_core::{AccessType, DeniedResource, ResourceType};

    #[test]
    fn native_capture_writes_version_five_reason_specific_guidance() {
        let directory = tempfile::tempdir().expect("temp directory");
        let output_path = directory.path().join("denials.json");
        let mut network_verbose_logging = CaptureVerboseLoggingSummary::default();
        let mut retained_bytes = 0;
        network_verbose_logging.record_with_byte_budget(
            CaptureVerboseLoggingSignature {
                provider: CaptureVerboseLoggingProvider::LearningModeNetworkDecision,
                provider_guid: "{301EC03D-2951-5EFB-6D99-59C64628BBFC}".to_string(),
                event_id: 1,
                event_name: Some("NetworkDecisionV1".to_string()),
                reason: CaptureVerboseLoggingOutcomeReason::Actionable,
                pid: 0,
                access_type: Some(AccessType::Unknown),
                resource_type: Some(ResourceType::Network),
                network_decision_reason: Some(NetworkDecisionReason::DirectDefaultDeny),
                configuration_recommendation: Some(ConfigurationRecommendation::AddEgressAllow),
                network_endpoint: Some(NetworkEndpoint {
                    protocol: "tcp".to_string(),
                    remote_address: "203.0.113.10".to_string(),
                    remote_port: Some(443),
                }),
                properties: Vec::new(),
            },
            &mut retained_bytes,
            crate::learning_mode_core::MAX_VERBOSE_LOGGING_SIGNATURE_BYTES,
        );
        let analysis = CaptureAnalysis {
            denials: vec![DeniedResource {
                resource: "tcp://203.0.113.10:443".to_string(),
                resource_type: ResourceType::Network,
                access_type: AccessType::Unknown,
                pid: 0,
                filetime: 99,
            }],
            denied_resources_truncated: false,
            verbose_logging: Default::default(),
            network_verbose_logging,
        };

        let metadata = write_capture_denials_document(analysis, 7, &output_path).unwrap();
        assert_eq!(metadata.kind, CaptureDenialsOutput::KIND);
        assert_eq!(metadata.output_path, output_path.to_string_lossy());
        assert_eq!(metadata.exit_code, 7);
        assert_eq!(metadata.total_denials, 1);
        assert!(!metadata.denied_resources_truncated);
        assert!(metadata.etl_path.is_none());

        let verbose: serde_json::Value = serde_json::from_slice(
            &std::fs::read(verbose_logging_output_path(&output_path).unwrap()).unwrap(),
        )
        .unwrap();
        assert_eq!(verbose["version"], CAPTURE_VERBOSE_LOGGING_VERSION);
        assert_eq!(
            verbose["signatures"][0]["signature"]["networkDecisionReason"],
            "directDefaultDeny"
        );
        assert_eq!(
            verbose["signatures"][0]["signature"]["configurationRecommendation"],
            "addEgressAllow"
        );
        assert_eq!(
            verbose["signatures"][0]["signature"]["networkEndpoint"]["remoteAddress"],
            "203.0.113.10"
        );
    }
}
