// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Request-aware Windows ProcessContainer probe.
//!
//! The backend owns tier detection and the serialized representation. This
//! module owns the engine-level optional-backend overlays used by the CLI.
//! The output describes ProcessContainer isolation tiers and host facts, so it
//! cannot represent support for backends with different capability models.
//! Those backends expose availability separately and validate requests on
//! their normal launch paths.

use crate::mxc_common::models::ContainmentBackend;
use crate::mxc_common::models::ExecutionRequest;

use crate::Error;

pub use crate::process_container_common::probe::{ProbeFacts, ProbeOutput, UiCapabilitySupport};

/// Probe an optional runtime request without creating a sandbox.
///
/// The executor and public Rust SDK use the same engine-owned probe seam.
#[doc(hidden)]
pub fn probe_execution_request(request: Option<&ExecutionRequest>) -> Result<ProbeOutput, Error> {
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

    let output = crate::process_container_common::probe::run_probe(
        request,
        crate::mxc_engine::guarded_capture::is_available(),
    );

    #[cfg(feature = "isolation_session")]
    let output = {
        let mut output = output;
        output.probes.isolation_session_available =
            crate::mxc_engine::isolation_session_available();
        output
    };

    #[cfg(all(feature = "hyperlight", target_arch = "x86_64"))]
    let output = {
        let mut output = output;
        output.probes.hyperlight_available = crate::hyperlight_common::is_whp_available();
        output
    };

    Ok(output)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn executor_probe_helper_keeps_the_diagnostic_shape() {
        let request = ExecutionRequest::default();
        let output = probe_execution_request(Some(&request))
            .expect("the default request resolves to ProcessContainer");

        let value = serde_json::to_value(output).expect("probe output serializes");
        assert!(value["warnings"].is_array());
        assert!(value["probes"].is_object());
        assert!(
            value.get("tier").is_some() || value.get("error").is_some(),
            "the CLI envelope must contain either the selected tier or detector error"
        );
        assert!(value["probes"].get("isolationSessionAvailable").is_some());
        assert!(value["probes"].get("hyperlightAvailable").is_some());
        assert!(value["probes"].get("uiCapabilities").is_some());
    }

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
}
