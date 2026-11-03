// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use mxc_sdk::mxc_common::config_parser::{load_mxc_request_from_json, ParseError};
use mxc_sdk::mxc_common::id::parse_sandbox_id_prefix;
use mxc_sdk::mxc_common::logger::{Logger, Mode};
use mxc_sdk::mxc_common::models::ContainmentBackend;
use mxc_sdk::mxc_common::mxc_error::MxcError;
use mxc_sdk::mxc_common::state_aware_dispatch::resolve_backend;
use mxc_sdk::mxc_common::state_aware_request::MxcRequest;
use mxc_sdk::mxc_contract::dev::{probe_phase, Phase};
use mxc_sdk::v1::{Error, ErrorCode};

#[derive(Clone, Copy)]
pub(crate) enum JsonSurface {
    OneShotStreaming,
    LifecycleEnvelope { dry_run: bool },
    LifecycleExec,
}

#[derive(serde::Deserialize)]
struct RoutingSelectors {
    containment: Option<String>,
    #[serde(rename = "sandboxId")]
    sandbox_id: Option<String>,
}

pub(crate) fn check_json_surface(
    json: &str,
    surface: JsonSurface,
    experimental: bool,
) -> Result<(), Error> {
    // This is only a pure prefilter. The authoritative parser still validates
    // every request, here before exclusion or in the existing operation delegate.
    let Ok(phase) = probe_phase(json) else {
        return Ok(());
    };
    let applicable = match surface {
        JsonSurface::OneShotStreaming => phase.is_none(),
        JsonSurface::LifecycleEnvelope { dry_run } => {
            phase.is_some() && (dry_run || phase != Some(Phase::Exec))
        }
        JsonSurface::LifecycleExec => phase == Some(Phase::Exec),
    };
    if !applicable {
        return Ok(());
    }
    let Ok(selectors) = serde_json::from_str::<RoutingSelectors>(json) else {
        return Ok(());
    };
    let selects_microvm = match phase {
        None | Some(Phase::Provision | Phase::ProvisionSession | Phase::DeprovisionSession) => {
            selectors.containment.as_deref() == Some("microvm")
        }
        Some(_) => selectors
            .sandbox_id
            .as_deref()
            .is_some_and(|id| matches!(parse_sandbox_id_prefix(id), Ok("microvm"))),
    };
    if !selects_microvm {
        return Ok(());
    }
    let mut logger = Logger::new(Mode::Buffer);
    check_parsed_surface(
        load_mxc_request_from_json(json, &mut logger),
        surface,
        experimental,
    )
}

fn check_parsed_surface(
    parsed: Result<MxcRequest, ParseError>,
    surface: JsonSurface,
    experimental: bool,
) -> Result<(), Error> {
    // Never retry a failed normalization: a transient probe failure must not
    // let dispatch parse a forbidden MicroVM request successfully on retry.
    let request = parsed.map_err(|error| {
        Error::from(match error {
            ParseError::StateAware(error) => error,
            ParseError::Decode(error)
            | ParseError::Version(error)
            | ParseError::OneShot(error)
            | ParseError::OneShotMalformed(error) => MxcError::malformed_request(error.to_string()),
        })
    })?;
    let code = match (surface, request) {
        (JsonSurface::OneShotStreaming, MxcRequest::OneShot(request))
            if request.containment == ContainmentBackend::MicroVm =>
        {
            ErrorCode::UnsupportedContainment
        }
        (
            JsonSurface::LifecycleEnvelope { .. } | JsonSurface::LifecycleExec,
            MxcRequest::StateAware(request),
        ) if matches!(resolve_backend(&request), Ok(ContainmentBackend::MicroVm)) => {
            ErrorCode::UnsupportedPhase
        }
        _ => return Ok(()),
    };
    // Preserve the engine's authorization error before the binding exclusion.
    if !experimental {
        return Err(MxcError::backend_unavailable(
            "the 'microvm' backend is experimental; enable experimental features to use it",
        )
        .into());
    }
    Err(Error::new(
        code,
        "MicroVM streaming and lifecycle operations are supported only through Rust \
         mxc_sdk::v1::dev JSON APIs",
    ))
}
