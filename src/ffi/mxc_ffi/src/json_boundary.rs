// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use mxc_sdk::mxc_common::config_parser::load_mxc_request_from_json;
use mxc_sdk::mxc_common::logger::{Logger, Mode};
use mxc_sdk::mxc_common::models::ContainmentBackend;
use mxc_sdk::mxc_common::state_aware_dispatch::resolve_backend;
use mxc_sdk::mxc_common::state_aware_request::MxcRequest;
use mxc_sdk::v1::{Error, ErrorCode};

pub(crate) enum JsonSurface {
    OneShotStreaming,
    Lifecycle,
}

pub(crate) fn check_json_surface(json: &str, surface: JsonSurface) -> Result<(), Error> {
    let mut logger = Logger::new(Mode::Buffer);
    // Classify only valid contracts. The existing entry point retains ownership
    // of malformed JSON, unknown fields, and requests for the wrong surface.
    let code = match (surface, load_mxc_request_from_json(json, &mut logger)) {
        (JsonSurface::OneShotStreaming, Ok(MxcRequest::OneShot(request)))
            if request.containment == ContainmentBackend::MicroVm =>
        {
            ErrorCode::UnsupportedContainment
        }
        (JsonSurface::Lifecycle, Ok(MxcRequest::StateAware(request)))
            if matches!(resolve_backend(&request), Ok(ContainmentBackend::MicroVm)) =>
        {
            ErrorCode::UnsupportedPhase
        }
        _ => return Ok(()),
    };
    Err(Error::new(
        code,
        "MicroVM streaming and lifecycle operations are supported only through Rust \
         mxc_sdk::v1::dev JSON APIs",
    ))
}
