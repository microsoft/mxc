// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use mxc_sdk::mxc_common::config_parser::{load_mxc_request_from_json, ParseError};
use mxc_sdk::mxc_common::logger::{Logger, Mode};
use mxc_sdk::mxc_common::models::ContainmentBackend;
use mxc_sdk::mxc_common::mxc_error::MxcError;
use mxc_sdk::mxc_common::state_aware_dispatch::resolve_backend;
use mxc_sdk::mxc_common::state_aware_request::MxcRequest;
use mxc_sdk::v1::{Error, ErrorCode};

pub(crate) enum JsonSurface {
    OneShotStreaming,
    Lifecycle,
}

pub(crate) fn check_json_surface(json: &str, surface: JsonSurface) -> Result<(), Error> {
    #[cfg(test)]
    if let Some(error) = tests::take_injected_failure() {
        return check_parsed_surface(Err(error), surface);
    }
    let mut logger = Logger::new(Mode::Buffer);
    check_parsed_surface(load_mxc_request_from_json(json, &mut logger), surface)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::*;
    use mxc_sdk::mxc_common::error::WxcError;
    use std::cell::RefCell;
    use std::ffi::CString;
    use std::mem::MaybeUninit;
    use std::ptr;

    thread_local! {
        static FAILURE: RefCell<Option<ParseError>> = const { RefCell::new(None) };
    }

    pub(super) fn take_injected_failure() -> Option<ParseError> {
        FAILURE.with(|failure| failure.borrow_mut().take())
    }

    #[test]
    fn valid_non_microvm_requests_still_pass_the_surface_check() {
        assert!(check_json_surface(
            r#"{"version":"1.1.0-alpha","containment":"process","process":{"commandLine":"true"}}"#,
            JsonSurface::OneShotStreaming,
        )
        .is_ok());
        assert!(check_json_surface(
            r#"{"version":"1.1.0-alpha","phase":"exec","sandboxId":"wslc:control","process":{"commandLine":"true"}}"#,
            JsonSurface::Lifecycle,
        ).is_ok());
    }

    #[test]
    fn public_spawn_does_not_retry_a_transient_normalization_failure() {
        // The backend-invalid timeout makes an unexpected dispatch safe even
        // in a feature-unified test binary with a signed runtime available.
        let json = CString::new(r#"{"version":"1.1.0-alpha","containment":"microvm","microvm":{"image":"mcr.microsoft.com/azurelinux/base/core:3.0"},"process":{"commandLine":"true","timeout":3600001}}"#).unwrap();
        FAILURE.with(|failure| {
            *failure.borrow_mut() = Some(ParseError::OneShot(WxcError::ConfigParse(
                "filesystem probe timed out after 5000ms".to_owned(),
            )))
        });
        for expected in [
            MXC_STATUS_MALFORMED_REQUEST,
            MXC_STATUS_UNSUPPORTED_CONTAINMENT,
        ] {
            let mut handle = ptr::null_mut();
            let mut detail = MaybeUninit::uninit();
            // SAFETY: all pointers reference valid request/output storage.
            let status =
                unsafe { mxc_spawn_json(json.as_ptr(), 1, &mut handle, detail.as_mut_ptr()) };
            assert!(handle.is_null());
            // SAFETY: the C entry point initialized the error storage.
            let mut detail = unsafe { detail.assume_init() };
            // SAFETY: error strings were allocated by this library.
            unsafe { mxc_error_detail_free(&mut detail) };
            assert_eq!(
                status, expected,
                "first failure must not reach a successful reparse"
            );
        }
    }

    #[test]
    fn public_provision_does_not_retry_a_transient_normalization_failure() {
        let json = CString::new(r#"{"version":"1.1.0-alpha","phase":"provision","containment":"microvm","microvm":{"image":"mcr.microsoft.com/azurelinux/base/core:3.0"}}"#).unwrap();
        FAILURE.with(|failure| {
            *failure.borrow_mut() = Some(ParseError::StateAware(MxcError::malformed_request(
                "filesystem probe timed out after 5000ms",
            )))
        });
        for expected in [MXC_STATUS_MALFORMED_REQUEST, MXC_STATUS_UNSUPPORTED_PHASE] {
            let mut result = MaybeUninit::<MxcStateAwareResult>::uninit();
            // SAFETY: request and result storage are valid for this call.
            let status =
                unsafe { mxc_run_state_aware_json(json.as_ptr(), 1, 1, result.as_mut_ptr()) };
            // SAFETY: the entry point initialized the result.
            let mut result = unsafe { result.assume_init() };
            assert!(result.response_json_utf8.is_null());
            // SAFETY: result strings were allocated by this library.
            unsafe { mxc_state_aware_result_free(&mut result) };
            assert_eq!(
                status, expected,
                "first failure must not reach a successful reparse"
            );
        }
    }
}

fn check_parsed_surface(
    parsed: Result<MxcRequest, ParseError>,
    surface: JsonSurface,
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
        (JsonSurface::Lifecycle, MxcRequest::StateAware(request))
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
