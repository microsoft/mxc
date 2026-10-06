// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Runtime authorization for experimental backends.
//!
//! The engine's [`backend_registry`](crate::mxc_engine::backend_registry) classifies each
//! backend as production or experimental. The caller's experimental opt-in
//! only permits selecting an experimental backend: it is ignored for
//! production backends and is independent of the contract version. One-shot
//! runner resolution and state-aware dispatch both call
//! [`require_experimental_optin`], so every entry point enforces the same rule
//! and reports the same error.

use crate::mxc_common::models::ContainmentBackend;
use crate::mxc_common::mxc_error::MxcError;

use crate::mxc_engine::backend_registry::registration;

/// Reject `backend` with `backend_unavailable` when it is experimental and the
/// caller has not opted in.
pub(crate) fn require_experimental_optin(
    backend: &ContainmentBackend,
    experimental_enabled: bool,
) -> Result<(), MxcError> {
    let metadata = registration(backend);
    if metadata.experimental && !experimental_enabled {
        return Err(MxcError::backend_unavailable(format!(
            "the '{}' backend is experimental; enable experimental features to use it",
            metadata.backend.wire_name()
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mxc_common::mxc_error::MxcErrorCode;

    const EXPERIMENTAL: [ContainmentBackend; 3] = [
        ContainmentBackend::MicroVm,
        ContainmentBackend::Hyperlight,
        ContainmentBackend::WindowsSandbox,
    ];

    const PRODUCTION: [ContainmentBackend; 7] = [
        ContainmentBackend::ProcessContainer,
        ContainmentBackend::Wslc,
        ContainmentBackend::Lxc,
        ContainmentBackend::Vm,
        ContainmentBackend::IsolationSession,
        ContainmentBackend::Seatbelt,
        ContainmentBackend::Bubblewrap,
    ];

    #[test]
    fn experimental_backends_require_the_optin() {
        for backend in EXPERIMENTAL {
            let error = require_experimental_optin(&backend, false).unwrap_err();
            assert_eq!(error.code, MxcErrorCode::BackendUnavailable);
            assert!(error.message.contains(backend.wire_name()), "{error:?}");
            assert!(error.message.contains("experimental"), "{error:?}");
            assert!(require_experimental_optin(&backend, true).is_ok());
        }
    }

    #[test]
    fn production_backends_ignore_the_optin() {
        for backend in PRODUCTION {
            assert!(require_experimental_optin(&backend, false).is_ok());
            assert!(require_experimental_optin(&backend, true).is_ok());
        }
    }
}
