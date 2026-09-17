// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! NVX backend preflight checks.
//!
//! PR1 intentionally does not include an executable NVX runtime runner. This
//! crate currently provides only typed availability checks that the engine can
//! call before dispatch.

use wxc_common::mxc_error::MxcError;

/// Typed backend-unavailable message for pinned releases without the NVX
/// workload-image archive.
pub const ERR_WORKLOAD_IMAGE_ASSET_UNAVAILABLE: &str =
    "NVX workload image asset is not available in the pinned release";

/// Verifies whether the pinned NVX release includes workload images required
/// by the runtime implementation.
///
/// The current pinned release does not ship those images, so preflight returns
/// a typed backend-unavailable error.
pub fn preflight() -> Result<(), MxcError> {
    if nvx_binaries::NVX_WORKLOAD_IMAGES_AVAILABLE != "1" {
        return Err(MxcError::backend_unavailable(
            ERR_WORKLOAD_IMAGE_ASSET_UNAVAILABLE,
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::preflight;
    use super::ERR_WORKLOAD_IMAGE_ASSET_UNAVAILABLE;
    use wxc_common::mxc_error::MxcErrorCode;

    #[test]
    fn pinned_release_marks_workload_images_unavailable() {
        assert_eq!(nvx_binaries::NVX_WORKLOAD_IMAGES_AVAILABLE, "0");
    }

    #[test]
    fn preflight_returns_typed_backend_unavailable_error() {
        let err = preflight().expect_err("preflight must fail in PR1");
        assert_eq!(err.code, MxcErrorCode::BackendUnavailable);
        assert_eq!(err.message, ERR_WORKLOAD_IMAGE_ASSET_UNAVAILABLE);
    }
}
