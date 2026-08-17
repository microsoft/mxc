// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! The structured failure detail carried across the C ABI.
//!
//! One shape for every failing surface in this library, rather than a bare
//! message per surface: the run-to-completion result, the state-aware result,
//! and the out-parameter of the two entry points that hand back a live handle
//! all carry an [`MxcErrorDetail`]. A binding therefore learns *which API call
//! failed and with what platform status* from any of them, and frees them all
//! the same way.
//!
//! ## Invariant
//!
//! `native_code_utf8` is non-null only when `operation_utf8` is — a status with
//! no call to attribute it to is not something a producer can express.
//! `remediation_utf8` carries no such coupling: it is populated from its own
//! field on the SDK error, independently of the other two.

use std::ffi::c_char;
use std::panic::catch_unwind;
use std::ptr;

use mxc_sdk::Error;

use crate::{alloc_cstring, free_cstr};

/// Why a call failed: the message, plus the failing API call when one was in
/// flight.
///
/// Every non-null field is owned by the caller and must be released — by
/// [`mxc_error_detail_free`] when the detail stands alone, or by the owning
/// result's free function when it is embedded in one.
#[repr(C)]
pub struct MxcErrorDetail {
    /// Human-readable message (UTF-8, NUL-terminated), or null on success.
    pub message_utf8: *mut c_char,
    /// The API call that failed, namespaced by its interface and free of call
    /// parameters, so it can be grouped in telemetry. Null when the failure was
    /// raised before any API call, as a malformed request is.
    pub operation_utf8: *mut c_char,
    /// The underlying platform status, e.g. `0x80070490`. Null unless
    /// `operation_utf8` is non-null.
    pub native_code_utf8: *mut c_char,
    /// An actionable hint, when the failure carries one. Null otherwise — this
    /// field does not depend on `operation_utf8`.
    pub remediation_utf8: *mut c_char,
}

impl MxcErrorDetail {
    /// The success shape: every field null.
    pub(crate) fn none() -> Self {
        Self {
            message_utf8: ptr::null_mut(),
            operation_utf8: ptr::null_mut(),
            native_code_utf8: ptr::null_mut(),
            remediation_utf8: ptr::null_mut(),
        }
    }

    /// A message with no API detail — for failures this library raises itself,
    /// such as a policy that will not parse.
    pub(crate) fn from_message(message: impl Into<String>) -> Self {
        Self {
            message_utf8: alloc_cstring(message.into().as_bytes()),
            ..Self::none()
        }
    }

    /// The full detail from an SDK error, carrying the API call across when the
    /// error names one.
    pub(crate) fn from_error(error: &Error) -> Self {
        Self {
            message_utf8: alloc_cstring(error.message.as_bytes()),
            operation_utf8: opt_cstring(error.operation.as_deref()),
            native_code_utf8: opt_cstring(error.native_code.as_deref()),
            remediation_utf8: opt_cstring(error.remediation.as_deref()),
        }
    }

    /// Free every owned string, resetting each to null. Idempotent, so a
    /// double free is a no-op rather than a fault.
    pub(crate) fn free_strings(&mut self) {
        free_cstr(&mut self.message_utf8);
        free_cstr(&mut self.operation_utf8);
        free_cstr(&mut self.native_code_utf8);
        free_cstr(&mut self.remediation_utf8);
    }
}

/// Allocate an optional string, mapping absence to null. Absence and the empty
/// string stay distinguishable, which is the whole point: `None` means the API
/// supplied no status, `Some("")` would mean it supplied an empty one.
fn opt_cstring(value: Option<&str>) -> *mut c_char {
    match value {
        Some(text) => alloc_cstring(text.as_bytes()),
        None => ptr::null_mut(),
    }
}

/// Free the strings owned by a standalone [`MxcErrorDetail`] — the shape the
/// out-parameter entry points fill.
///
/// Does **not** free the struct itself: that storage belongs to the caller.
/// Passing null is a no-op, and calling it twice is safe.
///
/// # Safety
/// `detail` must be null, or a valid pointer to an `MxcErrorDetail` this
/// library filled and nobody has freed by other means.
#[no_mangle]
pub unsafe extern "C" fn mxc_error_detail_free(detail: *mut MxcErrorDetail) {
    if detail.is_null() {
        return;
    }
    let _ = catch_unwind(|| {
        // SAFETY: non-null per the check above, and valid per the caller contract.
        unsafe { (*detail).free_strings() };
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use mxc_sdk::ErrorCode;
    use std::ffi::CStr;

    /// Read an owned C string back, or `None` when the pointer is null. Absence
    /// and emptiness must stay distinguishable.
    fn read(p: *mut c_char) -> Option<String> {
        if p.is_null() {
            None
        } else {
            // SAFETY: non-null per the check, and produced by `alloc_cstring`.
            Some(unsafe { CStr::from_ptr(p) }.to_string_lossy().into_owned())
        }
    }

    fn sdk_error_with_detail() -> Error {
        let mut error = Error::new(ErrorCode::BackendError, "The provision was not found.");
        error.operation = Some("IsoSessionOps.StopSessionAsync".into());
        error.native_code = Some("0x80070490".into());
        error.remediation = Some("Provision the session first.".into());
        error
    }

    /// The whole detail crosses the boundary, not just the message.
    ///
    /// The regression this pins: the C ABI used to expose a bare `error_utf8`,
    /// so a binding could report *that* a call failed but never *which* call or
    /// with what platform status.
    #[test]
    fn an_sdk_error_carries_its_api_detail_across() {
        let mut detail = MxcErrorDetail::from_error(&sdk_error_with_detail());

        assert_eq!(
            read(detail.message_utf8).as_deref(),
            Some("The provision was not found.")
        );
        assert_eq!(
            read(detail.operation_utf8).as_deref(),
            Some("IsoSessionOps.StopSessionAsync")
        );
        assert_eq!(read(detail.native_code_utf8).as_deref(), Some("0x80070490"));
        assert_eq!(
            read(detail.remediation_utf8).as_deref(),
            Some("Provision the session first.")
        );

        detail.free_strings();
    }

    /// An operation with no status leaves the optional halves NULL rather than
    /// empty: `None` and `Some("")` are different answers to "did the API
    /// supply a status?", and a binding maps null to `null`, not `""`.
    #[test]
    fn absent_optional_fields_stay_null_rather_than_empty() {
        let mut error = Error::new(ErrorCode::BackendError, "boom");
        error.operation = Some("Iface.Call".into());
        let mut detail = MxcErrorDetail::from_error(&error);

        assert_eq!(read(detail.operation_utf8).as_deref(), Some("Iface.Call"));
        assert!(detail.native_code_utf8.is_null());
        assert!(detail.remediation_utf8.is_null());

        detail.free_strings();
    }

    /// A failure raised before any API call carries a message and nothing else,
    /// which is what upholds "a native code implies an operation".
    #[test]
    fn a_library_raised_failure_carries_only_a_message() {
        let mut detail = MxcErrorDetail::from_message("policy JSON pointer is null");

        assert_eq!(
            read(detail.message_utf8).as_deref(),
            Some("policy JSON pointer is null")
        );
        assert!(detail.operation_utf8.is_null());
        assert!(detail.native_code_utf8.is_null());
        assert!(detail.remediation_utf8.is_null());

        detail.free_strings();
    }

    /// An error with no API detail at all still produces a message-only detail,
    /// so the success shape and the "no detail" shape stay distinguishable.
    #[test]
    fn an_error_without_api_detail_leaves_the_call_fields_null() {
        let error = Error::new(ErrorCode::MalformedRequest, "bad json");
        let mut detail = MxcErrorDetail::from_error(&error);

        assert_eq!(read(detail.message_utf8).as_deref(), Some("bad json"));
        assert!(detail.operation_utf8.is_null());

        detail.free_strings();
    }

    /// Success is all-null, so a caller can test any field to see there was no
    /// failure.
    #[test]
    fn the_success_shape_is_entirely_null() {
        let detail = MxcErrorDetail::none();
        assert!(detail.message_utf8.is_null());
        assert!(detail.operation_utf8.is_null());
        assert!(detail.native_code_utf8.is_null());
        assert!(detail.remediation_utf8.is_null());
    }

    /// Freeing twice is a no-op rather than a double free, because each field
    /// is nulled as it is released.
    #[test]
    fn freeing_is_idempotent() {
        let mut detail = MxcErrorDetail::from_error(&sdk_error_with_detail());

        // SAFETY: a valid, filled detail this test owns.
        unsafe { mxc_error_detail_free(&mut detail) };
        assert!(detail.message_utf8.is_null());
        assert!(detail.operation_utf8.is_null());

        // SAFETY: the same detail, already freed — must not fault.
        unsafe { mxc_error_detail_free(&mut detail) };
        assert!(detail.message_utf8.is_null());
    }

    /// Freeing a null pointer is tolerated, matching the other `*_free` entry
    /// points in this library.
    #[test]
    fn freeing_null_is_tolerated() {
        // SAFETY: null is explicitly part of the contract.
        unsafe { mxc_error_detail_free(ptr::null_mut()) };
    }
}
