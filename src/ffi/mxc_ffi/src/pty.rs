// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use std::ffi::c_char;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::ptr;

use mxc_sdk::__ffi::spawn_with_pty_json;
use mxc_sdk::v1::MxcPtySize;

use crate::streaming::{finish_handle, sdk_error_detail, MxcSandbox};
use crate::{
    cstr_to_str, MxcErrorDetail, MXC_STATUS_BACKEND_ERROR, MXC_STATUS_INVALID_UTF8,
    MXC_STATUS_MALFORMED_REQUEST, MXC_STATUS_NULL_ARGUMENT, MXC_STATUS_PANIC, MXC_STATUS_SUCCESS,
};

const INVALID_PTY_DIMENSIONS: &str = "PTY rows and columns must be between 1 and 32767";

fn validate_pty_dimensions(rows: u16, cols: u16) -> Result<(), i32> {
    MxcPtySize {
        rows,
        cols,
        pixel_width: 0,
        pixel_height: 0,
    }
    .validate()
    .map_err(|_| MXC_STATUS_MALFORMED_REQUEST)
}

/// Spawn an exact-version one-shot JSON request attached to an MXC-owned PTY.
///
/// `experimental` is nonzero to permit an experimental backend and is never
/// read from the JSON.
///
/// # Safety
/// - `request_json_utf8` must point to valid NUL-terminated UTF-8.
/// - `out_handle` must point to writable pointer storage.
/// - `out_error`, when non-null, must point to writable [`MxcErrorDetail`] storage.
#[no_mangle]
pub unsafe extern "C" fn mxc_spawn_pty_json(
    request_json_utf8: *const c_char,
    experimental: i32,
    rows: u16,
    cols: u16,
    out_handle: *mut *mut MxcSandbox,
    out_error: *mut MxcErrorDetail,
) -> i32 {
    if !out_handle.is_null() {
        unsafe { *out_handle = ptr::null_mut() };
    }
    if !out_error.is_null() {
        unsafe { ptr::write(out_error, MxcErrorDetail::none()) };
    }
    if out_handle.is_null() {
        return MXC_STATUS_NULL_ARGUMENT;
    }

    let outcome = catch_unwind(AssertUnwindSafe(|| {
        if let Err(status) = validate_pty_dimensions(rows, cols) {
            return Err((status, MxcErrorDetail::from_message(INVALID_PTY_DIMENSIONS)));
        }
        let request_json = match unsafe { cstr_to_str(request_json_utf8) } {
            Some(value) => value,
            None if request_json_utf8.is_null() => {
                return Err((
                    MXC_STATUS_NULL_ARGUMENT,
                    MxcErrorDetail::from_message("request JSON pointer is null"),
                ));
            }
            None => {
                return Err((
                    MXC_STATUS_INVALID_UTF8,
                    MxcErrorDetail::from_message("request JSON is not UTF-8"),
                ));
            }
        };
        spawn_with_pty_json(
            request_json,
            experimental != 0,
            MxcPtySize {
                rows,
                cols,
                pixel_width: 0,
                pixel_height: 0,
            },
        )
        .map(MxcSandbox::new_pty)
        .map_err(sdk_error_detail)
    }))
    .unwrap_or_else(|panic| {
        crate::report_panic("mxc_spawn_pty_json", &*panic);
        Err((
            MXC_STATUS_PANIC,
            MxcErrorDetail::from_message("the mxc engine panicked"),
        ))
    });

    unsafe { finish_handle(outcome, out_handle, out_error) }
}

/// Resize a PTY-backed sandbox handle.
///
/// # Safety
/// `handle` must be a live handle returned by [`mxc_spawn_pty_json`] or
/// [`crate::mxc_state_aware_exec_pty`], and this call must be serialized with
/// every other operation on that handle.
#[no_mangle]
pub unsafe extern "C" fn mxc_sandbox_pty_resize(
    handle: *mut MxcSandbox,
    rows: u16,
    cols: u16,
) -> i32 {
    if handle.is_null() {
        return MXC_STATUS_NULL_ARGUMENT;
    }
    if let Err(status) = validate_pty_dimensions(rows, cols) {
        return status;
    }

    catch_unwind(AssertUnwindSafe(|| {
        let sandbox = unsafe { &*handle };
        sandbox
            .resize_pty(MxcPtySize {
                rows,
                cols,
                pixel_width: 0,
                pixel_height: 0,
            })
            .map(|()| MXC_STATUS_SUCCESS)
            .unwrap_or(MXC_STATUS_BACKEND_ERROR)
    }))
    .unwrap_or_else(|panic| {
        crate::report_panic("mxc_sandbox_pty_resize", &*panic);
        MXC_STATUS_PANIC
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pty_dimensions_map_invalid_values_to_malformed_request() {
        for (rows, cols) in [(0, 80), (24, 0), (32768, 80), (24, 32768)] {
            assert_eq!(
                validate_pty_dimensions(rows, cols),
                Err(MXC_STATUS_MALFORMED_REQUEST)
            );
        }
        assert_eq!(validate_pty_dimensions(1, 1), Ok(()));
        assert_eq!(validate_pty_dimensions(32767, 32767), Ok(()));
    }
}
