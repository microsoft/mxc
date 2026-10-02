// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use std::ffi::c_char;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::ptr;

use mxc_sdk::{v1::spawn_with_pty, MxcPtySize};

use crate::streaming::{finish_handle, parse_request, sdk_error_detail, MxcSandbox};
use crate::{
    MxcErrorDetail, MXC_STATUS_BACKEND_ERROR, MXC_STATUS_NULL_ARGUMENT, MXC_STATUS_PANIC,
    MXC_STATUS_SUCCESS,
};

/// Spawn a complete one-shot request attached to an MXC-owned PTY.
///
/// The returned handle uses the ordinary `mxc_sandbox_*` lifecycle and stream
/// functions. Only resize is PTY-specific.
///
/// # Safety
/// - `request_json_utf8` must point to valid NUL-terminated UTF-8.
/// - `out_handle` must point to writable pointer storage.
/// - `out_error`, when non-null, must point to writable [`MxcErrorDetail`] storage.
#[no_mangle]
pub unsafe extern "C" fn mxc_spawn_pty_request(
    request_json_utf8: *const c_char,
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
        if rows == 0 || cols == 0 {
            return Err((
                crate::MXC_STATUS_MALFORMED_REQUEST,
                MxcErrorDetail::from_message("PTY rows and columns must be non-zero"),
            ));
        }
        let request = parse_request(request_json_utf8)?;
        spawn_with_pty(
            request,
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
        crate::report_panic("mxc_spawn_pty_request", &*panic);
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
/// `handle` must be a live handle returned by [`mxc_spawn_pty_request`].
#[no_mangle]
pub unsafe extern "C" fn mxc_sandbox_pty_resize(
    handle: *const MxcSandbox,
    rows: u16,
    cols: u16,
) -> i32 {
    if handle.is_null() {
        return MXC_STATUS_NULL_ARGUMENT;
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
