// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! State-aware lifecycle C ABI over the MXC public Rust SDK.
//!
//! Two entry points mirror the SDK's [`mxc_sdk::run_state_aware_json`] and
//! [`mxc_sdk::exec_sandbox`]:
//!
//! - [`mxc_state_aware`] drives the **envelope phases** (`provision` / `start` /
//!   `stop` / `deprovision`, and a dry run of any phase): JSON request in, JSON
//!   response envelope out, filled into an [`MxcStateAwareResult`].
//! - [`mxc_state_aware_exec`] drives the **exec phase** as a **live streaming**
//!   process, returning the same opaque [`MxcSandbox`](crate::MxcSandbox) handle
//!   as [`mxc_spawn`](crate::mxc_spawn) — so the caller reuses the
//!   `mxc_stream_*` / `mxc_sandbox_*` externs to read/write/wait/kill.
//!
//! As elsewhere in this crate, every entry point is [`catch_unwind`]-wrapped,
//! strings in/out are UTF-8 NUL-terminated, and owned out-pointers must be
//! freed with the matching destructor.

use std::ffi::c_char;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::ptr;

use mxc_sdk::{exec_sandbox, run_state_aware_json};

use crate::streaming::MxcSandbox;
use crate::{
    alloc_cstring, cstr_to_str, free_cstr, status_from_error_code, MXC_STATUS_INVALID_UTF8,
    MXC_STATUS_NULL_ARGUMENT, MXC_STATUS_PANIC, MXC_STATUS_SUCCESS,
};

/// The result of an [`mxc_state_aware`] call.
///
/// On success (`status == 0`), `response_json_utf8` holds the response-envelope
/// JSON (`error_utf8` is null). On failure, `error_utf8` holds a human-readable
/// message and `response_json_utf8` is null. Both non-null pointers are owned by
/// the caller and released with [`mxc_state_aware_result_free`].
#[repr(C)]
pub struct MxcStateAwareResult {
    /// `0` on success; otherwise one of the `MXC_STATUS_*` codes.
    pub status: i32,
    /// The response-envelope JSON (UTF-8, NUL-terminated) on success, else null.
    pub response_json_utf8: *mut c_char,
    /// Error message (UTF-8, NUL-terminated) when `status != 0`, else null.
    pub error_utf8: *mut c_char,
}

impl MxcStateAwareResult {
    #[cfg(test)]
    fn empty() -> Self {
        Self {
            status: MXC_STATUS_SUCCESS,
            response_json_utf8: ptr::null_mut(),
            error_utf8: ptr::null_mut(),
        }
    }

    fn error(status: i32, message: impl Into<String>) -> Self {
        Self {
            status,
            response_json_utf8: ptr::null_mut(),
            error_utf8: alloc_cstring(message.into().as_bytes()),
        }
    }

    fn free_strings(&mut self) {
        free_cstr(&mut self.response_json_utf8);
        free_cstr(&mut self.error_utf8);
    }
}

/// Run a state-aware lifecycle request (envelope phases) and capture the
/// response-envelope JSON.
///
/// Parses `request_json_utf8` (the wire-format request, with a `phase` field),
/// runs the requested phase, and writes the outcome into `*out`. A non-dry-run
/// `exec` streams and is rejected here — use [`mxc_state_aware_exec`].
///
/// Returns the resulting status code (also stored in `out->status`). Returns
/// [`MXC_STATUS_NULL_ARGUMENT`] without touching `*out` if `out` is null.
///
/// # Safety
/// - `request_json_utf8` must be null or a valid NUL-terminated UTF-8 C string.
/// - `out` must be null or point to writable [`MxcStateAwareResult`]-sized storage.
/// - On success the caller must release `*out` with [`mxc_state_aware_result_free`].
#[no_mangle]
pub unsafe extern "C" fn mxc_state_aware(
    request_json_utf8: *const c_char,
    dry_run: i32,
    out: *mut MxcStateAwareResult,
) -> i32 {
    let result = catch_unwind(AssertUnwindSafe(|| {
        state_aware_inner(request_json_utf8, dry_run != 0)
    }))
    .unwrap_or_else(|_| MxcStateAwareResult::error(MXC_STATUS_PANIC, "the mxc engine panicked"));

    if out.is_null() {
        let mut orphan = result;
        orphan.free_strings();
        return MXC_STATUS_NULL_ARGUMENT;
    }

    let status = result.status;
    // SAFETY: `out` is non-null and caller-guaranteed writable; ownership of the
    // out-strings transfers to the caller (freed via `mxc_state_aware_result_free`).
    unsafe { ptr::write(out, result) };
    status
}

fn state_aware_inner(request_json_utf8: *const c_char, dry_run: bool) -> MxcStateAwareResult {
    // SAFETY: caller contract on `mxc_state_aware`; borrowed only within scope.
    let request_json = match unsafe { cstr_to_str(request_json_utf8) } {
        Some(s) => s,
        None if request_json_utf8.is_null() => {
            return MxcStateAwareResult::error(
                MXC_STATUS_NULL_ARGUMENT,
                "request JSON pointer is null",
            )
        }
        None => {
            return MxcStateAwareResult::error(MXC_STATUS_INVALID_UTF8, "request JSON is not UTF-8")
        }
    };

    match run_state_aware_json(request_json, dry_run) {
        Ok(response_json) => MxcStateAwareResult {
            status: MXC_STATUS_SUCCESS,
            response_json_utf8: alloc_cstring(response_json.as_bytes()),
            error_utf8: ptr::null_mut(),
        },
        Err(e) => MxcStateAwareResult::error(status_from_error_code(e.code), e.message),
    }
}

/// Free the owned out-strings of an [`MxcStateAwareResult`] produced by
/// [`mxc_state_aware`]. Idempotent; the struct itself is caller-owned.
///
/// # Safety
/// `r` must be null or point to a result previously filled by [`mxc_state_aware`],
/// not already freed.
#[no_mangle]
pub unsafe extern "C" fn mxc_state_aware_result_free(r: *mut MxcStateAwareResult) {
    if r.is_null() {
        return;
    }
    let _ = catch_unwind(AssertUnwindSafe(|| {
        // SAFETY: caller guarantees `r` points to a valid, not-yet-freed result.
        unsafe { (*r).free_strings() };
    }));
}

/// Run the `exec` phase of a state-aware request as a **live streaming** process.
///
/// Parses `request_json_utf8` (an `exec`-phase request with a `sandboxId`),
/// spawns the process, and on success writes an opaque
/// [`MxcSandbox`](crate::MxcSandbox) handle to `*out_handle` (drive it with the
/// `mxc_stream_*` / `mxc_sandbox_*` externs, free it with `mxc_sandbox_free`).
/// On failure returns the status code and, if `out_error` is non-null, writes an
/// owned UTF-8 error string to `*out_error`; `*out_handle` is set to null.
///
/// # Safety
/// - `request_json_utf8` must be null or a valid NUL-terminated UTF-8 C string.
/// - `out_handle` must be non-null and point to writable pointer-sized storage;
///   on success the caller owns `*out_handle` and frees it with `mxc_sandbox_free`.
/// - `out_error` must be null or point to writable pointer-sized storage.
#[no_mangle]
pub unsafe extern "C" fn mxc_state_aware_exec(
    request_json_utf8: *const c_char,
    out_handle: *mut *mut MxcSandbox,
    out_error: *mut *mut c_char,
) -> i32 {
    if !out_handle.is_null() {
        // SAFETY: caller-guaranteed writable pointer-sized storage.
        unsafe { *out_handle = ptr::null_mut() };
    }
    if !out_error.is_null() {
        // SAFETY: caller-guaranteed writable pointer-sized storage.
        unsafe { *out_error = ptr::null_mut() };
    }
    if out_handle.is_null() {
        return MXC_STATUS_NULL_ARGUMENT;
    }

    let outcome = catch_unwind(AssertUnwindSafe(|| {
        // SAFETY: caller contract; borrowed only within scope.
        let request_json = match unsafe { cstr_to_str(request_json_utf8) } {
            Some(s) => s,
            None if request_json_utf8.is_null() => {
                return Err((
                    MXC_STATUS_NULL_ARGUMENT,
                    "request JSON pointer is null".to_string(),
                ))
            }
            None => {
                return Err((
                    MXC_STATUS_INVALID_UTF8,
                    "request JSON is not UTF-8".to_string(),
                ))
            }
        };
        exec_sandbox(request_json).map_err(|e| (status_from_error_code(e.code), e.message))
    }))
    .unwrap_or(Err((
        MXC_STATUS_PANIC,
        "the mxc engine panicked".to_string(),
    )));

    // SAFETY: `out_handle` non-null (checked), `out_error` null or writable.
    unsafe { crate::streaming::finish_spawn(outcome, out_handle, out_error) }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::CString;

    fn call(json: &str, dry_run: bool) -> MxcStateAwareResult {
        let j = CString::new(json).unwrap();
        let mut out = MxcStateAwareResult::empty();
        // SAFETY: valid string and out pointer.
        let status = unsafe { mxc_state_aware(j.as_ptr(), dry_run as i32, &mut out) };
        assert_eq!(status, out.status);
        out
    }

    #[test]
    fn one_shot_config_is_malformed_request() {
        let mut out = call(
            r#"{"version":"0.8.0-alpha","process":{"commandLine":"echo hi"}}"#,
            false,
        );
        assert_eq!(out.status, crate::MXC_STATUS_MALFORMED_REQUEST);
        assert!(out.response_json_utf8.is_null());
        assert!(!out.error_utf8.is_null());
        // SAFETY: filled by `mxc_state_aware`.
        unsafe { mxc_state_aware_result_free(&mut out) };
        assert!(out.error_utf8.is_null());
    }

    #[test]
    fn non_dry_run_exec_is_rejected() {
        let mut out = call(
            r#"{"phase":"exec","sandboxId":"isolationsession:abc","process":{"commandLine":"echo hi"}}"#,
            false,
        );
        assert_eq!(out.status, crate::MXC_STATUS_MALFORMED_REQUEST);
        // SAFETY: filled by `mxc_state_aware`.
        unsafe { mxc_state_aware_result_free(&mut out) };
    }

    #[test]
    fn unregistered_backend_prefix_is_unsupported_containment() {
        // A non-provision phase routes by the sandbox-id prefix; an unregistered
        // prefix is unsupported_containment — deterministic regardless of the
        // isolation_session feature or host, and with no backend side effects.
        // (A real isolation_session provision is avoided: on a capable host it
        // would actually provision a sandbox. See the mxc-sdk state_aware test.)
        let mut out = call(
            r#"{"phase":"start","sandboxId":"nosuchbackend:abc123"}"#,
            false,
        );
        assert_eq!(out.status, crate::MXC_STATUS_UNSUPPORTED_CONTAINMENT);
        // SAFETY: filled by `mxc_state_aware`.
        unsafe { mxc_state_aware_result_free(&mut out) };
    }

    #[test]
    fn null_request_reports_null_argument() {
        let mut out = MxcStateAwareResult::empty();
        // SAFETY: null request is explicitly handled; valid out pointer.
        let status = unsafe { mxc_state_aware(ptr::null(), 0, &mut out) };
        assert_eq!(status, MXC_STATUS_NULL_ARGUMENT);
        assert!(!out.error_utf8.is_null());
        // SAFETY: filled by `mxc_state_aware`.
        unsafe { mxc_state_aware_result_free(&mut out) };
    }

    #[test]
    fn null_out_reports_null_argument() {
        let j = CString::new(r#"{"phase":"provision","containment":"isolation_session"}"#).unwrap();
        // SAFETY: valid string, deliberately-null out.
        let status = unsafe { mxc_state_aware(j.as_ptr(), 0, ptr::null_mut()) };
        assert_eq!(status, MXC_STATUS_NULL_ARGUMENT);
    }

    #[test]
    fn exec_null_out_handle_is_null_argument() {
        let j = CString::new(r#"{"phase":"exec","sandboxId":"x:y"}"#).unwrap();
        // SAFETY: valid string, deliberately-null out_handle.
        let status = unsafe { mxc_state_aware_exec(j.as_ptr(), ptr::null_mut(), ptr::null_mut()) };
        assert_eq!(status, MXC_STATUS_NULL_ARGUMENT);
    }

    #[test]
    fn exec_non_exec_phase_reports_error_and_null_handle() {
        let j = CString::new(r#"{"phase":"provision","containment":"isolation_session"}"#).unwrap();
        let mut handle: *mut MxcSandbox = ptr::null_mut();
        let mut err: *mut c_char = ptr::null_mut();
        // SAFETY: valid string and out pointers.
        let status = unsafe { mxc_state_aware_exec(j.as_ptr(), &mut handle, &mut err) };
        assert_eq!(status, crate::MXC_STATUS_MALFORMED_REQUEST);
        assert!(handle.is_null());
        assert!(!err.is_null());
        // SAFETY: `err` was allocated by `mxc_state_aware_exec`.
        unsafe { crate::mxc_string_free(err) };
    }
}
