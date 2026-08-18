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
    alloc_cstring, cstr_to_str, free_cstr, status_from_error_code, MxcErrorDetail,
    MXC_STATUS_INVALID_UTF8, MXC_STATUS_NULL_ARGUMENT, MXC_STATUS_PANIC, MXC_STATUS_SUCCESS,
};

/// The result of an [`mxc_state_aware`] call.
///
/// On success (`status == 0`), `response_json_utf8` holds the response-envelope
/// JSON (every field of `error` is null). On failure, `error` carries the
/// message and, when an API call was in flight, which call failed and with what
/// platform status; `response_json_utf8` is null. All non-null pointers are
/// owned by the caller and released with [`mxc_state_aware_result_free`].
#[repr(C)]
pub struct MxcStateAwareResult {
    /// `0` on success; otherwise one of the `MXC_STATUS_*` codes.
    pub status: i32,
    /// The response-envelope JSON (UTF-8, NUL-terminated) on success, else null.
    pub response_json_utf8: *mut c_char,
    /// Why the call failed, when `status != 0`; all-null otherwise.
    pub error: MxcErrorDetail,
}

impl MxcStateAwareResult {
    #[cfg(test)]
    fn empty() -> Self {
        Self {
            status: MXC_STATUS_SUCCESS,
            response_json_utf8: ptr::null_mut(),
            error: MxcErrorDetail::none(),
        }
    }

    /// A failure this library raised itself, with no API call behind it.
    fn error(status: i32, message: impl Into<String>) -> Self {
        Self {
            status,
            response_json_utf8: ptr::null_mut(),
            error: MxcErrorDetail::from_message(message),
        }
    }

    /// A failure from the SDK, carrying its API detail across.
    fn from_sdk_error(error: &mxc_sdk::Error) -> Self {
        Self {
            status: status_from_error_code(error.code),
            response_json_utf8: ptr::null_mut(),
            error: MxcErrorDetail::from_error(error),
        }
    }

    fn free_strings(&mut self) {
        free_cstr(&mut self.response_json_utf8);
        self.error.free_strings();
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
/// [`MXC_STATUS_NULL_ARGUMENT`] **without running the phase** if `out` is null:
/// the caller has nowhere to receive a sandbox id, so provisioning one would
/// strand it — nothing else can reclaim a sandbox whose only handle was
/// discarded. [`mxc_state_aware_exec`] checks its out-parameter first for the
/// same reason.
///
/// `experimental` is non-zero to opt in to the experimental backends
/// (WindowsSandbox, IsolationSession, WSLc); with zero they are refused with
/// `backend_unavailable` before any work is done.
///
/// # Safety
/// - `request_json_utf8` must be null or a valid NUL-terminated UTF-8 C string.
/// - `out` must be null or point to writable [`MxcStateAwareResult`]-sized storage.
/// - On success the caller must release `*out` with [`mxc_state_aware_result_free`].
#[no_mangle]
pub unsafe extern "C" fn mxc_state_aware(
    request_json_utf8: *const c_char,
    dry_run: i32,
    experimental: i32,
    out: *mut MxcStateAwareResult,
) -> i32 {
    if out.is_null() {
        return MXC_STATUS_NULL_ARGUMENT;
    }

    let result = catch_unwind(AssertUnwindSafe(|| {
        state_aware_inner(request_json_utf8, dry_run != 0, experimental != 0)
    }))
    .unwrap_or_else(|panic| {
        crate::report_panic("mxc_state_aware", &*panic);
        MxcStateAwareResult::error(MXC_STATUS_PANIC, "the mxc engine panicked")
    });

    let status = result.status;
    // SAFETY: `out` is non-null and caller-guaranteed writable; ownership of the
    // out-strings transfers to the caller (freed via `mxc_state_aware_result_free`).
    unsafe { ptr::write(out, result) };
    status
}

fn state_aware_inner(
    request_json_utf8: *const c_char,
    dry_run: bool,
    experimental: bool,
) -> MxcStateAwareResult {
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

    match run_state_aware_json(request_json, dry_run, experimental) {
        Ok(response_json) => MxcStateAwareResult {
            status: MXC_STATUS_SUCCESS,
            response_json_utf8: alloc_cstring(response_json.as_bytes()),
            error: MxcErrorDetail::none(),
        },
        Err(e) => MxcStateAwareResult::from_sdk_error(&e),
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
    if let Err(panic) = catch_unwind(AssertUnwindSafe(|| {
        // SAFETY: caller guarantees `r` points to a valid, not-yet-freed result.
        unsafe { (*r).free_strings() };
    })) {
        crate::report_panic("mxc_state_aware_result_free", &*panic);
    }
}

/// Run the `exec` phase of a state-aware request as a **live streaming** process.
///
/// Parses `request_json_utf8` (an `exec`-phase request with a `sandboxId`),
/// spawns the process, and on success writes an opaque
/// [`MxcSandbox`](crate::MxcSandbox) handle to `*out_handle` (drive it with the
/// `mxc_stream_*` / `mxc_sandbox_*` externs, free it with `mxc_sandbox_free`).
/// On failure returns the status code and, if `out_error` is non-null, fills it
/// with the message plus the failing API call when there was one (release it
/// with [`mxc_error_detail_free`](crate::mxc_error_detail_free));
/// `*out_handle` is set to null.
///
/// `experimental` opts in to the experimental backends, as for
/// [`mxc_state_aware`].
///
/// # Safety
/// - `request_json_utf8` must be null or a valid NUL-terminated UTF-8 C string.
/// - `out_handle` must be non-null and point to writable pointer-sized storage
///   holding **no live handle** — it is overwritten with null before anything
///   else, and `mxc_sandbox_free` is the handle's only destructor, so free an
///   existing one before reusing its storage. On success the caller owns
///   `*out_handle` and frees it with `mxc_sandbox_free`.
/// - `out_error` must be null, or point to writable storage for one
///   [`MxcErrorDetail`] that holds **no live detail**: either fresh or
///   uninitialised storage, or storage already released with
///   [`mxc_error_detail_free`](crate::mxc_error_detail_free). This function
///   overwrites that storage without freeing what was there, so handing it a
///   populated detail leaks that detail's strings.
#[no_mangle]
pub unsafe extern "C" fn mxc_state_aware_exec(
    request_json_utf8: *const c_char,
    experimental: i32,
    out_handle: *mut *mut MxcSandbox,
    out_error: *mut MxcErrorDetail,
) -> i32 {
    if !out_handle.is_null() {
        // SAFETY: caller-guaranteed writable pointer-sized storage.
        unsafe { *out_handle = ptr::null_mut() };
    }
    if !out_error.is_null() {
        // `write` rather than assignment, for the reason given on `mxc_spawn`:
        // the storage may be uninitialised, and nothing here is dropped.
        // SAFETY: caller-guaranteed writable storage for one detail.
        unsafe { ptr::write(out_error, MxcErrorDetail::none()) };
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
                    MxcErrorDetail::from_message("request JSON pointer is null"),
                ))
            }
            None => {
                return Err((
                    MXC_STATUS_INVALID_UTF8,
                    MxcErrorDetail::from_message("request JSON is not UTF-8"),
                ))
            }
        };
        exec_sandbox(request_json, experimental != 0).map_err(|e| {
            (
                status_from_error_code(e.code),
                MxcErrorDetail::from_error(&e),
            )
        })
    }))
    .unwrap_or_else(|panic| {
        crate::report_panic("mxc_state_aware_exec", &*panic);
        Err((
            MXC_STATUS_PANIC,
            MxcErrorDetail::from_message("the mxc engine panicked"),
        ))
    });

    // SAFETY: `out_handle` non-null (checked), `out_error` null or writable.
    unsafe { crate::streaming::finish_spawn(outcome, out_handle, out_error) }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::CString;

    fn call(json: &str, dry_run: bool) -> MxcStateAwareResult {
        call_opt(json, dry_run, false)
    }

    fn call_opt(json: &str, dry_run: bool, experimental: bool) -> MxcStateAwareResult {
        let j = CString::new(json).unwrap();
        let mut out = MxcStateAwareResult::empty();
        // SAFETY: valid string and out pointer.
        let status =
            unsafe { mxc_state_aware(j.as_ptr(), dry_run as i32, experimental as i32, &mut out) };
        assert_eq!(status, out.status);
        out
    }

    /// The state-aware result carries the same API detail as the
    /// run-to-completion one, and maps the code the same way.
    #[test]
    fn from_sdk_error_carries_the_api_detail() {
        let mut error =
            mxc_sdk::Error::new(crate::ErrorCode::StaleId, "The provision was not found.");
        error.operation = Some("IsoSessionOps.StopSessionAsync".to_string());
        error.native_code = Some("0x80070490".to_string());
        error.remediation = Some("Re-provision the sandbox.".to_string());

        let mut result = MxcStateAwareResult::from_sdk_error(&error);
        assert_eq!(result.status, crate::MXC_STATUS_STALE_ID);
        assert!(result.response_json_utf8.is_null());

        // SAFETY: every pointer was produced by `alloc_cstring` just above.
        unsafe {
            assert_eq!(
                std::ffi::CStr::from_ptr(result.error.operation_utf8)
                    .to_str()
                    .unwrap(),
                "IsoSessionOps.StopSessionAsync"
            );
            assert_eq!(
                std::ffi::CStr::from_ptr(result.error.native_code_utf8)
                    .to_str()
                    .unwrap(),
                "0x80070490"
            );
            assert_eq!(
                std::ffi::CStr::from_ptr(result.error.remediation_utf8)
                    .to_str()
                    .unwrap(),
                "Re-provision the sandbox."
            );
        }

        result.error.free_strings();
    }

    #[test]
    fn one_shot_config_is_malformed_request() {
        let mut out = call(
            r#"{"version":"0.8.0-alpha","process":{"commandLine":"echo hi"}}"#,
            false,
        );
        assert_eq!(out.status, crate::MXC_STATUS_MALFORMED_REQUEST);
        assert!(out.response_json_utf8.is_null());
        assert!(!out.error.message_utf8.is_null());
        // SAFETY: filled by `mxc_state_aware`.
        unsafe { mxc_state_aware_result_free(&mut out) };
        assert!(out.error.message_utf8.is_null());
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
        let status = unsafe { mxc_state_aware(ptr::null(), 0, 0, &mut out) };
        assert_eq!(status, MXC_STATUS_NULL_ARGUMENT);
        assert!(!out.error.message_utf8.is_null());
        // SAFETY: filled by `mxc_state_aware`.
        unsafe { mxc_state_aware_result_free(&mut out) };
    }

    #[test]
    fn null_out_reports_null_argument() {
        let j = CString::new(r#"{"phase":"provision","containment":"isolation_session"}"#).unwrap();
        // SAFETY: valid string, deliberately-null out.
        let status = unsafe { mxc_state_aware(j.as_ptr(), 0, 0, ptr::null_mut()) };
        assert_eq!(status, MXC_STATUS_NULL_ARGUMENT);
    }

    #[test]
    fn exec_null_out_handle_is_null_argument() {
        let j = CString::new(r#"{"phase":"exec","sandboxId":"x:y"}"#).unwrap();
        // SAFETY: valid string, deliberately-null out_handle.
        let status =
            unsafe { mxc_state_aware_exec(j.as_ptr(), 0, ptr::null_mut(), ptr::null_mut()) };
        assert_eq!(status, MXC_STATUS_NULL_ARGUMENT);
    }

    #[test]
    fn exec_non_exec_phase_reports_error_and_null_handle() {
        let j = CString::new(r#"{"phase":"provision","containment":"isolation_session"}"#).unwrap();
        let mut handle: *mut MxcSandbox = ptr::null_mut();
        let mut err = MxcErrorDetail::none();
        // SAFETY: valid string and out pointers.
        let status = unsafe { mxc_state_aware_exec(j.as_ptr(), 0, &mut handle, &mut err) };
        assert_eq!(status, crate::MXC_STATUS_MALFORMED_REQUEST);
        assert!(handle.is_null());
        assert!(!err.message_utf8.is_null());
        // SAFETY: `err` was filled by `mxc_state_aware_exec` and not yet freed.
        unsafe { crate::mxc_error_detail_free(&mut err) };
    }

    /// Without the opt-in the C ABI refuses an experimental backend, and the
    /// refusal crosses as a message with **no** API-call detail — nothing was in
    /// flight when the gate fired.
    #[test]
    fn experimental_backend_is_refused_without_the_optin() {
        let mut out = call_opt(
            r#"{"phase":"provision","containment":"windows_sandbox"}"#,
            true,
            false,
        );
        assert_eq!(out.status, crate::MXC_STATUS_BACKEND_UNAVAILABLE);
        assert!(!out.error.message_utf8.is_null());
        assert!(out.error.operation_utf8.is_null());
        assert!(out.error.native_code_utf8.is_null());
        assert!(out.error.remediation_utf8.is_null());
        // SAFETY: filled by `mxc_state_aware`.
        unsafe { mxc_state_aware_result_free(&mut out) };
    }

    /// Passing the opt-in gets past the gate. Asserting "not
    /// `BACKEND_UNAVAILABLE`" rather than a specific success keeps this
    /// host-independent while still failing if the flag is dropped on the way
    /// down; the dry run keeps it side-effect-free.
    #[test]
    fn the_optin_admits_an_experimental_backend() {
        let mut out = call_opt(
            r#"{"phase":"provision","containment":"windows_sandbox"}"#,
            true,
            true,
        );
        assert_ne!(out.status, crate::MXC_STATUS_BACKEND_UNAVAILABLE);
        // SAFETY: filled by `mxc_state_aware`.
        unsafe { mxc_state_aware_result_free(&mut out) };
    }

    /// The streaming entry point carries the opt-in on its own path, which the
    /// envelope tests above cannot cover: the two reach the same gate by
    /// different routes, so hardcoding the flag in one would leave the other
    /// green. A `wsb:` id lands on `unsupported_phase` once past the gate, which
    /// is distinguishable from the gate's own refusal without a host or a
    /// backend.
    #[test]
    fn exec_honours_the_optin_on_its_own_path() {
        let j = CString::new(
            r#"{"phase":"exec","sandboxId":"wsb:0a1b2c3d","process":{"commandLine":"echo hi"}}"#,
        )
        .unwrap();

        for (experimental, expect_refused) in [(0, true), (1, false)] {
            let mut handle: *mut MxcSandbox = ptr::null_mut();
            let mut err = MxcErrorDetail::none();
            // SAFETY: valid string and out pointers.
            let status =
                unsafe { mxc_state_aware_exec(j.as_ptr(), experimental, &mut handle, &mut err) };
            assert!(handle.is_null(), "no handle is produced either way");
            if expect_refused {
                assert_eq!(status, crate::MXC_STATUS_BACKEND_UNAVAILABLE);
            } else {
                assert_ne!(status, crate::MXC_STATUS_BACKEND_UNAVAILABLE);
            }
            // SAFETY: filled by `mxc_state_aware_exec` and not yet freed.
            unsafe { crate::mxc_error_detail_free(&mut err) };
        }
    }
}
