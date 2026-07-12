// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! C ABI over the MXC public Rust SDK ([`mxc_sdk`]).
//!
//! This is the flat, panic-safe C surface that language bindings (currently the
//! C# SDK) load. It intentionally mirrors the SDK's run-to-completion path:
//! [`mxc_run`] builds a request from a `SandboxPolicy` JSON + a command string,
//! runs the sandbox to completion, and returns the captured stdout/stderr and
//! exit outcome.
//!
//! ## Contract
//!
//! - **Strings in** are UTF-8, NUL-terminated (`*const c_char`).
//! - **Strings out** are heap-allocated by this library (`*mut c_char`); the
//!   caller must free every non-null out-string via [`mxc_run_result_free`]
//!   (which frees a whole [`MxcRunResult`]) or [`mxc_string_free`]. The pointer
//!   returned by [`mxc_version`] is static and must **not** be freed.
//! - **Never unwinds**: every entry point wraps its body in
//!   [`std::panic::catch_unwind`]; a panic becomes a status code
//!   ([`MXC_STATUS_PANIC`]), never an unwind across the boundary.
//! - **Data contract**: JSON in, captured bytes + status out. The status codes
//!   mirror `mxc_sdk::ErrorCode` one-for-one (plus a few FFI-local codes).
//!
//! ## ABI stability
//!
//! **This C ABI is not (yet) a stable external contract.** The native library
//! and every binding that loads it (currently the C# SDK) are built and
//! versioned **together** from this repository at the same workspace version,
//! and the C# P/Invoke layer is *generated* from this surface by csbindgen (a
//! CI drift gate keeps the two in lockstep). Because both halves always ship
//! together, this surface is free to evolve — entry points may be added, and
//! the layout of `#[repr(C)]` types such as [`MxcRunResult`] may change —
//! between releases **without** a compatibility shim, so long as the generated
//! binding is regenerated in the same change. Do not treat `mxc_ffi` as a
//! frozen ABI to link third-party consumers against; consume MXC through a
//! versioned binding (the C# SDK) matched to the same release.
//!
//! Planned additions (streaming stdio + process control, and the state-aware
//! lifecycle) will extend this surface with new entry points and types; the
//! [`MXC_STATUS_*`](MXC_STATUS_SUCCESS) space already reserves the codes those
//! paths need, so they will not perturb the existing one.

use std::ffi::{c_char, CStr, CString};
use std::panic::catch_unwind;
use std::ptr;
use std::sync::OnceLock;

use mxc_sdk::{build_request, run, ErrorCode, SandboxPolicy, WaitOutcome};

// ---------------------------------------------------------------------------
// Status codes
// ---------------------------------------------------------------------------

/// Success.
pub const MXC_STATUS_SUCCESS: i32 = 0;
// 1..=12 mirror `mxc_sdk::ErrorCode` (kept in lockstep with a CI drift gate).
/// The request/policy was malformed.
pub const MXC_STATUS_MALFORMED_REQUEST: i32 = 1;
/// The requested containment backend is not supported by this library.
pub const MXC_STATUS_UNSUPPORTED_CONTAINMENT: i32 = 2;
/// The requested state-aware phase is unsupported.
pub const MXC_STATUS_UNSUPPORTED_PHASE: i32 = 3;
/// The backend is unavailable on this host.
pub const MXC_STATUS_BACKEND_UNAVAILABLE: i32 = 4;
/// A sandbox id was malformed.
pub const MXC_STATUS_MALFORMED_ID: i32 = 5;
/// A sandbox id referred to stale state.
pub const MXC_STATUS_STALE_ID: i32 = 6;
/// The sandbox was not provisioned.
pub const MXC_STATUS_NOT_PROVISIONED: i32 = 7;
/// The sandbox was not started.
pub const MXC_STATUS_NOT_STARTED: i32 = 8;
/// The sandbox was already started.
pub const MXC_STATUS_ALREADY_STARTED: i32 = 9;
/// The sandbox was already stopped.
pub const MXC_STATUS_ALREADY_STOPPED: i32 = 10;
/// Policy validation failed.
pub const MXC_STATUS_POLICY_VALIDATION: i32 = 11;
/// A generic backend error.
pub const MXC_STATUS_BACKEND_ERROR: i32 = 12;

// 100+ are FFI-local statuses with no `ErrorCode` equivalent.
/// A required pointer argument was null.
pub const MXC_STATUS_NULL_ARGUMENT: i32 = 100;
/// An input string was not valid UTF-8.
pub const MXC_STATUS_INVALID_UTF8: i32 = 101;
/// The Rust side panicked; the panic was caught at the boundary.
pub const MXC_STATUS_PANIC: i32 = 102;

/// Map an [`ErrorCode`] to its stable FFI status code.
fn status_from_error_code(code: ErrorCode) -> i32 {
    match code {
        ErrorCode::MalformedRequest => MXC_STATUS_MALFORMED_REQUEST,
        ErrorCode::UnsupportedContainment => MXC_STATUS_UNSUPPORTED_CONTAINMENT,
        ErrorCode::UnsupportedPhase => MXC_STATUS_UNSUPPORTED_PHASE,
        ErrorCode::BackendUnavailable => MXC_STATUS_BACKEND_UNAVAILABLE,
        ErrorCode::MalformedId => MXC_STATUS_MALFORMED_ID,
        ErrorCode::StaleId => MXC_STATUS_STALE_ID,
        ErrorCode::NotProvisioned => MXC_STATUS_NOT_PROVISIONED,
        ErrorCode::NotStarted => MXC_STATUS_NOT_STARTED,
        ErrorCode::AlreadyStarted => MXC_STATUS_ALREADY_STARTED,
        ErrorCode::AlreadyStopped => MXC_STATUS_ALREADY_STOPPED,
        ErrorCode::PolicyValidation => MXC_STATUS_POLICY_VALIDATION,
        ErrorCode::BackendError => MXC_STATUS_BACKEND_ERROR,
    }
}

// ---------------------------------------------------------------------------
// Result struct
// ---------------------------------------------------------------------------

/// The result of an [`mxc_run`] call.
///
/// On success (`status == 0`), `exit_code` / `timed_out` describe how the
/// process finished and `stdout_utf8` / `stderr_utf8` carry its captured output
/// (`error_utf8` is null). On failure, `error_utf8` carries a human-readable
/// message and the output fields are null.
///
/// All non-null `*_utf8` pointers are owned by the caller and must be released
/// with [`mxc_run_result_free`].
#[repr(C)]
pub struct MxcRunResult {
    /// `0` on success; otherwise one of the `MXC_STATUS_*` codes.
    pub status: i32,
    /// The process exit code (valid when `status == 0` and `timed_out == 0`).
    pub exit_code: i32,
    /// `1` if the run hit its `scriptTimeout` and was killed, else `0`.
    pub timed_out: i32,
    /// Captured stdout (UTF-8, NUL-terminated), or null.
    pub stdout_utf8: *mut c_char,
    /// Captured stderr (UTF-8, NUL-terminated), or null.
    pub stderr_utf8: *mut c_char,
    /// Error message (UTF-8, NUL-terminated) when `status != 0`, else null.
    pub error_utf8: *mut c_char,
}

impl MxcRunResult {
    fn empty() -> Self {
        Self {
            status: MXC_STATUS_SUCCESS,
            exit_code: 0,
            timed_out: 0,
            stdout_utf8: ptr::null_mut(),
            stderr_utf8: ptr::null_mut(),
            error_utf8: ptr::null_mut(),
        }
    }

    fn error(status: i32, message: impl Into<String>) -> Self {
        Self {
            status,
            error_utf8: alloc_cstring(message.into().as_bytes()),
            ..Self::empty()
        }
    }

    /// Free any owned out-strings, resetting them to null. Idempotent.
    fn free_strings(&mut self) {
        free_cstr(&mut self.stdout_utf8);
        free_cstr(&mut self.stderr_utf8);
        free_cstr(&mut self.error_utf8);
    }
}

// ---------------------------------------------------------------------------
// String helpers
// ---------------------------------------------------------------------------

/// Allocate a heap C string from bytes, lossily decoding invalid UTF-8 and
/// replacing interior NULs (which a C string can't hold) with U+FFFD. Returns
/// null only if allocation of the `CString` itself somehow fails.
fn alloc_cstring(bytes: &[u8]) -> *mut c_char {
    let lossy = String::from_utf8_lossy(bytes);
    let sanitized = lossy.replace('\0', "\u{fffd}");
    match CString::new(sanitized) {
        Ok(c) => c.into_raw(),
        Err(_) => ptr::null_mut(),
    }
}

/// Free a `CString` previously produced by [`alloc_cstring`] / [`into_raw`],
/// resetting the pointer to null.
fn free_cstr(p: &mut *mut c_char) {
    if !p.is_null() {
        // SAFETY: `*p` was produced by `CString::into_raw` in this library, so
        // reconstructing and dropping it frees exactly that allocation.
        unsafe { drop(CString::from_raw(*p)) };
        *p = ptr::null_mut();
    }
}

/// Borrow a `*const c_char` as `&str`, or `None` if null / not UTF-8.
///
/// # Safety
/// `p` must be null or a valid NUL-terminated C string that stays alive for the
/// duration of the borrow.
unsafe fn cstr_to_str<'a>(p: *const c_char) -> Option<&'a str> {
    if p.is_null() {
        return None;
    }
    CStr::from_ptr(p).to_str().ok()
}

// ---------------------------------------------------------------------------
// Entry points
// ---------------------------------------------------------------------------

/// Run a sandbox to completion and capture its output.
///
/// Parses `policy_json_utf8` as a `SandboxPolicy`, sets `command_utf8` as the
/// command to run (the `process.commandLine` equivalent), runs the sandbox to
/// completion, and writes the outcome into `*out`.
///
/// Returns the resulting status code (also stored in `out->status`). Returns
/// [`MXC_STATUS_NULL_ARGUMENT`] without touching `*out` if `out` is null.
///
/// # Safety
/// - `policy_json_utf8` and `command_utf8` must be null or valid NUL-terminated
///   UTF-8 C strings.
/// - `out` must be null or point to writable [`MxcRunResult`]-sized storage.
/// - On success the caller must release `*out` with [`mxc_run_result_free`].
#[no_mangle]
pub unsafe extern "C" fn mxc_run(
    policy_json_utf8: *const c_char,
    command_utf8: *const c_char,
    out: *mut MxcRunResult,
) -> i32 {
    let result = catch_unwind(|| run_inner(policy_json_utf8, command_utf8))
        .unwrap_or_else(|_| MxcRunResult::error(MXC_STATUS_PANIC, "the mxc engine panicked"));

    if out.is_null() {
        // Nowhere to hand ownership; free anything we allocated to avoid a leak.
        let mut orphan = result;
        orphan.free_strings();
        return MXC_STATUS_NULL_ARGUMENT;
    }

    let status = result.status;
    // SAFETY: `out` is non-null and caller-guaranteed writable; ownership of the
    // out-strings transfers to the caller (freed via `mxc_run_result_free`).
    unsafe { ptr::write(out, result) };
    status
}

/// The bulk of [`mxc_run`], split out so the whole thing runs under
/// `catch_unwind`. Never panics deliberately; returns an error result instead.
fn run_inner(policy_json_utf8: *const c_char, command_utf8: *const c_char) -> MxcRunResult {
    // SAFETY: caller contract on `mxc_run`; both are borrowed only within scope.
    let policy_json = match unsafe { cstr_to_str(policy_json_utf8) } {
        Some(s) => s,
        None if policy_json_utf8.is_null() => {
            return MxcRunResult::error(MXC_STATUS_NULL_ARGUMENT, "policy JSON pointer is null")
        }
        None => return MxcRunResult::error(MXC_STATUS_INVALID_UTF8, "policy JSON is not UTF-8"),
    };
    let command = match unsafe { cstr_to_str(command_utf8) } {
        Some(s) => s,
        None if command_utf8.is_null() => {
            return MxcRunResult::error(MXC_STATUS_NULL_ARGUMENT, "command pointer is null")
        }
        None => return MxcRunResult::error(MXC_STATUS_INVALID_UTF8, "command is not UTF-8"),
    };

    let policy: SandboxPolicy = match serde_json::from_str(policy_json) {
        Ok(p) => p,
        Err(e) => {
            return MxcRunResult::error(
                MXC_STATUS_MALFORMED_REQUEST,
                format!("failed to parse policy JSON: {e}"),
            )
        }
    };

    let mut request = match build_request(&policy, None) {
        Ok(r) => r,
        Err(e) => return MxcRunResult::error(status_from_error_code(e.code), e.message),
    };
    request.set_script(command);

    match run(request) {
        Ok(output) => {
            let (exit_code, timed_out) = match output.outcome {
                WaitOutcome::Exited(code) => (code, 0),
                WaitOutcome::TimedOut => (-1, 1),
            };
            MxcRunResult {
                status: MXC_STATUS_SUCCESS,
                exit_code,
                timed_out,
                stdout_utf8: alloc_cstring(&output.stdout),
                stderr_utf8: alloc_cstring(&output.stderr),
                error_utf8: ptr::null_mut(),
            }
        }
        Err(e) => MxcRunResult::error(status_from_error_code(e.code), e.message),
    }
}

/// Free the owned out-strings of an [`MxcRunResult`] produced by [`mxc_run`].
///
/// Safe to call once per result. The result struct itself is caller-owned
/// (typically stack storage); this frees only the heap strings it points to and
/// nulls them.
///
/// # Safety
/// `r` must be null or point to an [`MxcRunResult`] previously filled by
/// [`mxc_run`], not already freed.
#[no_mangle]
pub unsafe extern "C" fn mxc_run_result_free(r: *mut MxcRunResult) {
    if r.is_null() {
        return;
    }
    let _ = catch_unwind(|| {
        // SAFETY: caller guarantees `r` points to a valid, not-yet-freed result.
        unsafe { (*r).free_strings() };
    });
}

/// Free a single heap C string returned by this library.
///
/// # Safety
/// `s` must be null or a string previously returned by this library and not
/// already freed.
#[no_mangle]
pub unsafe extern "C" fn mxc_string_free(s: *mut c_char) {
    if s.is_null() {
        return;
    }
    let _ = catch_unwind(|| {
        let mut p = s;
        free_cstr(&mut p);
    });
}

/// Return the library version as a static, NUL-terminated C string.
///
/// The pointer is valid for the lifetime of the process and must **not** be
/// freed.
#[no_mangle]
pub extern "C" fn mxc_version() -> *const c_char {
    static VERSION: OnceLock<CString> = OnceLock::new();
    VERSION
        .get_or_init(|| CString::new(env!("CARGO_PKG_VERSION")).unwrap_or_default())
        .as_ptr()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn run_with(policy_json: &str, command: Option<&str>) -> MxcRunResult {
        let policy = CString::new(policy_json).unwrap();
        let command = command.map(|c| CString::new(c).unwrap());
        let command_ptr = command.as_ref().map(|c| c.as_ptr()).unwrap_or(ptr::null());
        let mut out = MxcRunResult::empty();
        // SAFETY: valid CStrings and a valid out pointer.
        let status = unsafe { mxc_run(policy.as_ptr(), command_ptr, &mut out) };
        assert_eq!(status, out.status);
        out
    }

    #[test]
    fn malformed_policy_json_reports_malformed_request() {
        let mut out = run_with("{ not json", Some("echo hi"));
        assert_eq!(out.status, MXC_STATUS_MALFORMED_REQUEST);
        assert!(!out.error_utf8.is_null());
        assert!(out.stdout_utf8.is_null());
        // SAFETY: `out` was filled by `mxc_run`.
        unsafe { mxc_run_result_free(&mut out) };
        assert!(out.error_utf8.is_null());
    }

    #[test]
    fn null_command_reports_null_argument() {
        let mut out = run_with(r#"{"version":"0.7.0-alpha"}"#, None);
        assert_eq!(out.status, MXC_STATUS_NULL_ARGUMENT);
        assert!(!out.error_utf8.is_null());
        unsafe { mxc_run_result_free(&mut out) };
    }

    #[test]
    fn null_out_pointer_reports_null_argument_without_leaking() {
        let policy = CString::new(r#"{"version":"0.7.0-alpha"}"#).unwrap();
        let command = CString::new("echo hi").unwrap();
        // SAFETY: valid strings, deliberately-null out pointer.
        let status = unsafe { mxc_run(policy.as_ptr(), command.as_ptr(), ptr::null_mut()) };
        assert_eq!(status, MXC_STATUS_NULL_ARGUMENT);
    }

    #[test]
    fn version_is_non_null_and_matches_crate() {
        let p = mxc_version();
        assert!(!p.is_null());
        // SAFETY: `mxc_version` returns a valid static C string.
        let s = unsafe { CStr::from_ptr(p) }.to_str().unwrap();
        assert_eq!(s, env!("CARGO_PKG_VERSION"));
    }

    #[test]
    fn freeing_null_is_safe() {
        // SAFETY: null is explicitly allowed.
        unsafe {
            mxc_run_result_free(ptr::null_mut());
            mxc_string_free(ptr::null_mut());
        }
    }
}
