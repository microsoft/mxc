// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! C ABI over the MXC public Rust SDK ([`mxc_sdk`]).
//!
//! This is the flat, panic-safe C surface that language bindings (currently the
//! C# SDK) load. It spans three surfaces:
//!
//! - **Run to completion** — [`mxc_run`] builds a request from a `SandboxPolicy`
//!   JSON + a command string, runs the sandbox to completion, and returns the
//!   captured stdout/stderr and exit outcome.
//! - **Streaming** (`streaming` module) — [`mxc_spawn`] returns an opaque live
//!   handle the caller reads/writes/waits/kills via the `mxc_stream_*` /
//!   `mxc_sandbox_*` externs.
//! - **State-aware lifecycle** (`state_aware` module) — [`mxc_state_aware`]
//!   drives the envelope phases (provision / start / stop / deprovision), and
//!   [`mxc_state_aware_exec`] runs the exec phase as a live streaming handle
//!   (reusing the streaming externs).
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

use std::any::Any;
use std::ffi::{c_char, CStr, CString};
use std::io::{self, Write};
use std::panic::catch_unwind;
use std::ptr;
use std::sync::OnceLock;

use mxc_sdk::{build_request, run, ErrorCode, SandboxPolicy, WaitOutcome};

mod state_aware;
mod streaming;
pub use state_aware::*;
pub use streaming::*;

/// Write a diagnostic line to stderr without ever panicking.
///
/// `eprintln!` **panics** if the write fails, and a closed or broken stderr is
/// routine when a host redirects its streams. Every caller here runs either at
/// an `extern "C"` boundary or while unwinding from one, where a panic would
/// abort the process or unwind into foreign frames (undefined behaviour). So
/// the write has to be infallible by construction, not merely unlikely to fail.
fn report_to_stderr(args: std::fmt::Arguments<'_>) {
    let stderr = io::stderr();
    let mut handle = stderr.lock();
    let _ = handle.write_fmt(args);
    let _ = handle.write_all(b"\n");
    let _ = handle.flush();
}

/// Report a panic caught at the FFI boundary.
///
/// A panic here is always a bug in MXC, and `catch_unwind` would otherwise
/// discard the payload entirely — leaving the host with a bare status code and
/// no way to find out what failed. Writing to stderr keeps the diagnosis
/// possible without unwinding into the host's foreign frames, which would be
/// undefined behaviour.
///
/// Deliberately unconditional (not gated behind `MXC_DIAG_CONSOLE`): this path
/// is a should-never-happen bug, not routine diagnostic chatter, and it cannot
/// spam because the operation has already failed.
///
/// Never panics itself: the write goes through [`report_to_stderr`], which
/// discards I/O errors, and the payload downcast falls back to a placeholder.
/// A second panic while already unwinding would abort the embedding process.
fn report_panic(operation: &str, payload: &(dyn Any + Send)) {
    let message = payload
        .downcast_ref::<&str>()
        .copied()
        .or_else(|| payload.downcast_ref::<String>().map(String::as_str))
        .unwrap_or("<non-string panic payload>");
    report_to_stderr(format_args!(
        "mxc: internal error: panic caught at the FFI boundary in {operation}: {message}. \
         Failing closed; the calling process is unaffected."
    ));
}

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
/// Telemetry consent could not be persisted (e.g. non-Windows host, or
/// `%LOCALAPPDATA%` unavailable/unwritable). Never returned by
/// [`mxc_telemetry_get_consent`], which always succeeds.
pub const MXC_STATUS_CONSENT_WRITE_FAILED: i32 = 103;

/// Map an [`ErrorCode`] to its stable FFI status code.
pub(crate) fn status_from_error_code(code: ErrorCode) -> i32 {
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
    /// Structured output metadata JSON (UTF-8, NUL-terminated), or null.
    pub output_metadata_json_utf8: *mut c_char,
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
            output_metadata_json_utf8: ptr::null_mut(),
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
        free_cstr(&mut self.output_metadata_json_utf8);
    }
}

// ---------------------------------------------------------------------------
// String helpers
// ---------------------------------------------------------------------------

/// Allocate a heap C string from bytes, lossily decoding invalid UTF-8 and
/// replacing interior NULs (which a C string can't hold) with U+FFFD. Returns
/// null only if allocation of the `CString` itself somehow fails.
pub(crate) fn alloc_cstring(bytes: &[u8]) -> *mut c_char {
    let lossy = String::from_utf8_lossy(bytes);
    let sanitized = lossy.replace('\0', "\u{fffd}");
    match CString::new(sanitized) {
        Ok(c) => c.into_raw(),
        Err(_) => ptr::null_mut(),
    }
}

/// Free a `CString` previously produced by [`alloc_cstring`] / [`into_raw`],
/// resetting the pointer to null.
pub(crate) fn free_cstr(p: &mut *mut c_char) {
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
pub(crate) unsafe fn cstr_to_str<'a>(p: *const c_char) -> Option<&'a str> {
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
    let result = catch_unwind(|| run_inner(policy_json_utf8, command_utf8)).unwrap_or_else(|p| {
        report_panic("mxc_run", &*p);
        MxcRunResult::error(MXC_STATUS_PANIC, "the mxc engine panicked")
    });

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
            let output_metadata_json_utf8 = match output
                .output_metadata
                .as_ref()
                .map(serde_json::to_vec)
                .transpose()
            {
                Ok(Some(json)) => alloc_cstring(&json),
                Ok(None) => ptr::null_mut(),
                Err(error) => {
                    return MxcRunResult::error(
                        MXC_STATUS_BACKEND_ERROR,
                        format!("failed to serialize sandbox output metadata: {error}"),
                    )
                }
            };
            MxcRunResult {
                status: MXC_STATUS_SUCCESS,
                exit_code,
                timed_out,
                stdout_utf8: alloc_cstring(&output.stdout),
                stderr_utf8: alloc_cstring(&output.stderr),
                error_utf8: ptr::null_mut(),
                output_metadata_json_utf8,
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
    if let Err(p) = catch_unwind(|| {
        // SAFETY: caller guarantees `r` points to a valid, not-yet-freed result.
        unsafe { (*r).free_strings() };
    }) {
        report_panic("mxc_run_result_free", &*p);
    }
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
    if let Err(p) = catch_unwind(|| {
        let mut p = s;
        free_cstr(&mut p);
    }) {
        report_panic("mxc_string_free", &*p);
    }
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

// ---------------------------------------------------------------------------
// Telemetry consent
// ---------------------------------------------------------------------------
//
// See docs/telemetry/telemetry-consent-design.md. MXC only ever collects
// telemetry on Windows, and only when this persisted, MXC-owned consent flag
// is granted — never derived from any Windows-level diagnostics setting.
// `mxc_sdk::telemetry` compiles a non-Windows stub that always
// reports "not-applicable" and rejects writes, so these entry points behave
// identically here across platforms: callers get one C ABI regardless of
// host OS, and the platform gate lives in exactly one place (the Rust
// module), not duplicated at the FFI boundary.

/// Read the persisted telemetry consent state.
///
/// Always succeeds and writes one of `"granted"`, `"denied"`,
/// `"undetermined"`, or `"not-applicable"` (non-Windows hosts) into
/// `*out_utf8` as a heap-allocated, NUL-terminated UTF-8 string. The caller
/// must free it with [`mxc_string_free`].
///
/// Returns [`MXC_STATUS_SUCCESS`] on success, or [`MXC_STATUS_NULL_ARGUMENT`]
/// without touching `*out_utf8` if `out_utf8` is null.
///
/// # Safety
/// `out_utf8` must be null or point to writable `*mut c_char`-sized storage.
#[no_mangle]
pub unsafe extern "C" fn mxc_telemetry_get_consent(out_utf8: *mut *mut c_char) -> i32 {
    let result = catch_unwind(|| mxc_sdk::telemetry::get_consent().as_str());
    let state_str = match result {
        Ok(s) => s,
        Err(p) => {
            report_panic("mxc_telemetry_get_consent", &*p);
            return MXC_STATUS_PANIC;
        }
    };

    if out_utf8.is_null() {
        return MXC_STATUS_NULL_ARGUMENT;
    }
    // SAFETY: `out_utf8` is non-null and caller-guaranteed writable.
    unsafe { ptr::write(out_utf8, alloc_cstring(state_str.as_bytes())) };
    MXC_STATUS_SUCCESS
}

/// Grant or revoke telemetry consent and persist the decision.
///
/// `granted` is `1` to grant, `0` to revoke/deny. `source_utf8` is an
/// optional, free-form provenance string (e.g. `"prompt"`, `"settings-ui"`)
/// recorded for support/debugging only — it is never transmitted anywhere. A
/// null `source_utf8` records `"sdk"`.
///
/// Returns [`MXC_STATUS_SUCCESS`] on success. Returns
/// [`MXC_STATUS_CONSENT_WRITE_FAILED`] if the decision could not be
/// persisted — always the case on non-Windows hosts, since MXC must not
/// collect (and therefore must not offer consent for) telemetry there.
///
/// # Safety
/// `source_utf8` must be null or a valid NUL-terminated UTF-8 C string.
#[no_mangle]
pub unsafe extern "C" fn mxc_telemetry_set_consent(
    granted: i32,
    source_utf8: *const c_char,
) -> i32 {
    // SAFETY: caller contract above.
    let source = match unsafe { cstr_to_str(source_utf8) } {
        Some(s) => s,
        None if source_utf8.is_null() => "sdk",
        None => return MXC_STATUS_INVALID_UTF8,
    };
    let source = source.to_string();
    let granted = granted != 0;

    let result = catch_unwind(|| mxc_sdk::telemetry::set_consent(granted, &source));
    match result {
        Ok(Ok(())) => MXC_STATUS_SUCCESS,
        Ok(Err(e)) => {
            // The status code alone cannot say *why* the write failed (missing
            // profile directory, denied ACL, read-only volume). Without this the
            // reason is lost and a host sees only "consent did not stick".
            // This arm runs *outside* `catch_unwind`, so it must not panic.
            report_to_stderr(format_args!(
                "mxc: failed to persist telemetry consent: {e}"
            ));
            MXC_STATUS_CONSENT_WRITE_FAILED
        }
        Err(p) => {
            report_panic("mxc_telemetry_set_consent", &*p);
            MXC_STATUS_PANIC
        }
    }
}

/// Whether a hosting application should offer its own first-run telemetry
/// consent prompt.
///
/// Writes `1` or `0` into `*out_needs_prompt`. Always `0` on non-Windows
/// hosts, where MXC collects no telemetry and consent is not a meaningful
/// concept.
///
/// This is exported rather than left for each binding to derive from
/// [`mxc_telemetry_get_consent`] so that the prompt policy has exactly one
/// implementation (`ConsentState::needs_prompt`) shared by every language.
///
/// Returns [`MXC_STATUS_SUCCESS`] on success, or [`MXC_STATUS_NULL_ARGUMENT`]
/// without touching `*out_needs_prompt` if it is null.
///
/// # Safety
/// `out_needs_prompt` must be null or point to writable `i32`-sized storage.
#[no_mangle]
pub unsafe extern "C" fn mxc_telemetry_needs_consent_prompt(out_needs_prompt: *mut i32) -> i32 {
    if out_needs_prompt.is_null() {
        return MXC_STATUS_NULL_ARGUMENT;
    }

    let needs_prompt = match catch_unwind(mxc_sdk::telemetry::needs_consent_prompt) {
        Ok(b) => b,
        Err(p) => {
            report_panic("mxc_telemetry_needs_consent_prompt", &*p);
            return MXC_STATUS_PANIC;
        }
    };

    // SAFETY: `out_needs_prompt` is non-null and caller-guaranteed writable.
    unsafe { ptr::write(out_needs_prompt, i32::from(needs_prompt)) };
    MXC_STATUS_SUCCESS
}

/// Read the administrative (MDM / Group Policy) telemetry policy.
///
/// Always succeeds and writes one of `"unrestricted"` (no policy configured),
/// `"allowed"`, `"blocked"`, or `"not-applicable"` (non-Windows hosts) into
/// `*out_utf8` as a heap-allocated, NUL-terminated UTF-8 string. The caller
/// must free it with [`mxc_string_free`].
///
/// The policy is a *ceiling*, never a grant: `"allowed"` does not mean
/// telemetry is on, only that an administrator has not forbidden it. An
/// explicit user consent grant is still required. `"blocked"` means nothing is
/// collected regardless of consent, and a host must not offer a consent
/// prompt — [`mxc_telemetry_needs_consent_prompt`] already reports `0` in that
/// case.
///
/// Exposed so a host can distinguish "the user has not opted in" from "an
/// administrator has disabled this" and explain the difference, rather than
/// rendering a toggle that silently does nothing.
///
/// Returns [`MXC_STATUS_SUCCESS`] on success, or [`MXC_STATUS_NULL_ARGUMENT`]
/// without touching `*out_utf8` if `out_utf8` is null.
///
/// # Safety
/// `out_utf8` must be null or point to writable `*mut c_char`-sized storage.
#[no_mangle]
pub unsafe extern "C" fn mxc_telemetry_get_policy(out_utf8: *mut *mut c_char) -> i32 {
    let result = catch_unwind(|| mxc_sdk::telemetry::get_policy().as_str());
    let state_str = match result {
        Ok(s) => s,
        Err(p) => {
            report_panic("mxc_telemetry_get_policy", &*p);
            return MXC_STATUS_PANIC;
        }
    };

    if out_utf8.is_null() {
        return MXC_STATUS_NULL_ARGUMENT;
    }
    // SAFETY: `out_utf8` is non-null and caller-guaranteed writable.
    unsafe { ptr::write(out_utf8, alloc_cstring(state_str.as_bytes())) };
    MXC_STATUS_SUCCESS
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

    // -----------------------------------------------------------------
    // Telemetry consent
    // -----------------------------------------------------------------
    //
    // These tests drive both process-global telemetry test overrides:
    // `MXC_TEST_LOCALAPPDATA_OVERRIDE` (consent store) and the policy
    // registry redirect. Both are debug-build-only escape hatches that
    // `wxc_common::telemetry` reads instead of trusting the real
    // `LOCALAPPDATA` / `HKLM` locations (see those modules for the security
    // rationale — a release binary compiles both overrides out entirely).
    //
    // Because the overrides do not exist in a release build, the whole
    // section below is `#[cfg(debug_assertions)]`. Without that gate,
    // `cargo test -p mxc_ffi --release` would silently read and *write* the
    // developer's real telemetry consent record: the tests would still pass,
    // having proved nothing and mutated live state.
    //
    // Everything here serializes on `CONSENT_ENV_LOCK`, and `TelemetryTestEnv`
    // additionally takes `POLICY_LOCK` via its `PolicyKeyGuard`, so consent
    // tests are mutually exclusive both with each other and with the policy
    // tests further down. The `mxc_run` tests above touch neither override and
    // may run in parallel with these.
    #[cfg(debug_assertions)]
    static CONSENT_ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    /// Isolates *both* process-global telemetry test overrides for the
    /// lifetime of the guard: `MXC_TEST_LOCALAPPDATA_OVERRIDE` points at a
    /// fresh temp directory, and the administrative policy read is redirected
    /// to a fresh, empty `HKCU` key.
    ///
    /// Both are required even for a consent-only assertion. `needs_prompt` is
    /// `consent AND policy`, so a policy test mutating the shared registry
    /// override concurrently would flip a consent test's expected result;
    /// equally, an ambient policy genuinely configured on the developer's
    /// machine would otherwise leak into these assertions. Owning the
    /// [`PolicyKeyGuard`] here takes `POLICY_LOCK` too, which mutually
    /// excludes the policy tests below.
    ///
    /// The two locks are always taken in this order — consent, then policy —
    /// and this is the only place in the crate that holds both, so the
    /// ordering cannot deadlock.
    #[cfg(debug_assertions)]
    struct TelemetryTestEnv {
        _lock: std::sync::MutexGuard<'static, ()>,
        _policy: wxc_common::telemetry::policy::test_support::PolicyKeyGuard,
        original: Option<std::ffi::OsString>,
        _dir: tempfile_like::TempDir,
    }

    // A tiny, dependency-free stand-in for a temp directory: create a unique
    // subdirectory under `env::temp_dir()` and remove it on drop. Avoids
    // pulling in the `tempfile` crate for two tests.
    #[cfg(debug_assertions)]
    mod tempfile_like {
        use std::path::{Path, PathBuf};

        pub struct TempDir(PathBuf);

        impl TempDir {
            pub fn new(label: &str) -> Self {
                let mut path = std::env::temp_dir();
                path.push(format!(
                    "mxc_ffi_consent_test_{label}_{}_{}",
                    std::process::id(),
                    std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .map(|d| d.as_nanos())
                        .unwrap_or(0)
                ));
                std::fs::create_dir_all(&path).expect("create temp dir");
                Self(path)
            }

            pub fn path(&self) -> &Path {
                &self.0
            }
        }

        impl Drop for TempDir {
            fn drop(&mut self) {
                let _ = std::fs::remove_dir_all(&self.0);
            }
        }
    }

    #[cfg(debug_assertions)]
    impl TelemetryTestEnv {
        fn new(label: &str) -> Self {
            let lock = CONSENT_ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
            let policy = wxc_common::telemetry::policy::test_support::PolicyKeyGuard::new();
            let original = std::env::var_os("MXC_TEST_LOCALAPPDATA_OVERRIDE");
            let dir = tempfile_like::TempDir::new(label);
            std::env::set_var("MXC_TEST_LOCALAPPDATA_OVERRIDE", dir.path());
            Self {
                _lock: lock,
                _policy: policy,
                original,
                _dir: dir,
            }
        }
    }

    #[cfg(debug_assertions)]
    impl Drop for TelemetryTestEnv {
        fn drop(&mut self) {
            match &self.original {
                Some(v) => std::env::set_var("MXC_TEST_LOCALAPPDATA_OVERRIDE", v),
                None => std::env::remove_var("MXC_TEST_LOCALAPPDATA_OVERRIDE"),
            }
        }
    }

    #[cfg(debug_assertions)]
    #[test]
    fn get_consent_reports_string_and_never_errors() {
        let _guard = TelemetryTestEnv::new("get_default");
        let mut out: *mut c_char = ptr::null_mut();
        // SAFETY: `out` is a valid writable pointer to a local variable.
        let status = unsafe { mxc_telemetry_get_consent(&mut out) };
        assert_eq!(status, MXC_STATUS_SUCCESS);
        assert!(!out.is_null());
        // SAFETY: `out` was just allocated by `mxc_telemetry_get_consent`.
        let s = unsafe { CStr::from_ptr(out) }.to_str().unwrap().to_string();
        #[cfg(target_os = "windows")]
        assert_eq!(s, "undetermined");
        #[cfg(not(target_os = "windows"))]
        assert_eq!(s, "not-applicable");
        // SAFETY: `out` was allocated via `alloc_cstring`/`CString::into_raw`.
        unsafe { mxc_string_free(out) };
    }

    #[cfg(debug_assertions)]
    #[test]
    fn get_consent_null_out_reports_null_argument() {
        let _guard = TelemetryTestEnv::new("get_null_out");
        // SAFETY: null out-pointer is explicitly handled.
        let status = unsafe { mxc_telemetry_get_consent(ptr::null_mut()) };
        assert_eq!(status, MXC_STATUS_NULL_ARGUMENT);
    }

    #[cfg(debug_assertions)]
    #[test]
    fn set_then_get_consent_round_trips() {
        let _guard = TelemetryTestEnv::new("round_trip");
        let source = CString::new("prompt").unwrap();
        // SAFETY: `source` is a valid NUL-terminated UTF-8 C string.
        let set_status = unsafe { mxc_telemetry_set_consent(1, source.as_ptr()) };

        let mut out: *mut c_char = ptr::null_mut();
        // SAFETY: `out` is a valid writable pointer to a local variable.
        let get_status = unsafe { mxc_telemetry_get_consent(&mut out) };
        assert_eq!(get_status, MXC_STATUS_SUCCESS);
        // SAFETY: `out` was just allocated by `mxc_telemetry_get_consent`.
        let s = unsafe { CStr::from_ptr(out) }.to_str().unwrap().to_string();
        unsafe { mxc_string_free(out) };

        #[cfg(target_os = "windows")]
        {
            assert_eq!(set_status, MXC_STATUS_SUCCESS);
            assert_eq!(s, "granted");
        }
        #[cfg(not(target_os = "windows"))]
        {
            assert_eq!(set_status, MXC_STATUS_CONSENT_WRITE_FAILED);
            assert_eq!(s, "not-applicable");
        }
    }

    #[cfg(debug_assertions)]
    #[test]
    fn set_consent_null_source_defaults_to_sdk() {
        let _guard = TelemetryTestEnv::new("null_source");
        // SAFETY: null source is explicitly allowed (defaults to "sdk").
        let status = unsafe { mxc_telemetry_set_consent(0, ptr::null()) };
        #[cfg(target_os = "windows")]
        assert_eq!(status, MXC_STATUS_SUCCESS);
        #[cfg(not(target_os = "windows"))]
        assert_eq!(status, MXC_STATUS_CONSENT_WRITE_FAILED);
    }

    #[cfg(debug_assertions)]
    #[test]
    fn needs_consent_prompt_tracks_the_store() {
        let _guard = TelemetryTestEnv::new("needs_prompt");
        let mut needs: i32 = -1;
        // SAFETY: `needs` is a valid writable pointer to a local variable.
        let status = unsafe { mxc_telemetry_needs_consent_prompt(&mut needs) };
        assert_eq!(status, MXC_STATUS_SUCCESS);
        // Fresh store on Windows must prompt; off Windows nothing is collected
        // so nothing may be asked.
        #[cfg(target_os = "windows")]
        assert_eq!(needs, 1);
        #[cfg(not(target_os = "windows"))]
        assert_eq!(needs, 0);

        #[cfg(target_os = "windows")]
        {
            let source = CString::new("prompt").unwrap();
            // SAFETY: `source` is a valid NUL-terminated UTF-8 C string.
            assert_eq!(
                unsafe { mxc_telemetry_set_consent(0, source.as_ptr()) },
                MXC_STATUS_SUCCESS
            );
            // SAFETY: `needs` is a valid writable pointer to a local variable.
            let status = unsafe { mxc_telemetry_needs_consent_prompt(&mut needs) };
            assert_eq!(status, MXC_STATUS_SUCCESS);
            assert_eq!(needs, 0, "a recorded denial must not re-prompt");
        }
    }

    #[cfg(debug_assertions)]
    #[test]
    fn needs_consent_prompt_null_out_reports_null_argument() {
        let _guard = TelemetryTestEnv::new("needs_prompt_null");
        // SAFETY: null out-pointer is explicitly handled.
        let status = unsafe { mxc_telemetry_needs_consent_prompt(ptr::null_mut()) };
        assert_eq!(status, MXC_STATUS_NULL_ARGUMENT);
    }

    /// The policy *semantics* (which registry values map to which state) are
    /// exhaustively tested in `wxc_common::telemetry::policy`. What this layer
    /// owns is that the export marshals the exact corresponding string, and
    /// that the caller can free it.
    #[test]
    fn get_policy_returns_a_valid_state_string() {
        let s = read_policy_string();
        #[cfg(target_os = "windows")]
        assert!(
            ["unrestricted", "allowed", "blocked"].contains(&s.as_str()),
            "unexpected policy state {s:?}"
        );
        #[cfg(not(target_os = "windows"))]
        assert_eq!(s, "not-applicable");
    }

    /// Calls the export and returns the marshalled string, freeing the
    /// allocation. Shared by the policy tests below.
    fn read_policy_string() -> String {
        let mut out: *mut c_char = ptr::null_mut();
        // SAFETY: `out` is a valid writable pointer to a local variable.
        let status = unsafe { mxc_telemetry_get_policy(&mut out) };
        assert_eq!(status, MXC_STATUS_SUCCESS);
        assert!(!out.is_null());
        // SAFETY: `out` was just allocated by `mxc_telemetry_get_policy`.
        let s = unsafe { CStr::from_ptr(out) }.to_str().unwrap().to_string();
        unsafe { mxc_string_free(out) };
        s
    }

    /// Drives every administrative policy state through a redirected registry
    /// key and asserts the exact string this layer marshals for each. Without
    /// this the export could return one hard-coded valid state and still pass.
    ///
    /// Debug-only: `PolicyKeyGuard` redirects the policy read, and that
    /// override is compiled out of a release build by design. Without this
    /// gate the test would read the developer's *real* machine policy and
    /// fail (or, on an unmanaged machine, pass for the wrong reason).
    #[cfg(all(target_os = "windows", debug_assertions))]
    #[test]
    fn get_policy_marshals_the_exact_state_for_each_registry_value() {
        use wxc_common::telemetry::policy::test_support::PolicyKeyGuard;

        let guard = PolicyKeyGuard::new();
        // No value set: an unmanaged machine.
        assert_eq!(read_policy_string(), "unrestricted");

        guard.set_value(3);
        assert_eq!(read_policy_string(), "allowed");

        for blocked in [0u32, 1, 2, 99, u32::MAX] {
            guard.set_value(blocked);
            assert_eq!(
                read_policy_string(),
                "blocked",
                "value {blocked} must marshal as blocked"
            );
        }

        // A wrong-typed value is a policy we cannot evaluate: it must fail
        // closed all the way out through the ABI, not read as unmanaged.
        guard.set_string_value("0");
        assert_eq!(read_policy_string(), "blocked");
    }

    #[test]
    fn get_policy_null_out_reports_null_argument() {
        // SAFETY: null out-pointer is explicitly handled.
        let status = unsafe { mxc_telemetry_get_policy(ptr::null_mut()) };
        assert_eq!(status, MXC_STATUS_NULL_ARGUMENT);
    }
}
