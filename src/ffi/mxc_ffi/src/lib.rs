// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! C ABI over the MXC public Rust SDK ([`mxc_sdk`]).
//!
//! This is the flat, panic-safe C surface loaded by language bindings.
//!
//! - **Run to completion** — [`mxc_run_request`] accepts the complete binding
//!   request; [`mxc_run`] is the policy + command compatibility entry point.
//! - **Host discovery** — [`mxc_available_backends_json`] reports every
//!   host-available backend, while [`mxc_platform_support_json`] reports the
//!   subset this SDK can launch.
//! - **Streaming** (`streaming` module) — [`mxc_spawn_request`] accepts the
//!   complete binding request and returns an opaque live handle;
//!   [`mxc_spawn`] is the compatibility entry point.
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
//! - **Failures** carry an [`MxcErrorDetail`]: the message, plus the API call
//!   that failed and its platform status when one was in flight. It is embedded
//!   in the result structs (freed with them) and filled through the `out_error`
//!   parameter of the handle-returning entry points (freed with
//!   [`mxc_error_detail_free`]). A null field means the layer below supplied
//!   nothing there — never an empty string.
//! - **Never unwinds**: every entry point wraps its body in
//!   [`std::panic::catch_unwind`]; a panic becomes a status code
//!   ([`MXC_STATUS_PANIC`]), never an unwind across the boundary.
//! - **Data contract**: JSON in, captured bytes + status out. The status codes
//!   mirror `mxc_sdk::ErrorCode` one-for-one (plus a few FFI-local codes).
//! - **Per-invocation telemetry opt-in**: [`mxc_run`] / [`mxc_spawn`] accept
//!   the canonical top-level execution field `telemetry.enabled` inside the
//!   policy JSON they already take.
//! - **Telemetry consent** — [`mxc_telemetry_get_consent`],
//!   [`mxc_telemetry_get_consent_status`], [`mxc_telemetry_request_consent`],
//!   [`mxc_telemetry_withdraw_consent`], [`mxc_telemetry_needs_consent_prompt`],
//!   and [`mxc_telemetry_get_policy`] expose the consent and policy surface to
//!   language bindings.
//!
//! ## ABI stability
//!
//! This C ABI is versioned with the native library and generated bindings. It
//! is not a stable external ABI; regenerate bindings when this surface changes.

use std::any::Any;
use std::ffi::{c_char, c_void, CStr, CString};
use std::io::{self, Write};
use std::panic::catch_unwind;
use std::ptr;
use std::sync::OnceLock;

use mxc_sdk::{
    available_backends, build_request, platform_support, run, ErrorCode, SandboxRequest,
    WaitOutcome,
};

mod error_detail;
mod request;
mod state_aware;
mod streaming;
pub use error_detail::*;
pub use state_aware::*;
pub use streaming::*;

/// Return code from an FFI telemetry-consent presenter callback.
pub const MXC_TELEMETRY_CONSENT_DECISION_NO: i32 = 0;
/// Return code from an FFI telemetry-consent presenter callback.
pub const MXC_TELEMETRY_CONSENT_DECISION_YES: i32 = 1;
/// Return code from an FFI telemetry-consent presenter callback.
pub const MXC_TELEMETRY_CONSENT_DECISION_DISMISSED: i32 = 2;
/// Return code indicating that the host presenter failed.
pub const MXC_TELEMETRY_CONSENT_PRESENTER_ERROR: i32 = -1;

/// Host callback invoked synchronously with the canonical consent prompt JSON.
///
/// The JSON pointer remains valid only for the duration of the callback. The
/// callback must return one of the `MXC_TELEMETRY_CONSENT_DECISION_*` values,
/// or [`MXC_TELEMETRY_CONSENT_PRESENTER_ERROR`] to signal presenter failure.
///
/// # Safety
///
/// **The callback must not unwind across the FFI boundary.** Every callback
/// or trampoline, including one written in Rust, must contain failures
/// internally and return
/// [`MXC_TELEMETRY_CONSENT_PRESENTER_ERROR`] instead of allowing the exception
/// or panic to propagate.
pub type MxcTelemetryConsentPresenter =
    Option<unsafe extern "C" fn(prompt_json_utf8: *const c_char, context: *mut c_void) -> i32>;

/// Write a diagnostic line to stderr without panicking.
fn report_to_stderr(args: std::fmt::Arguments<'_>) {
    let stderr = io::stderr();
    let mut handle = stderr.lock();
    let _ = handle.write_fmt(args);
    let _ = handle.write_all(b"\n");
    let _ = handle.flush();
}

/// Report a panic caught at the FFI boundary.
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

fn report_diagnostic_once(flag: &OnceLock<()>, args: std::fmt::Arguments<'_>) {
    if flag.set(()).is_ok() {
        report_to_stderr(args);
    }
}

fn report_consent_persist_failure_once(flag: &OnceLock<()>, operation: &str) {
    report_diagnostic_once(
        flag,
        format_args!(
            "mxc: {operation} failed because telemetry consent could not be persisted. \
             Returning a fail-closed status without host-specific details."
        ),
    );
}

fn report_request_consent_persist_failure_once() {
    static REQUEST_REPORTED: OnceLock<()> = OnceLock::new();
    report_consent_persist_failure_once(&REQUEST_REPORTED, "mxc_telemetry_request_consent");
}

fn report_withdraw_consent_persist_failure_once() {
    static WITHDRAW_REPORTED: OnceLock<()> = OnceLock::new();
    report_consent_persist_failure_once(&WITHDRAW_REPORTED, "mxc_telemetry_withdraw_consent");
}

fn report_consent_presenter_failure_once() {
    static REPORTED: OnceLock<()> = OnceLock::new();
    report_diagnostic_once(
        &REPORTED,
        format_args!(
            "mxc: telemetry consent presenter failed. Returning MXC_STATUS_BACKEND_ERROR \
             without host-supplied details."
        ),
    );
}

// ---------------------------------------------------------------------------
// Status codes
// ---------------------------------------------------------------------------

/// Success.
pub const MXC_STATUS_SUCCESS: i32 = 0;
// 1..=12 mirror `mxc_sdk::ErrorCode`.
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
/// Telemetry consent could not be persisted (for example `%LOCALAPPDATA%`
/// unavailable/unwritable on Windows). On non-Windows hosts consent actions
/// return a `"notApplicable"` outcome with [`MXC_STATUS_SUCCESS`], not this
/// status.
/// Consent reads do not return this status; an unexpected panic is reported as
/// [`MXC_STATUS_PANIC`].
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

/// The result of an [`mxc_run`] or [`mxc_run_request`] call.
///
/// On success (`status == 0`), `exit_code` / `timed_out` describe how the
/// process finished and `stdout_utf8` / `stderr_utf8` carry its captured output
/// (every field of `error` is null). On failure, `error` carries the message
/// and, when an API call was in flight, which call failed and with what
/// platform status; the output fields are null.
///
/// All non-null pointers — including those inside `error` — are owned by the
/// caller and must be released with [`mxc_run_result_free`].
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
    /// Why the call failed, when `status != 0`; all-null otherwise.
    pub error: MxcErrorDetail,
    /// Structured output metadata JSON (UTF-8, NUL-terminated), or null.
    pub output_metadata_json_utf8: *mut c_char,
    /// Security warnings raised during the run, as a JSON array of strings
    /// (UTF-8, NUL-terminated), or null when the run raised none.
    ///
    /// The sandbox emits these when a policy relaxes containment — notably
    /// `permissiveLearningMode`, which disables deny-by-default. They are not
    /// written to the host's stderr, so this field is the only way an FFI
    /// caller learns that containment was relaxed.
    pub warnings_json_utf8: *mut c_char,
}

impl MxcRunResult {
    fn empty() -> Self {
        Self {
            status: MXC_STATUS_SUCCESS,
            exit_code: 0,
            timed_out: 0,
            stdout_utf8: ptr::null_mut(),
            stderr_utf8: ptr::null_mut(),
            error: MxcErrorDetail::none(),
            output_metadata_json_utf8: ptr::null_mut(),
            warnings_json_utf8: ptr::null_mut(),
        }
    }

    /// A failure this library raised itself, with no API call behind it.
    fn error(status: i32, message: impl Into<String>) -> Self {
        Self {
            status,
            error: MxcErrorDetail::from_message(message),
            ..Self::empty()
        }
    }

    /// A failure from the SDK, carrying its API detail across.
    fn from_sdk_error(error: &mxc_sdk::Error) -> Self {
        Self {
            status: status_from_error_code(error.code),
            error: MxcErrorDetail::from_error(error),
            ..Self::empty()
        }
    }

    fn from_error_detail(status: i32, error: MxcErrorDetail) -> Self {
        Self {
            status,
            error,
            ..Self::empty()
        }
    }

    /// Free any owned out-strings, resetting them to null. Idempotent.
    fn free_strings(&mut self) {
        free_cstr(&mut self.stdout_utf8);
        free_cstr(&mut self.stderr_utf8);
        self.error.free_strings();
        free_cstr(&mut self.output_metadata_json_utf8);
        free_cstr(&mut self.warnings_json_utf8);
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

pub(crate) fn build_run_request(
    policy_json: &str,
    command: &str,
) -> Result<SandboxRequest, (i32, MxcErrorDetail)> {
    build_ffi_request(policy_json, command)
}

pub(crate) fn build_spawn_request(
    policy_json: &str,
    command: &str,
) -> Result<SandboxRequest, (i32, MxcErrorDetail)> {
    build_ffi_request(policy_json, command)
}

fn build_ffi_request(
    policy_json: &str,
    command: &str,
) -> Result<SandboxRequest, (i32, MxcErrorDetail)> {
    let parsed = mxc_sdk::ffi_internals::parse_policy_json(policy_json).map_err(|error| {
        (
            MXC_STATUS_MALFORMED_REQUEST,
            MxcErrorDetail::from_message(error),
        )
    })?;
    let mut request = build_request(&parsed.policy, None).map_err(|error| {
        (
            status_from_error_code(error.code),
            MxcErrorDetail::from_error(&error),
        )
    })?;
    request.set_script(command);
    if let Some(enabled) = parsed.telemetry_enabled {
        request.set_telemetry_enabled(enabled);
    }
    Ok(request)
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
    if out.is_null() {
        return MXC_STATUS_NULL_ARGUMENT;
    }

    let result = catch_unwind(|| run_inner(policy_json_utf8, command_utf8)).unwrap_or_else(|p| {
        report_panic("mxc_run", &*p);
        MxcRunResult::error(MXC_STATUS_PANIC, "the mxc engine panicked")
    });

    let status = result.status;
    // SAFETY: `out` is non-null and caller-guaranteed writable; ownership of the
    // out-strings transfers to the caller (freed via `mxc_run_result_free`).
    unsafe { ptr::write(out, result) };
    status
}

/// Run a complete one-shot request to completion and capture its output.
///
/// `request_json_utf8` describes the policy, command, containment backend,
/// container name, working directory, environment, and experimental opt-in.
/// The managed and native SDKs are co-versioned, so this JSON contract evolves
/// with them rather than becoming an independently stable C ABI.
///
/// # Safety
/// - `request_json_utf8` must be null or valid NUL-terminated UTF-8.
/// - `out` must be null or point to writable [`MxcRunResult`]-sized storage.
/// - On success the caller must release `*out` with [`mxc_run_result_free`].
#[no_mangle]
pub unsafe extern "C" fn mxc_run_request(
    request_json_utf8: *const c_char,
    out: *mut MxcRunResult,
) -> i32 {
    if out.is_null() {
        return MXC_STATUS_NULL_ARGUMENT;
    }

    let result = catch_unwind(|| run_request_inner(request_json_utf8))
        .unwrap_or_else(|_| MxcRunResult::error(MXC_STATUS_PANIC, "the mxc engine panicked"));

    let status = result.status;
    // SAFETY: `out` is non-null and caller-guaranteed writable.
    unsafe { ptr::write(out, result) };
    status
}

fn run_request_inner(request_json_utf8: *const c_char) -> MxcRunResult {
    // SAFETY: caller contract on `mxc_run_request`; borrowed only within scope.
    let request_json = match unsafe { cstr_to_str(request_json_utf8) } {
        Some(value) => value,
        None if request_json_utf8.is_null() => {
            return MxcRunResult::error(MXC_STATUS_NULL_ARGUMENT, "request JSON pointer is null")
        }
        None => return MxcRunResult::error(MXC_STATUS_INVALID_UTF8, "request JSON is not UTF-8"),
    };
    let request = match request::build_request_from_json(request_json) {
        Ok(request) => request,
        Err(error) => return MxcRunResult::from_sdk_error(&error),
    };
    execute_request(request)
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

    let request = match build_run_request(policy_json, command) {
        Ok(request) => request,
        Err((status, error)) => return MxcRunResult::from_error_detail(status, error),
    };

    execute_request(request)
}

fn execute_request(request: SandboxRequest) -> MxcRunResult {
    match run(request) {
        Ok(output) => {
            let (exit_code, timed_out) = match output.outcome {
                WaitOutcome::Exited(code) => (code, 0),
                WaitOutcome::TimedOut => (-1, 1),
            };
            // Serialize both JSON payloads before allocating any C string, so a
            // failure on the second one can't leak the first.
            let output_metadata_json = match output
                .output_metadata
                .as_ref()
                .map(serde_json::to_vec)
                .transpose()
            {
                Ok(json) => json,
                Err(error) => {
                    return MxcRunResult::error(
                        MXC_STATUS_BACKEND_ERROR,
                        format!("failed to serialize sandbox output metadata: {error}"),
                    )
                }
            };
            let warnings_json = if output.warnings.is_empty() {
                None
            } else {
                match serde_json::to_vec(&output.warnings) {
                    Ok(json) => Some(json),
                    Err(error) => {
                        return MxcRunResult::error(
                            MXC_STATUS_BACKEND_ERROR,
                            format!("failed to serialize sandbox warnings: {error}"),
                        )
                    }
                }
            };
            MxcRunResult {
                status: MXC_STATUS_SUCCESS,
                exit_code,
                timed_out,
                stdout_utf8: alloc_cstring(&output.stdout),
                stderr_utf8: alloc_cstring(&output.stderr),
                error: MxcErrorDetail::none(),
                output_metadata_json_utf8: output_metadata_json
                    .map_or(ptr::null_mut(), |json| alloc_cstring(&json)),
                warnings_json_utf8: warnings_json
                    .map_or(ptr::null_mut(), |json| alloc_cstring(&json)),
            }
        }
        Err(e) => MxcRunResult::from_sdk_error(&e),
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

/// Return every containment backend currently available on this host as JSON.
///
/// The result is a JSON array of `AvailableBackend` objects. It includes
/// host-capability backends that the public SDK cannot necessarily launch.
/// The returned string is owned by the caller and must be freed with
/// [`mxc_string_free`]. Returns null if probing panics or serialization fails.
#[no_mangle]
pub extern "C" fn mxc_available_backends_json() -> *mut c_char {
    catch_unwind(|| serialize_owned_json(&available_backends())).unwrap_or(ptr::null_mut())
}

/// Return support for the backends this public SDK can launch as JSON.
///
/// The result is a `PlatformSupport` object. The returned string is owned by
/// the caller and must be freed with [`mxc_string_free`]. Returns null if
/// probing panics or serialization fails.
#[no_mangle]
pub extern "C" fn mxc_platform_support_json() -> *mut c_char {
    catch_unwind(|| serialize_owned_json(&platform_support())).unwrap_or(ptr::null_mut())
}

fn serialize_owned_json(value: &impl serde::Serialize) -> *mut c_char {
    serde_json::to_vec(value)
        .map(|json| alloc_cstring(&json))
        .unwrap_or(ptr::null_mut())
}

/// Return the library version as a static, NUL-terminated C string.
///
/// The pointer is valid for the lifetime of the process and must **not** be
/// freed.
///
/// The body cannot panic today — the version is a compile-time constant and the
/// only fallible step is discharged with `unwrap_or_default` — but it is wrapped
/// anyway so the module's "every entry point" rule holds with no exception for a
/// reader to rediscover. The fallback is an empty **static** string rather than
/// null, so the pointer contract above holds on that path too.
#[no_mangle]
pub extern "C" fn mxc_version() -> *const c_char {
    static VERSION: OnceLock<CString> = OnceLock::new();
    catch_unwind(|| {
        VERSION
            .get_or_init(|| CString::new(env!("CARGO_PKG_VERSION")).unwrap_or_default())
            .as_ptr()
    })
    .unwrap_or(c"".as_ptr())
}

// ---------------------------------------------------------------------------
// Telemetry consent
// ---------------------------------------------------------------------------

/// Read the telemetry consent state currently effective for authorization.
///
/// On success, writes one of `"granted"`, `"denied"`, `"undetermined"`, or
/// `"not-applicable"` (non-Windows hosts) into
/// `*out_utf8` as a heap-allocated, NUL-terminated UTF-8 string. The caller
/// must free it with [`mxc_string_free`]. Call
/// [`mxc_telemetry_get_consent_status`] and read `storedState` when the
/// persisted decision is required.
///
/// After any non-success return with a non-null `out_utf8`, `*out_utf8` is
/// null and must not be freed.
///
/// Returns [`MXC_STATUS_SUCCESS`] on success, or [`MXC_STATUS_NULL_ARGUMENT`]
/// without touching `*out_utf8` if `out_utf8` is null.
///
/// # Safety
/// `out_utf8` must be null or point to writable `*mut c_char`-sized storage.
#[no_mangle]
pub unsafe extern "C" fn mxc_telemetry_get_consent(out_utf8: *mut *mut c_char) -> i32 {
    if out_utf8.is_null() {
        return MXC_STATUS_NULL_ARGUMENT;
    }
    // SAFETY: `out_utf8` is non-null and caller-guaranteed writable. Clear it
    // before any fallible work so every subsequent failure path (including a
    // caught panic) leaves the caller with a well-defined null pointer rather
    // than a stale/uninitialized value.
    unsafe { ptr::write(out_utf8, ptr::null_mut()) };

    let result = catch_unwind(|| mxc_sdk::telemetry::get_consent().as_str());
    let state_str = match result {
        Ok(s) => s,
        Err(p) => {
            report_panic("mxc_telemetry_get_consent", &*p);
            return MXC_STATUS_PANIC;
        }
    };

    // SAFETY: `out_utf8` is non-null and caller-guaranteed writable.
    unsafe { ptr::write(out_utf8, alloc_cstring(state_str.as_bytes())) };
    MXC_STATUS_SUCCESS
}

fn consent_status_json(
    status: mxc_sdk::telemetry::ConsentStatus,
    policy: mxc_sdk::telemetry::PolicyState,
) -> serde_json::Value {
    serde_json::json!({
        "storedState": status.stored_state.as_str(),
        "effectiveState": status.effective_state.as_str(),
        "reason": status.reason.map(|reason| reason.as_str()),
        "policy": policy.as_str(),
    })
}

fn consent_outcome_json(outcome: mxc_sdk::telemetry::ConsentActionOutcome) -> serde_json::Value {
    let mut value = consent_status_json(outcome.status, outcome.policy);
    value["result"] = serde_json::Value::String(outcome.result.as_str().to_string());
    value
}

fn consent_prompt_json(prompt: &mxc_sdk::telemetry::ConsentPrompt) -> serde_json::Value {
    fn message(value: mxc_sdk::telemetry::ConsentMessage) -> serde_json::Value {
        serde_json::json!({ "id": value.id, "text": value.text })
    }

    serde_json::json!({
        "resourceVersion": prompt.resource_version,
        "locale": prompt.locale,
        "title": message(prompt.title),
        "body": message(prompt.body),
        "affirmativeLabel": message(prompt.affirmative_label),
        "negativeLabel": message(prompt.negative_label),
        "learnMoreLabel": message(prompt.learn_more_label),
        "learnMoreUrl": prompt.learn_more_url,
    })
}

unsafe fn write_json_out(value: serde_json::Value, out_utf8: *mut *mut c_char) -> i32 {
    let bytes = match serde_json::to_vec(&value) {
        Ok(bytes) => bytes,
        Err(error) => {
            report_to_stderr(format_args!(
                "mxc: failed to serialize telemetry consent result: {error}"
            ));
            return MXC_STATUS_BACKEND_ERROR;
        }
    };
    // SAFETY: caller guarantees that the non-null out pointer is writable.
    unsafe { ptr::write(out_utf8, alloc_cstring(&bytes)) };
    MXC_STATUS_SUCCESS
}

/// Request telemetry consent through a host presenter callback.
///
/// On success, `*out_utf8` owns a heap-allocated, NUL-terminated JSON string;
/// the caller must free it with [`mxc_string_free`]. After any non-success
/// return with a non-null `out_utf8`, `*out_utf8` is null and must not be
/// freed.
/// On non-Windows hosts this returns a successful `"notApplicable"` outcome
/// without invoking the presenter.
///
/// # Safety
/// `locale_utf8` must be null or valid NUL-terminated UTF-8. `presenter` must
/// be a valid callback when non-null. `context` is passed through untouched.
/// `out_utf8` must point to writable pointer-sized storage.
#[no_mangle]
pub unsafe extern "C" fn mxc_telemetry_request_consent(
    locale_utf8: *const c_char,
    presenter: MxcTelemetryConsentPresenter,
    context: *mut c_void,
    out_utf8: *mut *mut c_char,
) -> i32 {
    if out_utf8.is_null() {
        return MXC_STATUS_NULL_ARGUMENT;
    }
    // Every failure path below (including a caught panic) must leave the
    // out-pointer in a well-defined null state, not the caller's prior value.
    // Do this before any other work.
    // SAFETY: `out_utf8` is non-null and caller-guaranteed writable.
    unsafe { ptr::write(out_utf8, ptr::null_mut()) };
    if presenter.is_none() {
        return MXC_STATUS_NULL_ARGUMENT;
    }
    // SAFETY: caller contract above.
    let locale = match unsafe { cstr_to_str(locale_utf8) } {
        Some(value) => Some(value.to_string()),
        None if locale_utf8.is_null() => None,
        None => return MXC_STATUS_INVALID_UTF8,
    };
    let presenter = presenter.expect("checked above");

    let result = catch_unwind(|| {
        mxc_sdk::telemetry::request_consent(locale.as_deref(), |prompt| {
            let prompt_json = serde_json::to_vec(&consent_prompt_json(prompt))
                .map_err(|error| error.to_string())?;
            let prompt_json = CString::new(prompt_json).map_err(|error| error.to_string())?;
            // SAFETY: the host supplied this callback and context. The prompt
            // pointer remains valid for the duration of this invocation.
            let decision = unsafe { presenter(prompt_json.as_ptr(), context) };
            match decision {
                MXC_TELEMETRY_CONSENT_DECISION_YES => Ok(mxc_sdk::telemetry::ConsentDecision::Yes),
                MXC_TELEMETRY_CONSENT_DECISION_NO => Ok(mxc_sdk::telemetry::ConsentDecision::No),
                MXC_TELEMETRY_CONSENT_DECISION_DISMISSED => {
                    Ok(mxc_sdk::telemetry::ConsentDecision::Dismissed)
                }
                MXC_TELEMETRY_CONSENT_PRESENTER_ERROR => {
                    Err("host consent presenter failed".to_string())
                }
                value => Err(format!(
                    "host consent presenter returned invalid decision {value}"
                )),
            }
        })
    });

    match result {
        Ok(Ok(outcome)) => {
            // SAFETY: validated above.
            unsafe { write_json_out(consent_outcome_json(outcome), out_utf8) }
        }
        Ok(Err(mxc_sdk::telemetry::ConsentError::Persist(error))) => {
            let _ = error;
            report_request_consent_persist_failure_once();
            MXC_STATUS_CONSENT_WRITE_FAILED
        }
        Ok(Err(mxc_sdk::telemetry::ConsentError::Presenter(error))) => {
            let _ = error;
            report_consent_presenter_failure_once();
            MXC_STATUS_BACKEND_ERROR
        }
        Err(panic) => {
            report_panic("mxc_telemetry_request_consent", &*panic);
            MXC_STATUS_PANIC
        }
    }
}

/// Persist an idempotent telemetry-consent withdrawal.
///
/// On non-Windows hosts this returns a `"notApplicable"` JSON outcome with
/// [`MXC_STATUS_SUCCESS`].
///
/// On success, `*out_utf8` owns a heap-allocated, NUL-terminated JSON string;
/// the caller must free it with [`mxc_string_free`]. After any non-success
/// return with a non-null `out_utf8`, `*out_utf8` is null and must not be
/// freed.
///
/// # Safety
/// `out_utf8` must point to writable pointer-sized storage.
#[no_mangle]
pub unsafe extern "C" fn mxc_telemetry_withdraw_consent(out_utf8: *mut *mut c_char) -> i32 {
    if out_utf8.is_null() {
        return MXC_STATUS_NULL_ARGUMENT;
    }
    // Every failure path below (including a caught panic) must leave the
    // out-pointer in a well-defined null state, not the caller's prior value.
    // SAFETY: `out_utf8` is non-null and caller-guaranteed writable.
    unsafe { ptr::write(out_utf8, ptr::null_mut()) };
    match catch_unwind(mxc_sdk::telemetry::withdraw_consent) {
        Ok(Ok(outcome)) => {
            // SAFETY: validated above.
            unsafe { write_json_out(consent_outcome_json(outcome), out_utf8) }
        }
        Ok(Err(error)) => {
            let _ = error;
            report_withdraw_consent_persist_failure_once();
            MXC_STATUS_CONSENT_WRITE_FAILED
        }
        Err(panic) => {
            report_panic("mxc_telemetry_withdraw_consent", &*panic);
            MXC_STATUS_PANIC
        }
    }
}

/// Return the typed persisted/effective consent and policy snapshot as JSON.
///
/// On success, `*out_utf8` owns a heap-allocated, NUL-terminated JSON string;
/// the caller must free it with [`mxc_string_free`]. After any non-success
/// return with a non-null `out_utf8`, `*out_utf8` is null and must not be
/// freed.
///
/// # Safety
/// `out_utf8` must point to writable pointer-sized storage.
#[no_mangle]
pub unsafe extern "C" fn mxc_telemetry_get_consent_status(out_utf8: *mut *mut c_char) -> i32 {
    if out_utf8.is_null() {
        return MXC_STATUS_NULL_ARGUMENT;
    }
    // Every failure path below (including a caught panic) must leave the
    // out-pointer in a well-defined null state, not the caller's prior value.
    // SAFETY: `out_utf8` is non-null and caller-guaranteed writable.
    unsafe { ptr::write(out_utf8, ptr::null_mut()) };
    let result = catch_unwind(|| {
        consent_status_json(
            mxc_sdk::telemetry::get_consent_status(),
            mxc_sdk::telemetry::get_policy(),
        )
    });
    match result {
        Ok(value) => {
            // SAFETY: validated above.
            unsafe { write_json_out(value, out_utf8) }
        }
        Err(panic) => {
            report_panic("mxc_telemetry_get_consent_status", &*panic);
            MXC_STATUS_PANIC
        }
    }
}

/// Whether a hosting application should offer its first-run consent prompt.
///
/// Writes `1` or `0` into `*out_needs_prompt`.
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
    // SAFETY: `out_needs_prompt` is non-null and caller-guaranteed writable.
    // Zero it before any fallible work so a caught panic still leaves the
    // caller with well-defined, non-garbage memory.
    unsafe { ptr::write(out_needs_prompt, 0) };

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
/// On success, writes one of `"unrestricted"` (no policy configured),
/// `"allowed"`, `"blocked"`, or `"not-applicable"` (non-Windows hosts) into
/// `*out_utf8` as a heap-allocated, NUL-terminated UTF-8 string. The caller
/// must free it with [`mxc_string_free`].
///
/// After any non-success return with a non-null `out_utf8`, `*out_utf8` is
/// null and must not be freed.
///
/// `"allowed"` does not grant user consent; `"blocked"` suppresses collection
/// and the consent prompt.
///
/// Returns [`MXC_STATUS_SUCCESS`] on success, or [`MXC_STATUS_NULL_ARGUMENT`]
/// without touching `*out_utf8` if `out_utf8` is null.
///
/// # Safety
/// `out_utf8` must be null or point to writable `*mut c_char`-sized storage.
#[no_mangle]
pub unsafe extern "C" fn mxc_telemetry_get_policy(out_utf8: *mut *mut c_char) -> i32 {
    if out_utf8.is_null() {
        return MXC_STATUS_NULL_ARGUMENT;
    }
    // SAFETY: `out_utf8` is non-null and caller-guaranteed writable. Clear it
    // before any fallible work so a caught panic still leaves the caller with
    // a well-defined null pointer rather than a stale/uninitialized value.
    unsafe { ptr::write(out_utf8, ptr::null_mut()) };

    let result = catch_unwind(|| mxc_sdk::telemetry::get_policy().as_str());
    let state_str = match result {
        Ok(s) => s,
        Err(p) => {
            report_panic("mxc_telemetry_get_policy", &*p);
            return MXC_STATUS_PANIC;
        }
    };

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
    fn build_run_request_propagates_telemetry_enablement() {
        for (policy_json, expected) in [
            (r#"{"version":"0.8.0-alpha"}"#, None),
            (
                r#"{"version":"0.9.0-alpha","telemetry":{"enabled":true}}"#,
                Some(true),
            ),
            (
                r#"{"version":"0.9.0-alpha","telemetry":{"enabled":false}}"#,
                Some(false),
            ),
        ] {
            let request = build_run_request(policy_json, "echo hi")
                .unwrap_or_else(|_| panic!("build_run_request failed for {policy_json}"));
            assert_eq!(
                request.telemetry_enabled(),
                expected,
                "policy: {policy_json}"
            );
        }
    }

    #[test]
    fn malformed_policy_json_reports_malformed_request() {
        let mut out = run_with("{ not json", Some("echo hi"));
        assert_eq!(out.status, MXC_STATUS_MALFORMED_REQUEST);
        assert!(!out.error.message_utf8.is_null());
        assert!(out.stdout_utf8.is_null());
        // SAFETY: `out` was filled by `mxc_run`.
        unsafe { mxc_run_result_free(&mut out) };
        assert!(out.error.message_utf8.is_null());
    }

    #[test]
    fn null_command_reports_null_argument() {
        let mut out = run_with(r#"{"version":"0.7.0-alpha"}"#, None);
        assert_eq!(out.status, MXC_STATUS_NULL_ARGUMENT);
        assert!(!out.error.message_utf8.is_null());
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
    fn available_backends_returns_owned_json_array() {
        let mut p = mxc_available_backends_json();
        assert!(!p.is_null());
        // SAFETY: the discovery entry point returns a valid owned C string.
        let json = unsafe { CStr::from_ptr(p) }.to_str().unwrap();
        let value: serde_json::Value = serde_json::from_str(json).unwrap();
        assert!(value.is_array(), "unexpected discovery JSON: {json}");
        free_cstr(&mut p);
    }

    #[test]
    fn platform_support_returns_owned_camel_case_json() {
        let mut p = mxc_platform_support_json();
        assert!(!p.is_null());
        // SAFETY: the discovery entry point returns a valid owned C string.
        let json = unsafe { CStr::from_ptr(p) }.to_str().unwrap();
        let value: serde_json::Value = serde_json::from_str(json).unwrap();
        assert!(value.get("isSupported").is_some());
        assert!(value.get("availableMethods").is_some());
        assert!(value.get("is_supported").is_none());
        free_cstr(&mut p);
    }

    #[test]
    fn freeing_null_is_safe() {
        // SAFETY: null is explicitly allowed.
        unsafe {
            mxc_run_result_free(ptr::null_mut());
            mxc_string_free(ptr::null_mut());
        }
    }

    /// `alloc_cstring` sanitizes interior NULs before `CString::new`, which is
    /// that call's only failure mode, so it never returns null. Callers rely on
    /// this: a null `message_utf8` means success, so a failure that allocated
    /// null would read as one.
    #[test]
    fn alloc_cstring_never_returns_null() {
        for input in [
            &b""[..],
            b"plain",
            b"interior\0nul",
            b"\0leading",
            b"trailing\0",
            b"\0\0\0",
            &[0xff, 0xfe, 0x00, 0x41][..],
        ] {
            let mut p = alloc_cstring(input);
            assert!(!p.is_null(), "returned null for {input:?}");
            free_cstr(&mut p);
        }
    }

    /// A failure from the SDK reaches the caller with its API detail intact,
    /// and the code maps to the matching `MXC_STATUS_*`.
    #[test]
    fn from_sdk_error_carries_the_api_detail() {
        let mut error =
            mxc_sdk::Error::new(ErrorCode::BackendError, "The provision was not found.");
        error.operation = Some("IsoSessionOps.StopSessionAsync".to_string());
        error.native_code = Some("0x80070490".to_string());
        error.remediation = Some("Re-provision the sandbox.".to_string());

        let mut result = MxcRunResult::from_sdk_error(&error);
        assert_eq!(result.status, MXC_STATUS_BACKEND_ERROR);

        // SAFETY: every pointer was produced by `alloc_cstring` just above.
        unsafe {
            assert_eq!(
                CStr::from_ptr(result.error.message_utf8).to_str().unwrap(),
                "The provision was not found."
            );
            assert_eq!(
                CStr::from_ptr(result.error.operation_utf8)
                    .to_str()
                    .unwrap(),
                "IsoSessionOps.StopSessionAsync"
            );
            assert_eq!(
                CStr::from_ptr(result.error.native_code_utf8)
                    .to_str()
                    .unwrap(),
                "0x80070490"
            );
            assert_eq!(
                CStr::from_ptr(result.error.remediation_utf8)
                    .to_str()
                    .unwrap(),
                "Re-provision the sandbox."
            );
        }

        result.free_strings();
    }

    /// An empty version parses as JSON but fails `build_request`, which is the
    /// arm that carries an SDK error rather than a message this library wrote.
    /// The message is asserted because the JSON-parse arm returns the same
    /// status.
    #[test]
    fn a_failing_build_request_reports_the_sdk_error() {
        let mut out = run_with(r#"{"version":""}"#, Some("echo hi"));
        assert_eq!(out.status, MXC_STATUS_MALFORMED_REQUEST);
        // SAFETY: `out` was filled by `mxc_run`.
        let message = unsafe { CStr::from_ptr(out.error.message_utf8) }
            .to_str()
            .unwrap()
            .to_string();
        assert_eq!(message, "Policy version is required");
        // SAFETY: `out` was filled by `mxc_run`.
        unsafe { mxc_run_result_free(&mut out) };
    }

    // -----------------------------------------------------------------
    // Telemetry consent
    // -----------------------------------------------------------------
    //
    // Telemetry overrides are debug-only, so these tests are excluded from
    // release builds rather than reading the host's real consent and policy
    // state. `CONSENT_ENV_LOCK` and `TelemetryTestEnv`'s policy lock serialize
    // the process-global overrides; unrelated `mxc_run` tests remain parallel.
    #[cfg(debug_assertions)]
    struct TelemetryTestEnv {
        _dir: tempfile::TempDir,
        _env: wxc_common::telemetry::test_support::TelemetryTestEnv,
    }

    #[cfg(debug_assertions)]
    impl TelemetryTestEnv {
        fn new(_label: &str) -> Self {
            let dir = tempfile::tempdir().expect("create temp dir");
            let env = wxc_common::telemetry::test_support::TelemetryTestEnv::new(dir.path());
            Self {
                _dir: dir,
                _env: env,
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
    fn presenter_request_then_get_consent_round_trips() {
        let _guard = TelemetryTestEnv::new("round_trip");
        unsafe extern "C" fn presenter(
            prompt_json_utf8: *const c_char,
            context: *mut c_void,
        ) -> i32 {
            // SAFETY: the FFI request provides valid pointers for this call.
            let prompt = unsafe { CStr::from_ptr(prompt_json_utf8) }
                .to_str()
                .unwrap();
            let prompt: serde_json::Value = serde_json::from_str(prompt).unwrap();
            let canonical = wxc_common::telemetry::consent_prompt::prompt_for_locale(Some("en-US"));
            assert_eq!(prompt["resourceVersion"], canonical.resource_version);
            assert_eq!(prompt["locale"], canonical.locale);
            assert_eq!(prompt["title"]["id"], canonical.title.id);
            assert_eq!(prompt["title"]["text"], canonical.title.text);
            assert_eq!(prompt["body"]["id"], canonical.body.id);
            assert_eq!(prompt["body"]["text"], canonical.body.text);
            assert_eq!(
                prompt["affirmativeLabel"]["text"],
                canonical.affirmative_label.text
            );
            assert_eq!(
                prompt["negativeLabel"]["text"],
                canonical.negative_label.text
            );
            assert_eq!(
                prompt["learnMoreLabel"]["text"],
                canonical.learn_more_label.text
            );
            assert_eq!(prompt["learnMoreUrl"], canonical.learn_more_url);
            // SAFETY: the test passes a pointer to this bool as context.
            unsafe { *(context as *mut bool) = true };
            MXC_TELEMETRY_CONSENT_DECISION_YES
        }

        let mut called = false;
        let mut outcome: *mut c_char = ptr::null_mut();
        // SAFETY: callback, context, and out pointer remain valid for the call.
        let request_status = unsafe {
            mxc_telemetry_request_consent(
                ptr::null(),
                Some(presenter),
                (&mut called as *mut bool).cast(),
                &mut outcome,
            )
        };
        assert_eq!(request_status, MXC_STATUS_SUCCESS);
        assert!(!outcome.is_null());
        // SAFETY: allocated by the request export.
        let outcome_json = unsafe { CStr::from_ptr(outcome) }.to_str().unwrap();
        let outcome_json: serde_json::Value = serde_json::from_str(outcome_json).unwrap();
        unsafe { mxc_string_free(outcome) };

        let mut out: *mut c_char = ptr::null_mut();
        // SAFETY: `out` is a valid writable pointer to a local variable.
        let get_status = unsafe { mxc_telemetry_get_consent(&mut out) };
        assert_eq!(get_status, MXC_STATUS_SUCCESS);
        // SAFETY: `out` was just allocated by `mxc_telemetry_get_consent`.
        let s = unsafe { CStr::from_ptr(out) }.to_str().unwrap().to_string();
        unsafe { mxc_string_free(out) };

        #[cfg(target_os = "windows")]
        {
            assert!(called);
            assert_eq!(outcome_json["result"], "granted");
            assert_eq!(s, "granted");
        }
        #[cfg(not(target_os = "windows"))]
        {
            assert!(!called);
            assert_eq!(outcome_json["result"], "notApplicable");
            assert_eq!(s, "not-applicable");
        }
    }

    #[cfg(debug_assertions)]
    #[test]
    fn request_consent_requires_a_presenter() {
        let _guard = TelemetryTestEnv::new("null_presenter");
        let mut out: *mut c_char = ptr::null_mut();
        // SAFETY: null presenter is explicitly rejected.
        let status =
            unsafe { mxc_telemetry_request_consent(ptr::null(), None, ptr::null_mut(), &mut out) };
        assert_eq!(status, MXC_STATUS_NULL_ARGUMENT);
        assert!(out.is_null());
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
            unsafe extern "C" fn deny(
                _prompt_json_utf8: *const c_char,
                _context: *mut c_void,
            ) -> i32 {
                MXC_TELEMETRY_CONSENT_DECISION_NO
            }
            let mut outcome: *mut c_char = ptr::null_mut();
            // SAFETY: callback and out pointer remain valid for the call.
            assert_eq!(
                unsafe {
                    mxc_telemetry_request_consent(
                        ptr::null(),
                        Some(deny),
                        ptr::null_mut(),
                        &mut outcome,
                    )
                },
                MXC_STATUS_SUCCESS
            );
            // SAFETY: allocated by the request export.
            unsafe { mxc_string_free(outcome) };
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

    #[cfg(debug_assertions)]
    #[test]
    fn withdraw_consent_reports_success_and_is_idempotent() {
        let _guard = TelemetryTestEnv::new("withdraw_idempotent");

        for _ in 0..2 {
            let mut out: *mut c_char = ptr::null_mut();
            // SAFETY: `out` is a valid writable pointer to a local variable.
            let status = unsafe { mxc_telemetry_withdraw_consent(&mut out) };
            assert_eq!(status, MXC_STATUS_SUCCESS);
            assert!(!out.is_null());
            // SAFETY: `out` was just allocated by `mxc_telemetry_withdraw_consent`.
            let outcome_json = unsafe { CStr::from_ptr(out) }.to_str().unwrap();
            let outcome_json: serde_json::Value = serde_json::from_str(outcome_json).unwrap();
            unsafe { mxc_string_free(out) };

            #[cfg(target_os = "windows")]
            {
                assert_eq!(outcome_json["result"], "withdrawn");
                assert_eq!(outcome_json["effectiveState"], "denied");
                assert_eq!(outcome_json["storedState"], "denied");
            }
            #[cfg(not(target_os = "windows"))]
            {
                assert_eq!(outcome_json["result"], "notApplicable");
                assert_eq!(outcome_json["effectiveState"], "not-applicable");
                assert_eq!(outcome_json["storedState"], "not-applicable");
            }
        }
    }

    #[cfg(all(target_os = "windows", debug_assertions))]
    #[test]
    fn withdraw_consent_write_failure_maps_to_status_103_with_null_output() {
        let dir = tempfile::tempdir().unwrap();
        let bogus_localappdata = dir.path().join("localappdata-file");
        std::fs::write(&bogus_localappdata, b"not a directory").unwrap();
        let _guard =
            wxc_common::telemetry::test_support::TelemetryTestEnv::new(&bogus_localappdata);

        let mut out: *mut c_char = ptr::null_mut();
        // SAFETY: `out` is a valid writable pointer to a local variable.
        let status = unsafe { mxc_telemetry_withdraw_consent(&mut out) };
        assert_eq!(status, MXC_STATUS_CONSENT_WRITE_FAILED);
        assert!(out.is_null());
    }

    /// Verifies the export marshals a valid state string that the caller can
    /// free. Policy semantics are tested in `wxc_common::telemetry::policy`.
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
    /// key and asserts the marshaled string. The redirect is debug-only.
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

    // Failure paths must clear caller-owned output pointers before validation
    // or other fallible work.

    /// Return an obvious sentinel `*mut c_char` value that isn't null and
    /// isn't a legal allocation from this library, so an accidental free
    /// would be caught. We only ever *read* the pointer's value; the exports
    /// under test must overwrite it with null before any failure path.
    fn stale_out_sentinel() -> *mut c_char {
        // Use an aligned, obviously-invalid address. Never dereferenced.
        0xDEAD_BEEF_usize as *mut c_char
    }

    #[test]
    fn request_consent_null_presenter_clears_stale_out_pointer() {
        let mut out: *mut c_char = stale_out_sentinel();
        // SAFETY: `out` is a valid writable pointer to a local variable;
        //         null presenter is explicitly rejected.
        let status =
            unsafe { mxc_telemetry_request_consent(ptr::null(), None, ptr::null_mut(), &mut out) };
        assert_eq!(status, MXC_STATUS_NULL_ARGUMENT);
        assert!(
            out.is_null(),
            "failure path must leave *out_utf8 null, not the caller's sentinel"
        );
    }

    #[test]
    fn request_consent_invalid_utf8_locale_clears_stale_out_pointer() {
        // A presenter that would panic if invoked. The invalid-UTF-8 locale
        // must be rejected before we ever reach the presenter, so this
        // proves the failure path both returns the right status *and* null
        // the out-pointer.
        unsafe extern "C" fn never_called_presenter(
            _prompt_json_utf8: *const c_char,
            _context: *mut c_void,
        ) -> i32 {
            panic!("presenter must not be invoked when locale rejection precedes it");
        }

        // A raw non-UTF-8 byte sequence with a valid NUL terminator.
        let bad_locale = [0xffu8, 0xfe, 0xfd, 0x00];
        let mut out: *mut c_char = stale_out_sentinel();
        // SAFETY: `bad_locale` is a NUL-terminated byte string; `out` is a
        //         valid writable pointer to a local variable.
        let status = unsafe {
            mxc_telemetry_request_consent(
                bad_locale.as_ptr() as *const c_char,
                Some(never_called_presenter),
                ptr::null_mut(),
                &mut out,
            )
        };
        assert_eq!(status, MXC_STATUS_INVALID_UTF8);
        assert!(
            out.is_null(),
            "invalid-UTF-8 failure path must leave *out_utf8 null"
        );
    }

    #[test]
    fn withdraw_consent_null_out_reports_null_argument() {
        // SAFETY: null out-pointer is explicitly handled.
        let status = unsafe { mxc_telemetry_withdraw_consent(ptr::null_mut()) };
        assert_eq!(status, MXC_STATUS_NULL_ARGUMENT);
    }

    #[test]
    fn get_consent_status_null_out_reports_null_argument() {
        // SAFETY: null out-pointer is explicitly handled.
        let status = unsafe { mxc_telemetry_get_consent_status(ptr::null_mut()) };
        assert_eq!(status, MXC_STATUS_NULL_ARGUMENT);
    }

    // The read-only exports also overwrite stale output pointers on success.

    #[test]
    fn get_consent_overwrites_stale_out_pointer_on_success() {
        let mut out: *mut c_char = stale_out_sentinel();
        // SAFETY: `out` is a valid writable pointer to a local variable.
        let status = unsafe { mxc_telemetry_get_consent(&mut out) };
        assert_eq!(status, MXC_STATUS_SUCCESS);
        assert!(!out.is_null(), "success path must produce a real string");
        // SAFETY: `out` was just allocated by `mxc_telemetry_get_consent`.
        unsafe { mxc_string_free(out) };
    }

    #[test]
    fn get_policy_overwrites_stale_out_pointer_on_success() {
        let mut out: *mut c_char = stale_out_sentinel();
        // SAFETY: `out` is a valid writable pointer to a local variable.
        let status = unsafe { mxc_telemetry_get_policy(&mut out) };
        assert_eq!(status, MXC_STATUS_SUCCESS);
        assert!(!out.is_null(), "success path must produce a real string");
        // SAFETY: `out` was just allocated by `mxc_telemetry_get_policy`.
        unsafe { mxc_string_free(out) };
    }

    // Use a synthetic store so the snapshot is deterministic on Windows.
    #[cfg(debug_assertions)]
    #[test]
    fn get_consent_status_returns_a_valid_json_snapshot() {
        let _guard = TelemetryTestEnv::new("get_status");
        let mut out: *mut c_char = stale_out_sentinel();
        // SAFETY: `out` is a valid writable pointer to a local variable.
        let status = unsafe { mxc_telemetry_get_consent_status(&mut out) };
        assert_eq!(status, MXC_STATUS_SUCCESS);
        assert!(!out.is_null());
        // SAFETY: `out` was just allocated by `mxc_telemetry_get_consent_status`.
        let json = unsafe { CStr::from_ptr(out) }.to_str().unwrap().to_string();
        let json: serde_json::Value = serde_json::from_str(&json).unwrap();
        // SAFETY: allocated by the export above.
        unsafe { mxc_string_free(out) };

        // The shape is fixed; the values depend on the platform.
        assert!(json.get("storedState").is_some());
        assert!(json.get("effectiveState").is_some());
        assert!(json.get("policy").is_some());
        // `reason` is `Option<..>` and may be JSON null.
        assert!(json.get("reason").is_some());

        #[cfg(target_os = "windows")]
        {
            // A fresh synthetic env has no persisted record.
            assert_eq!(json["storedState"], "undetermined");
            assert_eq!(json["effectiveState"], "undetermined");
            assert_eq!(json["reason"], "no-record");
        }
        #[cfg(not(target_os = "windows"))]
        {
            assert_eq!(json["storedState"], "not-applicable");
            assert_eq!(json["effectiveState"], "not-applicable");
            assert_eq!(json["reason"], "not-applicable");
            assert_eq!(json["policy"], "not-applicable");
        }
    }

    // Presenter failures are mapped to a backend error without persisting.
    #[cfg(all(target_os = "windows", debug_assertions))]
    #[test]
    fn request_consent_presenter_error_maps_to_backend_error() {
        let _guard = TelemetryTestEnv::new("presenter_error");
        unsafe extern "C" fn broken_presenter(
            _prompt_json_utf8: *const c_char,
            _context: *mut c_void,
        ) -> i32 {
            MXC_TELEMETRY_CONSENT_PRESENTER_ERROR
        }

        let mut out: *mut c_char = stale_out_sentinel();
        // SAFETY: callback and out pointer remain valid for the call.
        let status = unsafe {
            mxc_telemetry_request_consent(
                ptr::null(),
                Some(broken_presenter),
                ptr::null_mut(),
                &mut out,
            )
        };
        assert_eq!(status, MXC_STATUS_BACKEND_ERROR);
        assert!(
            out.is_null(),
            "presenter-error failure path must leave *out_utf8 null"
        );
    }

    #[cfg(all(target_os = "windows", debug_assertions))]
    #[test]
    fn request_consent_invalid_decision_maps_to_backend_error() {
        let _guard = TelemetryTestEnv::new("invalid_decision");
        unsafe extern "C" fn bad_decision(
            _prompt_json_utf8: *const c_char,
            _context: *mut c_void,
        ) -> i32 {
            // Neither of the four defined return values.
            42
        }

        let mut out: *mut c_char = stale_out_sentinel();
        // SAFETY: callback and out pointer remain valid for the call.
        let status = unsafe {
            mxc_telemetry_request_consent(
                ptr::null(),
                Some(bad_decision),
                ptr::null_mut(),
                &mut out,
            )
        };
        assert_eq!(status, MXC_STATUS_BACKEND_ERROR);
        assert!(
            out.is_null(),
            "invalid-decision failure path must leave *out_utf8 null"
        );
    }

    /// Verify the withdrawal export returns its typed JSON outcome.
    #[cfg(debug_assertions)]
    #[test]
    fn withdraw_consent_success_returns_typed_outcome() {
        let _guard = TelemetryTestEnv::new("withdraw_success");
        let mut out: *mut c_char = stale_out_sentinel();
        // SAFETY: `out` is a valid writable pointer to a local variable.
        let status = unsafe { mxc_telemetry_withdraw_consent(&mut out) };
        assert_eq!(status, MXC_STATUS_SUCCESS);
        assert!(!out.is_null());
        // SAFETY: `out` was just allocated by `mxc_telemetry_withdraw_consent`.
        let json = unsafe { CStr::from_ptr(out) }.to_str().unwrap().to_string();
        let json: serde_json::Value = serde_json::from_str(&json).unwrap();
        // SAFETY: allocated by the export above.
        unsafe { mxc_string_free(out) };

        #[cfg(target_os = "windows")]
        {
            assert_eq!(json["result"], "withdrawn");
            assert_eq!(json["effectiveState"], "denied");
        }
        #[cfg(not(target_os = "windows"))]
        {
            assert_eq!(json["result"], "notApplicable");
            assert_eq!(json["effectiveState"], "not-applicable");
        }
    }
}
