// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Streaming (handle-based) C ABI over the MXC public Rust SDK.
//!
//! Where [`mxc_run`](crate::mxc_run) runs a sandbox to completion and captures
//! its output, this surface hands the caller a live, opaque handle it can feed
//! stdin, read stdout/stderr from, wait on, and kill while the child runs —
//! mirroring [`mxc_sdk::spawn_sandbox`] / [`mxc_sdk::Sandbox`].
//!
//! ## Handles & ownership
//!
//! - [`mxc_spawn`] returns an opaque `*mut MxcSandbox`. Free it exactly once
//!   with [`mxc_sandbox_free`] (which kills the child tree if still running).
//! - [`mxc_sandbox_take_stdin`] / [`mxc_sandbox_take_stdout`] /
//!   [`mxc_sandbox_take_stderr`] each hand out a **separate** opaque stream
//!   handle (`*mut MxcWriteStream` / `*mut MxcReadStream`) the first time they
//!   are called, and null thereafter. Each stream handle is independently
//!   owned and freed via [`mxc_write_stream_free`] / [`mxc_read_stream_free`].
//!   Because the streams are distinct owned objects, a caller may read stdout
//!   and stderr and write stdin **concurrently on separate threads**.
//!
//! ## Concurrency contract
//!
//! The [`MxcSandbox`] control calls ([`mxc_sandbox_try_wait`],
//! [`mxc_sandbox_wait`], [`mxc_sandbox_kill`], [`mxc_sandbox_id`],
//! [`mxc_sandbox_free`]) borrow the handle mutably and are **not** safe to call
//! concurrently with one another on the same handle. A caller that needs a
//! cancellable wait should poll [`mxc_sandbox_try_wait`] and call
//! [`mxc_sandbox_kill`] from the *same* thread, rather than blocking one thread
//! in [`mxc_sandbox_wait`] and killing from another. The per-stream handles are
//! separate objects and are unaffected by this rule.
//!
//! Each stream handle is likewise single-owner: [`mxc_stream_read`] /
//! [`mxc_stream_write`] / [`mxc_stream_flush`] borrow the stream mutably, so
//! **no two of them may run concurrently on the same stream**, and none may run
//! concurrently with [`mxc_read_stream_free`] / [`mxc_write_stream_free`].
//! Overlapping calls alias a `&mut` — undefined behaviour, not merely interleaved
//! bytes — so a concurrent read-vs-read or write-vs-write is as illegal as a
//! read-vs-free. Drive each stream from a single thread, and free it only once
//! its reads and writes have returned. (The C# binding upholds this by holding a
//! per-handle lock across each native call, which also refcounts the handle via
//! `SafeHandle` so a free can never race an in-flight call.)
//!
//! ## Panics & errors
//!
//! Every entry point is wrapped in [`catch_unwind`]; a panic becomes
//! [`MXC_STATUS_PANIC`] (for `i32`-returning fns) or a null pointer (for
//! handle-returning fns), never an unwind across the boundary. Stream / process
//! I/O failures map to [`MXC_STATUS_BACKEND_ERROR`].

use std::ffi::c_char;
use std::io::{Read, Write};
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::ptr;

use mxc_sdk::{build_request, spawn_sandbox, Sandbox, SandboxPolicy, WaitOutcome};

use crate::{
    alloc_cstring, cstr_to_str, status_from_error_code, MXC_STATUS_BACKEND_ERROR,
    MXC_STATUS_INVALID_UTF8, MXC_STATUS_MALFORMED_REQUEST, MXC_STATUS_NULL_ARGUMENT,
    MXC_STATUS_PANIC, MXC_STATUS_SUCCESS,
};

// ---------------------------------------------------------------------------
// Opaque handles
// ---------------------------------------------------------------------------

/// Opaque live-sandbox handle wrapping an [`mxc_sdk::Sandbox`]. Created by
/// [`mxc_spawn`], destroyed by [`mxc_sandbox_free`].
pub struct MxcSandbox {
    inner: Sandbox,
}

impl MxcSandbox {
    /// Wrap an [`mxc_sdk::Sandbox`] as an opaque FFI handle. Used by both the
    /// one-shot spawn path ([`mxc_spawn`]) and the state-aware streaming exec
    /// path (`mxc_state_aware_exec`).
    pub(crate) fn new(inner: Sandbox) -> Self {
        Self { inner }
    }
}

/// Opaque readable stream (a child's stdout or stderr), handed out by
/// [`mxc_sandbox_take_stdout`] / [`mxc_sandbox_take_stderr`].
pub struct MxcReadStream {
    inner: Box<dyn Read + Send>,
}

/// Opaque writable stream (a child's stdin), handed out by
/// [`mxc_sandbox_take_stdin`]. Freeing it closes stdin, signalling EOF to the
/// child.
pub struct MxcWriteStream {
    inner: Box<dyn Write + Send>,
}

// ---------------------------------------------------------------------------
// Spawn
// ---------------------------------------------------------------------------

/// Spawn a live sandboxed process and return an opaque handle to it.
///
/// Parses `policy_json_utf8` as a `SandboxPolicy`, sets `command_utf8` as the
/// command to run, and spawns the process with piped stdio. On success writes
/// the handle to `*out_handle` and returns [`MXC_STATUS_SUCCESS`]. On failure
/// returns the status code and, if `out_error` is non-null, writes an owned
/// UTF-8 error string to `*out_error` (free it with
/// [`mxc_string_free`](crate::mxc_string_free)); `*out_handle` is set to null.
///
/// # Safety
/// - `policy_json_utf8` / `command_utf8` must be null or valid NUL-terminated
///   UTF-8 C strings.
/// - `out_handle` must be non-null and point to writable pointer-sized storage;
///   on success the caller owns `*out_handle` and must free it with
///   [`mxc_sandbox_free`].
/// - `out_error` must be null or point to writable pointer-sized storage.
#[no_mangle]
pub unsafe extern "C" fn mxc_spawn(
    policy_json_utf8: *const c_char,
    command_utf8: *const c_char,
    out_handle: *mut *mut MxcSandbox,
    out_error: *mut *mut c_char,
) -> i32 {
    // Initialise out-params defensively so a partial/failed call never leaves
    // stale pointers behind.
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
        spawn_inner(policy_json_utf8, command_utf8)
    }))
    .unwrap_or(Err((
        MXC_STATUS_PANIC,
        "the mxc engine panicked".to_string(),
    )));

    // SAFETY: `out_handle` non-null (checked), `out_error` null or writable.
    unsafe { finish_spawn(outcome, out_handle, out_error) }
}

/// Shared tail of the handle-returning spawn entry points ([`mxc_spawn`] and
/// `mxc_state_aware_exec`): on success box the [`Sandbox`] into an
/// [`MxcSandbox`] handle and write it to `*out_handle`; on failure write the
/// message to `*out_error` (when non-null) and return the status.
///
/// # Safety
/// `out_handle` must be non-null and writable; `out_error` must be null or
/// writable. Both are pointer-sized.
pub(crate) unsafe fn finish_spawn(
    outcome: Result<Sandbox, (i32, String)>,
    out_handle: *mut *mut MxcSandbox,
    out_error: *mut *mut c_char,
) -> i32 {
    match outcome {
        Ok(sandbox) => {
            let boxed = Box::new(MxcSandbox::new(sandbox));
            // SAFETY: `out_handle` non-null and writable per the caller contract.
            unsafe { *out_handle = Box::into_raw(boxed) };
            MXC_STATUS_SUCCESS
        }
        Err((status, message)) => {
            if !out_error.is_null() {
                // SAFETY: `out_error` non-null and writable per the caller contract.
                unsafe { *out_error = alloc_cstring(message.as_bytes()) };
            }
            status
        }
    }
}

/// The fallible core of [`mxc_spawn`], run under `catch_unwind`.
fn spawn_inner(
    policy_json_utf8: *const c_char,
    command_utf8: *const c_char,
) -> Result<Sandbox, (i32, String)> {
    // SAFETY: caller contract on `mxc_spawn`; borrowed only within scope.
    let policy_json = match unsafe { cstr_to_str(policy_json_utf8) } {
        Some(s) => s,
        None if policy_json_utf8.is_null() => {
            return Err((
                MXC_STATUS_NULL_ARGUMENT,
                "policy JSON pointer is null".into(),
            ))
        }
        None => return Err((MXC_STATUS_INVALID_UTF8, "policy JSON is not UTF-8".into())),
    };
    let command = match unsafe { cstr_to_str(command_utf8) } {
        Some(s) => s,
        None if command_utf8.is_null() => {
            return Err((MXC_STATUS_NULL_ARGUMENT, "command pointer is null".into()))
        }
        None => return Err((MXC_STATUS_INVALID_UTF8, "command is not UTF-8".into())),
    };

    let policy: SandboxPolicy = serde_json::from_str(policy_json).map_err(|e| {
        (
            MXC_STATUS_MALFORMED_REQUEST,
            format!("failed to parse policy JSON: {e}"),
        )
    })?;

    let mut request =
        build_request(&policy, None).map_err(|e| (status_from_error_code(e.code), e.message))?;
    request.set_script(command);

    spawn_sandbox(request).map_err(|e| (status_from_error_code(e.code), e.message))
}

// ---------------------------------------------------------------------------
// Stream accessors
// ---------------------------------------------------------------------------

/// Take the child's stdin stream. Returns null if `handle` is null, stdin was
/// not piped, or stdin was already taken. The returned handle must be freed
/// with [`mxc_write_stream_free`] (which closes stdin, sending EOF).
///
/// # Safety
/// `handle` must be null or a live handle from [`mxc_spawn`].
#[no_mangle]
pub unsafe extern "C" fn mxc_sandbox_take_stdin(handle: *mut MxcSandbox) -> *mut MxcWriteStream {
    take_stream(handle, |s| {
        s.inner.take_stdin().map(|inner| MxcWriteStream { inner })
    })
}

/// Take the child's stdout stream. Returns null if `handle` is null, stdout was
/// not piped, or stdout was already taken. Free with [`mxc_read_stream_free`].
///
/// # Safety
/// `handle` must be null or a live handle from [`mxc_spawn`].
#[no_mangle]
pub unsafe extern "C" fn mxc_sandbox_take_stdout(handle: *mut MxcSandbox) -> *mut MxcReadStream {
    take_read_stream(handle, |s| s.inner.take_stdout())
}

/// Take the child's stderr stream. Returns null if `handle` is null, stderr was
/// not piped, or stderr was already taken. Free with [`mxc_read_stream_free`].
///
/// # Safety
/// `handle` must be null or a live handle from [`mxc_spawn`].
#[no_mangle]
pub unsafe extern "C" fn mxc_sandbox_take_stderr(handle: *mut MxcSandbox) -> *mut MxcReadStream {
    take_read_stream(handle, |s| s.inner.take_stderr())
}

fn take_stream(
    handle: *mut MxcSandbox,
    take: impl FnOnce(&mut MxcSandbox) -> Option<MxcWriteStream>,
) -> *mut MxcWriteStream {
    if handle.is_null() {
        return ptr::null_mut();
    }
    let result = catch_unwind(AssertUnwindSafe(|| {
        // SAFETY: non-null live handle per the caller contract; borrowed only
        // for the duration of this call.
        let sandbox = unsafe { &mut *handle };
        take(sandbox).map(|s| Box::into_raw(Box::new(s)))
    }));
    result.unwrap_or(None).unwrap_or(ptr::null_mut())
}

fn take_read_stream(
    handle: *mut MxcSandbox,
    take: impl FnOnce(&mut MxcSandbox) -> Option<Box<dyn Read + Send>>,
) -> *mut MxcReadStream {
    if handle.is_null() {
        return ptr::null_mut();
    }
    let result = catch_unwind(AssertUnwindSafe(|| {
        // SAFETY: non-null live handle per the caller contract.
        let sandbox = unsafe { &mut *handle };
        take(sandbox).map(|inner| Box::into_raw(Box::new(MxcReadStream { inner })))
    }));
    result.unwrap_or(None).unwrap_or(ptr::null_mut())
}

// ---------------------------------------------------------------------------
// Stream I/O
// ---------------------------------------------------------------------------

/// Read up to `cap` bytes from `stream` into `buf`, writing the number of bytes
/// read to `*out_read`. A read of `0` bytes signals end-of-stream (EOF). Blocks
/// until at least one byte is available, EOF, or an error.
///
/// Returns [`MXC_STATUS_SUCCESS`], [`MXC_STATUS_NULL_ARGUMENT`] if any pointer
/// is null, or [`MXC_STATUS_BACKEND_ERROR`] on an I/O error.
///
/// # Safety
/// - `stream` must be null or a live handle from a `take_std*` call.
/// - `buf` must be null or point to at least `cap` writable bytes.
/// - `out_read` must be null or point to writable `usize` storage.
#[no_mangle]
pub unsafe extern "C" fn mxc_stream_read(
    stream: *mut MxcReadStream,
    buf: *mut u8,
    cap: usize,
    out_read: *mut usize,
) -> i32 {
    if stream.is_null() || buf.is_null() || out_read.is_null() {
        return MXC_STATUS_NULL_ARGUMENT;
    }
    let status = catch_unwind(AssertUnwindSafe(|| {
        // SAFETY: `stream` non-null live handle; `buf`/`cap` describe a valid
        // writable region per the caller contract.
        let s = unsafe { &mut *stream };
        let slice = unsafe { std::slice::from_raw_parts_mut(buf, cap) };
        match s.inner.read(slice) {
            Ok(n) => {
                // SAFETY: `out_read` non-null writable per the caller contract.
                unsafe { *out_read = n };
                MXC_STATUS_SUCCESS
            }
            Err(_) => MXC_STATUS_BACKEND_ERROR,
        }
    }));
    status.unwrap_or(MXC_STATUS_PANIC)
}

/// Write up to `len` bytes from `buf` to `stream`, writing the number of bytes
/// actually written to `*out_written`. May write fewer than `len` bytes.
///
/// Returns [`MXC_STATUS_SUCCESS`], [`MXC_STATUS_NULL_ARGUMENT`] if any pointer
/// is null, or [`MXC_STATUS_BACKEND_ERROR`] on an I/O error.
///
/// # Safety
/// - `stream` must be null or a live handle from [`mxc_sandbox_take_stdin`].
/// - `buf` must be null or point to at least `len` readable bytes.
/// - `out_written` must be null or point to writable `usize` storage.
#[no_mangle]
pub unsafe extern "C" fn mxc_stream_write(
    stream: *mut MxcWriteStream,
    buf: *const u8,
    len: usize,
    out_written: *mut usize,
) -> i32 {
    if stream.is_null() || buf.is_null() || out_written.is_null() {
        return MXC_STATUS_NULL_ARGUMENT;
    }
    let status = catch_unwind(AssertUnwindSafe(|| {
        // SAFETY: `stream` non-null live handle; `buf`/`len` describe a valid
        // readable region per the caller contract.
        let s = unsafe { &mut *stream };
        let slice = unsafe { std::slice::from_raw_parts(buf, len) };
        match s.inner.write(slice) {
            Ok(n) => {
                // SAFETY: `out_written` non-null writable per the caller contract.
                unsafe { *out_written = n };
                MXC_STATUS_SUCCESS
            }
            Err(_) => MXC_STATUS_BACKEND_ERROR,
        }
    }));
    status.unwrap_or(MXC_STATUS_PANIC)
}

/// Flush any buffered bytes on a stdin stream.
///
/// # Safety
/// `stream` must be null or a live handle from [`mxc_sandbox_take_stdin`].
#[no_mangle]
pub unsafe extern "C" fn mxc_stream_flush(stream: *mut MxcWriteStream) -> i32 {
    if stream.is_null() {
        return MXC_STATUS_NULL_ARGUMENT;
    }
    let status = catch_unwind(AssertUnwindSafe(|| {
        // SAFETY: `stream` non-null live handle per the caller contract.
        let s = unsafe { &mut *stream };
        match s.inner.flush() {
            Ok(()) => MXC_STATUS_SUCCESS,
            Err(_) => MXC_STATUS_BACKEND_ERROR,
        }
    }));
    status.unwrap_or(MXC_STATUS_PANIC)
}

// ---------------------------------------------------------------------------
// Process control
// ---------------------------------------------------------------------------

/// Return the child's OS process id, or `0` if `handle` is null.
///
/// # Safety
/// `handle` must be null or a live handle from [`mxc_spawn`].
#[no_mangle]
pub unsafe extern "C" fn mxc_sandbox_id(handle: *mut MxcSandbox) -> u32 {
    if handle.is_null() {
        return 0;
    }
    catch_unwind(AssertUnwindSafe(|| {
        // SAFETY: non-null live handle per the caller contract.
        let sandbox = unsafe { &*handle };
        sandbox.inner.id()
    }))
    .unwrap_or(0)
}

/// Non-blocking exit check. On return, `*out_running` is `1` if the child is
/// still running (and `*out_exit` is untouched) or `0` if it has exited (and
/// `*out_exit` holds its exit code).
///
/// Returns [`MXC_STATUS_SUCCESS`], [`MXC_STATUS_NULL_ARGUMENT`] if any pointer
/// is null, or [`MXC_STATUS_BACKEND_ERROR`] on a wait error.
///
/// # Safety
/// - `handle` must be null or a live handle from [`mxc_spawn`].
/// - `out_exit` / `out_running` must be null or point to writable `i32` storage.
#[no_mangle]
pub unsafe extern "C" fn mxc_sandbox_try_wait(
    handle: *mut MxcSandbox,
    out_exit: *mut i32,
    out_running: *mut i32,
) -> i32 {
    if handle.is_null() || out_exit.is_null() || out_running.is_null() {
        return MXC_STATUS_NULL_ARGUMENT;
    }
    let status = catch_unwind(AssertUnwindSafe(|| {
        // SAFETY: non-null live handle per the caller contract.
        let sandbox = unsafe { &mut *handle };
        match sandbox.inner.try_wait() {
            Ok(Some(code)) => {
                // SAFETY: out-params non-null writable per the caller contract.
                unsafe {
                    *out_exit = code;
                    *out_running = 0;
                }
                MXC_STATUS_SUCCESS
            }
            Ok(None) => {
                // SAFETY: out-params non-null writable per the caller contract.
                unsafe { *out_running = 1 };
                MXC_STATUS_SUCCESS
            }
            Err(_) => MXC_STATUS_BACKEND_ERROR,
        }
    }));
    status.unwrap_or(MXC_STATUS_PANIC)
}

/// Block until the child exits (honouring the request's `scriptTimeout`),
/// draining any untaken stdout/stderr so it cannot block on a full pipe. On a
/// normal exit `*out_exit` holds the exit code and `*out_timed_out` is `0`; on
/// timeout `*out_timed_out` is `1` and `*out_exit` is set to `-1`.
///
/// Must not be called concurrently with [`mxc_sandbox_kill`] on the same handle
/// (see the module concurrency contract).
///
/// # Safety
/// - `handle` must be null or a live handle from [`mxc_spawn`].
/// - `out_exit` / `out_timed_out` must be null or writable `i32` storage.
#[no_mangle]
pub unsafe extern "C" fn mxc_sandbox_wait(
    handle: *mut MxcSandbox,
    out_exit: *mut i32,
    out_timed_out: *mut i32,
) -> i32 {
    if handle.is_null() || out_exit.is_null() || out_timed_out.is_null() {
        return MXC_STATUS_NULL_ARGUMENT;
    }
    let status = catch_unwind(AssertUnwindSafe(|| {
        // SAFETY: non-null live handle per the caller contract.
        let sandbox = unsafe { &mut *handle };
        match sandbox.inner.wait() {
            Ok(WaitOutcome::Exited(code)) => {
                // SAFETY: out-params non-null writable per the caller contract.
                unsafe {
                    *out_exit = code;
                    *out_timed_out = 0;
                }
                MXC_STATUS_SUCCESS
            }
            Ok(WaitOutcome::TimedOut) => {
                // SAFETY: out-params non-null writable per the caller contract.
                unsafe {
                    *out_exit = -1;
                    *out_timed_out = 1;
                }
                MXC_STATUS_SUCCESS
            }
            Err(_) => MXC_STATUS_BACKEND_ERROR,
        }
    }));
    status.unwrap_or(MXC_STATUS_PANIC)
}

/// Kill the child and its whole process tree. Reaping happens in a subsequent
/// [`mxc_sandbox_wait`] / [`mxc_sandbox_try_wait`] or in [`mxc_sandbox_free`].
///
/// # Safety
/// `handle` must be null or a live handle from [`mxc_spawn`].
#[no_mangle]
pub unsafe extern "C" fn mxc_sandbox_kill(handle: *mut MxcSandbox) -> i32 {
    if handle.is_null() {
        return MXC_STATUS_NULL_ARGUMENT;
    }
    let status = catch_unwind(AssertUnwindSafe(|| {
        // SAFETY: non-null live handle per the caller contract.
        let sandbox = unsafe { &mut *handle };
        match sandbox.inner.kill() {
            Ok(()) => MXC_STATUS_SUCCESS,
            Err(_) => MXC_STATUS_BACKEND_ERROR,
        }
    }));
    status.unwrap_or(MXC_STATUS_PANIC)
}

// ---------------------------------------------------------------------------
// Handle destructors
// ---------------------------------------------------------------------------

/// Free a sandbox handle from [`mxc_spawn`], killing the child tree if it is
/// still running. Safe to call with null (no-op). Must be called exactly once
/// per handle.
///
/// # Safety
/// `handle` must be null or a live, not-yet-freed handle from [`mxc_spawn`].
#[no_mangle]
pub unsafe extern "C" fn mxc_sandbox_free(handle: *mut MxcSandbox) {
    if handle.is_null() {
        return;
    }
    let _ = catch_unwind(AssertUnwindSafe(|| {
        // SAFETY: non-null handle produced by `Box::into_raw` in `mxc_spawn`,
        // not yet freed; reconstructing the Box drops it (and its child).
        drop(unsafe { Box::from_raw(handle) });
    }));
}

/// Free a readable stream handle. Safe to call with null (no-op). Must be
/// called exactly once per handle.
///
/// # Safety
/// `stream` must be null or a live, not-yet-freed handle from a
/// `mxc_sandbox_take_stdout` / `mxc_sandbox_take_stderr` call.
#[no_mangle]
pub unsafe extern "C" fn mxc_read_stream_free(stream: *mut MxcReadStream) {
    if stream.is_null() {
        return;
    }
    let _ = catch_unwind(AssertUnwindSafe(|| {
        // SAFETY: non-null handle produced by `Box::into_raw`, not yet freed.
        drop(unsafe { Box::from_raw(stream) });
    }));
}

/// Free a writable (stdin) stream handle, closing stdin and sending EOF to the
/// child. Safe to call with null (no-op). Must be called exactly once.
///
/// # Safety
/// `stream` must be null or a live, not-yet-freed handle from
/// [`mxc_sandbox_take_stdin`].
#[no_mangle]
pub unsafe extern "C" fn mxc_write_stream_free(stream: *mut MxcWriteStream) {
    if stream.is_null() {
        return;
    }
    let _ = catch_unwind(AssertUnwindSafe(|| {
        // SAFETY: non-null handle produced by `Box::into_raw`, not yet freed.
        drop(unsafe { Box::from_raw(stream) });
    }));
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::CString;

    #[test]
    fn spawn_null_out_handle_is_null_argument() {
        let policy = CString::new(r#"{"version":"0.7.0-alpha"}"#).unwrap();
        let command = CString::new("echo hi").unwrap();
        // SAFETY: valid strings, deliberately-null out_handle.
        let status = unsafe {
            mxc_spawn(
                policy.as_ptr(),
                command.as_ptr(),
                ptr::null_mut(),
                ptr::null_mut(),
            )
        };
        assert_eq!(status, MXC_STATUS_NULL_ARGUMENT);
    }

    #[test]
    fn spawn_null_policy_reports_null_argument() {
        let command = CString::new("echo hi").unwrap();
        let mut handle: *mut MxcSandbox = ptr::null_mut();
        let mut err: *mut c_char = ptr::null_mut();
        // SAFETY: null policy pointer is explicitly handled.
        let status = unsafe { mxc_spawn(ptr::null(), command.as_ptr(), &mut handle, &mut err) };
        assert_eq!(status, MXC_STATUS_NULL_ARGUMENT);
        assert!(handle.is_null());
        assert!(!err.is_null(), "an error message should be provided");
        // SAFETY: `err` was allocated by `mxc_spawn`.
        unsafe { crate::mxc_string_free(err) };
    }

    #[test]
    fn spawn_malformed_policy_reports_malformed_request() {
        let policy = CString::new("{ not json").unwrap();
        let command = CString::new("echo hi").unwrap();
        let mut handle: *mut MxcSandbox = ptr::null_mut();
        let mut err: *mut c_char = ptr::null_mut();
        // SAFETY: valid strings and valid out pointers.
        let status = unsafe { mxc_spawn(policy.as_ptr(), command.as_ptr(), &mut handle, &mut err) };
        assert_eq!(status, MXC_STATUS_MALFORMED_REQUEST);
        assert!(handle.is_null());
        assert!(!err.is_null());
        // SAFETY: `err` was allocated by `mxc_spawn`.
        unsafe { crate::mxc_string_free(err) };
    }

    #[test]
    fn spawn_null_error_out_is_tolerated() {
        let policy = CString::new("{ not json").unwrap();
        let command = CString::new("echo hi").unwrap();
        let mut handle: *mut MxcSandbox = ptr::null_mut();
        // SAFETY: valid strings; null out_error must be tolerated.
        let status = unsafe {
            mxc_spawn(
                policy.as_ptr(),
                command.as_ptr(),
                &mut handle,
                ptr::null_mut(),
            )
        };
        assert_eq!(status, MXC_STATUS_MALFORMED_REQUEST);
        assert!(handle.is_null());
    }

    #[test]
    fn null_stream_and_control_ops_report_null_argument() {
        let mut n: usize = 0;
        let mut i: i32 = 0;
        let mut j: i32 = 0;
        // SAFETY: every argument is null / benign; each fn must reject cleanly.
        unsafe {
            assert_eq!(
                mxc_stream_read(ptr::null_mut(), ptr::null_mut(), 0, &mut n),
                MXC_STATUS_NULL_ARGUMENT
            );
            assert_eq!(
                mxc_stream_write(ptr::null_mut(), ptr::null(), 0, &mut n),
                MXC_STATUS_NULL_ARGUMENT
            );
            assert_eq!(mxc_stream_flush(ptr::null_mut()), MXC_STATUS_NULL_ARGUMENT);
            assert_eq!(mxc_sandbox_id(ptr::null_mut()), 0);
            assert_eq!(
                mxc_sandbox_try_wait(ptr::null_mut(), &mut i, &mut j),
                MXC_STATUS_NULL_ARGUMENT
            );
            assert_eq!(
                mxc_sandbox_wait(ptr::null_mut(), &mut i, &mut j),
                MXC_STATUS_NULL_ARGUMENT
            );
            assert_eq!(mxc_sandbox_kill(ptr::null_mut()), MXC_STATUS_NULL_ARGUMENT);
        }
    }

    #[test]
    fn take_from_null_handle_returns_null() {
        // SAFETY: null handles are explicitly allowed and return null.
        unsafe {
            assert!(mxc_sandbox_take_stdin(ptr::null_mut()).is_null());
            assert!(mxc_sandbox_take_stdout(ptr::null_mut()).is_null());
            assert!(mxc_sandbox_take_stderr(ptr::null_mut()).is_null());
        }
    }

    #[test]
    fn freeing_null_handles_is_safe() {
        // SAFETY: null is explicitly allowed for every destructor.
        unsafe {
            mxc_sandbox_free(ptr::null_mut());
            mxc_read_stream_free(ptr::null_mut());
            mxc_write_stream_free(ptr::null_mut());
        }
    }

    /// Full streaming round-trip against a real sandbox: spawn `echo`, drain
    /// stdout to EOF, and wait for a clean exit. Ignored by default because it
    /// requires a host able to launch a sandboxed process (host-prepped Windows
    /// / capable Linux or macOS); run explicitly on such a host with
    /// `cargo test -p mxc_ffi -- --ignored real_echo_streaming_roundtrip`.
    #[test]
    #[ignore]
    fn real_echo_streaming_roundtrip() {
        let policy = CString::new(r#"{"version":"0.8.0-alpha"}"#).unwrap();
        #[cfg(target_os = "windows")]
        let command = CString::new("C:\\Windows\\System32\\cmd.exe /c echo mxc_stream_ok").unwrap();
        #[cfg(not(target_os = "windows"))]
        let command = CString::new("echo mxc_stream_ok").unwrap();

        let mut handle: *mut MxcSandbox = ptr::null_mut();
        let mut err: *mut c_char = ptr::null_mut();
        // SAFETY: valid strings and out pointers.
        let status = unsafe { mxc_spawn(policy.as_ptr(), command.as_ptr(), &mut handle, &mut err) };
        assert_eq!(status, MXC_STATUS_SUCCESS, "spawn failed (status {status})");
        assert!(!handle.is_null());

        // SAFETY: live handle from a successful spawn.
        let stdout = unsafe { mxc_sandbox_take_stdout(handle) };
        assert!(!stdout.is_null(), "stdout should be piped");

        let mut collected = Vec::new();
        let mut buf = [0u8; 256];
        loop {
            let mut got: usize = 0;
            // SAFETY: live stream, valid buffer + out pointer.
            let rc = unsafe { mxc_stream_read(stdout, buf.as_mut_ptr(), buf.len(), &mut got) };
            assert_eq!(rc, MXC_STATUS_SUCCESS);
            if got == 0 {
                break; // EOF
            }
            collected.extend_from_slice(&buf[..got]);
        }

        let mut exit = -999;
        let mut timed_out = -1;
        // SAFETY: live handle and valid out pointers.
        let rc = unsafe { mxc_sandbox_wait(handle, &mut exit, &mut timed_out) };
        assert_eq!(rc, MXC_STATUS_SUCCESS);
        assert_eq!(timed_out, 0);
        assert_eq!(exit, 0, "echo should exit 0");

        let text = String::from_utf8_lossy(&collected);
        assert!(text.contains("mxc_stream_ok"), "stdout was: {text:?}");

        // SAFETY: live handles freed exactly once.
        unsafe {
            mxc_read_stream_free(stdout);
            mxc_sandbox_free(handle);
        }
    }

    /// Real write→read round-trip: feed stdin via `mxc_stream_write` and read
    /// the echoed line back via `mxc_stream_read`. Proves the FFI write path
    /// (only exercised indirectly by the C# suite otherwise). Ignored like the
    /// other real-host tests.
    #[test]
    #[ignore]
    #[cfg(target_os = "windows")]
    fn real_stdin_write_stdout_read_roundtrip() {
        let policy = CString::new(r#"{"version":"0.8.0-alpha"}"#).unwrap();
        // A cmd builtin that reads one stdin line and echoes it back.
        let command =
            CString::new("C:\\Windows\\System32\\cmd.exe /v:on /c set /p x= & echo GOT:!x!")
                .unwrap();

        let mut handle: *mut MxcSandbox = ptr::null_mut();
        let mut err: *mut c_char = ptr::null_mut();
        // SAFETY: valid strings and out pointers.
        let status = unsafe { mxc_spawn(policy.as_ptr(), command.as_ptr(), &mut handle, &mut err) };
        assert_eq!(status, MXC_STATUS_SUCCESS, "spawn failed (status {status})");

        // SAFETY: live handle.
        let stdin = unsafe { mxc_sandbox_take_stdin(handle) };
        let stdout = unsafe { mxc_sandbox_take_stdout(handle) };
        assert!(!stdin.is_null() && !stdout.is_null());

        let line = b"mxc_write_ok\r\n";
        let mut written = 0usize;
        // SAFETY: live stream + valid buffer.
        let rc = unsafe { mxc_stream_write(stdin, line.as_ptr(), line.len(), &mut written) };
        assert_eq!(rc, MXC_STATUS_SUCCESS);
        assert!(written > 0);
        // Close stdin so `set /p` completes.
        unsafe { mxc_write_stream_free(stdin) };

        let mut collected = Vec::new();
        let mut buf = [0u8; 256];
        loop {
            let mut got = 0usize;
            // SAFETY: live stream + valid buffer.
            let rc = unsafe { mxc_stream_read(stdout, buf.as_mut_ptr(), buf.len(), &mut got) };
            assert_eq!(rc, MXC_STATUS_SUCCESS);
            if got == 0 {
                break;
            }
            collected.extend_from_slice(&buf[..got]);
        }
        let text = String::from_utf8_lossy(&collected);
        assert!(text.contains("GOT:mxc_write_ok"), "stdout was: {text:?}");

        let mut exit = -1;
        let mut timed_out = -1;
        // SAFETY: live handle + out pointers.
        let rc = unsafe { mxc_sandbox_wait(handle, &mut exit, &mut timed_out) };
        assert_eq!(rc, MXC_STATUS_SUCCESS);
        assert_eq!(exit, 0);

        // SAFETY: live handles freed once.
        unsafe {
            mxc_read_stream_free(stdout);
            mxc_sandbox_free(handle);
        }
    }

    /// Real kill: spawn a child blocked on stdin, `mxc_sandbox_kill` it, and
    /// confirm the wait then reports it gone. Proves the FFI kill path directly.
    #[test]
    #[ignore]
    #[cfg(target_os = "windows")]
    fn real_kill_terminates_blocked_child() {
        let policy = CString::new(r#"{"version":"0.8.0-alpha"}"#).unwrap();
        // Blocks reading a stdin line; we keep stdin open (never take it) so it
        // stays parked until killed.
        let command =
            CString::new("C:\\Windows\\System32\\cmd.exe /v:on /c set /p x= & echo done").unwrap();

        let mut handle: *mut MxcSandbox = ptr::null_mut();
        let mut err: *mut c_char = ptr::null_mut();
        // SAFETY: valid strings and out pointers.
        let status = unsafe { mxc_spawn(policy.as_ptr(), command.as_ptr(), &mut handle, &mut err) };
        assert_eq!(status, MXC_STATUS_SUCCESS, "spawn failed (status {status})");

        // Child should still be running.
        let mut exit = 0;
        let mut running = 0;
        // SAFETY: live handle + out pointers.
        let rc = unsafe { mxc_sandbox_try_wait(handle, &mut exit, &mut running) };
        assert_eq!(rc, MXC_STATUS_SUCCESS);
        assert_eq!(running, 1, "blocked child should still be running");

        // SAFETY: live handle.
        let rc = unsafe { mxc_sandbox_kill(handle) };
        assert_eq!(rc, MXC_STATUS_SUCCESS);

        // Wait reaps the killed child.
        let mut timed_out = -1;
        // SAFETY: live handle + out pointers.
        let rc = unsafe { mxc_sandbox_wait(handle, &mut exit, &mut timed_out) };
        assert_eq!(rc, MXC_STATUS_SUCCESS);
        assert_ne!(exit, 0, "a killed child should not exit cleanly");

        // SAFETY: live handle freed once.
        unsafe { mxc_sandbox_free(handle) };
    }
}
