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
//! - [`mxc_sandbox_stdout_closer`] / [`mxc_sandbox_stderr_closer`] return
//!   independent [`MxcStreamCloser`] handles. Calling
//!   [`mxc_stream_closer_close`] unblocks a read without killing the child.
//!
//! ## Concurrency contract
//!
//! Calls that take an [`MxcSandbox`] handle — process control, stream/closer
//! accessors, warning/metadata getters, and [`mxc_sandbox_free`] — must be
//! serialized by the caller. A caller that needs a cancellable wait should poll
//! [`mxc_sandbox_try_wait`] and call [`mxc_sandbox_kill`] from the *same*
//! thread, rather than blocking one thread in [`mxc_sandbox_wait`] and killing
//! from another. Handles already returned for streams and closers are separate
//! objects and are unaffected by this rule.
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

use mxc_sdk::{spawn_sandbox, Sandbox, StreamCloser, WaitOutcome};

use crate::{
    alloc_cstring, build_spawn_request, cstr_to_str, request, status_from_error_code,
    MxcErrorDetail, MXC_STATUS_BACKEND_ERROR, MXC_STATUS_INVALID_UTF8, MXC_STATUS_NULL_ARGUMENT,
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

/// Opaque closer for a child's stdout or stderr stream.
pub struct MxcStreamCloser {
    inner: StreamCloser,
}

// ---------------------------------------------------------------------------
// Spawn
// ---------------------------------------------------------------------------

/// Spawn a live sandboxed process and return an opaque handle to it.
///
/// Parses `policy_json_utf8` as a `SandboxPolicy`, sets `command_utf8` as the
/// command to run, and spawns the process with piped stdio. On success writes
/// the handle to `*out_handle` and returns [`MXC_STATUS_SUCCESS`]. On failure
/// returns the status code and, if `out_error` is non-null, fills it with the
/// message plus the failing API call when there was one (release it with
/// [`mxc_error_detail_free`](crate::mxc_error_detail_free)); `*out_handle` is
/// set to null.
///
/// # Safety
/// - `policy_json_utf8` / `command_utf8` must be null or valid NUL-terminated
///   UTF-8 C strings.
/// - `out_handle` must be non-null and point to writable pointer-sized storage
///   holding **no live handle**: this function overwrites it with null before
///   doing anything else, so a handle already stored there is stranded, and
///   [`mxc_sandbox_free`] is its only destructor. Free an existing handle
///   before reusing its storage. On success the caller owns `*out_handle` and
///   must free it with [`mxc_sandbox_free`].
/// - `out_error` must be null, or point to writable storage for one
///   [`MxcErrorDetail`] that holds **no live detail**: either fresh or
///   uninitialised storage, or storage already released with
///   [`mxc_error_detail_free`](crate::mxc_error_detail_free). This function
///   overwrites that storage without freeing what was there, so handing it a
///   populated detail leaks that detail's strings. It cannot do otherwise:
///   uninitialised storage holds no pointers it could safely release, and
///   nothing distinguishes the two cases at runtime.
#[no_mangle]
pub unsafe extern "C" fn mxc_spawn(
    policy_json_utf8: *const c_char,
    command_utf8: *const c_char,
    out_handle: *mut *mut MxcSandbox,
    out_error: *mut MxcErrorDetail,
) -> i32 {
    // Initialise out-params defensively so a partial/failed call never leaves
    // stale pointers behind.
    if !out_handle.is_null() {
        // SAFETY: caller-guaranteed writable pointer-sized storage.
        unsafe { *out_handle = ptr::null_mut() };
    }
    if !out_error.is_null() {
        // `write` rather than assignment: the storage may be uninitialised, and
        // assigning would be a claim that a valid value is being overwritten.
        // Nothing is dropped either way -- the type owns raw pointers and has no
        // destructor -- which is exactly why the contract above requires the
        // caller to hand over storage holding no live detail.
        // SAFETY: caller-guaranteed writable storage for one detail.
        unsafe { ptr::write(out_error, MxcErrorDetail::none()) };
    }
    if out_handle.is_null() {
        return MXC_STATUS_NULL_ARGUMENT;
    }

    let outcome = catch_unwind(AssertUnwindSafe(|| {
        spawn_inner(policy_json_utf8, command_utf8)
    }))
    .unwrap_or_else(|panic| {
        crate::report_panic("mxc_spawn", &*panic);
        Err((
            MXC_STATUS_PANIC,
            MxcErrorDetail::from_message("the mxc engine panicked"),
        ))
    });

    // SAFETY: `out_handle` non-null (checked), `out_error` null or writable.
    unsafe { finish_spawn(outcome, out_handle, out_error) }
}

/// Spawn a complete one-shot request as a live sandboxed process.
///
/// Uses the same co-versioned request JSON contract as
/// [`mxc_run_request`](crate::mxc_run_request).
///
/// # Safety
/// - `request_json_utf8` must be null or valid NUL-terminated UTF-8.
/// - `out_handle` and `out_error` follow the ownership contract of [`mxc_spawn`].
#[no_mangle]
pub unsafe extern "C" fn mxc_spawn_request(
    request_json_utf8: *const c_char,
    out_handle: *mut *mut MxcSandbox,
    out_error: *mut MxcErrorDetail,
) -> i32 {
    if !out_handle.is_null() {
        // SAFETY: caller-guaranteed writable pointer-sized storage.
        unsafe { *out_handle = ptr::null_mut() };
    }
    if !out_error.is_null() {
        // SAFETY: caller-guaranteed writable storage for one fresh detail.
        unsafe { ptr::write(out_error, MxcErrorDetail::none()) };
    }
    if out_handle.is_null() {
        return MXC_STATUS_NULL_ARGUMENT;
    }

    let outcome = catch_unwind(AssertUnwindSafe(|| spawn_request_inner(request_json_utf8)))
        .unwrap_or_else(|_| {
            Err((
                MXC_STATUS_PANIC,
                MxcErrorDetail::from_message("the mxc engine panicked"),
            ))
        });

    // SAFETY: `out_handle` is non-null and `out_error` is null or writable.
    unsafe { finish_spawn(outcome, out_handle, out_error) }
}

fn spawn_request_inner(request_json_utf8: *const c_char) -> Result<Sandbox, (i32, MxcErrorDetail)> {
    // SAFETY: caller contract on `mxc_spawn_request`; borrowed only within scope.
    let request_json = match unsafe { cstr_to_str(request_json_utf8) } {
        Some(value) => value,
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
    let request = request::build_request_from_json(request_json).map_err(sdk_error_detail)?;
    spawn_sandbox(request).map_err(sdk_error_detail)
}

/// Shared tail of the handle-returning spawn entry points ([`mxc_spawn`] and
/// `mxc_state_aware_exec`): on success box the [`Sandbox`] into an
/// [`MxcSandbox`] handle and write it to `*out_handle`; on failure hand the
/// detail to `*out_error` (when non-null) and return the status.
///
/// # Safety
/// `out_handle` must be non-null and writable; `out_error` must be null or
/// point to writable storage for one [`MxcErrorDetail`].
pub(crate) unsafe fn finish_spawn(
    outcome: Result<Sandbox, (i32, MxcErrorDetail)>,
    out_handle: *mut *mut MxcSandbox,
    out_error: *mut MxcErrorDetail,
) -> i32 {
    match outcome {
        Ok(sandbox) => {
            let boxed = Box::new(MxcSandbox::new(sandbox));
            // SAFETY: `out_handle` non-null and writable per the caller contract.
            unsafe { *out_handle = Box::into_raw(boxed) };
            MXC_STATUS_SUCCESS
        }
        Err((status, mut detail)) => {
            if out_error.is_null() {
                // The caller does not want the detail, but it already owns heap
                // strings — dropping the struct would leak every one of them,
                // because raw pointers have no destructor.
                detail.free_strings();
            } else {
                // SAFETY: `out_error` non-null and writable per the caller contract,
                // and initialised to an all-null detail by every caller before this
                // point -- so nothing live is overwritten here.
                unsafe { *out_error = detail };
            }
            status
        }
    }
}

/// The fallible core of [`mxc_spawn`], run under `catch_unwind`.
fn spawn_inner(
    policy_json_utf8: *const c_char,
    command_utf8: *const c_char,
) -> Result<Sandbox, (i32, MxcErrorDetail)> {
    // SAFETY: caller contract on `mxc_spawn`; borrowed only within scope.
    let policy_json = match unsafe { cstr_to_str(policy_json_utf8) } {
        Some(s) => s,
        None if policy_json_utf8.is_null() => {
            return Err((
                MXC_STATUS_NULL_ARGUMENT,
                MxcErrorDetail::from_message("policy JSON pointer is null"),
            ))
        }
        None => {
            return Err((
                MXC_STATUS_INVALID_UTF8,
                MxcErrorDetail::from_message("policy JSON is not UTF-8"),
            ))
        }
    };
    let command = match unsafe { cstr_to_str(command_utf8) } {
        Some(s) => s,
        None if command_utf8.is_null() => {
            return Err((
                MXC_STATUS_NULL_ARGUMENT,
                MxcErrorDetail::from_message("command pointer is null"),
            ))
        }
        None => {
            return Err((
                MXC_STATUS_INVALID_UTF8,
                MxcErrorDetail::from_message("command is not UTF-8"),
            ))
        }
    };

    let request = build_spawn_request(policy_json, command)?;

    spawn_sandbox(request).map_err(sdk_error_detail)
}

/// Map an SDK error onto the status + detail pair the spawn chain carries, so
/// the failing API call survives instead of being flattened to a message.
fn sdk_error_detail(error: mxc_sdk::Error) -> (i32, MxcErrorDetail) {
    (
        status_from_error_code(error.code),
        MxcErrorDetail::from_error(&error),
    )
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

/// Return a closer that unblocks reads on stdout without killing the child.
///
/// Returns null if `handle` is null or this backend has no interruptible stdout
/// stream. The returned handle is independent of the stdout reader and must be
/// freed with [`mxc_stream_closer_free`].
///
/// # Safety
/// `handle` must be null or a live handle from [`mxc_spawn`].
#[no_mangle]
pub unsafe extern "C" fn mxc_sandbox_stdout_closer(
    handle: *mut MxcSandbox,
) -> *mut MxcStreamCloser {
    take_closer(handle, |s| s.inner.stdout_closer())
}

/// Return a closer that unblocks reads on stderr without killing the child.
///
/// Returns null if `handle` is null or this backend has no interruptible stderr
/// stream. Free the returned handle with [`mxc_stream_closer_free`].
///
/// # Safety
/// `handle` must be null or a live handle from [`mxc_spawn`].
#[no_mangle]
pub unsafe extern "C" fn mxc_sandbox_stderr_closer(
    handle: *mut MxcSandbox,
) -> *mut MxcStreamCloser {
    take_closer(handle, |s| s.inner.stderr_closer())
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
    result
        .unwrap_or_else(|panic| {
            crate::report_panic("mxc_sandbox_take_stdin", &*panic);
            None
        })
        .unwrap_or(ptr::null_mut())
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
    result
        .unwrap_or_else(|panic| {
            crate::report_panic("mxc_sandbox_take_stdout_or_stderr", &*panic);
            None
        })
        .unwrap_or(ptr::null_mut())
}

fn take_closer(
    handle: *mut MxcSandbox,
    take: impl FnOnce(&MxcSandbox) -> Option<StreamCloser>,
) -> *mut MxcStreamCloser {
    if handle.is_null() {
        return ptr::null_mut();
    }
    let result = catch_unwind(AssertUnwindSafe(|| {
        // SAFETY: non-null live handle per the caller contract.
        let sandbox = unsafe { &*handle };
        take(sandbox).map(|inner| Box::into_raw(Box::new(MxcStreamCloser { inner })))
    }));
    result
        .unwrap_or_else(|panic| {
            crate::report_panic("mxc_sandbox_take_stdout_or_stderr_closer", &*panic);
            None
        })
        .unwrap_or(ptr::null_mut())
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
    // SAFETY: `out_read` is non-null and caller-guaranteed writable. Zero it
    // before any fallible work so a caught panic or I/O error never leaves the
    // caller's prior value behind.
    unsafe { *out_read = 0 };
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
    status.unwrap_or_else(|panic| {
        crate::report_panic("mxc_stream_read", &*panic);
        MXC_STATUS_PANIC
    })
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
    // SAFETY: `out_written` is non-null and caller-guaranteed writable. Zero
    // it before any fallible work so a caught panic or I/O error never leaves
    // the caller's prior value behind.
    unsafe { *out_written = 0 };
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
    status.unwrap_or_else(|panic| {
        crate::report_panic("mxc_stream_write", &*panic);
        MXC_STATUS_PANIC
    })
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
    status.unwrap_or_else(|panic| {
        crate::report_panic("mxc_stream_flush", &*panic);
        MXC_STATUS_PANIC
    })
}

/// Close a stdout/stderr reader through its independent closer.
///
/// Makes an in-flight or subsequent read return EOF without killing the child.
/// Idempotent and safe to call after the reader has already reached EOF.
/// Multiple calls may run concurrently on the same closer, but no call may
/// overlap [`mxc_stream_closer_free`].
///
/// # Safety
/// `closer` must be null or a live handle from
/// [`mxc_sandbox_stdout_closer`] / [`mxc_sandbox_stderr_closer`].
#[no_mangle]
pub unsafe extern "C" fn mxc_stream_closer_close(closer: *mut MxcStreamCloser) -> i32 {
    if closer.is_null() {
        return MXC_STATUS_NULL_ARGUMENT;
    }
    catch_unwind(AssertUnwindSafe(|| {
        // SAFETY: non-null live handle per the caller contract. StreamCloser is
        // Sync and close takes &self, so concurrent close calls do not alias &mut.
        unsafe { &*closer }.inner.close();
        MXC_STATUS_SUCCESS
    }))
    .unwrap_or_else(|panic| {
        crate::report_panic("mxc_stream_closer_close", &*panic);
        MXC_STATUS_PANIC
    })
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
    .unwrap_or_else(|panic| {
        crate::report_panic("mxc_sandbox_id", &*panic);
        0
    })
}

/// Return structured output metadata as owned JSON. A successful call leaves
/// `*out_json_utf8` null when the sandbox has not completed or produced no
/// metadata.
///
/// The caller owns a non-null `*out_json_utf8` and must free it with
/// [`mxc_string_free`](crate::mxc_string_free).
///
/// # Safety
/// - `handle` must be null or a live handle from [`mxc_spawn`].
/// - `out_json_utf8` must be non-null and point to writable pointer storage.
#[no_mangle]
pub unsafe extern "C" fn mxc_sandbox_output_metadata_json(
    handle: *mut MxcSandbox,
    out_json_utf8: *mut *mut c_char,
) -> i32 {
    if !out_json_utf8.is_null() {
        // SAFETY: caller-guaranteed writable pointer-sized storage.
        unsafe { *out_json_utf8 = ptr::null_mut() };
    }
    if handle.is_null() || out_json_utf8.is_null() {
        return MXC_STATUS_NULL_ARGUMENT;
    }

    catch_unwind(AssertUnwindSafe(|| {
        // SAFETY: non-null live handle per the caller contract.
        let sandbox = unsafe { &*handle };
        let Some(metadata) = sandbox.inner.output_metadata() else {
            return MXC_STATUS_SUCCESS;
        };
        let json = match serde_json::to_vec(metadata) {
            Ok(json) => json,
            Err(_) => return MXC_STATUS_BACKEND_ERROR,
        };
        // SAFETY: non-null writable out pointer per the caller contract.
        unsafe { *out_json_utf8 = alloc_cstring(&json) };
        MXC_STATUS_SUCCESS
    }))
    .unwrap_or_else(|panic| {
        crate::report_panic("mxc_sandbox_output_metadata_json", &*panic);
        MXC_STATUS_PANIC
    })
}

/// Return the sandbox's security warnings as owned JSON.
///
/// A successful call leaves `*out_json_utf8` null when there are no warnings.
/// The caller owns a non-null result and must free it with
/// [`mxc_string_free`](crate::mxc_string_free).
///
/// # Safety
/// - `handle` must be null or a live handle from [`mxc_spawn`].
/// - `out_json_utf8` must be non-null and point to writable pointer storage.
#[no_mangle]
pub unsafe extern "C" fn mxc_sandbox_warnings_json(
    handle: *mut MxcSandbox,
    out_json_utf8: *mut *mut c_char,
) -> i32 {
    if !out_json_utf8.is_null() {
        // SAFETY: caller-guaranteed writable pointer-sized storage.
        unsafe { *out_json_utf8 = ptr::null_mut() };
    }
    if handle.is_null() || out_json_utf8.is_null() {
        return MXC_STATUS_NULL_ARGUMENT;
    }

    catch_unwind(AssertUnwindSafe(|| {
        // SAFETY: non-null live handle per the caller contract.
        let sandbox = unsafe { &*handle };
        if sandbox.inner.warnings().is_empty() {
            return MXC_STATUS_SUCCESS;
        }
        let json = match serde_json::to_vec(sandbox.inner.warnings()) {
            Ok(json) => json,
            Err(_) => return MXC_STATUS_BACKEND_ERROR,
        };
        // SAFETY: non-null writable out pointer per the caller contract.
        unsafe { *out_json_utf8 = alloc_cstring(&json) };
        MXC_STATUS_SUCCESS
    }))
    .unwrap_or_else(|panic| {
        crate::report_panic("mxc_sandbox_warnings_json", &*panic);
        MXC_STATUS_PANIC
    })
}

/// Non-blocking completion check. On return, `*out_running` is `1` if the child
/// is still running. For a normal exit it is `0`, `*out_exit` holds the exit
/// code, and `*out_timed_out` is `0`. For a finalized timeout it is `0`,
/// `*out_exit` is `-1`, and `*out_timed_out` is `1`.
///
/// Returns [`MXC_STATUS_SUCCESS`], [`MXC_STATUS_NULL_ARGUMENT`] if any pointer
/// is null, or [`MXC_STATUS_BACKEND_ERROR`] on a wait error.
///
/// # Safety
/// - `handle` must be null or a live handle from [`mxc_spawn`].
/// - `out_exit` / `out_running` / `out_timed_out` must be null or point to
///   writable `i32` storage.
#[no_mangle]
pub unsafe extern "C" fn mxc_sandbox_try_wait(
    handle: *mut MxcSandbox,
    out_exit: *mut i32,
    out_running: *mut i32,
    out_timed_out: *mut i32,
) -> i32 {
    if handle.is_null() || out_exit.is_null() || out_running.is_null() || out_timed_out.is_null() {
        return MXC_STATUS_NULL_ARGUMENT;
    }
    // SAFETY: out-params are non-null and caller-guaranteed writable. Zero
    // them before any fallible work so a caught panic or backend error never
    // leaks the caller's previous values back out.
    unsafe {
        *out_exit = 0;
        *out_running = 0;
        *out_timed_out = 0;
    }
    let status = catch_unwind(AssertUnwindSafe(|| {
        // SAFETY: non-null live handle per the caller contract.
        let sandbox = unsafe { &mut *handle };
        match try_wait_result_to_abi(sandbox.inner.try_wait()) {
            Ok((exit, running, timed_out)) => {
                // SAFETY: out-params non-null writable per the caller contract.
                unsafe {
                    *out_exit = exit;
                    *out_running = running;
                    *out_timed_out = timed_out;
                }
                MXC_STATUS_SUCCESS
            }
            Err(status) => status,
        }
    }));
    status.unwrap_or_else(|panic| {
        crate::report_panic("mxc_sandbox_try_wait", &*panic);
        MXC_STATUS_PANIC
    })
}

fn try_wait_result_to_abi(result: std::io::Result<Option<i32>>) -> Result<(i32, i32, i32), i32> {
    match result {
        Ok(Some(code)) => Ok((code, 0, 0)),
        Ok(None) => Ok((0, 1, 0)),
        Err(error) if error.kind() == std::io::ErrorKind::TimedOut => Ok((-1, 0, 1)),
        Err(_) => Err(MXC_STATUS_BACKEND_ERROR),
    }
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
    // SAFETY: out-params are non-null and caller-guaranteed writable. Zero
    // them before any fallible work so a caught panic or backend error never
    // leaks the caller's previous values back out.
    unsafe {
        *out_exit = 0;
        *out_timed_out = 0;
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
    status.unwrap_or_else(|panic| {
        crate::report_panic("mxc_sandbox_wait", &*panic);
        MXC_STATUS_PANIC
    })
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
    status.unwrap_or_else(|panic| {
        crate::report_panic("mxc_sandbox_kill", &*panic);
        MXC_STATUS_PANIC
    })
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
    if let Err(panic) = catch_unwind(AssertUnwindSafe(|| {
        // SAFETY: non-null handle produced by `Box::into_raw` in `mxc_spawn`,
        // not yet freed; reconstructing the Box drops it (and its child).
        drop(unsafe { Box::from_raw(handle) });
    })) {
        crate::report_panic("mxc_sandbox_free", &*panic);
    }
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
    if let Err(panic) = catch_unwind(AssertUnwindSafe(|| {
        // SAFETY: non-null handle produced by `Box::into_raw`, not yet freed.
        drop(unsafe { Box::from_raw(stream) });
    })) {
        crate::report_panic("mxc_read_stream_free", &*panic);
    }
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
    if let Err(panic) = catch_unwind(AssertUnwindSafe(|| {
        // SAFETY: non-null handle produced by `Box::into_raw`, not yet freed.
        drop(unsafe { Box::from_raw(stream) });
    })) {
        crate::report_panic("mxc_write_stream_free", &*panic);
    }
}

/// Free a stream-closer handle. Safe to call with null (no-op). Must be called
/// exactly once and not concurrently with [`mxc_stream_closer_close`].
///
/// # Safety
/// `closer` must be null or a live, not-yet-freed handle from
/// [`mxc_sandbox_stdout_closer`] / [`mxc_sandbox_stderr_closer`].
#[no_mangle]
pub unsafe extern "C" fn mxc_stream_closer_free(closer: *mut MxcStreamCloser) {
    if closer.is_null() {
        return;
    }
    if let Err(panic) = catch_unwind(AssertUnwindSafe(|| {
        // SAFETY: non-null handle produced by Box::into_raw, not yet freed.
        drop(unsafe { Box::from_raw(closer) });
    })) {
        crate::report_panic("mxc_stream_closer_free", &*panic);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn try_wait_preserves_timeout_as_a_terminal_outcome() {
        assert_eq!(try_wait_result_to_abi(Ok(Some(42))), Ok((42, 0, 0)));
        assert_eq!(try_wait_result_to_abi(Ok(None)), Ok((0, 1, 0)));
        assert_eq!(
            try_wait_result_to_abi(Err(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "deadline elapsed"
            ))),
            Ok((-1, 0, 1))
        );
        assert_eq!(
            try_wait_result_to_abi(Err(std::io::Error::other("wait failed"))),
            Err(MXC_STATUS_BACKEND_ERROR)
        );
    }
    use std::ffi::CString;

    use crate::MXC_STATUS_MALFORMED_REQUEST;

    struct PanicReader;

    impl Read for PanicReader {
        fn read(&mut self, _buf: &mut [u8]) -> std::io::Result<usize> {
            panic!("forced panic in test reader");
        }
    }

    struct PanicWriter;

    impl Write for PanicWriter {
        fn write(&mut self, _buf: &[u8]) -> std::io::Result<usize> {
            panic!("forced panic in test writer");
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    struct PanicFlushWriter;

    impl Write for PanicFlushWriter {
        fn write(&mut self, _buf: &[u8]) -> std::io::Result<usize> {
            Ok(0)
        }

        fn flush(&mut self) -> std::io::Result<()> {
            panic!("forced panic in test flush");
        }
    }

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
    fn build_spawn_request_propagates_telemetry_enablement() {
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
            (
                r#"{"version":"0.8.0-alpha","telemetryEnabled":false}"#,
                Some(false),
            ),
        ] {
            let request = build_spawn_request(policy_json, "echo hi")
                .unwrap_or_else(|_| panic!("build_spawn_request failed for {policy_json}"));
            assert_eq!(
                request.telemetry_enabled(),
                expected,
                "policy: {policy_json}"
            );
        }
    }

    #[test]
    fn spawn_null_policy_reports_null_argument() {
        let command = CString::new("echo hi").unwrap();
        let mut handle: *mut MxcSandbox = ptr::null_mut();
        let mut err = MxcErrorDetail::none();
        // SAFETY: null policy pointer is explicitly handled.
        let status = unsafe { mxc_spawn(ptr::null(), command.as_ptr(), &mut handle, &mut err) };
        assert_eq!(status, MXC_STATUS_NULL_ARGUMENT);
        assert!(handle.is_null());
        assert!(
            !err.message_utf8.is_null(),
            "an error message should be provided"
        );
        // SAFETY: `err` was filled by `mxc_spawn` and not yet freed.
        unsafe { crate::mxc_error_detail_free(&mut err) };
    }

    #[test]
    fn spawn_malformed_policy_reports_malformed_request() {
        let policy = CString::new("{ not json").unwrap();
        let command = CString::new("echo hi").unwrap();
        let mut handle: *mut MxcSandbox = ptr::null_mut();
        let mut err = MxcErrorDetail::none();
        // SAFETY: valid strings and valid out pointers.
        let status = unsafe { mxc_spawn(policy.as_ptr(), command.as_ptr(), &mut handle, &mut err) };
        assert_eq!(status, MXC_STATUS_MALFORMED_REQUEST);
        assert!(handle.is_null());
        assert!(!err.message_utf8.is_null());
        // SAFETY: `err` was filled by `mxc_spawn` and not yet freed.
        unsafe { crate::mxc_error_detail_free(&mut err) };
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
            assert_eq!(
                mxc_stream_closer_close(ptr::null_mut()),
                MXC_STATUS_NULL_ARGUMENT
            );
            assert_eq!(mxc_sandbox_id(ptr::null_mut()), 0);
            let mut metadata = ptr::null_mut();
            assert_eq!(
                mxc_sandbox_output_metadata_json(ptr::null_mut(), &mut metadata),
                MXC_STATUS_NULL_ARGUMENT
            );
            let mut warnings = ptr::null_mut();
            assert_eq!(
                mxc_sandbox_warnings_json(ptr::null_mut(), &mut warnings),
                MXC_STATUS_NULL_ARGUMENT
            );
            assert_eq!(
                mxc_sandbox_try_wait(ptr::null_mut(), &mut i, &mut j, &mut j),
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
            assert!(mxc_sandbox_stdout_closer(ptr::null_mut()).is_null());
            assert!(mxc_sandbox_stderr_closer(ptr::null_mut()).is_null());
        }
    }

    #[test]
    fn freeing_null_handles_is_safe() {
        // SAFETY: null is explicitly allowed for every destructor.
        unsafe {
            mxc_sandbox_free(ptr::null_mut());
            mxc_read_stream_free(ptr::null_mut());
            mxc_write_stream_free(ptr::null_mut());
            mxc_stream_closer_free(ptr::null_mut());
        }
    }

    #[test]
    fn stream_read_panic_zeroes_out_read_before_returning_panic() {
        let mut stream = MxcReadStream {
            inner: Box::new(PanicReader),
        };
        let mut buf = [0u8; 8];
        let mut out_read = usize::MAX;
        // SAFETY: `stream`, `buf`, and `out_read` are valid for this call.
        let status =
            unsafe { mxc_stream_read(&mut stream, buf.as_mut_ptr(), buf.len(), &mut out_read) };
        assert_eq!(status, MXC_STATUS_PANIC);
        assert_eq!(out_read, 0);
    }

    #[test]
    fn stream_write_panic_zeroes_out_written_before_returning_panic() {
        let mut stream = MxcWriteStream {
            inner: Box::new(PanicWriter),
        };
        let buf = *b"panic";
        let mut out_written = usize::MAX;
        // SAFETY: `stream`, `buf`, and `out_written` are valid for this call.
        let status =
            unsafe { mxc_stream_write(&mut stream, buf.as_ptr(), buf.len(), &mut out_written) };
        assert_eq!(status, MXC_STATUS_PANIC);
        assert_eq!(out_written, 0);
    }

    #[test]
    fn stream_flush_panic_returns_panic_status() {
        let mut stream = MxcWriteStream {
            inner: Box::new(PanicFlushWriter),
        };
        // SAFETY: `stream` is a valid live stream handle.
        let status = unsafe { mxc_stream_flush(&mut stream) };
        assert_eq!(status, MXC_STATUS_PANIC);
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
        let mut err = MxcErrorDetail::none();
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
        let mut err = MxcErrorDetail::none();
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
        let mut err = MxcErrorDetail::none();
        // SAFETY: valid strings and out pointers.
        let status = unsafe { mxc_spawn(policy.as_ptr(), command.as_ptr(), &mut handle, &mut err) };
        assert_eq!(status, MXC_STATUS_SUCCESS, "spawn failed (status {status})");

        // Child should still be running.
        let mut exit = i32::MIN;
        let mut running = -1;
        // SAFETY: live handle + out pointers.
        let mut timed_out = -1;
        let rc = unsafe { mxc_sandbox_try_wait(handle, &mut exit, &mut running, &mut timed_out) };
        assert_eq!(rc, MXC_STATUS_SUCCESS);
        assert_eq!(running, 1, "blocked child should still be running");
        assert_eq!(exit, 0, "running poll should leave the zero sentinel");
        assert_eq!(timed_out, 0);

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
