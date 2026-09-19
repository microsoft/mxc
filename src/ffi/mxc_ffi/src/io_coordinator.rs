// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! C translation layer for native stdio and process lifecycle coordination.

use std::ffi::{c_char, CStr};
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::ptr;

use mxc_engine::{IoCoordinator, IoCoordinatorError};

use crate::{
    alloc_cstring, request, status_from_error_code, MxcErrorDetail, MXC_STATUS_BACKEND_ERROR,
    MXC_STATUS_INVALID_UTF8, MXC_STATUS_NULL_ARGUMENT, MXC_STATUS_PANIC, MXC_STATUS_SUCCESS,
};

/// Opaque lifecycle coordinator for event-loop language bindings.
pub struct MxcIoCoordinator {
    inner: IoCoordinator,
}

/// Caller-owned native stdio endpoints.
///
/// Values are Win32 `HANDLE`s on Windows and file descriptors on Unix.
/// Absent endpoints are `0` on Windows and `-1` on Unix.
#[repr(C)]
pub struct MxcNativeStdio {
    pub stdin_handle: isize,
    pub stdout_handle: isize,
    pub stderr_handle: isize,
}

impl MxcNativeStdio {
    const fn invalid() -> Self {
        #[cfg(target_os = "windows")]
        const INVALID: isize = 0;
        #[cfg(not(target_os = "windows"))]
        const INVALID: isize = -1;

        Self {
            stdin_handle: INVALID,
            stdout_handle: INVALID,
            stderr_handle: INVALID,
        }
    }
}

fn coordinator_ref<'a>(handle: *mut MxcIoCoordinator) -> Option<&'a MxcIoCoordinator> {
    if handle.is_null() {
        None
    } else {
        // SAFETY: callers of the public FFI functions guarantee a live handle.
        Some(unsafe { &*handle })
    }
}

fn catch_status(operation: &str, body: impl FnOnce() -> i32) -> i32 {
    catch_unwind(AssertUnwindSafe(body)).unwrap_or_else(|panic| {
        crate::report_panic(operation, &*panic);
        MXC_STATUS_PANIC
    })
}

/// Spawn a one-shot sandbox with native stdio and lifecycle coordination.
///
/// # Safety
/// - `request_json_utf8` must be null or valid NUL-terminated UTF-8.
/// - `out_handle` must point to writable pointer storage holding no live handle.
/// - `out_error` must be null or point to writable fresh error storage.
#[no_mangle]
pub unsafe extern "C" fn mxc_io_spawn_request(
    request_json_utf8: *const c_char,
    out_handle: *mut *mut MxcIoCoordinator,
    out_error: *mut MxcErrorDetail,
) -> i32 {
    unsafe {
        spawn_coordinator(
            "mxc_io_spawn_request",
            request_json_utf8,
            out_handle,
            out_error,
            |request_json| {
                let request = request::build_request_from_json(request_json)
                    .map_err(|error| sdk_error_detail(&error))?;
                mxc_engine::spawn_io(&request).map_err(|error| sdk_error_detail(&error))
            },
        )
    }
}

/// Execute a state-aware request with native stdio and lifecycle coordination.
///
/// # Safety
/// Pointer requirements are identical to [`mxc_io_spawn_request`].
#[no_mangle]
pub unsafe extern "C" fn mxc_io_state_aware_exec(
    request_json_utf8: *const c_char,
    experimental: i32,
    out_handle: *mut *mut MxcIoCoordinator,
    out_error: *mut MxcErrorDetail,
) -> i32 {
    unsafe {
        spawn_coordinator(
            "mxc_io_state_aware_exec",
            request_json_utf8,
            out_handle,
            out_error,
            |request_json| {
                let process = mxc_engine::exec_state_aware_json(request_json, experimental != 0)
                    .map_err(|error| sdk_error_detail(&error))?;
                mxc_engine::coordinate_io(process, None).map_err(|error| sdk_error_detail(&error))
            },
        )
    }
}

unsafe fn spawn_coordinator(
    operation: &str,
    request_json_utf8: *const c_char,
    out_handle: *mut *mut MxcIoCoordinator,
    out_error: *mut MxcErrorDetail,
    spawn: impl FnOnce(&str) -> Result<IoCoordinator, (i32, MxcErrorDetail)>,
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

    let outcome = catch_unwind(AssertUnwindSafe(|| {
        let request_json = if request_json_utf8.is_null() {
            return Err((
                MXC_STATUS_NULL_ARGUMENT,
                MxcErrorDetail::from_message("request JSON pointer is null"),
            ));
        } else {
            // SAFETY: caller contract guarantees a valid C string.
            unsafe { CStr::from_ptr(request_json_utf8) }
                .to_str()
                .map_err(|_| {
                    (
                        MXC_STATUS_INVALID_UTF8,
                        MxcErrorDetail::from_message("request JSON is not UTF-8"),
                    )
                })?
        };
        spawn(request_json)
    }))
    .unwrap_or_else(|panic| {
        crate::report_panic(operation, &*panic);
        Err((
            MXC_STATUS_PANIC,
            MxcErrorDetail::from_message("the mxc engine panicked"),
        ))
    });

    match outcome {
        Ok(coordinator) => {
            // SAFETY: `out_handle` is non-null and writable.
            unsafe {
                *out_handle = Box::into_raw(Box::new(MxcIoCoordinator { inner: coordinator }))
            };
            MXC_STATUS_SUCCESS
        }
        Err((status, mut detail)) => {
            if out_error.is_null() {
                detail.free_strings();
            } else {
                // SAFETY: caller-guaranteed writable fresh storage.
                unsafe { *out_error = detail };
            }
            status
        }
    }
}

fn sdk_error_detail(error: &mxc_sdk::Error) -> (i32, MxcErrorDetail) {
    (
        status_from_error_code(error.code),
        MxcErrorDetail::from_error(error),
    )
}

/// Return the child process identifier, or zero for an invalid handle.
///
/// # Safety
/// `handle` must be null or a live coordinator handle.
#[no_mangle]
pub unsafe extern "C" fn mxc_io_id(handle: *mut MxcIoCoordinator) -> u32 {
    catch_unwind(AssertUnwindSafe(|| {
        coordinator_ref(handle).map_or(0, |coordinator| coordinator.inner.id())
    }))
    .unwrap_or_else(|panic| {
        crate::report_panic("mxc_io_id", &*panic);
        0
    })
}

/// Transfer native stdio endpoints from the coordinator exactly once.
///
/// # Safety
/// - `handle` must be null or a live coordinator handle.
/// - `out_stdio` must point to writable storage for one [`MxcNativeStdio`].
#[no_mangle]
pub unsafe extern "C" fn mxc_io_take_native_stdio(
    handle: *mut MxcIoCoordinator,
    out_stdio: *mut MxcNativeStdio,
) -> i32 {
    if out_stdio.is_null() {
        return MXC_STATUS_NULL_ARGUMENT;
    }
    // SAFETY: caller-guaranteed writable storage.
    unsafe { ptr::write(out_stdio, MxcNativeStdio::invalid()) };
    catch_status("mxc_io_take_native_stdio", || {
        let Some(coordinator) = coordinator_ref(handle) else {
            return MXC_STATUS_NULL_ARGUMENT;
        };
        let Some(stdio) = coordinator.inner.take_native_stdio() else {
            return MXC_STATUS_BACKEND_ERROR;
        };
        let result = MxcNativeStdio {
            stdin_handle: native_pipe_into_raw(stdio.stdin),
            stdout_handle: native_pipe_into_raw(stdio.stdout),
            stderr_handle: native_pipe_into_raw(stdio.stderr),
        };
        // SAFETY: non-null writable output per the caller contract.
        unsafe { ptr::write(out_stdio, result) };
        MXC_STATUS_SUCCESS
    })
}

#[cfg(target_os = "windows")]
fn native_pipe_into_raw(pipe: Option<std::os::windows::io::OwnedHandle>) -> isize {
    use std::os::windows::io::IntoRawHandle;
    pipe.map_or(0, |handle| handle.into_raw_handle() as isize)
}

#[cfg(not(target_os = "windows"))]
fn native_pipe_into_raw(pipe: Option<std::os::fd::OwnedFd>) -> isize {
    use std::os::fd::IntoRawFd;
    pipe.map_or(-1, |fd| fd.into_raw_fd() as isize)
}

/// Close a transferred endpoint that the caller could not adopt.
///
/// # Safety
/// `handle` must be an owned endpoint returned by
/// [`mxc_io_take_native_stdio`] and must not have been closed or adopted.
#[no_mangle]
pub unsafe extern "C" fn mxc_native_pipe_close(handle: isize) {
    if let Err(panic) = catch_unwind(AssertUnwindSafe(|| close_native_pipe(handle))) {
        crate::report_panic("mxc_native_pipe_close", &*panic);
    }
}

#[cfg(target_os = "windows")]
fn close_native_pipe(handle: isize) {
    use std::os::windows::io::{FromRawHandle, OwnedHandle};
    if handle != 0 {
        // SAFETY: caller transfers one live owned handle to this function.
        drop(unsafe { OwnedHandle::from_raw_handle(handle as _) });
    }
}

#[cfg(not(target_os = "windows"))]
fn close_native_pipe(handle: isize) {
    use std::os::fd::{FromRawFd, OwnedFd};
    if let Ok(fd) = i32::try_from(handle) {
        if fd >= 0 {
            // SAFETY: caller transfers one live owned descriptor to this function.
            drop(unsafe { OwnedFd::from_raw_fd(fd) });
        }
    }
}

/// Poll process completion without blocking.
///
/// # Safety
/// All output pointers must be non-null and writable.
#[no_mangle]
pub unsafe extern "C" fn mxc_io_try_wait(
    handle: *mut MxcIoCoordinator,
    out_exit: *mut i32,
    out_running: *mut i32,
    out_timed_out: *mut i32,
) -> i32 {
    if handle.is_null() || out_exit.is_null() || out_running.is_null() || out_timed_out.is_null() {
        return MXC_STATUS_NULL_ARGUMENT;
    }
    // SAFETY: caller-guaranteed writable outputs.
    unsafe {
        *out_exit = 0;
        *out_running = 1;
        *out_timed_out = 0;
    }
    catch_status("mxc_io_try_wait", || {
        let Some(coordinator) = coordinator_ref(handle) else {
            return MXC_STATUS_NULL_ARGUMENT;
        };
        match coordinator.inner.poll_process() {
            Ok(status) => {
                // SAFETY: non-null writable outputs per the caller contract.
                unsafe {
                    *out_exit = status.exit_code;
                    *out_running = i32::from(status.running);
                    *out_timed_out = i32::from(status.timed_out);
                }
                MXC_STATUS_SUCCESS
            }
            Err(IoCoordinatorError::Closed | IoCoordinatorError::Backend) => {
                MXC_STATUS_BACKEND_ERROR
            }
        }
    })
}

/// Queue a process-tree kill and return immediately.
///
/// # Safety
/// `handle` must be null or a live coordinator handle.
#[no_mangle]
pub unsafe extern "C" fn mxc_io_request_kill(handle: *mut MxcIoCoordinator) -> i32 {
    catch_status("mxc_io_request_kill", || {
        coordinator_ref(handle).map_or(MXC_STATUS_NULL_ARGUMENT, |coordinator| {
            coordinator
                .inner
                .request_kill()
                .map_or(MXC_STATUS_BACKEND_ERROR, |()| MXC_STATUS_SUCCESS)
        })
    })
}

/// Request process shutdown without releasing the caller's handle.
///
/// # Safety
/// `handle` must be null or a live coordinator handle.
#[no_mangle]
pub unsafe extern "C" fn mxc_io_request_shutdown(handle: *mut MxcIoCoordinator) -> i32 {
    catch_status("mxc_io_request_shutdown", || {
        let Some(coordinator) = coordinator_ref(handle) else {
            return MXC_STATUS_NULL_ARGUMENT;
        };
        coordinator.inner.request_shutdown();
        MXC_STATUS_SUCCESS
    })
}

unsafe fn copy_owned_json(
    handle: *mut MxcIoCoordinator,
    out_json_utf8: *mut *mut c_char,
    value: impl FnOnce(&IoCoordinator) -> Option<Vec<u8>>,
) -> i32 {
    if !out_json_utf8.is_null() {
        // SAFETY: caller-guaranteed writable pointer-sized storage.
        unsafe { *out_json_utf8 = ptr::null_mut() };
    }
    if handle.is_null() || out_json_utf8.is_null() {
        return MXC_STATUS_NULL_ARGUMENT;
    }
    let Some(coordinator) = coordinator_ref(handle) else {
        return MXC_STATUS_NULL_ARGUMENT;
    };
    if let Some(json) = value(&coordinator.inner) {
        // SAFETY: caller-guaranteed writable pointer-sized storage.
        unsafe { *out_json_utf8 = alloc_cstring(&json) };
    }
    MXC_STATUS_SUCCESS
}

/// Return the latest warnings JSON without blocking.
///
/// # Safety
/// `out_json_utf8` must be null or point to writable pointer-sized storage.
#[no_mangle]
pub unsafe extern "C" fn mxc_io_warnings_json(
    handle: *mut MxcIoCoordinator,
    out_json_utf8: *mut *mut c_char,
) -> i32 {
    catch_status("mxc_io_warnings_json", || {
        // SAFETY: forwarded caller contract.
        unsafe {
            copy_owned_json(handle, out_json_utf8, |coordinator| {
                serde_json::to_vec(&coordinator.warnings()).ok()
            })
        }
    })
}

/// Return terminal output metadata JSON without blocking.
///
/// # Safety
/// `out_json_utf8` must be null or point to writable pointer-sized storage.
#[no_mangle]
pub unsafe extern "C" fn mxc_io_output_metadata_json(
    handle: *mut MxcIoCoordinator,
    out_json_utf8: *mut *mut c_char,
) -> i32 {
    catch_status("mxc_io_output_metadata_json", || {
        // SAFETY: forwarded caller contract.
        unsafe {
            copy_owned_json(handle, out_json_utf8, |coordinator| {
                coordinator
                    .output_metadata()
                    .and_then(|metadata| serde_json::to_vec(&metadata).ok())
            })
        }
    })
}

/// Request shutdown and release the coordinator.
///
/// This call may block while the native lifecycle worker exits. Event-loop
/// bindings should invoke it through a native worker pool.
///
/// # Safety
/// `handle` must be null or a live, not-yet-freed coordinator handle.
#[no_mangle]
pub unsafe extern "C" fn mxc_io_free(handle: *mut MxcIoCoordinator) {
    if handle.is_null() {
        return;
    }
    if let Err(panic) = catch_unwind(AssertUnwindSafe(|| {
        // SAFETY: live unique handle produced by `Box::into_raw`.
        drop(unsafe { Box::from_raw(handle) });
    })) {
        crate::report_panic("mxc_io_free", &*panic);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn null_handle_accessors_fail_closed() {
        let mut exit = 7;
        let mut running = 7;
        let mut timed_out = 7;
        // SAFETY: null handles are explicitly accepted and writable outputs
        // are provided.
        let status =
            unsafe { mxc_io_try_wait(ptr::null_mut(), &mut exit, &mut running, &mut timed_out) };
        assert_eq!(status, MXC_STATUS_NULL_ARGUMENT);
    }

    #[test]
    fn native_stdio_output_is_initialized_before_handle_validation() {
        let mut stdio = MxcNativeStdio {
            stdin_handle: 5,
            stdout_handle: 6,
            stderr_handle: 7,
        };
        // SAFETY: null handles are explicitly accepted and `stdio` is writable.
        let status = unsafe { mxc_io_take_native_stdio(ptr::null_mut(), &mut stdio) };
        assert_eq!(status, MXC_STATUS_NULL_ARGUMENT);
        let invalid = MxcNativeStdio::invalid();
        assert_eq!(stdio.stdin_handle, invalid.stdin_handle);
        assert_eq!(stdio.stdout_handle, invalid.stdout_handle);
        assert_eq!(stdio.stderr_handle, invalid.stderr_handle);
    }
}
