// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! C translation layer for the engine-owned native I/O coordinator.

use std::collections::HashSet;
use std::ffi::{c_char, c_void, CStr};
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::ptr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::thread::{self, JoinHandle};
use std::time::Duration;

use mxc_engine::{IoCoordinator, IoReadState};

use crate::{
    alloc_cstring, request, status_from_error_code, MxcErrorDetail, MXC_STATUS_BACKEND_ERROR,
    MXC_STATUS_INVALID_UTF8, MXC_STATUS_NULL_ARGUMENT, MXC_STATUS_PANIC, MXC_STATUS_SUCCESS,
};

/// Output selector for [`mxc_io_request_read`] and [`mxc_io_close_output`].
pub const MXC_IO_STDOUT: i32 = 1;
/// Output selector for [`mxc_io_request_read`] and [`mxc_io_close_output`].
pub const MXC_IO_STDERR: i32 = 2;

/// Callback event containing stdout bytes.
pub const MXC_IO_EVENT_STDOUT: i32 = 1;
/// Callback event containing stderr bytes.
pub const MXC_IO_EVENT_STDERR: i32 = 2;
/// Callback event reporting stdout end-of-file.
pub const MXC_IO_EVENT_STDOUT_EOF: i32 = 3;
/// Callback event reporting stderr end-of-file.
pub const MXC_IO_EVENT_STDERR_EOF: i32 = 4;
/// Callback event completing a stdin operation.
pub const MXC_IO_EVENT_STDIN_COMPLETE: i32 = 5;
/// Callback event reporting process completion.
pub const MXC_IO_EVENT_EXIT: i32 = 6;
/// Callback event reporting an asynchronous coordinator failure.
pub const MXC_IO_EVENT_ERROR: i32 = 7;
/// Final callback event confirming that native callback production has stopped.
pub const MXC_IO_EVENT_SHUTDOWN: i32 = 8;

const EVENT_POLL_INTERVAL: Duration = Duration::from_millis(1);
const EVENT_BUFFER_BYTES: usize = 16 * 1024;

/// Native event callback used by event-loop language bindings.
///
/// `operation` identifies stdin operations, `data`/`len` carry output bytes,
/// and `value`/`flag` carry event-specific scalar values.
pub type MxcIoEventCallback = unsafe extern "C" fn(
    user_data: *mut c_void,
    event: i32,
    operation: u32,
    data: *const u8,
    len: usize,
    value: i64,
    flag: i32,
);

struct EventPumpState {
    callback: MxcIoEventCallback,
    user_data: usize,
    stdout_requested: AtomicBool,
    stderr_requested: AtomicBool,
    operations: Mutex<HashSet<u32>>,
    shutdown_requested: AtomicBool,
}

/// Opaque coordinator handle for event-loop language bindings.
pub struct MxcIoCoordinator {
    inner: Arc<IoCoordinator>,
    events: Arc<EventPumpState>,
    event_thread: Mutex<Option<JoinHandle<()>>>,
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

fn lock_unpoisoned<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// Spawn a sandbox and deliver native I/O completions through `callback`.
///
/// The callback may be invoked from the coordinator's event thread until a
/// [`MXC_IO_EVENT_SHUTDOWN`] event is delivered. The caller must keep the
/// callback and `user_data` alive until then.
///
/// # Safety
/// - `request_json_utf8` must be null or valid NUL-terminated UTF-8.
/// - `callback` must remain valid for the complete callback lifetime.
/// - `user_data` must remain valid for every callback invocation.
/// - `out_handle` must point to writable pointer storage holding no live handle.
/// - `out_error` must be null or writable fresh [`MxcErrorDetail`] storage.
#[no_mangle]
pub unsafe extern "C" fn mxc_io_spawn_request_callback(
    request_json_utf8: *const c_char,
    callback: Option<MxcIoEventCallback>,
    user_data: *mut c_void,
    out_handle: *mut *mut MxcIoCoordinator,
    out_error: *mut MxcErrorDetail,
) -> i32 {
    unsafe {
        spawn_callback(
            "mxc_io_spawn_request_callback",
            request_json_utf8,
            callback,
            user_data,
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

/// Execute a state-aware `exec` request and deliver native I/O completions
/// through `callback`.
///
/// This is the lifecycle counterpart to [`mxc_io_spawn_request_callback`].
/// The request must be an `exec` phase and reference an already-provisioned
/// sandbox.
///
/// # Safety
/// The pointer and callback lifetime requirements are identical to
/// [`mxc_io_spawn_request_callback`].
#[no_mangle]
pub unsafe extern "C" fn mxc_io_state_aware_exec_callback(
    request_json_utf8: *const c_char,
    experimental: i32,
    callback: Option<MxcIoEventCallback>,
    user_data: *mut c_void,
    out_handle: *mut *mut MxcIoCoordinator,
    out_error: *mut MxcErrorDetail,
) -> i32 {
    unsafe {
        spawn_callback(
            "mxc_io_state_aware_exec_callback",
            request_json_utf8,
            callback,
            user_data,
            out_handle,
            out_error,
            |request_json| {
                let process = mxc_engine::exec_state_aware_json(request_json, experimental != 0)
                    .map_err(|error| sdk_error_detail(&error))?;
                Ok(mxc_engine::coordinate_io(process, None))
            },
        )
    }
}

unsafe fn spawn_callback(
    operation: &str,
    request_json_utf8: *const c_char,
    callback: Option<MxcIoEventCallback>,
    user_data: *mut c_void,
    out_handle: *mut *mut MxcIoCoordinator,
    out_error: *mut MxcErrorDetail,
    spawn: impl FnOnce(&str) -> Result<IoCoordinator, (i32, MxcErrorDetail)>,
) -> i32 {
    let Some(callback) = callback else {
        return MXC_STATUS_NULL_ARGUMENT;
    };
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
            // SAFETY: the caller contract guarantees a valid C string.
            unsafe { CStr::from_ptr(request_json_utf8) }
                .to_str()
                .map_err(|_| {
                    (
                        MXC_STATUS_INVALID_UTF8,
                        MxcErrorDetail::from_message("request JSON is not UTF-8"),
                    )
                })?
        };
        let coordinator = spawn(request_json)?;
        let inner = Arc::new(coordinator);
        let events = Arc::new(EventPumpState {
            callback,
            user_data: user_data as usize,
            stdout_requested: AtomicBool::new(false),
            stderr_requested: AtomicBool::new(false),
            operations: Mutex::new(HashSet::new()),
            shutdown_requested: AtomicBool::new(false),
        });
        let event_thread = {
            let coordinator = Arc::clone(&inner);
            let events = Arc::clone(&events);
            thread::spawn(move || run_event_pump(coordinator, events))
        };
        Ok(MxcIoCoordinator {
            inner,
            events,
            event_thread: Mutex::new(Some(event_thread)),
        })
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
            unsafe { *out_handle = Box::into_raw(Box::new(coordinator)) };
            MXC_STATUS_SUCCESS
        }
        Err((status, mut detail)) => {
            if out_error.is_null() {
                detail.free_strings();
            } else {
                // SAFETY: `out_error` is caller-guaranteed writable fresh storage.
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

fn emit_event(
    events: &EventPumpState,
    event: i32,
    operation: u32,
    data: &[u8],
    value: i64,
    flag: i32,
) {
    // SAFETY: the callback registration contract keeps the callback and user
    // data alive until the final shutdown event returns.
    unsafe {
        (events.callback)(
            events.user_data as *mut c_void,
            event,
            operation,
            data.as_ptr(),
            data.len(),
            value,
            flag,
        );
    }
}

fn pump_output(
    coordinator: &IoCoordinator,
    events: &EventPumpState,
    stream: i32,
    buffer: &mut [u8],
) {
    let requested = match stream {
        MXC_IO_STDOUT => &events.stdout_requested,
        MXC_IO_STDERR => &events.stderr_requested,
        _ => return,
    };
    if !requested.swap(false, Ordering::AcqRel) {
        return;
    }

    let state = match stream {
        MXC_IO_STDOUT => coordinator.try_read_stdout(buffer),
        MXC_IO_STDERR => coordinator.try_read_stderr(buffer),
        _ => return,
    };
    match state {
        Ok(IoReadState::Pending) => requested.store(true, Ordering::Release),
        Ok(IoReadState::Data(read)) => emit_event(
            events,
            if stream == MXC_IO_STDOUT {
                MXC_IO_EVENT_STDOUT
            } else {
                MXC_IO_EVENT_STDERR
            },
            0,
            &buffer[..read],
            0,
            0,
        ),
        Ok(IoReadState::Eof) => emit_event(
            events,
            if stream == MXC_IO_STDOUT {
                MXC_IO_EVENT_STDOUT_EOF
            } else {
                MXC_IO_EVENT_STDERR_EOF
            },
            0,
            &[],
            0,
            0,
        ),
        Err(_) => emit_event(events, MXC_IO_EVENT_ERROR, stream as u32, &[], 0, 0),
    }
}

fn run_event_pump(coordinator: Arc<IoCoordinator>, events: Arc<EventPumpState>) {
    let mut output = vec![0_u8; EVENT_BUFFER_BYTES];
    let mut process_complete = false;
    loop {
        pump_output(&coordinator, &events, MXC_IO_STDOUT, output.as_mut_slice());
        pump_output(&coordinator, &events, MXC_IO_STDERR, output.as_mut_slice());

        let operations: Vec<_> = lock_unpoisoned(&events.operations)
            .iter()
            .copied()
            .collect();
        for operation in operations {
            let Some(result) = coordinator.poll_stdin(operation) else {
                continue;
            };
            lock_unpoisoned(&events.operations).remove(&operation);
            match result {
                Ok(written) => emit_event(
                    &events,
                    MXC_IO_EVENT_STDIN_COMPLETE,
                    operation,
                    &[],
                    written as i64,
                    1,
                ),
                Err(_) => emit_event(&events, MXC_IO_EVENT_STDIN_COMPLETE, operation, &[], 0, 0),
            }
        }

        if !process_complete {
            match coordinator.poll_process() {
                Ok(status) if !status.running => {
                    process_complete = true;
                    emit_event(
                        &events,
                        MXC_IO_EVENT_EXIT,
                        0,
                        &[],
                        i64::from(status.exit_code),
                        i32::from(status.timed_out),
                    );
                }
                Ok(_) => {}
                Err(_) => {
                    process_complete = true;
                    emit_event(&events, MXC_IO_EVENT_ERROR, 0, &[], 0, 0);
                }
            }
        }

        if events.shutdown_requested.load(Ordering::Acquire)
            && process_complete
            && lock_unpoisoned(&events.operations).is_empty()
        {
            emit_event(&events, MXC_IO_EVENT_SHUTDOWN, 0, &[], 0, 0);
            return;
        }
        thread::sleep(EVENT_POLL_INTERVAL);
    }
}

/// Return the child process identifier, or zero for an invalid handle.
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

/// Report whether the sandbox exposes stdin.
#[no_mangle]
pub unsafe extern "C" fn mxc_io_has_stdin(handle: *mut MxcIoCoordinator) -> i32 {
    catch_boolean("mxc_io_has_stdin", || {
        coordinator_ref(handle).is_some_and(|coordinator| coordinator.inner.has_stdin())
    })
}

/// Report whether the sandbox exposes stdout.
#[no_mangle]
pub unsafe extern "C" fn mxc_io_has_stdout(handle: *mut MxcIoCoordinator) -> i32 {
    catch_boolean("mxc_io_has_stdout", || {
        coordinator_ref(handle).is_some_and(|coordinator| coordinator.inner.has_stdout())
    })
}

/// Report whether the sandbox exposes stderr.
#[no_mangle]
pub unsafe extern "C" fn mxc_io_has_stderr(handle: *mut MxcIoCoordinator) -> i32 {
    catch_boolean("mxc_io_has_stderr", || {
        coordinator_ref(handle).is_some_and(|coordinator| coordinator.inner.has_stderr())
    })
}

fn catch_boolean(operation: &str, body: impl FnOnce() -> bool) -> i32 {
    catch_unwind(AssertUnwindSafe(body))
        .map(i32::from)
        .unwrap_or_else(|panic| {
            crate::report_panic(operation, &*panic);
            0
        })
}

/// Queue a process-tree kill and return immediately.
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

/// Request process and stream shutdown without releasing the caller's handle.
#[no_mangle]
pub unsafe extern "C" fn mxc_io_request_shutdown(handle: *mut MxcIoCoordinator) -> i32 {
    catch_status("mxc_io_request_shutdown", || {
        let Some(coordinator) = coordinator_ref(handle) else {
            return MXC_STATUS_NULL_ARGUMENT;
        };
        coordinator
            .events
            .shutdown_requested
            .store(true, Ordering::Release);
        coordinator.inner.request_shutdown();
        MXC_STATUS_SUCCESS
    })
}

/// Request delivery of one output chunk or end-of-file event.
#[no_mangle]
pub unsafe extern "C" fn mxc_io_request_read(handle: *mut MxcIoCoordinator, stream: i32) -> i32 {
    catch_status("mxc_io_request_read", || {
        let Some(coordinator) = coordinator_ref(handle) else {
            return MXC_STATUS_NULL_ARGUMENT;
        };
        match stream {
            MXC_IO_STDOUT => coordinator
                .events
                .stdout_requested
                .store(true, Ordering::Release),
            MXC_IO_STDERR => coordinator
                .events
                .stderr_requested
                .store(true, Ordering::Release),
            _ => return MXC_STATUS_NULL_ARGUMENT,
        }
        MXC_STATUS_SUCCESS
    })
}

/// Close and discard one output stream without blocking.
#[no_mangle]
pub unsafe extern "C" fn mxc_io_close_output(handle: *mut MxcIoCoordinator, stream: i32) -> i32 {
    catch_status("mxc_io_close_output", || {
        let Some(coordinator) = coordinator_ref(handle) else {
            return MXC_STATUS_NULL_ARGUMENT;
        };
        match stream {
            MXC_IO_STDOUT => coordinator.inner.close_stdout(),
            MXC_IO_STDERR => coordinator.inner.close_stderr(),
            _ => return MXC_STATUS_NULL_ARGUMENT,
        }
        MXC_STATUS_SUCCESS
    })
}

/// Queue a bounded stdin write.
///
/// # Safety
/// `buf` must address `len` readable bytes and `out_operation` must be writable.
#[no_mangle]
pub unsafe extern "C" fn mxc_io_start_write(
    handle: *mut MxcIoCoordinator,
    buf: *const u8,
    len: usize,
    out_operation: *mut u32,
) -> i32 {
    catch_status("mxc_io_start_write", || {
        if handle.is_null() || buf.is_null() || out_operation.is_null() {
            return MXC_STATUS_NULL_ARGUMENT;
        }
        // SAFETY: `out_operation` is caller-guaranteed writable.
        unsafe { *out_operation = 0 };
        let Some(coordinator) = coordinator_ref(handle) else {
            return MXC_STATUS_NULL_ARGUMENT;
        };
        // SAFETY: `buf` addresses `len` readable bytes by caller contract.
        let bytes = unsafe { std::slice::from_raw_parts(buf, len) };
        match coordinator.inner.start_write(bytes) {
            Ok(operation) => {
                if let Some(operation) = operation {
                    lock_unpoisoned(&coordinator.events.operations).insert(operation);
                }
                // SAFETY: `out_operation` is caller-guaranteed writable.
                unsafe { *out_operation = operation.unwrap_or(0) };
                MXC_STATUS_SUCCESS
            }
            Err(_) => MXC_STATUS_BACKEND_ERROR,
        }
    })
}

/// Queue a stdin flush.
///
/// # Safety
/// `out_operation` must be non-null and writable.
#[no_mangle]
pub unsafe extern "C" fn mxc_io_start_flush(
    handle: *mut MxcIoCoordinator,
    out_operation: *mut u32,
) -> i32 {
    catch_status("mxc_io_start_flush", || {
        if handle.is_null() || out_operation.is_null() {
            return MXC_STATUS_NULL_ARGUMENT;
        }
        // SAFETY: `out_operation` is caller-guaranteed writable.
        unsafe { *out_operation = 0 };
        let Some(coordinator) = coordinator_ref(handle) else {
            return MXC_STATUS_NULL_ARGUMENT;
        };
        match coordinator.inner.start_flush() {
            Ok(operation) => {
                if let Some(operation) = operation {
                    lock_unpoisoned(&coordinator.events.operations).insert(operation);
                }
                // SAFETY: `out_operation` is caller-guaranteed writable.
                unsafe { *out_operation = operation.unwrap_or(0) };
                MXC_STATUS_SUCCESS
            }
            Err(_) => MXC_STATUS_BACKEND_ERROR,
        }
    })
}

/// Close stdin after all accepted writes.
#[no_mangle]
pub unsafe extern "C" fn mxc_io_close_stdin(handle: *mut MxcIoCoordinator) -> i32 {
    catch_status("mxc_io_close_stdin", || {
        let Some(coordinator) = coordinator_ref(handle) else {
            return MXC_STATUS_NULL_ARGUMENT;
        };
        coordinator.inner.close_stdin();
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

/// Request native shutdown and release the caller's coordinator handle.
///
/// Callback-backed coordinators are reaped on a native thread so this call
/// never blocks the JavaScript event loop waiting for a callback that Koffi
/// must deliver on that same event loop.
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
        let coordinator = unsafe { Box::from_raw(handle) };
        coordinator.inner.request_shutdown();
        coordinator
            .events
            .shutdown_requested
            .store(true, Ordering::Release);
        let event_thread = lock_unpoisoned(&coordinator.event_thread).take();
        if let Some(event_thread) = event_thread {
            thread::spawn(move || {
                let _ = event_thread.join();
                drop(coordinator);
            });
        } else {
            drop(coordinator);
        }
    })) {
        crate::report_panic("mxc_io_free", &*panic);
    }
}
