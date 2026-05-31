// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Pipe relay primitives used by the IsolationSession backend to bridge
//! wxc-exec's stdio with the agent process's pipe handles across the
//! desktop-session boundary.
//!
//! Two relay variants:
//! - [`create_relay_thread`] — EOF-driven; used for stdout / stderr.
//! - [`create_relay_thread_with_stop`] — stop-event-aware; used for stdin
//!   in TTY (ConPTY) mode where the agent can exit while the local stdin
//!   handle remains open.

use crate::error::WxcError;
use crate::process_util::OwnedHandle;

use windows::Win32::Foundation::{HANDLE, WAIT_OBJECT_0};
use windows::Win32::Storage::FileSystem::{FlushFileBuffers, ReadFile, WriteFile};
use windows::Win32::System::Threading::{
    CreateThread, WaitForMultipleObjects, THREAD_CREATION_FLAGS,
};

const BUFFER_SIZE: u32 = 4096;

/// Parameters for a pipe relay thread. The thread reads from `h_read` and
/// writes every chunk to `h_write`, flushing after each write.
///
/// # Safety
/// The caller **must** keep this struct alive until the relay thread exits
/// (i.e. wait for the thread handle before dropping the params).
#[repr(C)]
pub(super) struct PipeRelayParams {
    pub h_read: HANDLE,
    pub h_write: HANDLE,
}

/// Thread procedure for relaying data between two handles.
///
/// # Safety
/// `param` must point to a valid `PipeRelayParams` that outlives the thread.
unsafe extern "system" fn pipe_relay_thread_proc(param: *mut core::ffi::c_void) -> u32 {
    let params = &*(param as *const PipeRelayParams);
    let mut buffer = [0u8; BUFFER_SIZE as usize];

    loop {
        let mut bytes_read = 0u32;
        if ReadFile(
            params.h_read,
            Some(&mut buffer),
            Some(&mut bytes_read),
            None,
        )
        .is_err()
            || bytes_read == 0
        {
            break;
        }

        let mut bytes_written = 0u32;
        if WriteFile(
            params.h_write,
            Some(&buffer[..bytes_read as usize]),
            Some(&mut bytes_written),
            None,
        )
        .is_err()
            || bytes_written != bytes_read
        {
            break;
        }

        let _ = FlushFileBuffers(params.h_write);
    }

    0
}

/// Create a relay thread via `CreateThread`. Returns the thread HANDLE
/// wrapped in `OwnedHandle`.
///
/// # Safety
/// `params` must remain valid until the thread exits. The caller is
/// responsible for joining (waiting on) the thread before `params` is dropped.
pub(super) unsafe fn create_relay_thread(
    params: *mut PipeRelayParams,
) -> Result<OwnedHandle, WxcError> {
    let handle = CreateThread(
        None,
        0,
        Some(pipe_relay_thread_proc),
        Some(params as *const core::ffi::c_void),
        THREAD_CREATION_FLAGS(0),
        None,
    )
    .map_err(|e| WxcError::Process(format!("CreateThread for pipe relay failed: {}", e)))?;

    Ok(OwnedHandle::new(handle))
}

// ── Stop-event-aware pipe relay ────────────────────────────────────────────
//
// Used for the IsolationSession stdin relay in TTY (ConPTY) mode, where the
// agent process can exit naturally while wxc-exec's stdin remains open (held
// by the parent: node-pty, shell, etc.). Without an external signal the relay
// sits in `ReadFile` forever.
//
// `CancelSynchronousIo` is the obvious alternative but has documented edge
// cases on console handles, and wxc-exec's stdin is a console handle in the
// dominant `spawnSandbox` (node-pty) and direct-cmd cases.
//
// `h_read` MUST be a waitable handle whose signal state correctly reflects
// "input available" (a console input handle is the canonical case; events
// also work). Anonymous pipe handles are NOT supported: they appear "always
// signalled when open", so the wait returns immediately, the relay enters
// `ReadFile`, and from there the stop event cannot interrupt it. For
// pipe-backed stdin (the non-TTY case), use the simpler EOF-driven
// `create_relay_thread` and rely on natural EOF or process exit for cleanup.

/// Parameters for a stop-event-aware relay thread. The thread loops
/// `WaitForMultipleObjects({h_stop_event, h_read})`; copies a chunk when
/// `h_read` is ready; exits when `h_stop_event` is signalled, on read EOF,
/// on read error, on write error, or on `WaitForMultipleObjects` failure.
///
/// `h_stop_event` should be a manual-reset event so the relay observes it
/// even if signalled before the next loop iteration.
///
/// `h_read` must be a waitable handle (console input, event). Anonymous
/// pipes are not supported — see module-level comment above.
///
/// # Safety
/// All three handles must remain valid until the relay thread exits. The
/// struct must outlive the thread (caller waits on the thread before dropping
/// `params`).
#[repr(C)]
pub(super) struct PipeRelayWithStopParams {
    pub h_read: HANDLE,
    pub h_write: HANDLE,
    pub h_stop_event: HANDLE,
}

/// Thread procedure for a stop-event-aware relay.
///
/// # Safety
/// `param` must point to a valid `PipeRelayWithStopParams` that outlives the
/// thread.
unsafe extern "system" fn pipe_relay_with_stop_thread_proc(param: *mut core::ffi::c_void) -> u32 {
    let params = &*(param as *const PipeRelayWithStopParams);
    let mut buffer = [0u8; BUFFER_SIZE as usize];
    let wait_handles = [params.h_stop_event, params.h_read];

    loop {
        let wait_result = WaitForMultipleObjects(&wait_handles, false, u32::MAX);
        // `WAIT_OBJECT_0 + 1` means `h_read` signalled (data available or EOF).
        // Anything else (stop event = `WAIT_OBJECT_0`, `WAIT_FAILED`, etc.) → exit.
        if wait_result.0 != WAIT_OBJECT_0.0 + 1 {
            break;
        }

        let mut bytes_read = 0u32;
        if ReadFile(
            params.h_read,
            Some(&mut buffer),
            Some(&mut bytes_read),
            None,
        )
        .is_err()
            || bytes_read == 0
        {
            break;
        }

        let mut bytes_written = 0u32;
        if WriteFile(
            params.h_write,
            Some(&buffer[..bytes_read as usize]),
            Some(&mut bytes_written),
            None,
        )
        .is_err()
            || bytes_written != bytes_read
        {
            break;
        }

        let _ = FlushFileBuffers(params.h_write);
    }

    0
}

/// Create a stop-event-aware relay thread via `CreateThread`. Returns the
/// thread HANDLE wrapped in `OwnedHandle`.
///
/// # Safety
/// `params` must remain valid until the thread exits. The caller is
/// responsible for joining (waiting on) the thread before `params` is dropped.
pub(super) unsafe fn create_relay_thread_with_stop(
    params: *mut PipeRelayWithStopParams,
) -> Result<OwnedHandle, WxcError> {
    let handle = CreateThread(
        None,
        0,
        Some(pipe_relay_with_stop_thread_proc),
        Some(params as *const core::ffi::c_void),
        THREAD_CREATION_FLAGS(0),
        None,
    )
    .map_err(|e| {
        WxcError::Process(format!(
            "CreateThread for stop-aware pipe relay failed: {}",
            e
        ))
    })?;

    Ok(OwnedHandle::new(handle))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::process_util::{create_std_pipes, read_from_pipe, SendOwnedHandle};
    use crate::string_util;
    use windows::Win32::System::Pipes::CreatePipe;
    use windows::Win32::System::Threading::{
        CreateEventW, CreateProcessW, SetEvent, WaitForSingleObject, CREATE_NO_WINDOW,
        PROCESS_INFORMATION, STARTF_USESTDHANDLES, STARTUPINFOW,
    };
    use windows_core::{PCWSTR, PWSTR};

    /// Creates a non-inheritable pipe pair for use in tests. Unlike
    /// `create_std_pipes`, neither end is marked inheritable, which prevents
    /// handles from leaking into child processes spawned by other tests
    /// running concurrently (cargo test runs in parallel). Leaked write-ends
    /// would keep pipes open and cause `read_from_pipe` to block.
    fn create_test_pipes() -> (OwnedHandle, OwnedHandle) {
        let mut h_read = HANDLE::default();
        let mut h_write = HANDLE::default();
        unsafe {
            CreatePipe(&mut h_read, &mut h_write, None, 0).unwrap();
        }
        (OwnedHandle::new(h_read), OwnedHandle::new(h_write))
    }

    /// Helper: create a manual-reset, initially-unsignalled event for tests.
    fn create_test_stop_event() -> OwnedHandle {
        unsafe {
            let h = CreateEventW(None, true, false, PCWSTR::null()).unwrap();
            OwnedHandle::new(h)
        }
    }

    /// Helper: spawn a child process with specified std handles.
    /// Returns (process_handle, thread_handle).
    fn spawn_child(
        cmd: &str,
        stdin: Option<HANDLE>,
        stdout: Option<HANDLE>,
        stderr: Option<HANDLE>,
    ) -> (OwnedHandle, OwnedHandle) {
        let si = STARTUPINFOW {
            cb: std::mem::size_of::<STARTUPINFOW>() as u32,
            dwFlags: STARTF_USESTDHANDLES,
            hStdInput: stdin.unwrap_or_default(),
            hStdOutput: stdout.unwrap_or_default(),
            hStdError: stderr.unwrap_or_default(),
            ..Default::default()
        };
        let mut pi = PROCESS_INFORMATION::default();
        let mut cmd_wide = string_util::to_wide(cmd);

        unsafe {
            CreateProcessW(
                PCWSTR::null(),
                Some(PWSTR(cmd_wide.as_mut_ptr())),
                None,
                None,
                true,
                CREATE_NO_WINDOW,
                None,
                PCWSTR::null(),
                &si,
                &mut pi,
            )
            .unwrap();
        }
        (OwnedHandle::new(pi.hProcess), OwnedHandle::new(pi.hThread))
    }

    #[test]
    fn test_pipe_relay_copies_data() {
        // Create two pipe pairs: source and destination.
        // Relay thread reads from source_read and writes to dest_write.
        // We write to source_write and read from dest_read to verify the relay.
        let (source_read, source_write) = create_test_pipes();
        let (mut dest_read, dest_write) = create_test_pipes();

        let mut params = PipeRelayParams {
            h_read: source_read.get(),
            h_write: dest_write.get(),
        };

        let relay_thread = unsafe { create_relay_thread(&mut params).unwrap() };

        // Read from dest concurrently — the relay calls FlushFileBuffers after
        // each write, which blocks until the reader drains the pipe buffer.
        // Without a concurrent reader the relay and main thread deadlock.
        let dest_send = SendOwnedHandle::take(&mut dest_read);
        let reader = std::thread::spawn(move || read_from_pipe(dest_send.get()));

        // Write test data to the source pipe
        let test_data = b"Hello from relay test!";
        let mut bytes_written = 0u32;
        unsafe {
            WriteFile(
                source_write.get(),
                Some(test_data),
                Some(&mut bytes_written),
                None,
            )
            .unwrap();
        }

        // Close the source write end to signal EOF to the relay thread.
        // drop() calls CloseHandle via OwnedHandle::Drop.
        drop(source_write);

        // Wait for relay thread to finish
        unsafe {
            WaitForSingleObject(relay_thread.get(), 5000);
        }

        // Close the dest write end so the reader sees EOF
        drop(dest_write);

        let output = reader.join().unwrap();
        assert_eq!(output, "Hello from relay test!");
    }

    #[test]
    fn test_pipe_relay_handles_large_data() {
        let (source_read, mut source_write) = create_test_pipes();
        let (mut dest_read, dest_write) = create_test_pipes();

        let mut params = PipeRelayParams {
            h_read: source_read.get(),
            h_write: dest_write.get(),
        };

        let relay_thread = unsafe { create_relay_thread(&mut params).unwrap() };

        // Write data larger than the pipe buffer (4096 bytes default).
        // Use ASCII to avoid from_utf8_lossy expansion of invalid bytes.
        let test_data: Vec<u8> = (0..10000).map(|i| b'A' + (i % 26) as u8).collect();
        let write_data = test_data.clone();
        let expected_len = test_data.len();

        // Read from dest in a concurrent thread to prevent deadlock —
        // the relay's WriteFile would block if the dest pipe buffer fills.
        let dest_send = SendOwnedHandle::take(&mut dest_read);
        let reader = std::thread::spawn(move || read_from_pipe(dest_send.get()));

        // Write in a separate thread (pipe buffer can fill between write and relay).
        let send_write = SendOwnedHandle::take(&mut source_write);
        let writer = std::thread::spawn(move || {
            let mut bytes_written = 0u32;
            unsafe {
                let _ = WriteFile(
                    send_write.get(),
                    Some(&write_data),
                    Some(&mut bytes_written),
                    None,
                );
            }
            // SendOwnedHandle::Drop closes the handle, signaling EOF.
            drop(send_write);
        });

        writer.join().unwrap();
        // Wait for relay thread to finish (source EOF propagated)
        unsafe {
            WaitForSingleObject(relay_thread.get(), 5000);
        }
        // Close the dest write end so the reader sees EOF
        drop(dest_write);

        let output = reader.join().unwrap();
        assert_eq!(output.len(), expected_len);
    }

    /// Tests the production pattern: relay a child process's stdout to the
    /// parent. Mirrors the wxc-exec scenario where Process B writes output
    /// and the relay copies it for Process A to read.
    #[test]
    fn test_pipe_relay_child_stdout() {
        // child_stdout: inheritable write end (child writes here)
        let (child_stdout_read, child_stdout_write) = create_std_pipes(true).unwrap();
        // dest: non-inheritable (only the test reads here)
        let (mut dest_read, dest_write) = create_test_pipes();

        let mut params = PipeRelayParams {
            h_read: child_stdout_read.get(),
            h_write: dest_write.get(),
        };
        let relay_thread = unsafe { create_relay_thread(&mut params).unwrap() };

        // Concurrent reader to avoid FlushFileBuffers deadlock
        let dest_send = SendOwnedHandle::take(&mut dest_read);
        let reader = std::thread::spawn(move || read_from_pipe(dest_send.get()));

        let (child, _child_thread) = spawn_child(
            "cmd.exe /c echo hello from child process",
            None,
            Some(child_stdout_write.get()),
            None,
        );

        // Close parent's copy — child and relay still have theirs
        drop(child_stdout_write);

        // Child exits → last write-end closes → relay sees EOF → relay exits
        unsafe {
            WaitForSingleObject(child.get(), 10000);
            WaitForSingleObject(relay_thread.get(), 5000);
        }

        // Close relay's dest write so reader sees EOF
        drop(dest_write);

        let output = reader.join().unwrap();
        assert!(
            output.trim().contains("hello from child process"),
            "Expected child output relayed to dest, got: {:?}",
            output
        );
    }

    /// Tests the production pattern: relay data from the parent into a
    /// child process's stdin. Mirrors the wxc-exec scenario where Process A
    /// sends input that the relay copies to Process B's stdin.
    #[test]
    fn test_pipe_relay_child_stdin() {
        // source: non-inheritable (test writes here)
        let (source_read, source_write) = create_test_pipes();
        // child_stdin: inheritable read end (child reads from here)
        let (child_stdin_read, child_stdin_write) = create_std_pipes(false).unwrap();
        // child_stdout: inheritable write end (to capture child output)
        let (mut child_stdout_read, child_stdout_write) = create_std_pipes(true).unwrap();

        // Relay: test input → child stdin
        let mut params = PipeRelayParams {
            h_read: source_read.get(),
            h_write: child_stdin_write.get(),
        };
        let relay_thread = unsafe { create_relay_thread(&mut params).unwrap() };

        // findstr /R "." echoes all non-empty lines from stdin to stdout
        let (child, _child_thread) = spawn_child(
            "cmd.exe /c findstr /R \".\"",
            Some(child_stdin_read.get()),
            Some(child_stdout_write.get()),
            None,
        );

        // Close parent copies of child-side handles
        drop(child_stdin_read);
        drop(child_stdout_write);

        // Read child stdout concurrently
        let stdout_send = SendOwnedHandle::take(&mut child_stdout_read);
        let reader = std::thread::spawn(move || read_from_pipe(stdout_send.get()));

        // Write data through: test → source → relay → child stdin
        let mut bw = 0u32;
        unsafe {
            WriteFile(
                source_write.get(),
                Some(b"relayed to child\r\n"),
                Some(&mut bw),
                None,
            )
            .unwrap();
        }
        // Close source → relay sees EOF → relay exits
        drop(source_write);

        unsafe {
            WaitForSingleObject(relay_thread.get(), 5000);
        }

        // Close child_stdin_write → child sees EOF → child exits
        drop(child_stdin_write);

        unsafe {
            WaitForSingleObject(child.get(), 10000);
        }

        let output = reader.join().unwrap();
        assert!(
            output.contains("relayed to child"),
            "Expected relayed input in child output, got: {:?}",
            output
        );
    }

    // ── Tests for `create_relay_thread_with_stop` ──────────────────────────
    //
    // These exercise the stop-event-aware relay variant. Cancellation (test #1)
    // is the load-bearing case: it's the reason this primitive exists and
    // distinguishes it from the EOF-driven `create_relay_thread`.

    #[test]
    fn test_pipe_relay_with_stop_exits_on_stop_event() {
        // Core cancellation case: relay is blocked in WaitForMultipleObjects
        // (no data on h_read, h_read not closed). Signal the stop event;
        // verify the relay exits within a short timeout.
        let (source_read, _source_write) = create_test_pipes();
        let (mut dest_read, dest_write) = create_test_pipes();
        let stop_event = create_test_stop_event();

        let mut params = PipeRelayWithStopParams {
            h_read: source_read.get(),
            h_write: dest_write.get(),
            h_stop_event: stop_event.get(),
        };
        let relay_thread = unsafe { create_relay_thread_with_stop(&mut params).unwrap() };

        // Source has no data and is not closed → relay sits in
        // WaitForMultipleObjects. Without the stop event it would hang.
        unsafe {
            SetEvent(stop_event.get()).unwrap();
        }

        let wait_result = unsafe { WaitForSingleObject(relay_thread.get(), 5000) };
        assert_eq!(
            wait_result, WAIT_OBJECT_0,
            "Relay did not exit within 5s of stop event"
        );

        // Drain the dest pipe so its handles can drop cleanly.
        drop(dest_write);
        let dest_send = SendOwnedHandle::take(&mut dest_read);
        let _ = std::thread::spawn(move || read_from_pipe(dest_send.get())).join();
    }

    #[test]
    fn test_pipe_relay_with_stop_exits_on_read_eof() {
        // Stop event never signalled; source closed → read EOF → relay exits.
        let (source_read, source_write) = create_test_pipes();
        let (mut dest_read, dest_write) = create_test_pipes();
        let stop_event = create_test_stop_event();

        let mut params = PipeRelayWithStopParams {
            h_read: source_read.get(),
            h_write: dest_write.get(),
            h_stop_event: stop_event.get(),
        };
        let relay_thread = unsafe { create_relay_thread_with_stop(&mut params).unwrap() };

        // Concurrent reader (no-op here, but defensive in case data flows on
        // any FlushFileBuffers iteration; avoids any pipe-buffer deadlock).
        let dest_send = SendOwnedHandle::take(&mut dest_read);
        let reader = std::thread::spawn(move || read_from_pipe(dest_send.get()));

        // Close source write end → relay's read returns EOF → break.
        drop(source_write);

        let wait_result = unsafe { WaitForSingleObject(relay_thread.get(), 5000) };
        assert_eq!(wait_result, WAIT_OBJECT_0, "Relay did not exit on read EOF");

        drop(dest_write);
        let _ = reader.join();
    }

    #[test]
    fn test_pipe_relay_with_stop_copies_data_before_exit() {
        // Stop event never signalled; data is written; verify it is copied.
        let (source_read, source_write) = create_test_pipes();
        let (mut dest_read, dest_write) = create_test_pipes();
        let stop_event = create_test_stop_event();

        let mut params = PipeRelayWithStopParams {
            h_read: source_read.get(),
            h_write: dest_write.get(),
            h_stop_event: stop_event.get(),
        };
        let relay_thread = unsafe { create_relay_thread_with_stop(&mut params).unwrap() };

        // Concurrent reader to avoid FlushFileBuffers deadlock.
        let dest_send = SendOwnedHandle::take(&mut dest_read);
        let reader = std::thread::spawn(move || read_from_pipe(dest_send.get()));

        let test_data = b"hello via stop-aware relay";
        let mut bytes_written = 0u32;
        unsafe {
            WriteFile(
                source_write.get(),
                Some(test_data),
                Some(&mut bytes_written),
                None,
            )
            .unwrap();
        }
        drop(source_write); // EOF → relay exits.

        let wait_result = unsafe { WaitForSingleObject(relay_thread.get(), 5000) };
        assert_eq!(wait_result, WAIT_OBJECT_0);

        drop(dest_write);
        let output = reader.join().unwrap();
        assert_eq!(output, "hello via stop-aware relay");
    }

    // Note: a "signal-stop-mid-data" test using anonymous pipes is not viable —
    // anonymous pipe handles appear always-signalled to WaitForMultipleObjects,
    // so once the relay returns from the wait into ReadFile, the stop event
    // cannot interrupt the blocked read. The intended production usage is with
    // a console input handle (or other waitable handle) where signal state
    // accurately reflects data-available. The "stop-event-only" path
    // (test_pipe_relay_with_stop_exits_on_stop_event) and the "EOF-after-data"
    // path (test_pipe_relay_with_stop_copies_data_before_exit) together cover
    // the invariants that matter for the production case.

    #[test]
    fn test_pipe_relay_with_stop_exits_on_invalid_handle() {
        // Defensive path: pass a default (invalid) HANDLE for h_read.
        // WaitForMultipleObjects returns WAIT_FAILED → relay loop breaks →
        // thread exits cleanly. No panic, no hang.
        let (_, dest_write) = create_test_pipes();
        let stop_event = create_test_stop_event();

        let mut params = PipeRelayWithStopParams {
            h_read: HANDLE::default(), // invalid — not a kernel handle
            h_write: dest_write.get(),
            h_stop_event: stop_event.get(),
        };
        let relay_thread = unsafe { create_relay_thread_with_stop(&mut params).unwrap() };

        let wait_result = unsafe { WaitForSingleObject(relay_thread.get(), 5000) };
        assert_eq!(
            wait_result, WAIT_OBJECT_0,
            "Relay did not exit on invalid h_read"
        );
    }
}
