// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use crate::error::WxcError;
use crate::string_util;

use windows::Win32::Foundation::{
    CloseHandle, LocalFree, SetHandleInformation, HANDLE, HANDLE_FLAGS, HANDLE_FLAG_INHERIT,
    HLOCAL, WAIT_OBJECT_0,
};
use windows::Win32::Security::{DeriveCapabilitySidsFromName, PSID, SECURITY_ATTRIBUTES};
use windows::Win32::Storage::FileSystem::{FlushFileBuffers, ReadFile, WriteFile};
use windows::Win32::System::Pipes::CreatePipe;
use windows::Win32::System::Threading::{CreateThread, WaitForSingleObject, THREAD_CREATION_FLAGS};
use windows_core::BOOL;
use windows_core::PCWSTR;

const BUFFER_SIZE: u32 = 4096;
const MAX_OUTPUT_CHARS: usize = 1024 * 1024;

// ── Pipe relay infrastructure ──────────────────────────────────────────────

/// Parameters for a pipe relay thread. The thread reads from `h_read` and
/// writes every chunk to `h_write`, flushing after each write.
///
/// # Safety
/// The caller **must** keep this struct alive until the relay thread exits
/// (i.e. wait for the thread handle before dropping the params).
#[repr(C)]
pub struct PipeRelayParams {
    pub h_read: HANDLE,
    pub h_write: HANDLE,
}

/// Thread procedure for relaying data between two handles.
/// Matches the C++ `PipeThread` function exactly: read → write → flush loop.
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
pub unsafe fn create_relay_thread(params: *mut PipeRelayParams) -> Result<OwnedHandle, WxcError> {
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

/// Thread-safe owned handle wrapper that transfers HANDLE ownership across thread boundaries.
/// After construction the source `OwnedHandle` is invalidated, and this wrapper is
/// responsible for closing the handle on drop.
///
/// SAFETY: Windows HANDLEs are process-wide and safe to use from any thread.
pub struct SendOwnedHandle(isize);
unsafe impl Send for SendOwnedHandle {}

impl SendOwnedHandle {
    /// Takes ownership of the handle from an `OwnedHandle`.
    /// The original `OwnedHandle` is invalidated and will not close the handle.
    pub fn take(handle: &mut OwnedHandle) -> Self {
        Self(handle.take().0 as isize)
    }

    pub fn get(&self) -> HANDLE {
        HANDLE(self.0 as *mut core::ffi::c_void)
    }
}

impl Drop for SendOwnedHandle {
    fn drop(&mut self) {
        let h = HANDLE(self.0 as *mut core::ffi::c_void);
        if !h.is_invalid() && h != HANDLE::default() {
            unsafe {
                let _ = CloseHandle(h);
            }
        }
    }
}

/// RAII wrapper for a Windows HANDLE that calls CloseHandle on drop.
pub struct OwnedHandle(HANDLE);

impl OwnedHandle {
    pub fn new(h: HANDLE) -> Self {
        Self(h)
    }

    pub fn get(&self) -> HANDLE {
        self.0
    }

    pub fn take(&mut self) -> HANDLE {
        let h = self.0;
        self.0 = HANDLE::default();
        h
    }

    pub fn is_valid(&self) -> bool {
        !self.0.is_invalid() && self.0 != HANDLE::default()
    }
}

impl Drop for OwnedHandle {
    fn drop(&mut self) {
        if self.is_valid() {
            unsafe {
                let _ = CloseHandle(self.0);
            }
        }
    }
}

/// Read all data from a pipe as UTF-8 text, capped at 1MB of characters.
pub fn read_from_pipe(pipe: HANDLE) -> String {
    let mut result = String::with_capacity(BUFFER_SIZE as usize);
    let mut char_count: usize = 0;
    let mut buffer = [0u8; BUFFER_SIZE as usize];
    loop {
        let mut bytes_read = 0u32;
        let ok = unsafe { ReadFile(pipe, Some(&mut buffer), Some(&mut bytes_read), None) };
        if ok.is_err() || bytes_read == 0 {
            break;
        }
        let chunk = String::from_utf8_lossy(&buffer[..bytes_read as usize]);
        let remaining = MAX_OUTPUT_CHARS.saturating_sub(char_count);
        if remaining == 0 {
            break;
        }
        let chunk_char_count = chunk.chars().count();
        if chunk_char_count > remaining {
            // Take only up to `remaining` chars
            let truncated: String = chunk.chars().take(remaining).collect();
            result.push_str(&truncated);
            break;
        }
        result.push_str(&chunk);
        char_count += chunk_char_count;
    }
    result
}

/// Create a pair of pipe handles (read, write) with appropriate inheritance.
/// If `no_inherit_read` is true, the read end is made non-inheritable;
/// otherwise the write end is made non-inheritable.
pub fn create_std_pipes(no_inherit_read: bool) -> Result<(OwnedHandle, OwnedHandle), WxcError> {
    let sa = SECURITY_ATTRIBUTES {
        nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
        bInheritHandle: BOOL::from(true),
        lpSecurityDescriptor: std::ptr::null_mut(),
    };
    let mut h_read = HANDLE::default();
    let mut h_write = HANDLE::default();

    unsafe {
        CreatePipe(&mut h_read, &mut h_write, Some(&sa), 0)
            .map_err(|_| WxcError::Process("Failed to create pipe".into()))?;

        let h_dup = if no_inherit_read { h_read } else { h_write };
        SetHandleInformation(h_dup, HANDLE_FLAG_INHERIT.0, HANDLE_FLAGS(0)).map_err(|_| {
            let _ = CloseHandle(h_read);
            let _ = CloseHandle(h_write);
            WxcError::Process("Failed to set handle information on pipe".into())
        })?;
    }

    Ok((OwnedHandle::new(h_read), OwnedHandle::new(h_write)))
}

/// Remove a specific Python "Failed to find real location of ..." line from stderr.
pub fn suppress_python_location_error(stderr: &mut String) {
    let needle = "Failed to find real location of ";
    if let Some(pos) = stderr.find(needle) {
        if let Some(nl) = stderr[pos..].find('\n') {
            stderr.replace_range(pos..pos + nl + 1, "");
        } else {
            stderr.truncate(pos);
        }
    }
}

// ── Captured-output process execution ──────────────────────────────────────

/// Result of running a process with captured stdout/stderr.
#[derive(Debug)]
pub struct CapturedOutput {
    pub stdout: String,
    pub stderr: String,
    pub exit_code: i32,
}

/// Run an external process and capture its stdout/stderr into strings.
/// Uses reader threads to avoid pipe deadlocks, with a configurable timeout.
///
/// This is used by `FileSystemBfsManager` (for `bfscfg.exe`) and the test
/// driver — anywhere we need to inspect process output rather than relay it.
pub fn run_process_with_captured_output(
    command_line: &str,
    timeout_ms: u32,
) -> Result<CapturedOutput, WxcError> {
    use windows::Win32::System::Threading::{
        CreateProcessW, GetExitCodeProcess, TerminateProcess, CREATE_NO_WINDOW,
        PROCESS_INFORMATION, STARTF_USESTDHANDLES, STARTUPINFOW,
    };
    use windows_core::PWSTR;

    // Create pipes (stdin not connected to anything — child gets EOF)
    let (_stdin_read, _stdin_write) =
        create_std_pipes(false).map_err(|e| WxcError::Process(format!("stdin pipe: {}", e)))?;
    let (mut stdout_read, stdout_write) =
        create_std_pipes(true).map_err(|e| WxcError::Process(format!("stdout pipe: {}", e)))?;
    let (mut stderr_read, stderr_write) =
        create_std_pipes(true).map_err(|e| WxcError::Process(format!("stderr pipe: {}", e)))?;

    let si = STARTUPINFOW {
        cb: std::mem::size_of::<STARTUPINFOW>() as u32,
        dwFlags: STARTF_USESTDHANDLES,
        hStdInput: _stdin_read.get(),
        hStdOutput: stdout_write.get(),
        hStdError: stderr_write.get(),
        ..Default::default()
    };

    let mut cmd_wide: Vec<u16> = command_line
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect();
    let mut pi = PROCESS_INFORMATION::default();

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
        .map_err(|e| WxcError::Process(format!("CreateProcessW failed: {}", e)))?;
    }

    // Close child-side handles in the parent
    drop(_stdin_read);
    drop(stdout_write);
    drop(stderr_write);

    let process_handle = OwnedHandle::new(pi.hProcess);
    let _thread_handle = OwnedHandle::new(pi.hThread);

    // Spawn reader threads (using std::thread — we only need JoinHandle here)
    let stdout_send = SendOwnedHandle::take(&mut stdout_read);
    let stderr_send = SendOwnedHandle::take(&mut stderr_read);

    let stdout_thread = std::thread::spawn(move || read_from_pipe(stdout_send.get()));
    let stderr_thread = std::thread::spawn(move || read_from_pipe(stderr_send.get()));

    // Wait for process with timeout
    let wait_result = unsafe { WaitForSingleObject(process_handle.get(), timeout_ms) };

    if wait_result != WAIT_OBJECT_0 {
        unsafe {
            let _ = TerminateProcess(process_handle.get(), 1);
            // Wait for the OS to confirm the process is gone
            let _ = WaitForSingleObject(process_handle.get(), u32::MAX);
        }
        let _ = stdout_thread.join();
        let _ = stderr_thread.join();
        return Err(WxcError::Process("Process timed out".into()));
    }

    // Give reader threads a grace period (2s) to finish draining
    // We can't use WaitForMultipleObjects here since these are std::thread,
    // so just join with a reasonable expectation they'll finish quickly.
    let stdout_output = stdout_thread.join().unwrap_or_default();
    let stderr_output = stderr_thread.join().unwrap_or_default();

    let mut exit_code: u32 = 0;
    unsafe {
        GetExitCodeProcess(process_handle.get(), &mut exit_code)
            .map_err(|_| WxcError::Process("GetExitCodeProcess failed".into()))?;
    }

    Ok(CapturedOutput {
        stdout: stdout_output,
        stderr: stderr_output,
        exit_code: exit_code as i32,
    })
}

// ── Capability SID helpers ────────────────────────────────────────────────

/// Derive the capability SID for a given capability name.
/// Returns the raw SID pointer. The caller is responsible for freeing it with `LocalFree`.
pub fn get_capability_sid_from_name(name: &str) -> Result<*mut core::ffi::c_void, WxcError> {
    let wide_name = string_util::to_wide(name);
    let pcwstr = PCWSTR(wide_name.as_ptr());

    let mut capability_sids: *mut PSID = std::ptr::null_mut();
    let mut capability_sid_count: u32 = 0;
    let mut group_sids: *mut PSID = std::ptr::null_mut();
    let mut group_sid_count: u32 = 0;

    unsafe {
        DeriveCapabilitySidsFromName(
            pcwstr,
            &mut group_sids,
            &mut group_sid_count,
            &mut capability_sids,
            &mut capability_sid_count,
        )
        .map_err(|e| {
            WxcError::Process(format!("DeriveCapabilitySidsFromName({name}) failed: {e}"))
        })?;

        // Free group SIDs
        for i in 0..group_sid_count {
            let sid = *group_sids.add(i as usize);
            let _ = LocalFree(Some(HLOCAL(sid.0)));
        }
        let _ = LocalFree(Some(HLOCAL(group_sids as *mut _)));

        if capability_sid_count == 0 {
            let _ = LocalFree(Some(HLOCAL(capability_sids as *mut _)));
            return Err(WxcError::Process(format!(
                "No capability SID returned for {}",
                name
            )));
        }

        // Take the first capability SID
        let result_sid = (*capability_sids).0;

        // Free remaining capability SIDs (index 1+)
        for i in 1..capability_sid_count {
            let sid = *capability_sids.add(i as usize);
            let _ = LocalFree(Some(HLOCAL(sid.0)));
        }
        let _ = LocalFree(Some(HLOCAL(capability_sids as *mut _)));

        Ok(result_sid)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Creates a non-inheritable pipe pair for use in tests.
    /// Unlike `create_std_pipes`, neither end is marked inheritable, which
    /// prevents handles from leaking into child processes spawned by other
    /// tests running concurrently (cargo test runs in parallel). Leaked
    /// write-ends would keep pipes open and cause `read_from_pipe` to block.
    fn create_test_pipes() -> (OwnedHandle, OwnedHandle) {
        let mut h_read = HANDLE::default();
        let mut h_write = HANDLE::default();
        unsafe {
            CreatePipe(&mut h_read, &mut h_write, None, 0).unwrap();
        }
        (OwnedHandle::new(h_read), OwnedHandle::new(h_write))
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

    #[test]
    fn test_captured_output_stdout() {
        let output =
            run_process_with_captured_output("cmd.exe /c echo hello world", 10000).unwrap();
        assert!(output.stdout.trim().contains("hello world"));
        assert_eq!(output.exit_code, 0);
    }

    #[test]
    fn test_captured_output_stderr() {
        let output =
            run_process_with_captured_output("cmd.exe /c echo error_msg 1>&2", 10000).unwrap();
        assert!(output.stderr.trim().contains("error_msg"));
    }

    #[test]
    fn test_captured_output_exit_code() {
        let output = run_process_with_captured_output("cmd.exe /c exit 42", 10000).unwrap();
        assert_eq!(output.exit_code, 42);
    }

    #[test]
    fn test_captured_output_timeout() {
        // Use a very short timeout with a command that sleeps
        let result = run_process_with_captured_output("cmd.exe /c ping -n 10 127.0.0.1", 500);
        assert!(result.is_err());
        let err_msg = result.unwrap_err().to_string();
        assert!(err_msg.contains("timed out"));
    }

    #[test]
    fn test_read_from_pipe_basic() {
        let (mut read_handle, write_handle) = create_test_pipes();
        let test_msg = b"test pipe content";
        let mut bytes_written = 0u32;
        unsafe {
            WriteFile(
                write_handle.get(),
                Some(test_msg),
                Some(&mut bytes_written),
                None,
            )
            .unwrap();
        }
        drop(write_handle);
        let output = read_from_pipe(read_handle.take());
        assert_eq!(output, "test pipe content");
    }

    #[test]
    fn test_create_std_pipes_no_inherit_read() {
        use windows::Win32::Foundation::GetHandleInformation;

        let (read_handle, write_handle) = create_std_pipes(true).unwrap();
        let mut read_flags = 0u32;
        let mut write_flags = 0u32;
        unsafe {
            GetHandleInformation(read_handle.get(), &mut read_flags).unwrap();
            GetHandleInformation(write_handle.get(), &mut write_flags).unwrap();
        }
        // no_inherit_read=true: read end should NOT be inheritable, write end SHOULD be
        assert_eq!(
            read_flags & HANDLE_FLAG_INHERIT.0,
            0,
            "read end should be non-inheritable"
        );
        assert_ne!(
            write_flags & HANDLE_FLAG_INHERIT.0,
            0,
            "write end should be inheritable"
        );
    }

    #[test]
    fn test_create_std_pipes_no_inherit_write() {
        use windows::Win32::Foundation::GetHandleInformation;

        let (read_handle, write_handle) = create_std_pipes(false).unwrap();
        let mut read_flags = 0u32;
        let mut write_flags = 0u32;
        unsafe {
            GetHandleInformation(read_handle.get(), &mut read_flags).unwrap();
            GetHandleInformation(write_handle.get(), &mut write_flags).unwrap();
        }
        // no_inherit_read=false: read end SHOULD be inheritable, write end should NOT be
        assert_ne!(
            read_flags & HANDLE_FLAG_INHERIT.0,
            0,
            "read end should be inheritable"
        );
        assert_eq!(
            write_flags & HANDLE_FLAG_INHERIT.0,
            0,
            "write end should be non-inheritable"
        );
    }

    #[test]
    fn test_suppress_python_location_error_removes_line() {
        let mut stderr =
            "Some output\nFailed to find real location of python.exe\nMore output".to_string();
        suppress_python_location_error(&mut stderr);
        assert_eq!(stderr, "Some output\nMore output");
    }

    #[test]
    fn test_suppress_python_location_error_no_match() {
        let mut stderr = "Normal error output".to_string();
        suppress_python_location_error(&mut stderr);
        assert_eq!(stderr, "Normal error output");
    }

    /// Helper: spawn a child process with specified std handles.
    /// Returns (process_handle, thread_handle).
    fn spawn_child(
        cmd: &str,
        stdin: Option<HANDLE>,
        stdout: Option<HANDLE>,
        stderr: Option<HANDLE>,
    ) -> (OwnedHandle, OwnedHandle) {
        use windows::Win32::System::Threading::{
            CreateProcessW, CREATE_NO_WINDOW, PROCESS_INFORMATION, STARTF_USESTDHANDLES,
            STARTUPINFOW,
        };
        use windows_core::PWSTR;

        let si = STARTUPINFOW {
            cb: std::mem::size_of::<STARTUPINFOW>() as u32,
            dwFlags: STARTF_USESTDHANDLES,
            hStdInput: stdin.unwrap_or_default(),
            hStdOutput: stdout.unwrap_or_default(),
            hStdError: stderr.unwrap_or_default(),
            ..Default::default()
        };
        let mut pi = PROCESS_INFORMATION::default();
        let mut cmd_wide: Vec<u16> = cmd.encode_utf16().chain(std::iter::once(0)).collect();

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
}
