// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use std::path::PathBuf;
use std::sync::{Arc, Mutex, Weak};
use std::time::Duration;

use crate::error::WxcError;
use crate::sandbox_process::StreamCloser;
use crate::string_util;

use windows::Win32::Foundation::{
    CloseHandle, LocalFree, SetHandleInformation, HANDLE, HANDLE_FLAGS, HANDLE_FLAG_INHERIT,
    HLOCAL, WAIT_OBJECT_0,
};
use windows::Win32::Security::{DeriveCapabilitySidsFromName, PSID, SECURITY_ATTRIBUTES};
use windows::Win32::Storage::FileSystem::{ReadFile, WriteFile};
use windows::Win32::System::Pipes::CreatePipe;
use windows::Win32::System::Threading::WaitForSingleObject;
use windows::Win32::System::IO::CancelIoEx;
use windows_core::BOOL;
use windows_core::PCWSTR;

/// A readable end of an anonymous pipe (e.g. the child's stdout/stderr),
/// owning the handle and closing it on drop. Implements [`std::io::Read`]
/// via `ReadFile`; a broken pipe (all write ends closed) reads as EOF.
/// `Send` so it can be handed to a reader thread.
pub struct PipeReader(SendOwnedHandle);

impl PipeReader {
    /// Take ownership of `handle` (invalidating the source `OwnedHandle`).
    pub fn new(mut handle: OwnedHandle) -> Self {
        Self(SendOwnedHandle::take(&mut handle))
    }
}

impl std::io::Read for PipeReader {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        use windows::Win32::Foundation::ERROR_BROKEN_PIPE;
        let mut read: u32 = 0;
        // SAFETY: `self.0` owns a valid pipe handle for the lifetime of this
        // `PipeReader`; `buf`/`read` are valid local out-params for the call.
        match unsafe { ReadFile(self.0.get(), Some(buf), Some(&mut read), None) } {
            Ok(()) => Ok(read as usize),
            // Write ends all closed: normal end-of-stream, report EOF.
            Err(e) if e.code() == ERROR_BROKEN_PIPE.to_hresult() => Ok(0),
            Err(e) => Err(std::io::Error::other(e)),
        }
    }
}

/// Cancellation state shared between an [`InterruptiblePipeReader`] and its
/// [`PipeReadCanceller`]s. Owns the pipe handle — closed only when the **last**
/// reference drops, so a canceller's `CancelIoEx` can never race a closed (and
/// possibly reused) handle — plus the [`ReadGate`] the reader and cancellers
/// hand off through.
struct CancelablePipe {
    handle: SendOwnedHandle,
    gate: Mutex<ReadGate>,
}

/// Reader/canceller handshake, guarded by [`CancelablePipe::gate`].
///
/// `CancelIoEx` is *edge-triggered*: it aborts only I/O already pending when it
/// is called. A bare `cancelled` flag + a single `CancelIoEx` therefore has a
/// lost-wakeup race — a `close` landing between a read's flag check and its
/// `ReadFile` entering the kernel cancels nothing and never retries, parking the
/// read until real EOF. The mutex closes that race by ordering "a read is
/// starting" against "cancel requested": a racing `close` either sees the read
/// has not started (and the read then observes `cancelled`) or sees `reading`
/// and keeps issuing `CancelIoEx` until the read is aborted.
#[derive(Default)]
struct ReadGate {
    /// Set once `close` has been called; a read observing it returns EOF instead
    /// of issuing (or while abandoning) a `ReadFile`.
    cancelled: bool,
    /// True while a read is in — or about to enter — its blocking `ReadFile`, so
    /// `close` knows to keep issuing `CancelIoEx` until that read is aborted.
    reading: bool,
}

impl CancelablePipe {
    /// Lock the gate, tolerating a poisoned mutex (the guarded data is two
    /// bools with no broken invariant on panic).
    fn lock(&self) -> std::sync::MutexGuard<'_, ReadGate> {
        self.gate
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }
}

// SAFETY: the only non-`Sync` field is a process-global Windows HANDLE whose
// value is copied for `ReadFile` / `CancelIoEx`; issuing `CancelIoEx` from one
// thread to abort a `ReadFile` blocked on another is the documented, supported
// way to interrupt synchronous pipe I/O, and the reader/canceller handshake is
// serialised by `gate`. So sharing `&CancelablePipe` across threads is sound.
unsafe impl Sync for CancelablePipe {}

/// A readable pipe end (e.g. the child's stdout/stderr) whose blocking
/// `ReadFile` can be cancelled out-of-band via a [`PipeReadCanceller`] —
/// reporting EOF — without closing the child or its other streams. A broken
/// pipe (all write ends closed) still reads as EOF as usual. `Send` so it can
/// be handed to a reader thread. Single-reader: at most one thread may `read` it
/// at a time (any number of cancellers may fire concurrently).
pub struct InterruptiblePipeReader(Arc<CancelablePipe>);

impl InterruptiblePipeReader {
    /// Take ownership of `handle` (invalidating the source `OwnedHandle`).
    pub fn new(mut handle: OwnedHandle) -> Self {
        Self(Arc::new(CancelablePipe {
            handle: SendOwnedHandle::take(&mut handle),
            gate: Mutex::new(ReadGate::default()),
        }))
    }

    /// Mint a closer that EOFs this reader's `read` on demand. Several closers
    /// may be minted; they share one cancellation state. The closer holds only a
    /// [`Weak`] reference, so it never keeps the read handle open past this
    /// reader's lifetime.
    pub fn canceller(&self) -> PipeReadCanceller {
        PipeReadCanceller(Arc::downgrade(&self.0))
    }
}

impl std::io::Read for InterruptiblePipeReader {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        use windows::Win32::Foundation::{ERROR_BROKEN_PIPE, ERROR_OPERATION_ABORTED};
        // Announce the read under the gate: a `close` that already fired makes us
        // EOF without touching the pipe; otherwise mark `reading` so a `close`
        // racing us keeps issuing `CancelIoEx` until our `ReadFile` is aborted.
        {
            let mut gate = self.0.lock();
            if gate.cancelled {
                return Ok(0);
            }
            gate.reading = true;
        }
        let mut read: u32 = 0;
        // SAFETY: the `Arc` keeps the pipe handle valid for this call;
        // `buf`/`read` are valid local out-params.
        let result = unsafe { ReadFile(self.0.handle.get(), Some(buf), Some(&mut read), None) };
        let cancelled = {
            let mut gate = self.0.lock();
            gate.reading = false;
            gate.cancelled
        };
        // If `close` fired while this read was in flight, drop any
        // completed-but-undelivered chunk and report EOF — matching the Unix
        // reader, which never delivers data once cancelled.
        if cancelled {
            return Ok(0);
        }
        match result {
            Ok(()) => Ok(read as usize),
            // Write ends all closed: normal end-of-stream, report EOF.
            Err(e) if e.code() == ERROR_BROKEN_PIPE.to_hresult() => Ok(0),
            // A canceller's `CancelIoEx` aborted this read: report EOF.
            Err(e) if e.code() == ERROR_OPERATION_ABORTED.to_hresult() => Ok(0),
            Err(e) => Err(std::io::Error::other(e)),
        }
    }
}

/// A [`StreamCloser`] for an [`InterruptiblePipeReader`]. Cloneable and
/// `Send + Sync` so a watchdog thread can hold and fire it; all clones share
/// one cancellation state and [`close`](StreamCloser::close) is idempotent.
/// Holds a [`Weak`] reference so a stored canceller never keeps the reader's
/// data-pipe handle open after the reader is dropped.
#[derive(Clone)]
pub struct PipeReadCanceller(Weak<CancelablePipe>);

impl StreamCloser for PipeReadCanceller {
    fn close(&self) {
        // Upgrade to a temporary strong ref for the duration of the cancel. If
        // the reader has already been dropped there is nothing to cancel (and
        // its handle is already closed), so this is a no-op.
        let Some(pipe) = self.0.upgrade() else {
            return;
        };
        // Mark cancelled once (so reads short-circuit to EOF), then abort an
        // in-flight read. Because `CancelIoEx` is edge-triggered, retry while a
        // read is in its announce→`ReadFile` window (`reading == true`): the next
        // iteration catches the `ReadFile` once it enters the kernel. The reader
        // clears `reading` when its `ReadFile` returns (aborted or with data),
        // which bounds the loop; if no read is in progress it exits at once.
        {
            let mut gate = pipe.lock();
            if gate.cancelled {
                return;
            }
            gate.cancelled = true;
        }
        loop {
            // SAFETY: the upgraded `Arc` keeps the handle valid; `CancelIoEx`
            // with a null overlapped aborts all outstanding synchronous I/O on
            // it. Ignore the result — a benign no-op (ERROR_NOT_FOUND) when none
            // is pending.
            unsafe {
                let _ = CancelIoEx(pipe.handle.get(), None);
            }
            if !pipe.lock().reading {
                return;
            }
            std::thread::sleep(Duration::from_millis(1));
        }
    }
}

/// A writable end of an anonymous pipe (e.g. the child's stdin), owning the
/// handle and closing it on drop (which sends EOF to the child). Implements
/// [`std::io::Write`] via `WriteFile`. `Send`.
pub struct PipeWriter(SendOwnedHandle);

impl PipeWriter {
    /// Take ownership of `handle` (invalidating the source `OwnedHandle`).
    pub fn new(mut handle: OwnedHandle) -> Self {
        Self(SendOwnedHandle::take(&mut handle))
    }
}

impl std::io::Write for PipeWriter {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        use windows::Win32::Foundation::ERROR_BROKEN_PIPE;
        let mut written: u32 = 0;
        // SAFETY: `self.0` owns a valid pipe handle for the lifetime of this
        // `PipeWriter`; `buf`/`written` are valid local params for the call.
        match unsafe { WriteFile(self.0.get(), Some(buf), Some(&mut written), None) } {
            Ok(()) => Ok(written as usize),
            // The read end is gone (child exited / closed its stdin): surface the
            // standard `BrokenPipe` kind so callers' graceful handling fires
            // instead of an opaque OS error.
            Err(e) if e.code() == ERROR_BROKEN_PIPE.to_hresult() => {
                Err(std::io::Error::from(std::io::ErrorKind::BrokenPipe))
            }
            Err(e) => Err(std::io::Error::other(e)),
        }
    }

    fn flush(&mut self) -> std::io::Result<()> {
        // Anonymous pipes are not buffered on the writer side.
        Ok(())
    }
}

const BUFFER_SIZE: u32 = 4096;
const MAX_OUTPUT_CHARS: usize = 1024 * 1024;

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
/// `application_name`, when `Some`, is passed verbatim as
/// `lpApplicationName` to `CreateProcessW`. This **disables Windows'
/// executable search order** — the OS will load exactly the binary
/// named, with no fallback to the loader's directory, the CWD, the
/// system directories, or `PATH`. Callers that have an authoritative
/// absolute path (resolved from a probe, e.g. via
/// [`crate::fallback_detector::find_bfscfg_exe`]) should pass it here
/// to defeat executable-search-order hijacking.
///
/// When `application_name` is `None`, the executable is resolved from
/// the first token of `command_line` according to the standard
/// `CreateProcessW` rules — vulnerable to search-order attacks if the
/// first token is a bare name.
///
/// This is used by `FileSystemBfsManager` (for `bfscfg.exe`) and the test
/// driver — anywhere we need to inspect process output rather than relay it.
pub fn run_process_with_captured_output(
    application_name: Option<&str>,
    command_line: &str,
    timeout_ms: u32,
) -> Result<CapturedOutput, WxcError> {
    use windows::Win32::System::Threading::{
        CreateProcessW, GetExitCodeProcess, TerminateProcess, CREATE_NO_WINDOW,
        PROCESS_INFORMATION, STARTF_USESTDHANDLES, STARTUPINFOW,
    };
    use windows_core::{PCWSTR, PWSTR};

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

    let mut cmd_wide = string_util::to_wide(command_line);
    // When `application_name` is `Some`, keep the wide buffer alive for
    // the duration of the `CreateProcessW` call so the `PCWSTR` we pass
    // remains valid.
    let app_wide: Option<Vec<u16>> = application_name.map(string_util::to_wide);
    let app_pcwstr: PCWSTR = match app_wide.as_ref() {
        Some(w) => PCWSTR(w.as_ptr()),
        None => PCWSTR::null(),
    };
    let mut pi = PROCESS_INFORMATION::default();

    unsafe {
        CreateProcessW(
            app_pcwstr,
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

/// A `SID_AND_ATTRIBUTES`-compatible struct for building capability arrays
/// and loopback exemption lists.
///
/// Using a manual struct avoids issues with conditional availability of
/// `windows::Win32::Security::SID_AND_ATTRIBUTES`.
#[repr(C)]
pub struct SidAndAttributes {
    pub sid: PSID,
    pub attributes: u32,
}

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

// ── Sibling binary resolution ─────────────────────────────────────────────

/// Return the directory containing the current executable.
pub fn exe_dir() -> Result<PathBuf, WxcError> {
    let exe = std::env::current_exe()
        .map_err(|e| WxcError::Process(format!("cannot determine exe path: {}", e)))?;
    exe.parent()
        .map(|p| p.to_path_buf())
        .ok_or_else(|| WxcError::Process("exe has no parent directory".to_string()))
}

/// Locate a sibling executable next to the current exe.
///
/// Returns the full path if the binary exists, or an error describing
/// where it was expected.
pub fn resolve_sibling_binary(name: &str) -> Result<PathBuf, WxcError> {
    let dir = exe_dir()?;
    let path = dir.join(name);
    if path.exists() {
        Ok(path)
    } else {
        Err(WxcError::Process(format!(
            "{} not found at {}",
            name,
            path.display()
        )))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use windows::Win32::Storage::FileSystem::WriteFile;

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
    fn test_captured_output_stdout() {
        let output =
            run_process_with_captured_output(None, "cmd.exe /c echo hello world", 10000).unwrap();
        assert!(output.stdout.trim().contains("hello world"));
        assert_eq!(output.exit_code, 0);
    }

    #[test]
    fn test_captured_output_stderr() {
        let output =
            run_process_with_captured_output(None, "cmd.exe /c echo error_msg 1>&2", 10000)
                .unwrap();
        assert!(output.stderr.trim().contains("error_msg"));
    }

    #[test]
    fn test_captured_output_exit_code() {
        let output = run_process_with_captured_output(None, "cmd.exe /c exit 42", 10000).unwrap();
        assert_eq!(output.exit_code, 42);
    }

    #[test]
    fn test_captured_output_timeout() {
        // Use a very short timeout with a command that sleeps
        let result = run_process_with_captured_output(None, "cmd.exe /c ping -n 10 127.0.0.1", 500);
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
}
