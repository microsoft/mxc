use crate::error::WxcError;
use crate::string_util;

use std::thread;
use windows::Win32::Foundation::{
    CloseHandle, BOOL, HANDLE, HANDLE_FLAGS, HANDLE_FLAG_INHERIT, HLOCAL, LocalFree,
    SetHandleInformation, WAIT_OBJECT_0,
};
use windows::Win32::Security::{
    DeriveCapabilitySidsFromName, PSID, SECURITY_ATTRIBUTES,
};
use windows::Win32::Storage::FileSystem::{FlushFileBuffers, ReadFile, WriteFile};
use windows::Win32::System::Pipes::CreatePipe;
use windows::Win32::System::Threading::{
    CreateProcessW, GetExitCodeProcess, TerminateProcess, WaitForSingleObject,
    PROCESS_CREATION_FLAGS, PROCESS_INFORMATION, STARTF_USESTDHANDLES, STARTUPINFOW,
};
use windows_core::PCWSTR;

const BUFFER_SIZE: u32 = 4096;
const MAX_OUTPUT_CHARS: usize = 1024 * 1024;

// Wrapper to send a raw handle value across threads.
// SAFETY: Windows HANDLEs are safe to use from any thread.
struct SendHandle(isize);
unsafe impl Send for SendHandle {}

impl SendHandle {
    fn from_handle(h: HANDLE) -> Self {
        Self(h.0 as isize)
    }
    fn to_handle(&self) -> HANDLE {
        HANDLE(self.0 as *mut core::ffi::c_void)
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

/// Captured output from a child process.
pub struct CapturedOutput {
    pub stdout_output: String,
    pub stderr_output: String,
    pub exit_code: i32,
}

/// Relay data from one pipe handle to another until EOF or error.
/// Intended to be run on a background thread.
pub fn pipe_relay(read: HANDLE, write: HANDLE) {
    let mut buffer = [0u8; BUFFER_SIZE as usize];
    loop {
        let mut bytes_read = 0u32;
        let ok = unsafe {
            ReadFile(read, Some(&mut buffer), Some(&mut bytes_read), None)
        };
        if ok.is_err() || bytes_read == 0 {
            break;
        }
        let mut bytes_written = 0u32;
        let ok = unsafe {
            WriteFile(
                write,
                Some(&buffer[..bytes_read as usize]),
                Some(&mut bytes_written),
                None,
            )
        };
        if ok.is_err() || bytes_written != bytes_read {
            break;
        }
        let _ = unsafe { FlushFileBuffers(write) };
    }
}

/// Read all data from a pipe as UTF-8 text, capped at 1MB of characters.
pub fn read_from_pipe(pipe: HANDLE) -> String {
    let mut result = String::with_capacity(BUFFER_SIZE as usize);
    let mut buffer = [0u8; BUFFER_SIZE as usize];
    loop {
        let mut bytes_read = 0u32;
        let ok = unsafe { ReadFile(pipe, Some(&mut buffer), Some(&mut bytes_read), None) };
        if ok.is_err() || bytes_read == 0 {
            break;
        }
        let chunk = String::from_utf8_lossy(&buffer[..bytes_read as usize]);
        let remaining = MAX_OUTPUT_CHARS.saturating_sub(result.len());
        if remaining == 0 {
            break;
        }
        if chunk.len() > remaining {
            // Take only up to `remaining` chars
            let truncated: String = chunk.chars().take(remaining).collect();
            result.push_str(&truncated);
            break;
        }
        result.push_str(&chunk);
    }
    result
}

/// Create a pair of pipe handles (read, write) with appropriate inheritance.
/// If `no_inherit_read` is true, the read end is made non-inheritable;
/// otherwise the write end is made non-inheritable.
pub fn create_std_pipes(no_inherit_read: bool) -> Result<(OwnedHandle, OwnedHandle), WxcError> {
    let mut sa = SECURITY_ATTRIBUTES {
        nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
        bInheritHandle: BOOL::from(true),
        lpSecurityDescriptor: std::ptr::null_mut(),
    };
    let mut h_read = HANDLE::default();
    let mut h_write = HANDLE::default();

    unsafe {
        CreatePipe(&mut h_read, &mut h_write, Some(&mut sa), 0)
            .map_err(|_| WxcError::Process("Failed to create pipe".into()))?;

        let h_dup = if no_inherit_read { h_read } else { h_write };
        SetHandleInformation(h_dup, HANDLE_FLAG_INHERIT.0, HANDLE_FLAGS(0))
            .map_err(|_| {
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

/// Derive the capability SID for a given capability name.
/// Returns the raw SID pointer. The caller is responsible for freeing it with `LocalFree`.
pub fn get_capability_sid_from_name(
    name: &str,
) -> Result<*mut core::ffi::c_void, WxcError> {
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
        .map_err(|_| {
            WxcError::Process(format!(
                "DeriveCapabilitySidsFromName({}) failed",
                name
            ))
        })?;

        // Free group SIDs
        for i in 0..group_sid_count {
            let sid = *group_sids.add(i as usize);
            let _ = LocalFree(HLOCAL(sid.0));
        }
        let _ = LocalFree(HLOCAL(group_sids as *mut _));

        if capability_sid_count == 0 {
            let _ = LocalFree(HLOCAL(capability_sids as *mut _));
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
            let _ = LocalFree(HLOCAL(sid.0));
        }
        let _ = LocalFree(HLOCAL(capability_sids as *mut _));

        Ok(result_sid)
    }
}

/// Run a process with captured stdout/stderr and a timeout.
pub fn run_process_with_captured_output(
    executable: &str,
    command_line: &str,
    timeout_ms: u32,
) -> Result<CapturedOutput, WxcError> {
    let (stdin_read, _stdin_write) =
        create_std_pipes(false).map_err(|e| WxcError::Process(format!("stdin pipe: {}", e)))?;
    let (stdout_read, stdout_write) =
        create_std_pipes(true).map_err(|e| WxcError::Process(format!("stdout pipe: {}", e)))?;
    let (stderr_read, stderr_write) =
        create_std_pipes(true).map_err(|e| WxcError::Process(format!("stderr pipe: {}", e)))?;

    let mut si = STARTUPINFOW {
        cb: std::mem::size_of::<STARTUPINFOW>() as u32,
        dwFlags: STARTF_USESTDHANDLES,
        hStdOutput: stdout_write.get(),
        hStdError: stderr_write.get(),
        ..Default::default()
    };

    let mut pi = PROCESS_INFORMATION::default();

    let mut cmd_line_wide: Vec<u16> = command_line.encode_utf16().collect();
    cmd_line_wide.push(0);

    let exe_wide;
    let exe_pcwstr = if executable.is_empty() {
        PCWSTR::null()
    } else {
        exe_wide = string_util::to_wide(executable);
        PCWSTR(exe_wide.as_ptr())
    };

    unsafe {
        CreateProcessW(
            exe_pcwstr,
            windows_core::PWSTR(cmd_line_wide.as_mut_ptr()),
            None,
            None,
            true,
            PROCESS_CREATION_FLAGS(0),
            None,
            None,
            &mut si,
            &mut pi,
        )
        .map_err(|e| {
            WxcError::Process(format!("CreateProcessW failed: {}", e))
        })?;
    }

    // Close child-side handles so pipe reads see EOF when child exits
    drop(stdin_read);
    drop(stdout_write);
    drop(stderr_write);

    let process_handle = OwnedHandle::new(pi.hProcess);
    let _thread_handle = OwnedHandle::new(pi.hThread);

    // Spawn reader threads using std::thread
    let stdout_pipe = SendHandle::from_handle(stdout_read.get());
    let stderr_pipe = SendHandle::from_handle(stderr_read.get());

    let stdout_thread = thread::spawn(move || read_from_pipe(stdout_pipe.to_handle()));
    let stderr_thread = thread::spawn(move || read_from_pipe(stderr_pipe.to_handle()));

    // Wait for process
    let wait_result = unsafe { WaitForSingleObject(process_handle.get(), timeout_ms) };
    if wait_result != WAIT_OBJECT_0 {
        unsafe {
            let _ = TerminateProcess(process_handle.get(), 1);
        }
        return Err(WxcError::Process("Process timed out".into()));
    }

    let stdout_output = stdout_thread.join().unwrap_or_default();
    let stderr_output = stderr_thread.join().unwrap_or_default();

    let mut exit_code: u32 = 0;
    unsafe {
        GetExitCodeProcess(process_handle.get(), &mut exit_code)
            .map_err(|_| WxcError::Process("GetExitCodeProcess failed".into()))?;
    }

    Ok(CapturedOutput {
        stdout_output,
        stderr_output,
        exit_code: exit_code as i32,
    })
}
