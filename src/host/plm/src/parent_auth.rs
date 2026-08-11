// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Mutual PID authentication for the unelevated wxc-exec → PLM singleton
//! handoff. This replaces the spoofable environment/CLI bypass.

use std::io::{Read, Write};
use std::os::windows::io::{AsRawHandle, FromRawHandle};
use std::time::{Duration, Instant};

use windows::core::PCWSTR;
use windows::Win32::Foundation::{
    CloseHandle, ERROR_PIPE_CONNECTED, ERROR_PIPE_LISTENING, HANDLE, INVALID_HANDLE_VALUE,
};
use windows::Win32::Storage::FileSystem::{
    FILE_FLAGS_AND_ATTRIBUTES, FILE_FLAG_FIRST_PIPE_INSTANCE,
};
use windows::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, Process32FirstW, Process32NextW, PROCESSENTRY32W, TH32CS_SNAPPROCESS,
};
use windows::Win32::System::Pipes::{
    ConnectNamedPipe, CreateNamedPipeW, GetNamedPipeClientProcessId, GetNamedPipeServerProcessId,
    PIPE_NOWAIT, PIPE_READMODE_BYTE, PIPE_REJECT_REMOTE_CLIENTS, PIPE_TYPE_BYTE,
};

const PIPE_PREFIX: &str = r"\\.\pipe\mxc-plm-parent-";
const AUTH_BYTE: u8 = 0xa7;
const AUTH_TIMEOUT: Duration = Duration::from_secs(30);
const ERROR_NO_DATA: i32 = 232;

pub struct ParentAuthorization {
    pipe: HANDLE,
    name: String,
}

impl ParentAuthorization {
    pub fn new() -> Result<Self, String> {
        let name = new_pipe_name()?;
        let wide = to_wide(&name);
        // PIPE_ACCESS_OUTBOUND | FILE_FLAG_FIRST_PIPE_INSTANCE.
        let open_mode = FILE_FLAGS_AND_ATTRIBUTES(0x0000_0002) | FILE_FLAG_FIRST_PIPE_INSTANCE;
        let pipe = unsafe {
            CreateNamedPipeW(
                PCWSTR(wide.as_ptr()),
                open_mode,
                PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_NOWAIT | PIPE_REJECT_REMOTE_CLIENTS,
                1,
                1,
                0,
                0,
                None,
            )
        };
        if pipe == INVALID_HANDLE_VALUE {
            return Err(format!(
                "CreateNamedPipeW failed for PLM parent authorization: {}",
                std::io::Error::last_os_error()
            ));
        }
        Ok(Self { pipe, name })
    }

    pub fn pipe_name(&self) -> &str {
        &self.name
    }

    pub fn authorize(mut self, expected_client_pid: u32) -> Result<(), String> {
        let deadline = Instant::now() + AUTH_TIMEOUT;
        loop {
            match unsafe { ConnectNamedPipe(self.pipe, None) } {
                Ok(()) => break,
                Err(error) => {
                    let raw = (error.code().0 as u32) & 0xffff;
                    if raw == ERROR_PIPE_CONNECTED.0 {
                        break;
                    }
                    if raw != ERROR_PIPE_LISTENING.0 {
                        return Err(format!(
                            "ConnectNamedPipe failed for PLM authorization: {error}"
                        ));
                    }
                    if Instant::now() >= deadline {
                        return Err("timed out waiting for PLM authorization client".to_string());
                    }
                    std::thread::sleep(Duration::from_millis(10));
                }
            }
        }
        let mut actual_pid = 0u32;
        unsafe { GetNamedPipeClientProcessId(self.pipe, &mut actual_pid) }
            .map_err(|error| format!("GetNamedPipeClientProcessId failed: {error}"))?;
        if actual_pid != expected_client_pid {
            return Err(format!(
                "PLM authorization client PID mismatch: expected {expected_client_pid}, got {actual_pid}"
            ));
        }
        let raw = self.pipe.0;
        self.pipe = HANDLE::default();
        // SAFETY: ownership moves from this object into File.
        let mut pipe = unsafe { std::fs::File::from_raw_handle(raw) };
        pipe.write_all(&[AUTH_BYTE])
            .and_then(|_| pipe.flush())
            .map_err(|error| format!("failed to send PLM parent authorization: {error}"))
    }
}

impl Drop for ParentAuthorization {
    fn drop(&mut self) {
        if !self.pipe.is_invalid() {
            unsafe {
                let _ = CloseHandle(self.pipe);
            }
        }
    }
}

/// Claim a one-shot authorization created by the direct parent process.
pub fn claim(pipe_name: &str) -> Result<u32, String> {
    validate_pipe_name(pipe_name)?;
    let parent_pid = direct_parent_pid()?;
    let mut pipe = std::fs::OpenOptions::new()
        .read(true)
        .open(pipe_name)
        .map_err(|error| format!("failed to connect to PLM parent authorization: {error}"))?;
    let mut server_pid = 0u32;
    unsafe { GetNamedPipeServerProcessId(HANDLE(pipe.as_raw_handle()), &mut server_pid) }
        .map_err(|error| format!("GetNamedPipeServerProcessId failed: {error}"))?;
    if server_pid != parent_pid {
        return Err(format!(
            "PLM authorization server is not the direct parent: expected {parent_pid}, got {server_pid}"
        ));
    }
    let mut authorization = [0u8; 1];
    let deadline = Instant::now() + AUTH_TIMEOUT;
    loop {
        match pipe.read_exact(&mut authorization) {
            Ok(()) => break,
            Err(error) if error.raw_os_error() == Some(ERROR_NO_DATA) => {
                if Instant::now() >= deadline {
                    return Err("timed out reading PLM parent authorization".to_string());
                }
                std::thread::sleep(Duration::from_millis(10));
            }
            Err(error) => return Err(format!("failed to read PLM parent authorization: {error}")),
        }
    }
    if authorization[0] != AUTH_BYTE {
        return Err("invalid PLM parent authorization byte".to_string());
    }
    Ok(server_pid)
}

fn direct_parent_pid() -> Result<u32, String> {
    let current_pid = unsafe { windows::Win32::System::Threading::GetCurrentProcessId() };
    let snapshot = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) }
        .map_err(|error| format!("CreateToolhelp32Snapshot failed: {error}"))?;
    struct Snapshot(HANDLE);
    impl Drop for Snapshot {
        fn drop(&mut self) {
            unsafe {
                let _ = CloseHandle(self.0);
            }
        }
    }
    let snapshot = Snapshot(snapshot);
    let mut entry = PROCESSENTRY32W {
        dwSize: std::mem::size_of::<PROCESSENTRY32W>() as u32,
        ..Default::default()
    };
    unsafe { Process32FirstW(snapshot.0, &mut entry) }
        .map_err(|error| format!("Process32FirstW failed: {error}"))?;
    loop {
        if entry.th32ProcessID == current_pid {
            if entry.th32ParentProcessID == 0 {
                return Err("PLM process has no direct parent PID".to_string());
            }
            return Ok(entry.th32ParentProcessID);
        }
        if unsafe { Process32NextW(snapshot.0, &mut entry) }.is_err() {
            break;
        }
    }
    Err("could not locate PLM process in ToolHelp snapshot".to_string())
}

fn new_pipe_name() -> Result<String, String> {
    let mut random = [0u8; 16];
    getrandom::getrandom(&mut random)
        .map_err(|error| format!("failed to generate PLM authorization nonce: {error}"))?;
    let suffix: String = random.iter().map(|byte| format!("{byte:02x}")).collect();
    Ok(format!("{PIPE_PREFIX}{suffix}"))
}

fn validate_pipe_name(pipe_name: &str) -> Result<(), String> {
    let Some(suffix) = pipe_name.strip_prefix(PIPE_PREFIX) else {
        return Err("invalid PLM authorization pipe prefix".to_string());
    };
    if suffix.len() != 32 || !suffix.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err("invalid PLM authorization pipe nonce".to_string());
    }
    Ok(())
}

fn to_wide(value: &str) -> Vec<u16> {
    value.encode_utf16().chain(std::iter::once(0)).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_only_local_random_authorization_names() {
        assert!(
            validate_pipe_name(r"\\.\pipe\mxc-plm-parent-00112233445566778899aabbccddeeff").is_ok()
        );
        assert!(validate_pipe_name(
            r"\\remote\pipe\mxc-plm-parent-00112233445566778899aabbccddeeff"
        )
        .is_err());
        assert!(validate_pipe_name(r"\\.\pipe\mxc-plm-parent-short").is_err());
    }
}
