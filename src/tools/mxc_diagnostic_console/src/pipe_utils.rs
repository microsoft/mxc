// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Shared named pipe utilities used by both the diagnostic pipe and denial pipe servers.

use std::ffi::c_void;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use windows::Win32::Foundation::{CloseHandle, HANDLE, HLOCAL, INVALID_HANDLE_VALUE, LocalFree};
use windows::Win32::Security::Authorization::{
    ConvertSidToStringSidW, ConvertStringSecurityDescriptorToSecurityDescriptorW,
};
use windows::Win32::Security::{
    GetTokenInformation, PSECURITY_DESCRIPTOR, SECURITY_ATTRIBUTES, TOKEN_QUERY, TOKEN_USER,
    TokenUser,
};
use windows::Win32::Storage::FileSystem::{FILE_FLAGS_AND_ATTRIBUTES, FILE_FLAG_FIRST_PIPE_INSTANCE};
use windows::Win32::System::Pipes::{
    ConnectNamedPipe, CreateNamedPipeW, DisconnectNamedPipe, GetNamedPipeClientProcessId,
    PIPE_READMODE_MESSAGE, PIPE_TYPE_MESSAGE, PIPE_UNLIMITED_INSTANCES, PIPE_WAIT,
};
use windows::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};
use windows_core::PCWSTR;

/// Builds a pipe SDDL restricting access to the current user, SYSTEM, and Administrators.
/// Explicitly denies ALL_APP_PACKAGES (`S-1-15-2-1`) to prevent sandbox processes from connecting.
///
/// The current user is granted Generic Read + Write (`GRGW`); SYSTEM (`SY`) and Built-in
/// Administrators (`BA`) are granted Generic All (`GA`).
///
/// Returns `None` if the current user's SID cannot be resolved. In that case the
/// caller must refuse to create the pipe rather than fall back to weaker ACLs.
pub fn build_pipe_sddl() -> Option<String> {
    let user_sid = get_current_user_sid()?;
    Some(format!(
        "D:(D;;GA;;;S-1-15-2-1)(A;;GRGW;;;{user_sid})(A;;GA;;;SY)(A;;GA;;;BA)"
    ))
}

/// Gets the current user's SID as a string for SDDL construction.
///
/// Returns `None` if the process token cannot be opened or the SID cannot be resolved.
pub fn get_current_user_sid() -> Option<String> {
    // SAFETY: `GetCurrentProcess` returns a pseudo-handle that is always valid.
    // `OpenProcessToken`/`GetTokenInformation` operate on valid handles with proper
    // buffer sizes. `CloseHandle` is called on the token handle before returning, and
    // the SID string allocated by `ConvertSidToStringSidW` is freed via `LocalFree`.
    unsafe {
        let mut token = HANDLE::default();
        if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token).is_err() {
            return None;
        }

        // Query required buffer size.
        let mut size = 0u32;
        let _ = GetTokenInformation(token, TokenUser, None, 0, &mut size);

        let mut buffer = vec![0u8; size as usize];
        if GetTokenInformation(
            token,
            TokenUser,
            Some(buffer.as_mut_ptr() as *mut _),
            size,
            &mut size,
        )
        .is_err()
        {
            let _ = CloseHandle(token);
            return None;
        }
        let _ = CloseHandle(token);

        let token_user = &*(buffer.as_ptr() as *const TOKEN_USER);
        let mut sid_string = windows_core::PWSTR::null();
        if ConvertSidToStringSidW(token_user.User.Sid, &mut sid_string).is_err() {
            return None;
        }

        let result = sid_string.to_string().ok();
        let _ = LocalFree(Some(HLOCAL(sid_string.0 as *mut _)));
        result
    }
}

/// Creates a named pipe instance with the specified SDDL security descriptor.
///
/// # Arguments
/// * `name` - The full pipe name (e.g., `\\.\pipe\mxc-denials-S-1-5-...`)
/// * `sddl` - SDDL string defining the pipe's security descriptor
/// * `access_mode` - Pipe access mode flags (e.g., `PIPE_ACCESS_DUPLEX` or `PIPE_ACCESS_INBOUND`)
/// * `in_buffer_size` - Input buffer size in bytes
/// * `out_buffer_size` - Output buffer size in bytes
/// * `is_first` - If true, uses `FILE_FLAG_FIRST_PIPE_INSTANCE` to prevent squatting
///
/// # Errors
/// Returns an error if the security descriptor conversion or pipe creation fails.
pub fn create_pipe_with_sddl(
    name: &str,
    sddl: &str,
    access_mode: u32,
    in_buffer_size: u32,
    out_buffer_size: u32,
    is_first: bool,
) -> Result<HANDLE, std::io::Error> {
    let sddl_wide: Vec<u16> = sddl.encode_utf16().chain(std::iter::once(0)).collect();
    let mut sd = PSECURITY_DESCRIPTOR::default();

    // SAFETY: `sddl_wide` is a valid null-terminated UTF-16 SDDL string.
    // `sd` receives a pointer to a self-relative security descriptor allocated
    // by the system; freed via `LocalFree` after pipe creation.
    unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            PCWSTR(sddl_wide.as_ptr()),
            1, // SDDL_REVISION_1
            &mut sd,
            None,
        )
    }
    .map_err(|e| std::io::Error::other(format!("ConvertStringSecurityDescriptorToSecurityDescriptorW: {e}")))?;

    let sa = SECURITY_ATTRIBUTES {
        nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: sd.0,
        bInheritHandle: false.into(),
    };

    let mut open_mode = FILE_FLAGS_AND_ATTRIBUTES(access_mode);
    if is_first {
        open_mode |= FILE_FLAG_FIRST_PIPE_INSTANCE;
    }

    let pipe_name_wide: Vec<u16> = name.encode_utf16().chain(std::iter::once(0)).collect();

    // SAFETY: `pipe_name_wide` is a valid null-terminated UTF-16 string that outlives the call.
    // `sa` references a valid security descriptor. All parameters are valid.
    let handle = unsafe {
        CreateNamedPipeW(
            PCWSTR(pipe_name_wide.as_ptr()),
            open_mode,
            PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT,
            PIPE_UNLIMITED_INSTANCES,
            out_buffer_size,
            in_buffer_size,
            0, // default timeout
            Some(&sa),
        )
    };

    // Free the system-allocated security descriptor now that the pipe is created.
    // SAFETY: `sd.0` was allocated by ConvertStringSecurityDescriptorToSecurityDescriptorW.
    unsafe {
        let _ = LocalFree(Some(HLOCAL(sd.0)));
    }

    if handle == INVALID_HANDLE_VALUE {
        return Err(std::io::Error::last_os_error());
    }

    Ok(handle)
}

/// Resolves the client process ID from a connected named pipe handle, server-side.
///
/// Callers must never trust a client-supplied PID; this queries the OS for the
/// authoritative PID of the process on the other end of the pipe.
///
/// Returns `None` if the PID cannot be determined.
fn client_process_id(pipe: HANDLE) -> Option<u32> {
    let mut pid: u32 = 0;
    // SAFETY: `pipe` is a valid connected pipe handle; `pid` is a valid out pointer.
    let ok = unsafe { GetNamedPipeClientProcessId(pipe, &mut pid) };
    if ok.is_ok() && pid != 0 {
        Some(pid)
    } else {
        None
    }
}

/// Runs the shared named-pipe accept loop used by both the interactive console
/// and the Windows service entry points.
///
/// This factors out the common create-pipe -> `ConnectNamedPipe` ->
/// read-client-PID -> `max_clients`-check -> spawn-handler pattern. Each
/// iteration:
/// 1. Creates a pipe instance via `create_fn` (passing `true` for the first
///    instance so the caller can apply `FILE_FLAG_FIRST_PIPE_INSTANCE`).
/// 2. Blocks on `ConnectNamedPipe` until a client connects.
/// 3. Resolves the client's PID server-side (never trusting the client).
/// 4. Rejects the connection if `active_counter` has reached `max_clients`.
/// 5. Spawns a thread that invokes `handle_fn(pipe, pid)`; the handler owns the
///    pipe handle and is responsible for closing it. `active_counter` is
///    incremented before the handler is spawned and decremented when it returns.
///
/// The loop exits when `shutdown_flag` is set, or when even the first pipe
/// instance cannot be created.
///
/// # Arguments
/// * `create_fn` - Creates a pipe instance; `true` indicates the first instance.
/// * `handle_fn` - Per-client handler run on a dedicated thread.
/// * `max_clients` - Maximum number of concurrent handler threads.
/// * `active_counter` - Shared count of in-flight handler threads.
/// * `shutdown_flag` - Polled each iteration; the loop exits when it is set.
/// * `verbose` - When `true`, diagnostic errors are written to stderr
///   (interactive mode); when `false`, the loop runs silently (service mode).
pub fn run_accept_loop<C, H>(
    create_fn: C,
    handle_fn: H,
    max_clients: usize,
    active_counter: &'static AtomicUsize,
    shutdown_flag: &'static AtomicBool,
    verbose: bool,
) where
    C: Fn(bool) -> Result<HANDLE, String>,
    H: Fn(HANDLE, u32) + Send + Sync + 'static,
{
    let handle_fn = Arc::new(handle_fn);
    let mut is_first = true;

    loop {
        if shutdown_flag.load(Ordering::Relaxed) {
            break;
        }

        let pipe = match create_fn(is_first) {
            Ok(h) => h,
            Err(e) => {
                if verbose {
                    eprintln!("[error] Failed to create pipe instance: {e}");
                }
                if is_first {
                    // Cannot create even the first instance; nothing more to do.
                    break;
                }
                // For subsequent instances, wait briefly and retry.
                thread::sleep(Duration::from_secs(1));
                continue;
            }
        };
        is_first = false;

        // Block until a client connects.
        // SAFETY: `pipe` is a valid handle returned by `create_fn`.
        let connected = unsafe { ConnectNamedPipe(pipe, None) };
        if connected.is_err() {
            let err = std::io::Error::last_os_error();
            // ERROR_PIPE_CONNECTED (535): client connected between create and connect.
            if err.raw_os_error() != Some(535) {
                if verbose {
                    eprintln!("[error] ConnectNamedPipe failed: {err}");
                }
                // SAFETY: `pipe` is a valid handle from `create_fn`.
                unsafe {
                    let _ = CloseHandle(pipe);
                }
                continue;
            }
        }

        // Resolve the client PID server-side (don't trust the client).
        let pid = match client_process_id(pipe) {
            Some(p) => p,
            None => {
                if verbose {
                    eprintln!("[warn] Could not determine client PID");
                }
                // SAFETY: `pipe` is a valid connected handle from `create_fn`.
                unsafe {
                    let _ = DisconnectNamedPipe(pipe);
                    let _ = CloseHandle(pipe);
                }
                continue;
            }
        };

        // Reject if at maximum client capacity.
        if active_counter.load(Ordering::Relaxed) >= max_clients {
            if verbose {
                eprintln!("[warn] Max clients reached ({max_clients}), rejecting connection");
            }
            // SAFETY: `pipe` is a valid connected handle from `create_fn`.
            unsafe {
                let _ = DisconnectNamedPipe(pipe);
                let _ = CloseHandle(pipe);
            }
            continue;
        }
        active_counter.fetch_add(1, Ordering::Relaxed);

        // Transfer the handle to the client thread (HANDLE is !Send, use raw pointer).
        let raw_handle = pipe.0 as usize;
        let handler = Arc::clone(&handle_fn);
        thread::spawn(move || {
            let pipe = HANDLE(raw_handle as *mut c_void);
            handler(pipe, pid);
            active_counter.fetch_sub(1, Ordering::Relaxed);
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The per-user SDDL must resolve from the current process token and grant
    /// the current user access while explicitly denying ALL_APP_PACKAGES.
    #[test]
    fn build_pipe_sddl_includes_current_user_and_denies_app_packages() {
        let sddl = build_pipe_sddl().expect("current user SID should resolve in test context");
        // Denies AppContainer (ALL_APP_PACKAGES) processes.
        assert!(sddl.contains("(D;;GA;;;S-1-15-2-1)"), "missing app-package deny ACE: {sddl}");
        // Grants SYSTEM and Built-in Administrators full access.
        assert!(sddl.contains("(A;;GA;;;SY)"), "missing SYSTEM ACE: {sddl}");
        assert!(sddl.contains("(A;;GA;;;BA)"), "missing Administrators ACE: {sddl}");
    }

    /// A named pipe instance protected by the per-user SDDL must be creatable;
    /// this exercises the same `create_pipe_with_sddl` path the denial pipe
    /// server uses to stand up its listener.
    #[test]
    fn create_pipe_with_sddl_yields_valid_handle() {
        let sddl = build_pipe_sddl().expect("current user SID should resolve in test context");
        let pipe_name = format!(r"\\.\pipe\mxc-pipe-utils-test-{}", std::process::id());

        let handle = create_pipe_with_sddl(
            &pipe_name,
            &sddl,
            0x0000_0001, // PIPE_ACCESS_INBOUND
            64 * 1024,
            0,
            true,
        )
        .expect("pipe instance should be creatable with per-user SDDL");

        assert_ne!(handle, INVALID_HANDLE_VALUE);
        assert!(!handle.is_invalid());

        // SAFETY: `handle` is a valid pipe handle returned by create_pipe_with_sddl.
        unsafe {
            let _ = CloseHandle(handle);
        }
    }
}
