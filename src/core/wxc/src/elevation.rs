//! Elevation detection and UAC self-relaunch for `wxc-exec --audit`.
//!
//! `--audit` starts a kernel ETW session via `wpr.exe` which requires
//! Administrator. Rather than fail with an opaque "Access denied" when
//! the caller isn't elevated, we detect the non-elevated state up-front
//! and re-launch ourselves with `ShellExecuteExW` + `runas`, triggering
//! the standard UAC prompt. We then wait for the elevated child, read
//! its exit code, and propagate it so the outer invoker sees the same
//! return contract.
//!
//! Only compiled on Windows.

use std::env;
use std::os::windows::ffi::OsStrExt;
use std::path::PathBuf;

use windows::core::PCWSTR;
use windows::Win32::Foundation::{CloseHandle, ERROR_CANCELLED, HANDLE, WAIT_FAILED};
use windows::Win32::Security::{GetTokenInformation, TokenElevation, TOKEN_ELEVATION, TOKEN_QUERY};
use windows::Win32::System::Threading::{
    GetCurrentProcess, GetExitCodeProcess, OpenProcessToken, WaitForSingleObject, INFINITE,
};
use windows::Win32::UI::Shell::{ShellExecuteExW, SEE_MASK_NOCLOSEPROCESS, SHELLEXECUTEINFOW};

/// `SW_SHOWNORMAL` from `Win32_UI_WindowsAndMessaging`. Duplicated here
/// (as a literal) so we don't pull in that whole feature just for one
/// constant.
const SW_SHOWNORMAL: i32 = 1;

/// Returns `true` if the current process token is elevated.
///
/// Uses `TokenElevation` (available since Vista). On any API failure we
/// return `false` — a spurious re-launch is preferable to running
/// `wpr.exe` and failing mid-trace with a confusing error.
pub fn is_elevated() -> bool {
    unsafe {
        let mut token: HANDLE = HANDLE::default();
        if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token).is_err() {
            return false;
        }
        let mut elevation = TOKEN_ELEVATION::default();
        let mut ret_len: u32 = 0;
        let ok = GetTokenInformation(
            token,
            TokenElevation,
            Some(&mut elevation as *mut _ as *mut _),
            std::mem::size_of::<TOKEN_ELEVATION>() as u32,
            &mut ret_len,
        );
        let _ = CloseHandle(token);
        match ok {
            Ok(()) => elevation.TokenIsElevated != 0,
            Err(_) => false,
        }
    }
}

/// Encodes a UTF-16 null-terminated buffer for Win32 wide-string APIs.
fn to_wide<S: AsRef<std::ffi::OsStr>>(s: S) -> Vec<u16> {
    s.as_ref().encode_wide().chain(std::iter::once(0)).collect()
}

/// Quotes a single command-line argument using CommandLineToArgvW rules.
///
/// See MSDN "Parsing C++ Command-Line Arguments". We wrap in double
/// quotes and escape internal backslash runs preceding a `"` plus the
/// `"` itself. Empty arguments become `""`.
fn quote_arg(arg: &str) -> String {
    if !arg.is_empty() && !arg.contains([' ', '\t', '"', '\n']) {
        return arg.to_string();
    }
    let mut out = String::with_capacity(arg.len() + 2);
    out.push('"');
    let chars: Vec<char> = arg.chars().collect();
    let mut i = 0;
    while i < chars.len() {
        let mut backslashes = 0;
        while i < chars.len() && chars[i] == '\\' {
            backslashes += 1;
            i += 1;
        }
        if i == chars.len() {
            for _ in 0..(backslashes * 2) {
                out.push('\\');
            }
        } else if chars[i] == '"' {
            for _ in 0..(backslashes * 2 + 1) {
                out.push('\\');
            }
            out.push('"');
            i += 1;
        } else {
            for _ in 0..backslashes {
                out.push('\\');
            }
            out.push(chars[i]);
            i += 1;
        }
    }
    out.push('"');
    out
}

/// Re-launches the current executable elevated with the same argv and
/// waits for it to exit. Returns the child's exit code on success, or
/// an error describing the failure (UAC declined, ShellExecute error).
pub fn relaunch_elevated_and_wait() -> Result<i32, String> {
    let exe: PathBuf = env::current_exe().map_err(|e| format!("current_exe failed: {e}"))?;

    // Rebuild the argument string from argv (skip argv[0]).
    let args: Vec<String> = env::args().skip(1).map(|a| quote_arg(&a)).collect();
    let params = args.join(" ");

    let verb_w = to_wide("runas");
    let file_w = to_wide(exe.as_os_str());
    let params_w = to_wide(&params);
    let cwd_w = to_wide(
        env::current_dir()
            .map(|p| p.into_os_string())
            .unwrap_or_default(),
    );

    let mut sei = SHELLEXECUTEINFOW {
        cbSize: std::mem::size_of::<SHELLEXECUTEINFOW>() as u32,
        fMask: SEE_MASK_NOCLOSEPROCESS,
        lpVerb: PCWSTR(verb_w.as_ptr()),
        lpFile: PCWSTR(file_w.as_ptr()),
        lpParameters: PCWSTR(params_w.as_ptr()),
        lpDirectory: PCWSTR(cwd_w.as_ptr()),
        nShow: SW_SHOWNORMAL,
        ..Default::default()
    };

    let result = unsafe { ShellExecuteExW(&mut sei) };
    if let Err(e) = result {
        // Distinguish UAC decline (ERROR_CANCELLED = 1223) from other
        // failures so the caller can surface a friendlier message.
        let code = e.code();
        let raw = code.0 as u32 & 0xFFFF;
        if raw == ERROR_CANCELLED.0 {
            return Err("UAC prompt was cancelled; --audit requires elevation.".to_string());
        }
        return Err(format!("ShellExecuteExW failed: {e}"));
    }

    let proc_handle = sei.hProcess;
    if proc_handle.is_invalid() {
        return Err("ShellExecuteExW returned no process handle".to_string());
    }

    // Wait for the elevated child and read its exit code.
    let wait = unsafe { WaitForSingleObject(proc_handle, INFINITE) };
    if wait == WAIT_FAILED {
        unsafe {
            let _ = CloseHandle(proc_handle);
        }
        return Err("WaitForSingleObject failed on elevated child".to_string());
    }
    let mut exit_code: u32 = 0;
    let rc = unsafe { GetExitCodeProcess(proc_handle, &mut exit_code) };
    unsafe {
        let _ = CloseHandle(proc_handle);
    }
    if rc.is_err() {
        return Err("GetExitCodeProcess failed on elevated child".to_string());
    }
    Ok(exit_code as i32)
}
