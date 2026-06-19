// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Per-connection caller identification + access checks.
//!
//! Each pipe connection carries an identity (the user SID of the
//! process that connected) and a PID (`GetNamedPipeClientProcessId`).
//! The shim enforces two access invariants:
//!
//! 1. **`OpenDenialSession(target_pid)`** is only honoured when the
//!    caller (under impersonation) can open `target_pid` for query.
//!    This uses Windows' ACL system as the source of truth: if the
//!    caller's token does not grant
//!    `PROCESS_QUERY_LIMITED_INFORMATION` on the target, the shim
//!    refuses to spin up an audit session for it. Sandbox runtimes
//!    legitimately re-parent + token-restrict their workloads, so
//!    parent-PID or SID-equality checks don't generalise; the
//!    impersonate-then-OpenProcess check does.
//!
//! 2. **`ExtendDenialSession(name, pids)`** is only honoured when the
//!    caller's SID matches the SID that originally opened the session
//!    (tracked out-of-band in `pipe_server.rs`'s ownership map) AND
//!    each PID in the extend list passes the same
//!    impersonate-then-OpenProcess check as #1.

use std::ffi::c_void;

use windows::core::PWSTR;
use windows::Win32::Foundation::{CloseHandle, GetLastError, LocalFree, HANDLE, HLOCAL};
use windows::Win32::Security::Authorization::ConvertSidToStringSidW;
use windows::Win32::Security::{
    GetTokenInformation, RevertToSelf, TokenUser, TOKEN_QUERY, TOKEN_USER,
};
use windows::Win32::System::Pipes::{GetNamedPipeClientProcessId, ImpersonateNamedPipeClient};
use windows::Win32::System::Threading::{
    GetCurrentThread, OpenProcess, OpenThreadToken, PROCESS_QUERY_LIMITED_INFORMATION,
};

/// Identifies the process on the other end of an accepted pipe
/// connection.
///
/// Constructed once per connection by [`from_pipe`]. After
/// construction, the shim has already called `RevertToSelf` — the
/// caller's identity lives in this struct, not on the thread token,
/// so downstream ETW work runs with the shim's `LocalService` +
/// `SeSystemProfilePrivilege` as usual.
#[derive(Debug, Clone)]
pub struct CallerContext {
    /// PID of the process that connected to the pipe. Currently used
    /// for diagnostic logging; retained on the struct for future
    /// per-PID rate limiting / audit checks.
    #[allow(dead_code)]
    pub pid: u32,
    /// String-form SID (`S-1-5-...`) of the user the caller is running
    /// as. Used as the ownership key in the extend-session map and as
    /// the authority for the same-user PID ownership check.
    pub sid: String,
}

/// Reason a caller context could not be built.
#[derive(Debug, thiserror::Error)]
pub enum CallerContextError {
    #[error("GetNamedPipeClientProcessId failed: Win32 error {0:#X}")]
    GetClientPid(u32),
    #[error("ImpersonateNamedPipeClient failed: Win32 error {0:#X}")]
    Impersonate(u32),
    #[error("OpenThreadToken failed: Win32 error {0:#X}")]
    OpenThreadToken(u32),
    #[error("GetTokenInformation(TokenUser) failed: Win32 error {0:#X}")]
    GetTokenInformation(u32),
    #[error("ConvertSidToStringSidW failed: Win32 error {0:#X}")]
    ConvertSid(u32),
}

/// Builds a [`CallerContext`] for a freshly-connected pipe handle.
///
/// **Order matters**: impersonates the caller, reads the token, then
/// reverts. All Win32 calls outside the impersonate/revert window run
/// with the shim's own (`LocalService`) identity.
pub fn from_pipe(pipe: HANDLE) -> Result<CallerContext, CallerContextError> {
    let mut pid: u32 = 0;
    // SAFETY: `pipe` is a valid server-side pipe handle; `&mut pid` is
    // a valid out-parameter.
    let res = unsafe { GetNamedPipeClientProcessId(pipe, &mut pid) };
    if res.is_err() {
        let last = unsafe { GetLastError() };
        return Err(CallerContextError::GetClientPid(last.0));
    }

    // Impersonate so subsequent OpenThreadToken reads the caller's
    // token, not the shim's.
    let imp = unsafe { ImpersonateNamedPipeClient(pipe) };
    if imp.is_err() {
        let last = unsafe { GetLastError() };
        return Err(CallerContextError::Impersonate(last.0));
    }

    // Use an RAII guard so RevertToSelf runs even on early returns.
    let _revert = RevertGuard;

    let mut token = HANDLE::default();
    let r = unsafe { OpenThreadToken(GetCurrentThread(), TOKEN_QUERY, true, &mut token) };
    if r.is_err() {
        let last = unsafe { GetLastError() };
        return Err(CallerContextError::OpenThreadToken(last.0));
    }
    let _token_handle = TokenHandle(token);

    // First call sizes the buffer; second call fills it.
    let mut required: u32 = 0;
    let _ = unsafe { GetTokenInformation(token, TokenUser, None, 0, &mut required) };
    if required == 0 {
        let last = unsafe { GetLastError() };
        return Err(CallerContextError::GetTokenInformation(last.0));
    }
    let mut buf = vec![0u8; required as usize];
    let r = unsafe {
        GetTokenInformation(
            token,
            TokenUser,
            Some(buf.as_mut_ptr() as *mut c_void),
            required,
            &mut required,
        )
    };
    if r.is_err() {
        let last = unsafe { GetLastError() };
        return Err(CallerContextError::GetTokenInformation(last.0));
    }

    // SAFETY: `buf` starts with a `TOKEN_USER` struct followed by the
    // SID data the struct points into.
    let token_user = unsafe { &*(buf.as_ptr() as *const TOKEN_USER) };
    let sid_ptr = token_user.User.Sid;

    let mut sid_wide = PWSTR::null();
    let r = unsafe { ConvertSidToStringSidW(sid_ptr, &mut sid_wide) };
    if r.is_err() {
        let last = unsafe { GetLastError() };
        return Err(CallerContextError::ConvertSid(last.0));
    }
    let sid_string = unsafe { wide_to_string(sid_wide) };
    // ConvertSidToStringSidW allocates with LocalAlloc; free with
    // LocalFree.
    unsafe {
        let _ = LocalFree(Some(HLOCAL(sid_wide.0 as *mut c_void)));
    }

    Ok(CallerContext {
        pid,
        sid: sid_string,
    })
}

/// Validates that the caller (identified by the live pipe handle's
/// impersonation token) has at least `PROCESS_QUERY_LIMITED_INFORMATION`
/// access to `target_pid`. This is the right check because the
/// Windows ACL system already encodes "who can audit whom" — if the
/// caller can open the process at all, they have legitimate access.
///
/// Re-impersonates on each call (the [`from_pipe`] reverter already
/// dropped the impersonation token). The shim's `LocalService`
/// identity is restored before returning.
pub fn caller_can_query_pid(pipe: HANDLE, target_pid: u32) -> bool {
    let imp = unsafe { ImpersonateNamedPipeClient(pipe) };
    if imp.is_err() {
        return false;
    }
    let _revert = RevertGuard;

    // While impersonating, try to open the target. Success means the
    // caller's token grants access via normal Windows ACLs. The
    // returned handle is closed by `TokenHandle` (mis-named but
    // semantically a process handle here).
    let result = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, target_pid) };
    match result {
        Ok(h) => {
            // SAFETY: we own this handle for the duration of this
            // function call.
            unsafe {
                let _ = CloseHandle(h);
            }
            true
        }
        Err(_) => false,
    }
}

/// Same as [`caller_can_query_pid`] but checks a batch of PIDs under
/// a single impersonation bracket. Returns `false` if ANY pid is not
/// accessible to the caller's token.
pub fn caller_can_query_all_pids(pipe: HANDLE, target_pids: &[u32]) -> bool {
    let imp = unsafe { ImpersonateNamedPipeClient(pipe) };
    if imp.is_err() {
        return false;
    }
    let _revert = RevertGuard;

    for &pid in target_pids {
        let result = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid) };
        match result {
            Ok(h) => unsafe {
                let _ = CloseHandle(h);
            },
            Err(_) => return false,
        }
    }
    true
}

struct RevertGuard;
impl Drop for RevertGuard {
    fn drop(&mut self) {
        // RevertToSelf can fail in pathological cases; ignore the
        // result — there's nothing we can do, and the thread is about
        // to be reused for the next connection (which re-impersonates
        // anyway).
        unsafe {
            let _ = RevertToSelf();
        }
    }
}

struct TokenHandle(HANDLE);
impl Drop for TokenHandle {
    fn drop(&mut self) {
        unsafe {
            let _ = CloseHandle(self.0);
        }
    }
}

unsafe fn wide_to_string(pwstr: PWSTR) -> String {
    if pwstr.0.is_null() {
        return String::new();
    }
    let mut len = 0usize;
    while *pwstr.0.add(len) != 0 {
        len += 1;
    }
    let slice = std::slice::from_raw_parts(pwstr.0, len);
    String::from_utf16_lossy(slice)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn caller_can_query_self_pid_via_dummy_pipe() {
        // We can't synthesise a pipe handle here easily; this test
        // just exercises the `OpenProcess` round-trip in isolation by
        // calling it from a non-impersonated thread, which exercises
        // the underlying code path even if the impersonation step
        // would normally precede it. Real coverage of the
        // impersonate-then-open path lives in the VM functional tests.
        let h = unsafe {
            windows::Win32::System::Threading::OpenProcess(
                PROCESS_QUERY_LIMITED_INFORMATION,
                false,
                std::process::id(),
            )
        }
        .expect("self OpenProcess");
        unsafe {
            let _ = CloseHandle(h);
        }
    }
}
