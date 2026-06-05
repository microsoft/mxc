// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Tier 4 — `RestrictedTokenRunner`.
//!
//! Script runner that executes commands inside a Win32 **restricted
//! primary token** with Low integrity. This is the bottom rung of the
//! downlevel containment ladder, used only when Tiers 1–3 are
//! unavailable or unable to honor the policy. See
//! `docs/proposals/downlevel_support/tier4-restricted-token.md` for
//! the full design.
//!
//! # Phase status
//!
//! - **Phase 1 (this commit):** Token construction, happy-path
//!   `CreateProcessAsUserW` spawn, validation rejections, and unit
//!   tests for the token shape. No UI Job Object, no Win32k
//!   mitigation, no proxy, no DACL integration yet — those layer on
//!   in later phases.
//!
//! # Restricting SID set
//!
//! The set is load-bearing for ancestor traversal: dropping
//! `Users` / `Authenticated Users` reintroduces the Tier 3 failure
//! mode where the contained process cannot walk into a workspace
//! under `C:\`. See the design doc's "Restricting SID set" section.

use std::ptr;

use windows::Win32::Foundation::{
    GetLastError, LocalFree, HANDLE, HLOCAL, LUID, WAIT_FAILED, WAIT_OBJECT_0, WAIT_TIMEOUT,
};
use windows::Win32::Security::Authorization::ConvertStringSidToSidW;
use windows::Win32::Security::{
    AdjustTokenPrivileges, CreateRestrictedToken, DuplicateTokenEx, IsValidSid,
    LookupPrivilegeValueW, SecurityImpersonation, SetTokenInformation, TokenIntegrityLevel,
    TokenPrimary, CREATE_RESTRICTED_TOKEN_FLAGS, DISABLE_MAX_PRIVILEGE, LUID_AND_ATTRIBUTES, PSID,
    SE_PRIVILEGE_ENABLED, SID_AND_ATTRIBUTES, TOKEN_ADJUST_PRIVILEGES, TOKEN_ALL_ACCESS,
    TOKEN_DUPLICATE, TOKEN_MANDATORY_LABEL, TOKEN_PRIVILEGES, TOKEN_QUERY,
};
use windows::Win32::System::Threading::{
    CreateProcessAsUserW, GetCurrentProcess, GetExitCodeProcess, OpenProcessToken, ResumeThread,
    TerminateProcess, WaitForSingleObject, PROCESS_CREATION_FLAGS, PROCESS_INFORMATION,
    STARTUPINFOW,
};
use windows_core::{PCWSTR, PWSTR};

use wxc_common::error::WxcError;
use wxc_common::logger::Logger;
use wxc_common::models::{ExecutionRequest, NetworkEnforcementMode, ScriptResponse};
use wxc_common::process_util::OwnedHandle;
use wxc_common::script_runner::{get_timeout_milliseconds, ScriptRunner};
use wxc_common::string_util;

const CREATE_SUSPENDED: PROCESS_CREATION_FLAGS = PROCESS_CREATION_FLAGS(0x0000_0004);

const SID_USERS: &str = "S-1-5-32-545";
const SID_AUTHENTICATED_USERS: &str = "S-1-5-11";
const SID_RESTRICTED_CODE: &str = "S-1-5-12";
const SID_LOW_INTEGRITY: &str = "S-1-16-4096";

const SE_GROUP_INTEGRITY: u32 = 0x0000_0020;

/// RAII for a heap-allocated PSID returned by `ConvertStringSidToSidW`.
struct OwnedSid(PSID);

impl OwnedSid {
    fn parse(s: &str) -> Result<Self, WxcError> {
        let wide = string_util::to_wide(s);
        let mut psid = PSID(ptr::null_mut());
        unsafe {
            ConvertStringSidToSidW(PCWSTR(wide.as_ptr()), &mut psid).map_err(|e| {
                WxcError::Initialization(format!("ConvertStringSidToSidW({s}): {e}"))
            })?;
            if psid.0.is_null() || !IsValidSid(psid).as_bool() {
                if !psid.0.is_null() {
                    let _ = LocalFree(Some(HLOCAL(psid.0)));
                }
                return Err(WxcError::Initialization(format!("invalid SID string: {s}")));
            }
        }
        Ok(Self(psid))
    }

    fn as_psid(&self) -> PSID {
        self.0
    }
}

impl Drop for OwnedSid {
    fn drop(&mut self) {
        if !self.0 .0.is_null() {
            unsafe {
                let _ = LocalFree(Some(HLOCAL(self.0 .0)));
            }
        }
    }
}

/// Build a restricted primary token from the current process.
///
/// The returned token has:
/// - All privileges dropped except `SeChangeNotify`
///   (`DISABLE_MAX_PRIVILEGE`).
/// - A restricting SID set of `[Users, AuthenticatedUsers,
///   RestrictedCode]` — see module-level docs for why `Users` is
///   load-bearing.
/// - Mandatory integrity level set to **Low**.
fn build_restricted_token() -> Result<OwnedHandle, WxcError> {
    // 1. Open current process token.
    let current_proc = unsafe { GetCurrentProcess() };
    let mut process_token = HANDLE::default();
    unsafe {
        OpenProcessToken(
            current_proc,
            TOKEN_DUPLICATE | TOKEN_QUERY,
            &mut process_token,
        )
    }
    .map_err(|e| WxcError::Initialization(format!("OpenProcessToken failed: {e}")))?;
    let process_token = OwnedHandle::new(process_token);

    // 2. Duplicate it into a primary token we can modify.
    let mut primary_token = HANDLE::default();
    unsafe {
        DuplicateTokenEx(
            process_token.get(),
            TOKEN_ALL_ACCESS,
            None,
            SecurityImpersonation,
            TokenPrimary,
            &mut primary_token,
        )
    }
    .map_err(|e| WxcError::Initialization(format!("DuplicateTokenEx failed: {e}")))?;
    let primary_token = OwnedHandle::new(primary_token);

    // 3. Build the restricting-SID list. Each `OwnedSid` keeps its SID
    //    buffer alive for the duration of this function; the kernel
    //    copies the SIDs into the new token during the
    //    `CreateRestrictedToken` call.
    let users_sid = OwnedSid::parse(SID_USERS)?;
    let auth_users_sid = OwnedSid::parse(SID_AUTHENTICATED_USERS)?;
    let restricted_code_sid = OwnedSid::parse(SID_RESTRICTED_CODE)?;

    let restricting_sids: [SID_AND_ATTRIBUTES; 3] = [
        SID_AND_ATTRIBUTES {
            Sid: users_sid.as_psid(),
            Attributes: 0,
        },
        SID_AND_ATTRIBUTES {
            Sid: auth_users_sid.as_psid(),
            Attributes: 0,
        },
        SID_AND_ATTRIBUTES {
            Sid: restricted_code_sid.as_psid(),
            Attributes: 0,
        },
    ];

    // 4. CreateRestrictedToken.
    let mut restricted_token = HANDLE::default();
    unsafe {
        CreateRestrictedToken(
            primary_token.get(),
            CREATE_RESTRICTED_TOKEN_FLAGS(DISABLE_MAX_PRIVILEGE.0),
            None,
            None,
            Some(&restricting_sids),
            &mut restricted_token,
        )
    }
    .map_err(|e| WxcError::Initialization(format!("CreateRestrictedToken failed: {e}")))?;
    let restricted_token = OwnedHandle::new(restricted_token);

    // 5. Drop integrity level to Low.
    set_low_integrity(restricted_token.get())?;

    Ok(restricted_token)
}

/// Set the mandatory integrity level on `token` to Low (`S-1-16-4096`).
fn set_low_integrity(token: HANDLE) -> Result<(), WxcError> {
    let low_sid = OwnedSid::parse(SID_LOW_INTEGRITY)?;

    let label = TOKEN_MANDATORY_LABEL {
        Label: SID_AND_ATTRIBUTES {
            Sid: low_sid.as_psid(),
            Attributes: SE_GROUP_INTEGRITY,
        },
    };

    unsafe {
        SetTokenInformation(
            token,
            TokenIntegrityLevel,
            &label as *const TOKEN_MANDATORY_LABEL as *const core::ffi::c_void,
            std::mem::size_of::<TOKEN_MANDATORY_LABEL>() as u32,
        )
    }
    .map_err(|e| {
        WxcError::Initialization(format!("SetTokenInformation(TokenIntegrityLevel): {e}"))
    })?;

    Ok(())
}

/// Script runner that executes commands inside a Win32 restricted
/// primary token with Low integrity. See module docs for the full
/// design.
pub struct RestrictedTokenRunner {
    // Reserved for Phase 3 (proxy + env-block injection).
    #[allow(dead_code)]
    proxy_address: Option<wxc_common::models::ProxyAddress>,
}

impl RestrictedTokenRunner {
    pub fn new() -> Self {
        Self {
            proxy_address: None,
        }
    }

    /// Core implementation, returning `Result` so error paths are
    /// concise. Translated to a `ScriptResponse` by [`Self::execute`].
    fn run_internal_impl(
        &self,
        request: &ExecutionRequest,
        logger: &mut Logger,
    ) -> Result<ScriptResponse, WxcError> {
        let token = build_restricted_token()?;
        logger.log_line("Restricted token built (Low IL, DISABLE_MAX_PRIVILEGE)");

        // `CreateProcessAsUserW` requires `SeIncreaseQuotaPrivilege` on
        // the calling token (and would otherwise also require
        // `SeAssignPrimaryTokenPrivilege`, but the latter is waived
        // because our token is a restricted derivative of the caller's
        // primary token). The kernel auto-enables privileges that are
        // present-but-disabled, but if the privilege isn't in the token
        // at all, the spawn fails with `ERROR_PRIVILEGE_NOT_HELD`. We
        // best-effort enable it here; if the privilege is absent we let
        // the `CreateProcessAsUserW` call surface a clear error.
        let _ = maybe_enable_quota_privilege();

        // STARTUPINFOW — no STARTF_USESTDHANDLES; the child shares our
        // console. Phase 1 has no attribute list, no UI Job Object, no
        // proxy env block.
        let mut desktop_wide = string_util::to_wide("winsta0\\default");
        let si = STARTUPINFOW {
            cb: std::mem::size_of::<STARTUPINFOW>() as u32,
            lpDesktop: PWSTR(desktop_wide.as_mut_ptr()),
            ..Default::default()
        };

        let mut cmd_line_wide = string_util::to_wide(&request.script_code);
        let working_dir_wide = string_util::to_wide(&request.working_directory);
        let working_dir_pcwstr = if request.working_directory.is_empty() {
            PCWSTR::null()
        } else {
            PCWSTR(working_dir_wide.as_ptr())
        };

        let creation_flags = CREATE_SUSPENDED;

        let mut pi = PROCESS_INFORMATION::default();
        unsafe {
            CreateProcessAsUserW(
                Some(token.get()),
                PCWSTR::null(),
                Some(PWSTR(cmd_line_wide.as_mut_ptr())),
                None,
                None,
                false,
                creation_flags,
                None,
                working_dir_pcwstr,
                &si,
                &mut pi,
            )
        }
        .map_err(|e| WxcError::Process(format!("CreateProcessAsUserW failed: {e}")))?;

        logger.log_line(&format!(
            "Process created under restricted token (PID: {})",
            pi.dwProcessId,
        ));

        let process_handle = OwnedHandle::new(pi.hProcess);
        let thread_handle = OwnedHandle::new(pi.hThread);

        // Resume now. Phase 2 will assign a UiJobObject before this.
        let resumed = unsafe { ResumeThread(thread_handle.get()) };
        if resumed == u32::MAX {
            let err = unsafe { GetLastError() };
            unsafe {
                let _ = TerminateProcess(process_handle.get(), u32::MAX);
            }
            return Err(WxcError::Process(format!("ResumeThread failed: {err:?}")));
        }

        // Wait + collect exit code.
        let timeout_ms = get_timeout_milliseconds(request.script_timeout);
        let wait_result = unsafe { WaitForSingleObject(process_handle.get(), timeout_ms) };
        match wait_result {
            WAIT_OBJECT_0 => {}
            WAIT_TIMEOUT => unsafe {
                let _ = TerminateProcess(process_handle.get(), u32::MAX);
                let _ = WaitForSingleObject(process_handle.get(), u32::MAX);
            },
            WAIT_FAILED => {
                let err = unsafe { GetLastError() };
                return Err(WxcError::Process(format!(
                    "WaitForSingleObject failed: {err:?}"
                )));
            }
            other => {
                return Err(WxcError::Process(format!(
                    "WaitForSingleObject returned unexpected value: {}",
                    other.0
                )));
            }
        }

        let mut exit_code: u32 = 0;
        unsafe {
            GetExitCodeProcess(process_handle.get(), &mut exit_code)
                .map_err(|_| WxcError::Process("GetExitCodeProcess failed".into()))?;
        }

        Ok(ScriptResponse {
            exit_code: exit_code as i32,
            standard_out: String::new(),
            standard_err: String::new(),
            error_message: String::new(),
            ..Default::default()
        })
    }
}

impl Default for RestrictedTokenRunner {
    fn default() -> Self {
        Self::new()
    }
}

impl ScriptRunner for RestrictedTokenRunner {
    fn validate_runner(&self, request: &ExecutionRequest) -> Result<(), ScriptResponse> {
        // LPAC is an AppContainer-only construct; there is no
        // principal in a restricted token that LPAC can scope.
        if request.policy.least_privilege_mode {
            return Err(ScriptResponse::error(
                "Tier 4 rejects leastPrivilegeMode=true: LPAC is an AppContainer-only construct",
            ));
        }

        // Capability SIDs require an AppContainer principal; firewall
        // rules cannot be cleanly keyed to a non-AppContainer
        // principal either.
        if !request.policy.capabilities.is_empty() {
            return Err(ScriptResponse::error(
                "Tier 4 rejects non-empty capabilities: capability SIDs require an \
                 AppContainer principal",
            ));
        }

        if matches!(
            request.policy.network_enforcement_mode,
            NetworkEnforcementMode::Capabilities | NetworkEnforcementMode::Both,
        ) {
            return Err(ScriptResponse::error(
                "Tier 4 rejects network_enforcement_mode={Capabilities, Both}: Tier 4 is \
                 proxy-only because firewall COM rules cannot key to a non-AppContainer \
                 principal",
            ));
        }

        Ok(())
    }

    fn execute(&mut self, request: &ExecutionRequest, logger: &mut Logger) -> ScriptResponse {
        match self.run_internal_impl(request, logger) {
            Ok(response) => response,
            Err(e) => ScriptResponse::error(&e.to_string()),
        }
    }
}

// ─────────────────────────────────────────────────────────────────────
// Test helpers + unit tests
// ─────────────────────────────────────────────────────────────────────

/// Try to enable `SeIncreaseQuotaPrivilege` on the current process
/// token. Returns `true` if the privilege is now enabled (or was
/// already), `false` if it isn't present in the token at all. This is
/// best-effort: a `false` return doesn't fail the spawn here, the
/// subsequent `CreateProcessAsUserW` call will surface a clear
/// `ERROR_PRIVILEGE_NOT_HELD` if the privilege is genuinely missing.
fn maybe_enable_quota_privilege() -> bool {
    set_privilege_enabled(w_str("SeIncreaseQuotaPrivilege"))
        // SeAssignPrimaryTokenPrivilege isn't strictly required for
        // restricted derivatives of the caller's token, but enable it
        // anyway when present so admin/system callers don't surprise.
        | set_privilege_enabled(w_str("SeAssignPrimaryTokenPrivilege"))
}

fn w_str(s: &str) -> Vec<u16> {
    string_util::to_wide(s)
}

fn set_privilege_enabled(name_wide: Vec<u16>) -> bool {
    unsafe {
        let mut token = HANDLE::default();
        if OpenProcessToken(
            GetCurrentProcess(),
            TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY,
            &mut token,
        )
        .is_err()
        {
            return false;
        }
        let token = OwnedHandle::new(token);

        let mut luid = LUID::default();
        if LookupPrivilegeValueW(PCWSTR::null(), PCWSTR(name_wide.as_ptr()), &mut luid).is_err() {
            return false;
        }

        let tp = TOKEN_PRIVILEGES {
            PrivilegeCount: 1,
            Privileges: [LUID_AND_ATTRIBUTES {
                Luid: luid,
                Attributes: SE_PRIVILEGE_ENABLED,
            }],
        };

        let _ = AdjustTokenPrivileges(token.get(), false, Some(&tp), 0, None, None);
        // AdjustTokenPrivileges returns success even if the privilege
        // is not held — check GetLastError for ERROR_NOT_ALL_ASSIGNED.
        GetLastError().is_ok()
    }
}

/// Test helper: query `TokenPrivileges` from a token and return the
/// privilege LUIDs in a sorted Vec for comparison.
#[cfg(test)]
fn token_privilege_luids(token: HANDLE) -> Vec<(u32, i32)> {
    use windows::Win32::Security::{GetTokenInformation, TokenPrivileges, TOKEN_PRIVILEGES};

    let mut needed: u32 = 0;
    // First call: probe required size.
    let _ = unsafe { GetTokenInformation(token, TokenPrivileges, None, 0, &mut needed) };
    let mut buf = vec![0u8; needed as usize];
    unsafe {
        GetTokenInformation(
            token,
            TokenPrivileges,
            Some(buf.as_mut_ptr().cast()),
            buf.len() as u32,
            &mut needed,
        )
    }
    .expect("GetTokenInformation(TokenPrivileges)");
    let header = unsafe { &*(buf.as_ptr() as *const TOKEN_PRIVILEGES) };
    let count = header.PrivilegeCount as usize;
    let privs_ptr = unsafe {
        (buf.as_ptr() as *const TOKEN_PRIVILEGES)
            .cast::<u8>()
            .add(4)
    };
    let mut out = Vec::with_capacity(count);
    for i in 0..count {
        let entry_ptr = unsafe {
            privs_ptr.add(i * std::mem::size_of::<windows::Win32::Security::LUID_AND_ATTRIBUTES>())
        };
        let entry =
            unsafe { &*(entry_ptr as *const windows::Win32::Security::LUID_AND_ATTRIBUTES) };
        out.push((entry.Luid.LowPart, entry.Luid.HighPart));
    }
    out.sort();
    out
}

/// Test helper: read the mandatory integrity level RID from a token.
#[cfg(test)]
fn token_integrity_level_rid(token: HANDLE) -> u32 {
    use windows::Win32::Security::{
        GetSidSubAuthority, GetSidSubAuthorityCount, GetTokenInformation,
    };

    let mut needed: u32 = 0;
    let _ = unsafe { GetTokenInformation(token, TokenIntegrityLevel, None, 0, &mut needed) };
    let mut buf = vec![0u8; needed as usize];
    unsafe {
        GetTokenInformation(
            token,
            TokenIntegrityLevel,
            Some(buf.as_mut_ptr().cast()),
            buf.len() as u32,
            &mut needed,
        )
    }
    .expect("GetTokenInformation(TokenIntegrityLevel)");
    let label = unsafe { &*(buf.as_ptr() as *const TOKEN_MANDATORY_LABEL) };
    let count = unsafe { *GetSidSubAuthorityCount(label.Label.Sid) };
    assert!(count > 0);
    unsafe { *GetSidSubAuthority(label.Label.Sid, (count - 1) as u32) }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_restricted_token_returns_a_token() {
        let token = build_restricted_token().expect("build_restricted_token");
        assert!(!token.get().is_invalid());
    }

    /// `DISABLE_MAX_PRIVILEGE` strips every privilege except
    /// `SeChangeNotify`. The kernel still presents the entry in the
    /// `TokenPrivileges` array but with `SE_PRIVILEGE_REMOVED` set;
    /// in practice the count drops to <= 1 (just `SeChangeNotify`).
    #[test]
    fn build_restricted_token_drops_privileges() {
        let token = build_restricted_token().expect("build_restricted_token");
        let privs = token_privilege_luids(token.get());
        assert!(
            privs.len() <= 1,
            "expected DISABLE_MAX_PRIVILEGE to leave <= 1 privilege, got {} ({:?})",
            privs.len(),
            privs,
        );
    }

    /// Low Mandatory Level = `S-1-16-4096`, so the last sub-authority
    /// (the integrity RID) must be 0x1000 (4096).
    #[test]
    fn build_restricted_token_sets_low_integrity() {
        const SECURITY_MANDATORY_LOW_RID: u32 = 0x1000;
        let token = build_restricted_token().expect("build_restricted_token");
        let rid = token_integrity_level_rid(token.get());
        assert_eq!(
            rid, SECURITY_MANDATORY_LOW_RID,
            "expected Low IL ({:#x}), got {:#x}",
            SECURITY_MANDATORY_LOW_RID, rid,
        );
    }

    /// Smoke spawn: `cmd /c exit 42` under a restricted token must
    /// return exit code 42. Requires `SeIncreaseQuotaPrivilege` on the
    /// caller; skipped (with a clear log) when run from a
    /// non-elevated shell.
    #[test]
    fn restricted_token_runs_simple_command() {
        use wxc_common::logger::Mode;
        use wxc_common::models::ContainerPolicy;

        if !maybe_enable_quota_privilege() {
            eprintln!(
                "restricted_token_runs_simple_command: skipped — caller token \
                 lacks SeIncreaseQuotaPrivilege (run from an elevated shell to exercise)"
            );
            return;
        }

        let runner = RestrictedTokenRunner::new();
        let req = ExecutionRequest {
            script_code: "cmd.exe /c exit 42".to_string(),
            script_timeout: 30_000,
            policy: ContainerPolicy::default(),
            ..Default::default()
        };
        let mut logger = Logger::new(Mode::Buffer);
        let resp = runner.run_internal_impl(&req, &mut logger).unwrap();
        assert_eq!(resp.exit_code, 42, "exit code mismatch; resp={:?}", resp);
    }
}
