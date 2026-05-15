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
//! - **Phase 1:** Token construction, happy-path
//!   `CreateProcessAsUserW` spawn, validation rejections, and unit
//!   tests for the token shape.
//! - **Phase 2:** UI Job Object attachment and Win32k mitigation —
//!   honors `policy.ui.*` and `policy.ui.disable` using the shared
//!   `UiJobObject`, `process_mitigation`, and `ui_policy` infra.
//! - **Phase 3 (this commit):** Proxy + environment injection. The
//!   runner owns a `ProxyCoordinator`, launches the builtin test
//!   proxy when requested, and injects HTTP_PROXY/HTTPS_PROXY into
//!   a fresh `CREATE_UNICODE_ENVIRONMENT` block via the shared
//!   `child_env::build_proxy_env_block` helper. Tier 4 is
//!   proxy-only per v1's policy-satisfiability matrix.
//! - Phase 4 wires the DACL manager into the dispatcher; Phase 5
//!   handles docs/telemetry/E2E.
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
    CreateProcessAsUserW, DeleteProcThreadAttributeList, GetCurrentProcess, GetExitCodeProcess,
    InitializeProcThreadAttributeList, OpenProcessToken, ResumeThread, TerminateProcess,
    UpdateProcThreadAttribute, WaitForSingleObject, CREATE_UNICODE_ENVIRONMENT,
    EXTENDED_STARTUPINFO_PRESENT, LPPROC_THREAD_ATTRIBUTE_LIST, PROCESS_CREATION_FLAGS,
    PROCESS_INFORMATION, PROC_THREAD_ATTRIBUTE_MITIGATION_POLICY, STARTUPINFOEXW, STARTUPINFOW,
};
use windows_core::{PCWSTR, PWSTR};

use crate::job_object::UiJobObject;
use crate::process_mitigation;
use crate::proxy_coordinator::ProxyCoordinator;
use wxc_common::child_env::build_proxy_env_block;
use wxc_common::error::WxcError;
use wxc_common::logger::Logger;
use wxc_common::models::{ExecutionRequest, NetworkEnforcementMode, ProxyAddress, ScriptResponse};
use wxc_common::process_util::{OwnedHandle, SendOwnedHandle};
use wxc_common::sandbox_process::{SandboxBackend, SandboxProcess, StdioMode};
use wxc_common::script_runner::{get_timeout_milliseconds, ScriptRunner};
use wxc_common::{string_util, ui_policy};

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
#[derive(Default)]
pub struct RestrictedTokenRunner {
    proxy_coordinator: ProxyCoordinator,
}

impl RestrictedTokenRunner {
    pub fn new() -> Self {
        Self::default()
    }

    /// Spawn the child under a restricted token and hand back a live
    /// [`RestrictedTokenChild`] (process/thread handles, UI job object,
    /// pid, and resolved timeout) *before* it is waited on. Shared by the
    /// run-to-completion helper ([`Self::run_internal_impl`]) and the
    /// streaming [`SandboxBackend::spawn`] surface.
    fn spawn_child(
        &mut self,
        request: &ExecutionRequest,
        logger: &mut Logger,
    ) -> Result<RestrictedTokenChild, WxcError> {
        // ── Builtin test proxy (Phase 3) ─────────────────────────
        //
        // If the policy asks for the builtin test proxy, launch it
        // first so we know the address before constructing the env
        // block. Mirrors `BaseContainerRunner::execute`. Then any
        // configured proxy address is honored — Tier 4 is proxy-only
        // per v1's policy-satisfiability matrix.
        let mut request = request.clone();
        if request.policy.network_proxy.builtin_test_server {
            match self.proxy_coordinator.launch_test_proxy(logger) {
                Ok(port) => {
                    let addr = ProxyAddress::new("127.0.0.1".to_string(), port);
                    request.policy.network_proxy.address = Some(addr);
                }
                Err(e) => {
                    return Err(WxcError::Process(format!(
                        "Failed to start builtin test proxy: {e}"
                    )));
                }
            }
        }
        let proxy_address: Option<ProxyAddress> = request.policy.network_proxy.address.clone();

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

        // ── Attribute list ────────────────────────────────────────
        //
        // Tier 4 only ever needs one entry: PROC_THREAD_ATTRIBUTE_
        // MITIGATION_POLICY when `policy.ui.disable` is set. Unlike
        // AppContainer there is no SECURITY_CAPABILITIES or LPAC
        // attribute. When the policy doesn't request the Win32k
        // mitigation, we skip the extended startup info entirely.
        let mitigation_value: u64 = process_mitigation::win32k_disable_value();
        let use_attr_list = request.policy.ui.disable;

        let (mut _attr_list_buf, attr_list): (Vec<u8>, Option<LPPROC_THREAD_ATTRIBUTE_LIST>) =
            if use_attr_list {
                let mut size: usize = 0;
                unsafe {
                    let _ = InitializeProcThreadAttributeList(None, 1, None, &mut size);
                }
                let mut buf = vec![0u8; size];
                let list = LPPROC_THREAD_ATTRIBUTE_LIST(buf.as_mut_ptr() as *mut _);
                unsafe {
                    InitializeProcThreadAttributeList(Some(list), 1, None, &mut size).map_err(
                        |e| WxcError::Process(format!("InitializeProcThreadAttributeList: {e}")),
                    )?;
                    UpdateProcThreadAttribute(
                        list,
                        0,
                        PROC_THREAD_ATTRIBUTE_MITIGATION_POLICY as usize,
                        Some(&mitigation_value as *const u64 as *const core::ffi::c_void),
                        std::mem::size_of::<u64>(),
                        None,
                        None,
                    )
                    .map_err(|e| {
                        WxcError::Process(format!(
                            "UpdateProcThreadAttribute(MITIGATION_POLICY): {e}"
                        ))
                    })?;
                }
                logger.log_line("Win32k mitigation queued for child process");
                (buf, Some(list))
            } else {
                (Vec::new(), None)
            };

        // RAII guard so DeleteProcThreadAttributeList runs on every
        // exit path (success, validation error, terminate, panic).
        struct AttrListGuard(Option<LPPROC_THREAD_ATTRIBUTE_LIST>);
        impl Drop for AttrListGuard {
            fn drop(&mut self) {
                if let Some(list) = self.0 {
                    unsafe { DeleteProcThreadAttributeList(list) };
                }
            }
        }
        let _attr_guard = AttrListGuard(attr_list);

        // ── STARTUPINFO[EX]W ─────────────────────────────────────
        //
        // Use STARTUPINFOEXW unconditionally so the size matches what
        // EXTENDED_STARTUPINFO_PRESENT advertises; lpAttributeList is
        // optional (null when `use_attr_list == false`).
        let mut desktop_wide = string_util::to_wide("winsta0\\default");
        let si_ex = STARTUPINFOEXW {
            StartupInfo: STARTUPINFOW {
                cb: std::mem::size_of::<STARTUPINFOEXW>() as u32,
                lpDesktop: PWSTR(desktop_wide.as_mut_ptr()),
                ..Default::default()
            },
            lpAttributeList: attr_list.unwrap_or(LPPROC_THREAD_ATTRIBUTE_LIST(ptr::null_mut())),
        };

        let mut cmd_line_wide = string_util::to_wide(&request.script_code);
        let working_dir_wide = string_util::to_wide(&request.working_directory);
        let working_dir_pcwstr = if request.working_directory.is_empty() {
            PCWSTR::null()
        } else {
            PCWSTR(working_dir_wide.as_ptr())
        };

        // ── Environment block (Phase 3) ──────────────────────────
        //
        // When a proxy is configured (either by user or by the
        // builtin test server we just launched), inject
        // HTTP_PROXY/HTTPS_PROXY/NO_PROXY into a fresh env block via
        // the shared `build_proxy_env_block` helper. This avoids
        // mutating process-global env vars (not thread-safe).
        //
        // `build_proxy_env_block` sources the base entries from
        // `CreateEnvironmentBlock(bInherit=FALSE)` so the parent
        // process's env is never inherited into the sandboxed child;
        // a transient failure to query the user profile env is
        // surfaced as a `WxcError::Process` rather than silently
        // falling back to an empty/leaky block.
        let env_block: Option<Vec<u16>> = proxy_address
            .as_ref()
            .map(build_proxy_env_block)
            .transpose()?;
        let env_ptr = env_block
            .as_ref()
            .map(|block| block.as_ptr() as *const core::ffi::c_void);

        let creation_flags = if env_block.is_some() {
            PROCESS_CREATION_FLAGS(
                EXTENDED_STARTUPINFO_PRESENT.0 | CREATE_UNICODE_ENVIRONMENT.0 | CREATE_SUSPENDED.0,
            )
        } else {
            PROCESS_CREATION_FLAGS(EXTENDED_STARTUPINFO_PRESENT.0 | CREATE_SUSPENDED.0)
        };

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
                env_ptr,
                working_dir_pcwstr,
                &si_ex.StartupInfo as *const STARTUPINFOW,
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

        // ── UI Job Object ────────────────────────────────────────
        //
        // CRITICAL: child was created with CREATE_SUSPENDED. We must
        // either successfully attach the Job Object and ResumeThread,
        // or TerminateProcess. Anything that returns an error in this
        // block must terminate first. Mirrors the AppContainer runner
        // sequencing verbatim — the token model doesn't affect Job
        // Object attachment.
        let job = match (|| -> Result<UiJobObject, WxcError> {
            let job = UiJobObject::new()?;
            let restrictions = ui_policy::resolve_ui_restrictions(
                &request.policy.ui,
                &request.policy.base_process_ui,
            );
            job.set_ui_limits(&restrictions)?;
            job.assign_process(process_handle.get())?;
            Ok(job)
        })() {
            Ok(job) => {
                logger.log_line("UI Job Object assigned to child process");
                job
            }
            Err(e) => {
                unsafe {
                    let _ = TerminateProcess(process_handle.get(), u32::MAX);
                }
                return Err(e);
            }
        };

        // Resume the child now that UI restrictions are in place.
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
        Ok(RestrictedTokenChild {
            process: process_handle,
            _thread: thread_handle,
            job,
            pid: pi.dwProcessId,
            timeout_ms,
        })
    }

    /// Run the sandboxed command to completion under a restricted token,
    /// returning its exit code. Spawns via [`Self::spawn_child`] and then
    /// waits (terminating the child on timeout). Used by the [`ScriptRunner`]
    /// surface and the unit tests; the streaming [`SandboxBackend`] surface
    /// waits via [`RestrictedTokenSandboxProcess`] instead.
    fn run_internal_impl(
        &mut self,
        request: &ExecutionRequest,
        logger: &mut Logger,
    ) -> Result<ScriptResponse, WxcError> {
        let child = self.spawn_child(request, logger)?;
        let wait_result = unsafe { WaitForSingleObject(child.process.get(), child.timeout_ms) };
        match wait_result {
            WAIT_OBJECT_0 => {}
            WAIT_TIMEOUT => unsafe {
                let _ = TerminateProcess(child.process.get(), u32::MAX);
                let _ = WaitForSingleObject(child.process.get(), u32::MAX);
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
            GetExitCodeProcess(child.process.get(), &mut exit_code)
                .map_err(|_| WxcError::Process("GetExitCodeProcess failed".into()))?;
        }

        Ok(ScriptResponse {
            exit_code: exit_code as i32,
            ..Default::default()
        })
    }
}

/// A live child spawned under a restricted token, before it is waited on.
/// Produced by [`RestrictedTokenRunner::spawn_child`] and consumed either by
/// the run-to-completion helper or the streaming
/// [`RestrictedTokenSandboxProcess`].
struct RestrictedTokenChild {
    process: OwnedHandle,
    _thread: OwnedHandle,
    job: UiJobObject,
    pid: u32,
    timeout_ms: u32,
}

impl SandboxBackend for RestrictedTokenRunner {
    fn validate(&self, request: &ExecutionRequest) -> Result<(), ScriptResponse> {
        // Tier 4 honors the same policy-satisfiability constraints on either
        // surface; reuse the run-to-completion checks.
        ScriptRunner::validate_runner(self, request)
    }

    fn spawn(
        &mut self,
        request: &ExecutionRequest,
        logger: &mut Logger,
        _stdio: StdioMode,
    ) -> Result<Box<dyn SandboxProcess>, ScriptResponse> {
        use wxc_common::validator::validate_common;

        validate_common(request)?;
        self.validate(request)?;

        // Tier 4 does not capture child stdio: the child inherits the
        // executor's own std handles regardless of `stdio` (a TTY when the
        // binary runs under a pty), matching the pre-unification behavior.
        // Streaming callers therefore observe an exit code but no piped output.
        let child = self
            .spawn_child(request, logger)
            .map_err(|e| ScriptResponse::error(&e.to_string()))?;
        let proxy_coordinator = std::mem::take(&mut self.proxy_coordinator);
        Ok(Box::new(RestrictedTokenSandboxProcess::new(
            child,
            proxy_coordinator,
        )))
    }
}

/// A running restricted-token (Tier 4) process exposed as a [`SandboxProcess`].
/// Owns the process handle, the UI job object, and the per-run proxy state,
/// which it tears down once the child exits. Tier 4 does not capture stdio, so
/// the `take_std*` accessors return `None`.
struct RestrictedTokenSandboxProcess {
    process: SendOwnedHandle,
    _thread: SendOwnedHandle,
    job: UiJobObject,
    pid: u32,
    timeout_ms: u32,
    proxy_coordinator: ProxyCoordinator,
    teardown_done: bool,
}

// SAFETY: mirrors the AppContainer / BaseContainer sandbox processes. The only
// thread-affine state is the Windows process HANDLE, wrapped in
// `SendOwnedHandle`; it is process-global and owned exclusively by this handle,
// so moving it (and the owned job / proxy state) across threads is sound.
unsafe impl Send for RestrictedTokenSandboxProcess {}

impl RestrictedTokenSandboxProcess {
    fn new(mut child: RestrictedTokenChild, proxy_coordinator: ProxyCoordinator) -> Self {
        let process = SendOwnedHandle::take(&mut child.process);
        let thread = SendOwnedHandle::take(&mut child._thread);
        Self {
            process,
            _thread: thread,
            job: child.job,
            pid: child.pid,
            timeout_ms: child.timeout_ms,
            proxy_coordinator,
            teardown_done: false,
        }
    }

    fn run_teardown(&mut self) {
        if self.teardown_done {
            return;
        }
        self.teardown_done = true;
        let mut logger = Logger::new(wxc_common::logger::Mode::Buffer);
        self.proxy_coordinator.stop(&mut logger);
    }
}

impl SandboxProcess for RestrictedTokenSandboxProcess {
    fn take_stdin(&mut self) -> Option<Box<dyn std::io::Write + Send>> {
        None
    }

    fn take_stdout(&mut self) -> Option<Box<dyn std::io::Read + Send>> {
        None
    }

    fn take_stderr(&mut self) -> Option<Box<dyn std::io::Read + Send>> {
        None
    }

    fn try_wait(&mut self) -> std::io::Result<Option<i32>> {
        match unsafe { WaitForSingleObject(self.process.get(), 0) } {
            WAIT_OBJECT_0 => {
                let mut code: u32 = 0;
                if unsafe { GetExitCodeProcess(self.process.get(), &mut code) }.is_err() {
                    return Err(std::io::Error::other("GetExitCodeProcess failed"));
                }
                Ok(Some(code as i32))
            }
            WAIT_TIMEOUT => Ok(None),
            _ => Err(std::io::Error::other("WaitForSingleObject failed")),
        }
    }

    fn id(&self) -> u32 {
        self.pid
    }

    fn kill(&mut self) -> std::io::Result<()> {
        // Tree-kill the job: the child and every descendant assigned to it die
        // together.
        self.job.terminate(u32::MAX);
        Ok(())
    }

    fn wait(&mut self) -> std::io::Result<i32> {
        let result = match unsafe { WaitForSingleObject(self.process.get(), self.timeout_ms) } {
            WAIT_OBJECT_0 => {
                let mut code: u32 = 0;
                if unsafe { GetExitCodeProcess(self.process.get(), &mut code) }.is_err() {
                    Err(std::io::Error::other("GetExitCodeProcess failed"))
                } else {
                    Ok(code as i32)
                }
            }
            WAIT_TIMEOUT => Err(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                format!("script timed out after {}ms", self.timeout_ms),
            )),
            _ => Err(std::io::Error::other("WaitForSingleObject failed")),
        };

        // Tree-kill so any backgrounded descendant dies before teardown removes
        // the proxy enforcement, then reap the root before stopping the proxy.
        let _ = self.kill();
        unsafe {
            let _ = WaitForSingleObject(self.process.get(), u32::MAX);
        }
        self.run_teardown();
        result
    }
}

impl Drop for RestrictedTokenSandboxProcess {
    fn drop(&mut self) {
        // Kill and reap before tearing down proxy state so an abandoned-but-
        // running sandbox cannot outlive its enforcement (or leak as an orphan).
        let _ = self.kill();
        unsafe {
            let _ = WaitForSingleObject(self.process.get(), u32::MAX);
        }
        self.run_teardown();
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
        let result = self.run_internal_impl(request, logger);
        // Always stop the builtin test proxy if we launched it,
        // regardless of success or failure.
        self.proxy_coordinator.stop(logger);
        match result {
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

        let mut runner = RestrictedTokenRunner::new();
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

    /// Phase 2: with `policy.ui.disable = true`, the attribute list
    /// must be allocated and the Win32k mitigation attribute must
    /// install without error. We don't have a portable way to assert
    /// the bit is set on the child from a unit test, so we exercise
    /// the same code path end-to-end via `cmd /c exit 0` and rely on
    /// `UpdateProcThreadAttribute` returning success to confirm the
    /// attribute layout is valid. Skipped when privileges are
    /// unavailable.
    #[test]
    fn restricted_token_attaches_win32k_mitigation_when_ui_disabled() {
        use wxc_common::logger::Mode;
        use wxc_common::models::{ContainerPolicy, UiPolicy};

        if !maybe_enable_quota_privilege() {
            eprintln!(
                "restricted_token_attaches_win32k_mitigation_when_ui_disabled: \
                 skipped — caller lacks SeIncreaseQuotaPrivilege"
            );
            return;
        }

        let mut runner = RestrictedTokenRunner::new();
        let req = ExecutionRequest {
            script_code: "cmd.exe /c exit 0".to_string(),
            script_timeout: 30_000,
            policy: ContainerPolicy {
                ui: UiPolicy {
                    disable: true,
                    ..Default::default()
                },
                ..Default::default()
            },
            ..Default::default()
        };
        let mut logger = Logger::new(Mode::Buffer);
        let resp = runner.run_internal_impl(&req, &mut logger).unwrap();
        assert_eq!(resp.exit_code, 0, "exit code mismatch; resp={:?}", resp);
    }

    /// Phase 2: the child must be assigned to our `UiJobObject`
    /// before `ResumeThread`. We verify the contract by spawning the
    /// child and asserting it is in the calling process's job set
    /// via `IsProcessInJob(child, NULL)`, which returns TRUE only
    /// when the calling process is a member of *any* job the target
    /// also belongs to. (We pass `NULL` for the job handle to mean
    /// "the caller's job"; in this test, the test process is not in
    /// any job, so we instead use `OpenProcess` and the job handle
    /// owned by the runner via observable side-effect of the spawn
    /// succeeding under CREATE_SUSPENDED + assign + ResumeThread.)
    ///
    /// Practical check: if the Job Object attach fails, the runner
    /// terminates the child and returns an `Err`. A successful
    /// `Ok` return with the expected exit code is therefore proof
    /// the Job Object was assigned. Skipped when privileges are
    /// unavailable.
    #[test]
    fn restricted_token_assigns_ui_job_object() {
        use wxc_common::logger::Mode;
        use wxc_common::models::ContainerPolicy;

        if !maybe_enable_quota_privilege() {
            eprintln!(
                "restricted_token_assigns_ui_job_object: skipped — caller \
                 lacks SeIncreaseQuotaPrivilege"
            );
            return;
        }

        let mut runner = RestrictedTokenRunner::new();
        let req = ExecutionRequest {
            script_code: "cmd.exe /c exit 7".to_string(),
            script_timeout: 30_000,
            policy: ContainerPolicy::default(),
            ..Default::default()
        };
        let mut logger = Logger::new(Mode::Buffer);
        let resp = runner.run_internal_impl(&req, &mut logger).unwrap();
        assert_eq!(resp.exit_code, 7, "exit code mismatch; resp={:?}", resp);
    }

    /// Phase 3: when a proxy address is configured, the child's
    /// environment must include HTTP_PROXY / HTTPS_PROXY pointing to
    /// that address. We verify by spawning `cmd /c set HTTP_PROXY`
    /// and… actually `cmd /c set ...` writes to stdout, which the
    /// runner doesn't capture in Phase 1. Instead we drive the
    /// exit-code channel via `cmd /c if defined HTTP_PROXY (exit 11)
    /// else (exit 22)` — the script returns 11 when the env block
    /// reached the child, 22 otherwise. Skipped when privileges are
    /// unavailable.
    #[test]
    fn restricted_token_injects_proxy_env_when_configured() {
        use wxc_common::logger::Mode;
        use wxc_common::models::{ContainerPolicy, ProxyAddress, ProxyConfig};

        if !maybe_enable_quota_privilege() {
            eprintln!(
                "restricted_token_injects_proxy_env_when_configured: skipped \
                 — caller lacks SeIncreaseQuotaPrivilege"
            );
            return;
        }

        let mut runner = RestrictedTokenRunner::new();
        let req = ExecutionRequest {
            script_code: "cmd.exe /c if defined HTTP_PROXY (exit 11) else (exit 22)".to_string(),
            script_timeout: 30_000,
            policy: ContainerPolicy {
                network_proxy: ProxyConfig {
                    address: Some(ProxyAddress::new("127.0.0.1".to_string(), 8080)),
                    ..Default::default()
                },
                ..Default::default()
            },
            ..Default::default()
        };
        let mut logger = Logger::new(Mode::Buffer);
        let resp = runner.run_internal_impl(&req, &mut logger).unwrap();
        assert_eq!(
            resp.exit_code, 11,
            "HTTP_PROXY not visible in child env; resp={:?}",
            resp
        );
    }
}
