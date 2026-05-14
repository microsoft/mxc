// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use core::ffi::c_void;
use std::mem::size_of;
use std::ptr;

use windows::Win32::Foundation::{
    GetLastError, LocalFree, HLOCAL, WAIT_FAILED, WAIT_OBJECT_0, WAIT_TIMEOUT,
};
use windows::Win32::Security::Isolation::{
    CreateAppContainerProfile, DeriveAppContainerSidFromAppContainerName,
};
use windows::Win32::Security::PSID;
use windows::Win32::System::JobObjects::{
    AssignProcessToJobObject, CreateJobObjectW, JobObjectCpuRateControlInformation,
    JobObjectExtendedLimitInformation, SetInformationJobObject, TerminateJobObject,
    JOBOBJECT_CPU_RATE_CONTROL_INFORMATION, JOBOBJECT_CPU_RATE_CONTROL_INFORMATION_0,
    JOBOBJECT_EXTENDED_LIMIT_INFORMATION, JOB_OBJECT_CPU_RATE_CONTROL_ENABLE,
    JOB_OBJECT_CPU_RATE_CONTROL_HARD_CAP, JOB_OBJECT_LIMIT_ACTIVE_PROCESS,
    JOB_OBJECT_LIMIT_JOB_MEMORY, JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
};
use windows::Win32::System::Threading::{
    CreateProcessW, DeleteProcThreadAttributeList, GetExitCodeProcess,
    InitializeProcThreadAttributeList, ResumeThread, TerminateProcess, UpdateProcThreadAttribute,
    WaitForSingleObject, CREATE_SUSPENDED, LPPROC_THREAD_ATTRIBUTE_LIST, PROCESS_CREATION_FLAGS,
    PROCESS_INFORMATION, STARTUPINFOEXW, STARTUPINFOW,
};
use windows_core::{PCWSTR, PWSTR};

use crate::error::WxcError;
use crate::logger::Logger;
use crate::models::{
    CodexRequest, NetworkEnforcementMode, NetworkPolicy, ResourceLimits, ScriptResponse,
};
use crate::process_util::{get_capability_sid_from_name, OwnedHandle, SidAndAttributes};
use crate::script_runner::{get_timeout_milliseconds, ScriptRunner};
use crate::string_util;

// Attribute list constants (not always exported by the windows crate)
const PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES: usize = 0x0002_0009;
const PROC_THREAD_ATTRIBUTE_ALL_APPLICATION_PACKAGES_POLICY: usize = 0x0002_000F;
const PROC_THREAD_ATTRIBUTE_CHILD_PROCESS_POLICY: usize = 0x0002_000E;
const PROCESS_CREATION_ALL_APPLICATION_PACKAGES_OPT_OUT: u32 = 1;
const PROCESS_CREATION_CHILD_PROCESS_RESTRICTED: u32 = 0x01;
const EXTENDED_STARTUPINFO_PRESENT: PROCESS_CREATION_FLAGS = PROCESS_CREATION_FLAGS(0x0008_0000);
const CREATE_UNICODE_ENVIRONMENT: PROCESS_CREATION_FLAGS = PROCESS_CREATION_FLAGS(0x0000_0400);

/// SE_GROUP_ENABLED attribute value for SID_AND_ATTRIBUTES.
const SE_GROUP_ENABLED: u32 = 0x0000_0004;

/// HRESULT value for ERROR_ALREADY_EXISTS (183 / 0xB7).
const HRESULT_ERROR_ALREADY_EXISTS: i32 = 0x8007_00B7u32 as i32;

/// Proxy-related env var names to strip/override when building the child env block.
const PROXY_VAR_NAMES: &[&str] = &["HTTP_PROXY", "HTTPS_PROXY", "NO_PROXY", "ALL_PROXY"];

/// Build a Unicode environment block for CreateProcessW with proxy env vars injected.
///
/// Copies the current process environment, strips any existing proxy vars
/// (case-insensitive), injects HTTP_PROXY/HTTPS_PROXY pointing to the
/// localhost proxy, and returns a double-null-terminated UTF-16 block.
fn build_proxy_env_block(address: &crate::models::ProxyAddress) -> Vec<u16> {
    let proxy_url = address.to_url();
    let mut entries: Vec<(String, String)> = Vec::new();

    for (key, value) in std::env::vars_os() {
        let key_str = key.to_string_lossy();
        let is_proxy_var = PROXY_VAR_NAMES
            .iter()
            .any(|name| key_str.eq_ignore_ascii_case(name));
        if !is_proxy_var {
            entries.push((key_str.into_owned(), value.to_string_lossy().into_owned()));
        }
    }

    entries.push(("HTTP_PROXY".to_string(), proxy_url.clone()));
    entries.push(("HTTPS_PROXY".to_string(), proxy_url));

    // Sort case-insensitively by key (required by CreateProcessW).
    entries.sort_by(|(key_a, _), (key_b, _)| {
        key_a.to_ascii_uppercase().cmp(&key_b.to_ascii_uppercase())
    });

    let mut block = Vec::new();
    for (key, value) in &entries {
        for ch in format!("{}={}", key, value).encode_utf16() {
            block.push(ch);
        }
        block.push(0);
    }
    block.push(0);
    block
}

fn build_job_extended_limit_information(
    resource_limits: &ResourceLimits,
) -> JOBOBJECT_EXTENDED_LIMIT_INFORMATION {
    let mut info = JOBOBJECT_EXTENDED_LIMIT_INFORMATION::default();
    info.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;

    if resource_limits.memory_mb > 0 {
        info.BasicLimitInformation.LimitFlags |= JOB_OBJECT_LIMIT_JOB_MEMORY;
        info.JobMemoryLimit = resource_limits
            .memory_mb
            .saturating_mul(1024)
            .saturating_mul(1024) as usize;
    }

    if resource_limits.max_processes > 0 {
        info.BasicLimitInformation.LimitFlags |= JOB_OBJECT_LIMIT_ACTIVE_PROCESS;
        info.BasicLimitInformation.ActiveProcessLimit = resource_limits.max_processes;
    }

    info
}

fn build_job_cpu_rate_information(
    resource_limits: &ResourceLimits,
) -> Option<JOBOBJECT_CPU_RATE_CONTROL_INFORMATION> {
    if resource_limits.cpu_rate_percent == 0 {
        return None;
    }

    Some(JOBOBJECT_CPU_RATE_CONTROL_INFORMATION {
        ControlFlags: JOB_OBJECT_CPU_RATE_CONTROL_ENABLE | JOB_OBJECT_CPU_RATE_CONTROL_HARD_CAP,
        Anonymous: JOBOBJECT_CPU_RATE_CONTROL_INFORMATION_0 {
            CpuRate: u32::from(resource_limits.cpu_rate_percent) * 100,
        },
    })
}

fn create_appcontainer_job_object(
    resource_limits: &ResourceLimits,
) -> Result<OwnedHandle, WxcError> {
    let job_handle = OwnedHandle::new(
        unsafe { CreateJobObjectW(None, PCWSTR::null()) }
            .map_err(|e| WxcError::Process(format!("CreateJobObjectW failed: {e}")))?,
    );

    let extended_info = build_job_extended_limit_information(resource_limits);
    unsafe {
        SetInformationJobObject(
            job_handle.get(),
            JobObjectExtendedLimitInformation,
            &extended_info as *const _ as *const c_void,
            size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32,
        )
    }
    .map_err(|e| WxcError::Process(format!("SetInformationJobObject(extended) failed: {e}")))?;

    if let Some(cpu_info) = build_job_cpu_rate_information(resource_limits) {
        unsafe {
            SetInformationJobObject(
                job_handle.get(),
                JobObjectCpuRateControlInformation,
                &cpu_info as *const _ as *const c_void,
                size_of::<JOBOBJECT_CPU_RATE_CONTROL_INFORMATION>() as u32,
            )
        }
        .map_err(|e| WxcError::Process(format!("SetInformationJobObject(cpu) failed: {e}")))?;
    }

    Ok(job_handle)
}

/// RAII guard that frees capability SID pointers via `LocalFree` on drop.
/// Ensures SIDs are freed regardless of the error return path.
struct CapabilitySidGuard(Vec<*mut core::ffi::c_void>);

impl CapabilitySidGuard {
    fn new() -> Self {
        Self(Vec::new())
    }

    fn push(&mut self, sid: *mut core::ffi::c_void) {
        self.0.push(sid);
    }
}

impl Drop for CapabilitySidGuard {
    fn drop(&mut self) {
        for &sid in &self.0 {
            unsafe {
                let _ = LocalFree(Some(HLOCAL(sid)));
            }
        }
    }
}

/// A `SECURITY_CAPABILITIES`-compatible struct for `UpdateProcThreadAttribute`.
#[repr(C)]
struct SecurityCapabilities {
    app_container_sid: PSID,
    capabilities: *mut SidAndAttributes,
    capability_count: u32,
    reserved: u32,
}

/// Script runner that executes commands inside a Windows AppContainer.
pub struct AppContainerScriptRunner {
    app_container_name: String,
    app_container_sid: PSID,
    proxy_address: Option<crate::models::ProxyAddress>,
}

impl AppContainerScriptRunner {
    pub fn new() -> Self {
        Self {
            app_container_name: String::new(),
            app_container_sid: PSID(ptr::null_mut()),
            proxy_address: None,
        }
    }

    /// Create or derive an AppContainer SID for the given container name.
    fn create_app_container_sid(name: &str) -> Result<PSID, WxcError> {
        let wide_name = string_util::to_wide(name);
        let pcwstr_name = PCWSTR(wide_name.as_ptr());

        let display = string_util::to_wide("Agent scripting container");
        let pcwstr_display = PCWSTR(display.as_ptr());

        let desc = string_util::to_wide("Profile for agentic script execution");
        let pcwstr_desc = PCWSTR(desc.as_ptr());

        let result =
            unsafe { CreateAppContainerProfile(pcwstr_name, pcwstr_display, pcwstr_desc, None) };

        match result {
            Ok(sid) => Ok(sid),
            Err(e) if e.code().0 == HRESULT_ERROR_ALREADY_EXISTS => {
                // Profile already exists — derive the SID from the name.
                let sid = unsafe {
                    DeriveAppContainerSidFromAppContainerName(pcwstr_name).map_err(|e2| {
                        WxcError::Initialization(format!(
                            "DeriveAppContainerSidFromAppContainerName failed: {}",
                            e2
                        ))
                    })?
                };
                Ok(sid)
            }
            Err(e) => Err(WxcError::Initialization(format!(
                "CreateAppContainerProfile failed: {}",
                e
            ))),
        }
    }

    /// Core implementation of `run_internal`, returning `Result` for ergonomic error handling.
    fn run_internal_impl(
        &self,
        request: &CodexRequest,
        logger: &mut Logger,
    ) -> Result<ScriptResponse, WxcError> {
        // --- Validate permissiveLearningMode ---
        for cap in &request.policy.capabilities {
            if cap == "permissiveLearningMode" {
                #[cfg(debug_assertions)]
                {
                    logger.log_line("*** SECURITY WARNING ***");
                    logger.log_line(
                        "permissiveLearningMode is ENABLED. \
                         Container will learn and record access patterns.",
                    );
                }
                #[cfg(not(debug_assertions))]
                {
                    return Ok(ScriptResponse::error(
                        "SECURITY: permissiveLearningMode not allowed in release builds",
                    ));
                }
            }
        }

        // --- Build capability list ---
        let mut capabilities_to_add: Vec<String> = request.policy.capabilities.clone();
        capabilities_to_add.push("AgenticAppContainer".to_string());

        let use_capabilities_for_network = matches!(
            request.policy.network_enforcement_mode,
            NetworkEnforcementMode::Capabilities | NetworkEnforcementMode::Both
        );
        if use_capabilities_for_network
            && request.policy.default_network_policy == NetworkPolicy::Allow
            && !capabilities_to_add.iter().any(|c| c == "internetClient")
        {
            capabilities_to_add.push("internetClient".to_string());
        }

        // --- Derive SIDs for each capability ---
        let mut capability_sid_guard = CapabilitySidGuard::new();
        let mut sid_attrs: Vec<SidAndAttributes> = Vec::new();

        for cap_name in &capabilities_to_add {
            match get_capability_sid_from_name(cap_name) {
                Ok(sid_ptr) => {
                    sid_attrs.push(SidAndAttributes {
                        sid: PSID(sid_ptr),
                        attributes: SE_GROUP_ENABLED,
                    });
                    capability_sid_guard.push(sid_ptr);
                }
                Err(e) => {
                    logger.log_line(&format!(
                        "Warning: could not get SID for capability '{}': {}",
                        cap_name, e
                    ));
                }
            }
        }

        // --- Setup SECURITY_CAPABILITIES ---
        let security_capabilities = SecurityCapabilities {
            app_container_sid: self.app_container_sid,
            capabilities: if sid_attrs.is_empty() {
                ptr::null_mut()
            } else {
                sid_attrs.as_mut_ptr()
            },
            capability_count: sid_attrs.len() as u32,
            reserved: 0,
        };

        // --- Allocate and initialize attribute list ---
        let mut attr_count = 1u32;
        if request.policy.least_privilege_mode {
            attr_count += 1;
        }
        if request.resource_limits.child_processes_blocked() {
            attr_count += 1;
        }
        let mut attr_list_size: usize = 0;

        // First call to get the required buffer size.
        unsafe {
            let _ = InitializeProcThreadAttributeList(None, attr_count, None, &mut attr_list_size);
        }

        let mut attr_list_buf: Vec<u8> = vec![0u8; attr_list_size];
        let attr_list = LPPROC_THREAD_ATTRIBUTE_LIST(attr_list_buf.as_mut_ptr() as *mut _);

        unsafe {
            InitializeProcThreadAttributeList(
                Some(attr_list),
                attr_count,
                None,
                &mut attr_list_size,
            )
            .map_err(|e| WxcError::Process(format!("InitializeProcThreadAttributeList: {}", e)))?;
        }

        // RAII guard to call DeleteProcThreadAttributeList on exit.
        struct AttrListGuard(LPPROC_THREAD_ATTRIBUTE_LIST);
        impl Drop for AttrListGuard {
            fn drop(&mut self) {
                unsafe {
                    DeleteProcThreadAttributeList(self.0);
                }
            }
        }
        let _attr_guard = AttrListGuard(attr_list);

        // --- Update attributes ---

        // 1. SECURITY_CAPABILITIES
        unsafe {
            UpdateProcThreadAttribute(
                attr_list,
                0,
                PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES,
                Some(
                    &security_capabilities as *const SecurityCapabilities
                        as *const core::ffi::c_void,
                ),
                std::mem::size_of::<SecurityCapabilities>(),
                None,
                None,
            )
            .map_err(|e| {
                WxcError::Process(format!(
                    "UpdateProcThreadAttribute(SECURITY_CAPABILITIES): {}",
                    e
                ))
            })?;
        }

        // 2. ALL_APPLICATION_PACKAGES_POLICY (LPAC mode)
        let lpac_value = PROCESS_CREATION_ALL_APPLICATION_PACKAGES_OPT_OUT;
        if request.policy.least_privilege_mode {
            unsafe {
                UpdateProcThreadAttribute(
                    attr_list,
                    0,
                    PROC_THREAD_ATTRIBUTE_ALL_APPLICATION_PACKAGES_POLICY,
                    Some(&lpac_value as *const u32 as *const core::ffi::c_void),
                    std::mem::size_of::<u32>(),
                    None,
                    None,
                )
                .map_err(|e| {
                    WxcError::Process(format!("UpdateProcThreadAttribute(LPAC): {}", e))
                })?;
            }
        }

        // 3. CHILD_PROCESS_POLICY (block child process creation)
        let child_process_policy = PROCESS_CREATION_CHILD_PROCESS_RESTRICTED;
        if request.resource_limits.child_processes_blocked() {
            unsafe {
                UpdateProcThreadAttribute(
                    attr_list,
                    0,
                    PROC_THREAD_ATTRIBUTE_CHILD_PROCESS_POLICY,
                    Some(&child_process_policy as *const u32 as *const c_void),
                    size_of::<u32>(),
                    None,
                    None,
                )
                .map_err(|e| {
                    WxcError::Process(format!(
                        "UpdateProcThreadAttribute(CHILD_PROCESS_POLICY): {}",
                        e
                    ))
                })?;
            }
        }

        // --- Setup STARTUPINFOEXW ---
        let mut desktop_wide = string_util::to_wide("winsta0\\default");

        // No STARTF_USESTDHANDLES — child inherits parent's console.
        let si_ex = STARTUPINFOEXW {
            StartupInfo: STARTUPINFOW {
                cb: std::mem::size_of::<STARTUPINFOEXW>() as u32,
                lpDesktop: PWSTR(desktop_wide.as_mut_ptr()),
                ..Default::default()
            },
            lpAttributeList: attr_list,
        };

        // --- Build command line ---
        let mut cmd_line_wide = string_util::to_wide(&request.script_code);

        let working_dir_wide = string_util::to_wide(&request.working_directory);
        let working_dir_pcwstr = if request.working_directory.is_empty() {
            PCWSTR::null()
        } else {
            PCWSTR(working_dir_wide.as_ptr())
        };

        // Build an explicit environment block when proxy is active.
        // This avoids mutating process-global env vars (which isn't thread-safe).
        let env_block: Option<Vec<u16>> = self.proxy_address.as_ref().map(build_proxy_env_block);

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

        let job_handle = create_appcontainer_job_object(&request.resource_limits)?;

        // --- Create process (console inheritance) ---
        //
        // Console I/O path — no pipes, no relay threads:
        //
        //   stdin:  node-pty → ConPTY → wxc-exec → PowerShell (AppContainer)
        //   stdout: node-pty ← ConPTY ←─────────── PowerShell (shares parent's console)
        //                    ↑
        //                 onData()
        //
        // The child attaches to wxc-exec's console (the ConPTY created by node-pty)
        // so PowerShell sees a real terminal — PSReadLine, ANSI, UTF-8 all work.
        //
        // Why this works for AppContainer:
        //
        //   1. Kernel (PspSetupUserProcessAddressSpace):
        //      ObDuplicateObject copies the parent's ConsoleHandle
        //      (\Device\ConDrv\Reference) into the child using the parent's
        //      security context — before the AppContainer token takes effect.
        //
        //   2. condrv:
        //      FILE_DEVICE_ALLOW_APPCONTAINER_TRAVERSAL is set, so the I/O
        //      Manager permits the AppContainer to open \Device\ConDrv\Connect.
        //
        //   3. condrv (CdCreateConnection):
        //      Inheritance path skips CdAccessCheck. Having the Reference
        //      handle is proof of authorization.
        //
        //   4. conhost (ConsoleHandleConnectionRequest):
        //      No token check — allocates I/O handles unconditionally.
        //
        // bInheritHandles = false: we have no explicit handles to inherit.
        // Console attachment is a separate mechanism — the child automatically
        // attaches to the parent's console session via \Device\ConDrv during
        // process initialization, regardless of bInheritHandles. Since we don't
        // pass CREATE_NEW_CONSOLE or DETACH_PROCESS, the child shares our console.
        let mut pi = PROCESS_INFORMATION::default();

        unsafe {
            CreateProcessW(
                PCWSTR::null(),
                Some(PWSTR(cmd_line_wide.as_mut_ptr())),
                None,
                None,
                false, // bInheritHandles = false — no explicit handles to inherit
                creation_flags,
                env_ptr,
                working_dir_pcwstr,
                &si_ex.StartupInfo as *const STARTUPINFOW,
                &mut pi,
            )
        }
        .map_err(|err| WxcError::Process(format!("CreateProcessW failed: {}", err)))?;

        logger.log_line(&format!(
            "Process created successfully (PID: {})",
            pi.dwProcessId
        ));

        let process_handle = OwnedHandle::new(pi.hProcess);
        let thread_handle = OwnedHandle::new(pi.hThread);

        if let Err(err) =
            unsafe { AssignProcessToJobObject(job_handle.get(), process_handle.get()) }
        {
            unsafe {
                let _ = TerminateProcess(process_handle.get(), u32::MAX);
                let _ = WaitForSingleObject(process_handle.get(), u32::MAX);
            }
            return Err(WxcError::Process(format!(
                "AssignProcessToJobObject failed: {}",
                err
            )));
        }

        if unsafe { ResumeThread(thread_handle.get()) } == u32::MAX {
            let err = unsafe { GetLastError() };
            unsafe {
                let _ = TerminateJobObject(job_handle.get(), u32::MAX);
                let _ = WaitForSingleObject(process_handle.get(), u32::MAX);
            }
            return Err(WxcError::Process(format!("ResumeThread failed: {:?}", err)));
        }

        // --- Wait for child process to exit ---
        // No relay threads needed — child shares our console directly.
        let timeout_ms = get_timeout_milliseconds(request.script_timeout);

        let wait_result = unsafe { WaitForSingleObject(process_handle.get(), timeout_ms) };

        match wait_result {
            WAIT_OBJECT_0 => {}
            WAIT_TIMEOUT => unsafe {
                let _ = TerminateJobObject(job_handle.get(), u32::MAX);
                let _ = WaitForSingleObject(process_handle.get(), u32::MAX);
            },
            WAIT_FAILED => {
                let err = unsafe { GetLastError() };
                return Err(WxcError::Process(format!(
                    "WaitForSingleObject failed: {:?}",
                    err
                )));
            }
            other => {
                return Err(WxcError::Process(format!(
                    "WaitForSingleObject returned unexpected value: {}",
                    other.0
                )));
            }
        }

        // --- Get exit code ---
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
        })
    }

    /// Create the AppContainer SID for the given request.
    fn initialize(&mut self, request: &CodexRequest) -> Result<(), WxcError> {
        let container_name = if request.container_id.is_empty() {
            "CLI".to_string()
        } else {
            request.container_id.clone()
        };
        self.app_container_sid = Self::create_app_container_sid(&container_name)?;
        self.app_container_name = container_name;
        Ok(())
    }

    /// Return the SID string for firewall rule association.
    fn get_principal_id(&self) -> String {
        if self.app_container_sid.0.is_null() {
            return "unknown-sid".to_string();
        }
        unsafe { string_util::sid_to_string(self.app_container_sid.0, "unknown-sid") }
    }

    /// Execute the script inside the AppContainer, converting errors to ScriptResponse.
    fn run_internal(&mut self, request: &CodexRequest, logger: &mut Logger) -> ScriptResponse {
        match self.run_internal_impl(request, logger) {
            Ok(response) => response,
            Err(e) => ScriptResponse::error(&e.to_string()),
        }
    }
}

impl Default for AppContainerScriptRunner {
    fn default() -> Self {
        Self::new()
    }
}

impl ScriptRunner for AppContainerScriptRunner {
    fn execute(&mut self, request: &CodexRequest, logger: &mut Logger) -> ScriptResponse {
        use crate::filesystem_bfs::FileSystemBfsManager;
        use crate::network_manager::NetworkManager;

        // Apply experimental features when flag is set
        if request.experimental_enabled {
            if let Some(ref test) = request.experimental.test {
                logger.log_line(&format!(
                    "Experimental feature 'test' applied: {}",
                    test.message
                ));
            }
        }

        if let Err(e) = self.initialize(request) {
            return ScriptResponse::error(&e.to_string());
        }

        let principal_id = self.get_principal_id();

        let mut bfs_manager = FileSystemBfsManager::new(self.app_container_name.clone());
        if let Err(e) = bfs_manager.configure(&request.policy, logger) {
            return ScriptResponse::error(&e.to_string());
        }

        let mut network_manager = NetworkManager::new();
        match network_manager.start(
            &principal_id,
            &self.app_container_name,
            &request.policy,
            self.app_container_sid,
            logger,
        ) {
            Ok(()) => {
                self.proxy_address = network_manager.proxy_address().cloned();
            }
            Err(err) => {
                return ScriptResponse::error(&err.to_string());
            }
        }

        let response = match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            self.run_internal(request, logger)
        })) {
            Ok(r) => r,
            Err(_) => ScriptResponse::error("Unknown error during script execution."),
        };

        network_manager.stop_all(!request.lifecycle.preserve_policy, logger);
        if bfs_manager.configured() && !request.lifecycle.preserve_policy {
            bfs_manager.remove_configuration(logger);
        }

        response
    }
}

impl Drop for AppContainerScriptRunner {
    fn drop(&mut self) {
        if !self.app_container_sid.0.is_null() {
            unsafe {
                // AppContainer SIDs from CreateAppContainerProfile /
                // DeriveAppContainerSidFromAppContainerName must be freed with FreeSid.
                windows::Win32::Security::FreeSid(self.app_container_sid);
            }
            self.app_container_sid = PSID(ptr::null_mut());
        }
    }
}

#[cfg(all(test, target_os = "windows"))]
mod tests {
    use super::*;
    use std::thread::sleep;
    use std::time::{Duration, Instant};

    use windows::Win32::System::Diagnostics::ToolHelp::{
        CreateToolhelp32Snapshot, Process32FirstW, Process32NextW, PROCESSENTRY32W,
        TH32CS_SNAPPROCESS,
    };
    use windows::Win32::System::Threading::{OpenProcess, PROCESS_SYNCHRONIZE, PROCESS_TERMINATE};

    struct TestProcess {
        process: OwnedHandle,
        thread: OwnedHandle,
        pid: u32,
    }

    fn spawn_test_process(command_line: &str, flags: PROCESS_CREATION_FLAGS) -> TestProcess {
        let mut command_line_wide = string_util::to_wide(command_line);
        let si = STARTUPINFOW {
            cb: size_of::<STARTUPINFOW>() as u32,
            ..Default::default()
        };
        let mut pi = PROCESS_INFORMATION::default();

        unsafe {
            CreateProcessW(
                PCWSTR::null(),
                Some(PWSTR(command_line_wide.as_mut_ptr())),
                None,
                None,
                false,
                flags,
                None,
                PCWSTR::null(),
                &si,
                &mut pi,
            )
        }
        .expect("CreateProcessW");

        TestProcess {
            process: OwnedHandle::new(pi.hProcess),
            thread: OwnedHandle::new(pi.hThread),
            pid: pi.dwProcessId,
        }
    }

    fn assert_process_exits(process_handle: windows::Win32::Foundation::HANDLE) {
        let wait_result = unsafe { WaitForSingleObject(process_handle, 5_000) };
        assert_eq!(wait_result, WAIT_OBJECT_0, "process did not exit in time");
    }

    fn open_process_for_wait(pid: u32) -> Option<OwnedHandle> {
        unsafe { OpenProcess(PROCESS_SYNCHRONIZE | PROCESS_TERMINATE, false, pid) }
            .ok()
            .map(OwnedHandle::new)
    }

    fn find_child_process(parent_pid: u32) -> Option<u32> {
        let snapshot = OwnedHandle::new(unsafe {
            CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0).expect("process snapshot")
        });
        let mut entry = PROCESSENTRY32W {
            dwSize: size_of::<PROCESSENTRY32W>() as u32,
            ..Default::default()
        };

        if unsafe { Process32FirstW(snapshot.get(), &mut entry) }.is_err() {
            return None;
        }

        loop {
            if entry.th32ParentProcessID == parent_pid {
                return Some(entry.th32ProcessID);
            }
            if unsafe { Process32NextW(snapshot.get(), &mut entry) }.is_err() {
                return None;
            }
        }
    }

    fn wait_for_child_process(parent_pid: u32) -> Option<(u32, OwnedHandle)> {
        let deadline = Instant::now() + Duration::from_secs(5);
        while Instant::now() < deadline {
            if let Some(pid) = find_child_process(parent_pid) {
                if let Some(handle) = open_process_for_wait(pid) {
                    return Some((pid, handle));
                }
            }
            sleep(Duration::from_millis(100));
        }
        None
    }

    #[test]
    fn job_limit_info_uses_request_resource_limits() {
        let limits = ResourceLimits {
            memory_mb: 128,
            max_processes: 7,
            cpu_rate_percent: 50,
            allow_child_processes: false,
        };

        let extended = build_job_extended_limit_information(&limits);
        assert!(extended
            .BasicLimitInformation
            .LimitFlags
            .contains(JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE));
        assert!(extended
            .BasicLimitInformation
            .LimitFlags
            .contains(JOB_OBJECT_LIMIT_JOB_MEMORY));
        assert!(extended
            .BasicLimitInformation
            .LimitFlags
            .contains(JOB_OBJECT_LIMIT_ACTIVE_PROCESS));
        assert_eq!(extended.JobMemoryLimit, 128 * 1024 * 1024);
        assert_eq!(extended.BasicLimitInformation.ActiveProcessLimit, 7);

        let cpu = build_job_cpu_rate_information(&limits).expect("cpu cap");
        assert!(cpu
            .ControlFlags
            .contains(JOB_OBJECT_CPU_RATE_CONTROL_ENABLE));
        assert!(cpu
            .ControlFlags
            .contains(JOB_OBJECT_CPU_RATE_CONTROL_HARD_CAP));
        assert_eq!(unsafe { cpu.Anonymous.CpuRate }, 5_000);
        assert!(limits.child_processes_blocked());
    }

    #[test]
    fn job_object_kills_orphans_on_drop() {
        let job = create_appcontainer_job_object(&ResourceLimits::permissive()).expect("job");
        let child =
            spawn_test_process("cmd.exe /c ping -n 30 127.0.0.1", PROCESS_CREATION_FLAGS(0));

        unsafe { AssignProcessToJobObject(job.get(), child.process.get()) }.expect("assign");
        drop(job);

        assert_process_exits(child.process.get());
    }

    #[test]
    fn job_object_terminates_tree() {
        let job = create_appcontainer_job_object(&ResourceLimits::permissive()).expect("job");
        let parent = spawn_test_process(
            "cmd.exe /c start /b cmd.exe /c ping -n 30 127.0.0.1 & ping -n 30 127.0.0.1",
            CREATE_SUSPENDED,
        );

        unsafe { AssignProcessToJobObject(job.get(), parent.process.get()) }.expect("assign");
        assert_ne!(unsafe { ResumeThread(parent.thread.get()) }, u32::MAX);

        let (child_pid, child) = wait_for_child_process(parent.pid).expect("child process");
        let (_grandchild_pid, grandchild) =
            wait_for_child_process(child_pid).expect("grandchild process");
        unsafe { TerminateJobObject(job.get(), u32::MAX) }.expect("terminate job");

        assert_process_exits(parent.process.get());
        assert_process_exits(child.get());
        assert_process_exits(grandchild.get());
    }
}
