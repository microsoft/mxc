// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use std::ptr;

use windows::Win32::Foundation::{LocalFree, HLOCAL, WAIT_EVENT, WAIT_OBJECT_0};
use windows::Win32::Security::Isolation::{
    CreateAppContainerProfile, DeriveAppContainerSidFromAppContainerName,
};
use windows::Win32::Security::PSID;
use windows::Win32::System::Console::{
    GetStdHandle, STD_ERROR_HANDLE, STD_INPUT_HANDLE, STD_OUTPUT_HANDLE,
};
use windows::Win32::System::Threading::{
    CreateProcessW, DeleteProcThreadAttributeList, GetExitCodeProcess,
    InitializeProcThreadAttributeList, TerminateProcess, UpdateProcThreadAttribute,
    WaitForMultipleObjects, WaitForSingleObject, LPPROC_THREAD_ATTRIBUTE_LIST,
    PROCESS_CREATION_FLAGS, PROCESS_INFORMATION, STARTF_USESTDHANDLES, STARTUPINFOEXW,
    STARTUPINFOW,
};
use windows::Win32::System::IO::CancelSynchronousIo;
use windows_core::{PCWSTR, PWSTR};

use crate::error::WxcError;
use crate::logger::Logger;
use crate::models::{CodexRequest, NetworkEnforcementMode, NetworkPolicy, ScriptResponse};
use crate::process_util::{
    create_relay_thread, create_std_pipes, get_capability_sid_from_name, OwnedHandle,
    PipeRelayParams,
};
use crate::script_runner::{get_timeout_milliseconds, ScriptRunner};
use crate::string_util;

// Attribute list constants (not always exported by the windows crate)
const PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES: usize = 0x0002_0009;
const PROC_THREAD_ATTRIBUTE_HANDLE_LIST: usize = 0x0002_0002;
const PROC_THREAD_ATTRIBUTE_ALL_APPLICATION_PACKAGES_POLICY: usize = 0x0002_000F;
const PROCESS_CREATION_ALL_APPLICATION_PACKAGES_OPT_OUT: u32 = 1;
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

/// A `SID_AND_ATTRIBUTES`-compatible struct used to build the capabilities array.
/// Using a manual struct avoids issues with conditional availability of
/// `windows::Win32::Security::SID_AND_ATTRIBUTES`.
#[repr(C)]
struct SidAndAttributes {
    sid: PSID,
    attributes: u32,
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

        // --- Create pipes ---
        let (stdin_read, mut stdin_write) =
            create_std_pipes(false).map_err(|e| WxcError::Process(format!("stdin pipe: {}", e)))?;
        let (stdout_read, stdout_write) =
            create_std_pipes(true).map_err(|e| WxcError::Process(format!("stdout pipe: {}", e)))?;
        let (stderr_read, stderr_write) =
            create_std_pipes(true).map_err(|e| WxcError::Process(format!("stderr pipe: {}", e)))?;

        let inherit_handles = [stdin_read.get(), stdout_write.get(), stderr_write.get()];

        // --- Allocate and initialize attribute list ---
        let attr_count = if request.policy.least_privilege_mode {
            3u32
        } else {
            2u32
        };
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

        // 3. HANDLE_LIST
        unsafe {
            UpdateProcThreadAttribute(
                attr_list,
                0,
                PROC_THREAD_ATTRIBUTE_HANDLE_LIST,
                Some(inherit_handles.as_ptr() as *const core::ffi::c_void),
                std::mem::size_of_val(&inherit_handles),
                None,
                None,
            )
            .map_err(|e| {
                WxcError::Process(format!("UpdateProcThreadAttribute(HANDLE_LIST): {}", e))
            })?;
        }

        // --- Setup STARTUPINFOEXW ---
        let mut desktop_wide = string_util::to_wide("winsta0\\default");

        let si_ex = STARTUPINFOEXW {
            StartupInfo: STARTUPINFOW {
                cb: std::mem::size_of::<STARTUPINFOEXW>() as u32,
                hStdInput: stdin_read.get(),
                hStdOutput: stdout_write.get(),
                hStdError: stderr_write.get(),
                dwFlags: STARTF_USESTDHANDLES,
                lpDesktop: PWSTR(desktop_wide.as_mut_ptr()),
                ..Default::default()
            },
            lpAttributeList: attr_list,
        };

        // --- Build command line ---
        let mut cmd_line_wide: Vec<u16> = request
            .script_code
            .encode_utf16()
            .chain(std::iter::once(0))
            .collect();

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
            PROCESS_CREATION_FLAGS(EXTENDED_STARTUPINFO_PRESENT.0 | CREATE_UNICODE_ENVIRONMENT.0)
        } else {
            EXTENDED_STARTUPINFO_PRESENT
        };

        // --- Create process ---
        let mut pi = PROCESS_INFORMATION::default();

        unsafe {
            CreateProcessW(
                PCWSTR::null(),
                Some(PWSTR(cmd_line_wide.as_mut_ptr())),
                None,
                None,
                true,
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

        // --- Close child-side handles in the parent ---
        drop(stdin_read);
        drop(stdout_write);
        drop(stderr_write);

        let process_handle = OwnedHandle::new(pi.hProcess);
        let _thread_handle = OwnedHandle::new(pi.hThread);

        // --- Get parent console handles ---
        let parent_stdin = unsafe { GetStdHandle(STD_INPUT_HANDLE) }
            .map_err(|e| WxcError::Process(format!("GetStdHandle(stdin): {}", e)))?;
        let parent_stdout = unsafe { GetStdHandle(STD_OUTPUT_HANDLE) }
            .map_err(|e| WxcError::Process(format!("GetStdHandle(stdout): {}", e)))?;
        let parent_stderr = unsafe { GetStdHandle(STD_ERROR_HANDLE) }
            .map_err(|e| WxcError::Process(format!("GetStdHandle(stderr): {}", e)))?;

        // --- Create relay threads ---
        // Thread 1: Parent stdin → Child stdin
        let mut stdin_params = PipeRelayParams {
            h_read: parent_stdin,
            h_write: stdin_write.get(),
        };
        // Thread 2: Child stdout → Parent stdout
        let mut stdout_params = PipeRelayParams {
            h_read: stdout_read.get(),
            h_write: parent_stdout,
        };
        // Thread 3: Child stderr → Parent stderr
        let mut stderr_params = PipeRelayParams {
            h_read: stderr_read.get(),
            h_write: parent_stderr,
        };

        let stdin_relay = unsafe { create_relay_thread(&mut stdin_params)? };
        let stdout_relay = unsafe { create_relay_thread(&mut stdout_params)? };
        let stderr_relay = unsafe { create_relay_thread(&mut stderr_params)? };

        // --- Wait for process or output relay completion ---
        // Any of: process exit, stdout relay done, or stderr relay done signals
        // that the child session is over.
        let timeout_ms = get_timeout_milliseconds(request.script_timeout);
        let completion_handles = [process_handle.get(), stdout_relay.get(), stderr_relay.get()];

        let wait_result = unsafe { WaitForMultipleObjects(&completion_handles, false, timeout_ms) };

        if wait_result != WAIT_OBJECT_0
            && wait_result != WAIT_EVENT(WAIT_OBJECT_0.0 + 1)
            && wait_result != WAIT_EVENT(WAIT_OBJECT_0.0 + 2)
        {
            // Timeout or error: forcibly terminate the child process.
            unsafe {
                let _ = TerminateProcess(
                    process_handle.get(),
                    u32::MAX, // 0xFFFFFFFF — matches C++ behavior
                );
                // Block until the OS confirms the process is gone.
                let _ = WaitForSingleObject(process_handle.get(), u32::MAX);
            }
        }

        // --- Shut down stdin relay thread ---
        // CancelSynchronousIo interrupts the blocking ReadFile on parent stdin,
        // causing the relay thread to break out of its loop. Closing the write
        // handle ensures any in-flight WriteFile also fails.
        unsafe {
            let _ = CancelSynchronousIo(stdin_relay.get());
        }
        // Closing stdin_write causes the child's stdin pipe to break, which is
        // fine since the child has already exited (or been terminated).
        stdin_write.take();

        // --- Wait for all relay threads to finish draining ---
        // Use INFINITE because all pipe endpoints are closed at this point
        // (child is dead, stdin_write is closed, CancelSynchronousIo was called),
        // so the threads will exit promptly. We must wait for them to finish
        // because PipeRelayParams are stack-allocated and would become dangling
        // pointers if this function returned early.
        let all_threads = [stdin_relay.get(), stdout_relay.get(), stderr_relay.get()];
        unsafe {
            let _ = WaitForMultipleObjects(&all_threads, true, u32::MAX);
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
        self.app_container_sid =
            Self::create_app_container_sid(&request.policy.app_container_name)?;
        self.app_container_name = request.policy.app_container_name.clone();
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
    fn run(&mut self, request: &CodexRequest, logger: &mut Logger) -> ScriptResponse {
        use crate::filesystem_bfs::FileSystemBfsManager;
        use crate::network_firewall::NetworkFirewallManager;
        use crate::network_proxy::NetworkProxyManager;
        use crate::validator::validate_request;

        if let Err(e) = validate_request(request) {
            return ScriptResponse::error(&e.to_string());
        }
        if let Err(e) = self.initialize(request) {
            return ScriptResponse::error(&e.to_string());
        }

        let principal_id = self.get_principal_id();

        let mut bfs_manager = FileSystemBfsManager::new(request.policy.app_container_name.clone());
        if let Err(e) = bfs_manager.configure(&request.policy, logger) {
            return ScriptResponse::error(&e.to_string());
        }

        let mut network_proxy_manager = NetworkProxyManager::new();
        if request.policy.network_proxy.is_enabled() {
            match network_proxy_manager.start(
                &request.policy,
                &principal_id,
                self.app_container_sid,
                logger,
            ) {
                Ok(()) => {
                    self.proxy_address = network_proxy_manager.address().cloned();
                }
                Err(err) => {
                    return ScriptResponse::error(&err.to_string());
                }
            }
        }

        let mut fw_manager = NetworkFirewallManager::new();
        match fw_manager.apply_firewall_rules(&principal_id, &request.policy, logger) {
            Ok(true) => {}
            Ok(false) => {
                network_proxy_manager.stop(logger);
                return ScriptResponse::error("Failed to apply network firewall rules.");
            }
            Err(e) => {
                network_proxy_manager.stop(logger);
                return ScriptResponse::error(&e.to_string());
            }
        }

        let response = match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            self.run_internal(request, logger)
        })) {
            Ok(r) => r,
            Err(_) => ScriptResponse::error("Unknown error during script execution."),
        };

        if fw_manager.rules_applied() && request.policy.remove_firewall_rules_on_exit {
            let _ = fw_manager.remove_firewall_rules(logger);
        }
        if network_proxy_manager.is_active() {
            network_proxy_manager.stop(logger);
        }
        if bfs_manager.configured() && request.policy.clear_policy_on_exit {
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
