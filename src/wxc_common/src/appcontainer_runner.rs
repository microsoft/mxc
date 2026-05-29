// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use std::ptr;

use windows::Win32::Foundation::{
    GetLastError, LocalFree, ERROR_ALREADY_EXISTS, HLOCAL, WAIT_FAILED, WAIT_OBJECT_0, WAIT_TIMEOUT,
};
use windows::Win32::Security::Authorization::ConvertSidToStringSidW;
use windows::Win32::Security::Isolation::{
    CreateAppContainerProfile, DeleteAppContainerProfile, DeriveAppContainerSidFromAppContainerName,
};
use windows::Win32::Security::{FreeSid, PSID};
use windows::Win32::System::SystemServices::SE_GROUP_ENABLED;
use windows::Win32::System::Threading::{
    CreateProcessW, DeleteProcThreadAttributeList, GetExitCodeProcess,
    InitializeProcThreadAttributeList, ResumeThread, TerminateProcess, UpdateProcThreadAttribute,
    WaitForSingleObject, CREATE_SUSPENDED, CREATE_UNICODE_ENVIRONMENT,
    EXTENDED_STARTUPINFO_PRESENT, LPPROC_THREAD_ATTRIBUTE_LIST, PROCESS_CREATION_FLAGS,
    PROCESS_INFORMATION, PROC_THREAD_ATTRIBUTE_ALL_APPLICATION_PACKAGES_POLICY,
    PROC_THREAD_ATTRIBUTE_MITIGATION_POLICY, PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES,
    STARTUPINFOEXW, STARTUPINFOW,
};
use windows_core::{PCWSTR, PWSTR};

use crate::error::WxcError;
use crate::job_object::UiJobObject;
use crate::logger::Logger;
use crate::models::{ExecutionRequest, NetworkEnforcementMode, NetworkPolicy, ScriptResponse};
use crate::process_util::{get_capability_sid_from_name, OwnedHandle, SidAndAttributes};
use crate::script_runner::{get_timeout_milliseconds, ScriptRunner};
use crate::{process_mitigation, string_util, ui_policy};

/// `UpdateProcThreadAttribute` value for
/// `PROC_THREAD_ATTRIBUTE_ALL_APPLICATION_PACKAGES_POLICY` that opts the
/// process out of inheriting `ALL APPLICATION PACKAGES` grants. This
/// specific *value* (not the attribute id) is not currently exported
/// by the windows crate.
const PROCESS_CREATION_ALL_APPLICATION_PACKAGES_OPT_OUT: u32 = 1;

/// Proxy-related env var names to strip/override when building the child env block.
const PROXY_VAR_NAMES: &[&str] = &["HTTP_PROXY", "HTTPS_PROXY", "NO_PROXY", "ALL_PROXY"];

/// Serialize `KEY=VALUE` pairs into a double-null-terminated UTF-16 environment block.
///
/// Entries are sorted case-insensitively by key as required by `CreateProcessW`.
fn encode_env_block(entries: &[(String, String)]) -> Vec<u16> {
    let mut sorted: Vec<&(String, String)> = entries.iter().collect();
    sorted.sort_by(|(a, _), (b, _)| a.to_ascii_uppercase().cmp(&b.to_ascii_uppercase()));

    let mut block = Vec::new();
    for (key, value) in sorted {
        for ch in format!("{}={}", key, value).encode_utf16() {
            block.push(ch);
        }
        block.push(0);
    }
    block.push(0);
    block
}

/// Parse explicit `KEY=VALUE` strings into entry pairs, optionally injecting
/// proxy env vars (stripping any pre-existing proxy vars first).
fn build_explicit_entries(
    env_vars: &[String],
    proxy_address: Option<&crate::models::ProxyAddress>,
) -> Vec<(String, String)> {
    let mut entries: Vec<(String, String)> = env_vars
        .iter()
        .filter_map(|entry| {
            entry
                .split_once('=')
                .map(|(k, v)| (k.to_string(), v.to_string()))
        })
        .collect();

    if let Some(addr) = proxy_address {
        // Strip existing proxy vars before injecting ours.
        entries.retain(|(key, _)| {
            !PROXY_VAR_NAMES
                .iter()
                .any(|name| key.eq_ignore_ascii_case(name))
        });
        let proxy_url = addr.to_url();
        entries.push(("HTTP_PROXY".to_string(), proxy_url.clone()));
        entries.push(("HTTPS_PROXY".to_string(), proxy_url));
    }

    entries
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

/// Compute the number of `PROC_THREAD_ATTRIBUTE_*` entries the attribute
/// list will hold for a given policy.
///
/// Always at least 1 (`SECURITY_CAPABILITIES`). LPAC adds one
/// (`ALL_APPLICATION_PACKAGES_POLICY`); UI-disable adds one
/// (`MITIGATION_POLICY` for Win32k disable).
fn compute_attr_count(least_privilege_mode: bool, ui_disable: bool) -> u32 {
    let mut n = 1;
    if least_privilege_mode {
        n += 1;
    }
    if ui_disable {
        n += 1;
    }
    n
}

/// Derive the AppContainer SID for `profile_name` and return it as a string
/// in `S-1-15-...` form.
///
/// Used by the Phase 4 dispatcher to target deny / grant ACEs at the same
/// AppContainer principal the runner will execute under. Co-located with
/// [`AppContainerScriptRunner::create_app_container_sid`] so any future
/// name normalization is added to a single place — keeping the dispatcher's
/// ACE target and the runner's process principal from drifting.
///
/// `profile_name` corresponds to the AppContainer profile name the runner
/// would create (matching the `request.container_id` mapping in the
/// AppContainer / BaseContainer runners — empty becomes `"CLI"` at the
/// caller; this function rejects empty input outright).
///
/// # Errors
///
/// Returns [`WxcError::Initialization`] if `profile_name` is empty, the
/// derivation Win32 call fails, or the returned SID cannot be converted to
/// a string.
pub(crate) fn derive_sid_string(profile_name: &str) -> Result<String, WxcError> {
    if profile_name.is_empty() {
        return Err(WxcError::Initialization(
            "AppContainer profile name is empty; cannot derive SID".to_string(),
        ));
    }

    let wide_name = string_util::to_wide(profile_name);
    let pcwstr_name = PCWSTR(wide_name.as_ptr());

    // SAFETY: `wide_name` is a valid null-terminated UTF-16 string and lives
    // for the duration of the call.
    let sid: PSID =
        unsafe { DeriveAppContainerSidFromAppContainerName(pcwstr_name) }.map_err(|e| {
            WxcError::Initialization(format!(
                "DeriveAppContainerSidFromAppContainerName failed for '{profile_name}': {e}"
            ))
        })?;

    let mut string_sid = PWSTR::null();
    // SAFETY: `sid` is a valid SID returned by the call above.
    let convert_result = unsafe { ConvertSidToStringSidW(sid, &mut string_sid) };

    let result = match convert_result {
        Ok(()) => {
            // Defensive null-check: `ConvertSidToStringSidW` documents
            // that it always allocates a valid pointer on success, but
            // matching the rest of the codebase's posture on raw Win32
            // pointers is cheap. If we ever see a null here it's a
            // real Win32 bug — surface it as an error rather than UB.
            if string_sid.is_null() {
                Err(WxcError::Initialization(
                    "ConvertSidToStringSidW returned success but produced a null string SID"
                        .to_string(),
                ))
            } else {
                // SAFETY: ConvertSidToStringSidW writes a null-terminated
                // wide string to `string_sid` on success and we just
                // verified non-null.
                let s = unsafe { string_sid.to_string() }
                    .map_err(|e| WxcError::Initialization(format!("SID-to-string failed: {e}")));
                // SAFETY: `string_sid` was allocated by ConvertSidToStringSidW;
                // free it with LocalFree per the Win32 contract.
                unsafe {
                    let _ = LocalFree(Some(HLOCAL(string_sid.0 as *mut std::ffi::c_void)));
                }
                s
            }
        }
        Err(e) => Err(WxcError::Initialization(format!(
            "ConvertSidToStringSidW failed: {e}"
        ))),
    };

    // SAFETY: SIDs returned by DeriveAppContainerSidFromAppContainerName
    // must be released with FreeSid.
    unsafe {
        let _ = FreeSid(sid);
    }

    result
}

/// Selects how filesystem policy is enforced for an AppContainer run.
///
/// Used by the Phase 4 dispatcher to skip the in-runner BFS configure when
/// the caller (Tier 3) is enforcing filesystem policy via host DACLs
/// instead.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub enum FilesystemMode {
    /// Configure the AppContainer's BFS policy via `bfscfg.exe` (default
    /// historical behavior).
    #[default]
    Bfs,
    /// Skip BFS setup; the caller has handled filesystem policy via host
    /// DACL augmentation (Tier 3 path).
    Dacl,
}

/// Script runner that executes commands inside a Windows AppContainer.
pub struct AppContainerScriptRunner {
    app_container_name: String,
    app_container_sid: PSID,
    proxy_address: Option<crate::models::ProxyAddress>,
    filesystem_mode: FilesystemMode,
    /// Optional pre-derived SID string supplied by the dispatcher.
    ///
    /// When `Some`, the runner uses this value for the firewall
    /// principal-id and any other capability-string lookups instead of
    /// re-running `ConvertSidToStringSidW` on its owned `PSID`. The
    /// `PSID` itself is still derived by [`create_app_container_sid`]
    /// at run time because `windows-rs` does not expose a safe
    /// "string → PSID" conversion with the same ownership semantics as
    /// [`DeriveAppContainerSidFromAppContainerName`] / `FreeSid`; that
    /// duplicate Win32 call is documented and left as a follow-up.
    preset_sid_string: Option<String>,
}

impl AppContainerScriptRunner {
    pub fn new() -> Self {
        Self {
            app_container_name: String::new(),
            app_container_sid: PSID(ptr::null_mut()),
            proxy_address: None,
            filesystem_mode: FilesystemMode::Bfs,
            preset_sid_string: None,
        }
    }

    /// Construct a runner with an explicit [`FilesystemMode`].
    ///
    /// Used by the Phase 4 dispatcher to disable in-runner BFS setup for
    /// the Tier 3 (DACL-augmented) path.
    pub fn with_filesystem_mode(mode: FilesystemMode) -> Self {
        Self {
            app_container_name: String::new(),
            app_container_sid: PSID(ptr::null_mut()),
            proxy_address: None,
            filesystem_mode: mode,
            preset_sid_string: None,
        }
    }

    /// Construct a runner with an explicit [`FilesystemMode`] and a
    /// pre-derived SID string.
    ///
    /// Used by the Phase 4 dispatcher to avoid a second
    /// `ConvertSidToStringSidW` round-trip when the dispatcher has
    /// already derived the SID string for ACE targeting. The `PSID`
    /// itself is still derived inside [`create_app_container_sid`] at
    /// run time — see [`Self::preset_sid_string`].
    pub fn with_filesystem_mode_and_sid_string(mode: FilesystemMode, sid_string: String) -> Self {
        Self {
            app_container_name: String::new(),
            app_container_sid: PSID(ptr::null_mut()),
            proxy_address: None,
            filesystem_mode: mode,
            preset_sid_string: Some(sid_string),
        }
    }

    /// Create or derive an AppContainer SID for the given container name.
    ///
    /// Returns a [`PSID`] owned by the runner (released via [`FreeSid`] in
    /// cleanup). If you only need the string form of the SID (e.g. to
    /// target ACEs at the same principal), call
    /// [`derive_sid_string`] — it shares the underlying derivation so the
    /// two paths can't drift in name normalization.
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
            Err(e) if e.code() == ERROR_ALREADY_EXISTS.to_hresult() => {
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
        request: &ExecutionRequest,
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
                        attributes: SE_GROUP_ENABLED as u32,
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
        let attr_count = compute_attr_count(
            request.policy.least_privilege_mode,
            request.policy.ui.disable,
        );

        // Lifetime spans the attribute list and CreateProcessW:
        // PROC_THREAD_ATTRIBUTE_MITIGATION_POLICY stores a pointer into this u64.
        let mitigation_value: u64 = process_mitigation::win32k_disable_value();

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
                PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES as usize,
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
                    PROC_THREAD_ATTRIBUTE_ALL_APPLICATION_PACKAGES_POLICY as usize,
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

        // 3. MITIGATION_POLICY (Win32k syscall disable) — applied by the kernel
        // before the child runs any user-mode code, so there is no race window.
        if request.policy.ui.disable {
            unsafe {
                UpdateProcThreadAttribute(
                    attr_list,
                    0,
                    PROC_THREAD_ATTRIBUTE_MITIGATION_POLICY as usize,
                    Some(&mitigation_value as *const u64 as *const core::ffi::c_void),
                    std::mem::size_of::<u64>(),
                    None,
                    None,
                )
                .map_err(|e| {
                    WxcError::Process(format!(
                        "UpdateProcThreadAttribute(MITIGATION_POLICY): {}",
                        e
                    ))
                })?;
            }
            logger.log_line("Win32k mitigation applied to child process");
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

        // Environment block for the sandboxed child.
        // If explicit env vars were provided, use only those (+ proxy injection).
        // If only proxy is active (no explicit env), build a block with just proxy vars.
        // Otherwise, pass NULL to inherit the default environment.
        let env_block: Option<Vec<u16>> = if !request.env.is_empty() {
            let entries = build_explicit_entries(&request.env, self.proxy_address.as_ref());
            Some(encode_env_block(&entries))
        } else if let Some(addr) = self.proxy_address.as_ref() {
            // No explicit env but proxy is active -- inject only proxy vars.
            let proxy_url = addr.to_url();
            let entries = vec![
                ("HTTP_PROXY".to_string(), proxy_url.clone()),
                ("HTTPS_PROXY".to_string(), proxy_url),
            ];
            Some(encode_env_block(&entries))
        } else {
            None
        };

        let env_ptr = env_block
            .as_ref()
            .map(|b| b.as_ptr() as *const core::ffi::c_void);

        let creation_flags = {
            let mut flags = EXTENDED_STARTUPINFO_PRESENT.0 | CREATE_SUSPENDED.0;
            if env_block.is_some() {
                flags |= CREATE_UNICODE_ENVIRONMENT.0;
            }
            PROCESS_CREATION_FLAGS(flags)
        };

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

        // Pre-launch check: abort if policy paths are on ReFS (Dev Drive) volumes
        // where BFS cannot enforce filesystem policy.
        if let Some(diag) = crate::launch_diagnostics::check_refs_volumes(
            &request.policy.readonly_paths,
            &request.policy.readwrite_paths,
        ) {
            logger.log_line(&format!(
                "Error: Pre-launch diagnostic [{}]: {}",
                diag.kind, diag.message
            ));
            return Err(WxcError::Process(diag.message));
        }

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

        // CRITICAL: child was created with CREATE_SUSPENDED. We must either
        // successfully attach the Job Object and ResumeThread, OR TerminateProcess.
        // Anything that returns an error in this block must terminate first.
        let _job = match (|| -> Result<UiJobObject, WxcError> {
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
        // ResumeThread returns the previous suspend count (or u32::MAX on failure).
        let resume_result = unsafe { ResumeThread(thread_handle.get()) };
        if resume_result == u32::MAX {
            let err = unsafe { GetLastError() };
            unsafe {
                let _ = TerminateProcess(process_handle.get(), u32::MAX);
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
                let _ = TerminateProcess(process_handle.get(), u32::MAX);
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
            ..Default::default()
        })
    }

    /// Create the AppContainer SID for the given request.
    fn initialize(&mut self, request: &ExecutionRequest) -> Result<(), WxcError> {
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
        // Prefer the dispatcher-supplied string when present — saves a
        // `ConvertSidToStringSidW` round-trip (the dispatcher has
        // already converted the underlying SID once for ACE targeting).
        if let Some(s) = &self.preset_sid_string {
            return s.clone();
        }
        if self.app_container_sid.0.is_null() {
            return "unknown-sid".to_string();
        }
        unsafe { string_util::sid_to_string(self.app_container_sid.0, "unknown-sid") }
    }

    /// Execute the script inside the AppContainer, converting errors to ScriptResponse.
    fn run_internal(&mut self, request: &ExecutionRequest, logger: &mut Logger) -> ScriptResponse {
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
    fn execute(&mut self, request: &ExecutionRequest, logger: &mut Logger) -> ScriptResponse {
        use crate::filesystem_bfs::FileSystemBfsManager;
        use crate::launch_diagnostics::diagnose_process_exit;
        use crate::models::FailurePhase;
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
        logger.log_line(&format!("AppContainerSID: {principal_id}"));

        // Resolve `bfscfg.exe` by absolute path so probe and execution
        // agree on the binary — defeats executable-search-order
        // hijacking (see `fallback_detector::find_bfscfg_exe`). Only
        // resolve when we actually plan to use BFS; Tier 3 (DACL) hosts
        // legitimately may not have `bfscfg.exe` installed.
        let bfscfg_path = if self.filesystem_mode == FilesystemMode::Bfs {
            match crate::fallback_detector::find_bfscfg_exe() {
                Ok(p) => p,
                Err(e) => return ScriptResponse::error(&e.to_string()),
            }
        } else {
            None
        };

        let mut bfs_manager =
            FileSystemBfsManager::new(self.app_container_name.clone(), bfscfg_path);
        if self.filesystem_mode == FilesystemMode::Bfs {
            if let Err(e) = bfs_manager.configure(&request.policy, logger) {
                return ScriptResponse::error(&e.to_string());
            }
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

        let mut response = match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            self.run_internal(request, logger)
        })) {
            Ok(r) => r,
            Err(_) => ScriptResponse::error("Unknown error during script execution."),
        };

        // Post-failure diagnostics: if the child failed, check for known
        // environment issues and enrich the error message.
        if response.exit_code != 0 {
            response.failure_phase = FailurePhase::ProcessExited;
            if let Some(diag) = diagnose_process_exit(
                &request.script_code,
                &request.policy.readonly_paths,
                &request.policy.readwrite_paths,
                response.exit_code as u32,
            ) {
                logger.log_line(&format!(
                    "Error: Launch diagnostic [{}]: {}",
                    diag.kind, diag.message
                ));
                if !response.error_message.is_empty() {
                    response.extended_error = response.error_message.clone();
                }
                response.error_message = diag.message.clone();
                response.standard_err.push_str(&diag.message);
            }
        }

        network_manager.stop_all(!request.lifecycle.preserve_policy, logger);
        if self.filesystem_mode == FilesystemMode::Bfs
            && bfs_manager.configured()
            && !request.lifecycle.preserve_policy
        {
            bfs_manager.remove_configuration(logger);
        }

        response
    }
}

/// Delete the AppContainer profile created via [`CreateAppContainerProfile`]
/// and clear any BFS policy registered against it.
///
/// This is the explicit cleanup entry point used by `wxc-exec --delete`,
/// kept next to the create/setup path on `AppContainerScriptRunner` so
/// both ends of the profile lifecycle live in the same module.
///
/// The BFS-clear step is best-effort: it delegates to
/// [`FileSystemBfsManager::clear_policy`], which resolves `bfscfg.exe`
/// itself and logs (rather than fails) when the resolver returns no
/// path. The profile delete is still attempted in that case.
pub fn delete_app_container_profile(name: &str, logger: &mut Logger) -> bool {
    crate::filesystem_bfs::FileSystemBfsManager::clear_policy(name, logger);

    let wide_name: Vec<u16> = name.encode_utf16().chain(std::iter::once(0)).collect();
    let hstring = windows::core::HSTRING::from_wide(&wide_name[..wide_name.len() - 1]);
    match unsafe { DeleteAppContainerProfile(&hstring) } {
        Ok(()) => {
            logger.log_line(&format!("Deleted AppContainer profile: {}", name));
            true
        }
        Err(e) => {
            logger.log_line(&format!(
                "Failed to delete AppContainer profile '{}': {}",
                name, e
            ));
            false
        }
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

#[cfg(test)]
mod tests {
    #[test]
    fn attr_count_neither() {
        assert_eq!(super::compute_attr_count(false, false), 1);
    }

    #[test]
    fn attr_count_lpac_only() {
        assert_eq!(super::compute_attr_count(true, false), 2);
    }

    #[test]
    fn attr_count_ui_disable_only() {
        assert_eq!(super::compute_attr_count(false, true), 2);
    }

    #[test]
    fn attr_count_both() {
        assert_eq!(super::compute_attr_count(true, true), 3);
    }

    #[test]
    fn derive_sid_string_empty_profile_name_errors() {
        let res = super::derive_sid_string("");
        assert!(matches!(
            res,
            Err(crate::error::WxcError::Initialization(_))
        ));
    }

    #[test]
    fn derive_sid_string_returns_appcontainer_prefix() {
        let sid =
            super::derive_sid_string("MxcDeriveSidTestSimple").expect("derivation should succeed");
        assert!(
            sid.starts_with("S-1-15-"),
            "expected AppContainer SID prefix S-1-15-, got: {sid}"
        );
    }

    #[test]
    fn derive_sid_string_is_stable_for_same_name() {
        let a = super::derive_sid_string("MxcDeriveSidTestStable").expect("first derivation");
        let b = super::derive_sid_string("MxcDeriveSidTestStable").expect("second derivation");
        assert_eq!(a, b);
    }
}
