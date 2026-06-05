// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use std::io::IsTerminal;
use std::ptr;

use windows::Win32::Foundation::{
    GetLastError, LocalFree, SetHandleInformation, ERROR_ALREADY_EXISTS, HANDLE,
    HANDLE_FLAG_INHERIT, HLOCAL, WAIT_FAILED, WAIT_OBJECT_0, WAIT_TIMEOUT,
};
use windows::Win32::Security::Authorization::ConvertSidToStringSidW;
use windows::Win32::Security::Isolation::{
    CreateAppContainerProfile, DeleteAppContainerProfile, DeriveAppContainerSidFromAppContainerName,
};
use windows::Win32::Security::{FreeSid, PSID};
use windows::Win32::System::Console::{
    GetStdHandle, STD_ERROR_HANDLE, STD_INPUT_HANDLE, STD_OUTPUT_HANDLE,
};
use windows::Win32::System::SystemServices::SE_GROUP_ENABLED;
use windows::Win32::System::Threading::{
    CreateProcessW, DeleteProcThreadAttributeList, GetExitCodeProcess,
    InitializeProcThreadAttributeList, ResumeThread, TerminateProcess, UpdateProcThreadAttribute,
    WaitForSingleObject, CREATE_SUSPENDED, CREATE_UNICODE_ENVIRONMENT,
    EXTENDED_STARTUPINFO_PRESENT, LPPROC_THREAD_ATTRIBUTE_LIST, PROCESS_CREATION_FLAGS,
    PROCESS_INFORMATION, PROC_THREAD_ATTRIBUTE_ALL_APPLICATION_PACKAGES_POLICY,
    PROC_THREAD_ATTRIBUTE_HANDLE_LIST, PROC_THREAD_ATTRIBUTE_MITIGATION_POLICY,
    PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES, STARTF_USESTDHANDLES, STARTUPINFOEXW,
    STARTUPINFOW,
};
use windows_core::{PCWSTR, PWSTR};

use crate::job_object::UiJobObject;
use crate::process_mitigation;
use wxc_common::child_env::{
    build_explicit_entries, create_default_env_entries, encode_env_block, inject_proxy,
};
use wxc_common::error::WxcError;
use wxc_common::logger::Logger;
use wxc_common::models::{ExecutionRequest, NetworkEnforcementMode, NetworkPolicy, ScriptResponse};
use wxc_common::process_util::{get_capability_sid_from_name, OwnedHandle, SidAndAttributes};
use wxc_common::script_runner::{get_timeout_milliseconds, ScriptRunner};
use wxc_common::{string_util, ui_policy};

/// `UpdateProcThreadAttribute` value for
/// `PROC_THREAD_ATTRIBUTE_ALL_APPLICATION_PACKAGES_POLICY` that opts the
/// process out of inheriting `ALL APPLICATION PACKAGES` grants. This
/// specific *value* (not the attribute id) is not currently exported
/// by the windows crate.
const PROCESS_CREATION_ALL_APPLICATION_PACKAGES_OPT_OUT: u32 = 1;

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
fn compute_attr_count(least_privilege_mode: bool, ui_disable: bool, pipe_mode: bool) -> u32 {
    let mut n = 1; // SECURITY_CAPABILITIES always present
    if least_privilege_mode {
        n += 1;
    }
    if ui_disable {
        n += 1;
    }
    if pipe_mode {
        n += 1; // one attribute slot for HANDLE_LIST (the list itself can hold 1..N handles)
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
    proxy_address: Option<wxc_common::models::ProxyAddress>,
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

        // --- Determine STDIO mode ---
        // If wxc-exec's stdout or stderr is not a terminal (i.e., piped by the SDK),
        // we forward our own std handles to the child via STARTF_USESTDHANDLES so the
        // child's output streams directly to the SDK in real time. Otherwise we use
        // console sharing (the ConPTY path).
        let pipe_mode = !std::io::stdout().is_terminal() || !std::io::stderr().is_terminal();

        if pipe_mode {
            logger.log_line("STDIO mode: passthrough (forwarding parent handles to child)");
        }

        // --- Allocate and initialize attribute list ---
        let attr_count = compute_attr_count(
            request.policy.least_privilege_mode,
            request.policy.ui.disable,
            pipe_mode,
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

        // 3. MITIGATION_POLICY (Win32k syscall disable) -- applied by the kernel
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

        // --- Setup handle passthrough (pipe mode only) ---
        // Forward wxc-exec's own stdin/stdout/stderr handles to the child so the
        // child's output streams directly to the SDK caller in real time.
        // Handle list for PROC_THREAD_ATTRIBUTE_HANDLE_LIST. Must outlive CreateProcessW.
        let mut handle_list: Vec<HANDLE> = Vec::new();

        let h_stdin;
        let h_stdout;
        let h_stderr;

        if pipe_mode {
            h_stdin = unsafe { GetStdHandle(STD_INPUT_HANDLE) }
                .map_err(|e| WxcError::Process(format!("GetStdHandle(STDIN): {e}")))?;
            h_stdout = unsafe { GetStdHandle(STD_OUTPUT_HANDLE) }
                .map_err(|e| WxcError::Process(format!("GetStdHandle(STDOUT): {e}")))?;
            h_stderr = unsafe { GetStdHandle(STD_ERROR_HANDLE) }
                .map_err(|e| WxcError::Process(format!("GetStdHandle(STDERR): {e}")))?;

            if h_stdin.is_invalid() || h_stdin == HANDLE::default() {
                return Err(WxcError::Process(
                    "GetStdHandle(STDIN) returned null/invalid handle".to_string(),
                ));
            }
            if h_stdout.is_invalid() || h_stdout == HANDLE::default() {
                return Err(WxcError::Process(
                    "GetStdHandle(STDOUT) returned null/invalid handle".to_string(),
                ));
            }
            if h_stderr.is_invalid() || h_stderr == HANDLE::default() {
                return Err(WxcError::Process(
                    "GetStdHandle(STDERR) returned null/invalid handle".to_string(),
                ));
            }

            // Ensure the handles are inheritable.
            unsafe {
                SetHandleInformation(h_stdin, HANDLE_FLAG_INHERIT.0, HANDLE_FLAG_INHERIT)
                    .map_err(|e| WxcError::Process(format!("SetHandleInformation(STDIN): {e}")))?;
                SetHandleInformation(h_stdout, HANDLE_FLAG_INHERIT.0, HANDLE_FLAG_INHERIT)
                    .map_err(|e| WxcError::Process(format!("SetHandleInformation(STDOUT): {e}")))?;
                SetHandleInformation(h_stderr, HANDLE_FLAG_INHERIT.0, HANDLE_FLAG_INHERIT)
                    .map_err(|e| WxcError::Process(format!("SetHandleInformation(STDERR): {e}")))?;
            }

            handle_list.push(h_stdin);
            handle_list.push(h_stdout);
            handle_list.push(h_stderr);

            // 4. HANDLE_LIST -- restrict which handles the child inherits.
            unsafe {
                UpdateProcThreadAttribute(
                    attr_list,
                    0,
                    PROC_THREAD_ATTRIBUTE_HANDLE_LIST as usize,
                    Some(handle_list.as_ptr() as *const core::ffi::c_void),
                    handle_list.len() * std::mem::size_of::<HANDLE>(),
                    None,
                    None,
                )
                .map_err(|e| {
                    WxcError::Process(format!("UpdateProcThreadAttribute(HANDLE_LIST): {}", e))
                })?;
            }
        } else {
            h_stdin = HANDLE::default();
            h_stdout = HANDLE::default();
            h_stderr = HANDLE::default();
        }

        // --- Setup STARTUPINFOEXW ---
        let mut desktop_wide = string_util::to_wide("winsta0\\default");

        let si_ex = STARTUPINFOEXW {
            StartupInfo: STARTUPINFOW {
                cb: std::mem::size_of::<STARTUPINFOEXW>() as u32,
                lpDesktop: PWSTR(desktop_wide.as_mut_ptr()),
                dwFlags: if pipe_mode {
                    STARTF_USESTDHANDLES
                } else {
                    Default::default()
                },
                hStdInput: h_stdin,
                hStdOutput: h_stdout,
                hStdError: h_stderr,
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
        // SECURITY: Never pass NULL (which would inherit the parent process's
        // full environment). Always build an explicit block:
        //   1. If explicit env vars were provided, use only those (+ proxy injection).
        //   2. Otherwise, call CreateEnvironmentBlock(bInherit=FALSE) for a clean
        //      default user environment and merge proxy vars if needed.
        let env_block: Vec<u16> = if !request.env.is_empty() {
            let entries = build_explicit_entries(&request.env, self.proxy_address.as_ref());
            encode_env_block(&entries)
        } else {
            // Get clean default user env without inheriting process env vars.
            let mut entries = create_default_env_entries()?;
            // Strip any pre-existing proxy vars and inject our configured proxy
            // (no-op when `proxy_address` is None).
            inject_proxy(&mut entries, self.proxy_address.as_ref());
            encode_env_block(&entries)
        };

        let env_ptr = env_block.as_ptr() as *const core::ffi::c_void;

        let creation_flags = PROCESS_CREATION_FLAGS(
            EXTENDED_STARTUPINFO_PRESENT.0 | CREATE_SUSPENDED.0 | CREATE_UNICODE_ENVIRONMENT.0,
        );

        // --- Create process ---
        //
        // In console-sharing mode (pipe_mode == false):
        //   stdin:  node-pty -> ConPTY -> wxc-exec -> child (AppContainer)
        //   stdout: node-pty <- ConPTY <----------- child (shares parent's console)
        //   bInheritHandles = false, no STARTF_USESTDHANDLES.
        //
        // In pipe-passthrough mode (pipe_mode == true):
        //   The child receives wxc-exec's own stdin/stdout/stderr handles directly.
        //   Child output streams to the SDK in real time (no intermediate buffering).
        //   bInheritHandles = true, with PROC_THREAD_ATTRIBUTE_HANDLE_LIST restricting
        //   which handles the child can access.
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
                pipe_mode, // bInheritHandles: true only in pipe mode (restricted by HANDLE_LIST)
                creation_flags,
                Some(env_ptr),
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
    fn validate_runner(&self, request: &ExecutionRequest) -> Result<(), ScriptResponse> {
        if !request.policy.denied_paths.is_empty() && self.filesystem_mode != FilesystemMode::Dacl {
            return Err(ScriptResponse::error(
                wxc_common::error::DENIED_PATHS_NOT_SUPPORTED_MSG,
            ));
        }
        if !request.policy.allowed_hosts.is_empty() || !request.policy.blocked_hosts.is_empty() {
            return Err(ScriptResponse::error(
                wxc_common::error::HOST_LISTS_NOT_SUPPORTED_MSG,
            ));
        }
        Ok(())
    }

    fn execute(&mut self, request: &ExecutionRequest, logger: &mut Logger) -> ScriptResponse {
        use crate::filesystem_bfs::FileSystemBfsManager;
        use crate::launch_diagnostics::diagnose_process_exit;
        use crate::network_manager::NetworkManager;
        use wxc_common::models::FailurePhase;

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
                let msg = if matches!(&e, WxcError::BfsNotAvailable)
                    && request.schema_version.starts_with("0.4.0")
                {
                    format!(
                        "Filesystem policy error: bfscfg.exe is not available on this Windows build. \
                         Your config uses schema version '{}', which requires BFS support. \
                         Either update your Windows build to one that includes bfscfg.exe, \
                         or update your config to schema version '0.6.0-alpha' or later \
                         (which uses the BaseContainer backend and does not require bfscfg.exe).",
                        request.schema_version
                    )
                } else {
                    e.to_string()
                };
                return ScriptResponse::error(&msg);
            }
        }

        if request.policy.network_proxy.is_enabled() {
            logger.log_line(
                "warning: proxy support on Windows is best-effort -- only scripts that use \
                 the WinHTTP stack will be proxied; other HTTP stacks may bypass it. The \
                 AppContainer backend may also surface a UAC prompt.",
            );
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
        assert_eq!(super::compute_attr_count(false, false, false), 1);
    }

    #[test]
    fn attr_count_lpac_only() {
        assert_eq!(super::compute_attr_count(true, false, false), 2);
    }

    #[test]
    fn attr_count_ui_disable_only() {
        assert_eq!(super::compute_attr_count(false, true, false), 2);
    }

    #[test]
    fn attr_count_both() {
        assert_eq!(super::compute_attr_count(true, true, false), 3);
    }

    #[test]
    fn attr_count_pipe_mode() {
        assert_eq!(super::compute_attr_count(false, false, true), 2);
        assert_eq!(super::compute_attr_count(true, true, true), 4);
    }

    #[test]
    fn derive_sid_string_empty_profile_name_errors() {
        let res = super::derive_sid_string("");
        assert!(matches!(
            res,
            Err(wxc_common::error::WxcError::Initialization(_))
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

    // ---- validate_runner: unsupported policy fields surface as errors. ----

    use super::{AppContainerScriptRunner, FilesystemMode};
    use wxc_common::models::ExecutionRequest;
    use wxc_common::script_runner::ScriptRunner;

    #[test]
    fn validate_runner_rejects_denied_paths_in_bfs_mode() {
        let runner = AppContainerScriptRunner::with_filesystem_mode(FilesystemMode::Bfs);
        let mut request = ExecutionRequest::default();
        request.policy.denied_paths = vec!["C:\\secret".into()];

        let err = runner
            .validate_runner(&request)
            .expect_err("BFS mode must reject deniedPaths");
        assert!(
            err.error_message.contains("deniedPaths"),
            "expected message to mention deniedPaths, got: {}",
            err.error_message
        );
    }

    #[test]
    fn validate_runner_accepts_denied_paths_in_dacl_mode() {
        let runner = AppContainerScriptRunner::with_filesystem_mode(FilesystemMode::Dacl);
        let mut request = ExecutionRequest::default();
        request.policy.denied_paths = vec!["C:\\secret".into()];

        assert!(
            runner.validate_runner(&request).is_ok(),
            "DACL mode supports deniedPaths and should not error"
        );
    }

    #[test]
    fn validate_runner_rejects_allowed_hosts() {
        let runner = AppContainerScriptRunner::new();
        let mut request = ExecutionRequest::default();
        request.policy.allowed_hosts = vec!["example.com".into()];

        let err = runner
            .validate_runner(&request)
            .expect_err("allowedHosts is not yet supported");
        assert!(err.error_message.contains("allowedHosts"));
    }

    #[test]
    fn validate_runner_rejects_blocked_hosts() {
        let runner = AppContainerScriptRunner::new();
        let mut request = ExecutionRequest::default();
        request.policy.blocked_hosts = vec!["bad.example.com".into()];

        let err = runner
            .validate_runner(&request)
            .expect_err("blockedHosts is not yet supported");
        assert!(err.error_message.contains("blockedHosts"));
    }

    #[test]
    fn validate_runner_accepts_empty_policy() {
        let runner = AppContainerScriptRunner::new();
        let request = ExecutionRequest::default();
        assert!(runner.validate_runner(&request).is_ok());
    }
}
