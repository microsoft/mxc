// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! WSL Container runner — implements `ScriptRunner` for the WSLC SDK backend.
//!
//! Orchestrates the full lifecycle:
//! `WslcCanRun → Session → Image check → Process settings → Container → Start →
//!  I/O capture → Exit code → ScriptResponse`
//!
//! RAII guards ensure cleanup even on error paths.

use std::ffi::c_void;
use std::fmt::Write;
use std::ptr;
use std::sync::{Arc, Mutex};

use wxc_common::logger::Logger;
use wxc_common::models::{CodexRequest, NetworkPolicy, ScriptResponse, WslcConfig};
use wxc_common::script_runner::ScriptRunner;
use wxc_common::string_util::CoTaskMemPWSTR;

use crate::policy_mapping;
use crate::wslc_bindings::*;

/// Shared buffer for capturing process I/O via callbacks.
struct IoContext {
    stdout: Arc<Mutex<Vec<u8>>>,
    stderr: Arc<Mutex<Vec<u8>>>,
    exited: Arc<(std::sync::Mutex<bool>, std::sync::Condvar)>,
}

/// RAII guard that reclaims an Arc<IoContext> from a raw pointer on drop.
/// Prevents leaking the Arc reference count on early returns.
struct IoCtxRawGuard {
    ptr: *mut c_void,
}

impl IoCtxRawGuard {
    fn new(ptr: *mut c_void) -> Self {
        Self { ptr }
    }
}

impl Drop for IoCtxRawGuard {
    fn drop(&mut self) {
        if !self.ptr.is_null() {
            unsafe {
                let _ = Arc::from_raw(self.ptr as *const IoContext);
            }
        }
    }
}

/// Callback invoked by the WSLC SDK for stdout/stderr data.
///
/// # Safety
/// `context` must be a valid pointer to an `Arc<IoContext>` that outlives all
/// callbacks. This is guaranteed because `io_ctx` is kept alive in `run_internal`
/// until after the exit event wait completes and all callbacks have finished.
/// The `IoCtxRawGuard` ensures the Arc reference is reclaimed on all exit paths.
/// The SDK guarantees `data` is valid for `data_size` bytes during the callback.
unsafe extern "system" fn io_callback(
    io_handle: WslcProcessIOHandle,
    data: *const BYTE,
    data_size: u32,
    context: *mut c_void,
) {
    if context.is_null() || data.is_null() || data_size == 0 {
        return;
    }
    let ctx = &*(context as *const IoContext);
    let bytes = std::slice::from_raw_parts(data, data_size as usize);
    match io_handle {
        WslcProcessIOHandle::Stdout => {
            let mut buf = ctx.stdout.lock().unwrap_or_else(|e| e.into_inner());
            buf.extend_from_slice(bytes);
        }
        WslcProcessIOHandle::Stderr => {
            let mut buf = ctx.stderr.lock().unwrap_or_else(|e| e.into_inner());
            buf.extend_from_slice(bytes);
        }
        _ => {}
    }
}

/// Callback invoked when the process exits and all I/O has been flushed.
/// Per SDK docs: "Once this callback is invoked, any registered IO callbacks
/// will no longer be called." This guarantees buffers are complete.
///
/// # Safety
/// Same lifetime requirements as `io_callback` — `context` must point to a
/// valid `Arc<IoContext>` that outlives all callbacks.
unsafe extern "system" fn exit_callback(_exit_code: i32, context: *mut c_void) {
    if context.is_null() {
        return;
    }
    let ctx = &*(context as *const IoContext);
    let mut exited = ctx.exited.0.lock().unwrap_or_else(|e| e.into_inner());
    *exited = true;
    ctx.exited.1.notify_all();
}

/// WSL Container script runner using the WSLC SDK.
pub struct WSLContainerRunner {
    config: WslcConfig,
}

impl WSLContainerRunner {
    pub fn new(config: &WslcConfig) -> Self {
        Self {
            config: config.clone(),
        }
    }
}

/// Create a ScriptResponse error from an HRESULT failure with optional SDK error message.
fn sdk_error(context: &str, hr: HRESULT, sdk_msg: &str) -> ScriptResponse {
    let msg = if sdk_msg.is_empty() {
        format!("{}: HRESULT 0x{:08X}", context, hr as u32)
    } else {
        format!("{}: {} (HRESULT 0x{:08X})", context, sdk_msg, hr as u32)
    };
    ScriptResponse::error(&msg)
}

impl ScriptRunner for WSLContainerRunner {
    fn run(&mut self, request: &CodexRequest, logger: &mut Logger) -> ScriptResponse {
        unsafe { self.run_internal(request, logger) }
    }
}

impl WSLContainerRunner {
    unsafe fn run_internal(&self, request: &CodexRequest, logger: &mut Logger) -> ScriptResponse {
        let _ = writeln!(logger, "[WSLC] Starting WSL Container runner");

        // -- Step 0: COM initialization --
        // The WSLC SDK uses COM internally (STDAPI = COM calling convention).
        // Without CoInitializeEx, SDK calls fail with CO_E_NOTINITIALIZED (0x800401F0).
        let com_hr = windows::Win32::System::Com::CoInitializeEx(
            None,
            windows::Win32::System::Com::COINIT_MULTITHREADED,
        );
        if com_hr.is_err() {
            return ScriptResponse::error(&format!("COM initialization failed: {:?}", com_hr));
        }
        let _ = writeln!(logger, "[WSLC] COM initialized");

        // -- Step 1: Prerequisites check --
        let mut can_run: BOOL = 0;
        let mut missing = WslcComponentFlags::None;
        let hr = WslcCanRun(&mut can_run, &mut missing);
        if hr != S_OK {
            return sdk_error("WslcCanRun failed", hr, "");
        }
        if can_run == 0 {
            return ScriptResponse::error(&format!(
                "WSLC runtime not available. Missing components: {:?}. \
                 Ensure WSL2 and the WSLC SDK are installed.",
                missing
            ));
        }
        let _ = writeln!(logger, "[WSLC] Runtime check passed");

        // -- Step 2: Session settings --
        let session_name: Vec<u16> = format!("{}\0", request.container_id)
            .encode_utf16()
            .collect();
        let storage_path_str = self.config.storage_path.clone().unwrap_or_else(|| {
            std::env::temp_dir()
                .join("mxc-wslc-sessions")
                .to_string_lossy()
                .to_string()
        });
        let storage_path_wide: Vec<u16> =
            format!("{}\0", storage_path_str).encode_utf16().collect();

        let mut session_settings = std::mem::zeroed::<WslcSessionSettings>();
        let hr = WslcInitSessionSettings(
            session_name.as_ptr(),
            storage_path_wide.as_ptr(),
            &mut session_settings,
        );
        if hr != S_OK {
            return sdk_error("WslcInitSessionSettings failed", hr, "");
        }

        if let Some(cpu) = self.config.cpu_count {
            let hr = WslcSetSessionSettingsCpuCount(&mut session_settings, cpu);
            if hr != S_OK {
                return sdk_error("WslcSetSessionSettingsCpuCount failed", hr, "");
            }
        }
        if let Some(mem_mb) = self.config.memory_mb {
            let mem_mb = match u32::try_from(mem_mb) {
                Ok(v) => v,
                Err(_) => {
                    return ScriptResponse::error(&format!(
                        "Invalid config: memory_mb value {} exceeds maximum {} MB",
                        mem_mb,
                        u32::MAX
                    ));
                }
            };
            let hr = WslcSetSessionSettingsMemory(&mut session_settings, mem_mb);
            if hr != S_OK {
                return sdk_error("WslcSetSessionSettingsMemory failed", hr, "");
            }
        }
        if request.script_timeout > 0 {
            let hr = WslcSetSessionSettingsTimeout(&mut session_settings, request.script_timeout);
            if hr != S_OK {
                return sdk_error("WslcSetSessionSettingsTimeout failed", hr, "");
            }
        }
        if self.config.gpu {
            let hr = WslcSetSessionSettingsFeatureFlags(
                &mut session_settings,
                WslcSessionFeatureFlags::EnableGpu,
            );
            if hr != S_OK {
                return sdk_error("WslcSetSessionSettingsFeatureFlags failed", hr, "");
            }
        }

        // -- Step 3: Create session --
        let mut session: WslcSession = ptr::null_mut();
        let mut err_msg = CoTaskMemPWSTR::null();
        let hr = WslcCreateSession(&mut session_settings, &mut session, err_msg.as_mut_ptr());
        if hr != S_OK {
            let msg = err_msg.to_string_lossy();
            return sdk_error("WslcCreateSession failed", hr, &msg);
        }
        let session_guard = WslcSessionGuard::from_raw(session);
        let _ = writeln!(logger, "[WSLC] Session created");

        // -- Step 4: Image check --
        let mut images: *mut WslcImageInfo = ptr::null_mut();
        let mut image_count: u32 = 0;
        let hr = WslcListSessionImages(session_guard.as_raw(), &mut images, &mut image_count);
        if hr != S_OK {
            return sdk_error("WslcListSessionImages failed", hr, "");
        }

        let image_name = &self.config.image;
        let mut image_found = false;
        if !images.is_null() {
            for i in 0..image_count as isize {
                let info = &*images.offset(i);
                let name_bytes: Vec<u8> = info
                    .name
                    .iter()
                    .take_while(|&&b| b != 0)
                    .map(|&b| b as u8)
                    .collect();
                if let Ok(name) = std::str::from_utf8(&name_bytes) {
                    if name == image_name.as_str() {
                        image_found = true;
                        break;
                    }
                }
            }
            windows::Win32::System::Com::CoTaskMemFree(Some(images as *const c_void));
        }

        if !image_found {
            // TODO: Move image pulling to a setup script (scripts/setup-wslc.ps1) as
            // described in docs/wsl-container-support-plan.md Phase 5. MXC is an execution
            // layer — image management should be handled externally. For now, auto-pull is
            // used during development/testing.
            let _ = writeln!(
                logger,
                "[WSLC] Image '{}' not found locally, attempting pull...",
                image_name
            );
            let uri_cstr = format!("{}\0", image_name);
            let pull_opts = WslcPullImageOptions {
                uri: uri_cstr.as_bytes().as_ptr() as PCSTR,
                progress_callback: None,
                progress_callback_context: ptr::null_mut(),
                auth_info: ptr::null(),
            };
            err_msg = CoTaskMemPWSTR::null();
            let hr = WslcPullSessionImage(session_guard.as_raw(), &pull_opts, err_msg.as_mut_ptr());
            if hr != S_OK {
                let msg = err_msg.to_string_lossy();
                return sdk_error(&format!("Failed to pull image '{}'", image_name), hr, &msg);
            }
            let _ = writeln!(logger, "[WSLC] Image '{}' pulled successfully", image_name);
        } else {
            let _ = writeln!(logger, "[WSLC] Image '{}' found", image_name);
        }

        // -- Step 5: Process settings --
        let mut process_settings = std::mem::zeroed::<WslcProcessSettings>();
        let hr = WslcInitProcessSettings(&mut process_settings);
        if hr != S_OK {
            return sdk_error("WslcInitProcessSettings failed", hr, "");
        }

        // Register I/O callbacks to capture stdout/stderr.
        // We use Arc so the callback context stays alive even if the function
        // returns early (e.g., container creation fails after callbacks are
        // registered). The SDK may still invoke callbacks on its internal
        // threads; Arc ensures the memory isn't freed until all references
        // (including the one held by the SDK via raw pointer) are dropped.
        let io_ctx = Arc::new(IoContext {
            stdout: Arc::new(Mutex::new(Vec::new())),
            stderr: Arc::new(Mutex::new(Vec::new())),
            exited: Arc::new((std::sync::Mutex::new(false), std::sync::Condvar::new())),
        });
        let io_ctx_stdout = Arc::clone(&io_ctx.stdout);
        let io_ctx_stderr = Arc::clone(&io_ctx.stderr);
        let io_ctx_exited = Arc::clone(&io_ctx.exited);

        // Give the SDK an Arc reference via raw pointer. We must reconstruct
        // the Arc later to avoid leaking the reference count.
        let io_ctx_for_sdk = Arc::clone(&io_ctx);
        let io_ctx_raw = Arc::into_raw(io_ctx_for_sdk) as *mut c_void;
        let _io_ctx_guard = IoCtxRawGuard::new(io_ctx_raw);

        let callbacks = WslcProcessCallbacks {
            on_stdout: Some(io_callback),
            on_stderr: Some(io_callback),
            on_exit: Some(exit_callback),
        };
        let hr = WslcSetProcessSettingsCallbacks(&mut process_settings, &callbacks, io_ctx_raw);
        if hr != S_OK {
            return sdk_error("WslcSetProcessSettingsCallbacks failed", hr, "");
        }

        // Build command line: /bin/sh -c "<script_code>"
        let sh = b"/bin/sh\0";
        let dash_c = b"-c\0";
        let script_cstr = format!("{}\0", request.script_code);
        let script_bytes = script_cstr.as_bytes();
        let argv: [PCSTR; 3] = [
            sh.as_ptr() as PCSTR,
            dash_c.as_ptr() as PCSTR,
            script_bytes.as_ptr() as PCSTR,
        ];
        let hr = WslcSetProcessSettingsCmdLine(&mut process_settings, argv.as_ptr(), argv.len());
        if hr != S_OK {
            return sdk_error("WslcSetProcessSettingsCmdLine failed", hr, "");
        }

        // Set environment variables
        if !request.env.is_empty() {
            let env_cstrings: Vec<Vec<u8>> = request
                .env
                .iter()
                .map(|e| format!("{}\0", e).into_bytes())
                .collect();
            let env_ptrs: Vec<PCSTR> = env_cstrings.iter().map(|e| e.as_ptr() as PCSTR).collect();
            let hr = WslcSetProcessSettingsEnvVariables(
                &mut process_settings,
                env_ptrs.as_ptr(),
                env_ptrs.len(),
            );
            if hr != S_OK {
                return sdk_error("WslcSetProcessSettingsEnvVariables failed", hr, "");
            }
        }

        // Set working directory
        let _cwd_cstr; // kept alive for SDK pointer
        if !request.working_directory.is_empty() {
            if let Some(container_cwd) =
                policy_mapping::windows_path_to_container_path(&request.working_directory)
            {
                _cwd_cstr = format!("{}\0", container_cwd);
                let hr = WslcSetProcessSettingsCurrentDirectory(
                    &mut process_settings,
                    _cwd_cstr.as_bytes().as_ptr() as PCSTR,
                );
                if hr != S_OK {
                    return sdk_error("WslcSetProcessSettingsCurrentDirectory failed", hr, "");
                }
            }
        }

        // -- Step 6: Container settings --
        let image_cstr = format!("{}\0", image_name);
        let mut container_settings = std::mem::zeroed::<WslcContainerSettings>();
        let hr = WslcInitContainerSettings(
            image_cstr.as_bytes().as_ptr() as PCSTR,
            &mut container_settings,
        );
        if hr != S_OK {
            return sdk_error("WslcInitContainerSettings failed", hr, "");
        }

        // -- Step 7: Apply policy mapping --
        // TODO: Port mappings (WslcConfig.port_mappings) are parsed but not yet applied.
        // Requires adding WslcSetContainerSettingsPortMappings and WslcContainerPortMapping
        // bindings. See wslcsdk.h lines 120-128, 183-186.
        let (mounts, warnings) = policy_mapping::build_volume_mounts(
            &request.policy.readwrite_paths,
            &request.policy.readonly_paths,
        );
        for w in &warnings {
            let _ = writeln!(logger, "[WSLC] Warning: {}", w);
        }

        if !mounts.is_empty() {
            // Build WslcContainerVolume array — keep owned data alive.
            let wide_paths: Vec<(Vec<u16>, Vec<u8>)> = mounts
                .iter()
                .map(|m| {
                    let win: Vec<u16> = format!("{}\0", m.windows_path).encode_utf16().collect();
                    let ctr: Vec<u8> = format!("{}\0", m.container_path).into_bytes();
                    (win, ctr)
                })
                .collect();

            let volumes: Vec<WslcContainerVolume> = wide_paths
                .iter()
                .zip(mounts.iter())
                .map(|((win, ctr), m)| WslcContainerVolume {
                    windows_path: win.as_ptr(),
                    container_path: ctr.as_ptr() as PCSTR,
                    read_only: if m.read_only { 1 } else { 0 },
                })
                .collect();

            let hr = WslcSetContainerSettingsVolumes(
                &mut container_settings,
                volumes.as_ptr(),
                volumes.len() as u32,
            );
            if hr != S_OK {
                return sdk_error("WslcSetContainerSettingsVolumes failed", hr, "");
            }
            let _ = writeln!(
                logger,
                "[WSLC] {} volume mount(s) configured",
                volumes.len()
            );
        }

        // Network policy
        let is_default_block = request.policy.default_network_policy == NetworkPolicy::Block;
        let has_host_rules = policy_mapping::needs_host_filtering(
            is_default_block,
            &request.policy.allowed_hosts,
            &request.policy.blocked_hosts,
        );
        let net_mode = policy_mapping::map_network_policy(is_default_block, has_host_rules);
        let hr = WslcSetContainerSettingsNetworkingMode(&mut container_settings, net_mode);
        if hr != S_OK {
            return sdk_error("WslcSetContainerSettingsNetworkingMode failed", hr, "");
        }
        let _ = writeln!(logger, "[WSLC] Networking mode: {:?}", net_mode);

        // Build iptables rules (if per-host filtering is needed)
        let iptables_cmd = policy_mapping::build_iptables_rules(
            &request.policy.allowed_hosts,
            &request.policy.blocked_hosts,
            is_default_block,
        );

        // Container flags
        let mut flags = WslcContainerFlags::None;
        if request.lifecycle.destroy_on_exit {
            flags = flags | WslcContainerFlags::AutoRemove;
        }
        if self.config.gpu {
            flags = flags | WslcContainerFlags::EnableGpu;
        }
        if has_host_rules {
            // Privileged needed for iptables inside the container
            flags = flags | WslcContainerFlags::Privileged;
        }
        let hr = WslcSetContainerSettingsFlags(&mut container_settings, flags);
        if hr != S_OK {
            return sdk_error("WslcSetContainerSettingsFlags failed", hr, "");
        }

        // Attach init process
        let hr = WslcSetContainerSettingsInitProcess(&mut container_settings, &mut process_settings);
        if hr != S_OK {
            return sdk_error("WslcSetContainerSettingsInitProcess failed", hr, "");
        }

        // -- Step 9: Create container --
        let mut container: WslcContainer = ptr::null_mut();
        err_msg = CoTaskMemPWSTR::null();
        let hr = WslcCreateContainer(
            session_guard.as_raw(),
            &container_settings,
            &mut container,
            err_msg.as_mut_ptr(),
        );
        if hr != S_OK {
            let msg = err_msg.to_string_lossy();
            return sdk_error("WslcCreateContainer failed", hr, &msg);
        }
        let container_guard = WslcContainerGuard::from_raw(container);
        let _ = writeln!(logger, "[WSLC] Container created");

        // -- Step 10: Start container --
        err_msg = CoTaskMemPWSTR::null();
        let hr = WslcStartContainer(
            container_guard.as_raw(),
            WslcContainerStartFlags::Attach,
            err_msg.as_mut_ptr(),
        );
        if hr != S_OK {
            let msg = err_msg.to_string_lossy();
            return sdk_error("WslcStartContainer failed", hr, &msg);
        }
        let _ = writeln!(logger, "[WSLC] Container started");

        // -- Step 10b: Apply iptables rules (if per-host filtering) --
        if let Some(ref ipt_cmd) = iptables_cmd {
            let _ = writeln!(logger, "[WSLC] Applying iptables rules for host filtering");
            let mut ipt_settings = std::mem::zeroed::<WslcProcessSettings>();
            let hr = WslcInitProcessSettings(&mut ipt_settings);
            if hr != S_OK {
                return sdk_error("WslcInitProcessSettings (iptables) failed", hr, "");
            }

            let ipt_sh = b"/bin/sh\0";
            let ipt_c = b"-c\0";
            let ipt_script = format!("{}\0", ipt_cmd);
            let ipt_script_bytes = ipt_script.as_bytes();
            let ipt_argv: [PCSTR; 3] = [
                ipt_sh.as_ptr() as PCSTR,
                ipt_c.as_ptr() as PCSTR,
                ipt_script_bytes.as_ptr() as PCSTR,
            ];
            let hr =
                WslcSetProcessSettingsCmdLine(&mut ipt_settings, ipt_argv.as_ptr(), ipt_argv.len());
            if hr != S_OK {
                return sdk_error("WslcSetProcessSettingsCmdLine (iptables) failed", hr, "");
            }

            let mut ipt_process: WslcProcess = ptr::null_mut();
            err_msg = CoTaskMemPWSTR::null();
            let hr = WslcCreateContainerProcess(
                container_guard.as_raw(),
                &mut ipt_settings,
                &mut ipt_process,
                err_msg.as_mut_ptr(),
            );
            if hr != S_OK {
                let msg = err_msg.to_string_lossy();
                return sdk_error("Failed to exec iptables rules", hr, &msg);
            }
            let ipt_guard = WslcProcessGuard::from_raw(ipt_process);

            // Wait for iptables to complete
            let mut ipt_exit_event: HANDLE = ptr::null_mut();
            let hr = WslcGetProcessExitEvent(ipt_guard.as_raw(), &mut ipt_exit_event);
            if hr != S_OK {
                return sdk_error("WslcGetProcessExitEvent (iptables) failed", hr, "");
            }
            if !ipt_exit_event.is_null() {
                windows::Win32::System::Threading::WaitForSingleObject(
                    windows::Win32::Foundation::HANDLE(ipt_exit_event),
                    30_000, // 30s timeout for iptables
                );
            }

            let mut ipt_exit_code: i32 = -1;
            let hr = WslcGetProcessExitCode(ipt_guard.as_raw(), &mut ipt_exit_code);
            if hr != S_OK {
                return sdk_error("WslcGetProcessExitCode (iptables) failed", hr, "");
            }
            if ipt_exit_code != 0 {
                return ScriptResponse::error(&format!(
                    "iptables rules failed with exit code {} \
                     (image may not have iptables installed)",
                    ipt_exit_code
                ));
            }
            let _ = writeln!(logger, "[WSLC] iptables rules applied successfully");
        }

        // -- Step 11: Get init process handle --
        let mut process: WslcProcess = ptr::null_mut();
        let hr = WslcGetContainerInitProcess(container_guard.as_raw(), &mut process);
        if hr != S_OK {
            return sdk_error("WslcGetContainerInitProcess failed", hr, "");
        }
        let process_guard = WslcProcessGuard::from_raw(process);

        // -- Step 12: Wait for exit (callbacks capture I/O during execution) --
        let mut exit_event: HANDLE = ptr::null_mut();
        let hr = WslcGetProcessExitEvent(process_guard.as_raw(), &mut exit_event);
        if hr != S_OK {
            return sdk_error("WslcGetProcessExitEvent failed", hr, "");
        }
        if !exit_event.is_null() {
            windows::Win32::System::Threading::WaitForSingleObject(
                windows::Win32::Foundation::HANDLE(exit_event),
                u32::MAX,
            );
        }

        // Wait for exit callback to fire — this guarantees all I/O is flushed
        // before we read the buffers (per SDK docs).
        {
            let (lock, cvar) = &*io_ctx_exited;
            let mut exited = lock.lock().unwrap_or_else(|e| e.into_inner());
            if !*exited {
                let result = cvar
                    .wait_timeout(exited, std::time::Duration::from_secs(30))
                    .unwrap_or_else(|e| e.into_inner());
                exited = result.0;
                if !*exited {
                    let _ = writeln!(
                        logger,
                        "[WSLC] Warning: exit callback did not fire within 30s"
                    );
                }
            }
            drop(exited);
        }

        let mut exit_code: i32 = -1;
        let hr = WslcGetProcessExitCode(process_guard.as_raw(), &mut exit_code);
        if hr != S_OK {
            return sdk_error("WslcGetProcessExitCode failed", hr, "");
        }
        let _ = writeln!(logger, "[WSLC] Process exited with code {}", exit_code);

        // -- Step 13: Collect captured I/O from callbacks (guaranteed flushed) --
        let stdout =
            String::from_utf8_lossy(&io_ctx_stdout.lock().unwrap_or_else(|e| e.into_inner()))
                .to_string();
        let stderr =
            String::from_utf8_lossy(&io_ctx_stderr.lock().unwrap_or_else(|e| e.into_inner()))
                .to_string();

        if !stdout.is_empty() {
            let _ = writeln!(logger, "[WSLC] Captured {} bytes stdout", stdout.len());
        }
        if !stderr.is_empty() {
            let _ = writeln!(logger, "[WSLC] Captured {} bytes stderr", stderr.len());
        }

        // -- Step 14: Cleanup --
        if request.lifecycle.destroy_on_exit {
            err_msg = CoTaskMemPWSTR::null();
            let _ = WslcStopContainer(
                container_guard.as_raw(),
                WslcSignal::SigTerm,
                10,
                err_msg.as_mut_ptr(),
            );
            drop(err_msg);

            err_msg = CoTaskMemPWSTR::null();
            let _ = WslcDeleteContainer(
                container_guard.as_raw(),
                WslcDeleteContainerFlags::Force,
                err_msg.as_mut_ptr(),
            );
            drop(err_msg);
        }

        let _ = WslcTerminateSession(session_guard.as_raw());
        let _ = writeln!(logger, "[WSLC] Cleanup complete");

        // IoCtxRawGuard drops here, reclaiming the Arc reference.
        // All callbacks are guaranteed complete after the exit event wait.

        // RAII guards will call Release on drop.
        // CoUninitialize is not called explicitly — RAII guards need COM alive
        // for the Release calls, and the process exits shortly after.

        ScriptResponse {
            exit_code,
            standard_out: stdout,
            standard_err: stderr,
            error_message: String::new(),
        }
    }
}
