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

use wxc_common::logger::Logger;
use wxc_common::models::{CodexRequest, NetworkPolicy, ScriptResponse, WslcConfig};
use wxc_common::script_runner::ScriptRunner;

use crate::policy_mapping;
use crate::wslc_bindings::*;

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

    /// Free a PWSTR returned by the SDK (allocated with CoTaskMemAlloc).
    unsafe fn free_error_message(ptr: PWSTR) {
        if !ptr.is_null() {
            windows::Win32::System::Com::CoTaskMemFree(Some(ptr as *const c_void));
        }
    }

    /// Read the WSLC error message PWSTR into a Rust String, then free it.
    unsafe fn take_error_message(ptr: PWSTR) -> String {
        if ptr.is_null() {
            return String::new();
        }
        let mut len = 0;
        while *ptr.add(len) != 0 {
            len += 1;
        }
        let msg = String::from_utf16_lossy(std::slice::from_raw_parts(ptr, len));
        Self::free_error_message(ptr);
        msg
    }

    /// Format an HRESULT failure with optional SDK error message.
    fn format_error(context: &str, hr: HRESULT, sdk_msg: &str) -> String {
        if sdk_msg.is_empty() {
            format!("{}: HRESULT 0x{:08X}", context, hr as u32)
        } else {
            format!("{}: {} (HRESULT 0x{:08X})", context, sdk_msg, hr as u32)
        }
    }
}

impl ScriptRunner for WSLContainerRunner {
    fn run(&mut self, request: &CodexRequest, logger: &mut Logger) -> ScriptResponse {
        unsafe { self.run_internal(request, logger) }
    }
}

impl WSLContainerRunner {
    unsafe fn run_internal(&self, request: &CodexRequest, logger: &mut Logger) -> ScriptResponse {
        let _ = writeln!(logger, "[WSLC] Starting WSL Container runner");

        // -- Step 1: Prerequisites check --
        let mut can_run: BOOL = 0;
        let mut missing = WslcComponentFlags::None;
        let hr = WslcCanRun(&mut can_run, &mut missing);
        if hr != S_OK {
            return ScriptResponse::error(&Self::format_error("WslcCanRun failed", hr, ""));
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
        let session_name: Vec<u16> = "mxc-wslc\0".encode_utf16().collect();
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
            return ScriptResponse::error(&Self::format_error(
                "WslcInitSessionSettings failed",
                hr,
                "",
            ));
        }

        if let Some(cpu) = self.config.cpu_count {
            let _ = WslcSetSessionSettingsCpuCount(&mut session_settings, cpu);
        }
        if let Some(mem_mb) = self.config.memory_mb {
            let _ = WslcSetSessionSettingsMemory(&mut session_settings, mem_mb as u32);
        }
        if request.script_timeout > 0 {
            let _ =
                WslcSetSessionSettingsTimeout(&mut session_settings, request.script_timeout * 1000);
        }
        if self.config.gpu {
            let _ = WslcSetSessionSettingsFeatureFlags(
                &mut session_settings,
                WslcSessionFeatureFlags::EnableGpu,
            );
        }

        // -- Step 3: Create session --
        let mut session: WslcSession = ptr::null_mut();
        let mut err_msg: PWSTR = ptr::null_mut();
        let hr = WslcCreateSession(&mut session_settings, &mut session, &mut err_msg);
        if hr != S_OK {
            let msg = Self::take_error_message(err_msg);
            return ScriptResponse::error(&Self::format_error(
                "WslcCreateSession failed",
                hr,
                &msg,
            ));
        }
        let session_guard = WslcSessionGuard::from_raw(session);
        let _ = writeln!(logger, "[WSLC] Session created");

        // -- Step 4: Image check --
        let mut images: *mut WslcImageInfo = ptr::null_mut();
        let mut image_count: u32 = 0;
        let hr = WslcListSessionImages(session_guard.as_raw(), &mut images, &mut image_count);
        if hr != S_OK {
            return ScriptResponse::error(&Self::format_error(
                "WslcListSessionImages failed",
                hr,
                "",
            ));
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
            return ScriptResponse::error(&format!(
                "Container image '{}' not found. MXC requires images to be pre-pulled. \
                 Available images: {} found.",
                image_name, image_count
            ));
        }
        let _ = writeln!(logger, "[WSLC] Image '{}' found", image_name);

        // -- Step 5: Process settings --
        let mut process_settings = std::mem::zeroed::<WslcProcessSettings>();
        let hr = WslcInitProcessSettings(&mut process_settings);
        if hr != S_OK {
            return ScriptResponse::error(&Self::format_error(
                "WslcInitProcessSettings failed",
                hr,
                "",
            ));
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
        let _ = WslcSetProcessSettingsCmdLine(&mut process_settings, argv.as_ptr(), argv.len());

        // Set environment variables
        if !request.env.is_empty() {
            let env_cstrings: Vec<Vec<u8>> = request
                .env
                .iter()
                .map(|e| format!("{}\0", e).into_bytes())
                .collect();
            let env_ptrs: Vec<PCSTR> = env_cstrings.iter().map(|e| e.as_ptr() as PCSTR).collect();
            let _ = WslcSetProcessSettingsEnvVariables(
                &mut process_settings,
                env_ptrs.as_ptr(),
                env_ptrs.len(),
            );
        }

        // Set working directory
        if !request.working_directory.is_empty() {
            if let Some(container_cwd) =
                policy_mapping::windows_path_to_container_path(&request.working_directory)
            {
                let cwd_cstr = format!("{}\0", container_cwd);
                let _ = WslcSetProcessSettingsCurrentDirectory(
                    &mut process_settings,
                    cwd_cstr.as_bytes().as_ptr() as PCSTR,
                );
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
            return ScriptResponse::error(&Self::format_error(
                "WslcInitContainerSettings failed",
                hr,
                "",
            ));
        }

        // -- Step 7: Apply policy mapping --
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

            let _ = WslcSetContainerSettingsVolumes(
                &mut container_settings,
                volumes.as_ptr(),
                volumes.len() as u32,
            );
            let _ = writeln!(
                logger,
                "[WSLC] {} volume mount(s) configured",
                volumes.len()
            );
        }

        // Network policy
        let has_host_rules = policy_mapping::needs_host_filtering(
            &request.policy.allowed_hosts,
            &request.policy.blocked_hosts,
        );
        let is_default_block = request.policy.default_network_policy == NetworkPolicy::Block;
        let net_mode = policy_mapping::map_network_policy(is_default_block, has_host_rules);
        let _ = WslcSetContainerSettingsNetworkingMode(&mut container_settings, net_mode);
        let _ = writeln!(logger, "[WSLC] Networking mode: {:?}", net_mode);

        // Build iptables rules (if per-host filtering is needed)
        let iptables_cmd = policy_mapping::build_iptables_rules(
            &request.policy.allowed_hosts,
            &request.policy.blocked_hosts,
            is_default_block,
        );

        // Container flags
        let mut flags = WslcContainerFlags::AutoRemove;
        if self.config.gpu {
            flags = flags | WslcContainerFlags::EnableGpu;
        }
        if has_host_rules {
            // Privileged needed for iptables inside the container
            flags = flags | WslcContainerFlags::Privileged;
        }
        let _ = WslcSetContainerSettingsFlags(&mut container_settings, flags);

        // Attach init process
        let _ = WslcSetContainerSettingsInitProcess(&mut container_settings, &mut process_settings);

        // -- Step 9: Create container --
        let mut container: WslcContainer = ptr::null_mut();
        err_msg = ptr::null_mut();
        let hr = WslcCreateContainer(
            session_guard.as_raw(),
            &container_settings,
            &mut container,
            &mut err_msg,
        );
        if hr != S_OK {
            let msg = Self::take_error_message(err_msg);
            return ScriptResponse::error(&Self::format_error(
                "WslcCreateContainer failed",
                hr,
                &msg,
            ));
        }
        let container_guard = WslcContainerGuard::from_raw(container);
        let _ = writeln!(logger, "[WSLC] Container created");

        // -- Step 10: Start container --
        err_msg = ptr::null_mut();
        let hr = WslcStartContainer(
            container_guard.as_raw(),
            WslcContainerStartFlags::None,
            &mut err_msg,
        );
        if hr != S_OK {
            let msg = Self::take_error_message(err_msg);
            return ScriptResponse::error(&Self::format_error(
                "WslcStartContainer failed",
                hr,
                &msg,
            ));
        }
        let _ = writeln!(logger, "[WSLC] Container started");

        // -- Step 10b: Apply iptables rules (if per-host filtering) --
        if let Some(ref ipt_cmd) = iptables_cmd {
            let _ = writeln!(logger, "[WSLC] Applying iptables rules for host filtering");
            let mut ipt_settings = std::mem::zeroed::<WslcProcessSettings>();
            let hr = WslcInitProcessSettings(&mut ipt_settings);
            if hr != S_OK {
                return ScriptResponse::error(&Self::format_error(
                    "WslcInitProcessSettings (iptables) failed",
                    hr,
                    "",
                ));
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
            let _ =
                WslcSetProcessSettingsCmdLine(&mut ipt_settings, ipt_argv.as_ptr(), ipt_argv.len());

            let mut ipt_process: WslcProcess = ptr::null_mut();
            err_msg = ptr::null_mut();
            let hr = WslcCreateContainerProcess(
                container_guard.as_raw(),
                &mut ipt_settings,
                &mut ipt_process,
                &mut err_msg,
            );
            if hr != S_OK {
                let msg = Self::take_error_message(err_msg);
                return ScriptResponse::error(&Self::format_error(
                    "Failed to exec iptables rules",
                    hr,
                    &msg,
                ));
            }
            let ipt_guard = WslcProcessGuard::from_raw(ipt_process);

            // Wait for iptables to complete
            let mut ipt_exit_event: HANDLE = ptr::null_mut();
            let _ = WslcGetProcessExitEvent(ipt_guard.as_raw(), &mut ipt_exit_event);
            if !ipt_exit_event.is_null() {
                windows::Win32::System::Threading::WaitForSingleObject(
                    windows::Win32::Foundation::HANDLE(ipt_exit_event),
                    30_000, // 30s timeout for iptables
                );
            }

            let mut ipt_exit_code: i32 = -1;
            let _ = WslcGetProcessExitCode(ipt_guard.as_raw(), &mut ipt_exit_code);
            if ipt_exit_code != 0 {
                let _ = writeln!(
                    logger,
                    "[WSLC] Warning: iptables rules exited with code {} \
                     (image may not have iptables installed)",
                    ipt_exit_code
                );
            } else {
                let _ = writeln!(logger, "[WSLC] iptables rules applied successfully");
            }
        }

        // -- Step 11: Get init process handle --
        let mut process: WslcProcess = ptr::null_mut();
        let hr = WslcGetContainerInitProcess(container_guard.as_raw(), &mut process);
        if hr != S_OK {
            return ScriptResponse::error(&Self::format_error(
                "WslcGetContainerInitProcess failed",
                hr,
                "",
            ));
        }
        let process_guard = WslcProcessGuard::from_raw(process);

        // -- Step 12: Get I/O handles --
        let mut stdout_handle: HANDLE = ptr::null_mut();
        let mut stderr_handle: HANDLE = ptr::null_mut();
        let _ = WslcGetProcessIOHandle(
            process_guard.as_raw(),
            WslcProcessIOHandle::Stdout,
            &mut stdout_handle,
        );
        let _ = WslcGetProcessIOHandle(
            process_guard.as_raw(),
            WslcProcessIOHandle::Stderr,
            &mut stderr_handle,
        );

        // -- Step 13: Read stdout/stderr --
        let stdout = Self::read_handle(stdout_handle);
        let stderr = Self::read_handle(stderr_handle);

        // -- Step 14-15: Wait for exit and get exit code --
        let mut exit_event: HANDLE = ptr::null_mut();
        let _ = WslcGetProcessExitEvent(process_guard.as_raw(), &mut exit_event);
        if !exit_event.is_null() {
            windows::Win32::System::Threading::WaitForSingleObject(
                windows::Win32::Foundation::HANDLE(exit_event),
                u32::MAX,
            );
        }

        let mut exit_code: i32 = -1;
        let _ = WslcGetProcessExitCode(process_guard.as_raw(), &mut exit_code);
        let _ = writeln!(logger, "[WSLC] Process exited with code {}", exit_code);

        // -- Step 16: Cleanup (stop + delete container before guards drop) --
        err_msg = ptr::null_mut();
        let _ = WslcStopContainer(
            container_guard.as_raw(),
            WslcSignal::SigTerm,
            10,
            &mut err_msg,
        );
        Self::free_error_message(err_msg);

        err_msg = ptr::null_mut();
        let _ = WslcDeleteContainer(
            container_guard.as_raw(),
            WslcDeleteContainerFlags::Force,
            &mut err_msg,
        );
        Self::free_error_message(err_msg);

        let _ = WslcTerminateSession(session_guard.as_raw());
        let _ = writeln!(logger, "[WSLC] Cleanup complete");

        // RAII guards will call Release on drop.

        ScriptResponse {
            exit_code,
            standard_out: stdout,
            standard_err: stderr,
            error_message: String::new(),
        }
    }

    /// Read all bytes from a Win32 HANDLE until EOF.
    unsafe fn read_handle(handle: HANDLE) -> String {
        if handle.is_null() {
            return String::new();
        }

        let win_handle = windows::Win32::Foundation::HANDLE(handle);
        let mut output = Vec::new();
        let mut buf = [0u8; 4096];

        loop {
            let mut bytes_read: u32 = 0;
            let ok = windows::Win32::Storage::FileSystem::ReadFile(
                win_handle,
                Some(&mut buf),
                Some(&mut bytes_read),
                None,
            );
            if ok.is_err() || bytes_read == 0 {
                break;
            }
            output.extend_from_slice(&buf[..bytes_read as usize]);
        }

        String::from_utf8_lossy(&output).to_string()
    }
}
