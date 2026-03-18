// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use std::path::{Path, PathBuf};
use std::ptr;

use windows::core::PCWSTR;
use windows::Win32::Foundation::WAIT_OBJECT_0;
use windows::Win32::Security::PSID;
use windows::Win32::System::LibraryLoader::{GetProcAddress, LoadLibraryW};
use windows::Win32::System::Threading::{CreateEventW, SetEvent, WaitForSingleObject};
use windows::Win32::UI::Shell::{ShellExecuteExW, SEE_MASK_NOCLOSEPROCESS, SHELLEXECUTEINFOW};

use crate::error::WxcError;
use crate::logger::Logger;
use crate::models::ContainerPolicy;
use crate::process_util::OwnedHandle;
use crate::string_util;

#[repr(C)]
struct SidAndAttributes {
    sid: PSID,
    attributes: u32,
}

/// Remove an AppContainer from the loopback exemption list.
fn remove_loopback_exemption(container_name: &str) {
    let _ = std::process::Command::new("CheckNetIsolation.exe")
        .args([
            "LoopbackExempt",
            "-d",
            &format!("-n={}", container_name.to_lowercase()),
        ])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status();
}

/// Enable loopback network access for one or more AppContainers.
///
/// Preserves existing exemptions by reading the current list first.
fn enable_loopback_for_containers(container_sids: &[PSID]) -> Result<(), WxcError> {
    type FnGetConfig =
        unsafe extern "system" fn(count: *mut u32, entries: *mut *mut SidAndAttributes) -> u32;
    type FnSetConfig =
        unsafe extern "system" fn(count: u32, entries: *const SidAndAttributes) -> u32;

    let dll_name = string_util::to_wide("FirewallAPI.dll");
    let module = unsafe { LoadLibraryW(PCWSTR(dll_name.as_ptr())) }.map_err(|err| {
        WxcError::NetworkProxy(format!("Failed to load FirewallAPI.dll: {}", err))
    })?;

    let get_proc = unsafe {
        GetProcAddress(
            module,
            windows::core::s!("NetworkIsolationGetAppContainerConfig"),
        )
    };
    let set_proc = unsafe {
        GetProcAddress(
            module,
            windows::core::s!("NetworkIsolationSetAppContainerConfig"),
        )
    };
    let (Some(get_proc), Some(set_proc)) = (get_proc, set_proc) else {
        return Err(WxcError::NetworkProxy(
            "NetworkIsolation APIs not found in FirewallAPI.dll".into(),
        ));
    };

    unsafe {
        let get_fn: FnGetConfig =
            std::mem::transmute::<unsafe extern "system" fn() -> isize, FnGetConfig>(get_proc);
        let set_fn: FnSetConfig =
            std::mem::transmute::<unsafe extern "system" fn() -> isize, FnSetConfig>(set_proc);

        let mut existing_count: u32 = 0;
        let mut existing_entries: *mut SidAndAttributes = ptr::null_mut();
        let get_result = get_fn(&mut existing_count, &mut existing_entries);

        if get_result != 0 {
            existing_count = 0;
            existing_entries = ptr::null_mut();
        }

        let mut combined: Vec<SidAndAttributes> = Vec::new();
        if !existing_entries.is_null() {
            for index in 0..existing_count as usize {
                let entry = &*existing_entries.add(index);
                combined.push(SidAndAttributes {
                    sid: entry.sid,
                    attributes: entry.attributes,
                });
            }
        }
        for sid in container_sids {
            combined.push(SidAndAttributes {
                sid: *sid,
                attributes: 0,
            });
        }

        let set_result = set_fn(combined.len() as u32, combined.as_ptr());

        // Free the buffer allocated by NetworkIsolationGetAppContainerConfig.
        if !existing_entries.is_null() {
            if let Ok(heap) = windows::Win32::System::Memory::GetProcessHeap() {
                let _ = windows::Win32::System::Memory::HeapFree(
                    heap,
                    windows::Win32::System::Memory::HEAP_FLAGS(0),
                    Some(existing_entries as *const core::ffi::c_void),
                );
            }
        }

        if set_result != 0 {
            return Err(WxcError::NetworkProxy(format!(
                "Failed to set loopback exemption: 0x{:08x}",
                set_result
            )));
        }
    }

    Ok(())
}

/// Find a sibling executable next to the current exe.
fn find_sibling_exe(name: &str) -> Result<String, WxcError> {
    let exe_dir = std::env::current_exe()
        .map_err(|err| WxcError::NetworkProxy(format!("Failed to get current exe path: {}", err)))?
        .parent()
        .ok_or_else(|| WxcError::NetworkProxy("Failed to get exe directory".into()))?
        .to_path_buf();

    let path = exe_dir.join(name);
    if !path.exists() {
        return Err(WxcError::NetworkProxy(format!(
            "{} not found at {}",
            name,
            path.display()
        )));
    }

    Ok(path.to_string_lossy().to_string())
}

/// Generate a unique identifier for event and file naming.
fn generate_unique_id() -> String {
    let pid = std::process::id();
    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    format!("{}-{}", pid, timestamp)
}

/// Launch an executable elevated via UAC prompt using `ShellExecuteExW("runas")`.
///
/// Returns an owned process handle of the elevated child.
fn launch_elevated(
    exe_path: &str,
    args: &str,
    logger: &mut Logger,
) -> Result<OwnedHandle, WxcError> {
    let verb_wide = string_util::to_wide("runas");
    let exe_wide = string_util::to_wide(exe_path);
    let args_wide = string_util::to_wide(args);

    let mut shell_info: SHELLEXECUTEINFOW = unsafe { std::mem::zeroed() };
    shell_info.cbSize = std::mem::size_of::<SHELLEXECUTEINFOW>() as u32;
    shell_info.fMask = SEE_MASK_NOCLOSEPROCESS;
    shell_info.lpVerb = PCWSTR(verb_wide.as_ptr());
    shell_info.lpFile = PCWSTR(exe_wide.as_ptr());
    shell_info.lpParameters = PCWSTR(args_wide.as_ptr());
    shell_info.nShow = 0; // SW_HIDE

    logger.log_line("Requesting administrator privileges (UAC prompt)...");

    unsafe { ShellExecuteExW(&mut shell_info) }.map_err(|err| {
        WxcError::NetworkProxy(format!(
            "Failed to launch elevated winhttp-proxy-shim (user may have denied UAC): {}",
            err
        ))
    })?;

    if shell_info.hProcess.is_invalid() {
        return Err(WxcError::NetworkProxy(
            "ShellExecuteExW succeeded but returned no process handle".to_string(),
        ));
    }

    Ok(OwnedHandle::new(shell_info.hProcess))
}

/// Poll for the ready file that the shim writes after setting the proxy policy.
///
/// Also checks whether the shim process exited prematurely (e.g. access denied).
fn poll_for_ready_file(
    ready_path: &Path,
    shim_handle: &OwnedHandle,
    timeout_seconds: u32,
    logger: &mut Logger,
) -> Result<(), WxcError> {
    let start = std::time::Instant::now();
    let timeout = std::time::Duration::from_secs(timeout_seconds as u64);

    loop {
        if ready_path.exists() {
            logger.log_line("winhttp-proxy-shim reported ready.");
            return Ok(());
        }

        if start.elapsed() > timeout {
            return Err(WxcError::NetworkProxy(
                "Timed out waiting for winhttp-proxy-shim to set proxy policy".to_string(),
            ));
        }

        // Check if the shim exited before writing the ready file.
        let wait_result = unsafe { WaitForSingleObject(shim_handle.get(), 0) };
        if wait_result == WAIT_OBJECT_0 {
            return Err(WxcError::NetworkProxy(
                "winhttp-proxy-shim exited before setting proxy policy — check for elevation errors"
                    .to_string(),
            ));
        }

        std::thread::sleep(std::time::Duration::from_millis(100));
    }
}

/// Manages the network proxy policy for sandboxed AppContainer workloads.
///
/// Routes AppContainer traffic through an already-running localhost proxy
/// specified by port number. WinHTTP proxy policy is set by an elevated
/// `winhttp-proxy-shim` process launched via UAC, which binds the script's
/// AppContainer SID to the proxy's address and port.
pub struct NetworkProxyManager {
    proxy_port: u16,
    shim_process_handle: Option<OwnedHandle>,
    cleanup_event_handle: Option<OwnedHandle>,
    ready_file_path: Option<PathBuf>,
    loopback_container_name: Option<String>,
}

impl NetworkProxyManager {
    pub fn new() -> Self {
        Self {
            proxy_port: 0,
            shim_process_handle: None,
            cleanup_event_handle: None,
            ready_file_path: None,
            loopback_container_name: None,
        }
    }

    /// `true` if the proxy is active.
    pub fn is_active(&self) -> bool {
        self.proxy_port > 0
    }

    /// Returns the proxy port (0 if not active).
    pub fn proxy_port(&self) -> u16 {
        self.proxy_port
    }

    /// Set the WinHTTP proxy policy for the AppContainer and configure
    /// loopback access so the script can reach the localhost proxy.
    pub fn start(
        &mut self,
        policy: &ContainerPolicy,
        principal_id: &str,
        script_sid: PSID,
        logger: &mut Logger,
    ) -> Result<(), WxcError> {
        if self.is_active() {
            return Err(WxcError::NetworkProxy(
                "Network proxy is already active".into(),
            ));
        }

        let proxy_config = &policy.network_proxy;
        if !proxy_config.is_enabled() {
            return Ok(());
        }

        self.proxy_port = proxy_config.localhost;

        if let Err(err) = enable_loopback_for_containers(&[script_sid]) {
            self.cleanup_on_failure(logger);
            return Err(err);
        }
        self.loopback_container_name = Some(policy.app_container_name.clone());

        if let Err(err) = self.launch_shim(principal_id, logger) {
            self.cleanup_on_failure(logger);
            return Err(err);
        }

        logger.log_line(&format!(
            "Proxy policy active for SID {} -> 127.0.0.1:{}",
            principal_id, self.proxy_port,
        ));

        Ok(())
    }

    /// Launch the elevated winhttp-proxy-shim to set the per-AppContainer
    /// WinHTTP proxy policy.
    fn launch_shim(&mut self, principal_id: &str, logger: &mut Logger) -> Result<(), WxcError> {
        let unique_id = generate_unique_id();
        let ready_file_path =
            std::env::temp_dir().join(format!("wxc-shim-ready-{}.tmp", unique_id));
        let event_name = format!("Local\\wxc-shim-{}", unique_id);
        let event_name_wide = string_util::to_wide(&event_name);

        let event_handle =
            unsafe { CreateEventW(None, true, false, PCWSTR(event_name_wide.as_ptr())) }.map_err(
                |err| WxcError::NetworkProxy(format!("Failed to create cleanup event: {}", err)),
            )?;

        self.cleanup_event_handle = Some(OwnedHandle::new(event_handle));
        self.ready_file_path = Some(ready_file_path.clone());

        let shim_path = find_sibling_exe("winhttp-proxy-shim.exe")?;
        let shim_args = format!(
            "--sid {} --proxy-address 127.0.0.1 --proxy-port {} \
             --ready-file \"{}\" --cleanup-event \"{}\" --parent-pid {}",
            principal_id,
            self.proxy_port,
            ready_file_path.display(),
            event_name,
            std::process::id(),
        );

        logger.log_line(&format!(
            "Launching winhttp-proxy-shim elevated: SID {} -> 127.0.0.1:{}",
            principal_id, self.proxy_port
        ));

        let shim_handle = launch_elevated(&shim_path, &shim_args, logger)?;
        self.shim_process_handle = Some(shim_handle);

        poll_for_ready_file(
            &ready_file_path,
            self.shim_process_handle.as_ref().unwrap(),
            30,
            logger,
        )
    }

    /// Clean up any partially-initialized resources when start() fails.
    fn cleanup_on_failure(&mut self, logger: &mut Logger) {
        self.stop(logger);
    }

    /// Stop the proxy: signal shim cleanup, remove loopback exemption.
    pub fn stop(&mut self, logger: &mut Logger) {
        self.signal_shim_cleanup(logger);
        self.release_resources();
    }

    /// Signal the winhttp-proxy-shim to delete the proxy policy and wait for it.
    fn signal_shim_cleanup(&self, logger: &mut Logger) {
        let event_handle = if let Some(ref handle) = self.cleanup_event_handle {
            handle
        } else {
            return;
        };

        logger.log_line("Signaling winhttp-proxy-shim to clean up...");
        unsafe {
            let _ = SetEvent(event_handle.get());
        }

        if let Some(ref shim_handle) = self.shim_process_handle {
            let wait_result = unsafe { WaitForSingleObject(shim_handle.get(), 5000) };
            if wait_result == WAIT_OBJECT_0 {
                logger.log_line("winhttp-proxy-shim exited.");
            } else {
                logger.log_line(
                    "Warning: winhttp-proxy-shim did not exit within 5 seconds \
                     — proxy policy may still be set",
                );
            }
        }
    }

    /// Release all owned resources (handles, files, loopback exemption).
    /// Shared by both stop() and Drop.
    fn release_resources(&mut self) {
        self.cleanup_event_handle = None;
        self.shim_process_handle = None;
        self.proxy_port = 0;

        if let Some(path) = self.ready_file_path.take() {
            let _ = std::fs::remove_file(&path);
        }
        if let Some(container_name) = self.loopback_container_name.take() {
            remove_loopback_exemption(&container_name);
        }
    }
}

impl Default for NetworkProxyManager {
    fn default() -> Self {
        Self::new()
    }
}

impl Drop for NetworkProxyManager {
    fn drop(&mut self) {
        // Signal shim without logger (best-effort during drop).
        if let Some(ref event_handle) = self.cleanup_event_handle {
            unsafe {
                let _ = SetEvent(event_handle.get());
            }
            if let Some(ref shim_handle) = self.shim_process_handle {
                let _ = unsafe { WaitForSingleObject(shim_handle.get(), 5000) };
            }
        }
        self.release_resources();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new_manager() {
        let mgr = NetworkProxyManager::new();
        assert!(!mgr.is_active());
    }

    #[test]
    fn test_default_manager() {
        let mgr = NetworkProxyManager::default();
        assert!(!mgr.is_active());
    }

    #[test]
    fn test_stop_when_not_active() {
        let mut mgr = NetworkProxyManager::new();
        let mut logger = Logger::new(crate::logger::Mode::Buffer);
        mgr.stop(&mut logger);
        assert!(!mgr.is_active());
    }

    #[test]
    fn test_generate_unique_id() {
        let id = generate_unique_id();
        assert!(!id.is_empty());
        // Format: <pid>-<timestamp_nanos>
        let parts: Vec<&str> = id.split('-').collect();
        assert_eq!(parts.len(), 2, "ID should be in format 'pid-timestamp'");
        assert!(
            parts[0].parse::<u32>().is_ok(),
            "First part should be a valid PID"
        );
        assert!(
            parts[1].parse::<u128>().is_ok(),
            "Second part should be a valid timestamp"
        );
    }
}
