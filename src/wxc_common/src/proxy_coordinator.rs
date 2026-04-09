// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use std::path::{Path, PathBuf};
use std::ptr;

use windows::core::PCWSTR;
use windows::Win32::Foundation::WAIT_OBJECT_0;
use windows::Win32::Security::PSID;
use windows::Win32::System::LibraryLoader::{GetModuleHandleW, GetProcAddress};
use windows::Win32::System::Threading::{
    CreateEventW, OpenProcess, SetEvent, WaitForSingleObject, PROCESS_SYNCHRONIZE,
};
use windows::Win32::UI::Shell::{ShellExecuteExW, SEE_MASK_NOCLOSEPROCESS, SHELLEXECUTEINFOW};

use crate::error::WxcError;
use crate::logger::Logger;
use crate::models::{ProxyAddress, ProxyConfig};
use crate::process_util::{resolve_sibling_binary, OwnedHandle, SidAndAttributes};
use crate::string_util;

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

/// Enable loopback network access for a single AppContainer.
///
/// Preserves existing exemptions by reading the current list first.
fn enable_loopback(container_sid: PSID) -> Result<(), WxcError> {
    type FnGetConfig =
        unsafe extern "system" fn(count: *mut u32, entries: *mut *mut SidAndAttributes) -> u32;
    type FnSetConfig =
        unsafe extern "system" fn(count: u32, entries: *const SidAndAttributes) -> u32;

    let dll_name = string_util::to_wide("FirewallAPI.dll");
    let module = unsafe { GetModuleHandleW(PCWSTR(dll_name.as_ptr())) }
        .map_err(|err| WxcError::NetworkProxy(format!("FirewallAPI.dll not loaded: {}", err)))?;

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

    let result = unsafe {
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
        combined.push(SidAndAttributes {
            sid: container_sid,
            attributes: 0,
        });

        let set_result = set_fn(combined.len() as u32, combined.as_ptr());

        if !existing_entries.is_null() {
            if let Ok(heap) = windows::Win32::System::Memory::GetProcessHeap() {
                let _ = windows::Win32::System::Memory::HeapFree(
                    heap,
                    windows::Win32::System::Memory::HEAP_FLAGS(0),
                    Some(existing_entries as *const core::ffi::c_void),
                );
            }
        }

        set_result
    };

    if result != 0 {
        return Err(WxcError::NetworkProxy(format!(
            "Failed to set loopback exemption: 0x{:08x}",
            result
        )));
    }

    Ok(())
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

/// Poll for a ready file written by a child process.
///
/// Also checks whether the child process exited prematurely.
fn poll_for_ready_file(
    ready_path: &Path,
    child_handle: &OwnedHandle,
    timeout_seconds: u32,
    logger: &mut Logger,
    label: &str,
) -> Result<(), WxcError> {
    let start = std::time::Instant::now();
    let timeout = std::time::Duration::from_secs(timeout_seconds as u64);

    loop {
        if ready_path.exists() {
            logger.log_line(&format!("{} reported ready.", label));
            return Ok(());
        }

        if start.elapsed() > timeout {
            return Err(WxcError::NetworkProxy(format!(
                "Timed out waiting for {} to become ready",
                label
            )));
        }

        let wait_result = unsafe { WaitForSingleObject(child_handle.get(), 0) };
        if wait_result == WAIT_OBJECT_0 {
            return Err(WxcError::NetworkProxy(format!(
                "{} exited before becoming ready",
                label
            )));
        }

        std::thread::sleep(std::time::Duration::from_millis(100));
    }
}

/// Manages the network proxy lifecycle for sandboxed AppContainer workloads.
///
/// Handles two proxy modes:
/// - **External proxy**: user provides a `localhost` port in the config
/// - **Builtin test server**: wxc launches `wxc-test-proxy.exe` itself to get
///   an OS-assigned port (for integration testing only)
///
/// In both cases, WinHTTP proxy policy is set by an elevated
/// `winhttp-proxy-shim` process launched via UAC.
pub struct ProxyCoordinator {
    proxy_address: Option<crate::models::ProxyAddress>,
    shim_process_handle: Option<OwnedHandle>,
    shim_cleanup_event: Option<OwnedHandle>,
    shim_ready_file_path: Option<PathBuf>,
    test_proxy_handle: Option<OwnedHandle>,
    test_proxy_cleanup_event: Option<OwnedHandle>,
    test_proxy_ready_file_path: Option<PathBuf>,
    loopback_container_name: Option<String>,
}

/// Signal a child process to exit via its cleanup event and wait for it.
fn signal_process_cleanup(
    event: Option<OwnedHandle>,
    process: Option<OwnedHandle>,
    label: &str,
    logger: &mut Logger,
) {
    if let Some(ref event_handle) = event {
        logger.log_line(&format!("Signaling {} to clean up...", label));
        if let Err(err) = unsafe { SetEvent(event_handle.get()) } {
            logger.log_line(&format!("Warning: failed to signal {}: {}", label, err));
        }
    }

    if let Some(ref proc_handle) = process {
        let wait_result = unsafe { WaitForSingleObject(proc_handle.get(), 5000) };
        if wait_result == WAIT_OBJECT_0 {
            logger.log_line(&format!("{} exited.", label));
        } else {
            logger.log_line(&format!(
                "Warning: {} did not exit within 5 seconds.",
                label
            ));
        }
    }
}

impl ProxyCoordinator {
    pub fn new() -> Self {
        Self {
            proxy_address: None,
            shim_process_handle: None,
            shim_cleanup_event: None,
            shim_ready_file_path: None,
            test_proxy_handle: None,
            test_proxy_cleanup_event: None,
            test_proxy_ready_file_path: None,
            loopback_container_name: None,
        }
    }

    /// `true` if the proxy is active.
    pub fn is_active(&self) -> bool {
        self.proxy_address.is_some()
    }

    /// Returns the proxy address (if active).
    pub fn address(&self) -> Option<&crate::models::ProxyAddress> {
        self.proxy_address.as_ref()
    }

    /// Activate the proxy based on the given config.
    ///
    /// If `builtin_test_server` is set, launches `wxc-test-proxy.exe` first to
    /// obtain a port. Then sets up loopback exemption and WinHTTP proxy policy
    /// via the elevated shim.
    pub fn start(
        &mut self,
        proxy_config: &ProxyConfig,
        container_name: &str,
        principal_id: &str,
        script_sid: PSID,
        logger: &mut Logger,
    ) -> Result<(), WxcError> {
        if self.is_active() {
            return Err(WxcError::NetworkProxy(
                "Network proxy is already active".into(),
            ));
        }

        let address = if proxy_config.builtin_test_server {
            let port = self.launch_test_proxy(logger)?;
            ProxyAddress::new("127.0.0.1".to_string(), port, true)
        } else if let Some(ref addr) = proxy_config.address {
            addr.clone()
        } else {
            return Ok(());
        };

        self.proxy_address = Some(address);

        if let Err(err) = enable_loopback(script_sid) {
            self.stop(logger);
            return Err(err);
        }
        self.loopback_container_name = Some(container_name.to_string());

        if let Err(err) = self.launch_shim(principal_id, logger) {
            self.stop(logger);
            return Err(err);
        }

        logger.log_line(&format!(
            "Proxy policy active for SID {} -> {}",
            principal_id,
            self.proxy_address.as_ref().unwrap().to_url(),
        ));

        Ok(())
    }

    /// Launch `wxc-test-proxy.exe` and read its port from the ready file.
    fn launch_test_proxy(&mut self, logger: &mut Logger) -> Result<u16, WxcError> {
        logger.log_line(
            "WARNING: Starting builtin test proxy — this is for integration testing only, \
             NOT for production use.",
        );

        let unique_id = generate_unique_id();
        let ready_file_path =
            std::env::temp_dir().join(format!("wxc-test-proxy-ready-{}.tmp", unique_id));
        let event_name = format!("Local\\wxc-test-proxy-{}", unique_id);
        let event_name_wide = string_util::to_wide(&event_name);

        let event_handle =
            unsafe { CreateEventW(None, true, false, PCWSTR(event_name_wide.as_ptr())) }.map_err(
                |err| {
                    WxcError::NetworkProxy(format!(
                        "Failed to create test proxy cleanup event: {}",
                        err
                    ))
                },
            )?;

        self.test_proxy_cleanup_event = Some(OwnedHandle::new(event_handle));
        self.test_proxy_ready_file_path = Some(ready_file_path.clone());

        let proxy_exe = resolve_sibling_binary("wxc-test-proxy.exe")?;

        let mut child = std::process::Command::new(&proxy_exe)
            .arg("--ready-file")
            .arg(&ready_file_path)
            .arg("--cleanup-event")
            .arg(&event_name)
            .arg("--parent-pid")
            .arg(std::process::id().to_string())
            .stderr(std::process::Stdio::inherit())
            .stdout(std::process::Stdio::null())
            .stdin(std::process::Stdio::null())
            .spawn()
            .map_err(|err| {
                WxcError::NetworkProxy(format!("Failed to launch wxc-test-proxy.exe: {}", err))
            })?;

        let child_pid = child.id();
        let process_handle = match unsafe { OpenProcess(PROCESS_SYNCHRONIZE, false, child_pid) } {
            Ok(handle) => handle,
            Err(err) => {
                let _ = child.kill();
                return Err(WxcError::NetworkProxy(format!(
                    "Failed to open handle for test proxy process: {}",
                    err
                )));
            }
        };
        self.test_proxy_handle = Some(OwnedHandle::new(process_handle));

        poll_for_ready_file(
            &ready_file_path,
            self.test_proxy_handle.as_ref().unwrap(),
            15,
            logger,
            "wxc-test-proxy",
        )?;

        let content = std::fs::read_to_string(&ready_file_path).map_err(|err| {
            WxcError::NetworkProxy(format!("Failed to read test proxy ready file: {}", err))
        })?;

        let port: u16 = content.trim().parse().map_err(|err| {
            WxcError::NetworkProxy(format!(
                "Invalid port in test proxy ready file '{}': {}",
                content.trim(),
                err
            ))
        })?;

        Ok(port)
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

        self.shim_cleanup_event = Some(OwnedHandle::new(event_handle));
        self.shim_ready_file_path = Some(ready_file_path.clone());

        let shim_path = resolve_sibling_binary("winhttp-proxy-shim.exe")?;
        let addr = self.proxy_address.as_ref().unwrap();
        let shim_args = format!(
            "--sid {} --proxy-address {} --proxy-port {} \
             --ready-file \"{}\" --cleanup-event \"{}\" --parent-pid {}",
            principal_id,
            addr.host(),
            addr.port(),
            ready_file_path.display(),
            event_name,
            std::process::id(),
        );

        logger.log_line(&format!(
            "Launching winhttp-proxy-shim elevated: SID {} -> {}",
            principal_id,
            addr.to_url()
        ));

        let shim_handle = launch_elevated(&shim_path.to_string_lossy(), &shim_args, logger)?;
        self.shim_process_handle = Some(shim_handle);

        poll_for_ready_file(
            &ready_file_path,
            self.shim_process_handle.as_ref().unwrap(),
            30,
            logger,
            "winhttp-proxy-shim",
        )
    }

    /// Stop the proxy: signal shim and test proxy cleanup, remove loopback exemption.
    pub fn stop(&mut self, logger: &mut Logger) {
        signal_process_cleanup(
            self.shim_cleanup_event.take(),
            self.shim_process_handle.take(),
            "winhttp-proxy-shim",
            logger,
        );
        signal_process_cleanup(
            self.test_proxy_cleanup_event.take(),
            self.test_proxy_handle.take(),
            "wxc-test-proxy",
            logger,
        );
        self.proxy_address = None;

        if let Some(path) = self.shim_ready_file_path.take() {
            let _ = std::fs::remove_file(&path);
        }
        if let Some(path) = self.test_proxy_ready_file_path.take() {
            let _ = std::fs::remove_file(&path);
        }
        if let Some(container_name) = self.loopback_container_name.take() {
            remove_loopback_exemption(&container_name);
        }
    }
}

impl Default for ProxyCoordinator {
    fn default() -> Self {
        Self::new()
    }
}

impl Drop for ProxyCoordinator {
    fn drop(&mut self) {
        // Best-effort cleanup without a logger.
        let mut logger = Logger::new(crate::logger::Mode::Buffer);
        self.stop(&mut logger);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new_manager() {
        let mgr = ProxyCoordinator::new();
        assert!(!mgr.is_active());
    }

    #[test]
    fn test_default_manager() {
        let mgr = ProxyCoordinator::default();
        assert!(!mgr.is_active());
    }

    #[test]
    fn test_stop_when_not_active() {
        let mut mgr = ProxyCoordinator::new();
        let mut logger = Logger::new(crate::logger::Mode::Buffer);
        mgr.stop(&mut logger);
        assert!(!mgr.is_active());
    }

    #[test]
    fn test_generate_unique_id() {
        let id = generate_unique_id();
        assert!(!id.is_empty());
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
