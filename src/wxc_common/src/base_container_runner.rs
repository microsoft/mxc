// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! `BaseContainerRunner` — executes scripts via `Experimental_CreateProcessInSandbox` API.
//!
//! When `wxc-exec` receives a config with `schema_version` >= 0.5, this runner:
//! 1. Builds a FlatBuffer `SandboxSpec` from the container policy
//! 2. Loads `processmodel.dll` dynamically
//! 3. Calls `Experimental_CreateProcessInSandbox` to launch the child process
//! 4. Waits for the process to exit and returns the result

use std::ffi::c_void;
use std::fmt::Write;
use std::ptr;

use windows::Win32::Foundation::{CloseHandle, GetLastError, WAIT_FAILED, WAIT_TIMEOUT};
use windows::Win32::System::LibraryLoader::{
    GetProcAddress, LoadLibraryExW, LOAD_LIBRARY_SEARCH_SYSTEM32,
};
use windows::Win32::System::Threading::{
    GetExitCodeProcess, TerminateProcess, WaitForSingleObject, PROCESS_INFORMATION, STARTUPINFOW,
};
use windows_core::PCWSTR;

use crate::logger::Logger;
use crate::models::{
    BaseProcessUiConfig, ClipboardPolicy, CodexRequest, NetworkEnforcementMode, NetworkPolicy,
    ProxyAddress, ScriptResponse, UiPolicy,
};
use crate::proxy_coordinator::ProxyCoordinator;
use crate::script_runner::{get_timeout_milliseconds, ScriptRunner};
use crate::string_util;
use sandbox_spec::base_container_layout::{
    finish_sandbox_spec_buffer, proxy_info, proxy_infoArgs, NetworkPolicy as FbsNetworkPolicy,
    NetworkPolicyArgs, SandboxSpec, SandboxSpecArgs,
};

/// Function pointer type matching `Experimental_CreateProcessInSandbox` from processmodel.dll.
type PfnCreateProcessInSandbox = unsafe extern "system" fn(
    application_name: *const u16,
    command_line: *mut u16,
    process_attributes: *const c_void,
    thread_attributes: *const c_void,
    inherit_handles: i32,
    creation_flags: u32,
    environment: *const c_void,
    current_directory: *const u16,
    startup_info: *const STARTUPINFOW,
    identity: *const u16,
    sandbox_specification: *const u8,
    sandbox_specification_size: u32,
    process_information: *mut PROCESS_INFORMATION,
) -> i32;

/// Script runner that uses `Experimental_CreateProcessInSandbox` API
/// to launch a sandboxed process.
#[derive(Default)]
pub struct BaseContainerRunner {
    proxy_coordinator: ProxyCoordinator,
}

/// Windows error code for a function that exists but is not implemented
/// (e.g., disabled via feature-enablement mechanisms).
const ERROR_CALL_NOT_IMPLEMENTED: u32 = 120;

/// SandboxSpec FlatBuffer schema version embedded in every spec payload.
const SANDBOX_SPEC_VERSION: &str = "0.1.0";

impl BaseContainerRunner {
    pub fn new() -> Self {
        Self::default()
    }

    /// Pre-flight probe: check whether the current OS build exports the
    /// `Experimental_CreateProcessInSandbox` symbol from `processmodel.dll`.
    ///
    /// Returns `Ok(())` if the export is resolvable, or `Err` with a
    /// human-readable description when the DLL or export is missing.
    ///
    /// Note: a successful probe only means the symbol exists. The OS may
    /// still reject calls at runtime with `ERROR_CALL_NOT_IMPLEMENTED` if
    /// the feature is disabled (e.g., via internal feature-enablement mechanisms).
    pub fn is_base_container_api_present() -> Result<(), String> {
        Self::load_api().map(|_| ())
    }

    /// JOB_OBJECT_UILIMIT_* flag constants (from UIPolicy_Schema.md).
    const UILIMIT_HANDLES: u64 = 0x0001;
    const UILIMIT_READCLIPBOARD: u64 = 0x0002;
    const UILIMIT_WRITECLIPBOARD: u64 = 0x0004;
    const UILIMIT_SYSTEMPARAMETERS: u64 = 0x0008;
    const UILIMIT_DISPLAYSETTINGS: u64 = 0x0010;
    const UILIMIT_GLOBALATOMS: u64 = 0x0020;
    const UILIMIT_DESKTOP: u64 = 0x0040;
    const UILIMIT_EXITWINDOWS: u64 = 0x0080;
    const UILIMIT_IME: u64 = 0x0100;
    const UILIMIT_INJECTION: u64 = 0x0200;

    /// Build the JOB_OBJECT_UILIMIT_* bitmask from the cross-platform UI policy
    /// and the BaseProcessContainer-specific UI config.
    /// Mapping follows docs/UIPolicy_Schema.md.
    fn ui_restrictions_bitmask(ui: &UiPolicy, base_proc_ui: &BaseProcessUiConfig) -> u64 {
        // When UI is fully disabled: DisallowWin32kSystemCalls handles everything
        // except atoms (NT executive syscalls, not Win32k). Only set GLOBALATOMS.
        if ui.disable {
            return Self::UILIMIT_GLOBALATOMS;
        }

        let mut mask: u64 = 0;

        // Cross-platform: clipboard (default: "none" = block both)
        match ui.clipboard {
            ClipboardPolicy::All => {}
            ClipboardPolicy::Read => {
                mask |= Self::UILIMIT_WRITECLIPBOARD;
            }
            ClipboardPolicy::Write => {
                mask |= Self::UILIMIT_READCLIPBOARD;
            }
            // "none" or unrecognized → default-deny: block both
            _ => {
                mask |= Self::UILIMIT_READCLIPBOARD | Self::UILIMIT_WRITECLIPBOARD;
            }
        }

        // Cross-platform: input injection
        if !ui.injection {
            mask |= Self::UILIMIT_INJECTION;
        }

        // Backend-specific: isolation level (default: "container" = HANDLES + GLOBALATOMS)
        match base_proc_ui.isolation.as_str() {
            "desktop" => {
                // No isolation flags
            }
            "handles" => {
                mask |= Self::UILIMIT_HANDLES;
            }
            "atoms" => {
                mask |= Self::UILIMIT_GLOBALATOMS;
            }
            // "container" or unrecognized → default-deny: full isolation
            _ => {
                mask |= Self::UILIMIT_HANDLES | Self::UILIMIT_GLOBALATOMS;
            }
        }

        // Backend-specific: desktop system control
        if !base_proc_ui.desktop_system_control {
            mask |= Self::UILIMIT_DESKTOP | Self::UILIMIT_EXITWINDOWS;
        }

        // Backend-specific: system settings (default: "none" = block all)
        match base_proc_ui.system_settings.as_str() {
            "all" => {}
            "parameters" => {
                mask |= Self::UILIMIT_DISPLAYSETTINGS;
            }
            "display" => {
                mask |= Self::UILIMIT_SYSTEMPARAMETERS;
            }
            // "none" or unrecognized → default-deny: block all
            _ => {
                mask |= Self::UILIMIT_SYSTEMPARAMETERS | Self::UILIMIT_DISPLAYSETTINGS;
            }
        }

        // Backend-specific: IME
        if !base_proc_ui.ime {
            mask |= Self::UILIMIT_IME;
        }

        mask
    }

    /// Build a FlatBuffer `SandboxSpec` from the container policy in the request.
    ///
    /// Maps `ContainerPolicy` and `UiPolicy` fields to the BaseContainer schema:
    /// - `app_container` is always `true` (AppContainer is the base sandbox primitive)
    /// - `least_privilege` from `policy.least_privilege_mode`
    /// - `capabilities` from `policy.capabilities` (comma-joined)
    /// - `fs_read_write` from `policy.readwrite_paths`
    /// - `fs_read_only` from `policy.readonly_paths`
    /// - `disallowWin32kSystemCalls` from `ui.disable`
    /// - `ui_restrictions` bitmask from `ui.to_ui_restrictions_bitmask()`
    /// - `network_policy.proxy.url` from proxy config
    fn build_sandbox_spec(request: &CodexRequest) -> Vec<u8> {
        let mut builder = flatbuffers::FlatBufferBuilder::with_capacity(1024);

        let version = builder.create_string(SANDBOX_SPEC_VERSION);

        // Match legacy AppContainer behaviour: when network enforcement uses
        // capabilities and the default policy is Allow, ensure internetClient
        // is present so the sandboxed process has network access.
        let mut caps = request.policy.capabilities.clone();
        let use_caps_for_network = matches!(
            request.policy.network_enforcement_mode,
            NetworkEnforcementMode::Capabilities | NetworkEnforcementMode::Both
        );
        if use_caps_for_network
            && request.policy.default_network_policy == NetworkPolicy::Allow
            && !caps.iter().any(|c| c == "internetClient")
        {
            caps.push("internetClient".to_string());
        }

        let capabilities = if caps.is_empty() {
            None
        } else {
            Some(builder.create_string(&caps.join(",")))
        };

        let fs_read_write = if request.policy.readwrite_paths.is_empty() {
            None
        } else {
            let offsets: Vec<_> = request
                .policy
                .readwrite_paths
                .iter()
                .map(|s| builder.create_string(s))
                .collect();
            Some(builder.create_vector(&offsets))
        };

        let fs_read_only = if request.policy.readonly_paths.is_empty() {
            None
        } else {
            let offsets: Vec<_> = request
                .policy
                .readonly_paths
                .iter()
                .map(|s| builder.create_string(s))
                .collect();
            Some(builder.create_vector(&offsets))
        };

        // Build NetworkPolicy with proxy URL if configured
        let network_policy = if request.policy.network_proxy.is_enabled() {
            let proxy_url = request
                .policy
                .network_proxy
                .address
                .as_ref()
                .map(|addr| addr.to_url());

            let proxy = if let Some(url) = &proxy_url {
                let url_offset = builder.create_string(url);
                Some(proxy_info::create(
                    &mut builder,
                    &proxy_infoArgs {
                        url: Some(url_offset),
                    },
                ))
            } else {
                None
            };

            Some(FbsNetworkPolicy::create(
                &mut builder,
                &NetworkPolicyArgs { proxy },
            ))
        } else {
            None
        };

        // UI restrictions
        let ui_restrictions =
            Self::ui_restrictions_bitmask(&request.policy.ui, &request.policy.base_process_ui);

        let spec = SandboxSpec::create(
            &mut builder,
            &SandboxSpecArgs {
                version: Some(version),
                app_container: true,
                integrity_level: 0,
                disallowWin32kSystemCalls: request.policy.ui.disable,
                ui_restrictions,
                least_privilege: request.policy.least_privilege_mode,
                capabilities,
                fs_read_write,
                fs_read_only,
                network_policy,
            },
        );

        finish_sandbox_spec_buffer(&mut builder, spec);
        builder.finished_data().to_vec()
    }

    /// Load `processmodel.dll` and resolve the `Experimental_CreateProcessInSandbox` export.
    fn load_api() -> Result<PfnCreateProcessInSandbox, String> {
        let dll_name = string_util::to_wide("processmodel.dll");

        // SAFETY: `dll_name` is a valid null-terminated wide string that outlives the
        // call. `LOAD_LIBRARY_SEARCH_SYSTEM32` restricts the search to System32, avoiding
        // DLL-planting attacks. The returned `hmodule` is used only with `GetProcAddress`
        // below and is never freed (the DLL stays loaded for the process lifetime).
        // `GetProcAddress` returns a valid function pointer for a known export; we
        // transmute it to `PfnCreateProcessInSandbox` whose signature matches the
        // C declaration of `Experimental_CreateProcessInSandbox` in processmodel.dll.
        unsafe {
            let hmodule = LoadLibraryExW(
                PCWSTR(dll_name.as_ptr()),
                None,
                LOAD_LIBRARY_SEARCH_SYSTEM32,
            )
            .map_err(|e| format!("LoadLibraryExW(processmodel.dll) failed: {e}"))?;

            let proc = GetProcAddress(
                hmodule,
                windows::core::PCSTR(c"Experimental_CreateProcessInSandbox".as_ptr().cast()),
            )
            .ok_or_else(|| {
                "GetProcAddress(Experimental_CreateProcessInSandbox) failed — \
                 API not present on this OS build"
                    .to_string()
            })?;

            #[allow(clippy::missing_transmute_annotations)]
            Ok(std::mem::transmute(proc))
        }
    }
}

impl ScriptRunner for BaseContainerRunner {
    fn validate_runner(&self, request: &CodexRequest) -> Result<(), ScriptResponse> {
        Self::is_base_container_api_present().map_err(|e| {
            let hint = if !request.experimental_enabled {
                format!(
                    "BaseContainer API unavailable: {e}\n\
                     Hint: Config schema version '{}' requires the BaseContainer backend, \
                     but this OS build does not support it. \
                     Use schema version '0.4.0-alpha' to fall back to AppContainer.",
                    request.schema_version
                )
            } else {
                format!(
                    "BaseContainer API unavailable: {e}\n\
                     Hint: --experimental requested BaseContainer, but this OS build \
                     does not support it. Remove --experimental to use the AppContainer \
                     backend, or use an OS build with BaseContainer support."
                )
            };
            ScriptResponse::error(&hint)
        })
    }

    fn execute(&mut self, request: &CodexRequest, logger: &mut Logger) -> ScriptResponse {
        let _ = writeln!(logger, "SECTION: Backend runner 'BaseContainer'");

        let run_start = std::time::Instant::now();

        // Launch builtin test proxy if requested (before building spec so we have the port).
        let mut request = request.clone();
        if request.policy.network_proxy.builtin_test_server {
            match self.proxy_coordinator.launch_test_proxy(logger) {
                Ok(port) => {
                    let addr = ProxyAddress::new("127.0.0.1".to_string(), port);
                    request.policy.network_proxy.address = Some(addr);
                }
                Err(e) => {
                    return ScriptResponse::error(&format!(
                        "Failed to start builtin test proxy: {e}"
                    ));
                }
            }
        }

        // Log the effective proxy config after resolution.
        if request.policy.network_proxy.is_enabled() {
            let addr = request
                .policy
                .network_proxy
                .address
                .as_ref()
                .map(|a| a.to_url())
                .unwrap_or_else(|| "<pending>".to_string());
            let _ = writeln!(
                logger,
                "effective proxy: {} (builtin_test_server={})",
                addr, request.policy.network_proxy.builtin_test_server
            );
        }

        let _ = writeln!(logger, "SECTION: Build sandbox spec");

        // 1. Build the FlatBuffer sandbox spec from the request policy.
        let spec_bytes = Self::build_sandbox_spec(&request);

        // Print proxy URL in debug mode
        if let Some(ref addr) = request.policy.network_proxy.address {
            let _ = writeln!(logger, "proxy URL in spec: {}", addr.to_url());
        }

        let ui_restrictions =
            Self::ui_restrictions_bitmask(&request.policy.ui, &request.policy.base_process_ui);
        let _ = writeln!(logger, "sandbox spec built (version={}, {} bytes)", SANDBOX_SPEC_VERSION, spec_bytes.len());

        // Print flags in debug mode
        let _ = writeln!(
            logger,
            "disallowWin32kSystemCalls={}, ui_restrictions=0x{:04X}",
            request.policy.ui.disable, ui_restrictions
        );
        let _ = writeln!(
            logger,
            "ui.clipboard={:?}, ui.injection={}",
            request.policy.ui.clipboard, request.policy.ui.injection
        );
        let _ = writeln!(
            logger,
            "base_process_ui: isolation={}, desktopSystemControl={}, systemSettings={}, ime={}",
            request.policy.base_process_ui.isolation,
            request.policy.base_process_ui.desktop_system_control,
            request.policy.base_process_ui.system_settings,
            request.policy.base_process_ui.ime
        );
        let _ = writeln!(
            logger,
            "UILIMIT flags: HANDLES={} READCLIP={} WRITECLIP={} SYSPARAM={} DISPLAY={} ATOMS={} DESKTOP={} EXIT={} IME={} INJECT={}",
            ui_restrictions & Self::UILIMIT_HANDLES != 0,
            ui_restrictions & Self::UILIMIT_READCLIPBOARD != 0,
            ui_restrictions & Self::UILIMIT_WRITECLIPBOARD != 0,
            ui_restrictions & Self::UILIMIT_SYSTEMPARAMETERS != 0,
            ui_restrictions & Self::UILIMIT_DISPLAYSETTINGS != 0,
            ui_restrictions & Self::UILIMIT_GLOBALATOMS != 0,
            ui_restrictions & Self::UILIMIT_DESKTOP != 0,
            ui_restrictions & Self::UILIMIT_EXITWINDOWS != 0,
            ui_restrictions & Self::UILIMIT_IME != 0,
            ui_restrictions & Self::UILIMIT_INJECTION != 0,
        );

        let _ = writeln!(logger, "SECTION: Load API");

        // 2. Dynamically load the API from processmodel.dll.
        let create_process_in_sandbox = match Self::load_api() {
            Ok(f) => f,
            Err(e) => return ScriptResponse::error(&e),
        };
        let _ = writeln!(
            logger,
            "loaded Experimental_CreateProcessInSandbox from processmodel.dll"
        );

        let _ = writeln!(logger, "SECTION: Launch process");

        // 3. Build the command line (passed directly, same as AppContainerScriptRunner).
        let mut cmd_wide = string_util::to_wide(&request.script_code);

        // Working directory (NULL falls back to the current directory).
        let cwd_wide;
        let cwd_ptr = if request.working_directory.is_empty() {
            ptr::null()
        } else {
            cwd_wide = string_util::to_wide(&request.working_directory);
            cwd_wide.as_ptr()
        };

        // Identity -- used by the sandbox engine to name the AppContainer profile.
        let identity = if request.container_id.is_empty() {
            "MxcBaseContainer".to_string()
        } else {
            request.container_id.clone()
        };
        let identity_wide = string_util::to_wide(&identity);

        // STARTUPINFOW -- minimal, no handle inheritance (not yet supported by the API).
        let si = STARTUPINFOW {
            cb: std::mem::size_of::<STARTUPINFOW>() as u32,
            ..unsafe { std::mem::zeroed() }
        };
        let mut pi: PROCESS_INFORMATION = unsafe { std::mem::zeroed() };

        let _ = writeln!(logger, "launching: {}", request.script_code);
        let _ = writeln!(logger, "identity: {identity}");

        // 4. Call Experimental_CreateProcessInSandbox.
        let success = unsafe {
            create_process_in_sandbox(
                ptr::null(),             // applicationName (resolved from commandLine)
                cmd_wide.as_mut_ptr(),   // commandLine
                ptr::null(),             // processAttributes (must be NULL)
                ptr::null(),             // threadAttributes  (must be NULL)
                0,                       // inheritHandles    (must be FALSE)
                0,                       // creationFlags
                ptr::null(),             // environment       (must be NULL)
                cwd_ptr,                 // currentDirectory
                &si,                     // startupInfo
                identity_wide.as_ptr(),  // identity
                spec_bytes.as_ptr(),     // sandboxSpecification
                spec_bytes.len() as u32, // sandboxSpecificationSize
                &mut pi,                 // processInformation
            )
        };

        if success == 0 {
            let err = unsafe { GetLastError() };
            if err.0 == ERROR_CALL_NOT_IMPLEMENTED {
                return ScriptResponse::error(
                    "Experimental_CreateProcessInSandbox returned ERROR_CALL_NOT_IMPLEMENTED. \
                     The BaseContainer feature may be disabled on this OS build \
                     (e.g., via feature-enablement mechanisms). \
                     Use schema version '0.4.0-alpha' to fall back to the AppContainer backend.",
                );
            }
            return ScriptResponse::error(&format!(
                "Experimental_CreateProcessInSandbox failed: {err:?}"
            ));
        }

        let _ = writeln!(logger, "process created (PID: {})", pi.dwProcessId);

        let _ = writeln!(logger, "SECTION: Wait for exit");

        // 5. Wait for the child process to exit.
        let timeout_ms = get_timeout_milliseconds(request.script_timeout);
        let mut exit_code: u32 = u32::MAX;

        unsafe {
            let wait_result = WaitForSingleObject(pi.hProcess, timeout_ms);
            if wait_result == WAIT_FAILED {
                let err = GetLastError();
                let _ = CloseHandle(pi.hProcess);
                let _ = CloseHandle(pi.hThread);
                return ScriptResponse::error(&format!("WaitForSingleObject failed: {err:?}"));
            } else if wait_result == WAIT_TIMEOUT {
                let _ = writeln!(logger, "process timed out, terminating...");
                let _ = TerminateProcess(pi.hProcess, u32::MAX);
                let _ = WaitForSingleObject(pi.hProcess, 5000);
            }

            let _ = GetExitCodeProcess(pi.hProcess, &mut exit_code);

            let _ = CloseHandle(pi.hProcess);
            let _ = CloseHandle(pi.hThread);
        }

        let _ = writeln!(logger, "process exited with code {exit_code}");

        let _ = writeln!(
            logger,
            "SECTION: Done ({:.3}s)",
            run_start.elapsed().as_secs_f64()
        );

        // Stop the builtin test proxy if it was started.
        self.proxy_coordinator.stop(logger);

        ScriptResponse {
            exit_code: exit_code as i32,
            standard_out: String::new(),
            standard_err: String::new(),
            error_message: String::new(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::ProxyConfig;
    use sandbox_spec::base_container_layout;

    #[test]
    fn build_sandbox_spec_produces_valid_flatbuffer() {
        let mut request = CodexRequest::default();
        request.policy.least_privilege_mode = true;
        request.policy.capabilities = vec!["internetClient".into(), "registryRead".into()];
        request.policy.readwrite_paths = vec!["C:\\temp".into()];
        request.policy.readonly_paths = vec!["C:\\Windows".into()];

        let bytes = BaseContainerRunner::build_sandbox_spec(&request);

        // Verify the buffer has the SBOX identifier.
        assert!(base_container_layout::sandbox_spec_buffer_has_identifier(
            &bytes
        ));

        // Parse and verify field values.
        let spec = base_container_layout::root_as_sandbox_spec(&bytes)
            .expect("should be a valid SandboxSpec");
        assert_eq!(spec.version(), "0.1.0");
        assert!(spec.app_container());
        assert!(spec.least_privilege());
        assert_eq!(spec.capabilities(), Some("internetClient,registryRead"));
        assert_eq!(spec.integrity_level(), 0);
        assert!(spec.disallowWin32kSystemCalls());
        assert_eq!(
            spec.ui_restrictions(),
            BaseContainerRunner::UILIMIT_GLOBALATOMS
        ); // default: disable=true → only GLOBALATOMS

        let rw = spec.fs_read_write().unwrap();
        assert_eq!(rw.len(), 1);
        assert_eq!(rw.get(0), "C:\\temp");

        let ro = spec.fs_read_only().unwrap();
        assert_eq!(ro.len(), 1);
        assert_eq!(ro.get(0), "C:\\Windows");

        assert!(spec.network_policy().is_none());
    }

    #[test]
    fn build_sandbox_spec_empty_policy() {
        // Default network policy is Allow + Capabilities, so internetClient
        // should be auto-added even with an otherwise empty policy.
        let request = CodexRequest::default();
        let bytes = BaseContainerRunner::build_sandbox_spec(&request);

        assert!(base_container_layout::sandbox_spec_buffer_has_identifier(
            &bytes
        ));

        let spec = base_container_layout::root_as_sandbox_spec(&bytes).unwrap();
        assert_eq!(spec.version(), "0.1.0");
        assert!(spec.app_container());
        assert!(!spec.least_privilege());
        assert_eq!(spec.capabilities(), Some("internetClient"));
        assert!(spec.fs_read_write().is_none());
        assert!(spec.fs_read_only().is_none());
        assert!(spec.disallowWin32kSystemCalls());
        assert!(spec.network_policy().is_none());
    }

    #[test]
    fn build_sandbox_spec_network_block_no_internet_client() {
        let mut request = CodexRequest::default();
        request.policy.default_network_policy = NetworkPolicy::Block;

        let bytes = BaseContainerRunner::build_sandbox_spec(&request);
        let spec = base_container_layout::root_as_sandbox_spec(&bytes).unwrap();
        assert!(spec.capabilities().is_none());
    }

    #[test]
    fn build_sandbox_spec_ui_disabled() {
        use crate::models::UiPolicy;

        let mut request = CodexRequest::default();
        request.policy.ui = UiPolicy {
            disable: true,
            ..Default::default()
        };

        let bytes = BaseContainerRunner::build_sandbox_spec(&request);
        let spec = base_container_layout::root_as_sandbox_spec(&bytes).unwrap();

        assert!(spec.disallowWin32kSystemCalls());
        // disable=true → only GLOBALATOMS (Win32k disable handles the rest)
        assert_eq!(
            spec.ui_restrictions(),
            BaseContainerRunner::UILIMIT_GLOBALATOMS
        );
    }

    #[test]
    fn build_sandbox_spec_ui_clipboard_read_only() {
        let mut request = CodexRequest::default();
        request.policy.ui = UiPolicy {
            disable: false,
            clipboard: ClipboardPolicy::Read,
            injection: true,
        };

        let bytes = BaseContainerRunner::build_sandbox_spec(&request);
        let spec = base_container_layout::root_as_sandbox_spec(&bytes).unwrap();

        assert!(!spec.disallowWin32kSystemCalls());
        // WRITECLIPBOARD + backend defaults (isolation=container: HANDLES+GLOBALATOMS,
        // desktopSystemControl=false: DESKTOP+EXITWINDOWS, systemSettings=none: SYSTEMPARAMETERS+DISPLAYSETTINGS, ime=false: IME)
        let expected = BaseContainerRunner::UILIMIT_WRITECLIPBOARD
            | BaseContainerRunner::UILIMIT_HANDLES
            | BaseContainerRunner::UILIMIT_GLOBALATOMS
            | BaseContainerRunner::UILIMIT_DESKTOP
            | BaseContainerRunner::UILIMIT_EXITWINDOWS
            | BaseContainerRunner::UILIMIT_SYSTEMPARAMETERS
            | BaseContainerRunner::UILIMIT_DISPLAYSETTINGS
            | BaseContainerRunner::UILIMIT_IME;
        assert_eq!(spec.ui_restrictions(), expected);
    }

    #[test]
    fn build_sandbox_spec_ui_clipboard_readwrite_no_injection() {
        let mut request = CodexRequest::default();
        request.policy.ui = UiPolicy {
            disable: false,
            clipboard: ClipboardPolicy::All,
            injection: false,
        };

        let bytes = BaseContainerRunner::build_sandbox_spec(&request);
        let spec = base_container_layout::root_as_sandbox_spec(&bytes).unwrap();

        assert!(!spec.disallowWin32kSystemCalls());
        // INJECTION + backend defaults
        let expected = BaseContainerRunner::UILIMIT_INJECTION
            | BaseContainerRunner::UILIMIT_HANDLES
            | BaseContainerRunner::UILIMIT_GLOBALATOMS
            | BaseContainerRunner::UILIMIT_DESKTOP
            | BaseContainerRunner::UILIMIT_EXITWINDOWS
            | BaseContainerRunner::UILIMIT_SYSTEMPARAMETERS
            | BaseContainerRunner::UILIMIT_DISPLAYSETTINGS
            | BaseContainerRunner::UILIMIT_IME;
        assert_eq!(spec.ui_restrictions(), expected);
    }

    #[test]
    fn build_sandbox_spec_proxy_url() {
        use crate::models::ProxyAddress;

        let mut request = CodexRequest::default();
        request.policy.default_network_policy = NetworkPolicy::Block;
        request.policy.network_proxy = ProxyConfig {
            address: Some(ProxyAddress::new("127.0.0.1".to_string(), 8080)),
            builtin_test_server: false,
        };

        let bytes = BaseContainerRunner::build_sandbox_spec(&request);
        let spec = base_container_layout::root_as_sandbox_spec(&bytes).unwrap();

        let net = spec.network_policy().expect("network_policy should be set");
        let proxy = net.proxy().expect("proxy should be set");
        assert_eq!(proxy.url(), Some("http://127.0.0.1:8080"));
    }

    #[test]
    fn build_sandbox_spec_no_proxy() {
        let request = CodexRequest::default();
        let bytes = BaseContainerRunner::build_sandbox_spec(&request);
        let spec = base_container_layout::root_as_sandbox_spec(&bytes).unwrap();
        assert!(spec.network_policy().is_none());
    }

    #[test]
    fn ui_bitmask_disabled() {
        use crate::models::BaseProcessUiConfig;
        let ui = UiPolicy {
            disable: true,
            ..Default::default()
        };
        let bp = BaseProcessUiConfig::default();
        // disable=true → only GLOBALATOMS
        assert_eq!(
            BaseContainerRunner::ui_restrictions_bitmask(&ui, &bp),
            BaseContainerRunner::UILIMIT_GLOBALATOMS
        );
    }

    #[test]
    fn ui_bitmask_default_deny() {
        use crate::models::BaseProcessUiConfig;
        // UiPolicy default: disable=true → only GLOBALATOMS
        assert_eq!(
            BaseContainerRunner::ui_restrictions_bitmask(
                &UiPolicy::default(),
                &BaseProcessUiConfig::default()
            ),
            BaseContainerRunner::UILIMIT_GLOBALATOMS
        );
    }

    #[test]
    fn ui_bitmask_clipboard_read_with_default_backend() {
        use crate::models::BaseProcessUiConfig;
        let ui = UiPolicy {
            disable: false,
            clipboard: ClipboardPolicy::Read,
            injection: true,
        };
        let bp = BaseProcessUiConfig::default(); // isolation=container, desktopSystemControl=false, systemSettings=none, ime=false
        let expected = BaseContainerRunner::UILIMIT_WRITECLIPBOARD
            | BaseContainerRunner::UILIMIT_HANDLES
            | BaseContainerRunner::UILIMIT_GLOBALATOMS
            | BaseContainerRunner::UILIMIT_DESKTOP
            | BaseContainerRunner::UILIMIT_EXITWINDOWS
            | BaseContainerRunner::UILIMIT_SYSTEMPARAMETERS
            | BaseContainerRunner::UILIMIT_DISPLAYSETTINGS
            | BaseContainerRunner::UILIMIT_IME;
        assert_eq!(
            BaseContainerRunner::ui_restrictions_bitmask(&ui, &bp),
            expected
        );
    }

    #[test]
    fn ui_bitmask_no_backend_restrictions() {
        use crate::models::BaseProcessUiConfig;
        let ui = UiPolicy {
            disable: false,
            clipboard: ClipboardPolicy::All,
            injection: true,
        };
        let bp = BaseProcessUiConfig {
            isolation: "desktop".to_string(),
            desktop_system_control: true,
            system_settings: "all".to_string(),
            ime: true,
        };
        // No cross-platform restrictions + no backend restrictions = 0
        assert_eq!(BaseContainerRunner::ui_restrictions_bitmask(&ui, &bp), 0);
    }
}
