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
use crate::models::{CodexRequest, NetworkEnforcementMode, NetworkPolicy, ScriptResponse};
use crate::script_runner::{get_timeout_milliseconds, ScriptRunner};
use crate::string_util;
use sandbox_spec::base_container_layout::{
    finish_sandbox_spec_buffer, SandboxSpec, SandboxSpecArgs,
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
pub struct BaseContainerRunner;

impl BaseContainerRunner {
    pub fn new() -> Self {
        Self
    }

    /// Build a FlatBuffer `SandboxSpec` from the container policy in the request.
    ///
    /// Maps `ContainerPolicy` fields to the BaseContainer schema:
    /// - `app_container` is always `true` (AppContainer is the base sandbox primitive)
    /// - `least_privilege` from `policy.least_privilege_mode`
    /// - `capabilities` from `policy.capabilities` (comma-joined)
    /// - `fs_read_write` from `policy.readwrite_paths`
    /// - `fs_read_only` from `policy.readonly_paths`
    fn build_sandbox_spec(request: &CodexRequest) -> Vec<u8> {
        let mut builder = flatbuffers::FlatBufferBuilder::with_capacity(1024);

        let version = builder.create_string("0.1.0");

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

        let spec = SandboxSpec::create(
            &mut builder,
            &SandboxSpecArgs {
                version: Some(version),
                app_container: true,
                integrity_level: 0,
                ui_restrictions: 0,
                least_privilege: request.policy.least_privilege_mode,
                capabilities,
                fs_read_write,
                fs_read_only,
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
    fn run(&mut self, request: &CodexRequest, logger: &mut Logger) -> ScriptResponse {
        let _ = writeln!(logger, "BaseContainer: building sandbox specification...");

        // 1. Build the FlatBuffer sandbox spec from the request policy.
        let spec_bytes = Self::build_sandbox_spec(request);
        let _ = writeln!(
            logger,
            "BaseContainer: sandbox spec built ({} bytes)",
            spec_bytes.len()
        );

        // 2. Dynamically load the API from processmodel.dll.
        let create_process_in_sandbox = match Self::load_api() {
            Ok(f) => f,
            Err(e) => return ScriptResponse::error(&e),
        };
        let _ = writeln!(
            logger,
            "BaseContainer: loaded Experimental_CreateProcessInSandbox from processmodel.dll"
        );

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

        // Identity — used by the sandbox engine to name the AppContainer profile.
        let identity = if request.container_id.is_empty() {
            "MxcBaseContainer".to_string()
        } else {
            request.container_id.clone()
        };
        let identity_wide = string_util::to_wide(&identity);

        // STARTUPINFOW — minimal, no handle inheritance (not yet supported by the API).
        let si = STARTUPINFOW {
            cb: std::mem::size_of::<STARTUPINFOW>() as u32,
            ..unsafe { std::mem::zeroed() }
        };
        let mut pi: PROCESS_INFORMATION = unsafe { std::mem::zeroed() };

        let _ = writeln!(logger, "BaseContainer: launching: {}", request.script_code);
        let _ = writeln!(logger, "BaseContainer: identity: {identity}");

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
            return ScriptResponse::error(&format!(
                "Experimental_CreateProcessInSandbox failed: {err:?}"
            ));
        }

        let _ = writeln!(
            logger,
            "BaseContainer: process created (PID: {})",
            pi.dwProcessId
        );

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
                let _ = writeln!(logger, "BaseContainer: process timed out, terminating...");
                let _ = TerminateProcess(pi.hProcess, u32::MAX);
                let _ = WaitForSingleObject(pi.hProcess, 5000);
            }

            let _ = GetExitCodeProcess(pi.hProcess, &mut exit_code);

            let _ = CloseHandle(pi.hProcess);
            let _ = CloseHandle(pi.hThread);
        }

        let _ = writeln!(
            logger,
            "BaseContainer: process exited with code {exit_code}"
        );

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
        assert_eq!(spec.ui_restrictions(), 0);

        let rw = spec.fs_read_write().unwrap();
        assert_eq!(rw.len(), 1);
        assert_eq!(rw.get(0), "C:\\temp");

        let ro = spec.fs_read_only().unwrap();
        assert_eq!(ro.len(), 1);
        assert_eq!(ro.get(0), "C:\\Windows");
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
    }

    #[test]
    fn build_sandbox_spec_network_block_no_internet_client() {
        let mut request = CodexRequest::default();
        request.policy.default_network_policy = NetworkPolicy::Block;

        let bytes = BaseContainerRunner::build_sandbox_spec(&request);
        let spec = base_container_layout::root_as_sandbox_spec(&bytes).unwrap();
        assert!(spec.capabilities().is_none());
    }
}
