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
use std::io::IsTerminal;
use std::ptr;

use windows::Win32::Foundation::{
    CloseHandle, GetLastError, SetHandleInformation, HANDLE, HANDLE_FLAG_INHERIT, WAIT_FAILED,
    WAIT_TIMEOUT,
};
use windows::Win32::System::Console::{
    GetStdHandle, STD_ERROR_HANDLE, STD_INPUT_HANDLE, STD_OUTPUT_HANDLE,
};
use windows::Win32::System::LibraryLoader::{
    GetProcAddress, LoadLibraryExW, LOAD_LIBRARY_SEARCH_SYSTEM32,
};
use windows::Win32::System::Threading::{
    GetExitCodeProcess, TerminateProcess, WaitForSingleObject, PROCESS_INFORMATION,
    STARTF_USESTDHANDLES, STARTUPINFOW,
};
use windows_core::PCWSTR;

use crate::launch_diagnostics::{
    diagnose_create_process_failure, diagnose_environment_not_supported, diagnose_process_exit,
    is_environment_not_supported,
};
use crate::proxy_coordinator::ProxyCoordinator;
use crate::sandbox_tracking::{self, TrackingEntry};
use sandbox_spec::base_container_layout::{
    finish_sandbox_spec_buffer, proxy_info, proxy_infoArgs, IntegrityLevel,
    NetworkPolicy as FbsNetworkPolicy, NetworkPolicyArgs, SandboxSpec, SandboxSpecArgs,
};
use wxc_common::log_symbols::{
    EMOJI_ALLOWED, EMOJI_BLOCKED, EMOJI_NEUTRAL, EMOJI_SECTION, EMOJI_WARNING,
};
use wxc_common::logger::Logger;
use wxc_common::models::{
    ExecutionRequest, FailurePhase, NetworkEnforcementMode, NetworkPolicy, ProxyAddress,
    ScriptResponse,
};
use wxc_common::process_util::{create_std_pipes, read_from_pipe, OwnedHandle, SendOwnedHandle};
use wxc_common::script_runner::{get_timeout_milliseconds, ScriptRunner};
use wxc_common::string_util;

use windows::Win32::System::Threading::CREATE_UNICODE_ENVIRONMENT;

/// Serialize `KEY=VALUE` pairs into a double-null-terminated UTF-16 environment block.
///
/// Entries are sorted case-insensitively by key as required by `CreateProcessW`.
fn encode_env_block(env_vars: &[String]) -> Vec<u16> {
    let mut entries: Vec<(&str, &str)> =
        env_vars.iter().filter_map(|e| e.split_once('=')).collect();

    entries.sort_by(|(a, _), (b, _)| a.to_ascii_uppercase().cmp(&b.to_ascii_uppercase()));

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

/// SandboxSpec FlatBuffer schema version embedded in every spec payload.
const SANDBOX_SPEC_VERSION: &str = "0.1.0";

/// Sandbox cleanup stub. The actual cleanup (DeleteAppContainerProfile, BFS
/// policy removal, registry tracking deletion) is currently disabled because
/// wxc-exec only tracks the main AppContainer process handle -- child processes
/// may still be running when we reach this point. The tracking entry and
/// ephemeral identity features remain active for diagnostics and future use.
fn run_sandbox_cleanup(
    _identity: &str,
    _sid_string: &str,
    _proxy_enabled: bool,
    logger: &mut Logger,
) {
    let _ = writeln!(
        logger,
        "{EMOJI_SECTION} SECTION: Lifecycle cleanup (skipping -- child process tracking not yet implemented)"
    );
}

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

    /// Build a FlatBuffer `SandboxSpec` from the container policy in the request.
    ///
    /// Maps `ContainerPolicy` and `UiPolicy` fields to the BaseContainer schema:
    /// - `app_container` is always `true` (AppContainer is the base sandbox primitive)
    /// - `least_privilege` from `policy.least_privilege_mode`
    /// - `capabilities` from `policy.capabilities` (comma-joined)
    /// - `fs_read_write` from `policy.readwrite_paths`
    /// - `fs_read_only` from `policy.readonly_paths`
    /// - `disallow_win32k_system_calls` from `ui.disable`
    /// - `ui_restrictions` bitmask from `ui.to_ui_restrictions_bitmask()`
    /// - `network_policy.proxy.url` from proxy config
    fn build_sandbox_spec(request: &ExecutionRequest) -> Vec<u8> {
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
        let ui_restrictions = crate::job_object::to_job_object_uilimit_mask(
            &wxc_common::ui_policy::resolve_ui_restrictions(
                &request.policy.ui,
                &request.policy.base_process_ui,
            ),
        ) as u64;

        let spec = SandboxSpec::create(
            &mut builder,
            &SandboxSpecArgs {
                version: Some(version),
                app_container: true,
                disallow_win32k_system_calls: request.policy.ui.disable,
                ui_restrictions,
                least_privilege: request.policy.least_privilege_mode,
                capabilities,
                fs_read_write,
                fs_read_only,
                network_policy,
                ..Default::default()
            },
        );

        finish_sandbox_spec_buffer(&mut builder, spec);
        builder.finished_data().to_vec()
    }

    /// Log the contents of a built sandbox spec FlatBuffer for debug verification.
    ///
    /// Reads back token, network, and UI restriction fields from the serialised
    /// spec and writes a structured summary to the logger.
    fn log_sandbox_spec(spec_bytes: &[u8], logger: &mut Logger) {
        let spec = match sandbox_spec::base_container_layout::root_as_sandbox_spec(spec_bytes) {
            Ok(s) => s,
            Err(_) => return,
        };

        let _ = writeln!(
            logger,
            "sandbox spec built (version={}, {} bytes)",
            spec.version(),
            spec_bytes.len()
        );

        // Token
        let _ = writeln!(logger, "[token]");
        let integrity_emoji = if spec.integrity() == IntegrityLevel::system_default {
            EMOJI_NEUTRAL
        } else {
            EMOJI_WARNING
        };
        let _ = writeln!(
            logger,
            "  integrity:       {} {:?}",
            integrity_emoji,
            spec.integrity()
        );
        let app_container_emoji = if spec.app_container() {
            EMOJI_NEUTRAL
        } else {
            EMOJI_WARNING
        };
        let _ = writeln!(
            logger,
            "  app_container:   {} {} (least_privilege: {})",
            app_container_emoji,
            if spec.app_container() { "on" } else { "off" },
            if spec.least_privilege() { "on" } else { "off" }
        );
        if let Some(caps) = spec.capabilities() {
            let _ = writeln!(logger, "  capabilities:    {}", caps);
        }

        // Network
        let _ = writeln!(logger, "[network]");
        let proxy_url = spec
            .network_policy()
            .and_then(|np| np.proxy())
            .and_then(|proxy| proxy.url());
        if let Some(url) = proxy_url {
            let _ = writeln!(logger, "  network_policy.proxy.url: {}", url);
        } else {
            let _ = writeln!(logger, "  <unspecified>");
        }

        // UI restrictions
        let _ = writeln!(logger, "[ui subsystem]");
        let _ = writeln!(
            logger,
            "  win32k_system_calls: {} {}",
            if spec.disallow_win32k_system_calls() {
                EMOJI_BLOCKED
            } else {
                EMOJI_ALLOWED
            },
            if spec.disallow_win32k_system_calls() {
                "blocked"
            } else {
                "allowed"
            }
        );
        let r = spec.ui_restrictions();
        let flags: &[(&str, u64)] = &[
            ("handles", 0x0001),
            ("read_clip", 0x0002),
            ("write_clip", 0x0004),
            ("sys_params", 0x0008),
            ("display", 0x0010),
            ("atoms", 0x0020),
            ("desktop", 0x0040),
            ("exit_windows", 0x0080),
            ("ime", 0x0100),
            ("injection", 0x0200),
        ];
        let allowed: Vec<&str> = flags
            .iter()
            .filter(|(_, bit)| r & bit == 0)
            .map(|(name, _)| *name)
            .collect();
        let blocked: Vec<&str> = flags
            .iter()
            .filter(|(_, bit)| r & bit != 0)
            .map(|(name, _)| *name)
            .collect();
        let allowed_str = if allowed.is_empty() {
            "<none>".to_string()
        } else {
            allowed.join(", ")
        };
        let blocked_str = if blocked.is_empty() {
            "<none>".to_string()
        } else {
            blocked.join(", ")
        };
        let _ = writeln!(
            logger,
            "  uilimits allowed {EMOJI_ALLOWED}: {}",
            allowed_str
        );
        let _ = writeln!(
            logger,
            "  uilimits blocked {EMOJI_BLOCKED}: {} (0x{:04X})",
            blocked_str,
            spec.ui_restrictions()
        );
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
    fn validate_runner(&self, request: &ExecutionRequest) -> Result<(), ScriptResponse> {
        if !request.policy.denied_paths.is_empty() {
            return Err(ScriptResponse::error(
                wxc_common::error::DENIED_PATHS_NOT_SUPPORTED_MSG,
            ));
        }
        if !request.policy.allowed_hosts.is_empty() || !request.policy.blocked_hosts.is_empty() {
            return Err(ScriptResponse::error(
                wxc_common::error::HOST_LISTS_NOT_SUPPORTED_MSG,
            ));
        }
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

    fn execute(&mut self, request: &ExecutionRequest, logger: &mut Logger) -> ScriptResponse {
        let _ = writeln!(
            logger,
            "{EMOJI_SECTION} SECTION: Backend runner 'BaseContainer'"
        );

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
            let _ = writeln!(
                logger,
                "warning: proxy support on Windows is best-effort -- only scripts that use \
                 the WinHTTP stack will be proxied; other HTTP stacks may bypass it.",
            );
        }

        let _ = writeln!(logger, "{EMOJI_SECTION} SECTION: Build sandbox spec");

        // 1. Build the FlatBuffer sandbox spec from the request policy.
        let spec_bytes = Self::build_sandbox_spec(&request);

        Self::log_sandbox_spec(&spec_bytes, logger);

        let _ = writeln!(logger, "{EMOJI_SECTION} SECTION: Load API");

        // 2. Dynamically load the API from processmodel.dll.
        let create_process_in_sandbox = match Self::load_api() {
            Ok(f) => f,
            Err(e) => return ScriptResponse::error(&e),
        };
        let _ = writeln!(
            logger,
            "loaded Experimental_CreateProcessInSandbox from processmodel.dll"
        );

        let _ = writeln!(logger, "{EMOJI_SECTION} SECTION: Launch process");

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

        // Identity: when destroy_on_exit is true we generate a random ephemeral
        // identity so each sandbox gets a unique, cleanable AppContainer profile.
        // Otherwise we honour whatever the caller passed in (or the default).
        let (identity, sid_string) = if request.lifecycle.destroy_on_exit {
            let ephemeral = sandbox_tracking::generate_sandbox_identity();
            let _ = writeln!(
                logger,
                "{EMOJI_WARNING} destroy_on_exit=true: overriding caller identity '{}' -> '{}' for ephemeral cleanup",
                request.container_id, ephemeral
            );

            // Derive the AppContainer SID for registry tracking.
            // This is deterministic and does not require the profile to exist yet.
            let sid = match sandbox_tracking::derive_sid_string(&ephemeral) {
                Ok(s) => {
                    let _ = writeln!(logger, "derived SID: {}", s);
                    s
                }
                Err(e) => {
                    let _ = writeln!(logger, "warning: could not derive SID: {}", e);
                    String::new()
                }
            };

            // Write registry tracking entry before launch so it survives crashes.
            if !sid.is_empty() {
                let entry = TrackingEntry {
                    identity: ephemeral.clone(),
                    sid_string: sid.clone(),
                    destroy_on_exit: true,
                    requested_identity: request.container_id.clone(),
                };
                if let Err(e) = sandbox_tracking::write_tracking_entry(&entry, logger) {
                    let _ = writeln!(logger, "warning: tracking entry write failed: {}", e);
                }
            }

            (ephemeral, sid)
        } else {
            let id = if request.container_id.is_empty() {
                sandbox_tracking::generate_sandbox_identity()
            } else {
                request.container_id.clone()
            };
            let _ = writeln!(
                logger,
                "destroy_on_exit=false; using identity '{}', no tracking",
                id
            );
            (id, String::new())
        };
        let identity_wide = string_util::to_wide(&identity);

        // Register Ctrl+C handler early so cleanup runs if wxc-exec is interrupted
        // during or after the create call.
        if request.lifecycle.destroy_on_exit {
            sandbox_tracking::register_ctrl_c_cleanup(
                &identity,
                &sid_string,
                request.policy.network_proxy.is_enabled(),
            );
        }

        // --- Determine STDIO mode ---
        // If wxc-exec's stdout or stderr is not a terminal (i.e., piped by the SDK),
        // we forward our own std handles to the child via STARTF_USESTDHANDLES so the
        // child's output streams directly to the SDK in real time.
        //
        // When `capture_output` is set (the `mxc` library path) we always take
        // the pipe path and wire the child to capture pipes whose output we read
        // into the response.
        let capture = request.capture_output;
        let pipe_mode =
            capture || !std::io::stdout().is_terminal() || !std::io::stderr().is_terminal();

        if pipe_mode {
            if capture {
                let _ = writeln!(
                    logger,
                    "STDIO mode: capture (piping child output into the response)"
                );
            } else {
                let _ = writeln!(
                    logger,
                    "STDIO mode: passthrough (forwarding parent handles to child)"
                );
            }
        }

        // --- Retrieve / create std handles (pipe mode only) ---
        let mut h_stdin = HANDLE::default();
        let mut h_stdout = HANDLE::default();
        let mut h_stderr = HANDLE::default();

        // Capture pipe read-ends (parent side) kept alive until after the wait;
        // child-side ends kept alive until after process creation.
        let mut capture_reads: Option<(OwnedHandle, OwnedHandle)> = None;
        let mut capture_child_ends: Vec<OwnedHandle> = Vec::new();

        if pipe_mode {
            if capture {
                let (stdin_read, _stdin_write) = match create_std_pipes(false) {
                    Ok(p) => p,
                    Err(e) => return ScriptResponse::error(&format!("stdin pipe: {e}")),
                };
                let (stdout_read, stdout_write) = match create_std_pipes(true) {
                    Ok(p) => p,
                    Err(e) => return ScriptResponse::error(&format!("stdout pipe: {e}")),
                };
                let (stderr_read, stderr_write) = match create_std_pipes(true) {
                    Ok(p) => p,
                    Err(e) => return ScriptResponse::error(&format!("stderr pipe: {e}")),
                };

                h_stdin = stdin_read.get();
                h_stdout = stdout_write.get();
                h_stderr = stderr_write.get();

                capture_child_ends.push(stdin_read);
                capture_child_ends.push(stdout_write);
                capture_child_ends.push(stderr_write);
                // `_stdin_write` drops here: the child's stdin sees EOF.
                capture_reads = Some((stdout_read, stderr_read));
            } else {
                h_stdin = match unsafe { GetStdHandle(STD_INPUT_HANDLE) } {
                    Ok(h) => h,
                    Err(e) => return ScriptResponse::error(&format!("GetStdHandle(STDIN): {e}")),
                };
                h_stdout = match unsafe { GetStdHandle(STD_OUTPUT_HANDLE) } {
                    Ok(h) => h,
                    Err(e) => return ScriptResponse::error(&format!("GetStdHandle(STDOUT): {e}")),
                };
                h_stderr = match unsafe { GetStdHandle(STD_ERROR_HANDLE) } {
                    Ok(h) => h,
                    Err(e) => return ScriptResponse::error(&format!("GetStdHandle(STDERR): {e}")),
                };

                if h_stdin.is_invalid() || h_stdin == HANDLE::default() {
                    return ScriptResponse::error(
                        "GetStdHandle(STDIN) returned null/invalid handle",
                    );
                }
                if h_stdout.is_invalid() || h_stdout == HANDLE::default() {
                    return ScriptResponse::error(
                        "GetStdHandle(STDOUT) returned null/invalid handle",
                    );
                }
                if h_stderr.is_invalid() || h_stderr == HANDLE::default() {
                    return ScriptResponse::error(
                        "GetStdHandle(STDERR) returned null/invalid handle",
                    );
                }

                // Ensure the handles are inheritable.
                unsafe {
                    if let Err(e) =
                        SetHandleInformation(h_stdin, HANDLE_FLAG_INHERIT.0, HANDLE_FLAG_INHERIT)
                    {
                        return ScriptResponse::error(&format!("SetHandleInformation(STDIN): {e}"));
                    }
                    if let Err(e) =
                        SetHandleInformation(h_stdout, HANDLE_FLAG_INHERIT.0, HANDLE_FLAG_INHERIT)
                    {
                        return ScriptResponse::error(&format!(
                            "SetHandleInformation(STDOUT): {e}"
                        ));
                    }
                    if let Err(e) =
                        SetHandleInformation(h_stderr, HANDLE_FLAG_INHERIT.0, HANDLE_FLAG_INHERIT)
                    {
                        return ScriptResponse::error(&format!(
                            "SetHandleInformation(STDERR): {e}"
                        ));
                    }
                }
            }
        }

        // STARTUPINFOW -- in pipe mode, pass parent handles via STARTF_USESTDHANDLES
        // so child output streams directly to the SDK caller.
        let si = STARTUPINFOW {
            cb: std::mem::size_of::<STARTUPINFOW>() as u32,
            dwFlags: if pipe_mode {
                STARTF_USESTDHANDLES
            } else {
                Default::default()
            },
            hStdInput: h_stdin,
            hStdOutput: h_stdout,
            hStdError: h_stderr,
            ..unsafe { std::mem::zeroed() }
        };
        #[allow(unused_assignments)]
        let mut pi: PROCESS_INFORMATION = unsafe { std::mem::zeroed() };

        // Environment block for the sandboxed child.
        // If the caller specified explicit env vars, use only those.
        // Otherwise, pass NULL to let the OS provide the default environment
        // for the sandbox (CreateProcessInSandbox handles this internally).
        let env_block: Option<Vec<u16>> = if request.env.is_empty() {
            // TODO: consider calling CreateEnvironmentBlock(NULL, FALSE) here
            // for a cleansed default env if the OS API doesn't do it for us.
            None
        } else {
            Some(encode_env_block(&request.env))
        };

        let env_ptr = env_block
            .as_ref()
            .map(|b| b.as_ptr() as *const c_void)
            .unwrap_or(ptr::null());
        let creation_flags = if env_block.is_some() {
            CREATE_UNICODE_ENVIRONMENT.0
        } else {
            0
        };

        let _ = writeln!(logger, "launching: {}", request.script_code);
        let _ = writeln!(logger, "identity: {identity}");

        // Log the derived AppContainerSID for diagnostic correlation.
        let ac_sid_str = derive_sid_string_from_name(&identity);
        let _ = writeln!(logger, "AppContainerSID: {ac_sid_str}");

        // Pre-launch check: abort if policy paths are on ReFS (Dev Drive) volumes
        // where BFS cannot enforce filesystem policy.
        if let Some(diag) = crate::launch_diagnostics::check_refs_volumes(
            &request.policy.readonly_paths,
            &request.policy.readwrite_paths,
        ) {
            let _ = writeln!(
                logger,
                "Error: Pre-launch diagnostic [{}]: {}",
                diag.kind, diag.message
            );
            return ScriptResponse {
                exit_code: -1,
                error_message: diag.message.clone(),
                standard_err: diag.message,
                failure_phase: FailurePhase::LaunchFailed,
                ..Default::default()
            };
        }

        // 4. Call Experimental_CreateProcessInSandbox.
        //    If the OS returns ERROR_NOT_SUPPORTED (0x32) and we passed a non-null
        //    environment block, this is a downlevel build that doesn't support the
        //    `environment` parameter. Retry once without it.
        let mut current_env_ptr = env_ptr;
        let mut current_creation_flags = creation_flags;
        let mut retries_remaining: u32 = 1;

        // The loop yields (api_return_code, last_win32_error_on_failure).
        let (success, last_error) = loop {
            pi = unsafe { std::mem::zeroed() };

            let result = unsafe {
                create_process_in_sandbox(
                    ptr::null(),           // applicationName (resolved from commandLine)
                    cmd_wide.as_mut_ptr(), // commandLine
                    ptr::null(),           // processAttributes (must be NULL)
                    ptr::null(),           // threadAttributes  (must be NULL)
                    // inheritHandles: must be FALSE per the OS sandbox API contract.
                    // Unlike regular CreateProcess, CreateProcessInSandbox treats the
                    // explicit STDIO handles in STARTUPINFO (hStdInput/hStdOutput/hStdError)
                    // as inheritable when STARTF_USESTDHANDLES is set, but does not support
                    // general handle inheritance.
                    i32::from(false),        // inheritHandles
                    current_creation_flags,  // creationFlags
                    current_env_ptr,         // environment
                    cwd_ptr,                 // currentDirectory
                    &si,                     // startupInfo
                    identity_wide.as_ptr(),  // identity
                    spec_bytes.as_ptr(),     // sandboxSpecification
                    spec_bytes.len() as u32, // sandboxSpecificationSize
                    &mut pi,                 // processInformation
                )
            };

            if result != 0 {
                break (result, None);
            }

            // Call failed -- capture the error before any handle cleanup.
            let err = unsafe { GetLastError() };

            if retries_remaining > 0
                && is_environment_not_supported(err.0, !current_env_ptr.is_null())
            {
                retries_remaining -= 1;

                // Clean up handles from the failed attempt.
                unsafe {
                    if !pi.hProcess.is_invalid() {
                        let _ = CloseHandle(pi.hProcess);
                    }
                    if !pi.hThread.is_invalid() {
                        let _ = CloseHandle(pi.hThread);
                    }
                }

                let diag = diagnose_environment_not_supported();
                let _ = writeln!(
                    logger,
                    "{EMOJI_WARNING} Launch diagnostic [{}]: {}",
                    diag.kind, diag.message
                );

                // Retry without the environment block.
                current_env_ptr = ptr::null();
                current_creation_flags = 0;
                continue;
            }

            // Non-retryable failure.
            break (result, Some(err));
        };

        if success == 0 {
            // Clean up any partially-populated handles from the failed API call.
            unsafe {
                if !pi.hProcess.is_invalid() {
                    let _ = CloseHandle(pi.hProcess);
                }
                if !pi.hThread.is_invalid() {
                    let _ = CloseHandle(pi.hThread);
                }
            }
            // The OS may have created the AppContainer profile before failing,
            // so run the same cleanup logic used on normal exit.
            if request.lifecycle.destroy_on_exit {
                run_sandbox_cleanup(
                    &identity,
                    &sid_string,
                    request.policy.network_proxy.is_enabled(),
                    logger,
                );
            }

            //
            // Diagnose the launch failure (FailurePhase::LaunchFailed).
            //
            let err = last_error.unwrap_or_else(|| unsafe { GetLastError() });
            let diag = diagnose_create_process_failure(
                err.0,
                &request.script_code,
                &request.policy.readonly_paths,
            );

            let extended_error = format!("Experimental_CreateProcessInSandbox failed: {err:?}");
            let _ = writeln!(logger, "Error: {extended_error}");

            let _ = writeln!(
                logger,
                "Error: Launch diagnostic [{}]: {}",
                diag.kind, diag.message
            );

            return ScriptResponse {
                exit_code: -1,
                error_message: diag.message.clone(),
                standard_err: diag.message,
                extended_error,
                failure_phase: FailurePhase::LaunchFailed,
                ..Default::default()
            };
        }

        let _ = writeln!(logger, "process created (PID: {})", pi.dwProcessId);

        // Capture mode: the child has inherited the pipe handles, so close the
        // parent's child-side ends now and drain the read-ends on background
        // threads to avoid the child blocking on a full pipe buffer.
        let mut capture_threads: Option<(
            std::thread::JoinHandle<String>,
            std::thread::JoinHandle<String>,
        )> = None;
        if capture {
            capture_child_ends.clear();
            if let Some((mut stdout_read, mut stderr_read)) = capture_reads.take() {
                let stdout_send = SendOwnedHandle::take(&mut stdout_read);
                let stderr_send = SendOwnedHandle::take(&mut stderr_read);
                let stdout_thread = std::thread::spawn(move || read_from_pipe(stdout_send.get()));
                let stderr_thread = std::thread::spawn(move || read_from_pipe(stderr_send.get()));
                capture_threads = Some((stdout_thread, stderr_thread));
            }
        }

        let _ = writeln!(logger, "{EMOJI_SECTION} SECTION: Wait for exit");

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

        // Capture mode: the child has exited (read-ends will hit EOF); join the
        // drain threads to collect the captured output.
        let (captured_out, captured_err) = match capture_threads {
            Some((stdout_thread, stderr_thread)) => (
                stdout_thread.join().unwrap_or_default(),
                stderr_thread.join().unwrap_or_default(),
            ),
            None => (String::new(), String::new()),
        };

        // 6. Sandbox cleanup: delete AppContainer profile and tracking entry.
        //    Deferred if a network proxy is configured (proxy state can't be cleaned up yet).
        if request.lifecycle.destroy_on_exit {
            run_sandbox_cleanup(
                &identity,
                &sid_string,
                request.policy.network_proxy.is_enabled(),
                logger,
            );
            // Unregister so a late Ctrl+C doesn't double-cleanup.
            sandbox_tracking::unregister_ctrl_c_cleanup();
        }

        let _ = writeln!(
            logger,
            "{EMOJI_SECTION} SECTION: Done ({:.3}s)",
            run_start.elapsed().as_secs_f64()
        );

        // Stop the builtin test proxy if it was started.
        self.proxy_coordinator.stop(logger);

        //
        // Diagnose the application failure (FailurePhase::ProcessExited).
        //
        let (error_message, failure_phase) = if exit_code != 0 {
            if let Some(diag) = diagnose_process_exit(
                &request.script_code,
                &request.policy.readonly_paths,
                &request.policy.readwrite_paths,
                exit_code,
            ) {
                let _ = writeln!(
                    logger,
                    "Error: Launch diagnostic [{}]: {}",
                    diag.kind, diag.message
                );
                (diag.message, FailurePhase::ProcessExited)
            } else {
                (String::new(), FailurePhase::ProcessExited)
            }
        } else {
            (String::new(), FailurePhase::None)
        };

        // Merge diagnostic error into stderr field if present.
        // In passthrough mode, stdout/stderr already went directly to the SDK caller,
        // so standard_out/standard_err in ScriptResponse will be empty. In capture
        // mode we report the child's captured streams (appending any diagnostic
        // message to stderr).
        let final_stdout = if capture { captured_out } else { String::new() };
        let final_stderr = if capture {
            match (captured_err.is_empty(), error_message.is_empty()) {
                (_, true) => captured_err,
                (true, false) => error_message.clone(),
                (false, false) => format!("{captured_err}{error_message}"),
            }
        } else if error_message.is_empty() {
            String::new()
        } else {
            error_message.clone()
        };

        ScriptResponse {
            exit_code: exit_code as i32,
            standard_out: final_stdout,
            standard_err: final_stderr,
            error_message,
            failure_phase,
            ..Default::default()
        }
    }
}

/// Derive the AppContainer SID string from a container identity name.
/// Best-effort: returns a placeholder if derivation fails.
fn derive_sid_string_from_name(name: &str) -> String {
    use windows::Win32::Security::FreeSid;
    use windows::Win32::Security::Isolation::DeriveAppContainerSidFromAppContainerName;

    let wide_name = string_util::to_wide(name);
    let pcwstr_name = PCWSTR(wide_name.as_ptr());

    match unsafe { DeriveAppContainerSidFromAppContainerName(pcwstr_name) } {
        Ok(sid) => {
            let s = unsafe { string_util::sid_to_string(sid.0, "unknown-sid") };
            // SAFETY: SID returned by DeriveAppContainerSidFromAppContainerName
            // must be freed with FreeSid.
            unsafe {
                FreeSid(sid);
            }
            s
        }
        Err(_) => "unknown-sid".to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::job_object::to_job_object_uilimit_mask;
    use sandbox_spec::base_container_layout;
    use wxc_common::models::{ClipboardPolicy, ProxyConfig, UiPolicy};
    use wxc_common::ui_policy::EffectiveUiRestrictions;

    fn expected_mask(r: EffectiveUiRestrictions) -> u64 {
        to_job_object_uilimit_mask(&r) as u64
    }

    #[test]
    fn build_sandbox_spec_produces_valid_flatbuffer() {
        let mut request = ExecutionRequest::default();
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
        assert!(spec.disallow_win32k_system_calls());
        // disable=true sets all non-IME restrictions; ime=false (default) adds IME
        assert_eq!(
            spec.ui_restrictions(),
            expected_mask(EffectiveUiRestrictions {
                block_clipboard_read: true,
                block_clipboard_write: true,
                block_input_injection: true,
                block_input_method_changes: true,
                block_external_ui_objects: true,
                block_global_ui_namespace: true,
                block_desktop_switching: true,
                block_logoff_or_shutdown: true,
                block_system_parameter_changes: true,
                block_display_settings_changes: true,
            })
        );

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
        // Default network policy is Block — no internetClient auto-add.
        let request = ExecutionRequest::default();
        let bytes = BaseContainerRunner::build_sandbox_spec(&request);

        assert!(base_container_layout::sandbox_spec_buffer_has_identifier(
            &bytes
        ));

        let spec = base_container_layout::root_as_sandbox_spec(&bytes).unwrap();
        assert_eq!(spec.version(), "0.1.0");
        assert!(spec.app_container());
        assert!(!spec.least_privilege());
        assert!(spec.capabilities().is_none());
        assert!(spec.fs_read_write().is_none());
        assert!(spec.fs_read_only().is_none());
        assert!(spec.disallow_win32k_system_calls());
        assert!(spec.network_policy().is_none());
    }

    #[test]
    fn build_sandbox_spec_network_block_no_internet_client() {
        let mut request = ExecutionRequest::default();
        request.policy.default_network_policy = NetworkPolicy::Block;

        let bytes = BaseContainerRunner::build_sandbox_spec(&request);
        let spec = base_container_layout::root_as_sandbox_spec(&bytes).unwrap();
        assert!(spec.capabilities().is_none());
    }

    #[test]
    fn build_sandbox_spec_ui_disabled() {
        let mut request = ExecutionRequest::default();
        request.policy.ui = UiPolicy {
            disable: true,
            ..Default::default()
        };

        let bytes = BaseContainerRunner::build_sandbox_spec(&request);
        let spec = base_container_layout::root_as_sandbox_spec(&bytes).unwrap();

        assert!(spec.disallow_win32k_system_calls());
        // disable=true sets all non-IME restrictions; ime=false (default) adds IME
        assert_eq!(
            spec.ui_restrictions(),
            expected_mask(EffectiveUiRestrictions {
                block_clipboard_read: true,
                block_clipboard_write: true,
                block_input_injection: true,
                block_input_method_changes: true,
                block_external_ui_objects: true,
                block_global_ui_namespace: true,
                block_desktop_switching: true,
                block_logoff_or_shutdown: true,
                block_system_parameter_changes: true,
                block_display_settings_changes: true,
            })
        );
    }

    #[test]
    fn build_sandbox_spec_ui_clipboard_read_only() {
        let mut request = ExecutionRequest::default();
        request.policy.ui = UiPolicy {
            disable: false,
            clipboard: ClipboardPolicy::Read,
            injection: true,
        };

        let bytes = BaseContainerRunner::build_sandbox_spec(&request);
        let spec = base_container_layout::root_as_sandbox_spec(&bytes).unwrap();

        assert!(!spec.disallow_win32k_system_calls());
        // WRITECLIPBOARD + backend defaults (isolation=container: HANDLES+GLOBALATOMS,
        // desktopSystemControl=false: DESKTOP+EXITWINDOWS, systemSettings=none: SYSTEMPARAMETERS+DISPLAYSETTINGS, ime=false: IME)
        assert_eq!(
            spec.ui_restrictions(),
            expected_mask(EffectiveUiRestrictions {
                block_clipboard_write: true,
                block_external_ui_objects: true,
                block_global_ui_namespace: true,
                block_desktop_switching: true,
                block_logoff_or_shutdown: true,
                block_system_parameter_changes: true,
                block_display_settings_changes: true,
                block_input_method_changes: true,
                ..Default::default()
            })
        );
    }

    #[test]
    fn build_sandbox_spec_ui_clipboard_readwrite_no_injection() {
        let mut request = ExecutionRequest::default();
        request.policy.ui = UiPolicy {
            disable: false,
            clipboard: ClipboardPolicy::All,
            injection: false,
        };

        let bytes = BaseContainerRunner::build_sandbox_spec(&request);
        let spec = base_container_layout::root_as_sandbox_spec(&bytes).unwrap();

        assert!(!spec.disallow_win32k_system_calls());
        // INJECTION + backend defaults
        assert_eq!(
            spec.ui_restrictions(),
            expected_mask(EffectiveUiRestrictions {
                block_input_injection: true,
                block_external_ui_objects: true,
                block_global_ui_namespace: true,
                block_desktop_switching: true,
                block_logoff_or_shutdown: true,
                block_system_parameter_changes: true,
                block_display_settings_changes: true,
                block_input_method_changes: true,
                ..Default::default()
            })
        );
    }

    #[test]
    fn build_sandbox_spec_proxy_url() {
        use wxc_common::models::ProxyAddress;

        let mut request = ExecutionRequest::default();
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
        let request = ExecutionRequest::default();
        let bytes = BaseContainerRunner::build_sandbox_spec(&request);
        let spec = base_container_layout::root_as_sandbox_spec(&bytes).unwrap();
        assert!(spec.network_policy().is_none());
    }

    // ---- validate_runner: unsupported policy fields surface as errors. ----

    use wxc_common::script_runner::ScriptRunner;

    #[test]
    fn validate_runner_rejects_denied_paths() {
        let runner = BaseContainerRunner::new();
        let mut request = ExecutionRequest::default();
        request.policy.denied_paths = vec!["C:\\secret".into()];

        let err = runner
            .validate_runner(&request)
            .expect_err("BaseContainer does not yet support deniedPaths");
        assert!(
            err.error_message.contains("deniedPaths"),
            "expected message to mention deniedPaths, got: {}",
            err.error_message
        );
    }

    #[test]
    fn validate_runner_rejects_allowed_hosts() {
        let runner = BaseContainerRunner::new();
        let mut request = ExecutionRequest::default();
        request.policy.allowed_hosts = vec!["example.com".into()];

        let err = runner
            .validate_runner(&request)
            .expect_err("allowedHosts is not yet supported");
        assert!(err.error_message.contains("allowedHosts"));
    }

    #[test]
    fn validate_runner_rejects_blocked_hosts() {
        let runner = BaseContainerRunner::new();
        let mut request = ExecutionRequest::default();
        request.policy.blocked_hosts = vec!["bad.example.com".into()];

        let err = runner
            .validate_runner(&request)
            .expect_err("blockedHosts is not yet supported");
        assert!(err.error_message.contains("blockedHosts"));
    }

    #[test]
    fn validate_runner_accepts_empty_policy() {
        let runner = BaseContainerRunner::new();
        let request = ExecutionRequest::default();
        // validate_runner may still surface the host-API-unavailable error on
        // dev machines where BaseContainer isn't present; we only assert that
        // the policy-field checks above don't fire. Skip when the host doesn't
        // expose the API.
        if BaseContainerRunner::is_base_container_api_present().is_ok() {
            assert!(runner.validate_runner(&request).is_ok());
        }
    }
}
