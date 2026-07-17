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
use wxc_common::models::{ExecutionRequest, NetworkPolicy, ScriptResponse, WslcConfig};
use wxc_common::script_runner::ScriptRunner;
use wxc_common::string_util::{to_wide, CoTaskMemPWSTR};

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
                eprintln!("[WSLC][debug] IoCtxRawGuard dropped -- reclaiming Arc<IoContext>");
                let _ = Arc::from_raw(self.ptr as *const IoContext);
            }
        }
    }
}

/// Callback invoked by the WSLC SDK for stdout/stderr data.
///
/// # Safety
/// `context` must be a valid pointer obtained from `Arc::into_raw(Arc<IoContext>)`.
/// The `Arc` is kept alive in `run_internal` via `IoCtxRawGuard` (which reclaims it
/// on drop), so the pointer remains valid for the duration of all callbacks.
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
/// Same lifetime requirements as `io_callback` — `context` must be a valid
/// pointer from `Arc::into_raw(Arc<IoContext>)`, kept alive by `IoCtxRawGuard`.
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

    /// Detect the format of a tar file by scanning its entries in a single pass.
    ///
    /// - `manifest.json` present → Docker image archive (`docker save`)
    /// - Top-level Linux directories (`bin`, `etc`, `usr`, etc.) → rootfs (`docker export`)
    /// - Neither found after a successful scan → `TarFormat::Unknown`
    /// - Open/read/parse failures → propagated as `std::io::Error`
    fn detect_tar_format(path: &str) -> std::io::Result<TarFormat> {
        let file = std::fs::File::open(path)?;
        let mut archive = tar::Archive::new(file);
        let entries = archive.entries()?;

        const ROOTFS_MARKERS: &[&str] = &["bin", "etc", "usr", "lib", "sbin", "var"];
        let mut has_rootfs_dirs = false;

        for entry in entries {
            let entry = entry?;
            let entry_path = entry.path().map_err(|e| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!("failed to read tar entry path: {}", e),
                )
            })?;

            // Docker-save archives have `manifest.json` at the top level.
            // Match only the root entry — not nested `manifest.json` files
            // (e.g., from NPM packages). Handles both `manifest.json` and
            // `./manifest.json` (common tar prefix).
            let normalized: std::path::PathBuf = entry_path
                .components()
                .filter(|c| !matches!(c, std::path::Component::CurDir))
                .collect();
            if normalized.as_os_str() == "manifest.json" {
                return Ok(TarFormat::DockerSave);
            }

            if !has_rootfs_dirs {
                // Skip a leading `.` component that is commonly present
                // in tar archives (e.g., `./bin/...`).
                let first_component =
                    entry_path
                        .components()
                        .find_map(|component| match component {
                            std::path::Component::CurDir => None,
                            other => Some(other),
                        });

                if let Some(first) = first_component {
                    let first_str = first.as_os_str().to_string_lossy();
                    if ROOTFS_MARKERS
                        .iter()
                        .any(|marker| *marker == first_str.as_ref())
                    {
                        has_rootfs_dirs = true;
                    }
                }
            }
        }

        if has_rootfs_dirs {
            Ok(TarFormat::Rootfs)
        } else {
            Ok(TarFormat::Unknown)
        }
    }

    /// Import a container image from a local tar file.
    ///
    /// Supports both rootfs tars (`docker export`) and Docker image archives
    /// (`docker save`). The format is auto-detected via `detect_tar_format`.
    /// Returns `Ok(())` on success or `Err(ScriptResponse)` on failure.
    unsafe fn import_image_from_tar(
        sdk: &WslcSdk,
        session: WslcSession,
        image_name: &str,
        tar_path: &str,
        logger: &mut Logger,
    ) -> Result<(), ScriptResponse> {
        let path = std::path::Path::new(tar_path);
        if !path.exists() {
            return Err(ScriptResponse::error(&format!(
                "Image tar file not found: '{}'. Provide a valid rootfs tar \
                 (via 'docker export') or Docker image archive (via 'docker save').",
                tar_path
            )));
        }

        // Resolve to absolute path, following symlinks. Fall back to the
        // original path if canonicalization fails (e.g., permissions).
        let canonical = std::fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf());
        let tar_path = canonical.to_string_lossy();

        let tar_format = match Self::detect_tar_format(&tar_path) {
            Ok(fmt) => fmt,
            Err(e) => {
                return Err(ScriptResponse::error(&format!(
                    "Failed to read tar file '{}': {}",
                    tar_path, e
                )));
            }
        };
        let wide_path: Vec<u16> = to_wide(&tar_path);

        match tar_format {
            TarFormat::DockerSave => {
                let _ = writeln!(
                    logger,
                    "[WSLC] Loading Docker image archive from tar: {}",
                    tar_path
                );
                let load_opts = WslcLoadImageOptions {
                    progress_callback: None,
                    progress_callback_context: ptr::null_mut(),
                };
                let mut err_msg = CoTaskMemPWSTR::null();
                let hr = (sdk.WslcLoadSessionImageFromFile)(
                    session,
                    wide_path.as_ptr() as PCWSTR,
                    &load_opts,
                    err_msg.as_mut_ptr(),
                );
                if hr != S_OK {
                    let msg = err_msg.to_string_lossy();
                    return Err(sdk_error(
                        &format!("Failed to load Docker image archive from '{}'", tar_path),
                        hr,
                        &msg,
                    ));
                }
                let _ = writeln!(
                    logger,
                    "[WSLC] Docker image archive loaded successfully from tar"
                );
                let _ = writeln!(
                    logger,
                    "[WSLC] Note: container will use image '{}' — ensure this \
                     matches the tag inside the Docker archive",
                    image_name
                );
            }
            TarFormat::Rootfs => {
                let _ = writeln!(
                    logger,
                    "[WSLC] Importing rootfs image '{}' from tar: {}",
                    image_name, tar_path
                );
                let name_cstr = format!("{}\0", image_name);
                let import_opts = WslcImportImageOptions {
                    progress_callback: None,
                    progress_callback_context: ptr::null_mut(),
                };
                let mut err_msg = CoTaskMemPWSTR::null();
                let hr = (sdk.WslcImportSessionImageFromFile)(
                    session,
                    name_cstr.as_bytes().as_ptr() as PCSTR,
                    wide_path.as_ptr() as PCWSTR,
                    &import_opts,
                    err_msg.as_mut_ptr(),
                );
                if hr != S_OK {
                    let msg = err_msg.to_string_lossy();
                    return Err(sdk_error(
                        &format!("Failed to import image '{}' from tar", image_name),
                        hr,
                        &msg,
                    ));
                }
                let _ = writeln!(
                    logger,
                    "[WSLC] Image '{}' imported successfully from tar",
                    image_name
                );
            }
            TarFormat::Unknown => {
                return Err(ScriptResponse::error(&format!(
                    "Unrecognized tar format: '{}'. Provide a rootfs tar \
                     (via 'docker export') or a Docker image archive (via 'docker save').",
                    tar_path
                )));
            }
        }

        Ok(())
    }
}

/// Detected tar file format for image import.
enum TarFormat {
    /// Docker image archive from `docker save` (contains `manifest.json`).
    DockerSave,
    /// Rootfs filesystem tar from `docker export` (contains Linux root directories).
    Rootfs,
    /// Unrecognized format — not a valid tar or missing expected entries.
    Unknown,
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
    fn execute(&mut self, request: &ExecutionRequest, logger: &mut Logger) -> ScriptResponse {
        unsafe { self.run_internal(request, logger) }
    }
}

impl WSLContainerRunner {
    /// Initialize COM and load the WSLC SDK at runtime.
    ///
    /// # Safety
    /// Must be called once per process before any other WSLC SDK functions.
    /// The returned `WslcSdk` holds raw function pointers loaded from `wslcsdk.dll`;
    /// callers must keep it alive for the duration of all SDK use.
    unsafe fn init_and_load_sdk(logger: &mut Logger) -> Result<WslcSdk, ScriptResponse> {
        let com_hr = windows::Win32::System::Com::CoInitializeEx(
            None,
            windows::Win32::System::Com::COINIT_MULTITHREADED,
        );
        if com_hr.is_err() {
            return Err(ScriptResponse::error(&format!(
                "COM initialization failed: {:?}",
                com_hr
            )));
        }
        let _ = writeln!(logger, "[WSLC] COM initialized");

        let sdk = match WslcSdk::load() {
            Ok(s) => s,
            Err(e) => return Err(ScriptResponse::error(&e)),
        };

        // Prerequisites check
        let mut can_run: BOOL = 0;
        let mut missing = WslcComponentFlags::None;
        let hr = (sdk.WslcCanRun)(&mut can_run, &mut missing);
        if hr != S_OK {
            return Err(sdk_error("WslcCanRun failed", hr, ""));
        }
        if can_run == 0 {
            return Err(ScriptResponse::error(&format!(
                "WSLC runtime not available. Missing components: {:?}. \
                 Ensure WSL2 and the WSLC SDK are installed.",
                missing
            )));
        }
        let _ = writeln!(logger, "[WSLC] Runtime check passed");

        Ok(sdk)
    }

    /// Configure session settings and create the session.
    /// Returns the session guard (RAII).
    /// Keeps owned string data alive through session creation.
    ///
    /// # Safety
    /// `sdk` must contain valid, currently-loaded function pointers.
    /// COM must already be initialized on this thread.
    unsafe fn create_session(
        &self,
        sdk: &WslcSdk,
        request: &ExecutionRequest,
        logger: &mut Logger,
    ) -> Result<WslcSessionGuard, ScriptResponse> {
        let session_name: Vec<u16> = to_wide(&request.container_id);
        let storage_path_str = self.config.storage_path.clone().unwrap_or_else(|| {
            std::env::temp_dir()
                .join("mxc-wslc-sessions")
                .to_string_lossy()
                .to_string()
        });
        let storage_path_wide: Vec<u16> = to_wide(&storage_path_str);

        let mut settings = std::mem::zeroed::<WslcSessionSettings>();
        let hr = (sdk.WslcInitSessionSettings)(
            session_name.as_ptr(),
            storage_path_wide.as_ptr(),
            &mut settings,
        );
        if hr != S_OK {
            return Err(sdk_error("WslcInitSessionSettings failed", hr, ""));
        }

        if let Some(cpu) = self.config.cpu_count {
            let hr = (sdk.WslcSetSessionSettingsCpuCount)(&mut settings, cpu);
            if hr != S_OK {
                return Err(sdk_error("WslcSetSessionSettingsCpuCount failed", hr, ""));
            }
        }
        if let Some(mem_mb) = self.config.memory_mb {
            let mem_mb = match u32::try_from(mem_mb) {
                Ok(v) => v,
                Err(_) => {
                    return Err(ScriptResponse::error(&format!(
                        "Invalid config: memory_mb value {} exceeds maximum {} MB",
                        mem_mb,
                        u32::MAX
                    )));
                }
            };
            let hr = (sdk.WslcSetSessionSettingsMemory)(&mut settings, mem_mb);
            if hr != S_OK {
                return Err(sdk_error("WslcSetSessionSettingsMemory failed", hr, ""));
            }
        }
        if request.script_timeout > 0 {
            let hr = (sdk.WslcSetSessionSettingsTimeout)(&mut settings, request.script_timeout);
            if hr != S_OK {
                return Err(sdk_error("WslcSetSessionSettingsTimeout failed", hr, ""));
            }
        }
        if self.config.gpu {
            let hr = (sdk.WslcSetSessionSettingsFeatureFlags)(
                &mut settings,
                WslcSessionFeatureFlags::EnableGpu,
            );
            if hr != S_OK {
                return Err(sdk_error(
                    "WslcSetSessionSettingsFeatureFlags failed",
                    hr,
                    "",
                ));
            }
        }

        // Create session while string data is still alive
        let mut session: WslcSession = ptr::null_mut();
        let mut err_msg = CoTaskMemPWSTR::null();
        let hr = (sdk.WslcCreateSession)(&mut settings, &mut session, err_msg.as_mut_ptr());
        if hr != S_OK {
            let msg = err_msg.to_string_lossy();
            return Err(sdk_error("WslcCreateSession failed", hr, &msg));
        }
        let _ = writeln!(logger, "[WSLC] Session created");

        Ok(WslcSessionGuard::from_raw(
            session,
            sdk.WslcTerminateSession,
            sdk.WslcReleaseSession,
        ))
    }

    /// Check if image exists, import from tar, or pull from registry.
    ///
    /// # Safety
    /// `sdk` must contain valid function pointers and `session` must be a
    /// live session handle obtained from `WslcCreateSession`.
    unsafe fn resolve_image(
        &self,
        sdk: &WslcSdk,
        session: WslcSession,
        logger: &mut Logger,
    ) -> Result<(), ScriptResponse> {
        let mut images: *mut WslcImageInfo = ptr::null_mut();
        let mut image_count: u32 = 0;
        let hr = (sdk.WslcListSessionImages)(session, &mut images, &mut image_count);
        if hr != S_OK {
            return Err(sdk_error("WslcListSessionImages failed", hr, ""));
        }

        let image_name = &self.config.image;
        let mut image_found = false;
        if !images.is_null() {
            let images_slice = std::slice::from_raw_parts(images, image_count as usize);
            for info in images_slice {
                // `info.name` is a fixed-size, possibly-unterminated C buffer;
                // read up to the first NUL (or the whole buffer if there is
                // none) without allocating, matching the SDK's own truncation.
                let name_bytes =
                    std::slice::from_raw_parts(info.name.as_ptr().cast::<u8>(), info.name.len());
                let end = name_bytes
                    .iter()
                    .position(|&b| b == 0)
                    .unwrap_or(name_bytes.len());
                if let Ok(name) = std::str::from_utf8(&name_bytes[..end]) {
                    if name == image_name.as_str() {
                        image_found = true;
                        break;
                    }
                }
            }
            windows::Win32::System::Com::CoTaskMemFree(Some(images as *const c_void));
        }

        if image_found {
            if self.config.image_tar_path.is_some() {
                let _ = writeln!(
                    logger,
                    "[WSLC] Image '{}' already cached, skipping tar import",
                    image_name
                );
            } else {
                let _ = writeln!(logger, "[WSLC] Image '{}' found", image_name);
            }
        } else if let Some(tar_path) = &self.config.image_tar_path {
            Self::import_image_from_tar(sdk, session, image_name, tar_path, logger)?;
        } else {
            // MXC is an execution layer; image management is out of band. The
            // setup script `scripts\setup-wslc.ps1` (or `wxc-exec.exe
            // --setup-wslc --image <name>`) pre-pulls images into the same
            // WSLC storage_path the runner uses. When the config overrides
            // `experimental.wslc.storagePath`, include it in the suggested
            // commands so the operator's first copy-paste lands the image in
            // the cache the next run will actually read.
            let (storage_arg_wxc, storage_arg_ps) = match &self.config.storage_path {
                Some(sp) => (
                    format!(" --storage-path \"{}\"", sp),
                    format!(" -StoragePath \"{}\"", sp),
                ),
                None => (String::new(), String::new()),
            };
            return Err(ScriptResponse::error(&format!(
                "WSLC image '{}' not found locally. Pre-pull it with: \
                 wxc-exec.exe --setup-wslc --image {}{} \
                 (or scripts\\setup-wslc.ps1 -Image {}{}). \
                 MXC does not pull images at run time; \
                 see docs/wsl/wsl-container-support-plan.md.",
                image_name, image_name, storage_arg_wxc, image_name, storage_arg_ps,
            )));
        }

        Ok(())
    }

    /// Pre-pull a WSLC image into the SDK's local image cache.
    ///
    /// Loads the SDK, opens a minimal session against `storage_path` (or the
    /// runner default), pulls `image_name`, then releases the session. The
    /// image persists in the storage path's cache for subsequent runner
    /// invocations that pass the same `storage_path`.
    ///
    /// # Safety
    /// Must be called once per process before any other WSLC SDK functions
    /// (it initialises COM via `init_and_load_sdk`).
    pub unsafe fn setup_pull_image(
        image_name: &str,
        storage_path: Option<&str>,
        logger: &mut Logger,
    ) -> Result<(), String> {
        let sdk = match Self::init_and_load_sdk(logger) {
            Ok(s) => s,
            Err(resp) => return Err(resp.error_message),
        };

        let storage_path_str = storage_path.map(|s| s.to_string()).unwrap_or_else(|| {
            std::env::temp_dir()
                .join("mxc-wslc-sessions")
                .to_string_lossy()
                .to_string()
        });
        let session_name: Vec<u16> = to_wide("mxc-setup-wslc");
        let storage_path_wide: Vec<u16> = to_wide(&storage_path_str);

        let mut settings = std::mem::zeroed::<WslcSessionSettings>();
        let hr = (sdk.WslcInitSessionSettings)(
            session_name.as_ptr(),
            storage_path_wide.as_ptr(),
            &mut settings,
        );
        if hr != S_OK {
            return Err(format!(
                "WslcInitSessionSettings failed (HRESULT 0x{:08X})",
                hr as u32
            ));
        }

        let mut session: WslcSession = ptr::null_mut();
        let mut create_err = CoTaskMemPWSTR::null();
        let hr = (sdk.WslcCreateSession)(&mut settings, &mut session, create_err.as_mut_ptr());
        if hr != S_OK {
            return Err(format!(
                "WslcCreateSession failed (HRESULT 0x{:08X}): {}",
                hr as u32,
                create_err.to_string_lossy()
            ));
        }
        let _session_guard =
            WslcSessionGuard::from_raw(session, sdk.WslcTerminateSession, sdk.WslcReleaseSession);

        let _ = writeln!(
            logger,
            "[WSLC setup] Pulling image '{}' into {}",
            image_name, storage_path_str
        );
        let uri_cstr = format!("{}\0", image_name);
        let pull_opts = WslcPullImageOptions {
            uri: uri_cstr.as_bytes().as_ptr() as PCSTR,
            progress_callback: None,
            progress_callback_context: ptr::null_mut(),
            auth_info: ptr::null(),
        };
        let mut pull_err = CoTaskMemPWSTR::null();
        let hr = (sdk.WslcPullSessionImage)(session, &pull_opts, pull_err.as_mut_ptr());
        if hr != S_OK {
            return Err(format!(
                "WslcPullSessionImage('{}') failed (HRESULT 0x{:08X}): {}",
                image_name,
                hr as u32,
                pull_err.to_string_lossy()
            ));
        }
        let _ = writeln!(
            logger,
            "[WSLC setup] Image '{}' pulled successfully",
            image_name
        );
        Ok(())
    }

    /// Apply iptables rules inside a running container for host filtering.
    ///
    /// # Safety
    /// `sdk` must contain valid function pointers and `container` must be a
    /// live container handle for a started container.
    unsafe fn apply_iptables_rules(
        sdk: &WslcSdk,
        container: WslcContainer,
        ipt_cmd: &str,
        logger: &mut Logger,
    ) -> Result<(), ScriptResponse> {
        let _ = writeln!(logger, "[WSLC] Applying iptables rules for host filtering");
        let mut ipt_settings = std::mem::zeroed::<WslcProcessSettings>();
        let hr = (sdk.WslcInitProcessSettings)(&mut ipt_settings);
        if hr != S_OK {
            return Err(sdk_error(
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
        let hr = (sdk.WslcSetProcessSettingsCmdLine)(
            &mut ipt_settings,
            ipt_argv.as_ptr(),
            ipt_argv.len(),
        );
        if hr != S_OK {
            return Err(sdk_error(
                "WslcSetProcessSettingsCmdLine (iptables) failed",
                hr,
                "",
            ));
        }

        let mut ipt_process: WslcProcess = ptr::null_mut();
        let mut err_msg = CoTaskMemPWSTR::null();
        let hr = (sdk.WslcCreateContainerProcess)(
            container,
            &mut ipt_settings,
            &mut ipt_process,
            err_msg.as_mut_ptr(),
        );
        if hr != S_OK {
            let msg = err_msg.to_string_lossy();
            return Err(sdk_error("Failed to exec iptables rules", hr, &msg));
        }
        let ipt_guard = WslcProcessGuard::from_raw(ipt_process, sdk.WslcReleaseProcess);

        // Wait for iptables to complete
        let mut ipt_exit_event: HANDLE = ptr::null_mut();
        let hr = (sdk.WslcGetProcessExitEvent)(ipt_guard.as_raw(), &mut ipt_exit_event);
        if hr != S_OK {
            return Err(sdk_error(
                "WslcGetProcessExitEvent (iptables) failed",
                hr,
                "",
            ));
        }
        if !ipt_exit_event.is_null() {
            let wait_result = windows::Win32::System::Threading::WaitForSingleObject(
                windows::Win32::Foundation::HANDLE(ipt_exit_event),
                30_000,
            );
            if wait_result == windows::Win32::Foundation::WAIT_TIMEOUT {
                return Err(ScriptResponse::error("iptables rules timed out after 30s"));
            }
        }

        let mut ipt_exit_code: i32 = -1;
        let hr = (sdk.WslcGetProcessExitCode)(ipt_guard.as_raw(), &mut ipt_exit_code);
        if hr != S_OK {
            return Err(sdk_error(
                "WslcGetProcessExitCode (iptables) failed",
                hr,
                "",
            ));
        }
        if ipt_exit_code != 0 {
            return Err(ScriptResponse::error(&format!(
                "iptables rules failed with exit code {} \
                 (image may not have iptables installed)",
                ipt_exit_code
            )));
        }
        let _ = writeln!(logger, "[WSLC] iptables rules applied successfully");
        Ok(())
    }

    /// Wait for process exit with timeout enforcement.
    /// Returns (exit_code, timed_out).
    ///
    /// # Safety
    /// `sdk` must contain valid function pointers. `process_guard` and
    /// `container_guard` must hold live handles from this session.
    unsafe fn wait_for_process(
        sdk: &WslcSdk,
        process_guard: &WslcProcessGuard,
        container_guard: &WslcContainerGuard,
        io_ctx: &IoContext,
        request: &ExecutionRequest,
        logger: &mut Logger,
    ) -> Result<(i32, bool), ScriptResponse> {
        let mut exit_event: HANDLE = ptr::null_mut();
        let hr = (sdk.WslcGetProcessExitEvent)(process_guard.as_raw(), &mut exit_event);
        if hr != S_OK {
            return Err(sdk_error("WslcGetProcessExitEvent failed", hr, ""));
        }

        let wait_ms = if request.script_timeout > 0 {
            request.script_timeout
        } else {
            u32::MAX
        };

        let mut timed_out = false;
        if !exit_event.is_null() {
            let wait_result = windows::Win32::System::Threading::WaitForSingleObject(
                windows::Win32::Foundation::HANDLE(exit_event),
                wait_ms,
            );
            if wait_result == windows::Win32::Foundation::WAIT_TIMEOUT {
                timed_out = true;
                let _ = writeln!(
                    logger,
                    "[WSLC] Execution timeout ({}ms) reached — stopping container",
                    wait_ms
                );
                let mut err_msg = CoTaskMemPWSTR::null();
                let _ = (sdk.WslcStopContainer)(
                    container_guard.as_raw(),
                    WslcSignal::SigTerm,
                    2,
                    err_msg.as_mut_ptr(),
                );
                drop(err_msg);
            }
        }

        // Wait for exit callback to fire — guarantees all I/O is flushed.
        {
            let (lock, cvar) = &*io_ctx.exited;
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
        let hr = (sdk.WslcGetProcessExitCode)(process_guard.as_raw(), &mut exit_code);
        if hr != S_OK && !timed_out {
            return Err(sdk_error("WslcGetProcessExitCode failed", hr, ""));
        }
        if timed_out {
            let _ = writeln!(logger, "[WSLC] Process killed after timeout");
        } else {
            let _ = writeln!(logger, "[WSLC] Process exited with code {}", exit_code);
        }

        Ok((exit_code, timed_out))
    }

    /// Collect captured I/O and build the final ScriptResponse.
    fn collect_output(
        io_ctx: &IoContext,
        exit_code: i32,
        timed_out: bool,
        wait_ms: u32,
        logger: &mut Logger,
    ) -> ScriptResponse {
        let stdout =
            String::from_utf8_lossy(&io_ctx.stdout.lock().unwrap_or_else(|e| e.into_inner()))
                .to_string();
        let stderr =
            String::from_utf8_lossy(&io_ctx.stderr.lock().unwrap_or_else(|e| e.into_inner()))
                .to_string();

        if !stdout.is_empty() {
            let _ = writeln!(logger, "[WSLC] Captured {} bytes stdout", stdout.len());
        }
        if !stderr.is_empty() {
            let _ = writeln!(logger, "[WSLC] Captured {} bytes stderr", stderr.len());
        }

        ScriptResponse {
            exit_code: if timed_out { -1 } else { exit_code },
            standard_out: stdout,
            standard_err: stderr,
            error_message: if timed_out {
                format!("Process timed out after {}ms and was terminated", wait_ms)
            } else {
                String::new()
            },
            ..Default::default()
        }
    }

    /// Orchestrates the full WSLC lifecycle.
    /// Helpers handle phases that don't involve dangling-pointer risks;
    /// pointer-heavy SDK configuration stays inline to keep owned string
    /// data alive for the duration needed.
    ///
    /// # Safety
    /// Calls into the WSLC SDK via raw FFI. Owned buffers backing pointers
    /// passed to the SDK (cmdline, env, mounts, etc.) must remain alive
    /// until the SDK call that consumes them returns. RAII guards
    /// (`WslcSessionGuard`, `WslcContainerGuard`, `WslcProcessGuard`,
    /// `IoCtxRawGuard`) ensure handles and reference counts are released
    /// on every exit path.
    unsafe fn run_internal(
        &self,
        request: &ExecutionRequest,
        logger: &mut Logger,
    ) -> ScriptResponse {
        let _ = writeln!(logger, "[WSLC] Starting WSL Container runner");

        // Object-based FS-policy normalization (D6): tighten aliases of the same
        // host object to the strictest intent (deny > ro > rw) before mapping to
        // volume mounts. See `wxc_common::filesystem_object`. (A path moved to
        // `denied` is simply not mounted by WSLC — unmounted = invisible.) Only
        // clone the request when an aliasing conflict actually needs tightening;
        // an unresolvable path with deniedPaths present fails closed.
        let normalized;
        let request = match wxc_common::filesystem_object::normalize_object_conflicts(
            &request.policy,
            logger,
        ) {
            Ok(Some(policy)) => {
                normalized = ExecutionRequest {
                    policy,
                    ..request.clone()
                };
                &normalized
            }
            Ok(None) => request,
            Err(msg) => return ScriptResponse::error(&msg),
        };
        // Delegation check (D3): reject any policy path the invoking user cannot
        // access, so the sandbox never gains access the caller lacks. Runs AFTER
        // object normalization so it is evaluated against the already-tightened
        // intents. On Windows this covers directory readwrite paths (the common
        // WSLC case).
        if let Err(msg) = wxc_common::filesystem_access::check_delegation(&request.policy) {
            return ScriptResponse::error(&msg);
        }

        // Denied-path overlap validation: WSLC's flat volume-mount surface has no
        // overlay primitive, so a deniedPaths entry nested under a mounted
        // (readwrite/readonly) parent cannot be masked and would stay accessible
        // through the parent mount. Reject such configs rather than silently
        // leaving the subtree exposed. Runs after object normalization so it sees
        // the already-tightened intents.
        if let Err(msg) = policy_mapping::validate_denied_path_overlap(
            &request.policy.readwrite_paths,
            &request.policy.readonly_paths,
            &request.policy.denied_paths,
        ) {
            let _ = writeln!(logger, "[WSLC] {}", msg);
            return ScriptResponse::error(&msg);
        }

        // -- Init: COM + SDK + preflight --
        let sdk = match Self::init_and_load_sdk(logger) {
            Ok(r) => r,
            Err(e) => return e,
        };

        // -- Session (configure + create in one step to keep string data alive) --
        let session_guard = match self.create_session(&sdk, request, logger) {
            Ok(g) => g,
            Err(e) => return e,
        };

        // -- Image resolution --
        if let Err(e) = self.resolve_image(&sdk, session_guard.as_raw(), logger) {
            return e;
        }

        // -- Process settings --
        // String data (script_cstr, env_cstrings, _cwd_cstr) must stay alive
        // until after WslcCreateContainer, so this stays inline.
        let mut process_settings = std::mem::zeroed::<WslcProcessSettings>();
        let hr = (sdk.WslcInitProcessSettings)(&mut process_settings);
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
        let hr =
            (sdk.WslcSetProcessSettingsCallbacks)(&mut process_settings, &callbacks, io_ctx_raw);
        if hr != S_OK {
            return sdk_error("WslcSetProcessSettingsCallbacks failed", hr, "");
        }

        let sh = b"/bin/sh\0";
        let dash_c = b"-c\0";
        let script_cstr = format!("{}\0", request.script_code);
        let script_bytes = script_cstr.as_bytes();
        let argv: [PCSTR; 3] = [
            sh.as_ptr() as PCSTR,
            dash_c.as_ptr() as PCSTR,
            script_bytes.as_ptr() as PCSTR,
        ];
        let hr =
            (sdk.WslcSetProcessSettingsCmdLine)(&mut process_settings, argv.as_ptr(), argv.len());
        if hr != S_OK {
            return sdk_error("WslcSetProcessSettingsCmdLine failed", hr, "");
        }

        if !request.env.is_empty() {
            let env_cstrings: Vec<Vec<u8>> = request
                .env
                .iter()
                .map(|e| format!("{}\0", e).into_bytes())
                .collect();
            let env_ptrs: Vec<PCSTR> = env_cstrings.iter().map(|e| e.as_ptr() as PCSTR).collect();
            let hr = (sdk.WslcSetProcessSettingsEnvVariables)(
                &mut process_settings,
                env_ptrs.as_ptr(),
                env_ptrs.len(),
            );
            if hr != S_OK {
                return sdk_error("WslcSetProcessSettingsEnvVariables failed", hr, "");
            }
        }

        let _cwd_cstr;
        if !request.working_directory.is_empty() {
            if let Some(container_cwd) =
                policy_mapping::windows_path_to_container_path(&request.working_directory)
            {
                _cwd_cstr = format!("{}\0", container_cwd);
                let hr = (sdk.WslcSetProcessSettingsCurrentDirectory)(
                    &mut process_settings,
                    _cwd_cstr.as_bytes().as_ptr() as PCSTR,
                );
                if hr != S_OK {
                    return sdk_error("WslcSetProcessSettingsCurrentDirectory failed", hr, "");
                }
            }
        }

        // -- Container settings --
        // Volume and image string data must stay alive until WslcCreateContainer.
        let image_name = &self.config.image;
        let image_cstr = format!("{}\0", image_name);
        let mut container_settings = std::mem::zeroed::<WslcContainerSettings>();
        let hr = (sdk.WslcInitContainerSettings)(
            image_cstr.as_bytes().as_ptr() as PCSTR,
            &mut container_settings,
        );
        if hr != S_OK {
            return sdk_error("WslcInitContainerSettings failed", hr, "");
        }

        // -- Port mappings (host<->container) --
        // Apply before networking mode so the SDK has the complete picture
        // when the container is created. Empty list = no forwarding (default).
        // The parser rejects `"udp"` up front: the C header declares
        // `WSLC_PORT_PROTOCOL_UDP = 1` but the shipped runtime
        // (Microsoft.WSL.Containers 2.8.1) returns `E_NOTIMPL` when UDP is
        // actually requested. The protocol match below therefore only ever
        // sees `"tcp"` today, but the explicit branch is retained so this
        // code keeps compiling cleanly if/when the parser starts accepting
        // UDP after an SDK update.
        if !self.config.port_mappings.is_empty() {
            let mappings: Vec<WslcContainerPortMapping> = self
                .config
                .port_mappings
                .iter()
                .map(|pm| WslcContainerPortMapping {
                    windows_port: pm.windows_port,
                    container_port: pm.container_port,
                    protocol: if pm.protocol == "udp" {
                        WslcPortProtocol::Udp
                    } else {
                        WslcPortProtocol::Tcp
                    },
                    // Default bind address (typically loopback/0.0.0.0 per
                    // SDK config). Not exposed in the MXC config today.
                    windows_address: ptr::null(),
                })
                .collect();

            let hr = (sdk.WslcSetContainerSettingsPortMappings)(
                &mut container_settings,
                mappings.as_ptr(),
                mappings.len() as u32,
            );
            if hr != S_OK {
                return sdk_error("WslcSetContainerSettingsPortMappings failed", hr, "");
            }
            let _ = writeln!(
                logger,
                "[WSLC] {} port mapping(s) configured",
                mappings.len()
            );
        }
        let mounts = match policy_mapping::build_volume_mounts(
            &request.policy.readwrite_paths,
            &request.policy.readonly_paths,
        ) {
            Ok(m) => m,
            Err(e) => {
                let _ = writeln!(logger, "[WSLC] {}", e);
                return ScriptResponse::error(&e);
            }
        };

        // Keep owned data alive for volume pointers
        let wide_paths: Vec<(Vec<u16>, Vec<u8>)> = mounts
            .iter()
            .map(|m| {
                let win: Vec<u16> = to_wide(&m.windows_path);
                let ctr: Vec<u8> = format!("{}\0", m.container_path).into_bytes();
                (win, ctr)
            })
            .collect();

        if !mounts.is_empty() {
            let volumes: Vec<WslcContainerVolume> = wide_paths
                .iter()
                .zip(mounts.iter())
                .map(|((win, ctr), m)| WslcContainerVolume {
                    windows_path: win.as_ptr(),
                    container_path: ctr.as_ptr() as PCSTR,
                    read_only: if m.read_only { 1 } else { 0 },
                })
                .collect();

            let hr = (sdk.WslcSetContainerSettingsVolumes)(
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

        let is_default_block = request.policy.default_network_policy == NetworkPolicy::Block;
        let has_host_rules = policy_mapping::needs_host_filtering(
            is_default_block,
            &request.policy.allowed_hosts,
            &request.policy.blocked_hosts,
        );
        let net_mode = policy_mapping::map_network_policy(is_default_block, has_host_rules);
        let hr = (sdk.WslcSetContainerSettingsNetworkingMode)(&mut container_settings, net_mode);
        if hr != S_OK {
            return sdk_error("WslcSetContainerSettingsNetworkingMode failed", hr, "");
        }
        let _ = writeln!(logger, "[WSLC] Networking mode: {:?}", net_mode);

        let iptables_cmd = policy_mapping::build_iptables_rules(
            &request.policy.allowed_hosts,
            &request.policy.blocked_hosts,
            is_default_block,
        );

        let mut flags = WslcContainerFlags::None;
        if request.lifecycle.destroy_on_exit {
            flags = flags | WslcContainerFlags::AutoRemove;
        }
        if self.config.gpu {
            flags = flags | WslcContainerFlags::EnableGpu;
        }
        if has_host_rules {
            flags = flags | WslcContainerFlags::Privileged;
        }
        let hr = (sdk.WslcSetContainerSettingsFlags)(&mut container_settings, flags);
        if hr != S_OK {
            return sdk_error("WslcSetContainerSettingsFlags failed", hr, "");
        }

        let hr = (sdk.WslcSetContainerSettingsInitProcess)(
            &mut container_settings,
            &mut process_settings,
        );
        if hr != S_OK {
            return sdk_error("WslcSetContainerSettingsInitProcess failed", hr, "");
        }

        // -- Create & start container --
        let mut container: WslcContainer = ptr::null_mut();
        let mut err_msg = CoTaskMemPWSTR::null();
        let hr = (sdk.WslcCreateContainer)(
            session_guard.as_raw(),
            &container_settings,
            &mut container,
            err_msg.as_mut_ptr(),
        );
        if hr != S_OK {
            let msg = err_msg.to_string_lossy();
            return sdk_error("WslcCreateContainer failed", hr, &msg);
        }
        let container_guard = WslcContainerGuard::from_raw(container, sdk.WslcReleaseContainer);
        let _ = writeln!(logger, "[WSLC] Container created");

        err_msg = CoTaskMemPWSTR::null();
        let hr = (sdk.WslcStartContainer)(
            container_guard.as_raw(),
            WslcContainerStartFlags::Attach,
            err_msg.as_mut_ptr(),
        );
        if hr != S_OK {
            let msg = err_msg.to_string_lossy();
            return sdk_error("WslcStartContainer failed", hr, &msg);
        }
        let _ = writeln!(logger, "[WSLC] Container started");

        // -- Iptables (if needed) --
        if let Some(ref ipt_cmd) = iptables_cmd {
            if let Err(e) =
                Self::apply_iptables_rules(&sdk, container_guard.as_raw(), ipt_cmd, logger)
            {
                return e;
            }
        }

        // -- Get init process handle --
        let mut process: WslcProcess = ptr::null_mut();
        let hr = (sdk.WslcGetContainerInitProcess)(container_guard.as_raw(), &mut process);
        if hr != S_OK {
            return sdk_error("WslcGetContainerInitProcess failed", hr, "");
        }
        let process_guard = WslcProcessGuard::from_raw(process, sdk.WslcReleaseProcess);

        // -- Wait for exit --
        let (exit_code, timed_out) = match Self::wait_for_process(
            &sdk,
            &process_guard,
            &container_guard,
            &io_ctx,
            request,
            logger,
        ) {
            Ok(r) => r,
            Err(e) => return e,
        };

        // -- Cleanup --
        if request.lifecycle.destroy_on_exit {
            err_msg = CoTaskMemPWSTR::null();
            let _ = (sdk.WslcStopContainer)(
                container_guard.as_raw(),
                WslcSignal::SigTerm,
                10,
                err_msg.as_mut_ptr(),
            );
            drop(err_msg);

            err_msg = CoTaskMemPWSTR::null();
            let _ = (sdk.WslcDeleteContainer)(
                container_guard.as_raw(),
                WslcDeleteContainerFlags::Force,
                err_msg.as_mut_ptr(),
            );
            drop(err_msg);
        }

        // Session termination is handled by WslcSessionGuard's Drop impl.
        let _ = writeln!(logger, "[WSLC] Cleanup complete");

        let wait_ms = if request.script_timeout > 0 {
            request.script_timeout
        } else {
            u32::MAX
        };
        Self::collect_output(&io_ctx, exit_code, timed_out, wait_ms, logger)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    /// Create a temporary tar file from in-memory entries and return its path.
    fn build_test_tar(entries: &[(&str, &[u8])]) -> tempfile::NamedTempFile {
        let file = tempfile::NamedTempFile::new().unwrap();
        let mut ar = tar::Builder::new(file.as_file());
        for (path, data) in entries {
            let mut header = tar::Header::new_gnu();
            header.set_size(data.len() as u64);
            header.set_cksum();
            ar.append_data(&mut header, path, *data).unwrap();
        }
        ar.into_inner().unwrap().flush().unwrap();
        file
    }

    #[test]
    fn detect_docker_save_tar() {
        let file = build_test_tar(&[("manifest.json", b"{}")]);
        let result = WSLContainerRunner::detect_tar_format(file.path().to_str().unwrap());
        assert!(matches!(result, Ok(TarFormat::DockerSave)));
    }

    #[test]
    fn detect_docker_save_tar_with_dot_prefix() {
        let file = build_test_tar(&[("./manifest.json", b"{}")]);
        let result = WSLContainerRunner::detect_tar_format(file.path().to_str().unwrap());
        assert!(matches!(result, Ok(TarFormat::DockerSave)));
    }

    #[test]
    fn detect_rootfs_tar() {
        let file = build_test_tar(&[("bin/sh", b""), ("etc/passwd", b"")]);
        let result = WSLContainerRunner::detect_tar_format(file.path().to_str().unwrap());
        assert!(matches!(result, Ok(TarFormat::Rootfs)));
    }

    #[test]
    fn detect_rootfs_tar_with_dot_prefix() {
        let file = build_test_tar(&[("./bin/sh", b""), ("./etc/passwd", b"")]);
        let result = WSLContainerRunner::detect_tar_format(file.path().to_str().unwrap());
        assert!(matches!(result, Ok(TarFormat::Rootfs)));
    }

    #[test]
    fn detect_unknown_tar() {
        let file = build_test_tar(&[("random/file.txt", b"hello")]);
        let result = WSLContainerRunner::detect_tar_format(file.path().to_str().unwrap());
        assert!(matches!(result, Ok(TarFormat::Unknown)));
    }

    #[test]
    fn detect_empty_tar() {
        let file = build_test_tar(&[]);
        let result = WSLContainerRunner::detect_tar_format(file.path().to_str().unwrap());
        assert!(matches!(result, Ok(TarFormat::Unknown)));
    }

    #[test]
    fn nested_manifest_json_is_not_docker_save() {
        let file = build_test_tar(&[("app/manifest.json", b"{}")]);
        let result = WSLContainerRunner::detect_tar_format(file.path().to_str().unwrap());
        assert!(!matches!(result, Ok(TarFormat::DockerSave)));
    }

    #[test]
    fn docker_save_takes_priority_over_rootfs_markers() {
        let file = build_test_tar(&[
            ("bin/sh", b""),
            ("etc/passwd", b""),
            ("manifest.json", b"{}"),
        ]);
        let result = WSLContainerRunner::detect_tar_format(file.path().to_str().unwrap());
        assert!(matches!(result, Ok(TarFormat::DockerSave)));
    }

    #[test]
    fn nonexistent_file_returns_error() {
        let result = WSLContainerRunner::detect_tar_format("/nonexistent/path.tar");
        assert!(result.is_err());
    }

    #[test]
    fn run_rejects_denied_path_overlap_before_sdk_load() {
        // Wiring guard: a deniedPaths entry nested under a mounted parent must be
        // rejected at the pre-flight overlap check (run_internal, before SDK
        // load), so no container is ever started. The pure-function unit tests
        // in policy_mapping do not cover this call-site ordering. Uses
        // non-existent paths so D6 (Absent) and delegation (unknown) pass through
        // to the overlap check.
        let request = ExecutionRequest {
            containment: wxc_common::models::ContainmentBackend::Wslc,
            policy: wxc_common::models::ContainerPolicy {
                readwrite_paths: vec![r"C:\mxc-nonexistent-parent".to_string()],
                denied_paths: vec![r"C:\mxc-nonexistent-parent\secrets".to_string()],
                ..Default::default()
            },
            script_code: "echo hi".to_string(),
            ..Default::default()
        };

        let mut logger = Logger::new(wxc_common::logger::Mode::Buffer);
        let mut runner = WSLContainerRunner::new(&WslcConfig::default());
        let response = runner.execute(&request, &mut logger);

        assert_eq!(response.exit_code, -1, "overlap must fail the run");
        assert!(
            response.error_message.contains("cannot be enforced"),
            "expected the overlap error, got: {}",
            response.error_message
        );
    }
}
