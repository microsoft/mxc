// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Reusable WSLc SDK building blocks shared by the one-shot `ScriptRunner`
//! ([`crate::wsl_container_runner`]) and the state-aware daemon
//! (`wxc_wslc_daemon::session_manager`).
//!
//! # Why this module exists
//! The one-shot runner builds a `WslcProcessSettings` and a
//! `WslcContainerSettings` inline, then creates the container in a single
//! function whose stack locals keep the backing string/pointer buffers alive.
//! The WSLc SDK **stores raw pointers into those caller buffers** (it does not
//! copy them) and dereferences them at `WslcCreateContainer` /
//! `WslcCreateContainerProcess` time, so the buffers must outlive the create
//! call. In the one-shot path that "outlives" is expressed by stack scope.
//!
//! The state-aware daemon needs the *same* marshalling but across separate
//! phase calls, so the lifetime contract cannot be expressed by a single
//! function's stack. This module reifies each settings blob as a
//! **buffer-owning struct** ([`ProcessSettings`] / [`ContainerSettings`]) that
//! bundles the `Wslc*Settings` value together with every heap buffer its
//! pointers reference. Both callers hold the struct for as long as the SDK
//! needs the pointers valid.
//!
//! # Move safety
//! Every buffer a settings pointer references is heap-allocated (`Vec`, `Arc`)
//! or `'static`. Moving one of these structs copies only the owning headers —
//! the referenced heap allocations do not relocate — so the raw pointers the
//! SDK stored remain valid across a move. The one rule callers must honor:
//! **do not move the struct after handing a `&raw` (or a settings value that
//! embeds a pointer to it, e.g. an init-process settings) to the SDK.** In
//! practice the builders return the fully-populated struct by value (a single
//! move that happens *before* any `&raw` is taken), after which callers keep it
//! as a stationary local.

use std::ffi::c_void;
use std::fmt::Write;
use std::ptr;
use std::sync::{Arc, Condvar, Mutex};
use std::time::Duration;

use wxc_common::logger::Logger;
use wxc_common::models::{PortMapping, ScriptResponse};
use wxc_common::string_util::{to_wide, CoTaskMemPWSTR};

use crate::policy_mapping::{self, VolumeMount};
use crate::wsl_container_runner::{wslc_prerequisite_error, WSLContainerRunner};
use crate::wslc_bindings::*;

// ---------------------------------------------------------------------------
// Shared error helper
// ---------------------------------------------------------------------------

/// Build a `ScriptResponse` error from an HRESULT failure with an optional
/// SDK-provided message.
pub(crate) fn sdk_error(context: &str, hr: HRESULT, sdk_msg: &str) -> ScriptResponse {
    let msg = if sdk_msg.is_empty() {
        format!("{}: HRESULT 0x{:08X}", context, hr as u32)
    } else {
        format!("{}: {} (HRESULT 0x{:08X})", context, sdk_msg, hr as u32)
    };
    ScriptResponse::error(&msg)
}

// ---------------------------------------------------------------------------
// Process I/O capture plumbing
// ---------------------------------------------------------------------------

/// Shared buffer for capturing process I/O via SDK callbacks. Fields are
/// `pub(crate)` so the one-shot runner's wait/collect helpers can read the
/// captured bytes and exit signal.
pub struct IoContext {
    pub(crate) stdout: Arc<Mutex<Vec<u8>>>,
    pub(crate) stderr: Arc<Mutex<Vec<u8>>>,
    pub(crate) exited: Arc<(Mutex<bool>, Condvar)>,
}

/// Callback invoked by the WSLc SDK for stdout/stderr data.
///
/// # Safety
/// `context` must be a valid pointer obtained from `Arc::into_raw(Arc<IoContext>)`.
/// The `Arc` reference handed to the SDK is released inside [`exit_callback`]; the
/// SDK guarantees no I/O callback fires after exit, and the owning
/// [`ProcessSettings`] holds an independent reference, so the pointer stays valid
/// for every callback. The SDK guarantees `data` is valid for `data_size` bytes.
unsafe extern "C" fn io_callback(
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
        WslcProcessIOHandle::WSLC_PROCESS_IO_HANDLE_STDOUT => {
            let mut buf = ctx.stdout.lock().unwrap_or_else(|e| e.into_inner());
            buf.extend_from_slice(bytes);
        }
        WslcProcessIOHandle::WSLC_PROCESS_IO_HANDLE_STDERR => {
            let mut buf = ctx.stderr.lock().unwrap_or_else(|e| e.into_inner());
            buf.extend_from_slice(bytes);
        }
        _ => {}
    }
}

/// Callback invoked when the process exits and all I/O has been flushed.
/// Per SDK docs: "Once this callback is invoked, any registered IO callbacks
/// will no longer be called." This guarantees buffers are complete and that the
/// SDK will not touch `context` again, so this reclaims the `Arc` reference the
/// SDK was handed.
///
/// # Safety
/// `context` must be the pointer handed to `WslcSetProcessSettingsCallbacks`,
/// obtained from `Arc::into_raw(Arc<IoContext>)`, and must be invoked at most
/// once.
unsafe extern "C" fn exit_callback(_exit_code: i32, context: *mut c_void) {
    if context.is_null() {
        return;
    }
    // Reclaim the SDK's reference. The owning `ProcessSettings` holds its own
    // reference, so the `IoContext` stays alive for the waiting thread.
    let ctx = Arc::from_raw(context as *const IoContext);
    let mut exited = ctx.exited.0.lock().unwrap_or_else(|e| e.into_inner());
    *exited = true;
    ctx.exited.1.notify_all();
}

// ---------------------------------------------------------------------------
// ProcessSettings builder
// ---------------------------------------------------------------------------

/// A fully-populated `WslcProcessSettings` together with every heap buffer its
/// pointers reference (cmdline argv, env, working dir) and the I/O-capture
/// context. Safe to move (all referenced data is heap/`'static`); do not move
/// after taking `&raw`.
pub struct ProcessSettings {
    raw: WslcProcessSettings,
    io_ctx: Arc<IoContext>,
    // Reclaims the SDK's `IoContext` reference if settings build or process
    // creation fails before a live process adopts it. Disarmed by
    // `mark_process_created` once a process is created, after which
    // `exit_callback` (or a deliberate leak on kill) owns reclamation.
    sdk_io_ref: SdkIoRef,
    _sh: Vec<u8>,
    _dash_c: Vec<u8>,
    _script_cstr: Vec<u8>,
    _argv: Vec<PCSTR>,
    _env_cstrings: Vec<Vec<u8>>,
    _env_ptrs: Vec<PCSTR>,
    _cwd_cstr: Option<Vec<u8>>,
}

/// Owns an `Arc<IoContext>` reference handed to the SDK and reclaims it on drop
/// unless disarmed. Used both as a local guard while building settings and as
/// the stored owner inside [`ProcessSettings`], so any error path before a live
/// process adopts the reference frees it instead of leaking.
struct SdkIoRef(Option<*const IoContext>);

impl SdkIoRef {
    fn none() -> Self {
        Self(None)
    }

    /// Disarm reclamation, returning the raw pointer (dropped on the floor by the
    /// caller so ownership passes to `exit_callback`).
    fn disarm(&mut self) -> Option<*const IoContext> {
        self.0.take()
    }
}

impl Drop for SdkIoRef {
    fn drop(&mut self) {
        if let Some(p) = self.0.take() {
            // SAFETY: `p` came from `Arc::into_raw`. This runs only when no live
            // process ever adopted the SDK reference (settings build or process /
            // container creation failed), so the SDK will never invoke
            // `exit_callback` for it and reclaiming here is sound.
            unsafe {
                drop(Arc::from_raw(p));
            }
        }
    }
}

impl ProcessSettings {
    /// Build process settings that run `script_code` under `/bin/sh -c`, with
    /// the given `env` (already proxy-adjusted by the caller) and
    /// `working_directory` (a Windows path mapped to its container path; empty =
    /// container default). Registers stdout/stderr/exit capture callbacks.
    ///
    /// # Safety
    /// `sdk` must hold valid, currently-loaded function pointers and COM must be
    /// initialized on the calling thread.
    pub unsafe fn build(
        sdk: &WslcSdk,
        script_code: &str,
        env: &[String],
        working_directory: &str,
    ) -> Result<Self, ScriptResponse> {
        Self::build_inner(sdk, script_code, env, working_directory, true)
    }

    /// Like [`build`](Self::build) but registers no stdio callbacks and shares no
    /// `IoContext` with the SDK, for a detached init whose output is never
    /// streamed. [`io_ctx`](Self::io_ctx) is inert for the returned value.
    ///
    /// # Safety
    /// Same contract as [`build`](Self::build).
    pub unsafe fn build_detached(
        sdk: &WslcSdk,
        script_code: &str,
        env: &[String],
        working_directory: &str,
    ) -> Result<Self, ScriptResponse> {
        Self::build_inner(sdk, script_code, env, working_directory, false)
    }

    unsafe fn build_inner(
        sdk: &WslcSdk,
        script_code: &str,
        env: &[String],
        working_directory: &str,
        register_callbacks: bool,
    ) -> Result<Self, ScriptResponse> {
        let mut raw = std::mem::zeroed::<WslcProcessSettings>();
        let hr = sdk.WslcInitProcessSettings(&mut raw);
        if hr != S_OK {
            return Err(sdk_error("WslcInitProcessSettings failed", hr, ""));
        }

        let io_ctx = Arc::new(IoContext {
            stdout: Arc::new(Mutex::new(Vec::new())),
            stderr: Arc::new(Mutex::new(Vec::new())),
            exited: Arc::new((Mutex::new(false), Condvar::new())),
        });

        // Callbacks are registered only for the streamed path; a detached init
        // shares no IoContext with the SDK and mints no extra reference. The
        // SDK's reference is reclaimed inside `exit_callback`, so a process that
        // is killed without its exit callback firing deliberately leaks the
        // reference rather than freeing it while the SDK may still call back.
        // Until a process actually adopts the reference, `sdk_io_ref` guards it
        // so any early return below frees it instead of leaking.
        let mut sdk_io_ref = SdkIoRef::none();
        if register_callbacks {
            let io_ctx_raw = Arc::into_raw(Arc::clone(&io_ctx)) as *mut c_void;
            let callbacks = WslcProcessCallbacks {
                onStdOut: Some(io_callback),
                onStdErr: Some(io_callback),
                onExit: Some(exit_callback),
            };
            let hr = sdk.WslcSetProcessSettingsCallbacks(&mut raw, &callbacks, io_ctx_raw);
            if hr != S_OK {
                // The SDK never took ownership; reclaim the reference now.
                drop(Arc::from_raw(io_ctx_raw as *const IoContext));
                return Err(sdk_error("WslcSetProcessSettingsCallbacks failed", hr, ""));
            }
            sdk_io_ref = SdkIoRef(Some(io_ctx_raw as *const IoContext));
        }

        // Command line: /bin/sh -c <script>. argv points into the sh/dash_c/
        // script heaps; all are owned by the returned struct.
        let sh = b"/bin/sh\0".to_vec();
        let dash_c = b"-c\0".to_vec();
        let script_cstr = format!("{}\0", script_code).into_bytes();
        let argv: Vec<PCSTR> = vec![
            sh.as_ptr() as PCSTR,
            dash_c.as_ptr() as PCSTR,
            script_cstr.as_ptr() as PCSTR,
        ];
        let hr = sdk.WslcSetProcessSettingsCmdLine(&mut raw, argv.as_ptr(), argv.len());
        if hr != S_OK {
            return Err(sdk_error("WslcSetProcessSettingsCmdLine failed", hr, ""));
        }

        // Environment variables (only when non-empty, matching the one-shot
        // path). env_ptrs point into env_cstrings; both are owned below.
        let mut env_cstrings: Vec<Vec<u8>> = Vec::new();
        let mut env_ptrs: Vec<PCSTR> = Vec::new();
        if !env.is_empty() {
            env_cstrings = env
                .iter()
                .map(|e| format!("{}\0", e).into_bytes())
                .collect();
            env_ptrs = env_cstrings.iter().map(|e| e.as_ptr() as PCSTR).collect();
            let hr =
                sdk.WslcSetProcessSettingsEnvVariables(&mut raw, env_ptrs.as_ptr(), env_ptrs.len());
            if hr != S_OK {
                return Err(sdk_error(
                    "WslcSetProcessSettingsEnvVariables failed",
                    hr,
                    "",
                ));
            }
        }

        // Working directory (mapped Windows -> container path; skip if unmapped).
        let mut cwd_cstr: Option<Vec<u8>> = None;
        if !working_directory.is_empty() {
            if let Some(container_cwd) =
                policy_mapping::windows_path_to_container_path(working_directory)
            {
                let c = format!("{}\0", container_cwd).into_bytes();
                let hr = sdk.WslcSetProcessSettingsWorkingDirectory(&mut raw, c.as_ptr() as PCSTR);
                if hr != S_OK {
                    return Err(sdk_error(
                        "WslcSetProcessSettingsWorkingDirectory failed",
                        hr,
                        "",
                    ));
                }
                cwd_cstr = Some(c);
            }
        }

        Ok(ProcessSettings {
            raw,
            io_ctx,
            sdk_io_ref,
            _sh: sh,
            _dash_c: dash_c,
            _script_cstr: script_cstr,
            _argv: argv,
            _env_cstrings: env_cstrings,
            _env_ptrs: env_ptrs,
            _cwd_cstr: cwd_cstr,
        })
    }

    /// Transfer ownership of the SDK's `IoContext` reference to the newly-created
    /// process. After this, `Drop` will not reclaim it — `exit_callback` (or a
    /// deliberate leak on kill) owns reclamation, preserving the invariant that
    /// the reference is never freed while the SDK may still call back.
    ///
    /// # Safety
    /// Call exactly once, immediately after a process has been successfully
    /// created from these settings (`WslcCreateContainerProcess`, or
    /// `WslcCreateContainer` + `WslcStartContainer` when used as a container
    /// init). Skipping this after a successful create would let `Drop` free a
    /// reference the SDK still owns.
    pub unsafe fn mark_process_created(&mut self) {
        let _ = self.sdk_io_ref.disarm();
    }

    /// The I/O-capture context shared with the SDK callbacks.
    pub fn io_ctx(&self) -> &IoContext {
        &self.io_ctx
    }

    /// Mutable raw settings pointer for `WslcSetContainerSettingsInitProcess` /
    /// `WslcCreateContainerProcess`. Do not move `self` after calling this.
    pub fn raw_mut(&mut self) -> &mut WslcProcessSettings {
        &mut self.raw
    }
}

// ---------------------------------------------------------------------------
// ContainerSettings builder
// ---------------------------------------------------------------------------

/// A fully-populated `WslcContainerSettings` together with every heap buffer its
/// pointers reference (image name, volume paths, port mappings). The init
/// process is intentionally NOT set here — that is caller-specific (the one-shot
/// path bakes the script as init; the daemon uses a keepalive init) and is
/// applied by the caller before `WslcCreateContainer`.
pub struct ContainerSettings {
    raw: WslcContainerSettings,
    _image_cstr: Vec<u8>,
    _wide_paths: Vec<(Vec<u16>, Vec<u8>)>,
    _volumes: Vec<WslcContainerVolume>,
    _port_mappings: Vec<WslcContainerPortMapping>,
}

impl ContainerSettings {
    /// Build container settings for `image` with the given volume `mounts`,
    /// `port_mappings`, networking `net_mode`, and container `flags`. The caller
    /// computes `net_mode`/`flags`/`mounts` from policy (identical to the
    /// one-shot path) and applies the init process afterward.
    ///
    /// # Safety
    /// `sdk` must hold valid, currently-loaded function pointers.
    pub unsafe fn build(
        sdk: &WslcSdk,
        image: &str,
        mounts: &[VolumeMount],
        port_mappings: &[PortMapping],
        net_mode: WslcContainerNetworkingMode,
        flags: WslcContainerFlags,
        logger: &mut Logger,
    ) -> Result<Self, ScriptResponse> {
        let image_cstr = format!("{}\0", image).into_bytes();
        let mut raw = std::mem::zeroed::<WslcContainerSettings>();
        let hr = sdk.WslcInitContainerSettings(image_cstr.as_ptr() as PCSTR, &mut raw);
        if hr != S_OK {
            return Err(sdk_error("WslcInitContainerSettings failed", hr, ""));
        }

        // Port mappings (host<->container). Empty list = no forwarding. The
        // parser rejects UDP up front today; the explicit branch is retained so
        // this keeps compiling if UDP is enabled after an SDK update.
        let mut port_vec: Vec<WslcContainerPortMapping> = Vec::new();
        if !port_mappings.is_empty() {
            port_vec = port_mappings
                .iter()
                .map(|pm| WslcContainerPortMapping {
                    windowsPort: pm.windows_port,
                    containerPort: pm.container_port,
                    protocol: if pm.protocol == "udp" {
                        WslcPortProtocol::WSLC_PORT_PROTOCOL_UDP
                    } else {
                        WslcPortProtocol::WSLC_PORT_PROTOCOL_TCP
                    },
                    windowsAddress: ptr::null_mut(),
                })
                .collect();

            let hr = sdk.WslcSetContainerSettingsPortMappings(
                &mut raw,
                port_vec.as_ptr(),
                port_vec.len() as u32,
            );
            if hr != S_OK {
                return Err(sdk_error(
                    "WslcSetContainerSettingsPortMappings failed",
                    hr,
                    "",
                ));
            }
            let _ = writeln!(
                logger,
                "[WSLC] {} port mapping(s) configured",
                port_vec.len()
            );
        }

        // Volume mounts. wide_paths owns the widened Windows paths + NUL-
        // terminated container paths the volume pointers reference.
        let wide_paths: Vec<(Vec<u16>, Vec<u8>)> = mounts
            .iter()
            .map(|m| {
                let win: Vec<u16> = to_wide(&m.windows_path);
                let ctr: Vec<u8> = format!("{}\0", m.container_path).into_bytes();
                (win, ctr)
            })
            .collect();

        let mut volumes: Vec<WslcContainerVolume> = Vec::new();
        if !mounts.is_empty() {
            volumes = wide_paths
                .iter()
                .zip(mounts.iter())
                .map(|((win, ctr), m)| WslcContainerVolume {
                    windowsPath: win.as_ptr(),
                    containerPath: ctr.as_ptr() as PCSTR,
                    readOnly: if m.read_only { 1 } else { 0 },
                })
                .collect();

            let hr = sdk.WslcSetContainerSettingsVolumes(
                &mut raw,
                volumes.as_ptr(),
                volumes.len() as u32,
            );
            if hr != S_OK {
                return Err(sdk_error("WslcSetContainerSettingsVolumes failed", hr, ""));
            }
            let _ = writeln!(
                logger,
                "[WSLC] {} volume mount(s) configured",
                volumes.len()
            );
        }

        let hr = sdk.WslcSetContainerSettingsNetworkingMode(&mut raw, net_mode);
        if hr != S_OK {
            return Err(sdk_error(
                "WslcSetContainerSettingsNetworkingMode failed",
                hr,
                "",
            ));
        }
        let _ = writeln!(logger, "[WSLC] Networking mode: {:?}", net_mode);

        let hr = sdk.WslcSetContainerSettingsFlags(&mut raw, flags);
        if hr != S_OK {
            return Err(sdk_error("WslcSetContainerSettingsFlags failed", hr, ""));
        }

        Ok(ContainerSettings {
            raw,
            _image_cstr: image_cstr,
            _wide_paths: wide_paths,
            _volumes: volumes,
            _port_mappings: port_vec,
        })
    }

    /// Mutable raw settings for `WslcSetContainerSettingsInitProcess`.
    /// Do not move `self` after calling this.
    pub fn raw_mut(&mut self) -> &mut WslcContainerSettings {
        &mut self.raw
    }

    /// Shared raw settings for `WslcCreateContainer`.
    pub fn raw(&self) -> &WslcContainerSettings {
        &self.raw
    }
}

// ---------------------------------------------------------------------------
// State-aware daemon steps
// ---------------------------------------------------------------------------
//
// The one-shot runner expresses each phase (session → image → container →
// process → wait) as stack scope inside `run_internal`. The state-aware daemon
// (`wxc_wslc_daemon::session_manager`) drives the *same* SDK sequence but across
// separate provision/start/exec/stop/deprovision calls, so each step is reified
// as a standalone `pub unsafe fn` here. These wrappers keep every raw
// [`IoContext`] / SDK-buffer access inside `wslc_common` (the daemon is a
// separate crate and only holds the returned RAII guards + `WslcSdk`).
//
// COM affinity: unlike the one-shot path these do NOT call `CoInitializeEx` —
// the daemon worker thread joins the MTA for its whole lifetime before invoking
// any of them.

/// Long-lived container init command for daemon-owned containers. Unlike the
/// one-shot path (which bakes the caller's script as PID 1), the daemon needs an
/// init process that keeps the container alive across repeated `exec` calls.
/// `while true; do sleep 86400; done` is portable across busybox (`alpine`) and
/// coreutils (`mariner`/`fedora`/`python`) shells.
pub const KEEPALIVE_SCRIPT: &str = "while true; do sleep 86400; done";

/// Load the WSLc SDK and verify its runtime prerequisites, WITHOUT initialising
/// COM (the caller — the daemon worker thread — is already in the MTA).
///
/// # Safety
/// COM must already be initialised on the calling thread and the SDK DLL must be
/// resolvable. The returned [`WslcSdk`] holds raw function pointers; keep it
/// alive for the duration of all SDK use.
pub unsafe fn load_sdk_checked(logger: &mut Logger) -> Result<WslcSdk, ScriptResponse> {
    let sdk = WslcSdk::load().map_err(|e| ScriptResponse::error(&e))?;

    let mut missing = WslcComponentFlags::WSLC_COMPONENT_FLAG_NONE;
    let hr = sdk.WslcGetMissingComponents(&mut missing);
    if hr != S_OK {
        return Err(sdk_error("WslcGetMissingComponents failed", hr, ""));
    }
    if missing.any_missing() {
        return Err(ScriptResponse::error(&wslc_prerequisite_error(missing)));
    }
    let _ = writeln!(logger, "[WSLC][daemon] Runtime check passed");
    Ok(sdk)
}

/// Create the shared daemon session (the WSL2 utility VM). Minimal by design —
/// no per-request cpu/memory/timeout/gpu tuning (those are one-shot `WslcConfig`
/// knobs; the daemon amortises a single session across sandboxes).
///
/// # Safety
/// `sdk` must hold valid function pointers and COM must be initialised on this
/// thread.
pub unsafe fn create_daemon_session(
    sdk: &WslcSdk,
    session_name: &str,
    storage_path: &str,
    logger: &mut Logger,
) -> Result<WslcSessionGuard, ScriptResponse> {
    // Both wide buffers must outlive `WslcCreateSession` (the SDK stores pointers
    // into them at `WslcInitSessionSettings` time); they are function locals held
    // through the create call below.
    let name_wide: Vec<u16> = to_wide(session_name);
    let storage_wide: Vec<u16> = to_wide(storage_path);

    let mut settings = std::mem::zeroed::<WslcSessionSettings>();
    let hr = sdk.WslcInitSessionSettings(name_wide.as_ptr(), storage_wide.as_ptr(), &mut settings);
    if hr != S_OK {
        return Err(sdk_error("WslcInitSessionSettings failed", hr, ""));
    }

    let mut session: WslcSession = ptr::null_mut();
    let mut err_msg = CoTaskMemPWSTR::null();
    let hr = sdk.WslcCreateSession(&mut settings, &mut session, err_msg.as_mut_ptr());
    if hr != S_OK {
        let msg = err_msg.to_string_lossy();
        return Err(sdk_error("WslcCreateSession failed", hr, &msg));
    }
    let _ = writeln!(logger, "[WSLC][daemon] Session created");

    Ok(WslcSessionGuard::from_raw(
        session,
        sdk.terminate_session_fn(),
        sdk.release_session_fn(),
    ))
}

/// Ensure `image` is available in the session's local cache: use it if already
/// present, import it from `image_tar_path` if provided, otherwise fail with the
/// same pre-pull guidance as the one-shot path (MXC never pulls at run time).
///
/// # Safety
/// `sdk` must hold valid function pointers and `session` must be a live handle.
pub unsafe fn resolve_image(
    sdk: &WslcSdk,
    session: WslcSession,
    image: &str,
    image_tar_path: Option<&str>,
    storage_path: Option<&str>,
    logger: &mut Logger,
) -> Result<(), ScriptResponse> {
    let mut images: *mut WslcImageInfo = ptr::null_mut();
    let mut image_count: u32 = 0;
    let hr = sdk.WslcListSessionImages(session, &mut images, &mut image_count);
    if hr != S_OK {
        return Err(sdk_error("WslcListSessionImages failed", hr, ""));
    }

    let mut image_found = false;
    if !images.is_null() {
        let images_slice = std::slice::from_raw_parts(images, image_count as usize);
        for info in images_slice {
            let name_bytes =
                std::slice::from_raw_parts(info.name.as_ptr().cast::<u8>(), info.name.len());
            let end = name_bytes
                .iter()
                .position(|&b| b == 0)
                .unwrap_or(name_bytes.len());
            if let Ok(name) = std::str::from_utf8(&name_bytes[..end]) {
                if name == image {
                    image_found = true;
                    break;
                }
            }
        }
        windows::Win32::System::Com::CoTaskMemFree(Some(images as *const c_void));
    }

    if image_found {
        if image_tar_path.is_some() {
            let _ = writeln!(
                logger,
                "[WSLC][daemon] Image '{}' already cached, skipping tar import",
                image
            );
        } else {
            let _ = writeln!(logger, "[WSLC][daemon] Image '{}' found", image);
        }
        return Ok(());
    }

    if let Some(tar_path) = image_tar_path {
        return WSLContainerRunner::import_image_from_tar(sdk, session, image, tar_path, logger);
    }

    // MXC is an execution layer; image management is out of band. Mirror the
    // one-shot runner's pre-pull guidance so operators get the same actionable
    // command.
    let (storage_arg_wxc, storage_arg_ps) = match storage_path {
        Some(sp) => (
            format!(" --storage-path \"{}\"", sp),
            format!(" -StoragePath \"{}\"", sp),
        ),
        None => (String::new(), String::new()),
    };
    Err(ScriptResponse::error(&format!(
        "WSLC image '{}' not found locally. Pre-pull it with: \
         wxc-exec.exe --setup-wslc --image {}{} \
         (or scripts\\setup-wslc.ps1 -Image {}{}). \
         MXC does not pull images at run time; \
         see docs/wsl/wsl-container-support-plan.md.",
        image, image, storage_arg_wxc, image, storage_arg_ps,
    )))
}

/// Create a daemon-owned container with `keepalive` as its init process, so it
/// stays alive across repeated `exec` calls. The caller keeps `keepalive`
/// stationary until this returns (the SDK reads its buffers at
/// `WslcCreateContainer` time).
///
/// # Safety
/// `sdk` must hold valid function pointers and `session` must be a live handle.
pub unsafe fn create_daemon_container(
    sdk: &WslcSdk,
    session: WslcSession,
    image: &str,
    mounts: &[VolumeMount],
    net_mode: WslcContainerNetworkingMode,
    keepalive: &mut ProcessSettings,
    logger: &mut Logger,
) -> Result<WslcContainerGuard, ScriptResponse> {
    // Daemon containers never forward ports (no state-aware port-mapping config)
    // and set no container flags (auto-remove/gpu/privileged are one-shot-only).
    let mut container_settings = ContainerSettings::build(
        sdk,
        image,
        mounts,
        &[],
        net_mode,
        WslcContainerFlags::WSLC_CONTAINER_FLAG_NONE,
        logger,
    )?;

    let hr =
        sdk.WslcSetContainerSettingsInitProcess(container_settings.raw_mut(), keepalive.raw_mut());
    if hr != S_OK {
        return Err(sdk_error(
            "WslcSetContainerSettingsInitProcess failed",
            hr,
            "",
        ));
    }

    let mut container: WslcContainer = ptr::null_mut();
    let mut err_msg = CoTaskMemPWSTR::null();
    let hr = sdk.WslcCreateContainer(
        session,
        container_settings.raw(),
        &mut container,
        err_msg.as_mut_ptr(),
    );
    if hr != S_OK {
        let msg = err_msg.to_string_lossy();
        return Err(sdk_error("WslcCreateContainer failed", hr, &msg));
    }
    let _ = writeln!(logger, "[WSLC][daemon] Container created");

    Ok(WslcContainerGuard::from_raw(
        container,
        sdk.release_container_fn(),
    ))
}

/// Boot a created daemon container. Uses `START_FLAG_NONE` (not `ATTACH`): the
/// keepalive init's stdio is never streamed — per-`exec` processes carry the
/// user-visible I/O.
///
/// # Safety
/// `sdk` must hold valid function pointers and `container` must be a live handle.
pub unsafe fn start_daemon_container(
    sdk: &WslcSdk,
    container: WslcContainer,
    logger: &mut Logger,
) -> Result<(), ScriptResponse> {
    let mut err_msg = CoTaskMemPWSTR::null();
    let hr = sdk.WslcStartContainer(
        container,
        WslcContainerStartFlags::WSLC_CONTAINER_START_FLAG_NONE,
        err_msg.as_mut_ptr(),
    );
    if hr != S_OK {
        let msg = err_msg.to_string_lossy();
        return Err(sdk_error("WslcStartContainer failed", hr, &msg));
    }
    let _ = writeln!(logger, "[WSLC][daemon] Container started");
    Ok(())
}

/// Captured result of a daemon `exec`. Live bidirectional streaming is a later
/// fill-in; for now the whole stdout/stderr is captured and the exit code
/// returned once the process completes.
pub struct ExecOutcome {
    pub exit_code: i32,
    pub timed_out: bool,
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
}

/// Run `script_code` (under `/bin/sh -c`) as a fresh process inside a started
/// daemon container and wait for it to complete. On timeout the *process* is
/// killed (SIGKILL) — NOT the container — so the keepalive init survives for
/// subsequent execs.
///
/// # Safety
/// `sdk` must hold valid function pointers and `container` must be a live,
/// started handle.
pub unsafe fn exec_in_container(
    sdk: &WslcSdk,
    container: WslcContainer,
    script_code: &str,
    env: &[String],
    working_directory: &str,
    timeout_ms: u32,
    logger: &mut Logger,
) -> Result<ExecOutcome, ScriptResponse> {
    // `process_settings` owns every buffer the SDK reads at
    // `WslcCreateContainerProcess` time plus the I/O-capture context; it is held
    // as a stationary local until after the process exits below.
    let mut process_settings = ProcessSettings::build(sdk, script_code, env, working_directory)?;

    let mut process: WslcProcess = ptr::null_mut();
    let mut err_msg = CoTaskMemPWSTR::null();
    let hr = sdk.WslcCreateContainerProcess(
        container,
        process_settings.raw_mut(),
        &mut process,
        err_msg.as_mut_ptr(),
    );
    if hr != S_OK {
        let msg = err_msg.to_string_lossy();
        return Err(sdk_error("WslcCreateContainerProcess failed", hr, &msg));
    }
    let process_guard = WslcProcessGuard::from_raw(process, sdk.release_process_fn());
    // The process now owns the SDK's IoContext reference; `exit_callback` will
    // reclaim it. Disarm the settings guard so it is not freed underneath the SDK.
    process_settings.mark_process_created();

    let mut exit_event: HANDLE = ptr::null_mut();
    let hr = sdk.WslcGetProcessExitEvent(process_guard.as_raw(), &mut exit_event);
    if hr != S_OK {
        return Err(sdk_error("WslcGetProcessExitEvent failed", hr, ""));
    }

    let wait_ms = if timeout_ms > 0 { timeout_ms } else { u32::MAX };
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
                "[WSLC][daemon] exec timeout ({}ms) reached — killing process",
                wait_ms
            );
            // Kill only this process; the keepalive init keeps the container up.
            let kill_hr =
                sdk.WslcSignalProcess(process_guard.as_raw(), WslcSignal::WSLC_SIGNAL_SIGKILL);
            if kill_hr != S_OK {
                let _ = writeln!(
                    logger,
                    "[WSLC][daemon] Warning: WslcSignalProcess(SIGKILL) failed (hr={kill_hr:?}); process may still be running"
                );
            }
        }
    }

    // Wait for the exit callback to fire — guarantees all I/O is flushed.
    {
        let (lock, cvar) = &*process_settings.io_ctx().exited;
        let mut exited = lock.lock().unwrap_or_else(|e| e.into_inner());
        if !*exited {
            let result = cvar
                .wait_timeout(exited, Duration::from_secs(30))
                .unwrap_or_else(|e| e.into_inner());
            exited = result.0;
            if !*exited {
                let _ = writeln!(
                    logger,
                    "[WSLC][daemon] Warning: exit callback did not fire within 30s"
                );
            }
        }
        drop(exited);
    }

    let mut exit_code: i32 = -1;
    let hr = sdk.WslcGetProcessExitCode(process_guard.as_raw(), &mut exit_code);
    if hr != S_OK && !timed_out {
        return Err(sdk_error("WslcGetProcessExitCode failed", hr, ""));
    }

    let stdout = process_settings
        .io_ctx()
        .stdout
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .clone();
    let stderr = process_settings
        .io_ctx()
        .stderr
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .clone();

    if timed_out {
        let _ = writeln!(logger, "[WSLC][daemon] Process killed after timeout");
    } else {
        let _ = writeln!(
            logger,
            "[WSLC][daemon] Process exited with code {}",
            exit_code
        );
    }

    Ok(ExecOutcome {
        exit_code: if timed_out { -1 } else { exit_code },
        timed_out,
        stdout,
        stderr,
    })
}

/// Stop a running daemon container (SIGTERM), keeping it created for a later
/// `start`.
///
/// # Safety
/// `sdk` must hold valid function pointers and `container` must be a live handle.
pub unsafe fn stop_daemon_container(
    sdk: &WslcSdk,
    container: WslcContainer,
    logger: &mut Logger,
) -> Result<(), ScriptResponse> {
    let mut err_msg = CoTaskMemPWSTR::null();
    let hr = sdk.WslcStopContainer(
        container,
        WslcSignal::WSLC_SIGNAL_SIGTERM,
        10,
        err_msg.as_mut_ptr(),
    );
    if hr != S_OK {
        let msg = err_msg.to_string_lossy();
        return Err(sdk_error("WslcStopContainer failed", hr, &msg));
    }
    let _ = writeln!(logger, "[WSLC][daemon] Container stopped");
    Ok(())
}

/// Delete a daemon container (forcefully).
///
/// # Safety
/// `sdk` must hold valid function pointers and `container` must be a live handle.
pub unsafe fn delete_daemon_container(
    sdk: &WslcSdk,
    container: WslcContainer,
    logger: &mut Logger,
) -> Result<(), ScriptResponse> {
    let mut err_msg = CoTaskMemPWSTR::null();
    let hr = sdk.WslcDeleteContainer(
        container,
        WslcDeleteContainerFlags::WSLC_DELETE_CONTAINER_FLAG_FORCE,
        err_msg.as_mut_ptr(),
    );
    if hr != S_OK {
        let msg = err_msg.to_string_lossy();
        return Err(sdk_error("WslcDeleteContainer failed", hr, &msg));
    }
    let _ = writeln!(logger, "[WSLC][daemon] Container deleted");
    Ok(())
}
