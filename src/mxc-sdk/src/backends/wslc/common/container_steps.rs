// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Reusable WSLc SDK building blocks shared by the one-shot `ScriptRunner`
//! ([`crate::wslc_common::wsl_container_runner`]) and the state-aware daemon
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
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::time::{Duration, Instant};

use crate::mxc_common::logger::Logger;
use crate::mxc_common::models::{PortMapping, ScriptResponse};
use crate::mxc_common::string_util::{to_wide, CoTaskMemPWSTR};

use crate::wslc_common::daemon_protocol::ExecTerminal;

use crate::wslc_common::error::WslcError;
use crate::wslc_common::policy_mapping::VolumeMount;
use crate::wslc_common::process_env::{self, EnvScope};
use crate::wslc_common::sdk_init;
use crate::wslc_common::wslc_bindings::*;

// ---------------------------------------------------------------------------
// Shared error helper
// ---------------------------------------------------------------------------

/// `ERROR_SHARING_VIOLATION`, which the SDK reports when a call reaches a store
/// whose VHDX another live session already has mounted.
const E_SHARING_VIOLATION: HRESULT = 0x8007_0020_u32 as HRESULT;

/// VM/session boot budget, in milliseconds.
///
/// Deliberately independent of any per-command runtime deadline, so a short
/// command timeout cannot abort a cold VM boot.
pub const SESSION_BOOT_TIMEOUT_MS: u32 = 180_000;

/// How a session's WSL2 utility VM is sized.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct SessionSizing {
    /// Virtual CPUs, or `None` for the host default.
    pub cpu_count: Option<u32>,

    /// Memory in MB, or `None` for the host default.
    pub memory_mb: Option<u64>,

    /// Whether to enable GPU passthrough.
    pub gpu: bool,
}

/// What the host has installed, rather than what is currently free.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HostCapacity {
    /// Physical memory installed, in MB.
    pub total_memory_mb: u64,

    /// Logical processors the machine has.
    pub logical_cpus: u32,
}

/// Read what this host has installed.
fn host_capacity() -> Option<HostCapacity> {
    use windows::Win32::System::SystemInformation::{GlobalMemoryStatusEx, MEMORYSTATUSEX};
    use windows::Win32::System::Threading::{GetActiveProcessorCount, ALL_PROCESSOR_GROUPS};

    let mut status = MEMORYSTATUSEX {
        dwLength: std::mem::size_of::<MEMORYSTATUSEX>() as u32,
        ..Default::default()
    };

    // SAFETY: `status` is a valid `MEMORYSTATUSEX` whose `dwLength` is set, as
    // the API requires.
    unsafe { GlobalMemoryStatusEx(&mut status) }.ok()?;

    // Every processor group, not just the caller's: `GetSystemInfo` reports one
    // group and caps at 64, so a host with more would refuse a size it can run.
    // A job object narrowing what mxc may run on does not narrow what the
    // hypervisor can give a VM either.
    let logical_cpus = unsafe { GetActiveProcessorCount(ALL_PROCESSOR_GROUPS) };

    Some(HostCapacity {
        total_memory_mb: status.ullTotalPhys / (1024 * 1024),
        logical_cpus,
    })
}

/// Reject a session asking for more processors than the host has.
///
/// `memory_mb` is deliberately not checked: it is a ceiling the host backs on
/// demand, so asking for more memory than is installed works.
fn sizing_fits_host(sizing: SessionSizing, host: HostCapacity) -> Result<(), ScriptResponse> {
    // The SDK reads `0` as "use the default" rather than as a size.
    let Some(cpu_count) = sizing.cpu_count.filter(|cpus| *cpus > 0) else {
        return Ok(());
    };

    if cpu_count > host.logical_cpus {
        return Err(WslcError::Rejected(format!(
            "cpu_count {cpu_count} exceeds the {} logical processors this host has; \
             WSLc does not oversubscribe processors, though memory_mb may exceed \
             installed memory because it is a ceiling rather than a reservation",
            host.logical_cpus
        ))
        .into_response());
    }

    Ok(())
}

/// Reject a session sized past this host, when the host can be measured.
///
/// A host that cannot be measured is allowed through, since refusing real work
/// over a failed diagnostic call would be the worse failure.
pub fn check_sizing_against_host(sizing: SessionSizing) -> Result<(), ScriptResponse> {
    match host_capacity() {
        Some(host) => sizing_fits_host(sizing, host),
        None => Ok(()),
    }
}

/// Build a `ScriptResponse` error from an HRESULT failure with an optional
/// SDK-provided message. Thin wrapper over [`WslcError::Sdk`], which owns the
/// message formatting and the `LaunchFailed` phase attribution.
pub(crate) fn sdk_error(context: &str, hr: HRESULT, sdk_msg: &str) -> ScriptResponse {
    WslcError::sdk(context, hr, sdk_msg).into_response()
}

/// NUL-terminate `value` for a C string the WSLc SDK will read, rejecting an
/// interior NUL instead of letting the SDK silently observe a truncated value.
///
/// The daemon protocol accepts arbitrary JSON strings, so a command, env entry,
/// image, or container path can contain `\u{0}`. Rust keeps such a string whole,
/// but the SDK stops at the first NUL — so validation/logging and execution
/// would disagree about what actually ran. Reject at the marshalling boundary.
pub(crate) fn cstr_bytes(field: &str, value: &str) -> Result<Vec<u8>, ScriptResponse> {
    std::ffi::CString::new(value)
        .map(|c| c.into_bytes_with_nul())
        .map_err(|_| {
            WslcError::Rejected(format!(
                "{field} contains an interior NUL byte, which is not a valid C string"
            ))
            .into_response()
        })
}

// ---------------------------------------------------------------------------
// Process I/O capture plumbing
// ---------------------------------------------------------------------------
//
// # IoContext reference lifecycle (why a kill deliberately leaks)
//
// The SDK's stdout/stderr/exit callbacks each receive a raw `*IoContext`. We
// hand the SDK one `Arc<IoContext>` reference (`Arc::into_raw`) and keep an
// independent `Arc` inside `ProcessSettings`, so the context outlives every
// callback. Reclaiming the SDK's reference safely hinges on exactly one rule:
// **it is freed only from `exit_callback`, and the SDK guarantees no callback
// fires after exit.** That yields three reachable end-states:
//
//   build settings ──fail before create──▶ SdkIoRef::drop frees the ref
//        │                                  (no process exists to call back)
//        ▼
//   process created ──▶ mark_process_created() disarms SdkIoRef
//        │
//        ├── process exits ──▶ exit_callback fires ──▶ frees the SDK ref
//        │
//        └── process killed, exit_callback never fires ──▶ ref is LEAKED
//            on purpose: freeing it while the SDK might still call back would
//            be use-after-free. A confirmed-unkillable container is quarantined
//            (see `exec_in_container` / session_manager), bounding the leak to
//            that one compromised sandbox.
//
// So `SdkIoRef` guards the pre-adoption window (frees on early failure), and
// after adoption ownership passes to `exit_callback`; the kill path trades a
// bounded, one-time leak for memory safety.

/// Which standard stream a live-output chunk came from.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OutStream {
    Stdout,
    Stderr,
}

/// Optional live-output sink that replaces the capped capture buffers, so a
/// caller that sets one gets empty captured stdout/stderr.
///
/// **Two distinct live-output architectures — why they don't share plumbing.**
/// The one-shot runner streams via `OutputMode::Stream` (in `wsl_container_runner`)
/// plus a synchronous in-process `stream_pair`/`StreamReader` (in `stream_buffer`),
/// drained in the same process (caller pipes, or an `inherit_pump` thread). The
/// daemon cannot reuse that: it must relay output across a named pipe to a
/// *separate* client process through an async (tokio) control server, so it
/// bridges the synchronous SDK callback thread to the async pipe writer with a
/// bounded mpsc channel (see `session_manager::enqueue_output`). Their
/// backpressure invariants also differ deliberately: the one-shot `StreamReader`
/// is drained synchronously in-process, whereas this callback **must never
/// block** — the same SDK thread also delivers the process-exit callback, so the
/// daemon path uses a non-blocking `try_send` that drops on overflow rather than
/// stalling teardown. Keep the two paths separate for those reasons; share only
/// the leaf primitives ([`OutStream`], [`IoContext`]).
pub type OutputSink = Box<dyn Fn(OutStream, &[u8]) + Send + Sync>;

/// Shared buffer for capturing process I/O via SDK callbacks. Fields are
/// `pub(crate)` so the one-shot runner's wait/collect helpers can read the
/// captured bytes and exit signal.
pub struct IoContext {
    pub(crate) stdout: Arc<Mutex<Vec<u8>>>,
    pub(crate) stderr: Arc<Mutex<Vec<u8>>>,
    pub(crate) exited: Arc<(Mutex<bool>, Condvar)>,
    /// Live sink for streaming output; `None` when the caller wants the final
    /// captured blob instead. A streaming caller reads its bytes from the sink
    /// as they arrive, so the capture buffers stay empty. Its owning
    /// `Arc<IoContext>` is released on the same schedule as those buffers, so
    /// on the deliberate kill-path leak the sink (and its sender) is leaked too.
    sink: Option<OutputSink>,
}

/// Per-stream cap on captured stdout/stderr, in bytes. The WSLc SDK streams
/// output from untrusted in-container code straight into these buffers; without
/// a ceiling one exec could grow them without bound and OOM the persistent
/// daemon, taking down every sandbox it owns. When a stream reaches the cap the
/// tail is dropped and a one-time truncation marker is appended.
const MAX_CAPTURED_STREAM_BYTES: usize = 8 * 1024 * 1024;

/// Appended once to a captured stream when it first hits the cap, so a consumer
/// can tell the output was truncated rather than genuinely ending there.
const STREAM_TRUNCATION_MARKER: &[u8] = b"\n[output truncated: stream exceeded capture cap]\n";

/// Append `bytes` to a captured stream buffer, enforcing
/// [`MAX_CAPTURED_STREAM_BYTES`]. Once the cap is reached the buffer stops
/// growing; the marker is appended exactly once, on the call that crosses it.
fn append_capped(buf: &mut Vec<u8>, bytes: &[u8]) {
    if buf.len() >= MAX_CAPTURED_STREAM_BYTES {
        return;
    }
    let remaining = MAX_CAPTURED_STREAM_BYTES - buf.len();
    if bytes.len() <= remaining {
        buf.extend_from_slice(bytes);
    } else {
        buf.extend_from_slice(&bytes[..remaining]);
        buf.extend_from_slice(STREAM_TRUNCATION_MARKER);
    }
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
        WslcProcessIOHandle::WSLC_PROCESS_IO_HANDLE_STDOUT => match ctx.sink.as_ref() {
            Some(sink) => sink(OutStream::Stdout, bytes),
            None => {
                let mut buf = ctx.stdout.lock().unwrap_or_else(|e| e.into_inner());
                append_capped(&mut buf, bytes);
            }
        },
        WslcProcessIOHandle::WSLC_PROCESS_IO_HANDLE_STDERR => match ctx.sink.as_ref() {
            Some(sink) => sink(OutStream::Stderr, bytes),
            None => {
                let mut buf = ctx.stderr.lock().unwrap_or_else(|e| e.into_inner());
                append_capped(&mut buf, bytes);
            }
        },
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

/// The command-line and environment buffers the SDK stored pointers into.
///
/// The SDK does not copy them, so this must outlive the create call that reads
/// them.
pub(crate) struct CommandLineBuffers {
    _argv_cstrings: Vec<Vec<u8>>,
    _argv: Vec<PCSTR>,
    _env_cstrings: Vec<Vec<u8>>,
    _env_ptrs: Vec<PCSTR>,
}

/// Set `settings`' command line and environment from `script_code` and `env`
/// applied at `scope`, returning the buffers the SDK now points into.
///
/// # Safety
/// `sdk` must hold valid, currently-loaded function pointers, and `settings`
/// must remain at a fixed address while the returned buffers are alive.
pub(crate) unsafe fn set_command_line_and_env(
    sdk: &WslcSdk,
    settings: *mut WslcProcessSettings,
    scope: EnvScope,
    env: &[String],
    script_code: &str,
) -> Result<CommandLineBuffers, ScriptResponse> {
    let argv_cstrings = process_env::argv_words(scope, env, script_code)
        .iter()
        .map(|word| cstr_bytes("command", word))
        .collect::<Result<Vec<_>, _>>()?;
    let argv: Vec<PCSTR> = argv_cstrings.iter().map(|w| w.as_ptr() as PCSTR).collect();
    let hr = sdk.WslcSetProcessSettingsCmdLine(settings, argv.as_ptr(), argv.len());
    if hr != S_OK {
        return Err(sdk_error("WslcSetProcessSettingsCmdLine failed", hr, ""));
    }

    let env_cstrings: Vec<Vec<u8>> = process_env::sdk_entries(scope, env)
        .iter()
        .map(|e| cstr_bytes("environment variable", e))
        .collect::<Result<Vec<_>, _>>()?;
    let mut env_ptrs: Vec<PCSTR> = Vec::new();
    if !env_cstrings.is_empty() {
        env_ptrs = env_cstrings.iter().map(|e| e.as_ptr() as PCSTR).collect();
        let hr =
            sdk.WslcSetProcessSettingsEnvVariables(settings, env_ptrs.as_ptr(), env_ptrs.len());
        if hr != S_OK {
            return Err(sdk_error(
                "WslcSetProcessSettingsEnvVariables failed",
                hr,
                "",
            ));
        }
    }

    Ok(CommandLineBuffers {
        _argv_cstrings: argv_cstrings,
        _argv: argv,
        _env_cstrings: env_cstrings,
        _env_ptrs: env_ptrs,
    })
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
    // Backing buffers the SDK stored raw pointers into (it does not copy them)
    // and dereferences at `WslcCreateContainerProcess` time. They must outlive
    // the create call, so the struct owns them; the `_` prefix marks them as
    // held purely to anchor those lifetimes, never read directly.
    _command: CommandLineBuffers,
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
    /// the given `env` (already proxy-adjusted by the caller) applied at `scope`
    /// and `working_directory` (an absolute in-container path, e.g. `/work`;
    /// empty = container default). Registers stdout/stderr/exit capture
    /// callbacks.
    ///
    /// # Safety
    /// `sdk` must hold valid, currently-loaded function pointers and COM must be
    /// initialized on the calling thread.
    pub unsafe fn build(
        sdk: &WslcSdk,
        script_code: &str,
        env: &[String],
        scope: EnvScope,
        working_directory: &str,
        sink: Option<OutputSink>,
    ) -> Result<Self, ScriptResponse> {
        Self::build_inner(sdk, script_code, env, scope, working_directory, true, sink)
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
        scope: EnvScope,
        working_directory: &str,
    ) -> Result<Self, ScriptResponse> {
        Self::build_inner(sdk, script_code, env, scope, working_directory, false, None)
    }

    unsafe fn build_inner(
        sdk: &WslcSdk,
        script_code: &str,
        env: &[String],
        scope: EnvScope,
        working_directory: &str,
        register_callbacks: bool,
        sink: Option<OutputSink>,
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
            sink,
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

        let command = set_command_line_and_env(sdk, &mut raw, scope, env, script_code)?;

        // Working directory (an absolute in-container path, e.g. `/work`; empty =
        // container default). It is passed straight to the SDK; a non-absolute
        // value is rejected rather than silently ignored.
        let mut cwd_cstr: Option<Vec<u8>> = None;
        if !working_directory.is_empty() {
            if !working_directory.starts_with('/') {
                return Err(WslcError::Rejected(format!(
                    "working_directory must be an absolute in-container path (got {working_directory:?})"
                ))
                .into_response());
            }
            let c = cstr_bytes("working_directory", working_directory)?;
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

        Ok(ProcessSettings {
            raw,
            io_ctx,
            sdk_io_ref,
            _command: command,
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
        let image_cstr = cstr_bytes("image", image)?;
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
                let ctr: Vec<u8> = cstr_bytes("mount container_path", &m.container_path)?;
                Ok((win, ctr))
            })
            .collect::<Result<Vec<_>, ScriptResponse>>()?;

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
    let sdk = WslcSdk::load().map_err(|e| WslcError::Unavailable(e).into_response())?;

    let mut missing = WslcComponentFlags::WSLC_COMPONENT_FLAG_NONE;
    let hr = sdk.WslcGetMissingComponents(&mut missing);
    if hr != S_OK {
        return Err(sdk_error("WslcGetMissingComponents failed", hr, ""));
    }
    if missing.any_missing() {
        return Err(WslcError::Unavailable(sdk_init::prerequisite_error(missing)).into_response());
    }
    let _ = writeln!(logger, "[WSLC][daemon] Runtime check passed");
    Ok(sdk)
}

#[derive(Debug)]
pub struct SessionCreateFailure {
    pub response: ScriptResponse,
    pub store_may_be_held: bool,
}

impl From<ScriptResponse> for SessionCreateFailure {
    fn from(response: ScriptResponse) -> Self {
        Self {
            response,
            store_may_be_held: false,
        }
    }
}

/// Create the shared daemon session (the WSL2 utility VM).
///
/// # Safety
/// `sdk` must hold valid function pointers and COM must be initialised on this
/// thread.
pub unsafe fn create_daemon_session(
    sdk: &WslcSdk,
    session_name: &str,
    storage_path: &str,
    sizing: SessionSizing,
    logger: &mut Logger,
) -> Result<WslcSessionGuard, SessionCreateFailure> {
    // Both wide buffers must outlive `WslcCreateSession` (the SDK stores pointers
    // into them at `WslcInitSessionSettings` time); they are function locals held
    // through the create call below.
    let name_wide: Vec<u16> = to_wide(session_name);
    let storage_wide: Vec<u16> = to_wide(storage_path);

    let mut settings = std::mem::zeroed::<WslcSessionSettings>();
    let hr = sdk.WslcInitSessionSettings(name_wide.as_ptr(), storage_wide.as_ptr(), &mut settings);
    if hr != S_OK {
        return Err(sdk_error("WslcInitSessionSettings failed", hr, "").into());
    }
    apply_session_sizing(sdk, &mut settings, sizing)?;

    let mut session: WslcSession = ptr::null_mut();
    let mut err_msg = CoTaskMemPWSTR::null();
    let started = Instant::now();
    let hr = sdk.WslcCreateSession(&mut settings, &mut session, err_msg.as_mut_ptr());
    let created_in = started.elapsed();
    if hr != S_OK {
        let msg = err_msg.to_string_lossy();
        return Err(sdk_error("WslcCreateSession failed", hr, &msg).into());
    }

    let guard = WslcSessionGuard::from_raw(
        session,
        sdk.terminate_session_fn(),
        sdk.release_session_fn(),
    );

    // Timed separately from the create: a host that cannot supply the session
    // accepts it here in under a second and spends minutes failing in the
    // probe, so one figure would hide where the time went.
    let probed = Instant::now();
    let probe = validate_store_access(sdk, guard.as_raw(), storage_path);
    let probed_in = probed.elapsed();

    // Logged before the probe is allowed to fail, because the failing case is
    // the one whose timing matters.
    let _ = writeln!(
        logger,
        "[WSLC][daemon] Session '{session_name}' on store {storage_path}: create \
         {:.1}s, store probe {:.1}s, probe {}",
        created_in.as_secs_f32(),
        probed_in.as_secs_f32(),
        if probe.is_ok() { "ok" } else { "failed" }
    );

    if let Err(response) = probe {
        // Dropping the guard would ignore a failed terminate, and the caller
        // must know whether this VM may still hold the store.
        let store_may_be_held = match release_daemon_session(guard, session_name, logger) {
            Ok(()) => false,
            Err(release) => {
                let _ = writeln!(logger, "[WSLC][daemon] {}", release.error_message);
                true
            }
        };
        return Err(SessionCreateFailure {
            response,
            store_may_be_held,
        });
    }

    Ok(guard)
}

/// Apply a session's sizing and its boot deadline to `settings`.
///
/// The boot timeout is applied even when the caller asked for no sizing, since
/// `WslcCreateSession` is otherwise unbounded.
///
/// # Safety
/// `sdk` must hold valid function pointers and `settings` must be initialised.
unsafe fn apply_session_sizing(
    sdk: &WslcSdk,
    settings: &mut WslcSessionSettings,
    sizing: SessionSizing,
) -> Result<(), ScriptResponse> {
    check_sizing_against_host(sizing)?;

    if let Some(cpu) = sizing.cpu_count {
        let hr = sdk.WslcSetSessionSettingsCpuCount(settings, cpu);
        if hr != S_OK {
            return Err(sdk_error("WslcSetSessionSettingsCpuCount failed", hr, ""));
        }
    }

    if let Some(memory_mb) = sizing.memory_mb {
        let memory_mb = u32::try_from(memory_mb).map_err(|_| {
            WslcError::Rejected(format!(
                "memory_mb {memory_mb} exceeds the {} MB the WSLc SDK accepts",
                u32::MAX
            ))
            .into_response()
        })?;
        let hr = sdk.WslcSetSessionSettingsMemory(settings, memory_mb);
        if hr != S_OK {
            return Err(sdk_error("WslcSetSessionSettingsMemory failed", hr, ""));
        }
    }

    let hr = sdk.WslcSetSessionSettingsTimeout(settings, SESSION_BOOT_TIMEOUT_MS);
    if hr != S_OK {
        return Err(sdk_error("WslcSetSessionSettingsTimeout failed", hr, ""));
    }

    if sizing.gpu {
        let hr = sdk.WslcSetSessionSettingsFeatureFlags(
            settings,
            WslcSessionFeatureFlags::WSLC_SESSION_FEATURE_FLAG_ENABLE_GPU,
        );
        if hr != S_OK {
            return Err(sdk_error(
                "WslcSetSessionSettingsFeatureFlags failed",
                hr,
                "",
            ));
        }
    }

    Ok(())
}

/// Terminate and release a session, reporting a terminate the SDK refused.
///
/// A session whose VM did not stop still holds its image store, so reporting
/// success would hand back a store slot the next lease cannot open.
pub fn release_daemon_session(
    session: WslcSessionGuard,
    session_name: &str,
    logger: &mut Logger,
) -> Result<(), ScriptResponse> {
    let hr = session.release_checked();
    if hr != S_OK {
        return Err(sdk_error(
            "WslcTerminateSession failed",
            hr,
            &format!(
                "the WSL2 utility VM for session '{session_name}' may still be running, so its \
                 image store cannot be reused yet"
            ),
        ));
    }

    let _ = writeln!(logger, "[WSLC][daemon] Session '{session_name}' released");
    Ok(())
}

/// Confirm a session just created can reach the store it was given.
///
/// A store's VHDX admits one live session, and the SDK does not report a
/// conflict at create time: `WslcCreateSession` against a held store returns a
/// healthy-looking handle, and the violation appears on first use as
/// `HRESULT 0x80070020`. Probing here turns that into a create failure, so a
/// caller never mints a sandbox id against a session that would die at an
/// arbitrary later phase.
///
/// # Safety
/// `sdk` must hold valid function pointers and `session` must be a live handle.
pub unsafe fn validate_store_access(
    sdk: &WslcSdk,
    session: WslcSession,
    storage_path: &str,
) -> Result<(), ScriptResponse> {
    list_stored_images(sdk, session)
        .map(|_| ())
        .map_err(|hr| store_access_failure(hr, storage_path))
}

/// Render a failed store probe, telling a sharing violation apart from any
/// other reason the store could not be read.
fn store_access_failure(hr: HRESULT, storage_path: &str) -> ScriptResponse {
    if hr == E_SHARING_VIOLATION {
        sdk_error(
            "WSLc store unavailable",
            hr,
            &format!(
                "the image store at {storage_path} is already held by another live session. \
                 A running wxc-wslc-daemon.exe releases it after its idle timeout; a \
                 create-and-run execution releases it when the run ends; a slot being \
                 warmed by --setup-wslc releases it when the warm finishes"
            ),
        )
    } else {
        sdk_error(
            "WslcListSessionImages failed",
            hr,
            &format!("could not read the image store at {storage_path}"),
        )
    }
}

/// One entry of a session's image store.
pub(crate) struct StoredImage {
    pub(crate) name: String,
    pub(crate) sha256: [u8; 32],
}

/// Read a session's image store, preserving the `HRESULT` so a caller can tell
/// a sharing violation from any other failure.
///
/// # Safety
/// `sdk` must hold valid function pointers and `session` must be a live handle.
pub(crate) unsafe fn list_stored_images(
    sdk: &WslcSdk,
    session: WslcSession,
) -> Result<Vec<StoredImage>, HRESULT> {
    let mut images: *mut WslcImageInfo = ptr::null_mut();
    let mut count: u32 = 0;
    let hr = sdk.WslcListSessionImages(session, &mut images, &mut count);
    if hr != S_OK {
        return Err(hr);
    }
    if images.is_null() {
        return Ok(Vec::new());
    }

    let mut stored = Vec::with_capacity(count as usize);
    for info in std::slice::from_raw_parts(images, count as usize) {
        // `info.name` is a fixed-size, possibly-unterminated C buffer; read up
        // to the first NUL, or the whole buffer if there is none.
        let bytes = std::slice::from_raw_parts(info.name.as_ptr().cast::<u8>(), info.name.len());
        let end = bytes.iter().position(|&b| b == 0).unwrap_or(bytes.len());
        if let Ok(name) = std::str::from_utf8(&bytes[..end]) {
            stored.push(StoredImage {
                name: name.to_string(),
                sha256: info.sha256,
            });
        }
    }
    windows::Win32::System::Com::CoTaskMemFree(Some(images as *const c_void));

    Ok(stored)
}

/// The flags a lifecycle container is created with.
///
/// GPU is set on the session *and* the container; a session sized for a GPU
/// whose containers lack the flag gets no passthrough and reports nothing.
/// Auto-remove stays one-shot-only, since a lifecycle sandbox outlives its runs.
fn container_flags(gpu: bool) -> WslcContainerFlags {
    if gpu {
        WslcContainerFlags::WSLC_CONTAINER_FLAG_ENABLE_GPU
    } else {
        WslcContainerFlags::WSLC_CONTAINER_FLAG_NONE
    }
}

/// Create a daemon-owned container with `keepalive` as its init process, so it
/// stays alive across repeated `exec` calls. The caller keeps `keepalive`
/// stationary until this returns (the SDK reads its buffers at
/// `WslcCreateContainer` time).
///
/// # Safety
/// `sdk` must hold valid function pointers and `session` must be a live handle.
#[allow(clippy::too_many_arguments)]
pub unsafe fn create_daemon_container(
    sdk: &WslcSdk,
    session: WslcSession,
    image: &str,
    mounts: &[VolumeMount],
    port_mappings: &[PortMapping],
    net_mode: WslcContainerNetworkingMode,
    gpu: bool,
    keepalive: &mut ProcessSettings,
    logger: &mut Logger,
) -> Result<WslcContainerGuard, ScriptResponse> {
    let mut container_settings = ContainerSettings::build(
        sdk,
        image,
        mounts,
        port_mappings,
        net_mode,
        container_flags(gpu),
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

/// Maximum delay before observing cancellation while waiting for process exit.
const EXEC_WAIT_POLL_INTERVAL: Duration = Duration::from_millis(100);

/// Bounded wait for the SDK exit callback to confirm termination and flush I/O.
const EXIT_CALLBACK_WAIT: Duration = Duration::from_secs(30);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ExecInterruption {
    TimedOut,
    Cancelled,
}

impl ExecInterruption {
    fn get_interruption_word(self) -> &'static str {
        match self {
            Self::TimedOut => "timeout",
            Self::Cancelled => "cancellation",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ExitWait {
    Signalled,
    Interrupted(ExecInterruption),
    NoEvent,
    Failed { wait_result: u32, last_error: u32 },
}

fn wait_slice(timeout: Option<Duration>, elapsed: Duration) -> Duration {
    timeout
        .map(|limit| limit.saturating_sub(elapsed))
        .unwrap_or(EXEC_WAIT_POLL_INTERVAL)
        .min(EXEC_WAIT_POLL_INTERVAL)
}

fn wait_slice_ms(timeout: Option<Duration>, elapsed: Duration) -> u32 {
    u32::try_from(wait_slice(timeout, elapsed).as_millis())
        .expect("poll interval is bounded to 100ms")
}

fn requested_interruption(
    cancelled: bool,
    timeout: Option<Duration>,
    elapsed: Duration,
) -> Option<ExecInterruption> {
    if cancelled {
        Some(ExecInterruption::Cancelled)
    } else if timeout.is_some_and(|limit| elapsed >= limit) {
        Some(ExecInterruption::TimedOut)
    } else {
        None
    }
}

/// Wait for process exit or a cancellation/timeout request.
///
/// # Safety
/// `exit_event` must be null or a valid waitable event handle for the duration
/// of this call.
unsafe fn wait_for_exit_event(
    exit_event: HANDLE,
    io_ctx: &IoContext,
    timeout: Option<Duration>,
    cancellation: &AtomicBool,
) -> ExitWait {
    let started = Instant::now();
    loop {
        if let Some(interruption) = requested_interruption(
            cancellation.load(Ordering::Acquire),
            timeout,
            started.elapsed(),
        ) {
            return ExitWait::Interrupted(interruption);
        }

        if exit_event.is_null() {
            if wait_for_exit_callback_slice(io_ctx, wait_slice(timeout, started.elapsed())) {
                return ExitWait::NoEvent;
            }
            continue;
        }

        let wait_result = unsafe {
            windows::Win32::System::Threading::WaitForSingleObject(
                windows::Win32::Foundation::HANDLE(exit_event),
                wait_slice_ms(timeout, started.elapsed()),
            )
        };
        if wait_result == windows::Win32::Foundation::WAIT_OBJECT_0 {
            return ExitWait::Signalled;
        }
        if wait_result != windows::Win32::Foundation::WAIT_TIMEOUT {
            let last_error = unsafe { windows::Win32::Foundation::GetLastError() };
            return ExitWait::Failed {
                wait_result: wait_result.0,
                last_error: last_error.0,
            };
        }
    }
}

fn wait_for_exit_callback_slice(io_ctx: &IoContext, wait: Duration) -> bool {
    let (lock, cvar) = &*io_ctx.exited;
    let mut exited = lock.lock().unwrap_or_else(|e| e.into_inner());
    if !*exited {
        let result = cvar
            .wait_timeout(exited, wait)
            .unwrap_or_else(|e| e.into_inner());
        exited = result.0;
    }
    *exited
}

fn wait_for_exit_callback(io_ctx: &IoContext) -> bool {
    wait_for_exit_callback_slice(io_ctx, EXIT_CALLBACK_WAIT)
}

/// Terminal state of a daemon container process.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProcessCompletion {
    Confirmed(ExecTerminal),
    /// The process could not be positively confirmed dead. The owning
    /// container must be quarantined and never reused.
    TerminationUnconfirmed,
}

fn natural_exit_confirmed(exit_wait: ExitWait, callback_confirmed: bool) -> bool {
    matches!(exit_wait, ExitWait::Signalled)
        || (matches!(exit_wait, ExitWait::NoEvent) && callback_confirmed)
}

fn classify_completion(exit_wait: ExitWait, confirmed: bool, exit_code: i32) -> ProcessCompletion {
    if natural_exit_confirmed(exit_wait, confirmed) {
        return ProcessCompletion::Confirmed(ExecTerminal::Exited(exit_code));
    }

    match exit_wait {
        ExitWait::Interrupted(ExecInterruption::TimedOut) if confirmed => {
            ProcessCompletion::Confirmed(ExecTerminal::TimedOut)
        }
        ExitWait::Interrupted(ExecInterruption::Cancelled) if confirmed => {
            ProcessCompletion::Confirmed(ExecTerminal::Cancelled)
        }
        ExitWait::Interrupted(_) | ExitWait::Failed { .. } => {
            ProcessCompletion::TerminationUnconfirmed
        }
        ExitWait::NoEvent | ExitWait::Signalled => ProcessCompletion::TerminationUnconfirmed,
    }
}

/// Result of a daemon `exec`, including captured output retained by callbacks.
#[derive(Debug)]
pub struct ExecOutcome {
    pub completion: ProcessCompletion,
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
    /// Specific post-process-creation failure that made termination
    /// unobservable. The daemon uses this context when quarantining.
    pub post_launch_error: Option<ScriptResponse>,
}

/// Run `script_code` (under `/bin/sh -c`) as a fresh process inside a started
/// daemon container and wait for it to complete. On timeout the *process* is
/// killed (SIGKILL) — NOT the container — so the keepalive init survives for
/// subsequent execs.
///
/// # Safety
/// `sdk` must hold valid function pointers and `container` must be a live,
/// started handle.
#[expect(
    clippy::too_many_arguments,
    reason = "thin FFI boundary mirrors the SDK process inputs at its single call site"
)]
pub unsafe fn exec_in_container(
    sdk: &WslcSdk,
    container: WslcContainer,
    script_code: &str,
    env: &[String],
    scope: EnvScope,
    working_directory: &str,
    timeout_ms: u32,
    cancellation: &AtomicBool,
    sink: Option<OutputSink>,
    logger: &mut Logger,
) -> Result<ExecOutcome, ScriptResponse> {
    // `process_settings` owns every buffer the SDK reads at
    // `WslcCreateContainerProcess` time plus the I/O-capture context; it is held
    // as a stationary local until after the process exits below.
    let mut process_settings =
        ProcessSettings::build(sdk, script_code, env, scope, working_directory, sink)?;

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
        return Ok(ExecOutcome {
            completion: ProcessCompletion::TerminationUnconfirmed,
            stdout: Vec::new(),
            stderr: Vec::new(),
            post_launch_error: Some(sdk_error("WslcGetProcessExitEvent failed", hr, "")),
        });
    }

    let timeout = (timeout_ms > 0).then(|| Duration::from_millis(u64::from(timeout_ms)));
    let exit_wait =
        wait_for_exit_event(exit_event, process_settings.io_ctx(), timeout, cancellation);

    if let ExitWait::Failed {
        wait_result,
        last_error,
    } = exit_wait
    {
        let _ = writeln!(
            logger,
            "[WSLC][daemon] Warning: waiting on the exec exit event failed: \
             WaitForSingleObject returned 0x{wait_result:08X} \
             (GetLastError 0x{last_error:08X}); container state is unknown"
        );
    }

    let interruption = match exit_wait {
        ExitWait::Interrupted(interruption) => Some(interruption),
        _ => None,
    };
    if let Some(interruption) = interruption {
        let _ = writeln!(
            logger,
            "[WSLC][daemon] exec {} — killing process",
            interruption.get_interruption_word()
        );
        // Kill only this process; the keepalive init keeps the container up.
        let kill_hr =
            sdk.WslcSignalProcess(process_guard.as_raw(), WslcSignal::WSLC_SIGNAL_SIGKILL);
        if kill_hr != S_OK {
            let _ = writeln!(
                logger,
                "[WSLC][daemon] Warning: WslcSignalProcess(SIGKILL) failed (hr=0x{:08X}); \
                 process may still be running",
                kill_hr as u32
            );
        }
    }

    // Wait for the exit callback — the only proof the process is actually gone
    // and that all captured I/O has been flushed.
    let mut confirmed = wait_for_exit_callback(process_settings.io_ctx());
    if interruption.is_some() && !confirmed {
        // The SIGKILL was only a request and plainly has not landed yet; give
        // the callback one more bounded chance before declaring the outcome
        // unconfirmed.
        confirmed = wait_for_exit_callback(process_settings.io_ctx());
        if !confirmed {
            let _ = writeln!(
                logger,
                "[WSLC][daemon] Warning: exit callback did not fire after SIGKILL; \
                 process may still be running"
            );
        }
    }

    let mut exit_code: i32 = -1;
    let hr = sdk.WslcGetProcessExitCode(process_guard.as_raw(), &mut exit_code);
    if hr != S_OK {
        if natural_exit_confirmed(exit_wait, confirmed) {
            return Err(sdk_error("WslcGetProcessExitCode failed", hr, ""));
        }
        let _ = writeln!(
            logger,
            "[WSLC][daemon] Warning: WslcGetProcessExitCode failed while termination was \
             unconfirmed (hr=0x{:08X})",
            hr as u32
        );
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

    // Resolve the reported outcome from positive evidence only.
    let completion = classify_completion(exit_wait, confirmed, exit_code);
    match completion {
        ProcessCompletion::Confirmed(ExecTerminal::TimedOut) => {
            let _ = writeln!(
                logger,
                "[WSLC][daemon] Process killed after {}",
                ExecInterruption::TimedOut.get_interruption_word()
            );
        }
        ProcessCompletion::Confirmed(ExecTerminal::Cancelled) => {
            let _ = writeln!(
                logger,
                "[WSLC][daemon] Process killed after {}",
                ExecInterruption::Cancelled.get_interruption_word()
            );
        }
        ProcessCompletion::Confirmed(ExecTerminal::Exited(exit_code)) => {
            let _ = writeln!(
                logger,
                "[WSLC][daemon] Process exited with code {}",
                exit_code
            );
        }
        ProcessCompletion::TerminationUnconfirmed if matches!(exit_wait, ExitWait::NoEvent) => {
            let _ = writeln!(
                logger,
                "[WSLC][daemon] Warning: exec never reported an exit (no exit event, no exit \
                 callback); container state is unknown"
            );
        }
        ProcessCompletion::TerminationUnconfirmed => {}
    }

    Ok(ExecOutcome {
        completion,
        stdout,
        stderr,
        post_launch_error: None,
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mxc_common::models::FailurePhase;

    /// A modest machine: 16 GB and 8 logical processors.
    const TEST_HOST: HostCapacity = HostCapacity {
        total_memory_mb: 16 * 1024,
        logical_cpus: 8,
    };

    #[test]
    fn a_processor_count_the_host_cannot_supply_is_refused() {
        let refused = sizing_fits_host(
            SessionSizing {
                cpu_count: Some(TEST_HOST.logical_cpus + 1),
                ..SessionSizing::default()
            },
            TEST_HOST,
        )
        .expect_err("more processors than the host has must be refused");

        assert_eq!(refused.failure_phase, FailurePhase::Rejected);
        assert!(
            refused.error_message.contains('9') && refused.error_message.contains('8'),
            "the refusal must name both what was asked and what the host has: {}",
            refused.error_message
        );
    }

    #[test]
    fn a_processor_count_the_host_can_supply_is_allowed() {
        for cpus in [1, TEST_HOST.logical_cpus] {
            assert!(
                sizing_fits_host(
                    SessionSizing {
                        cpu_count: Some(cpus),
                        ..SessionSizing::default()
                    },
                    TEST_HOST,
                )
                .is_ok(),
                "{cpus} processors is within the host's {}",
                TEST_HOST.logical_cpus
            );
        }
    }

    /// `memory_mb` is a ceiling the host backs on demand, not a reservation,
    /// so a request past installed memory is legitimate.
    #[test]
    fn memory_past_installed_is_allowed_because_it_is_a_ceiling() {
        assert!(
            sizing_fits_host(
                SessionSizing {
                    memory_mb: Some(TEST_HOST.total_memory_mb * 8),
                    ..SessionSizing::default()
                },
                TEST_HOST,
            )
            .is_ok(),
            "memory_mb is a ceiling the host backs on demand, not a reservation"
        );
    }

    /// The SDK documents `0` as "reset to the default" for both figures, so it
    /// is a sentinel rather than a size and must not be measured against the
    /// host.
    #[test]
    fn zero_is_a_default_sentinel_rather_than_a_size() {
        assert!(sizing_fits_host(
            SessionSizing {
                cpu_count: Some(0),
                memory_mb: Some(0),
                gpu: false,
            },
            TEST_HOST,
        )
        .is_ok());
    }

    /// A request that names no sizing takes the host defaults and has nothing
    /// to check.
    #[test]
    fn absent_sizing_is_allowed() {
        assert!(sizing_fits_host(SessionSizing::default(), TEST_HOST).is_ok());
    }

    /// A session sized for a GPU whose containers lack the flag gets no
    /// passthrough and reports nothing, so the two halves must agree.
    #[test]
    fn a_gpu_session_creates_gpu_containers() {
        assert_eq!(
            container_flags(true),
            WslcContainerFlags::WSLC_CONTAINER_FLAG_ENABLE_GPU
        );
        assert_eq!(
            container_flags(false),
            WslcContainerFlags::WSLC_CONTAINER_FLAG_NONE
        );
    }

    #[test]
    fn a_held_store_is_reported_as_held_rather_than_as_a_failed_call() {
        let resp = store_access_failure(E_SHARING_VIOLATION, r"C:\slots\slot-0");

        assert!(
            resp.error_message
                .contains("already held by another live session"),
            "a sharing violation is the one store failure a caller can wait out: {}",
            resp.error_message
        );
        assert!(resp.error_message.contains(r"C:\slots\slot-0"));
        assert!(resp.error_message.contains("idle timeout"));
        assert!(
            resp.error_message.contains("--setup-wslc"),
            "warming holds a slot's store too, and that holder clears on its own: {}",
            resp.error_message
        );
        assert!(resp.error_message.contains("80070020"));
    }

    #[test]
    fn any_other_store_failure_keeps_the_call_that_produced_it() {
        let resp = store_access_failure(-2147467259, r"C:\slots\slot-0");

        assert!(
            resp.error_message.contains("WslcListSessionImages failed"),
            "an unrecognised failure must not be attributed to another holder: {}",
            resp.error_message
        );
        assert!(!resp.error_message.contains("already held"));
        assert!(resp.error_message.contains(r"C:\slots\slot-0"));
    }

    #[test]
    fn a_store_failure_is_attributed_to_bring_up() {
        assert_eq!(
            store_access_failure(E_SHARING_VIOLATION, "store").failure_phase,
            FailurePhase::LaunchFailed,
            "a held store frees up on its own, so this must not read as a rejection"
        );
    }

    #[test]
    fn cstr_bytes_nul_terminates_a_plain_value() {
        let bytes = cstr_bytes("command", "echo hi").expect("plain value is a valid C string");
        assert_eq!(bytes, b"echo hi\0");
    }

    #[test]
    fn cstr_bytes_accepts_empty() {
        let bytes = cstr_bytes("working_directory", "").expect("empty value is a valid C string");
        assert_eq!(bytes, b"\0");
    }

    #[test]
    fn cstr_bytes_rejects_interior_nul() {
        let err = cstr_bytes("command", "echo\0rm -rf /")
            .expect_err("an interior NUL must be rejected, not silently truncated");
        let msg = format!("{:?}", err);
        assert!(msg.contains("command"), "error names the field: {msg}");
        assert!(
            msg.contains("interior NUL"),
            "error explains the cause: {msg}"
        );
    }

    #[test]
    fn wait_slice_is_bounded_by_poll_interval_and_deadline() {
        assert_eq!(wait_slice(None, Duration::ZERO), Duration::from_millis(100));
        assert_eq!(
            wait_slice(Some(Duration::from_millis(250)), Duration::from_millis(225),),
            Duration::from_millis(25)
        );
        assert_eq!(wait_slice_ms(None, Duration::ZERO), 100);
        assert_eq!(
            wait_slice_ms(Some(Duration::from_millis(250)), Duration::from_millis(25)),
            100
        );
        assert_eq!(
            wait_slice_ms(Some(Duration::from_millis(250)), Duration::from_millis(225)),
            25
        );
        assert_eq!(
            wait_slice_ms(Some(Duration::from_millis(250)), Duration::from_millis(250)),
            0
        );
    }

    #[test]
    fn cancellation_takes_precedence_over_an_expired_timeout() {
        assert_eq!(
            requested_interruption(
                true,
                Some(Duration::from_millis(10)),
                Duration::from_millis(10),
            ),
            Some(ExecInterruption::Cancelled)
        );
    }

    #[test]
    fn timeout_requires_a_nonzero_deadline_to_expire() {
        assert_eq!(
            requested_interruption(false, None, Duration::from_secs(1)),
            None
        );
        assert_eq!(
            requested_interruption(
                false,
                Some(Duration::from_millis(10)),
                Duration::from_millis(9),
            ),
            None
        );
        assert_eq!(
            requested_interruption(
                false,
                Some(Duration::from_millis(10)),
                Duration::from_millis(10),
            ),
            Some(ExecInterruption::TimedOut)
        );
    }

    #[test]
    fn completion_classification_requires_positive_exit_evidence() {
        assert_eq!(
            classify_completion(ExitWait::Signalled, false, 7),
            ProcessCompletion::Confirmed(ExecTerminal::Exited(7))
        );
        assert_eq!(
            classify_completion(ExitWait::NoEvent, true, 8),
            ProcessCompletion::Confirmed(ExecTerminal::Exited(8))
        );
        assert_eq!(
            classify_completion(ExitWait::Interrupted(ExecInterruption::TimedOut), true, -1,),
            ProcessCompletion::Confirmed(ExecTerminal::TimedOut)
        );
        assert_eq!(
            classify_completion(ExitWait::Interrupted(ExecInterruption::Cancelled), true, -1,),
            ProcessCompletion::Confirmed(ExecTerminal::Cancelled)
        );
        assert_eq!(
            classify_completion(
                ExitWait::Interrupted(ExecInterruption::Cancelled),
                false,
                -1,
            ),
            ProcessCompletion::TerminationUnconfirmed
        );
        assert_eq!(
            classify_completion(
                ExitWait::Failed {
                    wait_result: 1,
                    last_error: 2,
                },
                true,
                0,
            ),
            ProcessCompletion::TerminationUnconfirmed
        );
        assert_eq!(
            classify_completion(ExitWait::NoEvent, false, -1),
            ProcessCompletion::TerminationUnconfirmed
        );
    }

    /// A streaming caller reads its bytes from the sink, so a second capped
    /// copy would double the daemon's per-exec output memory.
    #[test]
    fn a_streaming_callback_captures_nothing() {
        let streamed = Arc::new(Mutex::new(Vec::new()));
        let seen = Arc::clone(&streamed);
        let io_ctx = Arc::new(IoContext {
            stdout: Arc::new(Mutex::new(Vec::new())),
            stderr: Arc::new(Mutex::new(Vec::new())),
            exited: Arc::new((Mutex::new(false), Condvar::new())),
            sink: Some(Box::new(move |kind, bytes| {
                seen.lock().unwrap().push((kind, bytes.to_vec()));
            })),
        });

        let payload = b"streamed-not-captured";
        let raw = Arc::into_raw(Arc::clone(&io_ctx));
        // SAFETY: `raw` is a live `Arc<IoContext>` pointer and `payload` is
        // valid for its full length, matching what the SDK passes.
        unsafe {
            io_callback(
                WslcProcessIOHandle::WSLC_PROCESS_IO_HANDLE_STDOUT,
                payload.as_ptr(),
                payload.len() as u32,
                raw as *mut c_void,
            );
            drop(Arc::from_raw(raw));
        }

        assert_eq!(
            streamed.lock().unwrap().as_slice(),
            &[(OutStream::Stdout, payload.to_vec())]
        );
        assert!(
            io_ctx.stdout.lock().unwrap().is_empty(),
            "a streamed chunk must not also be captured"
        );
    }

    #[test]
    fn null_exit_event_still_observes_cancellation() {
        let io_ctx = IoContext {
            stdout: Arc::new(Mutex::new(Vec::new())),
            stderr: Arc::new(Mutex::new(Vec::new())),
            exited: Arc::new((Mutex::new(false), Condvar::new())),
            sink: None,
        };
        let cancellation = AtomicBool::new(true);

        let result = unsafe { wait_for_exit_event(ptr::null_mut(), &io_ctx, None, &cancellation) };

        assert_eq!(result, ExitWait::Interrupted(ExecInterruption::Cancelled));
    }

    #[test]
    fn null_exit_event_uses_callback_as_natural_exit_evidence() {
        let io_ctx = IoContext {
            stdout: Arc::new(Mutex::new(Vec::new())),
            stderr: Arc::new(Mutex::new(Vec::new())),
            exited: Arc::new((Mutex::new(true), Condvar::new())),
            sink: None,
        };
        let cancellation = AtomicBool::new(false);

        let result = unsafe { wait_for_exit_event(ptr::null_mut(), &io_ctx, None, &cancellation) };

        assert_eq!(result, ExitWait::NoEvent);
    }
}
