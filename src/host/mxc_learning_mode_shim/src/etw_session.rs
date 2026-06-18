// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Privileged ETW-session creation owned by the shim.
//!
//! Per request the shim:
//! 1. Generates a unique session name (`mxc-denials-<uuid>`).
//! 2. Calls `StartTraceW` with `EVENT_TRACE_REAL_TIME_MODE` and a
//!    fresh `EVENT_TRACE_PROPERTIES_V2` block. (Real-time mode, not
//!    private — private sessions are in-process only and can't be
//!    consumed by the unelevated caller.)
//! 3. Calls `EnableTraceEx2` for each provider (Microsoft-Windows-Kernel
//!    -General + the MXC OS-side TraceLogging provider) with an
//!    `EVENT_FILTER_TYPE_PID` filter scoped to the requested PID. If a
//!    package SID was supplied an `EVENT_FILTER_TYPE_PACKAGE_ID` filter
//!    is added too.
//! 4. (TODO) Calls `EventAccessControl` to grant the caller's user SID
//!    `TRACELOG_ACCESS_REALTIME | TRACELOG_GUID_ENABLE | WMIGUID_QUERY`
//!    on the session GUID so the unelevated caller can `OpenTrace` /
//!    `ControlTrace(STOP)`. Phase 2.2 returns the session name without
//!    this grant — the prototype caller is also elevated, so the default
//!    ACL is sufficient. The grant call lands when wxc-exec is wired in
//!    Phase 3 and we observe the access-denied error.
//! 5. Returns the session name in the wire response. The caller then
//!    owns the lifecycle.
//!
//! On any failure mid-setup the partially-created session is torn down
//! before returning an error to the caller, so we don't leak ETW slots
//! (Windows has a hard system-wide limit of ~64 user-mode sessions).

use std::mem::size_of;

use windows::core::{GUID, PCWSTR};
use windows::Win32::Foundation::{ERROR_ALREADY_EXISTS, WIN32_ERROR};
use windows::Win32::System::Diagnostics::Etw::{
    ControlTraceW, EnableTraceEx2, StartTraceW, CONTROLTRACE_HANDLE, ENABLE_TRACE_PARAMETERS,
    EVENT_CONTROL_CODE_ENABLE_PROVIDER, EVENT_FILTER_DESCRIPTOR, EVENT_TRACE_CONTROL_STOP,
    EVENT_TRACE_PROPERTIES, EVENT_TRACE_PROPERTIES_V2, EVENT_TRACE_REAL_TIME_MODE,
    TRACE_LEVEL_VERBOSE, WNODE_FLAG_TRACED_GUID,
};

/// `Microsoft-Windows-Kernel-General` provider GUID.
/// Source: documented Windows ETW provider GUID.
const KERNEL_GENERAL_PROVIDER: GUID = GUID::from_u128(0xa68ca8b7_004f_d7b6_a698_07e2de0f1f5d);

/// MXC OS-side TraceLogging provider GUID.
/// Source: `src/tools/mxc_diagnostic_console/src/etw.rs`.
const MXC_OS_PROVIDER: GUID = GUID::from_u128(0xf6ec123e_314e_400b_9e0a_151365e23083);

/// `EVENT_FILTER_TYPE_PID = 0x00000008`.
const EVENT_FILTER_TYPE_PID: u32 = 0x0000_0008;

/// Failure that wraps a Win32 error in human-readable form.
#[derive(Debug)]
pub struct EtwError {
    pub op: &'static str,
    pub code: u32,
}

impl std::fmt::Display for EtwError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: Win32 error {:#X}", self.op, self.code)
    }
}

impl std::error::Error for EtwError {}

/// A live ETW session held by the shim while the caller consumes it.
///
/// Phase 2.2: the shim creates and immediately disengages — the caller
/// owns lifecycle. The struct is returned from the create path so
/// callers in tests can stop the session deterministically; the
/// production hot path `mem::forget`s it. Allow dead-code on the
/// fields/methods used only by tests + future cleanup paths.
pub struct LiveSession {
    pub name: String,
    #[allow(dead_code)]
    pub control_handle: CONTROLTRACE_HANDLE,
}

impl LiveSession {
    /// Stops the session via `ControlTraceW(STOP)`. Idempotent: a
    /// session already stopped or never started returns an error which
    /// is logged and swallowed.
    #[allow(dead_code)]
    pub fn stop(self) {
        let mut name_wide: Vec<u16> = self.name.encode_utf16().chain(std::iter::once(0)).collect();
        let mut props = empty_session_properties(&self.name);

        // SAFETY: `props` is a properly-sized EVENT_TRACE_PROPERTIES_V2
        // initialized with a valid loggername buffer offset; `name_wide`
        // is a valid null-terminated UTF-16 string. ControlTraceW with
        // STOP frees the session.
        let status = unsafe {
            ControlTraceW(
                self.control_handle,
                PCWSTR(name_wide.as_mut_ptr()),
                &mut props as *mut _ as *mut EVENT_TRACE_PROPERTIES,
                EVENT_TRACE_CONTROL_STOP,
            )
        };
        if status != WIN32_ERROR(0) {
            eprintln!(
                "[mxc-learning-mode-shim] ControlTraceW(STOP) for {} failed: {:#X}",
                self.name, status.0
            );
        }
    }
}

/// Creates a denial-capture session scoped to `target_pid`.
///
/// `_package_sid` is accepted for forward compatibility but the
/// PACKAGE_ID filter wiring is deferred to Phase 3 (we need to wire up
/// the SID parser + filter blob shape; PID alone gets us the prototype
/// data we need).
pub fn create_denial_session(
    target_pid: u32,
    _package_sid: Option<&str>,
) -> Result<LiveSession, EtwError> {
    let session_name = format!("mxc-denials-{}", uuid::Uuid::new_v4().simple());

    let mut props = empty_session_properties(&session_name);
    let mut name_wide: Vec<u16> = session_name
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect();

    let mut control_handle = CONTROLTRACE_HANDLE::default();

    // SAFETY: `props` is a properly-sized EVENT_TRACE_PROPERTIES_V2 with
    // a valid trailing loggername buffer; `name_wide` is null-terminated
    // UTF-16 owned for the duration of the call.
    let status = unsafe {
        StartTraceW(
            &mut control_handle,
            PCWSTR(name_wide.as_mut_ptr()),
            &mut props as *mut _ as *mut EVENT_TRACE_PROPERTIES,
        )
    };

    if status == ERROR_ALREADY_EXISTS {
        // A session with the same name exists. UUIDs make this practically
        // impossible — surface as a hard error so we notice immediately.
        return Err(EtwError {
            op: "StartTraceW (already exists)",
            code: status.0,
        });
    }
    if status != WIN32_ERROR(0) {
        return Err(EtwError {
            op: "StartTraceW",
            code: status.0,
        });
    }

    // Enable each provider with a PID filter. If any enable call fails we
    // tear down the session before returning so we don't leak an ETW
    // slot.
    let target_pids = [target_pid];

    if let Err(e) = enable_provider_for_pid(control_handle, &KERNEL_GENERAL_PROVIDER, &target_pids)
    {
        let _ = stop_partial(&session_name, control_handle);
        return Err(e);
    }

    if let Err(e) = enable_provider_for_pid(control_handle, &MXC_OS_PROVIDER, &target_pids) {
        let _ = stop_partial(&session_name, control_handle);
        return Err(e);
    }

    Ok(LiveSession {
        name: session_name,
        control_handle,
    })
}

fn enable_provider_for_pid(
    handle: CONTROLTRACE_HANDLE,
    provider: &GUID,
    target_pids: &[u32],
) -> Result<(), EtwError> {
    let pid_filter = EVENT_FILTER_DESCRIPTOR {
        Ptr: target_pids.as_ptr() as u64,
        Size: std::mem::size_of_val(target_pids) as u32,
        Type: EVENT_FILTER_TYPE_PID,
    };

    let mut filters = [pid_filter];

    let params = ENABLE_TRACE_PARAMETERS {
        Version: 2,
        EnableProperty: 0,
        ControlFlags: 0,
        SourceId: GUID::default(),
        EnableFilterDesc: filters.as_mut_ptr(),
        FilterDescCount: filters.len() as u32,
    };

    // SAFETY: `handle` is a valid CONTROLTRACE_HANDLE returned by
    // StartTraceW; `params` and the embedded filter descriptor reference
    // `target_pids` and `filters` which both outlive the call.
    let status = unsafe {
        EnableTraceEx2(
            handle,
            provider,
            EVENT_CONTROL_CODE_ENABLE_PROVIDER.0,
            TRACE_LEVEL_VERBOSE as u8,
            0xFFFF_FFFF_FFFF_FFFF,
            0,
            0,
            Some(&params),
        )
    };

    if status != WIN32_ERROR(0) {
        return Err(EtwError {
            op: "EnableTraceEx2",
            code: status.0,
        });
    }

    Ok(())
}

fn stop_partial(name: &str, handle: CONTROLTRACE_HANDLE) -> Result<(), EtwError> {
    let mut name_wide: Vec<u16> = name.encode_utf16().chain(std::iter::once(0)).collect();
    let mut props = empty_session_properties(name);

    let status = unsafe {
        ControlTraceW(
            handle,
            PCWSTR(name_wide.as_mut_ptr()),
            &mut props as *mut _ as *mut EVENT_TRACE_PROPERTIES,
            EVENT_TRACE_CONTROL_STOP,
        )
    };

    if status != WIN32_ERROR(0) {
        return Err(EtwError {
            op: "ControlTraceW(STOP) during cleanup",
            code: status.0,
        });
    }
    Ok(())
}

/// Builds an `EVENT_TRACE_PROPERTIES_V2` block sized to hold the session
/// name as a trailing UTF-16 buffer.
///
/// ETW expects the properties struct followed by space for the session
/// name (and optionally a logfile name). We stack-allocate via the V2
/// struct and rely on its built-in trailing reserve to hold the name —
/// `LoggerNameOffset` points just past the struct.
fn empty_session_properties(_session_name: &str) -> EtwSessionProperties {
    // Layout: header followed by 2 wide-string buffers (LoggerName +
    // LogFileName). We use a fixed-size buffer big enough for any UUID
    // session name plus padding — 256 wide chars per buffer.
    const NAME_BUF_WCHARS: usize = 256;

    let mut p: EtwSessionProperties = unsafe { core::mem::zeroed() };
    p.base.Wnode.BufferSize = size_of::<EtwSessionProperties>() as u32;
    p.base.Wnode.Flags = WNODE_FLAG_TRACED_GUID;
    p.base.LogFileMode = EVENT_TRACE_REAL_TIME_MODE;
    // Defaults that work for most consumers; tune later if needed.
    p.base.MinimumBuffers = 4;
    p.base.MaximumBuffers = 64;
    p.base.LoggerNameOffset = size_of::<EVENT_TRACE_PROPERTIES_V2>() as u32;
    p.base.LogFileNameOffset =
        (size_of::<EVENT_TRACE_PROPERTIES_V2>() + NAME_BUF_WCHARS * size_of::<u16>()) as u32;

    p
}

/// Stack-friendly wrapper holding `EVENT_TRACE_PROPERTIES_V2` plus
/// space for the session name and (unused) logfile name.
#[repr(C)]
struct EtwSessionProperties {
    base: EVENT_TRACE_PROPERTIES_V2,
    logger_name: [u16; 256],
    log_file_name: [u16; 256],
}

// SAFETY: `EtwSessionProperties` is `#[repr(C)]` and contains only POD
// fields; we initialize via `core::mem::zeroed()` which is valid for
// all-POD structs.
unsafe impl Send for EtwSessionProperties {}

#[cfg(test)]
mod tests {
    use super::*;

    /// Sanity-only: ensure the layout math doesn't underflow / overflow
    /// for the offsets we hand the kernel.
    #[test]
    fn props_layout_offsets_are_in_range() {
        let p = empty_session_properties("any");
        assert!(p.base.LoggerNameOffset > 0);
        assert!(p.base.LogFileNameOffset > p.base.LoggerNameOffset);
        assert!(p.base.Wnode.BufferSize as usize >= size_of::<EVENT_TRACE_PROPERTIES_V2>());
    }

    /// Sanity: provider GUIDs have the expected high-bytes so we don't
    /// silently swap the constants between Kernel-General and MXC OS.
    #[test]
    fn provider_guids_distinct_and_recognizable() {
        assert_ne!(KERNEL_GENERAL_PROVIDER, MXC_OS_PROVIDER);
        assert_eq!(KERNEL_GENERAL_PROVIDER.data1, 0xa68ca8b7);
        assert_eq!(MXC_OS_PROVIDER.data1, 0xf6ec123e);
    }
}
