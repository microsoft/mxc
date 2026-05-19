// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Step 1d — spawn the probe's child binary inside an AppContainer process
//! and collect its structured JSON outcome over a named pipe.
//!
//! Mirrors the relevant subset of `wxc_common::appcontainer_runner` —
//! intentionally inline, not shared — so the spike has one self-contained
//! audit surface. The runner code in wxc_common is the eventual home for
//! whatever shape we land on; this is throwaway plumbing for the spike.

use std::ffi::c_void;
use std::path::{Path, PathBuf};
use std::ptr;

use serde::Serialize;

use windows::core::{PCWSTR, PWSTR};
use windows::Win32::Foundation::{
    CloseHandle, GetLastError, LocalFree, ERROR_PIPE_CONNECTED, HANDLE, HLOCAL,
    INVALID_HANDLE_VALUE, WAIT_OBJECT_0, WAIT_TIMEOUT,
};
use windows::Win32::Security::Authorization::{
    ConvertStringSecurityDescriptorToSecurityDescriptorW, ConvertStringSidToSidW,
    SDDL_REVISION_1,
};
use windows::Win32::Security::{
    PSECURITY_DESCRIPTOR, PSID, SECURITY_ATTRIBUTES, SECURITY_CAPABILITIES,
};
use windows::Win32::Storage::FileSystem::{
    ReadFile, FILE_FLAG_FIRST_PIPE_INSTANCE, PIPE_ACCESS_INBOUND,
};
use windows::Win32::System::Pipes::{
    ConnectNamedPipe, CreateNamedPipeW, PIPE_READMODE_BYTE, PIPE_TYPE_BYTE, PIPE_WAIT,
};
use windows::Win32::System::Threading::{
    CreateProcessW, DeleteProcThreadAttributeList, GetExitCodeProcess,
    InitializeProcThreadAttributeList, ResumeThread, TerminateProcess, UpdateProcThreadAttribute,
    WaitForSingleObject, LPPROC_THREAD_ATTRIBUTE_LIST, PROCESS_CREATION_FLAGS,
    PROCESS_INFORMATION, STARTUPINFOEXW, STARTUPINFOW,
};

// Constants the windows crate doesn't expose under our feature set.
const PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES: usize = 0x0002_0009;
const PROC_THREAD_ATTRIBUTE_ALL_APPLICATION_PACKAGES_POLICY: usize = 0x0002_000F;
const PROCESS_CREATION_ALL_APPLICATION_PACKAGES_OPT_OUT: u32 = 1;
const EXTENDED_STARTUPINFO_PRESENT: PROCESS_CREATION_FLAGS = PROCESS_CREATION_FLAGS(0x0008_0000);
const CREATE_SUSPENDED: PROCESS_CREATION_FLAGS = PROCESS_CREATION_FLAGS(0x0000_0004);
const CREATE_UNICODE_ENVIRONMENT: PROCESS_CREATION_FLAGS = PROCESS_CREATION_FLAGS(0x0000_0400);

#[derive(Debug, Clone, Serialize)]
pub(crate) struct AcChildReport {
    pub child_exe: PathBuf,
    pub pipe_name: String,
    pub exit_code: Option<u32>,
    pub wait_status: String,
    /// Raw JSON the child wrote to the pipe (re-emitted nested so the
    /// outer probe report keeps a single parse surface).
    pub child_json: Option<serde_json::Value>,
    pub errors: Vec<String>,
}

/// Run the child binary inside an AppContainer bound to the given SID
/// string. Returns whatever the child wrote to the pipe, plus the exit
/// status.
pub(crate) fn run_child_in_appcontainer(
    child_exe: &Path,
    virt_root: &Path,
    ac_sid_string: &str,
    check_dirs: &[String],
    write_probes: &[String],
    direct_reads: &[String],
    lpac: bool,
) -> Result<AcChildReport, String> {
    let pipe_name = format!(
        "\\\\.\\pipe\\mxc-projfs-probe-{}-{}",
        std::process::id(),
        rand_hex16()
    );

    // 1. Create the server end of the pipe. DACL grants the AC SID write
    //    access; the launching user keeps read access via the default DACL
    //    plus our explicit ACE.
    let pipe_handle = create_pipe_for_ac(&pipe_name, ac_sid_string)?;

    // 2. Spawn the AC child.
    let mut errors = Vec::new();
    let spawn_outcome = spawn_ac(
        child_exe,
        virt_root,
        &pipe_name,
        ac_sid_string,
        check_dirs,
        write_probes,
        direct_reads,
        lpac,
    );
    let (process_handle, thread_handle) = match spawn_outcome {
        Ok(h) => h,
        Err(e) => {
            unsafe {
                let _ = CloseHandle(pipe_handle);
            }
            return Err(e);
        }
    };

    // 3. Resume the suspended child so it can connect to the pipe, then
    //    wait for the JSON message + exit.
    let _ = unsafe { ResumeThread(thread_handle) };

    let child_json = match read_one_pipe_message(pipe_handle) {
        Ok(s) => match serde_json::from_str::<serde_json::Value>(&s) {
            Ok(v) => Some(v),
            Err(e) => {
                errors.push(format!("child json parse: {e}; raw={s:?}"));
                None
            }
        },
        Err(e) => {
            errors.push(format!("pipe read: {e}"));
            None
        }
    };

    // 4. Reap.
    let wait_status = match unsafe { WaitForSingleObject(process_handle, 5_000) } {
        WAIT_OBJECT_0 => "ok",
        WAIT_TIMEOUT => {
            let _ = unsafe { TerminateProcess(process_handle, 99) };
            errors.push("child timed out (5s)".to_string());
            "timeout"
        }
        _ => "wait failed",
    };

    let exit_code = {
        let mut code = 0u32;
        if unsafe { GetExitCodeProcess(process_handle, &mut code).is_ok() } {
            Some(code)
        } else {
            None
        }
    };

    unsafe {
        let _ = CloseHandle(process_handle);
        let _ = CloseHandle(thread_handle);
        let _ = CloseHandle(pipe_handle);
    }

    Ok(AcChildReport {
        child_exe: child_exe.to_path_buf(),
        pipe_name,
        exit_code,
        wait_status: wait_status.to_string(),
        child_json,
        errors,
    })
}

fn rand_hex16() -> String {
    let mut buf = [0u8; 8];
    let _ = getrandom_fallback(&mut buf);
    let mut out = String::with_capacity(16);
    for b in buf {
        out.push_str(&format!("{:02x}", b));
    }
    out
}

fn getrandom_fallback(buf: &mut [u8]) -> Result<(), ()> {
    // Avoid pulling getrandom-the-crate; use BCryptGenRandom-equivalent via
    // a Mix of pid + wallclock for the spike. Uniqueness over a single run
    // is sufficient.
    use std::time::SystemTime;
    let nanos = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map(|d| d.subsec_nanos())
        .unwrap_or(0);
    let pid = std::process::id();
    let mut seed = (pid as u64).wrapping_mul(2862933555777941757)
        ^ (nanos as u64).wrapping_mul(3037000493);
    for slot in buf {
        seed = seed.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
        *slot = (seed >> 33) as u8;
    }
    Ok(())
}

fn to_wide_z(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

fn create_pipe_for_ac(pipe_name: &str, ac_sid: &str) -> Result<HANDLE, String> {
    // SDDL: launching user / Administrators / SYSTEM get full control; the
    // AC SID gets generic-all so it can write the JSON body. We could trim
    // this to write-only in production, but for the spike GA keeps the
    // failure-mode analysis simple — `Win32 ERROR_ACCESS_DENIED` (5) here
    // would unambiguously mean "DACL is wrong" rather than "AC needs an
    // access right we didn't grant."
    let sddl = format!("D:(A;;GA;;;SY)(A;;GA;;;BA)(A;;GA;;;OW)(A;;GA;;;{ac_sid})");
    let sddl_w = to_wide_z(&sddl);

    let mut psd = PSECURITY_DESCRIPTOR::default();
    unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            PCWSTR(sddl_w.as_ptr()),
            SDDL_REVISION_1 as u32,
            &mut psd,
            None,
        )
        .map_err(|e| format!("ConvertStringSecurityDescriptorToSecurityDescriptorW: {e}"))?;
    }

    let sa = SECURITY_ATTRIBUTES {
        nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: psd.0,
        bInheritHandle: false.into(),
    };

    let name_w = to_wide_z(pipe_name);
    let pipe = unsafe {
        CreateNamedPipeW(
            PCWSTR(name_w.as_ptr()),
            PIPE_ACCESS_INBOUND | FILE_FLAG_FIRST_PIPE_INSTANCE,
            PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT,
            1,
            0,
            64 * 1024,
            0,
            Some(&sa),
        )
    };

    unsafe {
        let _ = LocalFree(Some(HLOCAL(psd.0 as *mut c_void)));
    }

    if pipe == INVALID_HANDLE_VALUE {
        let code = unsafe { GetLastError().0 };
        return Err(format!("CreateNamedPipeW failed (Win32 {code})"));
    }
    Ok(pipe)
}

fn read_one_pipe_message(pipe: HANDLE) -> Result<String, String> {
    // Block until the AC child connects.
    let connect = unsafe { ConnectNamedPipe(pipe, None) };
    if connect.is_err() {
        let code = unsafe { GetLastError().0 };
        if code != ERROR_PIPE_CONNECTED.0 {
            return Err(format!("ConnectNamedPipe failed (Win32 {code})"));
        }
    }

    let mut out = Vec::with_capacity(4096);
    let mut buf = [0u8; 4096];
    loop {
        let mut n = 0u32;
        let ok = unsafe { ReadFile(pipe, Some(&mut buf), Some(&mut n), None) };
        if ok.is_err() || n == 0 {
            break;
        }
        out.extend_from_slice(&buf[..n as usize]);
    }
    String::from_utf8(out).map_err(|e| format!("pipe payload not UTF-8: {e}"))
}

fn spawn_ac(
    exe: &Path,
    virt_root: &Path,
    pipe_name: &str,
    ac_sid_string: &str,
    check_dirs: &[String],
    write_probes: &[String],
    direct_reads: &[String],
    lpac: bool,
) -> Result<(HANDLE, HANDLE), String> {
    // Parse the AC SID string back to a binary SID for SECURITY_CAPABILITIES.
    let sid_w = to_wide_z(ac_sid_string);
    let mut psid = PSID::default();
    unsafe {
        ConvertStringSidToSidW(PCWSTR(sid_w.as_ptr()), &mut psid)
            .map_err(|e| format!("ConvertStringSidToSidW: {e}"))?;
    }

    let security_capabilities = SECURITY_CAPABILITIES {
        AppContainerSid: psid,
        Capabilities: ptr::null_mut(),
        CapabilityCount: 0,
        Reserved: 0,
    };

    // Build attribute list with SECURITY_CAPABILITIES (+ optional
    // ALL_APPLICATION_PACKAGES_POLICY for LPAC).
    let attr_count: u32 = if lpac { 2 } else { 1 };
    let mut attr_size = 0usize;
    unsafe {
        let _ = InitializeProcThreadAttributeList(None, attr_count, None, &mut attr_size);
    }
    if attr_size == 0 {
        free_sid(psid);
        return Err("InitializeProcThreadAttributeList sizing returned 0".to_string());
    }
    let mut attr_buf = vec![0u8; attr_size];
    let attr_list = LPPROC_THREAD_ATTRIBUTE_LIST(attr_buf.as_mut_ptr() as *mut c_void);
    unsafe {
        InitializeProcThreadAttributeList(Some(attr_list), attr_count, None, &mut attr_size)
            .map_err(|e| {
                free_sid(psid);
                format!("InitializeProcThreadAttributeList: {e}")
            })?;
    }

    let sec_caps_ptr: *const SECURITY_CAPABILITIES = &security_capabilities;
    unsafe {
        UpdateProcThreadAttribute(
            attr_list,
            0,
            PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES,
            Some(sec_caps_ptr as *const c_void),
            std::mem::size_of::<SECURITY_CAPABILITIES>(),
            None,
            None,
        )
        .map_err(|e| {
            DeleteProcThreadAttributeList(attr_list);
            free_sid(psid);
            format!("UpdateProcThreadAttribute(SECURITY_CAPABILITIES): {e}")
        })?;
    }

    // LPAC opt-out: the child loses implicit ALL APPLICATION PACKAGES
    // membership in its LowBox SIDs. Files whose DACL grants AAP only
    // (and not the specific AC SID) become inaccessible.
    let aap_optout: u32 = PROCESS_CREATION_ALL_APPLICATION_PACKAGES_OPT_OUT;
    if lpac {
        unsafe {
            UpdateProcThreadAttribute(
                attr_list,
                0,
                PROC_THREAD_ATTRIBUTE_ALL_APPLICATION_PACKAGES_POLICY,
                Some(&aap_optout as *const u32 as *const c_void),
                std::mem::size_of::<u32>(),
                None,
                None,
            )
            .map_err(|e| {
                DeleteProcThreadAttributeList(attr_list);
                free_sid(psid);
                format!("UpdateProcThreadAttribute(ALL_APP_PACKAGES_POLICY): {e}")
            })?;
        }
    }

    // Build the command line.  --check-dir is repeatable.
    let mut cmdline = format!(
        "\"{exe}\" --root \"{root}\" --pipe \"{pipe}\"",
        exe = exe.to_string_lossy(),
        root = virt_root.to_string_lossy(),
        pipe = pipe_name,
    );
    for d in check_dirs {
        cmdline.push_str(" --check-dir \"");
        cmdline.push_str(d);
        cmdline.push('"');
    }
    for b in write_probes {
        cmdline.push_str(" --write-probe \"");
        cmdline.push_str(b);
        cmdline.push('"');
    }
    for p in direct_reads {
        cmdline.push_str(" --direct-read \"");
        cmdline.push_str(p);
        cmdline.push('"');
    }
    let mut cmdline_w = to_wide_z(&cmdline);

    let si = STARTUPINFOEXW {
        StartupInfo: STARTUPINFOW {
            cb: std::mem::size_of::<STARTUPINFOEXW>() as u32,
            ..Default::default()
        },
        lpAttributeList: attr_list,
    };
    let mut pi = PROCESS_INFORMATION::default();

    let create = unsafe {
        CreateProcessW(
            PCWSTR::null(),
            Some(PWSTR(cmdline_w.as_mut_ptr())),
            None,
            None,
            false,
            EXTENDED_STARTUPINFO_PRESENT | CREATE_UNICODE_ENVIRONMENT | CREATE_SUSPENDED,
            None,
            PCWSTR::null(),
            &si.StartupInfo,
            &mut pi,
        )
    };

    let result = if create.is_err() {
        let code = unsafe { GetLastError().0 };
        Err(format!("CreateProcessW (AC): Win32 {code}"))
    } else {
        Ok((pi.hProcess, pi.hThread))
    };

    unsafe {
        DeleteProcThreadAttributeList(attr_list);
        free_sid(psid);
    }
    result
}

fn free_sid(psid: PSID) {
    // ConvertStringSidToSidW allocates via LocalAlloc; LocalFree releases it.
    if !psid.0.is_null() {
        unsafe {
            let _ = LocalFree(Some(HLOCAL(psid.0)));
        }
    }
}

// Removed unused helper stub.

