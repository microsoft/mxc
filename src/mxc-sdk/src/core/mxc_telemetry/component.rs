//! Optional loader for the external Required-telemetry component.
//!
//! When the component DLL sits next to this module and reports a supported ABI
//! version, the four Required events are written by it. Any failure leaves the
//! in-process provider in charge, so telemetry never blocks MXC.

use std::ffi::{c_char, CString};
use std::fs::{File, OpenOptions};
use std::os::windows::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Mutex;

use windows::core::{s, PCWSTR};
use windows::Win32::Foundation::HMODULE;
use windows::Win32::Storage::FileSystem::FILE_SHARE_READ;

use super::signature;
use windows::Win32::System::LibraryLoader::{
    GetModuleFileNameW, GetModuleHandleExW, GetProcAddress, LoadLibraryExW,
    GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS, GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
    LOAD_LIBRARY_SEARCH_DEFAULT_DIRS, LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR,
};

const COMPONENT_FILE: &str = "mxc_telemetry.dll";
const SUPPORTED_ABI: u32 = 2;
/// Signer the component must carry in release builds.
const COMPONENT_SIGNER: &str = "Microsoft Corporation";

#[repr(C)]
struct ExecutionEvent {
    size: u32,
    is_end: u32,
    exit_code: i32,
    duration_ms: u64,
    session_id: *const c_char,
    capture_denials: *const c_char,
    backend: *const c_char,
    sandbox_kind: *const c_char,
    outcome: *const c_char,
    failure_reason: *const c_char,
    phase: *const c_char,
    correlation_vector: *const c_char,
}

#[repr(C)]
struct ErrorEvent {
    size: u32,
    exit_code: i32,
    session_id: *const c_char,
    backend: *const c_char,
    sandbox_kind: *const c_char,
    error_type: *const c_char,
    phase: *const c_char,
    correlation_vector: *const c_char,
}

#[repr(C)]
struct ProcessExitedEvent {
    size: u32,
    process_id: u32,
    exit_code: i32,
    session_id: *const c_char,
    identity: *const c_char,
}

type AbiVersionFn = unsafe extern "C" fn() -> u32;
type InitFn = unsafe extern "C" fn(*const c_char, *const c_char, u32, *const u16) -> i32;
type ShutdownFn = unsafe extern "C" fn();
type WriteExecutionFn = unsafe extern "C" fn(*const ExecutionEvent) -> i32;
type WriteErrorFn = unsafe extern "C" fn(*const ErrorEvent) -> i32;
type WriteProcessExitedFn = unsafe extern "C" fn(*const ProcessExitedEvent) -> i32;

#[derive(Clone, Copy)]
struct Component {
    init: InitFn,
    shutdown: ShutdownFn,
    write_execution: WriteExecutionFn,
    write_error: WriteErrorFn,
    write_process_exited: WriteProcessExitedFn,
}

/// The loaded component stays mapped for the process lifetime; only its
/// registration is released at shutdown.
static LOADED: Mutex<Option<Option<Component>>> = Mutex::new(None);
static READY: AtomicBool = AtomicBool::new(false);

/// Path of the module containing this code (the executable or SDK DLL).
fn module_path() -> Option<PathBuf> {
    let mut module = HMODULE::default();
    // SAFETY: the address belongs to this module; the refcount is unchanged.
    unsafe {
        GetModuleHandleExW(
            GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
            PCWSTR(module_path as *const () as *const u16),
            &mut module,
        )
        .ok()?;
    }
    let mut buffer = [0u16; 1024];
    // SAFETY: `buffer` is a valid writable slice.
    let len = unsafe { GetModuleFileNameW(Some(module), &mut buffer) } as usize;
    if len == 0 || len >= buffer.len() {
        return None;
    }
    Some(PathBuf::from(String::from_utf16(&buffer[..len]).ok()?))
}

/// Opens the component so nobody can modify or replace it while it is
/// verified and loaded. Release builds require its Authenticode signature to be
/// trusted and issued to `COMPONENT_SIGNER`; the host's own signer does not
/// matter, because products that build MXC from source sign with their own
/// identity. Debug builds skip the signature check so local builds can use an
/// unsigned component.
fn open_trusted(path: &Path) -> Option<File> {
    let file = OpenOptions::new()
        .read(true)
        .share_mode(FILE_SHARE_READ.0)
        .open(path)
        .ok()?;
    if cfg!(debug_assertions) {
        return Some(file);
    }
    (signature::trusted_signer(&file, path)? == COMPONENT_SIGNER).then_some(file)
}

fn load() -> Option<Component> {
    let host = module_path()?;
    let path = host.parent()?.join(COMPONENT_FILE);
    if !path.is_file() {
        return None;
    }
    // Held until the library is loaded, and the loaded image keeps the file
    // locked afterwards.
    let _guard = open_trusted(&path)?;
    let wide: Vec<u16> = path
        .as_os_str()
        .to_string_lossy()
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect();
    // Full path with default-dir search only: no PATH or working-directory lookup.
    // SAFETY: `wide` is NUL-terminated.
    let module = unsafe {
        LoadLibraryExW(
            PCWSTR(wide.as_ptr()),
            None,
            LOAD_LIBRARY_SEARCH_DEFAULT_DIRS | LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR,
        )
    }
    .ok()?;

    macro_rules! symbol {
        ($name:expr, $ty:ty) => {{
            // SAFETY: the exported signature is fixed by the ABI version check below.
            let proc = unsafe { GetProcAddress(module, $name) }?;
            unsafe { std::mem::transmute::<unsafe extern "system" fn() -> isize, $ty>(proc) }
        }};
    }
    let abi_version: AbiVersionFn = symbol!(s!("mxc_telemetry_abi_version"), AbiVersionFn);
    // SAFETY: argument-free query.
    if unsafe { abi_version() } != SUPPORTED_ABI {
        return None;
    }
    Some(Component {
        init: symbol!(s!("mxc_telemetry_init"), InitFn),
        shutdown: symbol!(s!("mxc_telemetry_shutdown"), ShutdownFn),
        write_execution: symbol!(s!("mxc_telemetry_write_execution"), WriteExecutionFn),
        write_error: symbol!(s!("mxc_telemetry_write_error"), WriteErrorFn),
        write_process_exited: symbol!(
            s!("mxc_telemetry_write_process_exited"),
            WriteProcessExitedFn
        ),
    })
}

fn component() -> Option<Component> {
    let mut loaded = LOADED.lock().unwrap_or_else(|e| e.into_inner());
    *loaded.get_or_insert_with(load)
}

fn cstring(value: &str) -> CString {
    CString::new(value.replace('\0', "")).unwrap_or_default()
}

/// Registers the component's provider. Returns `false` when it is unavailable.
pub fn init(version: &str, channel: &str) -> bool {
    let Some(c) = component() else { return false };
    let Some(host) = module_path() else {
        return false;
    };
    let host: Vec<u16> = host
        .as_os_str()
        .to_string_lossy()
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect();
    let (version, channel) = (cstring(version), cstring(channel));
    // SAFETY: all strings are NUL-terminated and outlive the call.
    let ok = unsafe {
        (c.init)(
            version.as_ptr(),
            channel.as_ptr(),
            u32::from(cfg!(debug_assertions)),
            host.as_ptr(),
        )
    } == 0;
    READY.store(ok, Ordering::Release);
    ok
}

pub fn shutdown() {
    if READY.swap(false, Ordering::AcqRel) {
        if let Some(c) = component() {
            // SAFETY: paired with a successful `init`.
            unsafe { (c.shutdown)() };
        }
    }
}

fn ready() -> Option<Component> {
    if READY.load(Ordering::Acquire) {
        component()
    } else {
        None
    }
}

/// Each writer returns `true` when the component wrote the event.
#[allow(clippy::too_many_arguments)]
pub fn write_execution(
    is_end: bool,
    session_id: &str,
    capture_denials: &str,
    backend: &str,
    sandbox_kind: &str,
    exit_code: i32,
    outcome: &str,
    duration_ms: u64,
    failure_reason: &str,
    phase: &str,
    correlation_vector: &str,
) -> bool {
    let Some(c) = ready() else { return false };
    let strings = [
        session_id,
        capture_denials,
        backend,
        sandbox_kind,
        outcome,
        failure_reason,
        phase,
        correlation_vector,
    ]
    .map(cstring);
    let event = ExecutionEvent {
        size: std::mem::size_of::<ExecutionEvent>() as u32,
        is_end: u32::from(is_end),
        exit_code,
        duration_ms,
        session_id: strings[0].as_ptr(),
        capture_denials: strings[1].as_ptr(),
        backend: strings[2].as_ptr(),
        sandbox_kind: strings[3].as_ptr(),
        outcome: strings[4].as_ptr(),
        failure_reason: strings[5].as_ptr(),
        phase: strings[6].as_ptr(),
        correlation_vector: strings[7].as_ptr(),
    };
    // SAFETY: `event` and its strings live for the call.
    unsafe { (c.write_execution)(&event) == 0 }
}

pub fn write_error(
    session_id: &str,
    backend: &str,
    sandbox_kind: &str,
    error_type: &str,
    exit_code: i32,
    phase: &str,
    correlation_vector: &str,
) -> bool {
    let Some(c) = ready() else { return false };
    let strings = [
        session_id,
        backend,
        sandbox_kind,
        error_type,
        phase,
        correlation_vector,
    ]
    .map(cstring);
    let event = ErrorEvent {
        size: std::mem::size_of::<ErrorEvent>() as u32,
        exit_code,
        session_id: strings[0].as_ptr(),
        backend: strings[1].as_ptr(),
        sandbox_kind: strings[2].as_ptr(),
        error_type: strings[3].as_ptr(),
        phase: strings[4].as_ptr(),
        correlation_vector: strings[5].as_ptr(),
    };
    // SAFETY: `event` and its strings live for the call.
    unsafe { (c.write_error)(&event) == 0 }
}

pub fn write_process_exited(
    session_id: &str,
    identity: &str,
    process_id: u32,
    exit_code: i32,
) -> bool {
    let Some(c) = ready() else { return false };
    let strings = [session_id, identity].map(cstring);
    let event = ProcessExitedEvent {
        size: std::mem::size_of::<ProcessExitedEvent>() as u32,
        process_id,
        exit_code,
        session_id: strings[0].as_ptr(),
        identity: strings[1].as_ptr(),
    };
    // SAFETY: `event` and its strings live for the call.
    unsafe { (c.write_process_exited)(&event) == 0 }
}
