// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! In-sandbox UI mitigation probe.
//!
//! Reports `TAG=PASS` when the corresponding `JOB_OBJECT_UILIMIT_*` bit
//! (or Win32k mitigation) actually blocks the operation it documents,
//! `TAG=FAIL` when the operation succeeded, and an additional
//! `TAG=DIAG <reason>` line when the failure mode was unexpected.
//!
//! Critical: `user32.dll` is loaded at runtime via `LoadLibraryW` so the
//! Win32k syscall-disable mitigation does not kill this process at loader
//! resolution time. `kernel32` calls are safe to static-link.

use std::env;
use std::ffi::c_void;
use std::iter;
use std::path::Path;
use std::thread;
use std::time::{Duration, Instant};

type Bool = i32;
type Dword = u32;
type Hwnd = *mut c_void;
type Hmodule = *mut c_void;
type Hglobal = *mut c_void;
type Hdesk = *mut c_void;
type Atom = u16;
type FarProc = *const c_void;
type LpcWstr = *const u16;
type LpVoid = *mut c_void;

/// Optional `--key=value` parameters supplied by the test harness on the
/// command line for probes that require host coordination (GLOBALATOMS,
/// HANDLES). When absent (e.g. a developer running the probe by hand) those
/// probes emit diagnostics instead of attempting the isolation checks.
#[derive(Debug, Default, Clone)]
struct ProbeArgs {
    /// Name of an atom the host planted in its session-global atom table.
    /// The contained probe must NOT be able to find it.
    host_name: Option<String>,
    /// Name of an atom the contained probe creates in its (private) atom
    /// table. The host must NOT be able to find it.
    guest_name: Option<String>,
    /// File the probe creates once `guest_name` has been added, signalling the
    /// host that it may check its own atom table.
    ready_file: Option<String>,
    /// File the host creates once it has finished checking, releasing the
    /// probe to delete its atom and exit.
    release_file: Option<String>,
    /// HWND (as an integer) of a window owned by the host process — i.e. a
    /// USER handle owned by a process *outside* the job. Under
    /// `JOB_OBJECT_UILIMIT_HANDLES` the contained probe must NOT be able to
    /// use it (e.g. query its owning thread/process).
    handle_hwnd: Option<usize>,
    /// The process id that owns `handle_hwnd` (the host process). If the probe
    /// can read the owner back via `GetWindowThreadProcessId` and it matches,
    /// the handle restriction failed.
    handle_pid: Option<u32>,
}

#[repr(C)]
#[derive(Default, Clone, Copy)]
struct Point {
    x: i32,
    y: i32,
}

#[repr(C)]
#[derive(Default, Clone, Copy)]
struct Msg {
    hwnd: Hwnd,
    message: u32,
    w_param: usize,
    l_param: isize,
    time: u32,
    pt: Point,
    private: u32,
}

#[repr(C)]
#[derive(Default, Clone, Copy)]
struct SecurityAttributes {
    n_length: Dword,
    lp_security_descriptor: LpVoid,
    b_inherit_handle: Bool,
}

/// `MOUSEINPUT` payload of `INPUT`. Retained as the largest union member so
/// the `INPUT` struct is sized correctly (`SendInput` validates `cbSize`); the
/// probe only ever fills the keyboard variant, so its fields are never read.
#[repr(C)]
#[derive(Default, Clone, Copy)]
#[allow(dead_code)]
struct MouseInput {
    dx: i32,
    dy: i32,
    mouse_data: u32,
    dw_flags: u32,
    time: u32,
    dw_extra_info: usize,
}

/// `KEYBDINPUT` payload of `INPUT`.
#[repr(C)]
#[derive(Default, Clone, Copy)]
struct KeybdInput {
    w_vk: u16,
    w_scan: u16,
    dw_flags: u32,
    time: u32,
    dw_extra_info: usize,
}

/// Union of the `INPUT` payloads (sized by the largest member, `MOUSEINPUT`).
#[repr(C)]
union InputUnion {
    mi: MouseInput,
    ki: KeybdInput,
}

/// `INPUT` for `SendInput`.
#[repr(C)]
struct Input {
    input_type: u32,
    u: InputUnion,
}

/// `WNDCLASSEXW` for registering the probe's own transient window class. The
/// INJECTION probe creates and foregrounds its own top-level window so the
/// kernel's GPQ-foreground-accessible check (which precedes the injection job
/// limit and silently skips input when the foreground belongs to another
/// inaccessible process) passes and the injection limit is actually evaluated.
#[repr(C)]
struct WndClassExW {
    cb_size: u32,
    style: u32,
    lpfn_wnd_proc: *const c_void,
    cb_cls_extra: i32,
    cb_wnd_extra: i32,
    h_instance: Hmodule,
    h_icon: *mut c_void,
    h_cursor: *mut c_void,
    hbr_background: *mut c_void,
    lpsz_menu_name: *const u16,
    lpsz_class_name: *const u16,
    h_icon_sm: *mut c_void,
}

const CF_TEXT: u32 = 1;
const SPI_SETMOUSESPEED: u32 = 0x0071;
const SPIF_SENDCHANGE: u32 = 0x0002;
const EWX_LOGOFF: u32 = 0x00000000;
const EWX_FORCEIFHUNG: u32 = 0x00000010;
const DESKTOP_CREATEWINDOW: u32 = 0x0002;
const GENERIC_ALL: u32 = 0x10000000;
const INPUT_KEYBOARD: u32 = 1;
const KEYEVENTF_KEYUP: u32 = 0x0002;
/// `VK_NONAME` — a reserved no-op virtual key. Injecting a lone key-up of it is
/// a real synthetic-input event with no side effect on any focused window.
const VK_NONAME: u16 = 0xFC;
/// `ERROR_ACCESS_DENIED` (Win32). The kernel's injection job-limit denial path
/// (`DoInputCheck` → `xxxSendInput`) sets this via `UserSetLastError` when it
/// blocks an injection, so a genuine INJECTION block is distinguishable from a
/// zero-insert caused by some unrelated condition.
const ERROR_ACCESS_DENIED: u32 = 5;
/// Window styles for the probe's own transient foreground window.
const WS_VISIBLE: u32 = 0x1000_0000;
const WS_OVERLAPPEDWINDOW: u32 = 0x00CF_0000;
const SW_SHOW: i32 = 5;
const PM_REMOVE: u32 = 0x0001;

extern "system" {
    fn LoadLibraryW(name: LpcWstr) -> Hmodule;
    fn GetProcAddress(module: Hmodule, name: *const u8) -> FarProc;
    fn GlobalAddAtomW(name: LpcWstr) -> Atom;
    fn GlobalFindAtomW(name: LpcWstr) -> Atom;
    fn GlobalDeleteAtom(atom: Atom) -> Atom;
    fn GetLastError() -> Dword;
    fn GetModuleHandleW(name: LpcWstr) -> Hmodule;
    fn GetCurrentProcessId() -> Dword;
}

fn to_wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(iter::once(0)).collect()
}

fn load_user32() -> Option<Hmodule> {
    let wide = to_wide("user32.dll");
    let h = unsafe { LoadLibraryW(wide.as_ptr()) };
    if h.is_null() {
        None
    } else {
        Some(h)
    }
}

fn get_proc(module: Hmodule, name: &str) -> Option<FarProc> {
    let mut bytes: Vec<u8> = name.bytes().collect();
    bytes.push(0);
    let p = unsafe { GetProcAddress(module, bytes.as_ptr()) };
    if p.is_null() {
        None
    } else {
        Some(p)
    }
}

fn emit_pass(tag: &str) {
    println!("{}=PASS", tag);
}

/// Gate on potentially destructive probes (EXITWINDOWS, WIN32K). A
/// developer running `wxc-ui-probe EXITWINDOWS` directly on an
/// interactive desktop — without the explicit override — would
/// otherwise attempt to log out the user session.
///
/// The gate is an env-var allow-list rather than `IsAppContainerProcess`
/// auto-detection: there is no documented kernel32 export with that
/// name (the supported AC-detection API is
/// `GetTokenInformation(TokenIsAppContainer)`, which would pull in
/// advapi32 and re-open the Win32k-loader-resolution concern the
/// rest of this binary deliberately defers). Harnesses that legitimately
/// invoke destructive probes (the AppContainer wxc-exec sandbox) must
/// set `MXC_PROBE_DESTRUCTIVE_OK=1` in the child's environment.
fn destructive_probe_allowed() -> bool {
    matches!(env::var("MXC_PROBE_DESTRUCTIVE_OK").as_deref(), Ok("1"))
}

fn refuse_destructive(tag: &str) {
    emit_diag(
        tag,
        "refused: MXC_PROBE_DESTRUCTIVE_OK!=1 (set =1 to allow inside a sandbox)",
    );
    emit_fail(tag);
}

fn emit_fail(tag: &str) {
    println!("{}=FAIL", tag);
}

/// Emitted when a probe could not actually exercise its restriction, so neither
/// PASS nor FAIL would be truthful. The harness records this as a skip rather
/// than a verdict. Used by INJECTION when the contained process cannot acquire
/// the foreground (so `SendInput`'s foreground-accessible check pre-empts the
/// injection job-limit check and the limit is never evaluated).
fn emit_inconclusive(tag: &str) {
    println!("{}=INCONCLUSIVE", tag);
}

fn emit_diag(tag: &str, reason: &str) {
    println!("{}=DIAG {}", tag, reason);
}

/// Block until `path` exists or `timeout` elapses. Returns whether the file
/// exists at the end. Used for the GLOBALATOMS guest->host handshake so the
/// probe never hangs indefinitely if the host fails to release it.
fn wait_for_file(path: &str, timeout: Duration) -> bool {
    let p = Path::new(path);
    let start = Instant::now();
    while start.elapsed() < timeout {
        if p.exists() {
            return true;
        }
        thread::sleep(Duration::from_millis(50));
    }
    p.exists()
}

/// Probe the GLOBALATOMS UI restriction (`JOB_OBJECT_UILIMIT_GLOBALATOMS`).
///
/// Unlike most UI limits this does NOT make the atom APIs fail: the documented
/// behavior is that each job gets its own private atom table, so
/// `GlobalAddAtomW` still succeeds inside the container. The restriction is
/// therefore verified as *isolation* between the host's session-global atom
/// table and the contained job's private table, in both directions:
///
/// * `GLOBALATOMS_HOST_TO_GUEST` — the host plants an atom in its global table
///   and passes the name via `--atom-host-name`. PASS means this contained
///   process CANNOT find it (`GlobalFindAtomW` -> 0). Decided here.
/// * `GLOBALATOMS_GUEST_TO_HOST` — this process adds an atom named by
///   `--atom-guest-name`, signals readiness by creating `--atom-ready-file`,
///   then blocks until the host creates `--atom-release-file`. While the atom
///   is held alive the host checks its own global table and records the
///   result; this function only performs the create / hold / cleanup half.
fn probe_globalatoms(args: &ProbeArgs) {
    // Direction 1: host -> guest. We must not see the host's global atom.
    match args.host_name.as_deref() {
        Some(name) => {
            let wide = to_wide(name);
            let found = unsafe { GlobalFindAtomW(wide.as_ptr()) };
            if found == 0 {
                emit_pass("GLOBALATOMS_HOST_TO_GUEST");
            } else {
                emit_fail("GLOBALATOMS_HOST_TO_GUEST");
            }
        }
        None => emit_diag(
            "GLOBALATOMS_HOST_TO_GUEST",
            "no --atom-host-name provided (run via the harness)",
        ),
    }

    // Direction 2: guest -> host. The host must not see our atom. The PASS/FAIL
    // verdict is recorded host-side; here we create the atom and hold it alive
    // across the handshake.
    let guest = match args.guest_name.as_deref() {
        Some(g) => g,
        None => {
            emit_diag(
                "GLOBALATOMS_GUEST_TO_HOST",
                "no --atom-guest-name provided (run via the harness)",
            );
            return;
        }
    };
    let wide = to_wide(guest);
    let atom = unsafe { GlobalAddAtomW(wide.as_ptr()) };
    if atom == 0 {
        emit_diag(
            "GLOBALATOMS_GUEST_TO_HOST",
            "GlobalAddAtomW failed unexpectedly",
        );
        return;
    }

    // Signal the host that the atom now exists, then hold it until released.
    if let Some(ready) = args.ready_file.as_deref() {
        if std::fs::write(ready, b"ready").is_err() {
            emit_diag("GLOBALATOMS_GUEST_TO_HOST", "failed to write ready file");
        }
    }
    if let Some(release) = args.release_file.as_deref() {
        // Wait comfortably longer than the harness's readiness window (30s) so a
        // loaded host can't make us delete the atom before its GlobalFindAtomW
        // check runs — which would otherwise read as a false "isolated". On
        // timeout, surface a DIAG so the (otherwise silent) stall is diagnosable
        // rather than being misread as a pass.
        let released = wait_for_file(release, Duration::from_secs(60));
        if !released {
            emit_diag(
                "GLOBALATOMS_GUEST_TO_HOST",
                "release file not seen within 60s; host check may be unreliable",
            );
        }
    }

    unsafe {
        let _ = GlobalDeleteAtom(atom);
    }
}

fn probe_readclipboard(user32: Hmodule) {
    type OpenClipboardFn = unsafe extern "system" fn(Hwnd) -> Bool;
    type CloseClipboardFn = unsafe extern "system" fn() -> Bool;
    type GetClipboardDataFn = unsafe extern "system" fn(u32) -> Hglobal;

    let open = match get_proc(user32, "OpenClipboard") {
        Some(p) => unsafe { std::mem::transmute::<FarProc, OpenClipboardFn>(p) },
        None => {
            emit_diag("READCLIPBOARD", "OpenClipboard not resolvable");
            emit_fail("READCLIPBOARD");
            return;
        }
    };
    let close = get_proc(user32, "CloseClipboard")
        .map(|p| unsafe { std::mem::transmute::<FarProc, CloseClipboardFn>(p) });
    let get_data = match get_proc(user32, "GetClipboardData") {
        Some(p) => unsafe { std::mem::transmute::<FarProc, GetClipboardDataFn>(p) },
        None => {
            emit_diag("READCLIPBOARD", "GetClipboardData not resolvable");
            emit_fail("READCLIPBOARD");
            return;
        }
    };

    let opened = unsafe { open(std::ptr::null_mut()) };
    if opened == 0 {
        emit_pass("READCLIPBOARD");
        return;
    }
    let data = unsafe { get_data(CF_TEXT) };
    if let Some(close) = close {
        unsafe {
            let _ = close();
        }
    }
    // If OpenClipboard succeeded, the read path is open. Empty-clipboard
    // returning NULL from GetClipboardData is not a restriction signal.
    let _ = data;
    emit_diag(
        "READCLIPBOARD",
        "OpenClipboard succeeded; read path not blocked",
    );
    emit_fail("READCLIPBOARD");
}

fn probe_writeclipboard(user32: Hmodule) {
    type OpenClipboardFn = unsafe extern "system" fn(Hwnd) -> Bool;
    type CloseClipboardFn = unsafe extern "system" fn() -> Bool;
    type EmptyClipboardFn = unsafe extern "system" fn() -> Bool;
    type SetClipboardDataFn = unsafe extern "system" fn(u32, Hglobal) -> Hglobal;

    let open = match get_proc(user32, "OpenClipboard") {
        Some(p) => unsafe { std::mem::transmute::<FarProc, OpenClipboardFn>(p) },
        None => {
            emit_diag("WRITECLIPBOARD", "OpenClipboard not resolvable");
            emit_fail("WRITECLIPBOARD");
            return;
        }
    };
    let empty = match get_proc(user32, "EmptyClipboard") {
        Some(p) => unsafe { std::mem::transmute::<FarProc, EmptyClipboardFn>(p) },
        None => {
            emit_diag("WRITECLIPBOARD", "EmptyClipboard not resolvable");
            emit_fail("WRITECLIPBOARD");
            return;
        }
    };
    let set_data = match get_proc(user32, "SetClipboardData") {
        Some(p) => unsafe { std::mem::transmute::<FarProc, SetClipboardDataFn>(p) },
        None => {
            emit_diag("WRITECLIPBOARD", "SetClipboardData not resolvable");
            emit_fail("WRITECLIPBOARD");
            return;
        }
    };
    let close = get_proc(user32, "CloseClipboard")
        .map(|p| unsafe { std::mem::transmute::<FarProc, CloseClipboardFn>(p) });

    let opened = unsafe { open(std::ptr::null_mut()) };
    if opened == 0 {
        emit_pass("WRITECLIPBOARD");
        return;
    }
    let emptied = unsafe { empty() };
    let set_ok = unsafe { set_data(CF_TEXT, std::ptr::null_mut()) };
    if let Some(close) = close {
        unsafe {
            let _ = close();
        }
    }
    if emptied == 0 && set_ok.is_null() {
        emit_pass("WRITECLIPBOARD");
    } else {
        emit_fail("WRITECLIPBOARD");
    }
}

fn probe_systemparameters(user32: Hmodule) {
    type SpiFn = unsafe extern "system" fn(u32, u32, LpVoid, u32) -> Bool;
    let spi = match get_proc(user32, "SystemParametersInfoW") {
        Some(p) => unsafe { std::mem::transmute::<FarProc, SpiFn>(p) },
        None => {
            emit_diag("SYSTEMPARAMETERS", "SystemParametersInfoW not resolvable");
            emit_fail("SYSTEMPARAMETERS");
            return;
        }
    };
    // Restoring the user's current speed would require GET first; we
    // intentionally pick a value that's a no-op when the call is allowed:
    // SPI_SETMOUSESPEED with pvParam = current speed. We can't query under
    // the mitigation, so use the OS default (10) and accept that an allowed
    // call slightly perturbs the user setting on the test host.
    let ok = unsafe { spi(SPI_SETMOUSESPEED, 0, 10usize as LpVoid, SPIF_SENDCHANGE) };
    if ok == 0 {
        emit_pass("SYSTEMPARAMETERS");
    } else {
        emit_fail("SYSTEMPARAMETERS");
    }
}

fn probe_displaysettings(user32: Hmodule) {
    type CdsFn = unsafe extern "system" fn(LpVoid, u32) -> i32;
    let cds = match get_proc(user32, "ChangeDisplaySettingsW") {
        Some(p) => unsafe { std::mem::transmute::<FarProc, CdsFn>(p) },
        None => {
            emit_diag("DISPLAYSETTINGS", "ChangeDisplaySettingsW not resolvable");
            emit_fail("DISPLAYSETTINGS");
            return;
        }
    };
    // NULL devmode + flags=0 -> restore registry settings as the active mode.
    // DISP_CHANGE_SUCCESSFUL = 0. Any non-zero is a refusal.
    let rc = unsafe { cds(std::ptr::null_mut(), 0) };
    if rc != 0 {
        emit_pass("DISPLAYSETTINGS");
    } else {
        emit_fail("DISPLAYSETTINGS");
    }
}

fn probe_desktop(user32: Hmodule) {
    type CreateDesktopWFn = unsafe extern "system" fn(
        LpcWstr,
        LpcWstr,
        LpVoid,
        u32,
        u32,
        *const SecurityAttributes,
    ) -> Hdesk;
    type CloseDesktopFn = unsafe extern "system" fn(Hdesk) -> Bool;

    let create = match get_proc(user32, "CreateDesktopW") {
        Some(p) => unsafe { std::mem::transmute::<FarProc, CreateDesktopWFn>(p) },
        None => {
            emit_diag("DESKTOP", "CreateDesktopW not resolvable");
            emit_fail("DESKTOP");
            return;
        }
    };
    let close = get_proc(user32, "CloseDesktop")
        .map(|p| unsafe { std::mem::transmute::<FarProc, CloseDesktopFn>(p) });

    let name = to_wide("mxc_probe_desktop");
    let h = unsafe {
        create(
            name.as_ptr(),
            std::ptr::null(),
            std::ptr::null_mut(),
            0,
            DESKTOP_CREATEWINDOW | GENERIC_ALL,
            std::ptr::null(),
        )
    };
    if h.is_null() {
        emit_pass("DESKTOP");
        return;
    }
    if let Some(close) = close {
        unsafe {
            let _ = close(h);
        }
    }
    emit_fail("DESKTOP");
}

fn probe_exitwindows(user32: Hmodule) {
    type ExitWindowsExFn = unsafe extern "system" fn(u32, u32) -> Bool;
    let ewx = match get_proc(user32, "ExitWindowsEx") {
        Some(p) => unsafe { std::mem::transmute::<FarProc, ExitWindowsExFn>(p) },
        None => {
            emit_diag("EXITWINDOWS", "ExitWindowsEx not resolvable");
            emit_fail("EXITWINDOWS");
            return;
        }
    };
    // EWX_FORCEIFHUNG | EWX_LOGOFF: if the UI limit is set we get FALSE
    // immediately; if it's not we get an attempted logoff, which is bad
    // even when the test host is privileged enough — but the UILIMIT bit
    // is meant to block this call before any session-side dispatch.
    let ok = unsafe { ewx(EWX_LOGOFF | EWX_FORCEIFHUNG, 0) };
    if ok == 0 {
        emit_pass("EXITWINDOWS");
    } else {
        emit_fail("EXITWINDOWS");
    }
}

/// Probe the HANDLES UI restriction (`JOB_OBJECT_UILIMIT_HANDLES`).
///
/// This limit does NOT stop `FindWindow` from returning HWNDs — it blocks
/// *using* USER handles owned by processes outside the job. Isolation is
/// verified by calling `GetWindowThreadProcessId` on a window the host created
/// (a USER handle owned by a process outside the job). Unlike `GetWindowTextW`
/// it does not send `WM_GETTEXT`, so it is not confounded by UIPI / message
/// filtering / the target pumping messages — it reads window-manager state
/// directly. PASS means we could NOT resolve the owner (the limit blocked the
/// handle use); FAIL means we read back the host's owning process id.
fn probe_handles(user32: Hmodule, args: &ProbeArgs) {
    let hwnd_val = match args.handle_hwnd {
        Some(h) => h,
        None => {
            emit_diag("HANDLES", "no --handle-hwnd provided (run via the harness)");
            return;
        }
    };
    type GetWindowThreadProcessIdFn = unsafe extern "system" fn(Hwnd, *mut Dword) -> Dword;
    let get_wtpid = match get_proc(user32, "GetWindowThreadProcessId") {
        Some(p) => unsafe { std::mem::transmute::<FarProc, GetWindowThreadProcessIdFn>(p) },
        None => {
            emit_diag("HANDLES", "GetWindowThreadProcessId not resolvable");
            emit_fail("HANDLES");
            return;
        }
    };

    let hwnd = hwnd_val as Hwnd;
    let mut pid: Dword = 0;
    let tid = unsafe { get_wtpid(hwnd, &mut pid as *mut Dword) };
    if tid == 0 {
        // Could not access the external window handle -> the limit blocked it.
        emit_pass("HANDLES");
        return;
    }

    match args.handle_pid {
        Some(expected) if pid == expected => emit_fail("HANDLES"),
        Some(expected) => {
            emit_diag(
                "HANDLES",
                &format!("resolved owner pid {pid} != expected {expected}"),
            );
            emit_fail("HANDLES");
        }
        // We resolved an owner but have no expected pid to compare against, so
        // we can't make an isolation verdict. Per the tool's contract (missing
        // harness args -> DIAG + skip), emit a diagnostic instead of a FAIL that
        // would look like a real "handle restriction failed" result. The harness
        // always passes --handle-pid, so this only affects ad-hoc runs.
        None => emit_diag(
            "HANDLES",
            &format!("resolved owner pid {pid} but no --handle-pid provided to compare (run via the harness)"),
        ),
    }
}

/// Probe the INJECTION UI restriction (`JOB_OBJECT_UILIMIT_INJECTION`, build
/// 26100+). The limit blocks a job process from injecting synthetic input via
/// `SendInput`, enforced in the kernel against the caller.
///
/// Subtlety that this probe must work around: in the kernel's input check
/// (`DoInputCheck`), the **foreground-accessible** test runs *before* the
/// injection job-limit test, and `xxxSendInput` silently `continue`s (skips the
/// input, returns success, leaves `GetLastError` untouched) when the foreground
/// window belongs to another process the caller cannot access. A contained
/// (AppContainer) process on an interactive desktop almost always sees an
/// inaccessible foreground, so a naive `SendInput` returns `inserted=1, gle=0`
/// *without the injection limit ever being evaluated* — which would read as a
/// false "not enforced". The kernel deliberately allows a process to inject
/// into its **own** foreground window, so we create and foreground our own
/// top-level window first; only then does `SendInput` reach the injection
/// limit.
///
/// Outcomes:
/// * `PASS`  — we owned the foreground and `SendInput` injected 0 of 1 with
///   `gle=ERROR_ACCESS_DENIED`: the injection limit blocked it (enforced).
/// * `FAIL`  — we owned the foreground but the event went through
///   (`inserted=1, gle=0`): the limit did not block (genuinely not enforced).
/// * `INCONCLUSIVE` — either we could not create/own a foreground window (so the
///   foreground-accessible check would pre-empt the limit), or the injection was
///   dropped with a `gle` other than `ERROR_ACCESS_DENIED` (blocked for some
///   unrelated reason, not the job limit). Both are ambiguous, so the harness
///   records a skip rather than a verdict.
///
/// A DIAG line always reports `inserted`/expected and `GetLastError`.
fn probe_injection(user32: Hmodule) {
    type RegisterClassExWFn = unsafe extern "system" fn(*const WndClassExW) -> u16;
    #[allow(clippy::type_complexity)]
    type CreateWindowExWFn = unsafe extern "system" fn(
        u32,
        *const u16,
        *const u16,
        u32,
        i32,
        i32,
        i32,
        i32,
        Hwnd,
        *mut c_void,
        Hmodule,
        *mut c_void,
    ) -> Hwnd;
    type ShowWindowFn = unsafe extern "system" fn(Hwnd, i32) -> Bool;
    type SetForegroundWindowFn = unsafe extern "system" fn(Hwnd) -> Bool;
    type BringWindowToTopFn = unsafe extern "system" fn(Hwnd) -> Bool;
    type GetForegroundWindowFn = unsafe extern "system" fn() -> Hwnd;
    type GetWindowThreadProcessIdFn = unsafe extern "system" fn(Hwnd, *mut Dword) -> Dword;
    type DestroyWindowFn = unsafe extern "system" fn(Hwnd) -> Bool;
    type UnregisterClassWFn = unsafe extern "system" fn(*const u16, Hmodule) -> Bool;
    type PeekMessageWFn = unsafe extern "system" fn(*mut Msg, Hwnd, u32, u32, u32) -> Bool;
    type TranslateMessageFn = unsafe extern "system" fn(*const Msg) -> Bool;
    type DispatchMessageWFn = unsafe extern "system" fn(*const Msg) -> isize;
    type SendInputFn = unsafe extern "system" fn(u32, *const Input, i32) -> u32;

    macro_rules! resolve {
        ($name:literal, $ty:ty) => {
            match get_proc(user32, $name) {
                Some(p) => unsafe { std::mem::transmute::<FarProc, $ty>(p) },
                None => {
                    emit_diag("INJECTION", concat!($name, " not resolvable"));
                    emit_inconclusive("INJECTION");
                    return;
                }
            }
        };
    }

    let register_class = resolve!("RegisterClassExW", RegisterClassExWFn);
    let create_window = resolve!("CreateWindowExW", CreateWindowExWFn);
    let show_window = resolve!("ShowWindow", ShowWindowFn);
    let set_foreground = resolve!("SetForegroundWindow", SetForegroundWindowFn);
    let bring_to_top = resolve!("BringWindowToTop", BringWindowToTopFn);
    let get_foreground = resolve!("GetForegroundWindow", GetForegroundWindowFn);
    let get_wtpid = resolve!("GetWindowThreadProcessId", GetWindowThreadProcessIdFn);
    let destroy_window = resolve!("DestroyWindow", DestroyWindowFn);
    let unregister_class = resolve!("UnregisterClassW", UnregisterClassWFn);
    let peek_message = resolve!("PeekMessageW", PeekMessageWFn);
    let translate_message = resolve!("TranslateMessage", TranslateMessageFn);
    let dispatch_message = resolve!("DispatchMessageW", DispatchMessageWFn);
    let send_input = resolve!("SendInput", SendInputFn);
    // DefWindowProcW is used directly as the class window procedure.
    let def_window_proc: FarProc = match get_proc(user32, "DefWindowProcW") {
        Some(p) => p,
        None => {
            emit_diag("INJECTION", "DefWindowProcW not resolvable");
            emit_inconclusive("INJECTION");
            return;
        }
    };

    let class_name = to_wide("MxcInjectionProbeWindow");
    let title = to_wide("MxcInjectionProbe");
    let hinstance = unsafe { GetModuleHandleW(std::ptr::null()) };
    let wc = WndClassExW {
        cb_size: std::mem::size_of::<WndClassExW>() as u32,
        style: 0,
        lpfn_wnd_proc: def_window_proc,
        cb_cls_extra: 0,
        cb_wnd_extra: 0,
        h_instance: hinstance,
        h_icon: std::ptr::null_mut(),
        h_cursor: std::ptr::null_mut(),
        hbr_background: std::ptr::null_mut(),
        lpsz_menu_name: std::ptr::null(),
        lpsz_class_name: class_name.as_ptr(),
        h_icon_sm: std::ptr::null_mut(),
    };
    let class_atom = unsafe { register_class(&wc as *const WndClassExW) };
    if class_atom == 0 {
        emit_diag(
            "INJECTION",
            &format!("RegisterClassExW failed gle={}", unsafe { GetLastError() }),
        );
        emit_inconclusive("INJECTION");
        return;
    }
    let hwnd = unsafe {
        create_window(
            0,
            class_name.as_ptr(),
            title.as_ptr(),
            WS_OVERLAPPEDWINDOW | WS_VISIBLE,
            0,
            0,
            200,
            100,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            hinstance,
            std::ptr::null_mut(),
        )
    };
    if hwnd.is_null() {
        emit_diag(
            "INJECTION",
            &format!("CreateWindowExW failed gle={}", unsafe { GetLastError() }),
        );
        unsafe { unregister_class(class_name.as_ptr(), hinstance) };
        emit_inconclusive("INJECTION");
        return;
    }

    // Acquire the foreground (retry: activation can require a message pump).
    let self_pid = unsafe { GetCurrentProcessId() };
    let mut msg = Msg::default();
    let mut owns_foreground = false;
    let mut fg_pid: Dword = 0;
    for _ in 0..20 {
        unsafe {
            show_window(hwnd, SW_SHOW);
            bring_to_top(hwnd);
            set_foreground(hwnd);
            while peek_message(&mut msg as *mut Msg, std::ptr::null_mut(), 0, 0, PM_REMOVE) != 0 {
                translate_message(&msg as *const Msg);
                dispatch_message(&msg as *const Msg);
            }
        }
        let fg = unsafe { get_foreground() };
        fg_pid = 0;
        if !fg.is_null() {
            unsafe { get_wtpid(fg, &mut fg_pid as *mut Dword) };
        }
        if !fg.is_null() && fg_pid == self_pid {
            owns_foreground = true;
            break;
        }
        thread::sleep(Duration::from_millis(25));
    }

    if !owns_foreground {
        emit_diag(
            "INJECTION",
            &format!(
                "inconclusive: could not own foreground (fg owner pid {fg_pid} != self {self_pid}); \
                 SendInput's foreground-accessible check pre-empts the injection limit"
            ),
        );
        unsafe {
            destroy_window(hwnd);
            unregister_class(class_name.as_ptr(), hinstance);
        }
        emit_inconclusive("INJECTION");
        return;
    }

    // We own the foreground -> the kernel reaches the injection job-limit check.
    let input = Input {
        input_type: INPUT_KEYBOARD,
        u: InputUnion {
            ki: KeybdInput {
                w_vk: VK_NONAME,
                w_scan: 0,
                dw_flags: KEYEVENTF_KEYUP,
                time: 0,
                dw_extra_info: 0,
            },
        },
    };
    let inserted = unsafe {
        send_input(
            1,
            &input as *const Input,
            std::mem::size_of::<Input>() as i32,
        )
    };
    let gle = if inserted < 1 {
        unsafe { GetLastError() }
    } else {
        0
    };

    unsafe {
        destroy_window(hwnd);
        unregister_class(class_name.as_ptr(), hinstance);
    }

    emit_diag(
        "INJECTION",
        &format!("SendInput injected {inserted}/1 gle={gle} (owns foreground)"),
    );
    if inserted == 0 {
        // Blocked. Only a denial by the injection job limit sets
        // ERROR_ACCESS_DENIED; a zero-insert with any other gle was blocked for
        // some unrelated reason, so the limit was not what we observed.
        if gle == ERROR_ACCESS_DENIED {
            emit_pass("INJECTION");
        } else {
            emit_inconclusive("INJECTION");
        }
    } else {
        emit_fail("INJECTION");
    }
}

fn probe_win32k(user32: Hmodule) {
    type GetMessageWFn = unsafe extern "system" fn(*mut Msg, Hwnd, u32, u32) -> Bool;
    let get_message = match get_proc(user32, "GetMessageW") {
        Some(p) => unsafe { std::mem::transmute::<FarProc, GetMessageWFn>(p) },
        None => {
            emit_diag("WIN32K", "GetMessageW not resolvable");
            emit_fail("WIN32K");
            return;
        }
    };
    // Win32k mitigation kills the process on the syscall; the harness
    // treats "WIN32K never printed + non-zero exit" as PASS. If we reach
    // the line after the call, the mitigation did NOT fire.
    let mut msg = Msg::default();
    let _ = unsafe { get_message(&mut msg as *mut Msg, std::ptr::null_mut(), 0, 0) };
    emit_fail("WIN32K");
}

fn run_probe(tag: &str, user32: Option<Hmodule>, probe_args: &ProbeArgs) {
    match tag {
        "GLOBALATOMS" => probe_globalatoms(probe_args),
        "READCLIPBOARD" => match user32 {
            Some(h) => probe_readclipboard(h),
            None => {
                emit_diag("READCLIPBOARD", "user32.dll not loadable");
                emit_fail("READCLIPBOARD");
            }
        },
        "WRITECLIPBOARD" => match user32 {
            Some(h) => probe_writeclipboard(h),
            None => {
                emit_diag("WRITECLIPBOARD", "user32.dll not loadable");
                emit_fail("WRITECLIPBOARD");
            }
        },
        "SYSTEMPARAMETERS" => match user32 {
            Some(h) => probe_systemparameters(h),
            None => {
                emit_diag("SYSTEMPARAMETERS", "user32.dll not loadable");
                emit_fail("SYSTEMPARAMETERS");
            }
        },
        "DISPLAYSETTINGS" => match user32 {
            Some(h) => probe_displaysettings(h),
            None => {
                emit_diag("DISPLAYSETTINGS", "user32.dll not loadable");
                emit_fail("DISPLAYSETTINGS");
            }
        },
        "DESKTOP" => match user32 {
            Some(h) => probe_desktop(h),
            None => {
                emit_diag("DESKTOP", "user32.dll not loadable");
                emit_fail("DESKTOP");
            }
        },
        "EXITWINDOWS" => match user32 {
            Some(h) if destructive_probe_allowed() => probe_exitwindows(h),
            Some(_) => refuse_destructive("EXITWINDOWS"),
            None => {
                emit_diag("EXITWINDOWS", "user32.dll not loadable");
                emit_fail("EXITWINDOWS");
            }
        },
        "HANDLES" => match user32 {
            Some(h) => probe_handles(h, probe_args),
            None => {
                emit_diag("HANDLES", "user32.dll not loadable");
                emit_fail("HANDLES");
            }
        },
        "INJECTION" => match user32 {
            Some(h) => probe_injection(h),
            None => {
                emit_diag("INJECTION", "user32.dll not loadable");
                emit_fail("INJECTION");
            }
        },
        "WIN32K" => match user32 {
            Some(h) if destructive_probe_allowed() => probe_win32k(h),
            Some(_) => refuse_destructive("WIN32K"),
            None => {
                // user32 failed to load. Under the Win32k syscall-disable
                // mitigation (ui.disable=true) this is expected: user32's
                // initialization makes win32k syscalls the mitigation blocks,
                // so the GUI subsystem is unavailable. That is a
                // mitigation-honored outcome, NOT a failure — emit a DIAG only
                // and deliberately do not emit PASS or FAIL (the harness keys
                // off the ABSENCE of WIN32K=FAIL/PASS, same as the
                // killed-on-syscall path).
                emit_diag(
                    "WIN32K",
                    "user32.dll not loadable (GUI subsystem blocked by Win32k mitigation)",
                );
            }
        },
        other => {
            emit_diag(other, "unknown tag");
        }
    }
    // Flush after each probe so partial output survives a kernel kill.
    use std::io::Write;
    let _ = std::io::stdout().flush();
}

/// Collect raw arguments, falling back to `MXC_UI_PROBE_TAGS` when no
/// positional arguments are supplied. Returned values include both probe tags
/// and any `--key=value` flags; `parse_args` separates them.
fn collect_raw_args() -> Vec<String> {
    let mut raw: Vec<String> = env::args().skip(1).collect();
    if raw.is_empty() {
        if let Ok(v) = env::var("MXC_UI_PROBE_TAGS") {
            raw = v
                .split(|c: char| c == ',' || c.is_whitespace())
                .filter(|s| !s.is_empty())
                .map(|s| s.to_string())
                .collect();
        }
    }
    raw
}

/// Split raw arguments into positional probe tags and the optional
/// `--key=value` flags that parameterize the host-coordinated probes
/// (GLOBALATOMS handshake, HANDLES external-window access). Unknown flags are
/// ignored so the probe stays forward-compatible with the harness.
fn parse_args(raw: Vec<String>) -> (Vec<String>, ProbeArgs) {
    let mut tags = Vec::new();
    let mut args = ProbeArgs::default();
    for arg in raw {
        match arg.strip_prefix("--").and_then(|rest| rest.split_once('=')) {
            Some(("atom-host-name", value)) => args.host_name = Some(value.to_string()),
            Some(("atom-guest-name", value)) => args.guest_name = Some(value.to_string()),
            Some(("atom-ready-file", value)) => args.ready_file = Some(value.to_string()),
            Some(("atom-release-file", value)) => args.release_file = Some(value.to_string()),
            Some(("handle-hwnd", value)) => args.handle_hwnd = value.parse::<usize>().ok(),
            Some(("handle-pid", value)) => args.handle_pid = value.parse::<u32>().ok(),
            Some(_) => {} // unknown flag: ignore
            None => tags.push(arg),
        }
    }
    (tags, args)
}

fn main() {
    let (tags, probe_args) = parse_args(collect_raw_args());
    if tags.is_empty() {
        eprintln!(
            "usage: wxc-ui-probe <TAG>... (or MXC_UI_PROBE_TAGS=TAG,TAG); \
             valid tags: GLOBALATOMS READCLIPBOARD WRITECLIPBOARD SYSTEMPARAMETERS \
             DISPLAYSETTINGS DESKTOP EXITWINDOWS HANDLES INJECTION WIN32K. \
             GLOBALATOMS accepts --atom-host-name=, --atom-guest-name=, \
             --atom-ready-file=, --atom-release-file= for the host/guest \
             isolation handshake; HANDLES accepts --handle-hwnd=, --handle-pid= \
             for the external-window access check."
        );
        std::process::exit(2);
    }
    let user32 = load_user32();
    if user32.is_none() {
        eprintln!("LoadLibraryW(user32.dll) failed: gle={}", unsafe {
            GetLastError()
        });
    }

    // WIN32K is the only probe that may kill the process. Run it last so
    // every other probe gets a chance to report.
    let (win32k, rest): (Vec<_>, Vec<_>) = tags.into_iter().partition(|t| t == "WIN32K");
    for tag in rest {
        run_probe(&tag, user32, &probe_args);
    }
    for tag in win32k {
        run_probe(&tag, user32, &probe_args);
    }
}
