//! Clipboard probing for PLMTester.
//!
//! The clipboard is NOT gated by the AppContainer `clipboard` capability;
//! USER32's OpenClipboard/SetClipboardData/GetClipboardData run in the
//! caller's token and are gated by:
//!   * Window-station ACL (WINSTA_ACCESSCLIPBOARD)
//!   * Desktop ACL (DESKTOP_READOBJECTS | DESKTOP_WRITEOBJECTS)
//!   * UIPI (integrity level vs. current clipboard owner)
//!   * Owner-HWND rule (if the hwnd parameter is non-NULL, the caller
//!     must own it)
//!
//! On failure we dump enough context to tell which of those is biting.

use anyhow::{anyhow, Context, Result};
use clap::ValueEnum;

use windows::core::{w, PCWSTR, PWSTR};
use windows::Win32::Foundation::{
    CloseHandle, GetLastError, GlobalFree, HANDLE, HGLOBAL, HWND, LPARAM, LRESULT, WPARAM,
};
use windows::Win32::Graphics::Gdi::UpdateWindow;
use windows::Win32::Security::{
    GetSidSubAuthority, GetSidSubAuthorityCount, GetTokenInformation, TokenIntegrityLevel,
    TOKEN_MANDATORY_LABEL, TOKEN_QUERY,
};
use windows::Win32::System::Console::GetConsoleWindow;
use windows::Win32::System::DataExchange::{
    CloseClipboard, EmptyClipboard, GetClipboardData, GetClipboardOwner, OpenClipboard,
    SetClipboardData,
};
use windows::Win32::System::Diagnostics::Debug::{
    FormatMessageW, FORMAT_MESSAGE_FROM_SYSTEM, FORMAT_MESSAGE_IGNORE_INSERTS,
};
use windows::Win32::System::LibraryLoader::GetModuleHandleW;
use windows::Win32::System::Memory::{
    GlobalAlloc, GlobalLock, GlobalSize, GlobalUnlock, GMEM_MOVEABLE,
};
use windows::Win32::System::Ole::CF_UNICODETEXT;
use windows::Win32::System::StationsAndDesktops::{
    GetProcessWindowStation, GetThreadDesktop, GetUserObjectInformationW, UOI_NAME,
};
use windows::Win32::System::Threading::{
    GetCurrentProcess, GetCurrentThreadId, OpenProcess, OpenProcessToken,
    QueryFullProcessImageNameW, PROCESS_NAME_FORMAT, PROCESS_QUERY_LIMITED_INFORMATION,
};
use windows::Win32::UI::WindowsAndMessaging::{
    CreateWindowExW, DefWindowProcW, DestroyWindow, GetDesktopWindow, GetWindowThreadProcessId,
    RegisterClassW, ShowWindow, CW_USEDEFAULT, SW_SHOWNORMAL, WINDOW_EX_STYLE, WNDCLASSW,
    WS_OVERLAPPEDWINDOW, WS_VISIBLE,
};

unsafe extern "system" fn wndproc_thunk(hwnd: HWND, msg: u32, wp: WPARAM, lp: LPARAM) -> LRESULT {
    DefWindowProcW(hwnd, msg, wp, lp)
}

#[derive(Copy, Clone, Debug, ValueEnum)]
pub enum HwndSource {
    /// Pass HWND(NULL) — "ownerless" clipboard open. Useful as a
    /// counter-example: this is what fails most often under UIPI /
    /// sandboxed callers.
    None,
    /// Pass the current console window (GetConsoleWindow). The console
    /// window is owned by conhost.exe, NOT by this process, so this is
    /// usually the wrong choice for OpenClipboard's owner-HWND rule —
    /// kept for diagnostic comparison.
    Console,
    /// Create a small visible top-level window owned by this process
    /// and pass that. This is the correct "handle for the current
    /// process" and is the default.
    Owned,
    /// Pass GetDesktopWindow() — the shell desktop HWND. It is NOT
    /// owned by this process (it's owned by the window manager), so
    /// USER32 may reject it under the owner-HWND rule; useful as a
    /// diagnostic comparison.
    Desktop,
}

// --------------------------------------------------------------------------
// Diagnostics helpers
// --------------------------------------------------------------------------

fn format_win32_error(code: u32) -> String {
    let mut buf = [0u16; 512];
    let n = unsafe {
        FormatMessageW(
            FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
            None,
            code,
            0,
            PWSTR(buf.as_mut_ptr()),
            buf.len() as u32,
            None,
        )
    };
    String::from_utf16_lossy(&buf[..n as usize])
        .trim()
        .to_string()
}

fn last_error_pair() -> (u32, String) {
    let code = unsafe { GetLastError() }.0;
    (code, format_win32_error(code))
}

/// Map a Win32 error to a "likely cause" hint specific to clipboard failures.
fn clipboard_failure_hint(code: u32) -> &'static str {
    match code {
        0x5 /* ERROR_ACCESS_DENIED */ => {
            "ERROR_ACCESS_DENIED. Most common causes:\n\
             - UIPI: a higher-IL window currently owns the clipboard\n\
               (check 'clipboard owner' below).\n\
             - Window-station/desktop DACL does not grant\n\
               WINSTA_ACCESSCLIPBOARD or DESKTOP_*OBJECTS to this token."
        }
        0x6 /* ERROR_INVALID_HANDLE */ => "ERROR_INVALID_HANDLE — the HWND argument is not valid in this process.",
        0x578 /* ERROR_INVALID_WINDOW_HANDLE */ => {
            "ERROR_INVALID_WINDOW_HANDLE — the HWND passed to OpenClipboard \
             is not a window owned by this thread/process."
        }
        0x57F /* ERROR_CLIPBOARD_NOT_OPEN */ => "ERROR_CLIPBOARD_NOT_OPEN.",
        0x0 => "GetLastError() returned 0; the call may have failed silently or the API does not set last-error here.",
        _ => "",
    }
}

fn integrity_rid_label(rid: u32) -> String {
    match rid {
        0x0000 => "Untrusted (0x0000)".into(),
        0x1000 => "Low (0x1000)".into(),
        0x2000 => "Medium (0x2000)".into(),
        0x2100 => "Medium+ (0x2100)".into(),
        0x3000 => "High (0x3000)".into(),
        0x4000 => "System (0x4000)".into(),
        0x5000 => "Protected (0x5000)".into(),
        r => format!("Unknown (0x{r:04X})"),
    }
}

unsafe fn token_integrity_level(token: HANDLE) -> Option<String> {
    let mut needed = 0u32;
    // First call to size the buffer; this is expected to fail with
    // ERROR_INSUFFICIENT_BUFFER and populate `needed`.
    let _ = GetTokenInformation(token, TokenIntegrityLevel, None, 0, &mut needed);
    if needed == 0 {
        return None;
    }
    let mut buf = vec![0u8; needed as usize];
    GetTokenInformation(
        token,
        TokenIntegrityLevel,
        Some(buf.as_mut_ptr() as *mut _),
        needed,
        &mut needed,
    )
    .ok()?;
    let tml = &*(buf.as_ptr() as *const TOKEN_MANDATORY_LABEL);
    let count = *GetSidSubAuthorityCount(tml.Label.Sid) as u32;
    if count == 0 {
        return None;
    }
    let rid = *GetSidSubAuthority(tml.Label.Sid, count - 1);
    Some(integrity_rid_label(rid))
}

fn current_integrity_level() -> Option<String> {
    unsafe {
        let mut tok = HANDLE::default();
        OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut tok).ok()?;
        let r = token_integrity_level(tok);
        let _ = CloseHandle(tok);
        r
    }
}

fn process_integrity_level(pid: u32) -> Option<String> {
    unsafe {
        let p = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid).ok()?;
        let mut tok = HANDLE::default();
        let r = if OpenProcessToken(p, TOKEN_QUERY, &mut tok).is_ok() {
            let r = token_integrity_level(tok);
            let _ = CloseHandle(tok);
            r
        } else {
            None
        };
        let _ = CloseHandle(p);
        r
    }
}

fn process_image_name(pid: u32) -> Option<String> {
    unsafe {
        let p = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid).ok()?;
        let mut buf = [0u16; 1024];
        let mut n = buf.len() as u32;
        let res =
            QueryFullProcessImageNameW(p, PROCESS_NAME_FORMAT(0), PWSTR(buf.as_mut_ptr()), &mut n);
        let _ = CloseHandle(p);
        res.ok()?;
        Some(String::from_utf16_lossy(&buf[..n as usize]))
    }
}

fn window_station_name() -> Option<String> {
    unsafe {
        let h = GetProcessWindowStation().ok()?;
        let h = HANDLE(h.0);
        let mut needed = 0u32;
        let _ = GetUserObjectInformationW(h, UOI_NAME, None, 0, Some(&mut needed));
        if needed == 0 {
            return None;
        }
        let mut buf = vec![0u16; (needed as usize) / 2 + 1];
        GetUserObjectInformationW(
            h,
            UOI_NAME,
            Some(buf.as_mut_ptr() as *mut _),
            needed,
            Some(&mut needed),
        )
        .ok()?;
        Some(
            String::from_utf16_lossy(&buf)
                .trim_end_matches('\0')
                .to_string(),
        )
    }
}

fn desktop_name() -> Option<String> {
    unsafe {
        let h = GetThreadDesktop(GetCurrentThreadId()).ok()?;
        let h = HANDLE(h.0);
        let mut needed = 0u32;
        let _ = GetUserObjectInformationW(h, UOI_NAME, None, 0, Some(&mut needed));
        if needed == 0 {
            return None;
        }
        let mut buf = vec![0u16; (needed as usize) / 2 + 1];
        GetUserObjectInformationW(
            h,
            UOI_NAME,
            Some(buf.as_mut_ptr() as *mut _),
            needed,
            Some(&mut needed),
        )
        .ok()?;
        Some(
            String::from_utf16_lossy(&buf)
                .trim_end_matches('\0')
                .to_string(),
        )
    }
}

fn clipboard_owner_description() -> String {
    let hwnd = unsafe { GetClipboardOwner() }.unwrap_or_default();
    if hwnd.0.is_null() {
        return "(no current clipboard owner)".into();
    }
    let mut pid: u32 = 0;
    let _ = unsafe { GetWindowThreadProcessId(hwnd, Some(&mut pid)) };
    let img = process_image_name(pid).unwrap_or_else(|| "?".into());
    let il = process_integrity_level(pid).unwrap_or_else(|| "?".into());
    format!(
        "HWND={:p} pid={} image={} integrity={}",
        hwnd.0, pid, img, il
    )
}

pub fn dump_environment(prefix: &str) {
    eprintln!(
        "{prefix}   our integrity   : {}",
        current_integrity_level().unwrap_or_else(|| "?".into())
    );
    eprintln!(
        "{prefix}   window station  : {}",
        window_station_name().unwrap_or_else(|| "?".into())
    );
    eprintln!(
        "{prefix}   desktop         : {}",
        desktop_name().unwrap_or_else(|| "?".into())
    );
    eprintln!(
        "{prefix}   clipboard owner : {}",
        clipboard_owner_description()
    );
}

// --------------------------------------------------------------------------
// HWND resolution
// --------------------------------------------------------------------------

/// Owner of a window we create so it gets destroyed on drop.
pub struct OwnedWindow(HWND);
impl Drop for OwnedWindow {
    fn drop(&mut self) {
        if !self.0 .0.is_null() {
            unsafe {
                let _ = DestroyWindow(self.0);
            }
        }
    }
}

fn create_owned_window() -> Result<OwnedWindow> {
    unsafe {
        let hinst = GetModuleHandleW(None).context("GetModuleHandleW failed")?;
        let class_name = w!("PLMTesterOwnedWindow");
        let wc = WNDCLASSW {
            lpfnWndProc: Some(wndproc_thunk),
            hInstance: hinst.into(),
            lpszClassName: class_name,
            ..Default::default()
        };
        // RegisterClassW is idempotent across calls within the same
        // process; ignore "class already exists" error.
        let _ = RegisterClassW(&wc);

        let hwnd = CreateWindowExW(
            WINDOW_EX_STYLE(0),
            class_name,
            w!("PLMTester"),
            WS_OVERLAPPEDWINDOW | WS_VISIBLE,
            CW_USEDEFAULT,
            CW_USEDEFAULT,
            320,
            120,
            None,
            None,
            Some(hinst.into()),
            None,
        )
        .context("CreateWindowExW failed")?;
        let _ = ShowWindow(hwnd, SW_SHOWNORMAL);
        let _ = UpdateWindow(hwnd);
        Ok(OwnedWindow(hwnd))
    }
}

/// Resolves an HWND from the user's choice. Holds the `OwnedWindow`
/// guard for the lifetime of the clipboard operation when chosen.
pub fn resolve_hwnd(src: HwndSource) -> Result<(HWND, Option<OwnedWindow>)> {
    match src {
        HwndSource::None => Ok((HWND::default(), None)),
        HwndSource::Console => {
            let h = unsafe { GetConsoleWindow() };
            if h.0.is_null() {
                eprintln!("[warn] GetConsoleWindow returned NULL; falling back to HWND(NULL)");
            }
            Ok((h, None))
        }
        HwndSource::Owned => {
            let g = create_owned_window()?;
            let h = g.0;
            Ok((h, Some(g)))
        }
        HwndSource::Desktop => {
            let h = unsafe { GetDesktopWindow() };
            Ok((h, None))
        }
    }
}

// --------------------------------------------------------------------------
// Clipboard wrappers
// --------------------------------------------------------------------------

pub struct ClipboardGuard;

impl ClipboardGuard {
    pub fn open(hwnd: HWND) -> Result<Self> {
        eprintln!("[step] OpenClipboard(hwnd={:p})", hwnd.0);
        let r = unsafe { OpenClipboard(Some(hwnd)) };
        if r.is_err() {
            let (code, msg) = last_error_pair();
            eprintln!("[fail] OpenClipboard failed");
            eprintln!("       win32 error    : 0x{code:08X} ({code}) — {msg}");
            let hint = clipboard_failure_hint(code);
            if !hint.is_empty() {
                for line in hint.lines() {
                    eprintln!("       {line}");
                }
            }
            dump_environment("[fail]");
            return Err(anyhow!(
                "OpenClipboard(hwnd={:p}) failed with 0x{:08X}: {}",
                hwnd.0,
                code,
                msg
            ));
        }
        Ok(Self)
    }
}

impl Drop for ClipboardGuard {
    fn drop(&mut self) {
        unsafe {
            let _ = CloseClipboard();
        }
    }
}

pub fn clipboard_set(hwnd: HWND, value: &str) -> Result<()> {
    let guard = ClipboardGuard::open(hwnd)?;
    clipboard_set_locked(&guard, value)
}

/// Write `value` under a caller-held clipboard scope. Empties the
/// clipboard, allocates an HGLOBAL, and publishes it as
/// CF_UNICODETEXT. The caller must hold `_guard` for the entire
/// operation; drop it (or continue holding it) after.
pub fn clipboard_set_locked(_guard: &ClipboardGuard, value: &str) -> Result<()> {
    let mut wide: Vec<u16> = value.encode_utf16().collect();
    wide.push(0);
    let bytes = wide.len() * std::mem::size_of::<u16>();

    unsafe {
        EmptyClipboard().context("EmptyClipboard failed")?;
    }

    let hmem: HGLOBAL =
        unsafe { GlobalAlloc(GMEM_MOVEABLE, bytes) }.context("GlobalAlloc failed")?;

    unsafe {
        let dst = GlobalLock(hmem) as *mut u16;
        if dst.is_null() {
            let _ = GlobalFree(Some(hmem));
            return Err(anyhow!("GlobalLock returned null"));
        }
        std::ptr::copy_nonoverlapping(wide.as_ptr(), dst, wide.len());
        let _ = GlobalUnlock(hmem);
    }

    let handle = HANDLE(hmem.0);
    let set_result = unsafe { SetClipboardData(CF_UNICODETEXT.0 as u32, Some(handle)) };
    if set_result.is_err() {
        let (code, msg) = last_error_pair();
        unsafe {
            let _ = GlobalFree(Some(hmem));
        }
        eprintln!("[fail] SetClipboardData failed");
        eprintln!("       win32 error    : 0x{code:08X} ({code}) — {msg}");
        dump_environment("[fail]");
        return Err(anyhow!("SetClipboardData failed (0x{code:08X}): {msg}"));
    }

    Ok(())
}

pub fn clipboard_get(hwnd: HWND) -> Result<Option<String>> {
    let guard = ClipboardGuard::open(hwnd)?;
    clipboard_get_locked(&guard)
}

/// Read CF_UNICODETEXT under a caller-held clipboard scope. Returns
/// `Ok(None)` if the clipboard has no CF_UNICODETEXT entry.
pub fn clipboard_get_locked(_guard: &ClipboardGuard) -> Result<Option<String>> {
    eprintln!("[step] GetClipboardData(CF_UNICODETEXT)");
    let handle =
        unsafe { GetClipboardData(CF_UNICODETEXT.0 as u32) }.context("GetClipboardData failed")?;
    eprintln!(
        "[info] GetClipboardData -> HANDLE={:p} is_invalid={}",
        handle.0,
        handle.is_invalid()
    );

    let hmem = HGLOBAL(handle.0);
    let size_bytes = unsafe { GlobalSize(hmem) };
    eprintln!("[info] GlobalSize({:p}) = {} bytes", hmem.0, size_bytes);
    if size_bytes == 0 {
        return Ok(Some(String::new()));
    }

    let text = unsafe {
        let ptr = GlobalLock(hmem) as *const u16;
        if ptr.is_null() {
            return Err(anyhow!("GlobalLock on clipboard handle returned null"));
        }
        let s = PCWSTR(ptr)
            .to_string()
            .context("invalid UTF-16 in clipboard")?;
        let _ = GlobalUnlock(hmem);
        s
    };
    Ok(Some(text))
}
