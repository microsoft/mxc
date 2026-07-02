//! Input-injection probe for PLMTester.
//!
//! `SendInput` is the canonical USER32 API for synthesizing keyboard
//! and mouse events. It is gated by **UIPI** (a Low-IL or AppContainer
//! caller cannot inject input into a higher-IL foreground window) and
//! by the `inputInjectionBrokered` AppContainer capability for the
//! WinRT injection broker. A bare `SendInput` call from an
//! AppContainer typically returns 0 with `last_error = ERROR_ACCESS_DENIED`.
//!
//! This probe synthesizes a single `VK_F24` key-down + key-up pair.
//! `VK_F24` (0x87) is intentionally chosen because it has no default
//! shell binding, so a successful injection on a healthy host is
//! observable (SendInput's return value reports the event count) but
//! does not disturb any running application.

use anyhow::{anyhow, Result};
use clap::Args;
use std::ffi::c_void;

use windows::core::BOOL;
use windows::core::{w, PCWSTR};
use windows::Win32::Foundation::{GetLastError, HANDLE, HWND, LPARAM, LRESULT, WPARAM};
use windows::Win32::System::LibraryLoader::{GetModuleHandleW, GetProcAddress};
use windows::Win32::System::Threading::GetCurrentProcess;
use windows::Win32::UI::Input::KeyboardAndMouse::{
    SendInput, INPUT, INPUT_0, INPUT_KEYBOARD, KEYBDINPUT, KEYBD_EVENT_FLAGS, KEYEVENTF_KEYUP,
    VIRTUAL_KEY, VK_F24,
};
use windows::Win32::UI::WindowsAndMessaging::{
    CreateWindowExW, DefWindowProcW, DestroyWindow, RegisterClassW, SetForegroundWindow,
    HWND_MESSAGE, WINDOW_EX_STYLE, WINDOW_STYLE, WNDCLASSW,
};

#[derive(Args, Debug)]
pub struct InjectionArgs {
    /// Virtual-key code to inject. Defaults to 0x87 (`VK_F24`),
    /// which has no default binding so the event is observable via
    /// SendInput's return value but doesn't disturb running apps.
    #[arg(long, default_value_t = VK_F24.0)]
    pub vk: u16,

    /// Skip the matching key-up event. The probe normally sends both
    /// down and up so a successful injection leaves no key in the
    /// "held" state.
    #[arg(long, default_value_t = false)]
    pub no_keyup: bool,
}

fn build_events(args: &InjectionArgs) -> Vec<INPUT> {
    let mut events: Vec<INPUT> = Vec::with_capacity(2);

    let down = INPUT {
        r#type: INPUT_KEYBOARD,
        Anonymous: INPUT_0 {
            ki: KEYBDINPUT {
                wVk: VIRTUAL_KEY(args.vk),
                wScan: 0,
                dwFlags: KEYBD_EVENT_FLAGS(0),
                time: 0,
                dwExtraInfo: 0,
            },
        },
    };
    events.push(down);

    if !args.no_keyup {
        let up = INPUT {
            r#type: INPUT_KEYBOARD,
            Anonymous: INPUT_0 {
                ki: KEYBDINPUT {
                    wVk: VIRTUAL_KEY(args.vk),
                    wScan: 0,
                    dwFlags: KEYEVENTF_KEYUP,
                    time: 0,
                    dwExtraInfo: 0,
                },
            },
        };
        events.push(up);
    }

    events
}

// --- ConsoleControl(ConsoleSetForeground) plumbing ----------------------
//
// `ConsoleControl` is an undocumented ordinal export of user32.dll. The
// `ConsoleSetForeground` command (5) grants the calling process the right
// to call `SetForegroundWindow` even when UIPI / foreground-lock policy
// would normally deny it — this is how conhost.exe brings its own window
// to the foreground on behalf of a console child. The shape of the
// command parameter has been stable for years:
//
//     struct CONSOLESETFOREGROUND {
//         HANDLE hProcess;     // process to grant/revoke the right
//         BOOL   bForeground;  // TRUE to grant, FALSE to revoke
//     };
#[repr(C)]
struct ConsoleSetForeground {
    process_handle: HANDLE,
    foreground: BOOL,
}

const CONSOLE_SET_FOREGROUND: u32 = 5;

type ConsoleControlFn = unsafe extern "system" fn(u32, *mut c_void, u32) -> i32;

unsafe extern "system" fn wnd_proc(
    hwnd: HWND,
    msg: u32,
    wparam: WPARAM,
    lparam: LPARAM,
) -> LRESULT {
    DefWindowProcW(hwnd, msg, wparam, lparam)
}

fn create_message_window() -> Result<HWND> {
    let hinstance_mod = unsafe { GetModuleHandleW(PCWSTR::null()) }
        .map_err(|e| anyhow!("GetModuleHandleW(NULL) failed: {e}"))?;
    let hinstance: windows::Win32::Foundation::HINSTANCE = hinstance_mod.into();

    let class_name = w!("PLMTesterInjectionMsgWnd");

    let wc = WNDCLASSW {
        lpfnWndProc: Some(wnd_proc),
        hInstance: hinstance,
        lpszClassName: class_name,
        ..Default::default()
    };

    let atom = unsafe { RegisterClassW(&wc) };
    if atom == 0 {
        let code = unsafe { GetLastError() }.0;
        // 0x582 (ERROR_CLASS_ALREADY_EXISTS) is fine — a previous run
        // in the same process already registered it.
        if code != 0x582 {
            return Err(anyhow!("RegisterClassW failed (last_error=0x{code:08X})"));
        }
        eprintln!("[info] class already registered (last_error=0x{code:08X}) — continuing");
    } else {
        eprintln!("[ok]   RegisterClassW -> atom=0x{atom:04X}");
    }

    let hwnd = unsafe {
        CreateWindowExW(
            WINDOW_EX_STYLE(0),
            class_name,
            w!("PLMTester injection target"),
            WINDOW_STYLE(0),
            0,
            0,
            0,
            0,
            Some(HWND_MESSAGE),
            None,
            Some(hinstance),
            None,
        )
    }
    .map_err(|e| {
        let code = unsafe { GetLastError() }.0;
        anyhow!("CreateWindowExW(HWND_MESSAGE) failed: {e} (last_error=0x{code:08X})")
    })?;

    eprintln!("[ok]   CreateWindowExW -> HWND={:p} (message-only)", hwnd.0);
    Ok(hwnd)
}

fn grant_console_foreground_right() -> Result<()> {
    let user32 = unsafe { GetModuleHandleW(w!("user32.dll")) }
        .map_err(|e| anyhow!("GetModuleHandleW(user32.dll) failed: {e}"))?;

    let addr = unsafe { GetProcAddress(user32, windows::core::s!("ConsoleControl")) };
    let Some(addr) = addr else {
        let code = unsafe { GetLastError() }.0;
        return Err(anyhow!(
            "GetProcAddress(user32!ConsoleControl) returned NULL (last_error=0x{code:08X}). \
             The undocumented export is not reachable on this build."
        ));
    };
    let console_control: ConsoleControlFn = unsafe { std::mem::transmute(addr) };
    eprintln!(
        "[ok]   user32!ConsoleControl resolved at {:p}",
        addr as *const c_void
    );

    let mut info = ConsoleSetForeground {
        process_handle: unsafe { GetCurrentProcess() },
        foreground: BOOL(1),
    };

    eprintln!(
        "[step] ConsoleControl(ConsoleSetForeground={CONSOLE_SET_FOREGROUND}, \
         {{hProcess=GetCurrentProcess(), bForeground=TRUE}})"
    );

    let status = unsafe {
        console_control(
            CONSOLE_SET_FOREGROUND,
            &mut info as *mut _ as *mut c_void,
            std::mem::size_of::<ConsoleSetForeground>() as u32,
        )
    };

    // ConsoleControl returns an NTSTATUS; 0 == STATUS_SUCCESS.
    if status != 0 {
        let code = unsafe { GetLastError() }.0;
        return Err(anyhow!(
            "ConsoleControl(ConsoleSetForeground) returned NTSTATUS=0x{:08X} (last_error=0x{code:08X})",
            status as u32
        ));
    }
    eprintln!("[ok]   ConsoleControl(ConsoleSetForeground) -> STATUS_SUCCESS");
    Ok(())
}

pub fn run(args: InjectionArgs) -> Result<()> {
    // Step 1: create a hidden message-only window so this process
    // owns a foreground-eligible HWND.
    eprintln!("[step] CreateMessageWindow (HWND_MESSAGE, hidden)");
    let hwnd = create_message_window()?;

    // Step 2: grant this process the right to call
    // SetForegroundWindow despite UIPI / AppContainer constraints.
    eprintln!("[step] GrantConsoleForegroundRight via ConsoleControl(ConsoleSetForeground)");
    if let Err(e) = grant_console_foreground_right() {
        eprintln!("[warn] {e} — continuing to SetForegroundWindow anyway");
    }

    // Step 3: SetForegroundWindow on the owned HWND.
    eprintln!("[step] SetForegroundWindow({:p})", hwnd.0);
    let sfw_ok = unsafe { SetForegroundWindow(hwnd) };
    let sfw_err = unsafe { GetLastError() }.0;
    if sfw_ok.as_bool() {
        eprintln!("[ok]   SetForegroundWindow returned TRUE");
    } else {
        eprintln!(
            "[warn] SetForegroundWindow returned FALSE (last_error=0x{sfw_err:08X}) — \
             foreground-lock or UIPI rejected the call; continuing to SendInput so the \
             exit code still reflects SendInput's own gate."
        );
    }

    // Step 4: SendInput — the actual operation under test.
    let events = build_events(&args);
    let expected = events.len() as u32;
    eprintln!(
        "[step] SendInput(count={}, vk=0x{:02X}, keyup={})",
        expected, args.vk, !args.no_keyup
    );

    let injected = unsafe { SendInput(&events, std::mem::size_of::<INPUT>() as i32) };
    let last_error = if injected == 0 {
        unsafe { GetLastError() }.0
    } else {
        0
    };

    // Best-effort cleanup so re-runs in the same session start clean.
    let _ = unsafe { DestroyWindow(hwnd) };

    if injected == 0 {
        eprintln!(
            "[fail] SendInput injected 0 events (last_error=0x{last_error:08X}). \
             Even with ConsoleSetForeground + SetForegroundWindow, USER32 / UIPI / \
             AppContainer is filtering the call. Exit code = SendInput's GetLastError."
        );
        println!("injected=0 expected={expected} last_error=0x{last_error:08X}");
        // Exit code = GetLastError() from SendInput, per the reference test pattern.
        std::process::exit(last_error as i32);
    }

    eprintln!(
        "[ok]   SendInput injected {injected} / {expected} events (last_error = ERROR_SUCCESS)"
    );
    println!("injected={injected} expected={expected} last_error=0x00000000");
    Ok(())
}
