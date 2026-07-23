//! UI-isolation probes for PLMTester.
//!
//! * `find-window` — `FindWindowW(class, title)`. By default looks up
//!   `Shell_TrayWnd`, the top-level taskbar window owned by
//!   `explorer.exe`. Sandboxed tokens with strict UIPI / different
//!   desktops may not see it.

use anyhow::{anyhow, Result};
use clap::{Args, Subcommand};

use windows::core::PCWSTR;
use windows::Win32::Foundation::GetLastError;
use windows::Win32::UI::WindowsAndMessaging::{FindWindowW, GetWindowThreadProcessId};

#[derive(Subcommand, Debug)]
pub enum UiIsolationOp {
    /// Call `FindWindowW(class, title)` and report the HWND.
    FindWindow(FindWindowArgs),
}

#[derive(Args, Debug)]
pub struct FindWindowArgs {
    /// Window class name to search for. Default `Shell_TrayWnd` —
    /// the taskbar top-level window owned by `explorer.exe`. Pass
    /// the empty string to omit the class-name filter.
    #[arg(long, default_value = "Shell_TrayWnd")]
    pub class: String,

    /// Window title to search for. Empty (default) means "match any
    /// title".
    #[arg(long, default_value = "")]
    pub title: String,
}

fn to_wide(s: &str) -> Vec<u16> {
    let mut v: Vec<u16> = s.encode_utf16().collect();
    v.push(0);
    v
}

fn pcwstr_or_null(buf: &[u16], original: &str) -> PCWSTR {
    if original.is_empty() {
        PCWSTR::null()
    } else {
        PCWSTR(buf.as_ptr())
    }
}

pub fn run(op: UiIsolationOp) -> Result<()> {
    match op {
        UiIsolationOp::FindWindow(args) => run_find_window(args),
    }
}

fn run_find_window(args: FindWindowArgs) -> Result<()> {
    let class_wide = to_wide(&args.class);
    let title_wide = to_wide(&args.title);

    let class_p = pcwstr_or_null(&class_wide, &args.class);
    let title_p = pcwstr_or_null(&title_wide, &args.title);

    eprintln!(
        "[step] FindWindowW(class={:?}, title={:?})",
        if args.class.is_empty() {
            "<null>"
        } else {
            &args.class
        },
        if args.title.is_empty() {
            "<null>"
        } else {
            &args.title
        }
    );

    let hwnd = unsafe { FindWindowW(class_p, title_p) };
    match hwnd {
        Ok(h) if !h.0.is_null() => {
            let mut pid: u32 = 0;
            let _ = unsafe { GetWindowThreadProcessId(h, Some(&mut pid)) };
            eprintln!("[ok]   FindWindowW -> HWND={:p} pid={pid}", h.0);
            println!("hwnd=0x{:p} pid={pid}", h.0);
            Ok(())
        }
        _ => {
            let code = unsafe { GetLastError() }.0;
            eprintln!("[fail] FindWindowW returned NULL (last_error=0x{code:08X})");
            Err(anyhow!(
                "FindWindowW(class={:?}, title={:?}) returned NULL (last_error=0x{code:08X}). \
                 Either the window does not exist on this desktop / session, or UIPI is hiding \
                 it from this token.",
                args.class,
                args.title
            ))
        }
    }
}
