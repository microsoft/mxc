//! PLMTester — small harness for probing AppContainer / Low-IL /
//! Permissive Learning Mode behavior against various Windows surfaces.

mod clipboard;
mod display_settings;
mod injection;
mod screenshot;
mod screenshot_simple;
mod system_param;
mod uiisolation;

use anyhow::Result;
use clap::{Parser, Subcommand};
use std::path::PathBuf;

use clipboard::{
    clipboard_get, clipboard_get_in_scope, clipboard_set, dump_environment, resolve_hwnd,
    HwndSource,
};
use display_settings::DisplaySettingsArgs;
use system_param::SystemParamArgs;

#[derive(Parser, Debug)]
#[command(
    name = "PLMTester",
    version,
    about = "AppContainer / PLM behavior probes"
)]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand, Debug)]
enum Cmd {
    /// Clipboard probes (set / get / roundtrip).
    Clipboard {
        #[command(subcommand)]
        op: ClipboardOp,
    },
    /// Capture the screen using Windows.Graphics.Capture +
    /// GraphicsCapturePicker (WinRT). The user picks a display or
    /// window via the system picker.
    Screenshot {
        /// Output PNG path. Defaults to `screenshot.png` in CWD.
        #[arg(default_value = "screenshot.png")]
        output: PathBuf,
    },
    /// Capture the primary display using GDI BitBlt (no AppContainer
    /// capability required, but blocked by the desktop ACL inside an
    /// AppContainer / LPAC).
    ScreenshotSimple {
        /// Output PNG path. Defaults to `screenshot.png` in CWD.
        #[arg(default_value = "screenshot.png")]
        output: PathBuf,
    },
    /// Probe `SystemParametersInfoW` (USER32).
    SystemParam(SystemParamArgs),
    /// Probe `ChangeDisplaySettingsW` (USER32).
    DisplaySettings(DisplaySettingsArgs),
    /// UI-isolation probes (FindWindow).
    UiIsolation {
        #[command(subcommand)]
        op: uiisolation::UiIsolationOp,
    },
    /// Probe `SendInput` — synthetic keyboard input injection via the
    /// full child-window foreground flow (CreateMessageWindow →
    /// ConsoleControl(ConsoleSetForeground) → SetForegroundWindow →
    /// SendInput).
    Injection(injection::InjectionArgs),
}

#[derive(Subcommand, Debug)]
enum ClipboardOp {
    /// Set the clipboard to the given UTF-16 string.
    Set {
        /// Text to place on the clipboard.
        value: String,
        /// Which HWND to pass to OpenClipboard. Defaults to a visible
        /// top-level window owned by this process.
        #[arg(long, value_enum, default_value_t = HwndSource::Owned)]
        hwnd: HwndSource,
    },
    /// Print the current clipboard value (CF_UNICODETEXT) to stdout.
    Get {
        /// Which HWND to pass to OpenClipboard. Defaults to a visible
        /// top-level window owned by this process.
        #[arg(long, value_enum, default_value_t = HwndSource::Owned)]
        hwnd: HwndSource,
    },
    /// In a single process, set the clipboard to `value` and then read
    /// it back. Useful for distinguishing AppContainer clipboard
    /// isolation (cross-process fails but in-process succeeds) from a
    /// real set/get bug (both fail).
    Roundtrip {
        /// Text to write and then read back.
        value: String,
        /// Which HWND to pass to OpenClipboard for both calls.
        #[arg(long, value_enum, default_value_t = HwndSource::Owned)]
        hwnd: HwndSource,
        /// Open a fresh OpenClipboard scope for the read instead of
        /// keeping the set scope open. Defaults to true so the round
        /// trip exercises the same code path as two separate runs.
        #[arg(long, default_value_t = true, action = clap::ArgAction::Set)]
        reopen: bool,
    },
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    // Always dump the environment up front so success cases still show
    // the token / station / IL context for later comparison.
    eprintln!("[info] PLMTester environment:");
    dump_environment("[info]");

    match cli.cmd {
        Cmd::Clipboard { op } => match op {
            ClipboardOp::Set { value, hwnd } => {
                let (h, _guard) = resolve_hwnd(hwnd)?;
                eprintln!("[info] using HWND {:p} (source={:?})", h.0, hwnd);
                clipboard_set(h, &value)?;
                eprintln!("[ok]   clipboard set ({} chars)", value.chars().count());
            }
            ClipboardOp::Get { hwnd } => {
                let (h, _guard) = resolve_hwnd(hwnd)?;
                eprintln!("[info] using HWND {:p} (source={:?})", h.0, hwnd);
                match clipboard_get(h)? {
                    Some(s) => println!("{s}"),
                    None => {
                        eprintln!("[info] clipboard has no CF_UNICODETEXT");
                        std::process::exit(2);
                    }
                }
            }
            ClipboardOp::Roundtrip {
                value,
                hwnd,
                reopen,
            } => {
                let (h, _guard) = resolve_hwnd(hwnd)?;
                eprintln!(
                    "[info] roundtrip: HWND {:p} (source={:?}) reopen={}",
                    h.0, hwnd, reopen
                );

                eprintln!("[step] === phase 1: SET ===");
                clipboard_set(h, &value)?;
                eprintln!("[ok]   clipboard set ({} chars)", value.chars().count());

                let read_back = if reopen {
                    // Default: drop the SET clipboard scope before reading.
                    // This mirrors what two separate process invocations do.
                    eprintln!("[step] === phase 2: GET (fresh OpenClipboard) ===");
                    match clipboard_get(h)? {
                        Some(s) => s,
                        None => {
                            eprintln!(
                                "[fail] roundtrip: clipboard has no CF_UNICODETEXT after \
                                 same-process set. This is the AppContainer / clipboard-isolation \
                                 signature."
                            );
                            std::process::exit(2);
                        }
                    }
                } else {
                    // --reopen=false: hold a separate scope and read inside
                    // it. Tells you whether the in-clipboard HGLOBAL is
                    // readable at all from this token.
                    eprintln!("[step] === phase 2: GET (same OpenClipboard scope) ===");
                    clipboard_get_in_scope(h)?
                };

                let ok = read_back == value;
                eprintln!(
                    "[{}] roundtrip {}: wrote={:?} read={:?}",
                    if ok { "ok " } else { "fail" },
                    if ok { "match" } else { "MISMATCH" },
                    value,
                    read_back,
                );
                println!("{read_back}");
                if !ok {
                    std::process::exit(3);
                }
            }
        },
        Cmd::Screenshot { output } => {
            let (w, h) = screenshot::capture(&output)?;
            println!("wrote {} ({}x{})", output.display(), w, h);
        }
        Cmd::ScreenshotSimple { output } => {
            let (w, h) = screenshot_simple::capture(&output)?;
            println!("wrote {} ({}x{})", output.display(), w, h);
        }
        Cmd::SystemParam(args) => system_param::run(args)?,
        Cmd::DisplaySettings(args) => display_settings::run(args)?,
        Cmd::UiIsolation { op } => uiisolation::run(op)?,
        Cmd::Injection(args) => injection::run(args)?,
    }
    Ok(())
}
