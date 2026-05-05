// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! `mxc-diagnostic-console` -- shared diagnostic console for MXC.
//!
//! Listens on the named pipe `\\.\pipe\mxc-diagnostics` and displays
//! real-time log messages from multiple `wxc-exec.exe` instances.
//!
//! Usage:
//!   mxc-diagnostic-console.exe
//!
//! Then run `wxc-exec.exe` with `MXC_DIAG_CONSOLE=1` (or registry key).

mod etw;

use std::io::Read;
use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::mpsc;
use std::thread;
use std::time::SystemTime;

use clap::Parser;

use windows::Win32::Foundation::{CloseHandle, HANDLE, INVALID_HANDLE_VALUE};
use windows::Win32::Security::{
    InitializeSecurityDescriptor, SetSecurityDescriptorDacl, PSECURITY_DESCRIPTOR,
    SECURITY_ATTRIBUTES, SECURITY_DESCRIPTOR, TOKEN_ELEVATION, TOKEN_QUERY,
};
use windows::Win32::Storage::FileSystem::FILE_FLAG_FIRST_PIPE_INSTANCE;
use windows::Win32::System::Pipes::{
    ConnectNamedPipe, CreateNamedPipeW, DisconnectNamedPipe, GetNamedPipeClientProcessId,
    PIPE_READMODE_MESSAGE, PIPE_TYPE_MESSAGE, PIPE_UNLIMITED_INSTANCES, PIPE_WAIT,
};
use windows::Win32::System::ProcessStatus::GetModuleFileNameExW;
use windows::Win32::System::Threading::{
    GetCurrentProcess, OpenProcess, OpenProcessToken, PROCESS_QUERY_LIMITED_INFORMATION,
};
use windows_core::PCWSTR;

/// Maximum message size in bytes (256 KB -- enough for large redacted JSON).
const BUFFER_SIZE: u32 = 256 * 1024;

/// Colors for per-PID display. Cycles through these ANSI color codes.
const PID_COLORS: &[&str] = &[
    "\x1b[36m", // Cyan
    "\x1b[32m", // Green
    "\x1b[33m", // Yellow
    "\x1b[35m", // Magenta
    "\x1b[34m", // Blue
    "\x1b[91m", // Bright Red
    "\x1b[92m", // Bright Green
    "\x1b[96m", // Bright Cyan
];
const RESET: &str = "\x1b[0m";
const DIM: &str = "\x1b[2m";

/// Display mode for ETW event output.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum DisplayMode {
    /// Show all decoded properties.
    Full = 0,
    /// Show a reduced set of properties for common event types.
    Minified = 1,
}

/// Global display mode, set once at startup from CLI args.
static DISPLAY_MODE: AtomicU8 = AtomicU8::new(DisplayMode::Minified as u8);

pub fn display_mode() -> DisplayMode {
    match DISPLAY_MODE.load(Ordering::Relaxed) {
        0 => DisplayMode::Full,
        _ => DisplayMode::Minified,
    }
}

/// Events sent from reader threads to the display thread.
enum DisplayEvent {
    /// A new client connected with the given PID.
    Connected { pid: u32 },
    /// A log message arrived from a client.
    Message { pid: u32, text: String },
    /// A client disconnected.
    Disconnected { pid: u32 },
    /// An ETW event from the Tessera provider.
    EtwEvent { pid: u32, text: String },
}

/// Check whether the current process is running elevated (as admin).
fn is_elevated() -> bool {
    // SAFETY: GetCurrentProcess returns a pseudo-handle that is always valid.
    // OpenProcessToken/GetTokenInformation operate on valid handles with proper buffer sizes.
    // CloseHandle is called on the token handle before returning.
    unsafe {
        let mut token = HANDLE::default();
        if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token).is_err() {
            return false;
        }
        let mut elevation = TOKEN_ELEVATION::default();
        let mut returned = 0u32;
        let ok = windows::Win32::Security::GetTokenInformation(
            token,
            windows::Win32::Security::TokenElevation,
            Some(std::ptr::from_mut(&mut elevation).cast()),
            std::mem::size_of::<TOKEN_ELEVATION>() as u32,
            &mut returned,
        );
        let _ = CloseHandle(token);
        ok.is_ok() && elevation.TokenIsElevated != 0
    }
}

/// Registry path used by wxc-exec for diagnostic settings.
const DIAG_REGISTRY_SUBKEY: &str = r"SOFTWARE\Microsoft\MXC\Diagnostics";

/// Check whether wxc-exec diagnostic console output is enabled (env var).
fn is_diagnostic_console_enabled() -> bool {
    std::env::var("MXC_DIAG_CONSOLE").ok().as_deref() == Some("1")
}

/// Check whether ForceLearningMode is enabled in the registry.
fn is_force_learning_mode_enabled() -> bool {
    let hklm = winreg::RegKey::predef(winreg::enums::HKEY_LOCAL_MACHINE);
    let Ok(key) = hklm.open_subkey_with_flags(DIAG_REGISTRY_SUBKEY, winreg::enums::KEY_READ) else {
        return false;
    };
    key.get_value::<u32, _>("ForceLearningMode").unwrap_or(0) == 1
}

#[derive(Parser)]
#[command(
    name = "mxc-diagnostic-console",
    about = "Shared diagnostic console for MXC"
)]
struct Cli {
    /// Show all ETW event properties (default: minified)
    #[arg(long)]
    verbose: bool,
}

fn main() {
    let cli = Cli::parse();

    if cli.verbose {
        DISPLAY_MODE.store(DisplayMode::Full as u8, Ordering::Relaxed);
    } else {
        DISPLAY_MODE.store(DisplayMode::Minified as u8, Ordering::Relaxed);
    }

    // Compute the per-user pipe name (includes current user's SID).
    let pipe_name = wxc_common::diagnostic::diagnostic_pipe_name();

    // Enable ANSI escape codes on Windows console.
    enable_virtual_terminal();

    let mode_label = match display_mode() {
        DisplayMode::Full => "verbose",
        DisplayMode::Minified => "minified",
    };
    println!("\x1b[1;36m=== MXC Diagnostic Console ===\x1b[0m");
    println!("{DIM}Listening on {pipe_name}{RESET}");
    println!("{DIM}Display mode: {mode_label}{RESET}");
    println!("{DIM}Press Ctrl+C to exit{RESET}");
    println!();

    // Warn if wxc-exec diagnostic output is not enabled.
    if !is_diagnostic_console_enabled() {
        // Box width: 120 visible characters (border included).
        // W = inner width between the two ║ characters = 118.
        const W: usize = 118;
        let bar = "═".repeat(W);
        let y = "\x1b[1;33m"; // bold yellow
        let c = "\x1b[36m"; // cyan
        let r = "\x1b[0m"; // reset

        let blank = format!("{y}║{r}{:W$}{y}║{r}", "");
        let line = |text: &str| {
            // `text` may contain ANSI codes; pad by *visible* length.
            let visible_len = text.replace("\x1b[36m", "").replace("\x1b[0m", "").len();
            let pad = W.saturating_sub(visible_len);
            println!("{y}║{r}{text}{:pad$}{y}║{r}", "");
        };

        println!("{y}╔{bar}╗{r}");
        println!(
            "{y}║  WARNING: wxc-exec diagnostic output is not enabled!{:>w$}║{r}",
            "",
            w = W - 54
        );
        println!("{blank}");
        line("  wxc-exec won't send messages to this console unless you set the environment variable:");
        println!("{blank}");
        line(&format!("    {c}$env:MXC_DIAG_CONSOLE = \"1\"{r}"));
        println!("{blank}");
        println!("{y}╚{bar}╝{r}");
        println!();
    }

    // Warn if not running as admin (ETW requires elevation).
    if !is_elevated() {
        const W: usize = 118;
        let bar = "═".repeat(W);
        let y = "\x1b[1;33m"; // bold yellow
        let r = "\x1b[0m";

        let blank = format!("{y}║{r}{:W$}{y}║{r}", "");
        let line = |text: &str| {
            let visible_len = text.len();
            let pad = W.saturating_sub(visible_len);
            println!("{y}║{r}{text}{:pad$}{y}║{r}", "");
        };

        println!("{y}╔{bar}╗{r}");
        println!(
            "{y}║  WARNING: Not running as administrator{:>w$}║{r}",
            "",
            w = W - 39
        );
        println!("{blank}");
        line("  ETW event capture (Tessera + learning mode events) requires administrator privileges.");
        line("  Pipe-based log messages from wxc-exec will still work without elevation.");
        println!("{blank}");
        println!("{y}╚{bar}╝{r}");
        println!();
    }

    // Warn if ForceLearningMode registry key is not set.
    if !is_force_learning_mode_enabled() {
        const W: usize = 118;
        let bar = "═".repeat(W);
        let y = "\x1b[1;33m"; // bold yellow
        let c = "\x1b[36m"; // cyan
        let r = "\x1b[0m";

        let blank = format!("{y}║{r}{:W$}{y}║{r}", "");
        let line = |text: &str| {
            let visible_len = text.replace("\x1b[36m", "").replace("\x1b[0m", "").len();
            let pad = W.saturating_sub(visible_len);
            println!("{y}║{r}{text}{:pad$}{y}║{r}", "");
        };

        println!("{y}╔{bar}╗{r}");
        println!(
            "{y}║  WARNING: ForceLearningMode is not enabled{:>w$}║{r}",
            "",
            w = W - 44
        );
        println!("{blank}");
        line("  Without this registry key, wxc-exec will not inject the 'learningModeLogging' capability.");
        line("  Learning mode ETW events from Kernel-General will not appear in this console.");
        println!("{blank}");
        line("  To enable (run as admin):");
        println!("{blank}");
        line(&format!("    {c}Set-ItemProperty -Path \"HKLM:\\SOFTWARE\\Microsoft\\MXC\\Diagnostics\" -Name \"ForceLearningMode\" -Value 1 -Type DWord{r}"));
        println!("{blank}");
        println!("{y}╚{bar}╝{r}");
        println!();
    }

    // Channel for reader threads to send display events.
    let (tx, rx) = mpsc::channel::<DisplayEvent>();

    // Start ETW listener (best-effort; warns on failure).
    match etw::start_etw_listener(tx.clone()) {
        Ok(()) => {
            println!("\x1b[93m[ETW]\x1b[0m Listening for providers:");
            println!(
                "\x1b[93m[ETW]\x1b[0m   Tessera     \
                 {{f6ec123e-314e-400b-9e0a-151365e23083}}"
            );
            println!(
                "\x1b[93m[ETW]\x1b[0m   Kernel-General \
                 {{a68ca8b7-004f-d7b6-a698-07e2de0f1f5d}} (AccessCheckLog only)"
            );
        }
        Err(e) => {
            eprintln!("\x1b[93m[ETW]\x1b[0m Could not start ETW listener: {e}");
            eprintln!("\x1b[93m[ETW]\x1b[0m Hint: Run as administrator to capture ETW events.");
        }
    }
    println!();

    // Register a Ctrl+C handler to stop the ETW session cleanly.
    register_ctrl_handler();

    // Display thread: formats and prints events.
    let _display_handle = thread::spawn(move || {
        display_loop(rx);
    });

    // Accept loop: create pipe instances and wait for clients.
    let mut is_first = true;
    loop {
        let pipe = match create_pipe_instance(&pipe_name, is_first) {
            Ok(h) => h,
            Err(e) => {
                eprintln!("[error] Failed to create pipe instance: {e}");
                if is_first {
                    // If we can't even create the first instance, exit.
                    std::process::exit(1);
                }
                // For subsequent instances, wait and retry.
                thread::sleep(std::time::Duration::from_secs(1));
                continue;
            }
        };
        is_first = false;

        // Block until a client connects.
        // SAFETY: `pipe` is a valid handle returned by create_pipe_instance.
        let connected = unsafe { ConnectNamedPipe(pipe, None) };
        if connected.is_err() {
            let err = std::io::Error::last_os_error();
            // ERROR_PIPE_CONNECTED (535) means client connected between Create and Connect.
            if err.raw_os_error() != Some(535) {
                eprintln!("[error] ConnectNamedPipe failed: {err}");
                // SAFETY: `pipe` is a valid handle from create_pipe_instance.
                unsafe {
                    let _ = CloseHandle(pipe);
                }
                continue;
            }
        }

        // Get client PID server-side (don't trust client).
        let pid = match get_client_pid(pipe) {
            Some(p) => p,
            None => {
                eprintln!("[warn] Could not determine client PID");
                // SAFETY: `pipe` is a valid handle from create_pipe_instance.
                unsafe {
                    let _ = DisconnectNamedPipe(pipe);
                    let _ = CloseHandle(pipe);
                }
                continue;
            }
        };

        let tx = tx.clone();
        let _ = tx.send(DisplayEvent::Connected { pid });

        // Convert HANDLE to raw pointer for thread transfer (HANDLE is !Send).
        let raw_handle = pipe.0 as usize;
        thread::spawn(move || {
            let pipe = HANDLE(raw_handle as *mut std::ffi::c_void);
            client_reader(pipe, pid, tx);
        });
    }

    // The display thread runs until the process exits.
    #[allow(unreachable_code)]
    let _ = _display_handle.join();
}

/// Create a named pipe instance for the server.
fn create_pipe_instance(pipe_name: &str, first: bool) -> Result<HANDLE, String> {
    let name_wide: Vec<u16> = pipe_name.encode_utf16().chain(std::iter::once(0)).collect();
    use windows::Win32::Storage::FileSystem::FILE_FLAGS_AND_ATTRIBUTES;

    // Create a security descriptor with a NULL DACL (allows all access).
    // This is required so that medium/low integrity clients (e.g. sandboxed processes)
    // can connect to the pipe when the server is running elevated.
    let mut sd = SECURITY_DESCRIPTOR::default();
    let psd = PSECURITY_DESCRIPTOR(std::ptr::addr_of_mut!(sd).cast());
    // SAFETY: `psd` points to a valid stack-allocated SECURITY_DESCRIPTOR;
    // revision 1 is the only valid value. SetSecurityDescriptorDacl with None
    // sets a NULL DACL (allow all).
    unsafe {
        InitializeSecurityDescriptor(psd, 1)
            .map_err(|e| format!("InitializeSecurityDescriptor: {e}"))?;
        SetSecurityDescriptorDacl(psd, true, None, false)
            .map_err(|e| format!("SetSecurityDescriptorDacl: {e}"))?;
    }

    let sa = SECURITY_ATTRIBUTES {
        nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: psd.0,
        bInheritHandle: false.into(),
    };

    // PIPE_ACCESS_INBOUND (0x1) -- server reads, clients write.
    let mut open_mode = FILE_FLAGS_AND_ATTRIBUTES(0x0000_0001);
    if first {
        open_mode |= FILE_FLAG_FIRST_PIPE_INSTANCE;
    }

    // SAFETY: `name_wide` is a valid null-terminated UTF-16 string that outlives the call.
    // `sa` references a valid security descriptor on the stack. All parameters are valid.
    let handle = unsafe {
        CreateNamedPipeW(
            PCWSTR(name_wide.as_ptr()),
            open_mode,
            PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT,
            PIPE_UNLIMITED_INSTANCES,
            0,           // out buffer (server reads only)
            BUFFER_SIZE, // in buffer
            0,           // default timeout
            Some(&sa),
        )
    };

    if handle == INVALID_HANDLE_VALUE {
        return Err(format!(
            "CreateNamedPipeW failed: {}",
            std::io::Error::last_os_error()
        ));
    }

    Ok(handle)
}

/// Get the client process ID from a connected pipe handle.
fn get_client_pid(pipe: HANDLE) -> Option<u32> {
    let mut pid: u32 = 0;
    // SAFETY: `pipe` is a valid connected pipe handle; `pid` is a valid out pointer.
    let ok = unsafe { GetNamedPipeClientProcessId(pipe, &mut pid) };
    if ok.is_ok() && pid != 0 {
        Some(pid)
    } else {
        None
    }
}

/// Read messages from a connected client pipe until disconnect.
///
/// Handles both message-mode pipe clients (Rust wxc-exec, one JSON per read)
/// and stream-mode clients (Node SDK, newline-delimited JSON that may coalesce).
fn client_reader(pipe: HANDLE, pid: u32, tx: mpsc::Sender<DisplayEvent>) {
    // Wrap the pipe handle in a File for Read trait.
    // SAFETY: we own the handle and will close it at the end.
    use std::os::windows::io::FromRawHandle;
    let mut file: std::fs::File = unsafe { FromRawHandle::from_raw_handle(pipe.0) };

    let mut buf = vec![0u8; BUFFER_SIZE as usize];
    loop {
        match file.read(&mut buf) {
            Ok(0) => break, // Client disconnected (EOF).
            Ok(n) => {
                let text = String::from_utf8_lossy(&buf[..n]).to_string();
                // Split on newlines to handle coalesced stream writes.
                // A single message-mode write without newlines is also handled
                // (the whole string becomes one segment).
                for segment in text.split('\n') {
                    let segment = segment.trim();
                    if segment.is_empty() {
                        continue;
                    }
                    if let Some(msg) = parse_log_message(segment) {
                        let _ = tx.send(DisplayEvent::Message { pid, text: msg });
                    } else {
                        let _ = tx.send(DisplayEvent::Message {
                            pid,
                            text: segment.to_string(),
                        });
                    }
                }
            }
            Err(e) => {
                // ERROR_MORE_DATA (234): message was larger than buffer.
                if e.raw_os_error() == Some(234) {
                    let partial = String::from_utf8_lossy(&buf).to_string();
                    let _ = tx.send(DisplayEvent::Message {
                        pid,
                        text: format!("{partial}... (truncated)"),
                    });
                    continue;
                }
                // Any other error (including broken pipe) = disconnect.
                break;
            }
        }
    }

    let _ = tx.send(DisplayEvent::Disconnected { pid });

    // Disconnect the pipe instance before closing the handle.
    // Extract the raw handle so we can call DisconnectNamedPipe before File::drop closes it.
    use std::os::windows::io::IntoRawHandle;
    let raw = file.into_raw_handle();
    // SAFETY: `raw` is a valid pipe handle extracted from the File (which no longer owns it).
    // DisconnectNamedPipe and CloseHandle are both safe to call on a valid pipe handle.
    unsafe {
        let h = HANDLE(raw);
        let _ = DisconnectNamedPipe(h);
        let _ = CloseHandle(h);
    }
}

/// Parse a JSON log message envelope and extract the text.
///
/// Expected format: `{"msg": "the log text"}`
fn parse_log_message(json: &str) -> Option<String> {
    let v: serde_json::Value = serde_json::from_str(json).ok()?;
    v.get("msg").and_then(|m| m.as_str()).map(|s| s.to_string())
}

/// Tracks display metadata for a connected client process.
struct PidInfo {
    pid: u32,
    color_idx: usize,
    exe_name: String,
}

/// Display loop: reads events from the channel and prints them.
fn display_loop(rx: mpsc::Receiver<DisplayEvent>) {
    let mut pid_info_map: Vec<PidInfo> = Vec::new();
    let mut next_color: usize = 0;

    for event in rx {
        let ts = format_timestamp();
        match event {
            DisplayEvent::Connected { pid } => {
                let color_idx = next_color % PID_COLORS.len();
                let exe = process_exe_name(pid);
                pid_info_map.push(PidInfo {
                    pid,
                    color_idx,
                    exe_name: exe.clone(),
                });
                next_color += 1;
                let color = PID_COLORS[color_idx];
                println!(
                    "{DIM}[{ts}]{RESET} {color}>>>{RESET} {color}{exe}:{pid}{RESET} connected"
                );
            }
            DisplayEvent::Message { pid, text } => {
                let (color, exe) = get_pid_info(&pid_info_map, pid);
                for line in text.lines() {
                    if line.starts_with("WARNING:") {
                        println!("{DIM}[{ts}]{RESET} {color}[{exe}:{pid}]{RESET} \x1b[1;33m{line}\x1b[0m");
                    } else if line.starts_with("SECTION:") {
                        println!("{DIM}[{ts}]{RESET} {color}[{exe}:{pid}]{RESET} \x1b[1;36m{line}\x1b[0m");
                    } else if line.starts_with("ERROR:") || line.starts_with("Error:") {
                        println!("{DIM}[{ts}]{RESET} {color}[{exe}:{pid}]{RESET} \x1b[1;31m{line}\x1b[0m");
                    } else {
                        println!("{DIM}[{ts}]{RESET} {color}[{exe}:{pid}]{RESET} {line}");
                    }
                }
            }
            DisplayEvent::Disconnected { pid } => {
                let (color, exe) = get_pid_info(&pid_info_map, pid);
                println!(
                    "{DIM}[{ts}]{RESET} {color}<<<{RESET} {color}{exe}:{pid}{RESET} disconnected"
                );
            }
            DisplayEvent::EtwEvent { pid, text } => {
                // ETW events may come from kernel PIDs not in our pipe map.
                let (color, exe) = get_pid_info(&pid_info_map, pid);
                let label = if exe == "?" {
                    // Try to resolve on the fly for ETW-only PIDs.
                    let resolved = process_exe_name(pid);
                    format!("{resolved}:{pid}")
                } else {
                    format!("{exe}:{pid}")
                };
                println!("{DIM}[{ts}]{RESET} \x1b[93m[ETW]\x1b[0m {color}[{label}]{RESET} {text}");
            }
        }
    }
}

/// Get the ANSI color code and exe name for a PID.
fn get_pid_info(map: &[PidInfo], pid: u32) -> (&'static str, &str) {
    map.iter()
        .find(|info| info.pid == pid)
        .map(|info| (PID_COLORS[info.color_idx], info.exe_name.as_str()))
        .unwrap_or((PID_COLORS[0], "?"))
}

/// Look up the executable name for a process ID. Returns just the filename.
fn process_exe_name(pid: u32) -> String {
    // SAFETY: OpenProcess returns a valid handle or error (checked via match).
    // GetModuleFileNameExW writes into a stack buffer with bounded length.
    // CloseHandle is called on the valid process handle.
    unsafe {
        let handle = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid);
        let handle = match handle {
            Ok(h) => h,
            Err(_) => return format!("PID{pid}"),
        };
        let mut buf = [0u16; 260];
        let len = GetModuleFileNameExW(Some(handle), None, &mut buf);
        let _ = CloseHandle(handle);
        if len == 0 {
            // GetLastError would give details, but this is best-effort name resolution.
            return format!("PID{pid}");
        }
        let full = String::from_utf16_lossy(&buf[..len as usize]);
        full.rsplit('\\').next().unwrap_or(&full).to_string()
    }
}

/// Format a timestamp as `HH:MM:SS.mmm`.
fn format_timestamp() -> String {
    let dur = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or_default();
    let secs = dur.as_secs();
    let millis = dur.subsec_millis();
    let time_of_day = secs % 86400;
    let hours = time_of_day / 3600;
    let minutes = (time_of_day % 3600) / 60;
    let seconds = time_of_day % 60;
    format!("{hours:02}:{minutes:02}:{seconds:02}.{millis:03}")
}

/// Enable ANSI virtual terminal processing on the Windows console.
fn enable_virtual_terminal() {
    use windows::Win32::System::Console::{
        GetConsoleMode, GetStdHandle, SetConsoleMode, ENABLE_VIRTUAL_TERMINAL_PROCESSING,
        STD_OUTPUT_HANDLE,
    };
    // SAFETY: GetStdHandle returns the stdout handle (or error, checked with is_ok).
    // GetConsoleMode/SetConsoleMode operate on the valid stdout handle.
    unsafe {
        if let Ok(handle) = GetStdHandle(STD_OUTPUT_HANDLE) {
            let mut mode = Default::default();
            if GetConsoleMode(handle, &mut mode).is_ok() {
                let _ = SetConsoleMode(handle, mode | ENABLE_VIRTUAL_TERMINAL_PROCESSING);
            }
        }
    }
}

/// Register a console Ctrl handler to cleanly stop the ETW trace session.
fn register_ctrl_handler() {
    use windows::Win32::System::Console::{SetConsoleCtrlHandler, CTRL_CLOSE_EVENT, CTRL_C_EVENT};

    unsafe extern "system" fn handler(ctrl_type: u32) -> windows_core::BOOL {
        if ctrl_type == CTRL_C_EVENT || ctrl_type == CTRL_CLOSE_EVENT {
            etw::stop_etw_listener();
        }
        // Return FALSE so the default handler terminates the process.
        windows_core::BOOL(0)
    }

    // SAFETY: SetConsoleCtrlHandler with a valid function pointer is safe.
    // The handler function has the correct `unsafe extern "system"` signature.
    unsafe {
        let _ = SetConsoleCtrlHandler(Some(handler), true);
    }
}
