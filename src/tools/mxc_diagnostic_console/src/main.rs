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
mod pipe_utils;
pub mod denial_event;
pub mod denial_pipe;
mod service;

use std::collections::HashMap;
use std::io::{BufWriter, Read, Write};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU8, AtomicUsize, Ordering};
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, SystemTime};

use clap::Parser;

use windows::Win32::Foundation::{CloseHandle, HANDLE};
use windows::Win32::Security::{TOKEN_ELEVATION, TOKEN_QUERY};
use windows::Win32::System::Pipes::DisconnectNamedPipe;
use windows::Win32::System::ProcessStatus::GetModuleFileNameExW;
use windows::Win32::System::Threading::{
    GetCurrentProcess, OpenProcess, OpenProcessToken, PROCESS_QUERY_LIMITED_INFORMATION,
};

/// Maximum message size in bytes (256 KB -- enough for large redacted JSON).
const BUFFER_SIZE: u32 = 256 * 1024;

/// Maximum number of concurrent diagnostic-pipe client handler threads.
const MAX_CLIENTS: usize = 64;

/// Active diagnostic-pipe client handler thread count, used to enforce [`MAX_CLIENTS`].
static ACTIVE_CLIENTS: AtomicUsize = AtomicUsize::new(0);

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

/// Whether `--collect` mode is active.
static COLLECT_MODE_FLAG: AtomicBool = AtomicBool::new(false);

/// Shutdown signal set by the Ctrl+C handler to trigger graceful finalization.
static SHUTDOWN: AtomicBool = AtomicBool::new(false);

pub fn collect_mode() -> bool {
    COLLECT_MODE_FLAG.load(Ordering::Relaxed)
}

/// Events sent from reader threads to the display thread.
enum DisplayEvent {
    /// A new client connected with the given PID.
    Connected { pid: u32 },
    /// A log message arrived from a client.
    Message { pid: u32, text: String },
    /// A client disconnected.
    Disconnected { pid: u32 },
    /// An ETW event from the MXC OS-side provider.
    EtwEvent {
        pid: u32,
        text: String,
        /// Full (verbose) rendering for the verbose log (only populated in collect mode).
        verbose_text: Option<String>,
        /// Minified rendering for the minified log (only in collect mode;
        /// inner `None` means the event was suppressed in minified mode).
        minified_text: Option<Option<String>>,
    },
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

/// Check whether wxc-exec diagnostic console output is enabled (env var).
fn is_diagnostic_console_enabled() -> bool {
    std::env::var("MXC_DIAG_CONSOLE").ok().as_deref() == Some("1")
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

    /// Collect logs to files. Captures both verbose and minified output to a
    /// timestamped folder in %TEMP%, then zips the folder on exit (Ctrl+C).
    #[arg(long)]
    collect: bool,

    /// Run as a Windows service (invoked by the SCM, not for manual use).
    #[arg(long)]
    service: bool,

    /// Install the diagnostic console as a Windows service.
    #[arg(long)]
    install: bool,

    /// Uninstall the Windows service registration.
    #[arg(long)]
    uninstall: bool,
}

fn main() {
    let cli = Cli::parse();

    // Handle service-related subcommands first (they don't use the interactive console).
    if cli.install {
        if let Err(e) = service::install_service() {
            eprintln!("Error: {e}");
            std::process::exit(1);
        }
        return;
    }

    if cli.uninstall {
        if let Err(e) = service::uninstall_service() {
            eprintln!("Error: {e}");
            std::process::exit(1);
        }
        return;
    }

    if cli.service {
        // Running as a Windows service -- hand off to the service dispatcher.
        if let Err(e) = service::run_as_service() {
            // Cannot print in service mode, but if we get here the dispatcher
            // failed to start (e.g. not actually launched by the SCM).
            eprintln!("Error: {e}");
            std::process::exit(1);
        }
        return;
    }

    // --- Interactive (console) mode ---

    if cli.verbose {
        DISPLAY_MODE.store(DisplayMode::Full as u8, Ordering::Relaxed);
    } else {
        DISPLAY_MODE.store(DisplayMode::Minified as u8, Ordering::Relaxed);
    }

    if cli.collect {
        COLLECT_MODE_FLAG.store(true, Ordering::Relaxed);
    }

    // Create the collection directory (if --collect).
    let collect_dir = if cli.collect {
        match create_collect_dir() {
            Ok(dir) => {
                println!(
                    "\x1b[1;32m[collect]\x1b[0m Collecting logs to: {}",
                    dir.display()
                );
                Some(dir)
            }
            Err(e) => {
                eprintln!("\x1b[1;31m[collect]\x1b[0m Failed to create collection directory: {e}");
                std::process::exit(1);
            }
        }
    } else {
        None
    };

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
    if cli.collect {
        println!("{DIM}Collection: enabled (Ctrl+C to stop and finalize){RESET}");
    }
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
        line("  ETW event capture (MXC OS provider + learning mode events) requires administrator privileges.");
        line("  Pipe-based log messages from wxc-exec will still work without elevation.");
        println!("{blank}");
        println!("{y}╚{bar}╝{r}");
        println!();
    }

    // Channel for reader threads to send display events.
    let (tx, rx) = mpsc::channel::<DisplayEvent>();

    // Start the Tier-1 denial pipe server. This is the *primary* supported
    // deployment for the denial-capture feature: the interactive console runs
    // as the logged-in (interactive) user, so the per-user denial pipe
    // (`mxc-denials-{SID}`) is created under that user's SID and is directly
    // reachable by the SDK running in the same user session.
    //
    // The returned sender is handed to the ETW listener so denial events
    // decoded from ETW are forwarded to the denial pipe. `_denial_handle` is
    // held for the lifetime of the process; dropping it would only detach the
    // server thread, but binding it (rather than `_`) keeps the intent explicit
    // and avoids prematurely dropping the join handle.
    let (denial_tx, _denial_handle) = denial_pipe::start_denial_pipe_server();

    // Start ETW listener (best-effort; warns on failure).
    match etw::start_etw_listener(tx.clone(), Some(denial_tx)) {
        Ok(()) => {
            println!("\x1b[93m[ETW]\x1b[0m Listening for providers:");
            println!(
                "\x1b[93m[ETW]\x1b[0m   ProcessModel \
                 {{f6ec123e-314e-400b-9e0a-151365e23083}} (Sandboxing)"
            );
            println!(
                "\x1b[93m[ETW]\x1b[0m   Kernel-General \
                 {{a68ca8b7-004f-d7b6-a698-07e2de0f1f5d}} (Learning Mode messages)"
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
        display_loop(rx, collect_dir);
    });

    // Accept loop: create pipe instances and dispatch connected clients. The
    // create-pipe -> ConnectNamedPipe -> read-PID -> MAX_CLIENTS-check ->
    // spawn-handler pattern is shared with the service path via
    // [`pipe_utils::run_accept_loop`].
    let accept_tx = tx.clone();
    pipe_utils::run_accept_loop(
        |first| create_pipe_instance(&pipe_name, first),
        move |pipe, pid| {
            let tx = accept_tx.clone();
            let _ = tx.send(DisplayEvent::Connected { pid });
            client_reader(pipe, pid, tx);
        },
        MAX_CLIENTS,
        &ACTIVE_CLIENTS,
        &SHUTDOWN,
        true, // verbose: interactive mode prints errors to stderr
    );

    // Once the accept loop exits (shutdown signalled), wait for the display
    // thread to finish draining and finalizing.
    let _ = _display_handle.join();
}

/// Create a named pipe instance for the server.
///
/// Uses a dynamic, per-user SDDL security descriptor (see
/// [`pipe_utils::build_pipe_sddl`]) that grants the current user Generic Read +
/// Write, denies AppContainer processes (`ALL_APP_PACKAGES`, `S-1-15-2-1`), and
/// grants SYSTEM and Built-in Administrators full access. This prevents other
/// machine users from connecting and injecting log messages.
///
/// Returns an error if the current user's SID cannot be resolved; in that case the
/// pipe is not created and we never fall back to a weaker, machine-wide ACL.
pub(crate) fn create_pipe_instance(pipe_name: &str, first: bool) -> Result<HANDLE, String> {
    let sddl = pipe_utils::build_pipe_sddl().ok_or_else(|| {
        "failed to resolve current user SID; refusing to create diagnostic pipe with weaker ACLs"
            .to_string()
    })?;

    // PIPE_ACCESS_INBOUND (0x1): server reads, clients write.
    pipe_utils::create_pipe_with_sddl(
        pipe_name,
        &sddl,
        0x0000_0001, // PIPE_ACCESS_INBOUND
        BUFFER_SIZE, // in buffer
        0,           // out buffer (server reads only)
        first,
    )
    .map_err(|e| format!("CreateNamedPipeW failed: {e}"))
}

/// Read messages from a connected client pipe until disconnect.
///
/// Handles both message-mode pipe clients (Rust wxc-exec, one JSON per read)
/// and stream-mode clients (Node SDK, newline-delimited JSON that may coalesce).
pub(crate) fn client_reader(pipe: HANDLE, pid: u32, tx: mpsc::Sender<DisplayEvent>) {
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
    color_idx: usize,
    exe_name: String,
}

/// Display loop: reads events from the channel and prints them.
/// When `collect_dir` is `Some`, also writes ANSI-stripped output to log files.
fn display_loop(rx: mpsc::Receiver<DisplayEvent>, collect_dir: Option<PathBuf>) {
    let mut pid_info_map: HashMap<u32, PidInfo> = HashMap::new();
    let mut next_color: usize = 0;

    // Open log files if collecting.
    let mut log_writers: Option<(BufWriter<std::fs::File>, BufWriter<std::fs::File>)> =
        collect_dir.as_ref().map(|dir| {
            let verbose_file = std::fs::File::create(dir.join("verbose.log"))
                .expect("Failed to create verbose.log");
            let minified_file = std::fs::File::create(dir.join("minified.log"))
                .expect("Failed to create minified.log");
            (BufWriter::new(verbose_file), BufWriter::new(minified_file))
        });

    let mut flush_counter: u32 = 0;

    loop {
        let event = if collect_dir.is_some() {
            // Use recv_timeout so we can check the SHUTDOWN flag.
            match rx.recv_timeout(Duration::from_millis(250)) {
                Ok(ev) => ev,
                Err(mpsc::RecvTimeoutError::Timeout) => {
                    if SHUTDOWN.load(Ordering::Relaxed) {
                        // Drain remaining events before exiting.
                        while let Ok(ev) = rx.try_recv() {
                            process_display_event(
                                ev,
                                &mut pid_info_map,
                                &mut next_color,
                                &mut log_writers,
                            );
                        }
                        break;
                    }
                    // Periodic flush while idle.
                    if let Some((ref mut v, ref mut m)) = log_writers {
                        let _ = v.flush();
                        let _ = m.flush();
                    }
                    continue;
                }
                Err(mpsc::RecvTimeoutError::Disconnected) => break,
            }
        } else {
            match rx.recv() {
                Ok(ev) => ev,
                Err(_) => break,
            }
        };

        process_display_event(event, &mut pid_info_map, &mut next_color, &mut log_writers);

        // Periodic flush every 50 events.
        flush_counter += 1;
        if flush_counter >= 50 {
            flush_counter = 0;
            if let Some((ref mut v, ref mut m)) = log_writers {
                let _ = v.flush();
                let _ = m.flush();
            }
        }
    }

    // Final flush and finalization.
    if let Some((ref mut v, ref mut m)) = log_writers {
        let _ = v.flush();
        let _ = m.flush();
    }
    drop(log_writers);

    if let Some(dir) = collect_dir {
        finalize_collection(&dir);
        std::process::exit(0);
    }
}

/// Process a single display event: print to console and optionally write to log files.
fn process_display_event(
    event: DisplayEvent,
    pid_info_map: &mut HashMap<u32, PidInfo>,
    next_color: &mut usize,
    log_writers: &mut Option<(BufWriter<std::fs::File>, BufWriter<std::fs::File>)>,
) {
    let ts = format_timestamp();
    match event {
        DisplayEvent::Connected { pid } => {
            let color_idx = *next_color % PID_COLORS.len();
            let exe = process_exe_name(pid);
            pid_info_map.insert(
                pid,
                PidInfo {
                    color_idx,
                    exe_name: exe.clone(),
                },
            );
            *next_color += 1;
            let color = PID_COLORS[color_idx];
            let line =
                format!("{DIM}[{ts}]{RESET} {color}>>>{RESET} {color}{exe}:{pid}{RESET} connected");
            println!("{line}");
            if let Some((ref mut v, ref mut m)) = log_writers {
                let plain = format!("[{ts}] >>> {exe}:{pid} connected\n");
                let _ = v.write_all(plain.as_bytes());
                let _ = m.write_all(plain.as_bytes());
            }
        }
        DisplayEvent::Message { pid, text } => {
            let (color, exe) = get_pid_info(pid_info_map, pid);
            for line in text.lines() {
                if line.starts_with("WARNING:") {
                    println!(
                        "{DIM}[{ts}]{RESET} {color}[{exe}:{pid}]{RESET} \x1b[1;33m{line}\x1b[0m"
                    );
                } else if line.contains("SECTION:") {
                    println!(
                        "{DIM}[{ts}]{RESET} {color}[{exe}:{pid}]{RESET} \x1b[1;36m{line}\x1b[0m"
                    );
                } else if line.starts_with("ERROR:") || line.starts_with("Error:") {
                    println!(
                        "{DIM}[{ts}]{RESET} {color}[{exe}:{pid}]{RESET} \x1b[1;31m{line}\x1b[0m"
                    );
                } else {
                    println!("{DIM}[{ts}]{RESET} {color}[{exe}:{pid}]{RESET} {line}");
                }
                if let Some((ref mut v, ref mut m)) = log_writers {
                    let plain = format!("[{ts}] [{exe}:{pid}] {line}\n");
                    let _ = v.write_all(plain.as_bytes());
                    let _ = m.write_all(plain.as_bytes());
                }
            }
        }
        DisplayEvent::Disconnected { pid } => {
            let line = {
                let (color, exe) = get_pid_info(pid_info_map, pid);
                let l = format!(
                    "{DIM}[{ts}]{RESET} {color}<<<{RESET} {color}{exe}:{pid}{RESET} disconnected"
                );
                if let Some((ref mut v, ref mut m)) = log_writers {
                    let plain = format!("[{ts}] <<< {exe}:{pid} disconnected\n");
                    let _ = v.write_all(plain.as_bytes());
                    let _ = m.write_all(plain.as_bytes());
                }
                l
            };
            println!("{line}");
            // The client's reader thread has finished its cleanup
            // (DisconnectNamedPipe/CloseHandle) and will not be seen again, so
            // drop its display metadata to prevent unbounded map growth across
            // many short-lived connections.
            pid_info_map.remove(&pid);
        }
        DisplayEvent::EtwEvent {
            pid,
            text,
            verbose_text,
            minified_text,
        } => {
            let (color, exe) = get_pid_info(pid_info_map, pid);
            let label = if exe == "?" {
                let resolved = process_exe_name(pid);
                format!("{resolved}:{pid}")
            } else {
                format!("{exe}:{pid}")
            };
            println!("{DIM}[{ts}]{RESET} \x1b[93m[ETW]\x1b[0m {color}[{label}]{RESET} {text}");

            if let Some((ref mut v, ref mut m)) = log_writers {
                // Write verbose text to verbose.log.
                if let Some(ref vt) = verbose_text {
                    let plain = format!("[{ts}] [ETW] [{label}] {}\n", strip_ansi(vt));
                    let _ = v.write_all(plain.as_bytes());
                }
                // Write minified text to minified.log (skip if suppressed).
                if let Some(Some(ref mt)) = minified_text {
                    let plain = format!("[{ts}] [ETW] [{label}] {}\n", strip_ansi(mt));
                    let _ = m.write_all(plain.as_bytes());
                }
            }
        }
    }
}

/// Get the ANSI color code and exe name for a PID.
fn get_pid_info(map: &HashMap<u32, PidInfo>, pid: u32) -> (&'static str, &str) {
    map.get(&pid)
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

/// Strip ANSI escape codes from a string for plain-text log output.
fn strip_ansi(s: &str) -> String {
    let mut result = String::with_capacity(s.len());
    let mut chars = s.chars();
    while let Some(c) = chars.next() {
        if c == '\x1b' {
            // Skip until we hit a letter (the terminator of an ANSI sequence).
            for c2 in chars.by_ref() {
                if c2.is_ascii_alphabetic() {
                    break;
                }
            }
        } else {
            result.push(c);
        }
    }
    result
}

/// Create the timestamped collection directory in %TEMP%.
fn create_collect_dir() -> Result<PathBuf, String> {
    let temp = std::env::temp_dir();
    let now = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or_default();
    let secs = now.as_secs();
    let time_of_day = secs % 86400;
    let days = secs / 86400;

    // Approximate date from days since epoch.
    let (year, month, day) = days_to_ymd(days);
    let hours = time_of_day / 3600;
    let minutes = (time_of_day % 3600) / 60;
    let seconds = time_of_day % 60;
    let pid = std::process::id();

    let dir_name = format!(
        "mxc-diagnostics-{year:04}{month:02}{day:02}-{hours:02}{minutes:02}{seconds:02}-{pid}"
    );
    let dir = temp.join(dir_name);
    std::fs::create_dir_all(&dir).map_err(|e| format!("create_dir_all: {e}"))?;
    Ok(dir)
}

/// Convert days since Unix epoch to (year, month, day).
fn days_to_ymd(days: u64) -> (u64, u64, u64) {
    // Civil calendar algorithm (simplified Euclidean).
    let z = days + 719468;
    let era = z / 146097;
    let doe = z - era * 146097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146097) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    (y, m, d)
}

/// Finalize collection: zip the folder and print results.
fn finalize_collection(dir: &std::path::Path) {
    println!();
    println!("\x1b[1;32m[collect]\x1b[0m Finalizing collection...");

    let zip_path = dir.with_extension("zip");

    // Use PowerShell Compress-Archive to create the zip.
    let source = format!("{}\\*", dir.display());
    let dest = format!("{}", zip_path.display());

    let result = std::process::Command::new("powershell.exe")
        .args([
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            &format!(
                "Compress-Archive -Path '{}' -DestinationPath '{}' -Force",
                source, dest
            ),
        ])
        .status();

    let zip_ok = match result {
        Ok(status) if status.success() => true,
        Ok(status) => {
            eprintln!("\x1b[1;33m[collect]\x1b[0m Compress-Archive exited with status: {status}");
            false
        }
        Err(e) => {
            eprintln!("\x1b[1;33m[collect]\x1b[0m Failed to run PowerShell: {e}");
            false
        }
    };

    println!();
    println!("\x1b[1;36m=== Collection Complete ===\x1b[0m");
    println!("  Log folder:  {}", dir.display());
    println!("    verbose.log   (all ETW event properties)");
    println!("    minified.log  (reduced ETW event properties)");
    if zip_ok {
        println!("  Archive:     {}", zip_path.display());
    } else {
        println!("  Archive:     (zip creation failed; logs are still in the folder above)");
    }
    println!();
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

            if COLLECT_MODE_FLAG.load(Ordering::Relaxed) {
                // First Ctrl+C: signal graceful shutdown and suppress default termination.
                // Second Ctrl+C: allow default termination (hard exit).
                if SHUTDOWN.swap(true, Ordering::SeqCst) {
                    // Already set -- this is the second interrupt. Hard exit.
                    return windows_core::BOOL(0);
                }
                return windows_core::BOOL(1);
            }
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
