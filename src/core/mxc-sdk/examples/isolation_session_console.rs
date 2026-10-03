// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Hosts an interactive terminal inside an isolation session, in-process, from
//! a console application. Takes the same request JSON as `wxc-exec`.
//!
//! # Operator scenarios
//!
//! These have no automated oracle — an operator runs them and judges what they
//! see.
//!
//! ```text
//! cargo run -p mxc-sdk --features isolation_session --example isolation_session_console -- interactive
//! ```
//!
//! | Scenario | What it proves |
//! |---|---|
//! | `interactive` | ConPTY rendering, input, and exit-code propagation (`exit 7` → `Exited(7)`) |
//! | `streaming` | Output arrives progressively, not as a burst at exit |
//! | `resize` | The sandboxed process sees window-size changes live |
//!
//! The driver exits with the workload's exit code.
//!
//! Any other argument is treated as a literal command line.
//!
//! Must run at a real interactive console.

use std::{
    io::{self, Read, Write},
    thread,
};

#[cfg(target_os = "windows")]
use std::time::Duration;

use mxc_sdk::v1::{
    self, ContainerId, ExecRequest, MxcPtySize, OperationOptions, ProvisionRequest, WaitOutcome,
};

#[cfg(target_os = "windows")]
use mxc_sdk::v1::MxcPtyProcess;

type DriverResult<T> = Result<T, Box<dyn std::error::Error>>;

struct Teardown {
    container_id: ContainerId,
    options: OperationOptions,
}

impl Drop for Teardown {
    fn drop(&mut self) {
        eprintln!("\n[driver] tearing down…");
        let _ = v1::container::stop_sandbox(&self.container_id, self.options);
        match v1::container::deprovision_sandbox(&self.container_id, self.options) {
            Ok(_) => eprintln!("[driver] deprovisioned."),
            Err(error) => {
                eprintln!("[driver] WARNING: deprovision failed, account may leak: {error:?}")
            }
        }
    }
}

/// The scenarios differ only in command line; what they check is console
/// behaviour, not the SDK surface.
struct Scenario {
    name: &'static str,
    command: &'static str,
    what_to_look_for: &'static str,
}

const SCENARIOS: &[Scenario] = &[
    Scenario {
        name: "interactive",
        command: "powershell.exe -NoLogo",
        what_to_look_for: "The prompt draws and redraws. Colours, cursor movement and \
                           tab-completion behave. Type commands, then `exit 7` — the outcome \
                           printed at the end must be Exited(7).",
    },
    Scenario {
        name: "streaming",
        command: "cmd.exe /c echo line_1 & ping -n 3 127.0.0.1 >nul & echo line_2 & \
                  ping -n 3 127.0.0.1 >nul & echo line_3",
        what_to_look_for: "The three lines must appear ~2s apart as they are produced, NOT \
                           all at once when the process exits.",
    },
    Scenario {
        name: "resize",
        command: "powershell.exe -NoLogo -NoProfile -Command \"while ($true) { \
                  $w = $Host.UI.RawUI.WindowSize.Width; \
                  Write-Host ('{0,-4}' -f $w) -NoNewline; \
                  Write-Host ('.' * [Math]::Max(0, $w - 6) + '|'); \
                  Start-Sleep -Milliseconds 500 }\"",
        what_to_look_for: "A ruler is drawn to the full window width, with the width printed \
                           at the left. RESIZE THE WINDOW while it runs: the ruler must track \
                           the new width. Ctrl-C to finish.",
    },
];

fn usage() -> i32 {
    eprintln!("usage: isolation_session_console [interactive|streaming|resize|<command line>]");
    eprintln!();
    for s in SCENARIOS {
        eprintln!("  {:<12} {}", s.name, s.command);
    }
    eprintln!();
    eprintln!("Anything else is treated as a literal command line to run in the session.");
    2
}

/// Returns the exit code rather than calling `std::process::exit`, which would
/// skip the `Teardown` guard.
fn run() -> DriverResult<i32> {
    let arg = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "interactive".into());
    if arg == "--help" || arg == "-h" {
        return Ok(usage());
    }

    let (label, command, guidance) = match SCENARIOS.iter().find(|s| s.name == arg) {
        Some(s) => (s.name, s.command.to_string(), Some(s.what_to_look_for)),
        None => ("custom", arg, None),
    };

    if !mxc_sdk::available_backends()
        .iter()
        .any(|b| b.backend == "isolation_session")
    {
        eprintln!("IsolationSession is not available on this host.");
        return Ok(2);
    }

    let options = OperationOptions::new(true);
    let provisioned =
        v1::container::provision_sandbox(ProvisionRequest::isolation_session(None), options)?;
    let container_id = provisioned.container_id;
    let _teardown = Teardown {
        container_id: container_id.clone(),
        options,
    };
    eprintln!("[driver] provisioned.");

    v1::container::start_sandbox(&container_id, options)?;
    eprintln!("[driver] started. Scenario: {label}");
    if let Some(g) = guidance {
        eprintln!("[driver] WHAT TO LOOK FOR: {g}");
    }
    eprintln!("[driver] everything below runs inside the isolation session.\n");

    let outcome = if label == "streaming" {
        run_piped(&container_id, &command, options)?
    } else {
        run_with_pty(&container_id, &command, options)?
    };
    println!("\n[driver] outcome: {outcome:?}");
    Ok(match outcome {
        WaitOutcome::Exited(code) => code,
        WaitOutcome::TimedOut => 1,
    })
}

fn main() {
    match run() {
        Ok(code) => std::process::exit(code),
        Err(error) => {
            eprintln!("[driver] failed: {error}");
            std::process::exit(1);
        }
    }
}

fn exec_request(command: &str) -> ExecRequest {
    let mut request = ExecRequest::new(command);
    request.set_timeout(3_600_000);
    request
}

fn run_piped(
    container_id: &ContainerId,
    command: &str,
    options: OperationOptions,
) -> DriverResult<WaitOutcome> {
    let mut process = v1::spawn_in_container(container_id, exec_request(command), options)?;
    let mut stdout = process
        .take_stdout()
        .ok_or("the backend did not expose stdout")?;
    let mut stderr = process
        .take_stderr()
        .ok_or("the backend did not expose stderr")?;
    let stdout_task = thread::spawn(move || io::copy(&mut stdout, &mut io::stdout().lock()));
    let stderr_task = thread::spawn(move || io::copy(&mut stderr, &mut io::stderr().lock()));
    let outcome = process.wait()?;
    stdout_task
        .join()
        .map_err(|_| io::Error::other("stdout relay panicked"))??;
    stderr_task
        .join()
        .map_err(|_| io::Error::other("stderr relay panicked"))??;
    Ok(outcome)
}

#[cfg(target_os = "windows")]
fn run_with_pty(
    container_id: &ContainerId,
    command: &str,
    options: OperationOptions,
) -> DriverResult<WaitOutcome> {
    let size = current_console_size()?;
    let process = v1::container::spawn_in_container_with_pty(
        container_id,
        exec_request(command),
        size,
        options,
    )?;
    relay_pty(process)
}

#[cfg(not(target_os = "windows"))]
fn run_with_pty(
    _container_id: &ContainerId,
    _command: &str,
    _options: OperationOptions,
) -> DriverResult<WaitOutcome> {
    Err("the IsolationSession console driver requires Windows".into())
}

#[cfg(target_os = "windows")]
fn relay_pty(process: MxcPtyProcess) -> DriverResult<WaitOutcome> {
    let _console_mode = ConsoleMode::enter()?;
    let mut reader = process.try_clone_reader()?;
    let mut writer = process.take_writer()?;
    let output_task = thread::spawn(move || io::copy(&mut reader, &mut io::stdout().lock()));
    let _input_task = thread::spawn(move || {
        let mut input = io::stdin().lock();
        let mut buffer = [0_u8; 4096];
        loop {
            let count = match input.read(&mut buffer) {
                Ok(0) => return,
                Ok(count) => count,
                Err(error) => {
                    eprintln!("[driver] console input relay failed: {error}");
                    return;
                }
            };
            if let Err(error) = writer.write_all(&buffer[..count]) {
                if error.kind() != io::ErrorKind::BrokenPipe {
                    eprintln!("[driver] PTY input relay failed: {error}");
                }
                return;
            }
        }
    });

    let mut previous_size = current_console_size()?;
    loop {
        match process.try_wait() {
            Ok(Some(_)) => break,
            Ok(None) => {}
            Err(error) if error.kind() == io::ErrorKind::TimedOut => break,
            Err(error) => return Err(error.into()),
        }
        let size = current_console_size()?;
        if size != previous_size {
            process.resize(size)?;
            previous_size = size;
        }
        thread::sleep(Duration::from_millis(100));
    }

    let outcome = process.wait()?;
    if let Some(closer) = process.stdout_closer() {
        closer.close();
    }
    output_task
        .join()
        .map_err(|_| io::Error::other("PTY output relay panicked"))??;
    Ok(outcome)
}

#[cfg(target_os = "windows")]
struct ConsoleMode {
    input: windows::Win32::Foundation::HANDLE,
    output: windows::Win32::Foundation::HANDLE,
    input_mode: windows::Win32::System::Console::CONSOLE_MODE,
    output_mode: windows::Win32::System::Console::CONSOLE_MODE,
}

#[cfg(target_os = "windows")]
impl ConsoleMode {
    fn enter() -> io::Result<Self> {
        use windows::Win32::System::Console::{
            GetConsoleMode, GetStdHandle, SetConsoleMode, CONSOLE_MODE,
            DISABLE_NEWLINE_AUTO_RETURN, ENABLE_ECHO_INPUT, ENABLE_LINE_INPUT,
            ENABLE_PROCESSED_INPUT, ENABLE_VIRTUAL_TERMINAL_INPUT,
            ENABLE_VIRTUAL_TERMINAL_PROCESSING, STD_INPUT_HANDLE, STD_OUTPUT_HANDLE,
        };

        let input = unsafe { GetStdHandle(STD_INPUT_HANDLE) }.map_err(io::Error::other)?;
        let output = unsafe { GetStdHandle(STD_OUTPUT_HANDLE) }.map_err(io::Error::other)?;
        let mut input_mode = CONSOLE_MODE(0);
        let mut output_mode = CONSOLE_MODE(0);
        unsafe { GetConsoleMode(input, &mut input_mode) }.map_err(io::Error::other)?;
        unsafe { GetConsoleMode(output, &mut output_mode) }.map_err(io::Error::other)?;

        let raw_input = CONSOLE_MODE(
            (input_mode.0 | ENABLE_VIRTUAL_TERMINAL_INPUT.0)
                & !(ENABLE_PROCESSED_INPUT.0 | ENABLE_LINE_INPUT.0 | ENABLE_ECHO_INPUT.0),
        );
        let raw_output = CONSOLE_MODE(
            output_mode.0 | ENABLE_VIRTUAL_TERMINAL_PROCESSING.0 | DISABLE_NEWLINE_AUTO_RETURN.0,
        );
        unsafe { SetConsoleMode(input, raw_input) }.map_err(io::Error::other)?;
        if let Err(error) = unsafe { SetConsoleMode(output, raw_output) } {
            let _ = unsafe { SetConsoleMode(input, input_mode) };
            return Err(io::Error::other(error));
        }
        Ok(Self {
            input,
            output,
            input_mode,
            output_mode,
        })
    }
}

#[cfg(target_os = "windows")]
impl Drop for ConsoleMode {
    fn drop(&mut self) {
        use windows::Win32::System::Console::SetConsoleMode;

        let _ = unsafe { SetConsoleMode(self.output, self.output_mode) };
        let _ = unsafe { SetConsoleMode(self.input, self.input_mode) };
    }
}

#[cfg(target_os = "windows")]
fn current_console_size() -> io::Result<MxcPtySize> {
    use windows::Win32::System::Console::{
        GetConsoleScreenBufferInfo, GetStdHandle, CONSOLE_SCREEN_BUFFER_INFO, STD_OUTPUT_HANDLE,
    };

    let output = unsafe { GetStdHandle(STD_OUTPUT_HANDLE) }.map_err(io::Error::other)?;
    let mut info = CONSOLE_SCREEN_BUFFER_INFO::default();
    unsafe { GetConsoleScreenBufferInfo(output, &mut info) }.map_err(io::Error::other)?;
    let rows = u16::try_from(i32::from(info.srWindow.Bottom) - i32::from(info.srWindow.Top) + 1)
        .map_err(io::Error::other)?;
    let cols = u16::try_from(i32::from(info.srWindow.Right) - i32::from(info.srWindow.Left) + 1)
        .map_err(io::Error::other)?;
    Ok(MxcPtySize {
        rows,
        cols,
        pixel_width: 0,
        pixel_height: 0,
    })
}
