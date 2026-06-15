// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! `mxc-exec-mac` — macOS sandbox executor.
//!
//! Mirrors the CLI shape of `lxc-exec` (clap args, config loading, dry-run,
//! log-file). On macOS it dispatches to `SeatbeltScriptRunner`; on every
//! other platform it prints an explanatory error and exits 1 — that way
//! `cargo build -p mxc_darwin` succeeds in CI from any host, while runtime
//! use still requires macOS.

use std::fmt::Write;
use std::process;

use clap::Parser;
use wxc_common::config_parser::load_request;
use wxc_common::logger::{Logger, Mode};
use wxc_common::models::{ContainmentBackend, ExecutionRequest};

#[cfg(target_os = "macos")]
use std::time::Instant;
#[cfg(target_os = "macos")]
use wxc_common::models::ScriptResponse;

#[cfg(target_os = "macos")]
use wxc_common::script_runner::{handle_dry_run_exit, ScriptRunner};

#[derive(Parser)]
#[command(name = "mxc-exec-mac", about = "macOS sandbox executor for MXC")]
struct Cli {
    /// Path to config JSON file (positional)
    #[arg(value_name = "CONFIG_PATH")]
    config_path: Option<String>,

    /// Path to config JSON file
    #[arg(long = "config")]
    config: Option<String>,

    /// Base64-encoded JSON config
    #[arg(long = "config-base64")]
    config_base64: Option<String>,

    /// Enable debug/console output
    #[arg(long)]
    debug: bool,

    /// Enable experimental features
    #[arg(long)]
    experimental: bool,

    /// Parse and validate config then exit without executing
    #[arg(long = "dry-run")]
    dry_run: bool,

    /// Path to diagnostic log file (appends, creates if missing)
    #[arg(long = "log-file")]
    log_file: Option<String>,
}

fn log_request(request: &ExecutionRequest, logger: &mut Logger) {
    let _ = writeln!(logger, "Script code length: {}", request.script_code.len());
    let _ = writeln!(logger, "Working directory: {}", request.working_directory);
    let _ = writeln!(logger, "Script timeout: {}", request.script_timeout);
    let _ = writeln!(logger, "Container name: {}", request.container_id);
}

#[cfg(target_os = "macos")]
fn display_script_results(response: &ScriptResponse, logger: &mut Logger) {
    let code = response.exit_code;
    let _ = writeln!(logger, "Exit code: {} (0x{:08X})", code, code as u32);
    if !response.error_message.is_empty() {
        let _ = writeln!(logger, "Error: {}", response.error_message);
    }
}

fn main() {
    let cli = Cli::parse();

    // Determine config input.
    let (config_data, is_base64) = if let Some(ref b64) = cli.config_base64 {
        (b64.clone(), true)
    } else if let Some(ref path) = cli.config {
        (path.clone(), false)
    } else if let Some(ref path) = cli.config_path {
        (path.clone(), false)
    } else {
        eprintln!("Error: No config provided. Use a positional path, --config, or --config-base64");
        process::exit(1);
    };

    let mut logger = Logger::new(if cli.debug {
        Mode::Console
    } else {
        Mode::Buffer
    });

    if let Some(ref log_path) = cli.log_file {
        if let Err(e) = logger.enable_file_sink(std::path::Path::new(log_path)) {
            eprintln!("Warning: could not open log file '{}': {}", log_path, e);
        }
    }

    let mut request = match load_request(&config_data, &mut logger, is_base64) {
        Ok(r) => r,
        Err(_) => {
            eprint!("Request error\n{}", logger.get_buffer());
            process::exit(1);
        }
    };

    request.experimental_enabled = cli.experimental;
    request.dry_run = cli.dry_run;

    log_request(&request, &mut logger);

    // The SDK should always select Seatbelt on darwin. Be lenient and
    // log a note instead of failing — same behaviour as `lxc-exec`.
    if request.containment != ContainmentBackend::Seatbelt {
        logger.log_line("Note: Overriding containment backend to Seatbelt on macOS.");
    }

    run_seatbelt(&request, &mut logger);
}

#[cfg(target_os = "macos")]
fn run_seatbelt(request: &ExecutionRequest, logger: &mut Logger) -> ! {
    use seatbelt_common::seatbelt_runner::SeatbeltScriptRunner;
    use wxc_common::sandbox_process::Runner;

    let mut runner = Runner::new(SeatbeltScriptRunner::new());
    let run_start = Instant::now();
    let response = runner.run(request, logger);
    let run_elapsed = run_start.elapsed();
    let _ = writeln!(logger, "Runner completed in {}ms", run_elapsed.as_millis());

    if request.dry_run {
        handle_dry_run_exit(&response, logger);
    }

    display_script_results(&response, logger);

    print!("{}", response.standard_out);
    eprint!("{}", response.standard_err);
    process::exit(response.exit_code);
}

#[cfg(not(target_os = "macos"))]
fn run_seatbelt(_request: &ExecutionRequest, logger: &mut Logger) -> ! {
    eprintln!(
        "mxc-exec-mac: the macOS sandbox backend is only available on macOS. \
         This binary was built for a non-Darwin target and cannot execute scripts."
    );
    print!("{}", logger.get_buffer());
    process::exit(1);
}
