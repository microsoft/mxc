// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use std::fmt::Write;
use std::process;
use std::time::Instant;

use clap::Parser;
use wxc_common::config_parser::load_request;
use wxc_common::logger::{Logger, Mode};
use wxc_common::models::{CodexRequest, ContainmentBackend, ScriptResponse};
use wxc_common::script_runner::{handle_dry_run_exit, ScriptRunner};

use lxc_common::lxc_runner::LxcScriptRunner;
use lxc_common::signal_cleanup;

#[derive(Parser)]
#[command(name = "lxc-exec", about = "Linux Container Executor")]
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

    /// Delete container mode
    #[arg(long)]
    delete: bool,

    /// Container name (required with --delete)
    #[arg(long = "containername")]
    containername: Option<String>,

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

fn log_request(request: &CodexRequest, logger: &mut Logger) {
    let _ = writeln!(logger, "Script code length: {}", request.script_code.len());
    let _ = writeln!(logger, "Working directory: {}", request.working_directory);
    let _ = writeln!(logger, "Script timeout: {}", request.script_timeout);
    let _ = writeln!(logger, "Container name: {}", request.container_id);
}

fn display_script_results(response: &ScriptResponse, logger: &mut Logger) {
    let _ = writeln!(logger, "Exit code: {}", response.exit_code);
    if !response.error_message.is_empty() {
        let _ = writeln!(logger, "Error: {}", response.error_message);
    }
}

fn delete_lxc_container(name: &str, logger: &mut Logger) -> bool {
    use lxc_common::lxc_bindings::LxcContainer;

    let container = LxcContainer::new(name, None);

    if !container.is_defined() {
        logger.log_line(&format!("Container '{}' does not exist.", name));
        return false;
    }

    match container.destroy() {
        Ok(()) => {
            logger.log_line(&format!("Deleted LXC container: {}", name));
            true
        }
        Err(e) => {
            logger.log_line(&format!("Failed to delete LXC container '{}': {}", name, e));
            false
        }
    }
}

fn main() {
    // Install before spawning any other threads so the signal mask propagates.
    if let Err(e) = signal_cleanup::install() {
        eprintln!("Warning: failed to install signal cleanup handler: {}", e);
    }

    let cli = Cli::parse();

    // Determine config input
    let (config_data, is_base64) = if let Some(ref b64) = cli.config_base64 {
        (b64.clone(), true)
    } else if let Some(ref path) = cli.config {
        (path.clone(), false)
    } else if let Some(ref path) = cli.config_path {
        (path.clone(), false)
    } else if !cli.delete {
        eprintln!("Error: No config provided. Use a positional path, --config, or --config-base64");
        process::exit(1);
    } else {
        (String::new(), false)
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

    // Delete mode
    if cli.delete {
        let name = match cli.containername {
            Some(ref n) => n.as_str(),
            None => {
                eprintln!("Error: --containername is required with --delete");
                process::exit(1);
            }
        };
        let success = delete_lxc_container(name, &mut logger);
        print!("{}", logger.get_buffer());
        process::exit(if success { 0 } else { 1 });
    }

    // Load request
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

    // Verify containment backend is LXC
    if request.containment != ContainmentBackend::Lxc {
        // Default to LXC on Linux regardless of what was specified
        logger.log_line("Note: Overriding containment backend to LXC on Linux.");
    }

    // Run script in LXC container
    let mut runner = LxcScriptRunner::new(
        &request.lxc_config,
        &request.container_id,
        &request.lifecycle,
    );
    let run_start = Instant::now();
    let response = runner.run(&request, &mut logger);
    let run_elapsed = run_start.elapsed();
    let _ = writeln!(logger, "Runner completed in {}ms", run_elapsed.as_millis());

    if cli.dry_run {
        handle_dry_run_exit(&response, &mut logger);
    }

    display_script_results(&response, &mut logger);

    print!("{}", response.standard_out);
    eprint!("{}", response.standard_err);
    process::exit(response.exit_code);
}
