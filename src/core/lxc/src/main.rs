// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use std::fmt::Write;
use std::process;
use std::time::Instant;

use clap::Parser;
use wxc_common::config_parser::load_request;
use wxc_common::logger::{Logger, Mode};
use wxc_common::models::{ExecutionRequest, ScriptResponse};
use wxc_common::script_runner::handle_dry_run_exit;
use wxc_common::telemetry;

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

    /// Allow testing-only features that must never run in production, currently
    /// `network.proxy.builtinTestServer` (a bundled, deliberately-permissive
    /// test HTTP proxy). Distinct from --experimental.
    #[arg(long = "allow-testing-features")]
    allow_testing_features: bool,

    /// Parse and validate config then exit without executing
    #[arg(long = "dry-run")]
    dry_run: bool,

    /// Path to diagnostic log file (appends, creates if missing)
    #[arg(long = "log-file")]
    log_file: Option<String>,

    /// Install the warmed Hyperlight snapshot and exit. Pulls the
    /// published kernel + initrd from GHCR (via docker or podman),
    /// warms them up, and writes the snapshot into the default user
    /// data dir (~/.local/share/pyhl on Linux, %LOCALAPPDATA%\pyhl on
    /// Windows). $PYHL_HOME overrides the destination if set. Intended
    /// for tool install hooks so first-run has zero warmup cost.
    #[arg(long = "setup-hyperlight")]
    setup_hyperlight: bool,

    /// Rebuild the snapshot even if one already exists. Use after
    /// upgrading `kernel` or `initrd.cpio` so the warm state matches
    /// the new bits. Requires --setup-hyperlight.
    #[arg(long, requires = "setup_hyperlight")]
    force: bool,
}

fn log_request(request: &ExecutionRequest, logger: &mut Logger) {
    let _ = writeln!(logger, "Script code length: {}", request.script_code.len());
    let _ = writeln!(logger, "Working directory: {}", request.working_directory);
    let _ = writeln!(logger, "Script timeout: {}", request.script_timeout);
    let _ = writeln!(logger, "Container name: {}", request.container_id);
}

fn display_script_results(response: &ScriptResponse, logger: &mut Logger) {
    let code = response.exit_code;
    let _ = writeln!(logger, "Exit code: {} (0x{:08X})", code, code as u32);
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
    // Failure here is fatal: install() either succeeds with the watchdog
    // running, or restores the original signal mask and returns Err. We
    // refuse to continue without it because containers leaked on SIGTERM/INT
    // are exactly the failure mode this code exists to prevent.
    if let Err(e) = signal_cleanup::install() {
        eprintln!("Error: failed to install signal cleanup handler: {}", e);
        process::exit(1);
    }

    let cli = Cli::parse();

    // --setup-hyperlight: eagerly warm up the snapshot and exit. Runs
    // before config parsing so the user doesn't need a JSON file on
    // disk just to install.
    if cli.setup_hyperlight {
        #[cfg(all(feature = "hyperlight", target_arch = "x86_64"))]
        {
            let mut logger = Logger::new(if cli.debug {
                Mode::Console
            } else {
                Mode::Buffer
            });
            match hyperlight_common::setup(cli.force, &mut logger) {
                Ok(snap) => {
                    eprintln!("hyperlight setup: snapshot ready at {:?}", snap);
                    process::exit(0);
                }
                Err(msg) => {
                    eprintln!("hyperlight setup failed: {msg}");
                    process::exit(1);
                }
            }
        }
        #[cfg(not(all(feature = "hyperlight", target_arch = "x86_64")))]
        {
            eprintln!("Error: --setup-hyperlight requires x86_64 (Hyperlight needs KVM or WHP)");
            process::exit(1);
        }
    }

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
    request.testing_features_enabled = cli.allow_testing_features;
    request.dry_run = cli.dry_run;

    // ── Telemetry init (experimental) ───────────────────────────────
    let telemetry_active = if request.experimental_enabled {
        request
            .experimental
            .telemetry
            .as_ref()
            .map(|c| telemetry::init(c, &mut logger))
            .unwrap_or(false)
    } else {
        false
    };

    log_request(&request, &mut logger);

    // Dispatch by containment backend. Backend selection and runner
    // construction — Bubblewrap (the Linux default for abstract intents), LXC
    // (explicit `containment: "lxc"`, plus the catch-all for anything else such
    // as `processcontainer`), and the experimental Hyperlight / MicroVM
    // backends — live in `mxc_engine::run`, the single home for one-shot backend
    // dispatch. It runs the selected backend to completion and returns the
    // response; experimental backends that require `--experimental` (or that
    // aren't compiled in) surface an error here.
    let run_start = Instant::now();
    let response = match mxc_engine::run(&request, &mut logger) {
        Ok(response) => response,
        Err(e) => {
            eprintln!("error: {}", e.message);
            eprint!("{}", logger.get_buffer());
            telemetry::emit_early_exit(
                telemetry_active,
                &request.containment,
                telemetry::FailureReason::InitError,
            );
            process::exit(1);
        }
    };
    let run_elapsed = run_start.elapsed();
    let _ = writeln!(logger, "Runner completed in {}ms", run_elapsed.as_millis());

    if cli.dry_run {
        handle_dry_run_exit(&response, &mut logger);
    }

    display_script_results(&response, &mut logger);

    // ── Telemetry emit (experimental) ───────────────────────────────
    telemetry::emit_completion(
        telemetry_active,
        &request.containment,
        &response,
        run_elapsed,
    );

    print!("{}", response.standard_out);
    eprint!("{}", response.standard_err);
    process::exit(response.exit_code);
}
