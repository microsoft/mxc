// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

mod linux_executor_arguments;

use clap::Parser;
use std::fmt::Write;
use std::time::Instant;
use std::{eprint, process};

use mxc_sdk::mxc_common::logger::{Logger, Mode};
use mxc_sdk::mxc_common::models::{ExecutionRequest, ScriptResponse};
use mxc_sdk::mxc_common::script_runner;
use mxc_sdk::mxc_common::telemetry;

use mxc_sdk::lxc_common::signal_cleanup;

fn main() {
    let arguments = linux_executor_arguments::LinuxExecutorArguments::parse();

    // Get the logger
    let mut logger = Logger::new(if arguments.should_run_in_debug() {
        Mode::Console
    } else {
        Mode::Buffer
    });

    // Enable the file sink if needed
    if let Some(ref log_path) = arguments.get_log_path() {
        if let Err(e) = logger.enable_file_sink(std::path::Path::new(log_path)) {
            eprintln!("Warning: could not open log file '{}': {}", log_path, e);
        }
    }

    // Go through the different operating modes
    if arguments.should_display_avalible_backends() {
        match mxc_sdk::mxc_engine::to_json_pretty(&mxc_sdk::mxc_engine::available_backends()) {
            Ok(json) => {
                println!("{json}");
                process::exit(0);
            }
            Err(e) => {
                eprintln!("Error: probe serialization failed: {e}");
                process::exit(1);
            }
        }
    } else if arguments.does_user_want_hyperlight_setup() {
        match arguments.setup_hyperlight() {
            Ok(message) => {
                eprintln!("{message}");
                process::exit(0);
            }
            Err(message) => {
                eprintln!("{message}");
                process::exit(1);
            }
        }
    } else if arguments.does_user_want_to_delete_a_container() {
        match arguments.delete_container() {
            Ok(message) => {
                eprintln!("{message}");
                process::exit(0);
            }
            Err(message) => {
                eprintln!("{message}");
                process::exit(1);
            }
        }
    }

    // User wants to run a request.
    // Make the request.
    let request = arguments.get_request();

    let telemetry_active = request
        .telemetry
        .as_ref()
        .map(|c| telemetry::init(c, &mut logger))
        .unwrap_or(false);

    let requested_sandbox_kind = request
        .telemetry
        .as_ref()
        .and_then(|config| config.requested_sandbox_kind);

    if telemetry_active {
        telemetry::set_process_context_with_kind(&request.containment, requested_sandbox_kind);
        telemetry::install_panic_hook();
    }

    log_request(&request, &mut logger);

    // Setup watchdog for unexpected shutdowns
    if let Err(e) = signal_cleanup::install() {
        eprintln!("Error: failed to install signal cleanup handler: {e}");
        process::exit(1);
    }

    let run_start = Instant::now();

    // Run the request.
    let response = match mxc_sdk::mxc_engine::run(&request, &mut logger) {
        Ok(response) => response,
        Err(e) => {
            eprintln!("error: {}", e.message);
            emit_warnings(&logger);
            eprint!("{}", logger.get_buffer());
            telemetry::emit_early_exit_with_kind(
                telemetry_active,
                &request.containment,
                requested_sandbox_kind,
                telemetry::FailureReason::InitError,
            );
            process::exit(1);
        }
    };

    let run_elapsed = run_start.elapsed();
    let _ = writeln!(logger, "Runner completed in {}ms", run_elapsed.as_millis());

    emit_warnings(&logger);

    // Handle dry_run request.
    if arguments.parse_and_validate() {
        script_runner::handle_dry_run_exit(&response, &mut logger);
    }

    // Show output to the user.
    display_script_results(&response, &mut logger);

    telemetry::emit_completion_with_kind(
        telemetry_active,
        &request.containment,
        requested_sandbox_kind,
        &response,
        run_elapsed,
    );

    print!("{}", response.standard_out);
    eprint!("{}", response.standard_err);

    script_runner::emit_backend_error_envelope(&response);

    process::exit(response.exit_code);
}

fn log_request(request: &ExecutionRequest, logger: &mut Logger) {
    let _ = writeln!(logger, "Script code length: {}", request.script_code.len());
    let _ = writeln!(logger, "Working directory: {}", request.working_directory);
    let _ = writeln!(logger, "Script timeout: {}", request.script_timeout);
    let _ = writeln!(logger, "Container name: {}", request.container_id);
}

fn emit_warnings(logger: &Logger) {
    for warning in logger.warnings() {
        eprintln!("{warning}");
    }
}

fn display_script_results(response: &ScriptResponse, logger: &mut Logger) {
    let code = response.exit_code;
    let _ = writeln!(logger, "Exit code: {} (0x{:08X})", code, code as u32);
    if !response.error_message.is_empty() {
        let _ = writeln!(logger, "Error: {}", response.error_message);
    }
}
