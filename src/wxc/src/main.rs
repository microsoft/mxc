// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use std::fmt::Write;
use std::process;

use clap::Parser;
use windows::Win32::Security::Isolation::DeleteAppContainerProfile;
use wxc_common::appcontainer::AppContainerScriptRunner;
use wxc_common::config_parser::load_request;
use wxc_common::filesystem_bfs::FileSystemBfsManager;
use wxc_common::logger::{Logger, Mode};
use wxc_common::models::{CodexRequest, ContainmentBackend, ScriptResponse};
use wxc_common::sandbox_runner::SandboxScriptRunner;
use wxc_common::script_runner::ScriptRunner;

#[derive(Parser)]
#[command(name = "wxc-exec", about = "Windows Container Executor")]
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

    /// Delete container profile mode
    #[arg(long)]
    delete: bool,

    /// Container name (required with --delete)
    #[arg(long = "containername")]
    containername: Option<String>,
}

fn log_request(request: &CodexRequest, logger: &mut Logger) {
    let _ = writeln!(logger, "Script code length: {}", request.script_code.len());
    let _ = writeln!(logger, "Working directory: {}", request.working_directory);
    let _ = writeln!(logger, "Script timeout: {}", request.script_timeout);
    let _ = writeln!(
        logger,
        "Container name: {}",
        request.policy.app_container_name
    );
}

fn display_script_results(response: &ScriptResponse, logger: &mut Logger) {
    let _ = writeln!(logger, "Exit code: {}", response.exit_code);
    if !response.error_message.is_empty() {
        let _ = writeln!(logger, "Error: {}", response.error_message);
    }
}

fn delete_app_container_profile(name: &str, logger: &mut Logger) -> bool {
    // Clear BFS policy first
    let mut bfs = FileSystemBfsManager::new(name.to_string());
    bfs.remove_configuration(logger);

    // Delete the AppContainer profile
    let wide_name: Vec<u16> = name.encode_utf16().chain(std::iter::once(0)).collect();
    let hstring = windows::core::HSTRING::from_wide(&wide_name[..wide_name.len() - 1]);
    match unsafe { DeleteAppContainerProfile(&hstring) } {
        Ok(()) => {
            logger.log_line(&format!("Deleted AppContainer profile: {}", name));
            true
        }
        Err(e) => {
            logger.log_line(&format!(
                "Failed to delete AppContainer profile '{}': {}",
                name, e
            ));
            false
        }
    }
}

fn main() {
    let cli = Cli::parse();

    // Determine config input and whether it's base64
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

    // Delete mode
    if cli.delete {
        let name = match cli.containername {
            Some(ref n) => n.as_str(),
            None => {
                eprintln!("Error: --containername is required with --delete");
                process::exit(1);
            }
        };
        let success = delete_app_container_profile(name, &mut logger);
        print!("{}", logger.get_buffer());
        process::exit(if success { 0 } else { 1 });
    }

    // Load request
    let request = match load_request(&config_data, &mut logger, is_base64) {
        Ok(r) => r,
        Err(_) => {
            eprint!("Request error\n{}", logger.get_buffer());
            process::exit(1);
        }
    };

    log_request(&request, &mut logger);

    // Run script in selected containment backend
    let mut runner: Box<dyn ScriptRunner> = match request.containment {
        ContainmentBackend::AppContainer => Box::new(AppContainerScriptRunner::new()),
        ContainmentBackend::Sandbox => Box::new(SandboxScriptRunner::new(&request.sandbox_config)),
        ContainmentBackend::Wslc => {
            eprintln!("Error: WSLC backend not yet implemented (Phase 3)");
            process::exit(1);
        }
        _ => todo!("Return an error here"),
    };
    let response = runner.run(&request, &mut logger);
    display_script_results(&response, &mut logger);

    // Output was already relayed to the console by pipe threads.
    // Only print captured output if present (e.g. from error paths).
    if !response.standard_out.is_empty() {
        print!("{}", response.standard_out);
    }
    if !response.standard_err.is_empty() {
        eprint!("{}", response.standard_err);
    }
    process::exit(response.exit_code);
}
