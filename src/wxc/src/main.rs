// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use std::fmt::Write;
use std::process;
use std::time::Instant;

use clap::Parser;
use windows::Win32::Security::Isolation::DeleteAppContainerProfile;
use wxc_common::appcontainer_runner::AppContainerScriptRunner;
use wxc_common::base_container_runner::BaseContainerRunner;
use wxc_common::config_parser::{is_base_container_version, load_mxc_request, ParseError};
use wxc_common::filesystem_bfs::FileSystemBfsManager;
#[cfg(feature = "isolation_session")]
use wxc_common::isolation_session_runner::IsolationSessionRunner;
use wxc_common::logger::{Logger, Mode};
use wxc_common::models::{CodexRequest, ContainmentBackend, ScriptResponse};
use wxc_common::mxc_error::{MxcError, ResponseEnvelope};
use wxc_common::nanvix_runner::NanVixScriptRunner;
use wxc_common::script_runner::{handle_dry_run_exit, ScriptRunner};
use wxc_common::state_aware_dispatch::{run_state_aware, DispatchOutcome};
use wxc_common::state_aware_request::{MxcRequest, ParsedStateAwareRequest};
use wxc_common::windows_sandbox_runner::WindowsSandboxScriptRunner;

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
    if !request.container_id.is_empty() {
        let _ = writeln!(logger, "Container ID: {}", request.container_id);
    }
    let _ = writeln!(logger, "Platform: {}", request.platform);
    let _ = writeln!(logger, "Script code length: {}", request.script_code.len());
    let _ = writeln!(logger, "Working directory: {}", request.working_directory);
    let _ = writeln!(logger, "Script timeout: {}", request.script_timeout);
    let _ = writeln!(
        logger,
        "Container name: {}",
        if request.container_id.is_empty() {
            "CLI"
        } else {
            &request.container_id
        }
    );
}

fn display_script_results(response: &ScriptResponse, logger: &mut Logger) {
    let _ = writeln!(logger, "Exit code: {}", response.exit_code);
    if !response.error_message.is_empty() {
        let _ = writeln!(logger, "Error: {}", response.error_message);
    }
}

/// Drives the state-aware dispatch flow. On envelope success, writes the
/// JSON to stdout and exits 0. On exec success, exits with the script's
/// exit code (output already streamed). On failure, writes a JSON error
/// envelope to stdout and exits 1. Diagnostic logger output goes to stderr
/// regardless of mode (per design §7.3 stream protocol — stdout reserved
/// for the response envelope).
fn run_state_aware_main(parsed: ParsedStateAwareRequest, dry_run: bool, logger: &mut Logger) -> ! {
    let outcome = run_state_aware(parsed, dry_run);
    // Diagnostic buffer flushes to stderr regardless of success/failure so it
    // never interleaves with the stdout envelope.
    let buffered = logger.get_buffer().to_string();
    if !buffered.is_empty() {
        eprint!("{}", buffered);
    }
    match outcome {
        Ok(DispatchOutcome::Envelope(value)) => {
            println!("{}", value);
            process::exit(0);
        }
        Ok(DispatchOutcome::ExecCompleted { exit_code }) => process::exit(exit_code),
        Err(e) => {
            print_error_envelope(&e);
            process::exit(1);
        }
    }
}

fn print_error_envelope(error: &MxcError) {
    let envelope: ResponseEnvelope<()> = ResponseEnvelope::from_error(error);
    match serde_json::to_string(&envelope) {
        Ok(s) => println!("{}", s),
        Err(_) => {
            // Last-resort path: serialisation of the envelope itself failed —
            // emit a minimal structurally-valid envelope so consumers that
            // require `error.code` still parse something.
            println!(
                r#"{{"error":{{"code":"backend_error","message":"failed to serialise error envelope"}}}}"#
            );
        }
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
    // Initialize COM/WinRT for backends that use WinRT APIs (Isolation Session).
    // COINIT_MULTITHREADED is benign for backends that don't use COM.
    //
    // SAFETY: `CoInitializeEx` is sound to call once at process start before
    // any WinRT or COM activation. `pvReserved` must be `None` per the API
    // contract. The return value is intentionally ignored — repeat-init
    // outcomes (`S_FALSE`, `RPC_E_CHANGED_MODE`) are benign here.
    let _ = unsafe {
        windows::Win32::System::Com::CoInitializeEx(
            None,
            windows::Win32::System::Com::COINIT_MULTITHREADED,
        )
    };

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
        let success = delete_app_container_profile(name, &mut logger);
        print!("{}", logger.get_buffer());
        process::exit(if success { 0 } else { 1 });
    }

    // Load request — discriminates state-aware (top-level `phase` field) from
    // one-shot. State-aware failures emit a JSON envelope on stdout; one-shot
    // and pre-discrimination failures keep the existing diagnostic-on-stderr
    // convention.
    let request = match load_mxc_request(&config_data, &mut logger, is_base64) {
        Ok(MxcRequest::OneShot(req)) => req,
        Ok(MxcRequest::StateAware(parsed)) => {
            run_state_aware_main(parsed, cli.dry_run, &mut logger)
        }
        Err(ParseError::OneShot(_)) | Err(ParseError::Decode(_)) => {
            eprint!("Request error\n{}", logger.get_buffer());
            process::exit(1);
        }
        Err(ParseError::StateAware(e)) => {
            print_error_envelope(&e);
            eprint!("{}", logger.get_buffer());
            process::exit(1);
        }
    };

    let mut request = request;
    request.experimental_enabled = cli.experimental;
    request.dry_run = cli.dry_run;

    log_request(&request, &mut logger);

    // Run script in selected containment backend.
    // BaseContainer is used when --experimental is passed or schema version >= 0.5.
    // Sandbox and MicroVM require --experimental flag.
    let mut runner: Box<dyn ScriptRunner> = match request.containment {
        ContainmentBackend::AppContainer => {
            let version_implies_base_container = is_base_container_version(&request.schema_version);
            let use_base_container = request.experimental_enabled || version_implies_base_container;

            if use_base_container {
                let reason = if version_implies_base_container {
                    format!("schema version {}", request.schema_version)
                } else {
                    "--experimental".to_string()
                };
                let _ = writeln!(logger, "Using BaseContainer runner ({reason})");
                Box::new(BaseContainerRunner::new())
            } else {
                Box::new(AppContainerScriptRunner::new())
            }
        }
        ContainmentBackend::Wslc => {
            #[cfg(feature = "wslc")]
            {
                if !request.experimental_enabled {
                    eprintln!("Error: WSLC is an experimental feature. Use --experimental flag.");
                    process::exit(1);
                }
                let _ = writeln!(logger, "Using WSLContainer runner (--experimental)");
                let wslc_config = request
                    .experimental
                    .wslc
                    .as_ref()
                    .cloned()
                    .unwrap_or_default();
                Box::new(wslc_common::wsl_container_runner::WSLContainerRunner::new(
                    &wslc_config,
                ))
            }
            #[cfg(not(feature = "wslc"))]
            {
                eprintln!("Error: WSLC backend not compiled. Rebuild with --features wslc.");
                process::exit(1);
            }
        }
        ContainmentBackend::Lxc => {
            eprintln!("Error: LXC backend not available on Windows");
            process::exit(1);
        }
        ContainmentBackend::Vm => {
            eprintln!("Error: VM backend not yet implemented");
            process::exit(1);
        }
        ContainmentBackend::MicroVm => {
            if !request.experimental_enabled {
                eprintln!("Error: MicroVM is an experimental feature. Use --experimental flag.");
                process::exit(1);
            }
            Box::new(NanVixScriptRunner::new())
        }
        ContainmentBackend::WindowsSandbox => {
            if !request.experimental_enabled {
                eprintln!(
                    "Error: Windows Sandbox is an experimental feature. Use --experimental flag."
                );
                process::exit(1);
            }
            let sandbox_config = request
                .experimental
                .windows_sandbox
                .as_ref()
                .cloned()
                .unwrap_or_default();
            Box::new(WindowsSandboxScriptRunner::new(&sandbox_config))
        }
        ContainmentBackend::IsolationSession => {
            #[cfg(feature = "isolation_session")]
            {
                if !request.experimental_enabled {
                    eprintln!(
                        "Error: Isolation Session is an experimental feature. Use --experimental flag."
                    );
                    process::exit(1);
                }
                Box::new(IsolationSessionRunner::new())
            }
            #[cfg(not(feature = "isolation_session"))]
            {
                eprintln!(
                    "Error: IsolationSession backend not compiled. Rebuild with --features isolation_session."
                );
                process::exit(1);
            }
        }
    };
    let run_start = Instant::now();
    let response = runner.run(&request, &mut logger);
    let run_elapsed = run_start.elapsed();
    let _ = writeln!(logger, "Runner completed in {}ms", run_elapsed.as_millis());

    if cli.dry_run {
        handle_dry_run_exit(&response, &mut logger);
    }

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
