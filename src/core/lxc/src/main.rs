// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use std::fmt::Write;
use std::process;
use std::time::Instant;

use clap::Parser;
use wxc_common::config_parser::load_request_from_json;
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

    /// Manage telemetry consent without spawning a sandbox.
    #[arg(
        long = "telemetry-consent",
        value_name = "ACTION",
        conflicts_with_all = [
            "config_path",
            "config",
            "config_base64",
            "delete",
            "containername",
            "experimental",
            "allow_testing_features",
            "dry_run",
            "setup_hyperlight",
            "force"
        ]
    )]
    telemetry_consent: Option<telemetry::consent_cli::ConsentAction>,

    /// Preferred BCP 47 locale for a telemetry consent request.
    #[arg(long = "telemetry-consent-locale", requires = "telemetry_consent")]
    telemetry_consent_locale: Option<String>,

    /// Private SDK presenter protocol.
    #[arg(
        long = "telemetry-consent-protocol",
        requires = "telemetry_consent",
        hide = true
    )]
    telemetry_consent_protocol: Option<telemetry::consent_cli::ConsentProtocol>,
}

fn parse_cli() -> Cli {
    match Cli::try_parse() {
        Ok(cli) => cli,
        Err(error) => {
            if matches!(
                error.kind(),
                clap::error::ErrorKind::DisplayHelp | clap::error::ErrorKind::DisplayVersion
            ) {
                error.exit();
            }
            let is_consent_command =
                telemetry::consent_cli::invocation_uses_consent_options(std::env::args_os());
            if is_consent_command {
                let _ = error.print();
                process::exit(64);
            }
            error.exit();
        }
    }
}

/// See `wxc::handle_telemetry_consent_flags` for the Windows behavior this
/// mirrors. On Linux, `wxc_common::telemetry::consent` always reports
/// Delegates to the shared `wxc_common::telemetry::consent_cli` handler so
/// this fast path can't drift from `wxc-exec`/`mxc-exec-mac`. The shared
/// handler returns the outcome as data; terminating the process is this
/// binary's job, not the foundation crate's.
fn handle_telemetry_consent_flags(cli: &Cli) -> bool {
    let Some(action) = cli.telemetry_consent else {
        return false;
    };
    let outcome = telemetry::consent_cli::handle_consent_command(
        action,
        cli.telemetry_consent_locale.as_deref(),
        cli.telemetry_consent_protocol,
    );
    let code = outcome.emit();
    if code != 0 {
        std::process::exit(code);
    }
    true
}

/// Read the request source (file path / base64 blob) once.
fn decode_config_input_once(cli: &Cli) -> Option<Result<String, wxc_common::error::WxcError>> {
    let (input, is_base64) = if let Some(input) = cli.config_base64.as_ref() {
        (input.clone(), true)
    } else if let Some(input) = cli.config.as_ref().or(cli.config_path.as_ref()) {
        (input.clone(), false)
    } else {
        return None;
    };
    Some(wxc_common::config_parser::decode_request_input(
        &input, is_base64,
    ))
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

/// Surface warnings the run recorded (e.g. Bubblewrap reporting an IPv6 allow
/// the sandbox namespace cannot reach).
///
/// The logger only retains these rather than writing them itself, so that
/// `mxc_engine` embedders don't get unannounced writes to a terminal they own.
/// `lxc-exec` *does* own its terminal, so it opts in here — matching wxc-exec.
/// stderr, not stdout: stdout carries the workload's own output.
fn emit_warnings(logger: &Logger) {
    for warning in logger.warnings() {
        eprintln!("{warning}");
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
    let cli = parse_cli();

    // --telemetry-consent: report/administer the
    // (always not-applicable on Linux) consent state and exit. Runs before
    // signal_cleanup::install():
    // this is a read-only/local-file fast path that never spawns a
    // container, so it must not be gated on — or fail because of — signal
    // handler installation, matching `wxc-exec`/`mxc-exec-mac`, where the
    // consent fast path also runs unconditionally before any other setup.
    if handle_telemetry_consent_flags(&cli) {
        return;
    }
    // Decode the request source (file path / base64) once, up front.
    let decoded_config: Option<Result<String, wxc_common::error::WxcError>> =
        decode_config_input_once(&cli);
    let request_hint = decoded_config
        .as_ref()
        .and_then(|result| result.as_ref().ok())
        .and_then(|json| wxc_common::config_parser::parse_request_hint_from_json(json).ok());
    // Install before spawning any other threads so the signal mask propagates.
    // Failure here is fatal: install() either succeeds with the watchdog
    // running, or restores the original signal mask and returns Err. We
    // refuse to continue without it because containers leaked on SIGTERM/INT
    // are exactly the failure mode this code exists to prevent.
    if let Err(e) = signal_cleanup::install() {
        eprintln!("Error: failed to install signal cleanup handler: {}", e);
        process::exit(1);
    }

    // --setup-hyperlight: eagerly warm up the snapshot and exit. Runs
    // before config parsing so the user doesn't need a JSON file on
    // disk just to install.
    if cli.setup_hyperlight {
        #[cfg(all(feature = "hyperlight", target_arch = "x86_64"))]
        {
            // WHP is delay-loaded; check before pyhl::install warms a VM.
            #[cfg(target_os = "windows")]
            if !hyperlight_common::is_whp_available() {
                eprintln!(
                    "Error: --setup-hyperlight requires Windows Hypervisor Platform (WHP). \
                     Enable the HypervisorPlatform optional feature and reboot."
                );
                process::exit(1);
            }

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

    // Determine config input. In delete mode the config is optional; every
    // other path requires it. `decoded_config` above already read the source
    // once — if it's populated, unpack the decoded JSON (or surface the
    // decode error). If it's absent, either accept the empty state for
    // delete mode or report the missing-config error.
    let config_json: Option<String> = match decoded_config {
        Some(Ok(json)) => Some(json),
        Some(Err(error)) => {
            eprintln!("Request error\n{error}");
            process::exit(1);
        }
        None => {
            if !cli.delete {
                eprintln!(
                    "Error: No config provided. Use a positional path, --config, or --config-base64"
                );
                process::exit(1);
            }
            None
        }
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

    // Non-delete paths always have a config JSON at this point (or exited
    // above with the missing-config error).
    let config_json = config_json.expect("config_json is Some on non-delete paths");

    // Load request
    let parsed_request = if let Some(hint) = request_hint.as_ref() {
        wxc_common::config_parser::load_request_from_json_with_hint_and_options(
            &config_json,
            &mut logger,
            wxc_common::config_parser::LoadOptions::default(),
            hint,
        )
    } else {
        load_request_from_json(&config_json, &mut logger)
    };
    let mut request = match parsed_request {
        Ok(r) => r,
        Err(_) => {
            eprint!("Request error\n{}", logger.get_buffer());
            process::exit(1);
        }
    };

    request.experimental_enabled = cli.experimental;
    request.testing_features_enabled = cli.allow_testing_features;
    request.dry_run = cli.dry_run;

    // ── Telemetry init ──────────────────────────────────────────────
    let telemetry_active = request
        .telemetry
        .as_ref()
        .map(|c| telemetry::init(c, &mut logger))
        .unwrap_or(false);
    let requested_sandbox_kind = request
        .telemetry
        .as_ref()
        .and_then(|config| config.requested_sandbox_kind);

    // Install a crash-telemetry panic hook once telemetry is active, chaining
    // the previously-installed hook so the default stderr backtrace still
    // prints. The hook body is panic-free and emits no message text.
    if telemetry_active {
        telemetry::set_process_context_with_kind(&request.containment, requested_sandbox_kind);
        telemetry::install_panic_hook();
    }

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

    // Emitted before the dry-run branch below, which exits the process.
    emit_warnings(&logger);

    if cli.dry_run {
        handle_dry_run_exit(&response, &mut logger);
    }

    display_script_results(&response, &mut logger);

    // ── Telemetry emit ──────────────────────────────────────────────
    telemetry::emit_completion_with_kind(
        telemetry_active,
        &request.containment,
        requested_sandbox_kind,
        &response,
        run_elapsed,
    );

    print!("{}", response.standard_out);
    eprint!("{}", response.standard_err);

    // Never exit non-zero on an infrastructure failure without a diagnostic:
    // `display_script_results` only writes the error into the (buffered,
    // non-debug-suppressed) logger, so surface it on stderr here for parity
    // with wxc-exec (issue #564).
    wxc_common::script_runner::emit_backend_error_envelope(&response);

    process::exit(response.exit_code);
}
