// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use std::fmt::Write;
use std::fs;
use std::process;
use std::time::Instant;

use clap::Parser;
use wxc_common::appcontainer_runner::{delete_app_container_profile, AppContainerScriptRunner};
use wxc_common::config_parser::{is_base_container_version, load_mxc_request, ParseError};
use wxc_common::diagnostic::DiagnosticConfig;
#[cfg(all(feature = "hyperlight", target_arch = "x86_64"))]
use wxc_common::hyperlight_runner::HyperlightScriptRunner;
#[cfg(feature = "isolation_session")]
use wxc_common::isolation_session::IsolationSessionRunner;
use wxc_common::logger::{Logger, Mode};
use wxc_common::models::{CodexRequest, ContainmentBackend, ScriptResponse};
use wxc_common::mxc_error::{MxcError, ResponseEnvelope};
#[cfg(feature = "microvm")]
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

    /// Pre-pull a WSLC container image into the local image cache and exit.
    /// MXC is an execution layer and does not pull images at run time; this
    /// flag (or `scripts/setup-wslc.ps1`) is how operators populate the cache.
    /// Requires `--image` to specify which image to pull.
    #[arg(long = "setup-wslc")]
    setup_wslc: bool,

    /// Image reference to pre-pull (e.g. `alpine:latest`,
    /// `ghcr.io/owner/image:tag`). Required with `--setup-wslc`.
    #[arg(long = "image", requires = "setup_wslc")]
    image: Option<String>,

    /// Optional WSLC storage path. When omitted the runner default is used
    /// (`%TEMP%\mxc-wslc-sessions`). Pass the same value here that your
    /// runtime configs set in `experimental.wslc.storagePath`, otherwise
    /// the runner will not find the pulled image. Requires `--setup-wslc`.
    #[arg(long = "storage-path", requires = "setup_wslc")]
    storage_path: Option<String>,

    /// Grant the AppContainer "ALL APPLICATION PACKAGES" and
    /// "ALL RESTRICTED APPLICATION PACKAGES" groups the minimum rights
    /// needed to stat the system-drive root (e.g. `C:\`). Persistent —
    /// survives across runs. Requests elevation via UAC if not already
    /// elevated. See `wxc_common::system_drive_prep`.
    #[cfg(target_os = "windows")]
    #[arg(
        long = "prepare-system-drive",
        conflicts_with_all = [
            "unprepare_system_drive",
            "setup_hyperlight",
            "setup_wslc",
            "delete",
            "dry_run",
        ]
    )]
    prepare_system_drive: bool,

    /// Remove the ACEs added by `--prepare-system-drive`. Uses precise
    /// tuple matching: only ACEs the matching `--prepare-system-drive`
    /// invocation would have written are removed. Other explicit ACEs
    /// for the same SIDs are preserved.
    #[cfg(target_os = "windows")]
    #[arg(
        long = "unprepare-system-drive",
        conflicts_with_all = [
            "setup_hyperlight",
            "setup_wslc",
            "delete",
            "dry_run",
        ]
    )]
    unprepare_system_drive: bool,

    /// Internal — set by `--prepare-system-drive` / `--unprepare-system-drive`
    /// when re-launching with elevation. Not for user use.
    #[cfg(target_os = "windows")]
    #[arg(long = "internal-elevated-helper", hide = true)]
    internal_elevated_helper: bool,

    /// Internal — the target path resolved by the unelevated parent,
    /// passed to the elevated child so the child does not re-read
    /// `%SystemDrive%` from a potentially attacker-controlled
    /// environment. Validated as a drive root by the child.
    #[cfg(target_os = "windows")]
    #[arg(long = "internal-target-path", hide = true)]
    internal_target_path: Option<String>,

    /// Internal — the helper-log path chosen by the unelevated parent.
    /// Passed to the elevated child so both processes write to / read
    /// from the same file, even when UAC consents under a different
    /// user than the parent ("over-the-shoulder" UAC). Not for user
    /// use.
    #[cfg(target_os = "windows")]
    #[arg(long = "internal-log-path", hide = true)]
    internal_log_path: Option<String>,
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
    let code = response.exit_code;
    let _ = writeln!(logger, "Exit code: {} (0x{:08X})", code, code as u32);
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

    // Best-effort: reap any orphaned DACL state files left behind by
    // crashed prior MXC runs. Errors here are non-fatal and only surface
    // via stderr.
    match wxc_common::filesystem_dacl::recover_orphaned_state() {
        Ok(report) => {
            if report.files_processed > 0 || !report.errors.is_empty() {
                eprintln!(
                    "DACL recovery: {} file(s), {} ACE(s) restored, {} error(s)",
                    report.files_processed,
                    report.aces_restored,
                    report.errors.len()
                );
                for e in &report.errors {
                    eprintln!("  {e}");
                }
            }
        }
        Err(e) => eprintln!("DACL recovery failed: {e}"),
    }

    let cli = Cli::parse();

    // --prepare-system-drive / --unprepare-system-drive: host DACL prep.
    // Modifies the DACL of the system drive root to grant the well-known
    // AppContainer SIDs metadata-read access. Self-elevates via UAC.
    // Runs before config parsing so the user doesn't need a JSON file.
    // Mutual exclusion with other top-level "do and exit" flags is
    // enforced by clap (conflicts_with_all).
    #[cfg(target_os = "windows")]
    {
        if cli.prepare_system_drive {
            process::exit(wxc_common::system_drive_prep::run_prepare(
                cli.internal_elevated_helper,
                cli.internal_target_path.as_deref(),
                cli.internal_log_path.as_deref(),
            ));
        }
        if cli.unprepare_system_drive {
            process::exit(wxc_common::system_drive_prep::run_unprepare(
                cli.internal_elevated_helper,
                cli.internal_target_path.as_deref(),
                cli.internal_log_path.as_deref(),
            ));
        }
    }

    // --setup-hyperlight: warm up the snapshot and exit. Runs before
    // config parsing so the user doesn't need a JSON file on disk
    // just to install.
    if cli.setup_hyperlight {
        #[cfg(all(feature = "hyperlight", target_arch = "x86_64"))]
        {
            let mut logger = Logger::new(if cli.debug {
                Mode::Console
            } else {
                Mode::Buffer
            });
            match wxc_common::hyperlight_runner::setup(cli.force, &mut logger) {
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

    // --setup-wslc: pre-pull a WSLC image into the local cache and exit.
    // Runs before config parsing so the user doesn't need a JSON file just
    // to populate images. Clap enforces that `--image` is present.
    if cli.setup_wslc {
        #[cfg(feature = "wslc")]
        {
            let image = match cli.image.as_deref() {
                Some(s) if !s.is_empty() => s,
                _ => {
                    eprintln!("Error: --setup-wslc requires --image <name>");
                    process::exit(1);
                }
            };
            let mut logger = Logger::new(if cli.debug {
                Mode::Console
            } else {
                Mode::Buffer
            });
            // SAFETY: setup_pull_image is the canonical SDK-loading entry
            // point for this subcommand and is called exactly once before
            // process exit. It owns the COM init contract documented on
            // `init_and_load_sdk`.
            let result = unsafe {
                wslc_common::wsl_container_runner::WSLContainerRunner::setup_pull_image(
                    image,
                    cli.storage_path.as_deref(),
                    &mut logger,
                )
            };
            // Flush logger buffer to stderr regardless of outcome so the
            // user can see what happened.
            let buf = logger.get_buffer().to_string();
            if !buf.is_empty() {
                eprint!("{}", buf);
            }
            match result {
                Ok(()) => process::exit(0),
                Err(msg) => {
                    eprintln!("wslc setup failed: {msg}");
                    process::exit(1);
                }
            }
        }
        #[cfg(not(feature = "wslc"))]
        {
            eprintln!("Error: WSLC backend not compiled. Rebuild with --features wslc.");
            process::exit(1);
        }
    }

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

    // Inject learningModeLogging capability when diagnostic console is enabled.
    let learning_mode_injected = if DiagnosticConfig::force_learning_mode()
        && !request
            .policy
            .capabilities
            .iter()
            .any(|c| c == "learningModeLogging")
    {
        request
            .policy
            .capabilities
            .push("learningModeLogging".to_string());
        true
    } else {
        false
    };

    // Initialize diagnostic logging (registry/env-controlled).
    let diag_config = DiagnosticConfig::from_environment();
    if diag_config.console_enabled {
        logger.enable_diagnostics(&diag_config);

        // Log the preamble
        let exe_path = std::env::current_exe()
            .map(|p| p.to_string_lossy().into_owned())
            .unwrap_or_else(|_| "unknown".to_string());
        let parent_info = wxc_common::diagnostic::get_parent_process_info();
        let _ = writeln!(
            logger,
            "wxc-exec v{} (PID {})",
            env!("CARGO_PKG_VERSION"),
            std::process::id()
        );
        let _ = writeln!(logger, "\tpath: {}", exe_path);
        let _ = writeln!(logger, "\tparent: {}", parent_info);

        // Log if we're injecting Learning Mode
        if learning_mode_injected {
            let _ = writeln!(
                logger,
                "WARNING: injected 'learningModeLogging' capability via ForceLearningMode registry key"
            );
        }

        // Log the raw input JSON config before any transformation.
        let raw_json = if is_base64 {
            wxc_common::encoding::base64_decode(&config_data)
                .ok()
                .and_then(|b| String::from_utf8(b).ok())
        } else {
            fs::read_to_string(&config_data).ok()
        };
        if let Some(json) = raw_json {
            let _ = writeln!(logger, "SECTION: JSON Config");
            let _ = writeln!(logger, "{}", json.trim());
        }
    }

    let _ = writeln!(logger, "SECTION: Request simplified");
    log_request(&request, &mut logger);

    // Emit the full (redacted) request policy for diagnostics.
    let _ = writeln!(
        logger,
        "SECTION: Full `CodexRequest` configuration (redacted)"
    );
    let _ = writeln!(
        logger,
        "{}",
        wxc_common::diagnostic::redacted_request_json(&request)
    );

    // Drop-order contract — DO NOT REORDER, AND DO NOT ADD `process::exit`
    // BETWEEN THIS DECLARATION AND THE EXPLICIT `drop(_dacl_guard)` LATER
    // IN main() WITHOUT FIRST GOING THROUGH THAT DROP:
    //
    //   `_dacl_guard` is declared BEFORE `runner` so that, by Rust's
    //   reverse-declaration destructor order, `runner` drops first (its
    //   internal handles release the child) and the `DaclManager` Drop
    //   runs afterwards, removing the host filesystem ACEs we applied.
    //   Inverting the order would yank the ACEs while the child is still
    //   running. The explicit `drop(runner); drop(_dacl_guard);` later
    //   in main() is the `process::exit`-safe equivalent — `process::exit`
    //   skips destructors, so any new exit added between dispatch and
    //   that explicit drop must run `drop(_dacl_guard)` first or it will
    //   leak ACEs permanently on the host filesystem.
    //
    //   Audit of exit sites at this commit: every `process::exit` after
    //   `_dacl_guard = dispatched.dacl_manager;` is either (a) on the
    //   dispatcher's `Err` arm where `_dacl_guard` is still `None`, or
    //   (b) reached only after the explicit drops. Panic strategy is
    //   `unwind` (default; no `panic = "abort"` in any `[profile.*]`),
    //   so panics during `runner.run()` unwind through Drop and restore
    //   ACEs naturally. If you change either invariant, this comment is
    //   the place to update.
    let mut _dacl_guard: Option<wxc_common::filesystem_dacl::DaclManager> = None;

    // Run script in selected containment backend.
    // BaseContainer is used when --experimental is passed or schema version >= 0.5.
    // Sandbox and MicroVM require --experimental flag.
    let mut runner: Box<dyn ScriptRunner> = match request.containment {
        ContainmentBackend::ProcessContainer => {
            // Compute fallback eligibility on the ProcessContainer arm
            // only — every other `ContainmentBackend` variant is
            // unaffected by `use_base_container` and does not need to
            // pay the (trivial) semver parse cost.
            let version_implies_base_container = is_base_container_version(&request.schema_version);
            let use_base_container = request.experimental_enabled || version_implies_base_container;

            // Validation warning: deniedPaths is only honored on the
            // BaseContainer-fallback path. Surface once at parse time
            // through the buffered logger so it lands in `--dry-run`
            // output and any tooling scraping the diagnostic pipe.
            if !use_base_container && !request.policy.denied_paths.is_empty() {
                let _ = writeln!(
                    logger,
                    "warning: filesystem.deniedPaths is set but containment is ProcessContainer \
                     (no BaseContainer fallback in effect). deniedPaths will not be honored. \
                     Use --experimental or schema 0.5+ to enable fallback with deny enforcement."
                );
            }

            if use_base_container {
                let reason = if version_implies_base_container {
                    format!("schema version {}", request.schema_version)
                } else {
                    "--experimental".to_string()
                };
                let _ = writeln!(logger, "Using BaseContainer runner ({reason})");

                match wxc_common::dispatcher::dispatch_with_fallback(&request) {
                    Ok(dispatched) => {
                        for w in &dispatched.warnings {
                            let _ = writeln!(logger, "warning: {w}");
                        }
                        let _ = writeln!(
                            logger,
                            "selected isolation tier: {}",
                            dispatched.tier.as_str()
                        );

                        _dacl_guard = dispatched.dacl_manager;
                        dispatched.runner
                    }
                    Err(e) => {
                        eprintln!("error: {e}");
                        eprint!("{}", logger.get_buffer());
                        process::exit(1);
                    }
                }
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
        ContainmentBackend::Bubblewrap => {
            eprintln!("Error: Bubblewrap backend not available on Windows");
            process::exit(1);
        }
        ContainmentBackend::Seatbelt => {
            eprintln!("Error: Seatbelt backend is only available on macOS (use mxc-exec-mac)");
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
            #[cfg(feature = "microvm")]
            {
                Box::new(NanVixScriptRunner::new())
            }
            #[cfg(not(feature = "microvm"))]
            {
                eprintln!("Error: MicroVM backend not compiled in (build with --features microvm)");
                process::exit(1);
            }
        }
        ContainmentBackend::Hyperlight => {
            #[cfg(all(feature = "hyperlight", target_arch = "x86_64"))]
            {
                if !request.experimental_enabled {
                    eprintln!(
                        "Error: Hyperlight (Hyperlight+Unikraft) is an experimental feature. \
                         Use --experimental flag."
                    );
                    process::exit(1);
                }
                Box::new(HyperlightScriptRunner::new())
            }
            #[cfg(not(all(feature = "hyperlight", target_arch = "x86_64")))]
            {
                eprintln!(
                    "Error: Hyperlight backend requires x86_64 (Hyperlight needs KVM or WHP)"
                );
                process::exit(1);
            }
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

    // Explicitly drop the runner before the DACL guard so any
    // runner-internal resources holding child handles release first, then
    // the DaclManager's Drop restores the host filesystem ACEs we applied.
    // (process::exit below skips destructors, so we must do this manually
    // for prompt cleanup on the normal path.)
    drop(runner);
    drop(_dacl_guard);

    if cli.dry_run {
        handle_dry_run_exit(&response, &mut logger);
    }

    display_script_results(&response, &mut logger);

    // Close diagnostic pipe.
    logger.close_diagnostics();

    // Output was already relayed to the console by pipe threads.
    // Only print captured output if present (e.g. from error paths).
    if !response.standard_out.is_empty() {
        print!("{}", response.standard_out);
    }
    if !response.standard_err.is_empty() {
        eprint!("{}", response.standard_err);
    }

    // Emit a structured JSON error envelope on stderr for SDK/caller consumption
    // when the runner produced an error message (one-shot flows only).
    // In PTY mode stderr is merged into the PTY output stream, so the envelope
    // appears inline -- callers (e.g. copilot) can parse it from the output.
    if response.exit_code != 0 && !response.error_message.is_empty() {
        let mut envelope = serde_json::json!({
            "error": {
                "code": "backend_error",
                "message": response.error_message,
            }
        });
        if !response.extended_error.is_empty() {
            envelope["error"]["extended_error"] =
                serde_json::Value::String(response.extended_error.clone());
        }
        if let Ok(json) = serde_json::to_string(&envelope) {
            eprintln!("{json}");
        }
    }

    process::exit(response.exit_code);
}
