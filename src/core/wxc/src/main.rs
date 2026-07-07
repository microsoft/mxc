// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#[cfg(target_os = "windows")]
mod audit;
#[cfg(target_os = "windows")]
mod plm_launch;

use std::fmt::Write;
use std::fs;
use std::process;
use std::sync::atomic::Ordering;
use std::sync::{Mutex, OnceLock};
use std::time::Instant;

use appcontainer_common::appcontainer_runner::{
    delete_app_container_profile, AppContainerScriptRunner,
};
use clap::Parser;
#[cfg(all(feature = "hyperlight", target_arch = "x86_64"))]
use hyperlight_common::HyperlightScriptRunner;
#[cfg(feature = "isolation_session")]
use isolation_session_common::IsolationSessionRunner;
#[cfg(feature = "microvm")]
use nanvix_runner::NanVixScriptRunner;
use windows_sandbox_common::windows_sandbox_runner::WindowsSandboxScriptRunner;
use wxc_common::cmdline::{cmdline_from_argv_for_context, CommandLineContext, CommandLineError};
use wxc_common::config_parser::{
    is_base_container_version, load_mxc_request_with_options, load_request, LoadOptions, ParseError,
};
use wxc_common::diagnostic::DiagnosticConfig;
use wxc_common::logger::{Logger, Mode};
use wxc_common::models::{ContainmentBackend, ExecutionRequest, ScriptResponse};
use wxc_common::mxc_error::{MxcError, ResponseEnvelope};
use wxc_common::sandbox_process::Runner;
use wxc_common::script_runner::{handle_dry_run_exit, ScriptRunner};
#[cfg(all(target_os = "windows", feature = "isolation_session"))]
use wxc_common::state_aware_dispatch::dispatch_state_aware;
use wxc_common::state_aware_dispatch::{resolve_backend, run_state_aware, DispatchOutcome};
use wxc_common::state_aware_request::{MxcRequest, ParsedStateAwareRequest, Phase};
use wxc_common::telemetry;

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

    /// Run the fallback detector and emit JSON, without spawning a sandbox.
    #[arg(long)]
    probe: bool,

    /// Audit mode: inject the `permissiveLearningMode` capability into the
    /// AppContainer policy so denied operations are logged but allowed.
    /// Windows-only — the PLM trace pipeline (WPR/ETW) and the runner-side
    /// `request.audit` consumer (AppContainer) have no cross-platform
    /// counterpart, so accepting the flag elsewhere would print a misleading
    /// "restrictions will NOT be enforced" warning while the bubblewrap/
    /// seatbelt backends silently ignore both the flag and the injected
    /// capability.
    #[cfg(target_os = "windows")]
    #[arg(long)]
    audit: bool,

    /// Surface the PLM lifecycle diagnostics (spawn banner, plm.exe stderr
    /// lines, non-zero-exit / spawn-failure reasons) on wxc-exec's stderr in
    /// addition to the log buffer. Off by default so `--audit` doesn't pollute
    /// the wrapped workload's stdout/stderr; opt in when debugging the audit
    /// pipeline itself.
    #[cfg(target_os = "windows")]
    #[arg(long)]
    audit_verbose: bool,

    /// Command to run inside the container, overriding `process.commandLine`
    /// from the policy. The command must follow a `--` separator so normal
    /// CLI flags remain usable after the config path. Examples:
    ///   wxc-exec policy.json -- python --version
    /// When provided, `process.commandLine` in the policy file becomes
    /// optional and is overridden.
    #[arg(value_name = "COMMAND", last = true, allow_hyphen_values = true)]
    command: Vec<String>,
}

impl Cli {
    fn normalize_named_config_command(mut self) -> Self {
        if self.config.is_some() || self.config_base64.is_some() {
            if let Some(first) = self.config_path.take() {
                self.command.insert(0, first);
            }
        }
        self
    }
}

fn log_request(request: &ExecutionRequest, logger: &mut Logger) {
    if !request.container_id.is_empty() {
        let _ = writeln!(logger, "Container ID: {}", request.container_id);
    }
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

fn has_cli_command(cli: &Cli) -> bool {
    !cli.command.is_empty()
}

fn command_line_context_for_backend(backend: &ContainmentBackend) -> CommandLineContext {
    match backend {
        ContainmentBackend::IsolationSession | ContainmentBackend::WindowsSandbox => {
            CommandLineContext::WindowsCommandProcessor
        }
        ContainmentBackend::Wslc
        | ContainmentBackend::Lxc
        | ContainmentBackend::Seatbelt
        | ContainmentBackend::Bubblewrap => CommandLineContext::PosixShell,
        ContainmentBackend::ProcessContainer
        | ContainmentBackend::Vm
        | ContainmentBackend::MicroVm
        | ContainmentBackend::Hyperlight => CommandLineContext::WindowsCreateProcess,
    }
}

fn command_override_from_cli(
    cli: &Cli,
    context: CommandLineContext,
) -> Result<Option<String>, CommandLineError> {
    if cli.command.is_empty() {
        Ok(None)
    } else {
        cmdline_from_argv_for_context(&cli.command, context).map(Some)
    }
}

fn command_override_context_for_state_aware(
    parsed: &ParsedStateAwareRequest,
    has_command_override: bool,
) -> Result<Option<CommandLineContext>, MxcError> {
    if !has_command_override {
        return Ok(None);
    }
    if parsed.phase != Phase::Exec {
        return Err(MxcError::malformed_request(
            "CLI command override is only supported for state-aware exec requests",
        ));
    }
    resolve_backend(parsed).map(|backend| Some(command_line_context_for_backend(&backend)))
}

fn apply_command_override(
    request: &mut ExecutionRequest,
    command_override: Option<&str>,
    logger: &mut Logger,
) {
    if let Some(cmd) = command_override {
        if !request.script_code.is_empty() {
            let _ = writeln!(
                logger,
                "Overriding policy process.commandLine with CLI command: {}",
                cmd
            );
        }
        request.script_code = cmd.to_string();
    }
}

/// Drives the state-aware dispatch flow. On envelope success, writes the
/// JSON to stdout and exits 0. On exec success, exits with the script's
/// exit code (output already streamed). On failure, writes a JSON error
/// envelope to stdout and exits 1. Diagnostic logger output goes to stderr
/// regardless of mode (per design §7.3 stream protocol — stdout reserved
/// for the response envelope).
fn run_state_aware_main(parsed: ParsedStateAwareRequest, dry_run: bool, logger: &mut Logger) -> ! {
    let outcome = dispatch_state_aware_request(parsed, dry_run);
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

/// Per-backend dispatch for state-aware requests. Resolves the requested
/// backend and constructs its `StatefulSandboxBackend` impl from the
/// owning backend crate (which depends on `wxc_common`, so the
/// construction can't live inside `wxc_common` without a cycle). Falls
/// back to `wxc_common::state_aware_dispatch::run_state_aware` for
/// backends that have no state-aware impl, which surfaces the
/// `unsupported_phase` envelope.
fn dispatch_state_aware_request(
    parsed: ParsedStateAwareRequest,
    dry_run: bool,
) -> Result<DispatchOutcome, MxcError> {
    let backend = resolve_backend(&parsed)?;
    match backend {
        #[cfg(all(target_os = "windows", feature = "isolation_session"))]
        wxc_common::models::ContainmentBackend::IsolationSession => {
            let mut runner = isolation_session_common::IsolationSessionRunner::new();
            dispatch_state_aware(&mut runner, parsed, dry_run)
        }
        _ => run_state_aware(parsed, dry_run),
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

fn config_input(cli: &Cli) -> Option<(String, bool)> {
    if let Some(b64) = cli.config_base64.as_ref() {
        Some((b64.clone(), true))
    } else if let Some(p) = cli.config.as_ref() {
        Some((p.clone(), false))
    } else {
        cli.config_path.as_ref().map(|p| (p.clone(), false))
    }
}

/// Resolve the on-disk config path passed to `wxc-exec`, if any. Returns
/// `None` when the config was supplied as `--config-base64` (no file path)
/// or not at all. Used by `--audit` to thread `plm stop --config-path` so
/// findings can be merged back into the source policy.
#[cfg(target_os = "windows")]
fn config_file_path(cli: &Cli) -> Option<std::path::PathBuf> {
    if cli.config_base64.is_some() {
        return None;
    }
    cli.config
        .as_ref()
        .or(cli.config_path.as_ref())
        .map(std::path::PathBuf::from)
}

/// Path to `plm.exe`, expected to sit next to `wxc-exec.exe` in the
/// same install directory. Returns `None` when the current exe path
/// can't be resolved.
#[cfg(target_os = "windows")]
use audit::{
    cancel_active_audit_trace, mark_audit_active, release_audit_singleton, run_plm_command,
    try_acquire_audit_singleton, AuditSingletonGuard, AuditTraceGuard, AUDIT_ACTIVE,
    AUDIT_START_IN_FLIGHT,
};

// ---------------------------------------------------------------------------
// Graceful-exit DACL cleanup
// ---------------------------------------------------------------------------
//
// `DaclManager`'s `Drop` is the only thing that restores host ACEs we
// applied during a Tier 2 / Tier 3 run. We need that `Drop` to fire on
// every code path that can leave main, including the abnormal ones.
// There are three:
//
// 1. **Normal exit / `process::exit`** — destructors of stack-owned
//    values run on the former and are SKIPPED on the latter. We deal
//    with this by explicitly `drop(take_parked_dacl())`-ing before any
//    `process::exit` site below.
// 2. **Panic unwind** — destructors of stack-owned values run; the
//    release profile uses the default `unwind` strategy (see
//    `src/Cargo.toml`). But the `DaclManager` we extract from
//    `Dispatched` lives inside a process-global static (so the Ctrl-C
//    handler can reach it), and statics are NOT touched by unwinding.
//    To restore on panic we install a stack-owned `ParkedDaclGuard` in
//    `main` whose `Drop` calls `take_parked_dacl()` and drops the
//    manager. The guard sits at function scope so the unwind path
//    threads through it.
// 3. **Ctrl-C / Ctrl-Break / console close / logoff / shutdown** — the
//    default Windows handler calls `ExitProcess` directly, skipping
//    every Rust destructor. We install a `SetConsoleCtrlHandler` that
//    takes-and-drops the parked manager before yielding to the
//    default handler.
//
// The mutex in the slot serializes the Ctrl-C handler and the guard
// against each other, so the manager is taken (and therefore
// `Drop`'d) at most once.
//
// Parent-process kill (`TerminateProcess`) still bypasses every
// handler; any leak there is reaped by `recover_orphaned_state` on
// the next wxc-exec startup (which we already run at the top of
// `main`).

static DACL_CLEANUP_SLOT: OnceLock<Mutex<Option<wxc_common::filesystem_dacl::DaclManager>>> =
    OnceLock::new();

fn dacl_cleanup_slot() -> &'static Mutex<Option<wxc_common::filesystem_dacl::DaclManager>> {
    DACL_CLEANUP_SLOT.get_or_init(|| Mutex::new(None))
}

/// Park the DACL manager in the global slot so the Ctrl-C handler can
/// drop it if a signal arrives before the normal-exit path runs.
fn park_dacl_for_cleanup(mgr: wxc_common::filesystem_dacl::DaclManager) {
    let slot = dacl_cleanup_slot();
    let mut guard = slot.lock().unwrap_or_else(|p| p.into_inner());
    *guard = Some(mgr);
}

/// Take the parked DACL manager (if any) so the caller can drop it,
/// triggering ACE restore. Returns `None` if either nothing was parked
/// or another path (the Ctrl-C handler) already took it.
///
/// Recovers from `PoisonError` the same way [`park_dacl_for_cleanup`]
/// does (`into_inner`): a poisoned mutex must NOT silently swallow a
/// parked manager — that would leak ACEs until the next-startup
/// recovery scan reaps them.
fn take_parked_dacl() -> Option<wxc_common::filesystem_dacl::DaclManager> {
    DACL_CLEANUP_SLOT.get().and_then(|slot| {
        let mut guard = slot.lock().unwrap_or_else(|p| p.into_inner());
        guard.take()
    })
}

/// Stack-owned witness that ensures `take_parked_dacl()` runs on every
/// path out of `main`, including panic unwind. The parked
/// `DaclManager` lives in a process-global static (so the Ctrl-C
/// handler can reach it), and Rust's unwinder doesn't touch statics —
/// without this guard, a panic between `park_dacl_for_cleanup` and
/// the explicit `drop(take_parked_dacl())` near the end of `main`
/// would leave host ACEs in place until the next startup's recovery
/// scan.
///
/// `Drop` is a no-op if nothing was ever parked or if the Ctrl-C
/// handler already drained the slot.
struct ParkedDaclGuard;

impl Drop for ParkedDaclGuard {
    fn drop(&mut self) {
        drop(take_parked_dacl());
    }
}

/// Windows console-control handler. Called by the OS on Ctrl-C, Ctrl-Break,
/// console close, logoff, and shutdown. Takes the parked DACL manager and
/// drops it — `Drop` runs `restore()` which removes the ACEs we applied.
/// Returns `FALSE` so the default handler still runs (which terminates
/// the process).
///
/// Acquires the slot with a bounded wait
/// (`plm::coordination::CTRL_HANDLER_DRAIN_TIMEOUT`), not `try_lock`.
/// If the main thread is mid-`Drop` on the same manager — which can be
/// doing a `SetNamedSecurityInfoW` — returning FALSE immediately lets
/// the default handler call `ExitProcess`, terminating that drop mid-
/// Win32 and leaving the host DACL in an inconsistent state. The
/// bounded wait blocks the default handler until either main finishes
/// (lock released) or the shared timeout elapses — whichever comes
/// first. On timeout we proceed anyway; the recovery scan on the next
/// `wxc-exec` startup reaps anything left behind.
unsafe extern "system" fn dacl_ctrl_handler(_ctrl_type: u32) -> windows::core::BOOL {
    if let Some(slot) = DACL_CLEANUP_SLOT.get() {
        use std::time::{Duration, Instant};
        // The handler runs TWO bounded waits (this one + the
        // AUDIT_START_IN_FLIGHT wait below) before `wpr -cancel`, and
        // CTRL_CLOSE_EVENT / CTRL_LOGOFF / CTRL_SHUTDOWN have a hard
        // ~5s OS-imposed kill budget. The per-wait budget is sourced
        // from the shared `plm::coordination::CTRL_HANDLER_DRAIN_TIMEOUT`
        // so `wxc-exec` and `plm.exe`'s `plm_ctrl_handler` cannot
        // drift apart, and the budget invariant is pinned by a unit
        // test (`ctrl_handler_drain_timeout_respects_os_budget`).
        let deadline = Instant::now() + plm::coordination::CTRL_HANDLER_DRAIN_TIMEOUT;
        loop {
            if let Ok(mut guard) = slot.try_lock() {
                // Either main already took the manager (guard is None)
                // or it never parked one; dropping `Option::take` is
                // a no-op in both cases. Either way, the contract — no
                // restore thread running concurrently with the default
                // handler's ExitProcess — is satisfied.
                drop(guard.take());
                break;
            }
            if Instant::now() >= deadline {
                break;
            }
            std::thread::sleep(Duration::from_millis(50));
        }
    }
    // FALSE = "I did not fully handle this; run the next handler in the
    // chain (i.e. the default handler that calls ExitProcess)".
    //
    // if `plm start` is still in
    // flight when Ctrl+C arrives, wait briefly for it to complete
    // before deciding whether to issue `wpr -cancel`. Without this
    // wait, a cancel that races a not-yet-engaged session is a no-op
    // and the session leaks past wxc-exec exit. On timeout we proceed
    // anyway — the next-startup `recover_orphaned_state` scan plus a
    // manual `wpr -cancel` would catch any residue.
    //
    // the wait loop is
    // implemented by `plm::coordination::wait_until_cleared`, the
    // same tested helper `plm.exe`'s console-control handler uses.
    //
    // the per-wait
    // timeout is sourced from the shared
    // `plm::coordination::CTRL_HANDLER_DRAIN_TIMEOUT` const so the
    // wxc-exec and plm.exe handlers cannot drift apart. The const's
    // docs (and the
    // `ctrl_handler_drain_timeout_respects_os_budget` unit test)
    // pin the ~5s OS kill-budget invariant.
    let _ = plm::coordination::wait_until_cleared(
        &AUDIT_START_IN_FLIGHT,
        plm::coordination::CTRL_HANDLER_DRAIN_TIMEOUT,
        std::time::Duration::from_millis(50),
    );
    cancel_active_audit_trace();
    windows::core::BOOL(0)
}

/// Install the console-control handler. Idempotent — calling twice
/// registers the same handler twice, which is harmless because the
/// take-and-drop is `Option::take`-based.
fn install_dacl_ctrl_handler() {
    use windows::Win32::System::Console::SetConsoleCtrlHandler;
    // SAFETY: `dacl_ctrl_handler` has the correct ABI; the `Add=TRUE`
    // call merely appends to the OS handler chain.
    let _ = unsafe { SetConsoleCtrlHandler(Some(dacl_ctrl_handler), true) };
}

fn main() {
    let cli = Cli::parse().normalize_named_config_command();

    // Best-effort: reap any orphaned DACL state files left behind by
    // crashed prior MXC runs. Runs BEFORE the `--probe` arm because
    // `wxc-exec --probe` is the canonical recovery trigger consumers
    // (WinProcessContainer-Tests Phase 6, SDK warm-start) rely on. Errors here
    // are non-fatal and only surface via stderr. On a healthy host
    // with zero state files this is sub-millisecond.
    match wxc_common::filesystem_dacl::recover_orphaned_state() {
        Ok(report) => {
            if report.files_processed > 0 || !report.errors.is_empty() {
                eprintln!(
                    "DACL recovery: {} file(s), {} ACE(s) restored, {} pruned (missing), {} error(s)",
                    report.files_processed,
                    report.aces_restored,
                    report.aces_pruned_missing,
                    report.errors.len()
                );
                for e in &report.errors {
                    eprintln!("  {e}");
                }
            }
        }
        Err(e) => eprintln!("DACL recovery failed: {e}"),
    }

    // --probe is a detection-only fast path used by SDK
    // `getPlatformSupport()` on every first call. It does not spawn a
    // sandbox, never parks a DaclManager, and never calls into COM/WinRT.
    // Run it AFTER recovery (so consumers that rely on `--probe`-as-
    // reaper still get it) but BEFORE COM init / SetConsoleCtrlHandler
    // (which probe doesn't need; deferring them shaves cold-start cost
    // off the SDK warm path).
    if cli.probe {
        let policy = if let Some((data, is_b64)) = config_input(&cli) {
            // Parse using the existing pipeline but route logger output to
            // an in-memory buffer that we discard — the probe must not
            // emit anything other than its JSON line on stdout.
            let mut probe_logger = Logger::new(Mode::Buffer);
            match load_request(&data, &mut probe_logger, is_b64) {
                Ok(r) => r.policy,
                Err(_) => {
                    eprintln!("Error: failed to load probe config");
                    eprint!("{}", probe_logger.get_buffer());
                    process::exit(1);
                }
            }
        } else {
            wxc_common::models::ContainerPolicy::default()
        };
        let output = appcontainer_common::probe::run_probe(&policy);
        match appcontainer_common::probe::to_json_pretty(&output) {
            Ok(s) => println!("{s}"),
            Err(e) => {
                eprintln!("Error: probe serialization failed: {e}");
                process::exit(1);
            }
        }
        return;
    }

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

    // Install the Ctrl-C / Ctrl-Break handler that drops any parked
    // DaclManager on signal. Cheap and idempotent.
    install_dacl_ctrl_handler();

    // Stack-owned witness so a panic anywhere below — between
    // `park_dacl_for_cleanup` and the explicit `drop(take_parked_dacl())`
    // near the end of `main` — still drains the slot and runs
    // `restore()` during unwind. Without it the manager is parked in
    // a static and unwinding skips destructors of static-owned values.
    let _dacl_guard = ParkedDaclGuard;

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

    // --probe is handled at the top of `main` (before COM init) for
    // SDK first-call latency. See note there.

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
    let has_command_override = has_cli_command(&cli);
    let load_opts = LoadOptions {
        is_base64,
        allow_missing_command: has_command_override,
    };
    let request = match load_mxc_request_with_options(&config_data, &mut logger, load_opts) {
        Ok(MxcRequest::OneShot(req)) => req,
        Ok(MxcRequest::StateAware(mut parsed)) => {
            let context =
                match command_override_context_for_state_aware(&parsed, has_command_override) {
                    Ok(context) => context,
                    Err(e) => {
                        print_error_envelope(&e);
                        eprint!("{}", logger.get_buffer());
                        process::exit(1);
                    }
                };
            let command_override = match context
                .map(|context| command_override_from_cli(&cli, context))
                .transpose()
            {
                Ok(command_override) => command_override.flatten(),
                Err(e) => {
                    print_error_envelope(&MxcError::malformed_request(format!(
                        "invalid CLI command override: {e}"
                    )));
                    eprint!("{}", logger.get_buffer());
                    process::exit(1);
                }
            };
            apply_command_override(
                &mut parsed.request,
                command_override.as_deref(),
                &mut logger,
            );
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
    request.testing_features_enabled = cli.allow_testing_features;
    request.dry_run = cli.dry_run;
    #[cfg(target_os = "windows")]
    {
        request.audit = cli.audit;
    }

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

    // Apply the CLI command-line override to one-shot requests. State-aware
    // exec is handled above before dispatch.
    let command_override = match command_override_from_cli(
        &cli,
        command_line_context_for_backend(&request.containment),
    ) {
        Ok(command_override) => command_override,
        Err(e) => {
            eprintln!("Request error\ninvalid CLI command override: {e}");
            eprint!("{}", logger.get_buffer());
            telemetry::emit_early_exit(
                telemetry_active,
                &request.containment,
                telemetry::FailureReason::ConfigError,
            );
            process::exit(1);
        }
    };
    apply_command_override(&mut request, command_override.as_deref(), &mut logger);

    // --audit injects permissiveLearningMode so denied operations are logged
    // but allowed. Works in both debug and release builds; in release the
    // runner-side rejection is relaxed because request.audit is set.
    // Windows-only: the flag itself only exists on Windows (see `Cli::audit`).
    //
    // Downstream capability lookups are case-sensitive (the AppContainer
    // runner does exact string matches against the JSON capability name),
    // so the "already present?" check here matches case-sensitively too.
    // An operator who explicitly wrote a mis-cased spelling in the config
    // gets a second, correctly-cased entry appended rather than silently
    // relying on the mis-cased one that downstream lookups will ignore.
    #[cfg(target_os = "windows")]
    if cli.audit
        && !request
            .policy
            .capabilities
            .iter()
            .any(|c| c == "permissiveLearningMode")
    {
        request
            .policy
            .capabilities
            .push("permissiveLearningMode".to_string());
        logger.log("WARNING: --audit enabled - AppContainer restrictions will NOT be enforced\n");
        if cli.audit_verbose {
            eprintln!(
                "[mxc] permissiveLearningMode injected via --audit - AppContainer restrictions are NOT enforced"
            );
        }
    }

    // Final validation: a command line must come from somewhere. If neither
    // the policy nor the CLI supplied one we cannot proceed.
    if request.script_code.is_empty() {
        eprintln!(
            "Error: no command to run. Provide `process.commandLine` in the policy or pass the command as arguments after the config path."
        );
        eprint!("{}", logger.get_buffer());
        telemetry::emit_early_exit(
            telemetry_active,
            &request.containment,
            telemetry::FailureReason::ConfigError,
        );
        process::exit(1);
    }

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
        "SECTION: Full `ExecutionRequest` configuration (redacted)"
    );
    let _ = writeln!(
        logger,
        "{}",
        wxc_common::diagnostic::redacted_request_json(&request)
    );

    // DaclManager parking for the BaseContainer/fallback path. Parked
    // into a global slot (see `dacl_cleanup_slot`) so the Ctrl-C handler
    // can drop it on signal as well as the normal-exit path below. The
    // slot returns `None` if no DACL augmentation was required.

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

            if use_base_container {
                let reason = if version_implies_base_container {
                    format!("schema version {}", request.schema_version)
                } else {
                    "--experimental".to_string()
                };
                let _ = writeln!(logger, "Using BaseContainer-fallback dispatcher ({reason})");

                match appcontainer_common::dispatcher::dispatch_with_fallback(&request) {
                    Ok(dispatched) => {
                        for w in &dispatched.warnings {
                            let _ = writeln!(logger, "warning: {w}");
                        }
                        let _ = writeln!(
                            logger,
                            "selected isolation tier: {}",
                            dispatched.tier.as_str()
                        );

                        let (dispatched_runner, dacl_manager) = dispatched.into_runner_and_guard();
                        if let Some(mgr) = dacl_manager {
                            park_dacl_for_cleanup(mgr);
                        }
                        dispatched_runner
                    }
                    Err(e) => {
                        eprintln!("error: {e}");
                        if let appcontainer_common::dispatcher::DispatchError::Dacl {
                            warnings,
                            ..
                        } = &e
                        {
                            for w in warnings {
                                eprintln!("  dacl warning: {w}");
                            }
                        }
                        eprint!("{}", logger.get_buffer());
                        telemetry::emit_early_exit(
                            telemetry_active,
                            &request.containment,
                            telemetry::FailureReason::InitError,
                        );
                        process::exit(1);
                    }
                }
            } else {
                Box::new(Runner::new(AppContainerScriptRunner::new()))
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
                telemetry::emit_early_exit(
                    telemetry_active,
                    &request.containment,
                    telemetry::FailureReason::InitError,
                );
                process::exit(1);
            }
        }
        ContainmentBackend::Lxc => {
            eprintln!("Error: LXC backend not available on Windows");
            telemetry::emit_early_exit(
                telemetry_active,
                &request.containment,
                telemetry::FailureReason::InitError,
            );
            process::exit(1);
        }
        ContainmentBackend::Bubblewrap => {
            eprintln!("Error: Bubblewrap backend not available on Windows");
            telemetry::emit_early_exit(
                telemetry_active,
                &request.containment,
                telemetry::FailureReason::InitError,
            );
            process::exit(1);
        }
        ContainmentBackend::Seatbelt => {
            eprintln!("Error: Seatbelt backend is only available on macOS (use mxc-exec-mac)");
            telemetry::emit_early_exit(
                telemetry_active,
                &request.containment,
                telemetry::FailureReason::InitError,
            );
            process::exit(1);
        }
        ContainmentBackend::Vm => {
            eprintln!("Error: VM backend not yet implemented");
            telemetry::emit_early_exit(
                telemetry_active,
                &request.containment,
                telemetry::FailureReason::InitError,
            );
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
                telemetry::emit_early_exit(
                    telemetry_active,
                    &request.containment,
                    telemetry::FailureReason::InitError,
                );
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
                telemetry::emit_early_exit(
                    telemetry_active,
                    &request.containment,
                    telemetry::FailureReason::InitError,
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
                telemetry::emit_early_exit(
                    telemetry_active,
                    &request.containment,
                    telemetry::FailureReason::InitError,
                );
                process::exit(1);
            }
        }
    };

    // --audit: start the PLM (permissive learning mode) WPR trace before
    // the runner spawns the container so we capture access-denied events
    // for the lifetime of the workload. The matching `plm stop` below
    // tears the trace down and (when the policy came from a file)
    // merges findings back into it. Both calls are best-effort.
    //
    // Bracket the live-trace window with `AUDIT_ACTIVE` + a stack guard
    // so Ctrl-C / panic / process::exit between start and stop don't
    // leak the kernel ETW session.
    //
    // declaration order matters. Rust
    // drops locals in REVERSE declaration order, and on the cleanup
    // path we want the trace guard (`AuditTraceGuard`, which calls
    // `wpr -cancel`) to run BEFORE the singleton handle is released —
    // otherwise a concurrent wxc-exec could acquire the freed mutex
    // and start its own trace, only to have our stale `wpr -cancel`
    // tear it down. Declare the singleton first so it drops last.
    #[cfg(target_os = "windows")]
    let _audit_singleton: Option<AuditSingletonGuard>;
    #[cfg(target_os = "windows")]
    let _audit_guard: Option<AuditTraceGuard>;
    #[cfg(target_os = "windows")]
    let audit_config_file = if cli.audit {
        // refuse to start a second concurrent
        // audit. We acquire the host-wide named mutex BEFORE marking
        // AUDIT_ACTIVE so a failure here doesn't engage the cleanup
        // path that would cancel someone else's running trace.
        match try_acquire_audit_singleton() {
            Ok(g) => _audit_singleton = Some(g),
            Err(msg) => {
                let _ = writeln!(logger, "[audit] {msg}");
                eprintln!("error: {msg}");
                _audit_singleton = None;
                _audit_guard = None;
                std::process::exit(1);
            }
        }
        mark_audit_active();
        _audit_guard = Some(AuditTraceGuard);
        // previously this was
        // `let _ = run_plm_command(...)`, which discarded the failure
        // status. If plm start failed (missing plm.exe, wpr session
        // conflict not resolved, etc.), the workload ran with
        // `permissiveLearningMode` injected into the sandbox policy
        // but with zero WPR recording — an empty Adjusted_*.json
        // looked like "no denials." Bail explicitly on start failure
        // so the operator sees the error and the policy isn't
        // silently relaxed.
        //
        // bracket the spawn with
        // AUDIT_START_IN_FLIGHT so the console-control handler waits
        // for it to drain before deciding whether to issue `wpr
        // -cancel` (closes the Ctrl+C race where cancel arrives
        // before `plm.exe`'s child `wpr -start` has engaged the
        // kernel session).
        AUDIT_START_IN_FLIGHT.store(true, Ordering::SeqCst);
        let start_ok = run_plm_command(
            &[std::ffi::OsStr::new("start")],
            &mut logger,
            cli.audit_verbose,
        );
        AUDIT_START_IN_FLIGHT.store(false, Ordering::SeqCst);
        if !start_ok {
            let _ = writeln!(
                logger,
                "[audit] plm start failed; refusing to run the workload with \
                 permissiveLearningMode but no WPR recording"
            );
            eprintln!(
                "error: plm start failed; refusing to run --audit without an \
                 active trace. See logs for details."
            );
            // cancel_active_audit_trace is idempotent and safe to call
            // even if start never began a session — it inspects the
            // AUDIT_ACTIVE flag and only invokes wpr -cancel if set.
            cancel_active_audit_trace();
            std::process::exit(1);
        }
        config_file_path(&cli)
    } else {
        _audit_guard = None;
        _audit_singleton = None;
        None
    };

    let run_start = Instant::now();
    let response = runner.run(&request, &mut logger);
    let run_elapsed = run_start.elapsed();
    let _ = writeln!(logger, "Runner completed in {}ms", run_elapsed.as_millis());

    // Tear down the PLM trace after the container exits, regardless of
    // its exit code. Done before the runner is dropped so the trace
    // tooling sees a fully-quiesced workload.
    //
    // only clear `AUDIT_ACTIVE` when `plm stop` actually
    // succeeded. Previously the flag was cleared unconditionally,
    // which silently leaked the kernel ETW session whenever stop
    // failed (missing plm.exe, spawn fail, wpr -stop non-zero) and
    // simultaneously turned `AuditTraceGuard::drop` and the Ctrl-C
    // handler into no-ops. On failure we now leave the flag set so
    // the stack guard's `Drop` runs `wpr -cancel` for us.
    #[cfg(target_os = "windows")]
    if cli.audit {
        let mut stop_args: Vec<std::ffi::OsString> = vec![std::ffi::OsString::from("stop")];
        if let Some(cfg) = audit_config_file.as_ref() {
            stop_args.push(std::ffi::OsString::from("--config-path"));
            stop_args.push(cfg.clone().into_os_string());
        }
        let borrowed: Vec<&std::ffi::OsStr> = stop_args
            .iter()
            .map(std::ffi::OsString::as_os_str)
            .collect();
        let stop_ok = run_plm_command(&borrowed, &mut logger, cli.audit_verbose);
        if stop_ok {
            AUDIT_ACTIVE.store(false, Ordering::SeqCst);
        } else {
            let _ = writeln!(
                logger,
                "[audit] plm stop failed; leaving AUDIT_ACTIVE set so cleanup guards \
                 will run wpr -cancel on exit"
            );
        }
    }

    // Explicitly drop the runner before retrieving the parked DACL
    // manager so any runner-internal resources holding child handles
    // release first; then drop the manager so its `restore()` runs.
    // (process::exit below skips destructors, so we must do this
    // manually for prompt cleanup on the normal path. The Ctrl-C
    // handler covers the abnormal path; recover_orphaned_state on the
    // next startup covers everything else.)
    drop(runner);
    drop(take_parked_dacl());

    // the `process::exit` below skips destructors, so
    // `AuditTraceGuard::drop` (which calls `cancel_active_audit_trace`)
    // and `AuditSingletonGuard::drop` (which releases the host-wide
    // named mutex) never run on the normal path. Leaving `AUDIT_ACTIVE`
    // set so cleanup guards run `wpr -cancel` on stop failure is only
    // true on the panic-unwind / Ctrl-C path, not here. Manually
    // invoke the cleanups so a stop-failure path actually tears the
    // kernel ETW session down and frees the singleton.
    #[cfg(target_os = "windows")]
    {
        cancel_active_audit_trace();
        release_audit_singleton();
    }

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

#[cfg(test)]
mod tests {
    use super::*;

    use clap::{CommandFactory, Parser};
    use wxc_common::encoding::base64_encode;
    use wxc_common::logger::Mode;
    use wxc_common::mxc_error::MxcErrorCode;
    use wxc_common::state_aware_request::MxcRequest;

    fn parse_cli(argv: &[&str]) -> Cli {
        Cli::try_parse_from(argv)
            .unwrap()
            .normalize_named_config_command()
    }

    fn encoded_policy(json: &str) -> String {
        base64_encode(json.as_bytes())
    }

    fn test_logger() -> Logger {
        Logger::new(Mode::Buffer)
    }

    #[test]
    fn cli_parses_flags_after_config_path_without_command_override() {
        let cli = parse_cli(&["wxc-exec", "policy.json", "--experimental", "--debug"]);

        assert_eq!(cli.config_path.as_deref(), Some("policy.json"));
        assert!(cli.experimental);
        assert!(cli.debug);
        assert!(cli.command.is_empty());
    }

    #[test]
    fn cli_captures_command_after_separator() {
        let cli = parse_cli(&["wxc-exec", "policy.json", "--", "python", "--version"]);

        assert_eq!(cli.config_path.as_deref(), Some("policy.json"));
        assert_eq!(
            cli.command,
            vec!["python".to_string(), "--version".to_string()]
        );
        assert_eq!(
            command_override_from_cli(&cli, CommandLineContext::WindowsCreateProcess)
                .unwrap()
                .as_deref(),
            Some("python --version")
        );
    }

    #[test]
    fn cli_captures_command_after_named_config() {
        let cli = parse_cli(&[
            "wxc-exec",
            "--config",
            "policy.json",
            "--",
            "python",
            "--version",
        ]);

        assert_eq!(cli.config.as_deref(), Some("policy.json"));
        assert_eq!(cli.config_path.as_deref(), None);
        assert_eq!(
            cli.command,
            vec!["python".to_string(), "--version".to_string()]
        );
        assert_eq!(
            command_override_from_cli(&cli, CommandLineContext::WindowsCreateProcess)
                .unwrap()
                .as_deref(),
            Some("python --version")
        );
    }

    #[test]
    fn cli_captures_command_after_named_config_separator() {
        let cli = parse_cli(&[
            "wxc-exec",
            "--config",
            "policy.json",
            "--experimental",
            "--",
            "python",
            "--version",
        ]);

        assert_eq!(cli.config.as_deref(), Some("policy.json"));
        assert!(cli.experimental);
        assert_eq!(cli.config_path.as_deref(), None);
        assert_eq!(
            cli.command,
            vec!["python".to_string(), "--version".to_string()]
        );
        assert_eq!(
            command_override_from_cli(&cli, CommandLineContext::WindowsCreateProcess)
                .unwrap()
                .as_deref(),
            Some("python --version")
        );
    }

    #[test]
    fn cli_captures_command_after_config_base64() {
        let encoded = encoded_policy(r#"{ "process": { "commandLine": "policy" } }"#);
        let cli = parse_cli(&[
            "wxc-exec",
            "--config-base64",
            &encoded,
            "--",
            "python",
            "--version",
        ]);

        assert_eq!(cli.config_base64.as_deref(), Some(encoded.as_str()));
        assert_eq!(cli.config_path.as_deref(), None);
        assert_eq!(
            cli.command,
            vec!["python".to_string(), "--version".to_string()]
        );
        assert_eq!(
            command_override_from_cli(&cli, CommandLineContext::WindowsCreateProcess)
                .unwrap()
                .as_deref(),
            Some("python --version")
        );
    }

    #[test]
    fn cli_captures_hyphenated_command_after_separator() {
        let cli = parse_cli(&[
            "wxc-exec",
            "--config",
            "policy.json",
            "--",
            "-command",
            "value",
        ]);

        assert_eq!(cli.config.as_deref(), Some("policy.json"));
        assert_eq!(cli.config_path.as_deref(), None);
        assert_eq!(
            cli.command,
            vec!["-command".to_string(), "value".to_string()]
        );
        assert_eq!(
            command_override_from_cli(&cli, CommandLineContext::WindowsCreateProcess)
                .unwrap()
                .as_deref(),
            Some("-command value")
        );
    }

    #[test]
    fn help_text_documents_cli_command_override() {
        let mut command = Cli::command();
        let help = command.render_long_help().to_string();

        assert!(help.contains("Windows Container Executor"));
        assert!(help.contains("COMMAND"));
        assert!(help.contains("process.commandLine"));
        assert!(help.contains("wxc-exec policy.json -- python --version"));
    }

    #[test]
    fn windows_sandbox_cli_command_uses_cmd_context() {
        assert_eq!(
            command_line_context_for_backend(&ContainmentBackend::WindowsSandbox),
            CommandLineContext::WindowsCommandProcessor
        );
    }

    #[test]
    fn cli_command_overrides_policy_command_line_in_resolved_request() {
        let cli = parse_cli(&["wxc-exec", "policy.json", "--", "cli-app.exe", "--from-cli"]);
        let command_override =
            command_override_from_cli(&cli, CommandLineContext::WindowsCreateProcess).unwrap();
        let mut logger = test_logger();
        let policy = r#"{
            "process": {
                "commandLine": "policy-app.exe --from-policy",
                "cwd": "C:\\workspace"
            },
            "filesystem": {
                "readwritePaths": ["C:\\workspace"]
            }
        }"#;
        let opts = LoadOptions {
            is_base64: true,
            allow_missing_command: command_override.is_some(),
        };

        let mut request = match load_mxc_request_with_options(
            &encoded_policy(policy),
            &mut logger,
            opts,
        )
        .unwrap()
        {
            MxcRequest::OneShot(req) => req,
            MxcRequest::StateAware(_) => panic!("expected one-shot"),
        };
        apply_command_override(&mut request, command_override.as_deref(), &mut logger);

        assert_eq!(request.script_code, "cli-app.exe --from-cli");
        assert_eq!(request.working_directory, "C:\\workspace");
        assert_eq!(request.policy.readwrite_paths, vec!["C:\\workspace"]);
        assert!(logger.get_buffer().contains(
            "Overriding policy process.commandLine with CLI command: cli-app.exe --from-cli"
        ));
    }

    #[test]
    fn cli_command_matches_equivalent_policy_command_line() {
        let cli = parse_cli(&[
            "wxc-exec",
            "policy.json",
            "--",
            "cli-app.exe",
            "--message",
            "hello world",
        ]);
        let command_override =
            command_override_from_cli(&cli, CommandLineContext::WindowsCreateProcess)
                .unwrap()
                .unwrap();
        let mut policy_logger = test_logger();
        let mut cli_logger = test_logger();
        let policy = r#"{
            "process": {
                "commandLine": "cli-app.exe --message \"hello world\"",
                "cwd": "C:\\workspace"
            }
        }"#;
        let cli_policy = r#"{
            "process": {
                "cwd": "C:\\workspace"
            }
        }"#;

        let policy_request = match load_mxc_request_with_options(
            &encoded_policy(policy),
            &mut policy_logger,
            LoadOptions {
                is_base64: true,
                allow_missing_command: false,
            },
        )
        .unwrap()
        {
            MxcRequest::OneShot(req) => req,
            MxcRequest::StateAware(_) => panic!("expected one-shot"),
        };
        let mut cli_request = match load_mxc_request_with_options(
            &encoded_policy(cli_policy),
            &mut cli_logger,
            LoadOptions {
                is_base64: true,
                allow_missing_command: true,
            },
        )
        .unwrap()
        {
            MxcRequest::OneShot(req) => req,
            MxcRequest::StateAware(_) => panic!("expected one-shot"),
        };

        apply_command_override(&mut cli_request, Some(&command_override), &mut cli_logger);

        assert_eq!(cli_request.script_code, policy_request.script_code);
        assert_eq!(
            cli_request.working_directory,
            policy_request.working_directory
        );
    }

    #[test]
    fn isolation_session_cli_command_quotes_shell_metacharacters() {
        let cli = parse_cli(&[
            "wxc-exec",
            "policy.json",
            "--",
            "python",
            "-c",
            "if 5 < 10: print('hello')",
        ]);
        let command_override =
            command_override_from_cli(&cli, CommandLineContext::WindowsCommandProcessor)
                .unwrap()
                .unwrap();

        assert_eq!(command_override, "python -c \"if 5 < 10: print('hello')\"");
    }

    #[test]
    fn wslc_cli_command_uses_posix_shell_quoting() {
        let cli = parse_cli(&["wxc-exec", "policy.json", "--", "echo", "safe&whoami"]);
        let command_override = command_override_from_cli(&cli, CommandLineContext::PosixShell)
            .unwrap()
            .unwrap();

        assert_eq!(command_override, "echo 'safe&whoami'");
    }

    #[test]
    fn state_aware_command_override_only_applies_to_exec_phase() {
        let parsed = ParsedStateAwareRequest {
            request: ExecutionRequest::default(),
            phase: Phase::Start,
            containment: None,
            sandbox_id: Some("iso:wxc-1234".into()),
            experimental_raw: None,
        };

        let err = command_override_context_for_state_aware(&parsed, true).unwrap_err();

        assert_eq!(err.code, MxcErrorCode::MalformedRequest);
        assert!(err
            .message
            .contains("only supported for state-aware exec requests"));
    }
}
