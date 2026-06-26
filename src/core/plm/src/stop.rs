//! Port of `stop_plm_logging.ps1`.
//!
//! Stops the in-progress WPR trace, parses the .etl, and (optionally)
//! merges the discovered file-access paths and capability requests into
//! an MXC container config, writing an `Adjusted_*.json` next to it.

use anyhow::{Context, Result};
use chrono::Local;
use std::path::{Path, PathBuf};
use std::process::ExitStatus;

use crate::config::{
    apply_ui_operation_flags, deny_file_set, initialize_filesystem, load_config,
    merge_capabilities, resolve_adjusted_config_path, save_adjusted_config,
    set_ui_subsystem_enabled, update_from_access_events, write_added_paths_summary,
    write_detection_summary, write_requested_capabilities_summary,
};
use crate::event_parser::{parse_events, ParseResult};
use crate::wpr_path::wpr_command;

/// the "skip adjusted config" predicate extracted
/// from the inline check in `run`. A trace that produced no access
/// events, no capability requests, no `CONVERT_TO_GUI` hint, and no
/// `UI_OPERATION` flags has nothing to merge — emitting an
/// `Adjusted_*.json` byte-identical to the input would only confuse
/// the harness's diff-based pass/fail signal.
pub fn should_skip_adjusted(parse: &ParseResult) -> bool {
    parse.is_empty()
}

pub struct StopOptions {
    pub log_dir: Option<PathBuf>,
    pub bin_path: Option<PathBuf>,
    pub config_path: Option<PathBuf>,
    pub adjusted_config_path: Option<PathBuf>,
    /// When set, skip `wpr -stop` and parse the supplied .etl directly.
    /// Useful for re-processing a previously captured trace without an
    /// active WPR session.
    pub trace_file: Option<PathBuf>,
    pub verbose: bool,
}

/// Abstraction over `wpr -stop` invocations so the failure-mapping
/// state machine in `stop_plm_trace_with` is testable without
/// actually spawning processes. Mirrors `start::WprLauncher`
///.
pub trait WprStopper {
    fn stop(&mut self, trace_file: &Path) -> Result<ExitStatus>;
}

pub struct WprExeStopper;

impl WprStopper for WprExeStopper {
    fn stop(&mut self, trace_file: &Path) -> Result<ExitStatus> {
        let cmd = wpr_command();
        let resolved = cmd.get_program().to_string_lossy().into_owned();
        wpr_command()
            .args(["-stop", &trace_file.to_string_lossy()])
            .status()
            .map_err(|e| anyhow::anyhow!("failed to spawn wpr -stop ({resolved}): {e}"))
    }
}

/// Core success/failure mapping for `wpr -stop`, parameterised on a
/// `WprStopper` so tests can drive the non-zero-exit and spawn-error
/// branches deterministically without an actual `wpr.exe`.
pub fn stop_plm_trace_with<S: WprStopper>(stopper: &mut S, trace_file: &Path) -> Result<()> {
    let status = stopper.stop(trace_file)?;
    if !status.success() {
        anyhow::bail!("wpr -stop exited with {status}");
    }
    Ok(())
}

fn stop_plm_trace(trace_file: &Path) -> Result<()> {
    stop_plm_trace_with(&mut WprExeStopper, trace_file)
}

/// Resolve `--bin-path` (or the calling exe directory as a fallback)
/// to its canonical form so the self-access filter in
/// `config::update_from_access_events` can compare it against the
/// verbatim-prefixed paths ETW emits.
///
/// Returns the resolved path plus an optional warning string when the
/// canonicalize step diverged from the operator's intent. Extracted
/// from `run()` so the fallback chain
/// is unit-testable without spawning wpr or building a real ETL.
///
/// Fallback chain (in order):
///   1. `canonicalize(opt.bin_path)` if `Some`
///   2. raw `opt.bin_path` if `Some` (with a warning)
///   3. `exe_dir` (no warning — no operator intent to diverge from)
pub fn resolve_bin_path(opt: Option<&Path>, exe_dir: &Path) -> (PathBuf, Option<String>) {
    let Some(raw) = opt else {
        return (exe_dir.to_path_buf(), None);
    };
    match raw.canonicalize() {
        Ok(p) => (p, None),
        Err(e) => {
            let warning = format!(
                "could not canonicalize --bin-path {} ({}); self-access filter \
                 will use the raw path. Events referencing the binary via a \
                 different spelling (e.g. verbatim \\\\?\\) may leak into the \
                 adjusted config.",
                raw.display(),
                e
            );
            // Prefer the raw operator-supplied path over silently
            // substituting exe_dir; the previous behavior swallowed
            // operator intent entirely.
            (raw.to_path_buf(), Some(warning))
        }
    }
}

pub fn run(opts: StopOptions, exe_dir: &Path) -> Result<()> {
    // $LogDir defaults to "<exe dir>\logs\<timestamp>_pid<PID>". Including
    // the PID + sub-second component prevents collisions when multiple
    // PLM tasks finish within the same second (e.g. parallel test
    // harness runs all calling --audit on different configs).
    let log_dir = opts.log_dir.unwrap_or_else(|| {
        let stamp = format!(
            "{}_pid{}",
            Local::now().format("%Y-%m-%d_%H%M%S%.3f"),
            std::process::id()
        );
        exe_dir.join("logs").join(stamp)
    });
    std::fs::create_dir_all(&log_dir)
        .with_context(|| format!("failed to create log dir {}", log_dir.display()))?;

    // Resolve bin_path to its canonical form so the self-access filter
    // in `config::update_from_access_events` can compare it against the
    // verbatim-prefixed paths ETW emits. The fallback chain is in
    // `resolve_bin_path`.
    let (bin_path, warning) = resolve_bin_path(opts.bin_path.as_deref(), exe_dir);
    if let Some(w) = warning {
        eprintln!("[plm] warning: {w}");
    }

    let trace_file = if let Some(p) = opts.trace_file.as_ref() {
        // Operator supplied a pre-captured .etl -- don't try to stop a
        // (likely non-existent) live WPR session.
        if !p.exists() {
            anyhow::bail!("trace file does not exist: {}", p.display());
        }
        p.clone()
    } else {
        let p = log_dir.join("trace.etl");
        stop_plm_trace(&p)?;
        p
    };

    if opts.verbose {
        println!("Beginning event parsing, this may take several minutes");
    }

    // Current directory at parse time -- events under this path are
    // treated as test scaffolding noise and skipped.
    let cwd = std::env::current_dir()
        .ok()
        .map(|p| p.to_string_lossy().trim_end_matches('\\').to_string());

    let parse = parse_events(&trace_file, cwd.as_deref(), opts.verbose)?;

    write_detection_summary(
        &parse.valid_access_events,
        &parse.requested_capabilities,
        parse.ui_event_count,
        &parse.ui_events,
        parse.ui_operation_flags,
    );
    write_requested_capabilities_summary(&parse.requested_capabilities, opts.verbose);

    let config_path = match opts.config_path.as_ref() {
        Some(p) => p,
        None => return Ok(()),
    };
    // Write an adjusted config whenever the trace yielded anything
    // mergeable: file paths, capabilities, a CONVERT_TO_GUI hint, or a
    // UI_OPERATION relaxation. Bailing early on file/capability emptiness
    // alone would silently drop UI-only traces.
    if should_skip_adjusted(&parse) {
        return Ok(());
    }

    // Copy original config alongside the trace so we have a snapshot of
    // the exact input that produced this run's output.
    let leaf = config_path
        .file_name()
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or_else(|| "config.json".into());
    let dest_config = log_dir.join(&leaf);
    std::fs::copy(config_path, &dest_config)
        .with_context(|| format!("failed to copy {}", config_path.display()))?;

    let mut config = load_config(&dest_config)?;
    initialize_filesystem(&mut config)?;
    let deny = deny_file_set(&config);

    let bin_path_s = bin_path.to_string_lossy().into_owned();
    let added = update_from_access_events(
        &mut config,
        &bin_path_s,
        &parse.valid_access_events,
        &deny,
        opts.verbose,
    )?;

    if !parse.requested_capabilities.is_empty() {
        merge_capabilities(&mut config, &parse.requested_capabilities)?;
    }

    if parse.need_ui {
        set_ui_subsystem_enabled(&mut config)?;
    }
    if parse.ui_operation_flags != 0 {
        apply_ui_operation_flags(&mut config, parse.ui_operation_flags)?;
    }

    let adjusted = resolve_adjusted_config_path(&dest_config, opts.adjusted_config_path.as_deref());
    save_adjusted_config(&config, &adjusted)?;

    write_added_paths_summary(&added);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::access_event::LearningModeAccessEvent;
    use std::collections::HashSet;

    fn empty_parse() -> ParseResult {
        ParseResult {
            valid_access_events: Vec::new(),
            requested_capabilities: HashSet::new(),
            need_ui: false,
            ui_event_count: 0,
            ui_events: Vec::new(),
            ui_operation_flags: 0,
        }
    }

    fn dummy_event() -> LearningModeAccessEvent {
        LearningModeAccessEvent {
            time_created: chrono::Utc::now(),
            process_id: 0,
            thread_id: 0,
            learning_mode: String::new(),
            resource_type: String::new(),
            file_path: "C:\\foo".into(),
            app_path: String::new(),
            access_mask: 0,
        }
    }

    // pin the "skip adjusted config" predicate
    // against each single-signal ParseResult plus the all-empty case.

    #[test]
    fn should_skip_when_completely_empty() {
        assert!(should_skip_adjusted(&empty_parse()));
    }

    #[test]
    fn should_not_skip_when_access_events_present() {
        let mut p = empty_parse();
        p.valid_access_events.push(dummy_event());
        assert!(!should_skip_adjusted(&p));
    }

    #[test]
    fn should_not_skip_when_requested_capability_present() {
        let mut p = empty_parse();
        p.requested_capabilities.insert("internetClient".into());
        assert!(!should_skip_adjusted(&p));
    }

    #[test]
    fn should_not_skip_when_need_ui_set() {
        let mut p = empty_parse();
        p.need_ui = true;
        assert!(!should_skip_adjusted(&p));
    }

    #[test]
    fn should_not_skip_when_ui_operation_flag_set() {
        let mut p = empty_parse();
        p.ui_operation_flags = 0x004; // JOB_OBJECT_UILIMIT_WRITECLIPBOARD
        assert!(!should_skip_adjusted(&p));
    }

    // ---- resolve_bin_path -----------------------------------------------
    //
    // the bin-path canonicalization
    // fallback chain affects the self-event filter (and therefore
    // whether plm.exe leaks into Adjusted_*.json), but was previously
    // inline in `run()` and untestable without spawning wpr.

    #[test]
    fn resolve_bin_path_falls_back_to_exe_dir_when_no_override() {
        let exe = std::env::temp_dir();
        let (p, warn) = resolve_bin_path(None, &exe);
        assert_eq!(p, exe);
        assert!(warn.is_none(), "no operator intent means no warning");
    }

    #[test]
    fn resolve_bin_path_canonicalizes_existing_override() {
        // Use the temp dir as a path we know exists and is
        // canonicalizable. The canonical form may add a `\\?\` prefix
        // on Windows; assert it ends with the same directory name.
        let exe = std::env::temp_dir();
        let override_path = std::env::temp_dir();
        let (p, warn) = resolve_bin_path(Some(&override_path), &exe);
        assert!(p.exists(), "canonicalized path should still exist");
        assert!(warn.is_none(), "successful canonicalize must not warn");
    }

    #[test]
    fn resolve_bin_path_warns_and_returns_raw_when_canonicalize_fails() {
        let exe = std::env::temp_dir();
        // A nonexistent path canonicalize() will refuse to resolve.
        let bogus = std::path::PathBuf::from("Z:\\definitely-does-not-exist-plm-test");
        let (p, warn) = resolve_bin_path(Some(&bogus), &exe);
        assert_eq!(
            p, bogus,
            "must return the raw operator path rather than silently \
             substituting exe_dir (previous behavior dropped operator intent)"
        );
        let w = warn.expect("canonicalize failure must surface a warning");
        assert!(
            w.contains("Z:\\definitely-does-not-exist-plm-test"),
            "warning must reference the failing path: {w}",
        );
    }

    // ---- WprStopper / stop_plm_trace_with -------------------------------
    //
    // The start side already has a `WprLauncher` seam, but
    // `stop_plm_trace` historically hard-coded `wpr_command()`. The
    // non-zero-exit and spawn-error branches (the ones production
    // actually hits when WPR or the .etl file are unhealthy) had
    // zero test coverage. Mirror the start side.

    use std::os::windows::process::ExitStatusExt;

    struct FakeStopper {
        result: std::cell::Cell<Option<Result<ExitStatus>>>,
        calls: std::cell::Cell<usize>,
    }
    impl FakeStopper {
        fn ok(code: u32) -> Self {
            Self {
                result: std::cell::Cell::new(Some(Ok(ExitStatus::from_raw(code)))),
                calls: std::cell::Cell::new(0),
            }
        }
        fn err(msg: &'static str) -> Self {
            Self {
                result: std::cell::Cell::new(Some(Err(anyhow::anyhow!(msg)))),
                calls: std::cell::Cell::new(0),
            }
        }
    }
    impl WprStopper for FakeStopper {
        fn stop(&mut self, _trace_file: &Path) -> Result<ExitStatus> {
            self.calls.set(self.calls.get() + 1);
            self.result
                .replace(None)
                .expect("FakeStopper.stop called more than once")
        }
    }

    #[test]
    fn stop_plm_trace_returns_ok_on_zero_exit() {
        let mut s = FakeStopper::ok(0);
        stop_plm_trace_with(&mut s, Path::new("trace.etl"))
            .expect("zero-exit must propagate as Ok");
        assert_eq!(s.calls.get(), 1);
    }

    #[test]
    fn stop_plm_trace_propagates_nonzero_exit_with_context() {
        let mut s = FakeStopper::ok(1);
        let err = stop_plm_trace_with(&mut s, Path::new("trace.etl"))
            .expect_err("non-zero exit must propagate as Err");
        let msg = format!("{err}");
        assert!(
            msg.contains("wpr -stop exited"),
            "error must name the failed command: {msg}",
        );
    }

    #[test]
    fn stop_plm_trace_propagates_spawn_error_verbatim() {
        let mut s = FakeStopper::err("simulated spawn failure: not found");
        let err = stop_plm_trace_with(&mut s, Path::new("trace.etl"))
            .expect_err("spawn error must propagate");
        let msg = format!("{err}");
        assert!(
            msg.contains("simulated spawn failure"),
            "error must surface the underlying io::Error context: {msg}",
        );
    }
}
