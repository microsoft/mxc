//! Port of `stop_plm_logging.ps1`.
//!
//! Stops the in-progress WPR trace, parses the .etl, and (optionally)
//! merges the discovered file-access paths and capability requests into
//! an MXC container config, writing an `Adjusted_*.json` next to it.

use anyhow::{Context, Result};
use chrono::Local;
use std::path::{Path, PathBuf};

use crate::config::{
    apply_ui_operation_flags, deny_file_set, initialize_filesystem, load_config,
    merge_capabilities, resolve_adjusted_config_path, save_adjusted_config,
    set_ui_subsystem_enabled, update_from_access_events, write_added_paths_summary,
    write_detection_summary, write_requested_capabilities_summary,
};
use crate::event_parser::{parse_events, ParseResult};
use crate::wpr_path::wpr_command;

/// Round-4 finding V: the "skip adjusted config" predicate extracted
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

fn stop_plm_trace(trace_file: &Path) -> Result<()> {
    let status = wpr_command()
        .args(["-stop", &trace_file.to_string_lossy()])
        .status()
        .context("failed to spawn wpr -stop")?;
    if !status.success() {
        anyhow::bail!("wpr -stop exited with {status}");
    }
    Ok(())
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
    // verbatim-prefixed paths ETW emits. Round-3 review flagged the
    // previous silent `unwrap_or_else(|_| exe_dir.to_path_buf())` —
    // when an operator-supplied --bin-path failed to canonicalize the
    // PLM exe's own directory got substituted, breaking self-filter
    // and leaking the binary into the adjusted config with no warning.
    //
    // The fallback chain now (in order): canonical(--bin-path) →
    // raw --bin-path → canonical(exe_dir) → exe_dir. Each step emits
    // a stderr warning when it diverges from the operator's intent.
    let bin_path_raw = opts
        .bin_path
        .clone()
        .unwrap_or_else(|| exe_dir.to_path_buf());
    let bin_path: PathBuf = match bin_path_raw.canonicalize() {
        Ok(p) => p,
        Err(e) => {
            eprintln!(
                "[plm] warning: could not canonicalize --bin-path {} ({}); \
                 self-access filter will use the raw path. Events referencing \
                 the binary via a different spelling (e.g. verbatim \\\\?\\) \
                 may leak into the adjusted config.",
                bin_path_raw.display(),
                e
            );
            // Prefer the raw operator-supplied path over silently
            // substituting exe_dir; only fall back to exe_dir when the
            // operator gave us no bin_path at all.
            opts.bin_path
                .clone()
                .unwrap_or_else(|| exe_dir.to_path_buf())
        }
    };

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

    // Round-4 finding V: pin the "skip adjusted config" predicate
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
}
