//! Port of `stop_plm_logging.ps1`.
//!
//! Stops the in-progress WPR trace, parses the .etl, and (optionally)
//! merges the discovered file-access paths and capability requests into
//! an MXC container config, writing an `Adjusted_*.json` next to it.

use anyhow::{Context, Result};
use chrono::Local;
use std::path::{Path, PathBuf};
use std::process::Command;

use crate::config::{
    apply_ui_operation_flags, deny_file_set, initialize_filesystem, load_config,
    merge_capabilities, resolve_adjusted_config_path, save_adjusted_config,
    set_ui_subsystem_enabled, update_from_access_events, write_added_paths_summary,
    write_detection_summary, write_requested_capabilities_summary,
};
use crate::event_parser::parse_events;

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
    let status = Command::new("wpr")
        .args(["-stop", &trace_file.to_string_lossy()])
        .status()
        .context("failed to spawn wpr -stop")?;
    if !status.success() {
        anyhow::bail!("wpr -stop exited with {status}");
    }
    Ok(())
}

pub fn run(opts: StopOptions, exe_dir: &Path) -> Result<()> {
    // $LogDir defaults to "<exe dir>\logs\<timestamp>".
    let log_dir = opts.log_dir.unwrap_or_else(|| {
        exe_dir
            .join("logs")
            .join(Local::now().format("%Y-%m-%d_%H%M%S").to_string())
    });
    std::fs::create_dir_all(&log_dir)
        .with_context(|| format!("failed to create log dir {}", log_dir.display()))?;

    let bin_path: PathBuf = opts
        .bin_path
        .unwrap_or_else(|| exe_dir.to_path_buf())
        .canonicalize()
        .unwrap_or_else(|_| exe_dir.to_path_buf());

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
    if parse.valid_access_events.is_empty()
        && parse.requested_capabilities.is_empty()
        && !parse.need_ui
        && parse.ui_operation_flags == 0
    {
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
