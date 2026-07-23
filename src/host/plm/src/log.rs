//! Interactive "logging" mode.
//!
//! 1. Prompts the user to press Enter to start logging.
//! 2. Starts a WPR trace (same `AccessFailureProfile` used by `start`).
//! 3. Prompts the user to press Enter to stop logging.
//! 4. Stops the trace into a temp .etl, parses it, and prints the
//!    changes that *would* be merged into a blank (empty `{}`) config.
//!
//! The trace .etl file is cleaned up after parsing.

use anyhow::{Context, Result};
use chrono::Local;
use serde_json::{json, Value};
use std::io::{self, BufRead, Write};
use std::path::{Path, PathBuf};

use crate::config::{
    apply_ui_operation_flags, deny_file_set, initialize_filesystem, merge_capabilities,
    set_ui_subsystem_enabled, update_from_access_events, write_added_paths_summary,
    write_detection_summary, write_requested_capabilities_summary,
};
use crate::coordination::PLM_LOG_START_IN_FLIGHT;
use crate::event_parser::parse_events;
use crate::start;
use crate::stop::{stop_plm_trace_with, WprExeStopper};
use std::sync::atomic::Ordering;

fn prompt_enter(message: &str) -> Result<()> {
    print!("{message}");
    io::stdout().flush().ok();
    let stdin = io::stdin();
    let mut line = String::new();
    stdin
        .lock()
        .read_line(&mut line)
        .context("failed to read from stdin")?;
    Ok(())
}

pub fn run(
    wprp_path: &Path,
    verbose: bool,
    on_trace_started: impl FnOnce(),
    on_trace_stopped: impl FnOnce(),
) -> Result<()> {
    prompt_enter("Press Enter to start logging...")?;
    // Bracket the `wpr -start` spawn so the console-control handler
    // in `plm/src/main.rs` waits for it to drain before deciding
    // whether to issue `wpr -cancel`. Closes the same race the
    // wxc-exec side closes with `AUDIT_START_IN_FLIGHT`.
    PLM_LOG_START_IN_FLIGHT.store(true, Ordering::SeqCst);
    let start_result = start::start_plm_trace(wprp_path);
    PLM_LOG_START_IN_FLIGHT.store(false, Ordering::SeqCst);
    start_result?;
    // `wpr -start` has engaged the kernel session. Only NOW mark the
    // trace active so a stdin-EOF / spawn-fail before this point can't
    // trip the Ctrl+C handler into `wpr -cancel`ing an unrelated host
    // WPR session.
    on_trace_started();
    println!("Logging started.");

    prompt_enter("Press Enter to stop logging...")?;

    // Per-run trace file in temp; sub-second component prevents
    // parallel `plm log` invocations from colliding on the same .etl.
    let stamp = Local::now().format("%Y-%m-%d_%H%M%S%.3f").to_string();
    let trace_file: PathBuf = std::env::temp_dir().join(format!("plm_log_{stamp}.etl"));
    stop_plm_trace_with(&mut WprExeStopper, &trace_file)?;
    // Kernel session is torn down; safe to clear the active flag so
    // any subsequent Ctrl+C doesn't issue a stale `wpr -cancel`.
    on_trace_stopped();

    if verbose {
        println!("Beginning event parsing, this may take several minutes");
    }

    let cwd = std::env::current_dir()
        .ok()
        .map(|p| p.to_string_lossy().trim_end_matches('\\').to_string());
    let parse = parse_events(&trace_file, cwd.as_deref(), verbose);

    // Clean up the temp .etl regardless of parse outcome.
    let _ = std::fs::remove_file(&trace_file);

    let parse = parse?;

    write_detection_summary(
        &parse.valid_access_events,
        &parse.requested_capabilities,
        parse.ui_event_count,
        &parse.ui_events,
        parse.ui_operation_flags,
    );
    write_requested_capabilities_summary(&parse.requested_capabilities, verbose);

    // Synthesize a blank config and run the same merge logic the real
    // `stop` subcommand uses. We deliberately do not pass a containment
    // name -- a blank config has none, so `merge_capabilities` is a
    // no-op; instead, print the full requested-capabilities list below.
    let mut blank: Value = json!({});
    initialize_filesystem(&mut blank)?;
    let deny = deny_file_set(&blank);

    // For a blank config there is no app binary to skip -- pass a path
    // that will never match a real event's file path.
    let bin_path = String::from("\\\\plm-blank-config-bin-sentinel");

    let added = update_from_access_events(
        &mut blank,
        &bin_path,
        &parse.valid_access_events,
        &deny,
        verbose,
    )?;

    if parse.need_ui {
        set_ui_subsystem_enabled(&mut blank)?;
    }
    if parse.ui_operation_flags != 0 {
        apply_ui_operation_flags(&mut blank, parse.ui_operation_flags)?;
    }

    // `merge_capabilities` requires a `containment` name on the config,
    // which a blank config doesn't have. Print the full set of requested
    // capabilities here so the operator still sees what was discovered.
    if !parse.requested_capabilities.is_empty() {
        println!();
        println!(
            "Requested capabilities ({}):",
            parse.requested_capabilities.len()
        );
        let mut sorted: Vec<&String> = parse.requested_capabilities.iter().collect();
        sorted.sort();
        for c in sorted {
            println!("  + {c}");
        }
    } else {
        // Still call through so existing call-site stays exercised even
        // when the set is empty -- this is a no-op for a blank config.
        merge_capabilities(&mut blank, &parse.requested_capabilities)?;
    }

    write_added_paths_summary(&added, verbose);

    println!();
    println!("Blank config after merge:");
    println!("{}", serde_json::to_string_pretty(&blank)?);

    Ok(())
}
