// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Interactive "logging" mode.
//!
//! 1. Prompts the user to press Enter to start logging.
//! 2. Starts a WPR trace (same `AccessFailureProfile` used by `start`).
//! 3. Prompts the user to press Enter to stop logging.
//! 4. Stops the trace into a temp .etl and reports where it landed.

use anyhow::{Context, Result};
use chrono::Local;
use serde_json::{json, Value};
use std::io::{self, BufRead, Write};
use std::path::{Path, PathBuf};

use crate::config::{
    deny_file_set, initialize_filesystem, update_from_access_events, write_added_paths_summary,
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

    // Per-run trace file in temp; PID + sub-second component prevents
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

    // Synthesize a blank config and run the FS merge to preview what a
    // policy authored from scratch would receive. Capability and UI
    // merging arrive in later PRs.
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

    write_added_paths_summary(&added);

    println!();
    println!("Blank config after merge:");
    println!("{}", serde_json::to_string_pretty(&blank)?);

    Ok(())
}
