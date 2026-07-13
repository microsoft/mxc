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
use std::io::{self, BufRead, Write};
use std::path::{Path, PathBuf};

use crate::coordination::PLM_LOG_START_IN_FLIGHT;
use crate::start;
use crate::wpr_path::wpr_command;
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

fn stop_wpr_trace(trace_file: &Path) -> Result<()> {
    // Capture stdio rather than inheriting so `wpr -stop`'s progress
    // bar (`100% [>>>>>>>>>]`) and other chatter don't leak into any
    // wrapping tool's stdout. On non-zero exit we replay the captured
    // streams via the shared `replay_wpr_output` helper so operators
    // can still see wpr's own diagnostic.
    let output = wpr_command()
        .args(["-stop", &trace_file.to_string_lossy()])
        .output()
        .context("failed to spawn wpr -stop")?;
    if !output.status.success() {
        crate::start::replay_wpr_output("stop", &output);
        anyhow::bail!("wpr -stop exited with {}", output.status);
    }
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
    stop_wpr_trace(&trace_file)?;
    // Kernel session is torn down; safe to clear the active flag so
    // any subsequent Ctrl+C doesn't issue a stale `wpr -cancel`.
    on_trace_stopped();

    println!("Trace captured at {}.", trace_file.display());
    if verbose {
        println!("verbose logging requested.");
    }
    Ok(())
}
