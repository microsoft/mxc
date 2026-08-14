// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Interactive "logging" mode.
//!
//! 1. Prompts the user to press Enter to start logging.
//! 2. Starts a WPR trace (same `AccessFailureProfile` used by `start`).
//! 3. Prompts the user to press Enter to stop logging.
//! 4. Stops the trace into a temp .etl and reports where it landed.

use anyhow::{Context, Result};
use learning_mode_core::AnalysisResult;
use serde_json::{json, Value};
use std::io::{self, BufRead, Write};

use crate::analysis::{legacy_config_inputs, write_detection_summary};
use crate::config::{
    deny_file_set, initialize_filesystem, update_from_access_events, write_added_paths_summary,
};
use crate::elevated;

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

fn can_generate_policy_preview(analysis: &AnalysisResult) -> bool {
    !analysis.denied_resources_truncated
}

pub fn run(owner_pid: u32, verbose: bool, on_trace_started: impl FnOnce()) -> Result<()> {
    prompt_enter("Press Enter to start logging...")?;
    elevated::invoke_guarded_start(owner_pid)?;
    // `wpr -start` has engaged the kernel session. Only NOW mark the
    // trace active so a stdin-EOF / spawn-fail before this point can't
    // trip the Ctrl+C handler into `wpr -cancel`ing an unrelated host
    // WPR session.
    on_trace_started();
    println!("Logging started.");

    prompt_enter("Press Enter to stop logging...")?;

    if verbose {
        println!("Beginning event parsing, this may take several minutes");
    }
    let analysis = elevated::stop_current_guarded_start()?;
    write_detection_summary(&analysis);
    if !can_generate_policy_preview(&analysis) {
        eprintln!(
            "[plm] warning: denial analysis was truncated; skipping blank-config preview \
             because the learned policy would be incomplete"
        );
        return Ok(());
    }
    let current_directory = std::env::current_dir()
        .ok()
        .map(|path| path.to_string_lossy().into_owned());
    let (valid_access_events, _) =
        legacy_config_inputs(&analysis.denials, current_directory.as_deref());

    // Synthesize a blank config and run the FS merge to preview what a
    // policy authored from scratch would receive. Capability and UI
    // merging arrive in later PRs.
    let mut blank: Value = json!({});
    initialize_filesystem(&mut blank)?;
    let deny = deny_file_set(&blank);

    // For a blank config there is no app binary to skip -- pass a path
    // that will never match a real event's file path.
    let bin_path = String::from("\\\\plm-blank-config-bin-sentinel");

    let added =
        update_from_access_events(&mut blank, &bin_path, &valid_access_events, &deny, verbose)?;

    write_added_paths_summary(&added, verbose);

    println!();
    println!("Blank config after merge:");
    println!("{}", serde_json::to_string_pretty(&blank)?);

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::can_generate_policy_preview;
    use learning_mode_core::AnalysisResult;

    #[test]
    fn truncated_analysis_cannot_generate_policy_preview() {
        assert!(!can_generate_policy_preview(&AnalysisResult {
            denials: Vec::new(),
            denied_resources_truncated: true,
            data_loop: Default::default(),
        }));
    }
}
