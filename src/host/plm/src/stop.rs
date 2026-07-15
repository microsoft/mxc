// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! `plm stop` — stop the in-progress WPR trace and write `trace.etl`
//! into a log directory.

use anyhow::{Context, Result};
use chrono::Local;
use std::path::{Path, PathBuf};
use std::process::ExitStatus;

use crate::config::{
    deny_file_set, initialize_filesystem, load_config, update_from_access_events,
    write_added_paths_summary,
};
use crate::event_parser::parse_events;
use crate::wpr_path::wpr_command;

pub struct StopOptions {
    pub log_dir: Option<PathBuf>,
    pub bin_path: Option<PathBuf>,
    pub config_path: Option<PathBuf>,
    pub adjusted_config_path: Option<PathBuf>,
    /// When set, skip `wpr -stop` and treat the supplied .etl as the
    /// captured trace. Useful for re-processing a previously captured
    /// trace without an active WPR session.
    pub trace_file: Option<PathBuf>,
    pub verbose: bool,
}

/// Abstraction over `wpr -stop` invocations so the failure-mapping
/// state machine in `stop_plm_trace_with` is testable without
/// actually spawning processes. Mirrors `start::WprLauncher`.
pub trait WprStopper {
    fn stop(&mut self, trace_file: &Path) -> Result<ExitStatus>;
}

pub struct WprExeStopper;

impl WprStopper for WprExeStopper {
    fn stop(&mut self, trace_file: &Path) -> Result<ExitStatus> {
        let mut cmd = wpr_command();
        let resolved = cmd.get_program().to_string_lossy().into_owned();
        cmd.arg("-stop")
            .arg(trace_file)
            .status()
            .map_err(|e| anyhow::anyhow!("failed to spawn wpr -stop ({resolved}): {e}"))
    }
}

/// Testable wrapper for `wpr -stop` status handling.
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

/// Resolve `--bin-path` (or fall back to the calling exe directory)
/// to its canonical form. Consumed by `update_from_access_events` as
/// the self-access filter: events referencing this path are dropped
/// from the adjusted config so the container never grants itself
/// broad access to its own binary directory.
///
/// Fallback chain:
///   1. `canonicalize(opt.bin_path)` if `Some`
///   2. raw `opt.bin_path` if `Some` (with a warning)
///   3. `exe_dir` (no warning)
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
            // substituting exe_dir; that would drop operator intent.
            (raw.to_path_buf(), Some(warning))
        }
    }
}

pub fn run(opts: StopOptions, exe_dir: &Path) -> Result<()> {
    // $LogDir defaults to "<exe dir>\logs\<timestamp>_pid<PID>".
    // Including PID + sub-second component avoids collisions when
    // parallel PLM tasks finish in the same second.
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

    let config_path = match opts.config_path.as_ref() {
        Some(p) => p,
        None => return Ok(()),
    };

    // Load the source config into memory FIRST, before any disk
    // side effect touches the log directory. If the source is
    // unreadable or malformed we want to bail before we've
    // produced a half-populated log_dir (bare trace.etl + no
    // config, no adjusted).
    let base_config = load_config(config_path)?;

    // Copy the original config alongside the trace unconditionally
    // so operators always have a snapshot of the exact input that
    // produced this run's `trace.etl`, even when the parse yielded
    // nothing mergeable. The copy MUST land on disk before we
    // attempt any edit-and-save cycle below: it's the operator's
    // only record of the pre-edit state, and losing it turns an
    // Adjusted_*.json into an un-auditable delta.
    let leaf = config_path
        .file_name()
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or_else(|| "config.json".into());
    let dest_config = log_dir.join(&leaf);
    std::fs::copy(config_path, &dest_config)
        .with_context(|| format!("failed to copy {}", config_path.display()))?;

    if parse.is_empty() {
        // Nothing mergeable -- skip producing an Adjusted_*.json (which
        // would be byte-identical to the input and confuse the harness's
        // diff-based pass/fail signal).
        return Ok(());
    }

    // Edit the pre-loaded copy of the config in memory rather than
    // re-reading `dest_config` — this avoids a read-after-write on
    // Windows where an AV filter can occasionally serve a stale or
    // empty buffer for a file that `std::fs::copy` just wrote.
    let mut config = base_config;
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

    write_added_paths_summary(&added, opts.verbose);

    // `adjusted_config_path` is accepted today so the wxc-exec --audit
    // harness can pass it through; the Adjusted_*.json writer arrives
    // in the next PR (config-generation).
    if let Some(p) = opts.adjusted_config_path.as_ref() {
        let _ = p;
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    // ---- resolve_bin_path -----------------------------------------------

    #[test]
    fn resolve_bin_path_falls_back_to_exe_dir_when_no_override() {
        let exe = std::env::temp_dir();
        let (p, warn) = resolve_bin_path(None, &exe);
        assert_eq!(p, exe);
        assert!(warn.is_none(), "no operator intent means no warning");
    }

    #[test]
    fn resolve_bin_path_canonicalizes_existing_override() {
        let exe = std::env::temp_dir();
        let override_path = std::env::temp_dir();
        let (p, warn) = resolve_bin_path(Some(&override_path), &exe);
        assert!(p.exists(), "canonicalized path should still exist");
        assert!(warn.is_none(), "successful canonicalize must not warn");
    }

    #[test]
    fn resolve_bin_path_warns_and_returns_raw_when_canonicalize_fails() {
        let exe = std::env::temp_dir();
        let bogus = std::path::PathBuf::from("Z:\\definitely-does-not-exist-plm-test");
        let (p, warn) = resolve_bin_path(Some(&bogus), &exe);
        assert_eq!(
            p, bogus,
            "must return the raw operator path rather than silently \
             substituting exe_dir (would drop operator intent)"
        );
        let w = warn.expect("canonicalize failure must surface a warning");
        assert!(
            w.contains("Z:\\definitely-does-not-exist-plm-test"),
            "warning must reference the failing path: {w}",
        );
    }

    // ---- WprStopper / stop_plm_trace_with -------------------------------

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
