// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! `plm stop` — stop the in-progress WPR trace and write `trace.etl`
//! into a log directory.

use anyhow::{Context, Result};
use chrono::Local;
use std::path::{Path, PathBuf};
use std::process::ExitStatus;

use crate::wpr_path::wpr_command;

pub struct StopOptions {
    pub log_dir: Option<PathBuf>,
    pub config_path: Option<PathBuf>,
    /// When set, skip `wpr -stop` and treat the supplied .etl as the
    /// captured trace. Useful for re-processing a previously captured
    /// trace without an active WPR session.
    pub trace_file: Option<PathBuf>,
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
        // Capture stdio rather than inheriting so a successful `wpr
        // -stop` doesn't leak wpr chatter into any wrapping tool (e.g.
        // `wxc-exec --audit`). On non-zero exit we replay the captured
        // streams so operators can still see wpr's own diagnostic.
        let mut cmd = wpr_command();
        let resolved = cmd.get_program().to_string_lossy().into_owned();
        let output = cmd
            .args(["-stop", &trace_file.to_string_lossy()])
            .output()
            .map_err(|e| anyhow::anyhow!("failed to spawn wpr -stop ({resolved}): {e}"))?;
        if !output.status.success() {
            crate::start::replay_wpr_output("stop", &output);
        }
        Ok(output.status)
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

pub fn run(opts: StopOptions, exe_dir: &Path) -> Result<()> {
    // $LogDir defaults to "<exe dir>\logs\<timestamp>". The sub-second
    // component makes parallel PLM runs finishing in the same second
    // land in distinct directories.
    let log_dir = opts.log_dir.unwrap_or_else(|| {
        let stamp = Local::now().format("%Y-%m-%d_%H%M%S%.3f").to_string();
        exe_dir.join("logs").join(stamp)
    });
    std::fs::create_dir_all(&log_dir)
        .with_context(|| format!("failed to create log dir {}", log_dir.display()))?;

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

    println!("Trace captured at {}.", trace_file.display());

    // `config_path` is accepted today so the wxc-exec --audit harness
    // can pass it through; the merge that consumes it arrives in the
    // filesystem-extraction PR.
    if let Some(p) = opts.config_path.as_ref() {
        let _ = p;
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

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
