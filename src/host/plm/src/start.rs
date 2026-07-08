// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! `plm start` — start a WPR trace using the `AccessFailureProfile`
//! defined in `profile_gen::EMBEDDED_WPRP` (materialized to disk next
//! to `plm.exe` by `profile_gen`). If a pre-existing WPR session
//! blocks our start, we cancel it and retry exactly once.

use anyhow::Result;
use std::path::Path;
use std::process::{ExitStatus, Stdio};

use crate::wpr_path::wpr_command;

/// Trait for testable `wpr.exe` start/cancel invocations. Tests
/// supply a fake that returns canned exit codes; production uses
/// `WprExe`.
pub trait WprLauncher {
    fn start(&mut self, profile_arg: &str) -> Result<ExitStatus>;
    fn cancel(&mut self);
}

pub struct WprExe;

impl WprLauncher for WprExe {
    fn start(&mut self, profile_arg: &str) -> Result<ExitStatus> {
        // Surface the resolved wpr.exe path in the spawn-failure
        // context so hosts missing the Windows Performance Toolkit
        // (e.g. stripped Server SKUs) get an actionable hint instead
        // of a bare `os error 2`.
        //
        // Capture wpr.exe's stdout/stderr rather than inheriting them
        // (via `.status()`) so a successful `wpr -start` doesn't
        // pollute the console of any wrapping tool (e.g. wxc-exec
        // --audit); on non-zero exit we replay the captured streams
        // so operators can still diagnose real failures.
        let cmd = wpr_command();
        let resolved = cmd.get_program().to_string_lossy().into_owned();
        let output = wpr_command()
            .args(["-start", profile_arg, "-filemode"])
            .output()
            .map_err(|e| describe_wpr_spawn_error("start", &resolved, e))?;
        if !output.status.success() {
            replay_wpr_output("start", &output);
        }
        Ok(output.status)
    }
    fn cancel(&mut self) {
        cancel_existing_wpr_trace();
    }
}

/// Wrap a `wpr.exe` spawn `io::Error` with the resolved absolute path
/// so failures are actionable (`wpr.exe not present at <path> —
/// install the Windows Performance Toolkit`).
fn describe_wpr_spawn_error(verb: &str, resolved: &str, e: std::io::Error) -> anyhow::Error {
    if e.kind() == std::io::ErrorKind::NotFound {
        anyhow::anyhow!(
            "failed to spawn wpr -{verb}: {e} (resolved path: {resolved}). \
             The Windows Performance Recorder (wpr.exe) is required for PLM \
             tracing; install the Windows Performance Toolkit (part of the \
             Windows ADK) and ensure {resolved} is present.",
        )
    } else {
        anyhow::anyhow!("failed to spawn wpr -{verb} ({resolved}): {e}",)
    }
}

/// Replay captured wpr.exe stdout/stderr to the caller's own streams.
/// Used only on failure paths — the happy path stays silent so PLM
/// can be embedded in wrappers (e.g. `wxc-exec --audit`) without
/// polluting their console.
pub(crate) fn replay_wpr_output(verb: &str, output: &std::process::Output) {
    use std::io::Write as _;
    if !output.stdout.is_empty() {
        let _ = std::io::stdout().write_all(&output.stdout);
    }
    if !output.stderr.is_empty() {
        let _ = std::io::stderr().write_all(&output.stderr);
    }
    eprintln!("[plm] wpr -{verb} exited with {}", output.status);
}

/// Cancel any pre-existing in-memory WPR session before starting a
/// new one. Returns non-zero when no session was active — we ignore
/// the exit code and silence output.
///
/// Only one NT Kernel Logger session can exist host-wide, so this
/// necessarily terminates any concurrent recording (PLM's previous
/// run or an unrelated tool); we log a warning to stderr.
///
/// We deliberately do NOT gate this on `wpr -status` — its English-
/// only stdout match breaks on every localized Windows install.
/// Cancel is invoked only on the retry path after `wpr -start`
/// itself reports a conflict (locale-invariant).
pub fn cancel_existing_wpr_trace() {
    eprintln!(
        "[plm] cancelling pre-existing WPR session via `wpr -cancel`; \
         any concurrent non-PLM WPR recording on this host has just been terminated. \
         (Only one NT Kernel Logger session can exist at a time.)"
    );
    let _ = wpr_command()
        .arg("-cancel")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status();
}

/// Core try-then-cancel-then-retry state machine, parameterised on a
/// `WprLauncher` so tests can drive the conflict + retry branches
/// deterministically.
pub fn start_plm_trace_with<L: WprLauncher>(launcher: &mut L, wprp_path: &Path) -> Result<()> {
    let arg = format!("{}!AccessFailureProfile", wprp_path.display());
    let first = launcher.start(&arg)?;
    if first.success() {
        return Ok(());
    }
    launcher.cancel();
    let second = launcher.start(&arg)?;
    if !second.success() {
        anyhow::bail!(
            "wpr -start exited with {second} (also failed after retry following wpr -cancel)"
        );
    }
    Ok(())
}

pub fn start_plm_trace(wprp_path: &Path) -> Result<()> {
    start_plm_trace_with(&mut WprExe, wprp_path)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::windows::process::ExitStatusExt;
    use std::path::PathBuf;

    struct FakeLauncher {
        starts: Vec<ExitStatus>,
        idx: usize,
        cancels: usize,
    }
    impl FakeLauncher {
        fn new(codes: &[u32]) -> Self {
            Self {
                starts: codes.iter().map(|c| ExitStatus::from_raw(*c)).collect(),
                idx: 0,
                cancels: 0,
            }
        }
    }
    impl WprLauncher for FakeLauncher {
        fn start(&mut self, _arg: &str) -> Result<ExitStatus> {
            let s = self.starts[self.idx];
            self.idx += 1;
            Ok(s)
        }
        fn cancel(&mut self) {
            self.cancels += 1;
        }
    }

    #[test]
    fn start_plm_trace_first_attempt_success_does_not_cancel() {
        let mut f = FakeLauncher::new(&[0]);
        start_plm_trace_with(&mut f, &PathBuf::from("plm.wprp")).unwrap();
        assert_eq!(f.idx, 1);
        assert_eq!(f.cancels, 0);
    }

    #[test]
    fn start_plm_trace_retries_once_after_conflict() {
        // First attempt fails (non-zero), cancel runs, second succeeds.
        let mut f = FakeLauncher::new(&[1, 0]);
        start_plm_trace_with(&mut f, &PathBuf::from("plm.wprp")).unwrap();
        assert_eq!(f.idx, 2);
        assert_eq!(f.cancels, 1);
    }

    #[test]
    fn start_plm_trace_propagates_when_retry_also_fails() {
        let mut f = FakeLauncher::new(&[1, 1]);
        let err = start_plm_trace_with(&mut f, &PathBuf::from("plm.wprp")).unwrap_err();
        assert!(format!("{err}").contains("failed after retry"));
        assert_eq!(f.idx, 2);
        assert_eq!(f.cancels, 1);
    }

    /// when wpr.exe isn't on the system
    /// (e.g. Server SKU without WPT), the spawn-failure context must
    /// surface the resolved path AND nudge the operator toward
    /// installing the Windows Performance Toolkit. Asserting against
    /// a real spawn isn't deterministic on CI, so drive the formatter
    /// directly with a synthesized NotFound `io::Error`.
    #[test]
    fn wpr_spawn_not_found_error_is_actionable() {
        let err = describe_wpr_spawn_error(
            "start",
            "C:\\Windows\\System32\\wpr.exe",
            std::io::Error::new(std::io::ErrorKind::NotFound, "the system cannot find"),
        );
        let s = format!("{err}");
        assert!(
            s.contains("C:\\Windows\\System32\\wpr.exe"),
            "error must surface resolved wpr path: {s}",
        );
        assert!(
            s.contains("Windows Performance Toolkit") || s.contains("Windows ADK"),
            "error must hint at WPT install: {s}",
        );
    }

    #[test]
    fn wpr_spawn_other_error_keeps_path_in_context() {
        let err = describe_wpr_spawn_error(
            "stop",
            "C:\\Windows\\System32\\wpr.exe",
            std::io::Error::new(std::io::ErrorKind::PermissionDenied, "access denied"),
        );
        let s = format!("{err}");
        assert!(s.contains("C:\\Windows\\System32\\wpr.exe"), "got: {s}");
        assert!(s.contains("stop"), "verb must appear: {s}");
    }

    /// Pin that the embedded WPR profile (`profile_gen::EMBEDDED_WPRP`)
    /// is well-formed XML and still declares the `AccessFailureProfile`
    /// recording referenced by `start_plm_trace_with`. The profile is
    /// no longer a separate file — it lives as a raw string in
    /// `profile_gen.rs` — so this test is the only schema gate.
    #[test]
    fn plm_wprp_resource_is_well_formed_and_declares_access_failure_profile() {
        let wprp = crate::profile_gen::EMBEDDED_WPRP;
        let doc =
            roxmltree::Document::parse(wprp).expect("EMBEDDED_WPRP must parse as well-formed XML");

        // The recording name must stay `AccessFailureProfile` —
        // `start_plm_trace_with` builds `<wprp_path>!AccessFailureProfile`.
        let has_profile = doc
            .descendants()
            .filter(|n| n.has_tag_name("Profile"))
            .any(|n| n.attribute("Name") == Some("AccessFailureProfile"));
        assert!(
            has_profile,
            "EMBEDDED_WPRP must declare a <Profile Name=\"AccessFailureProfile\"> \
             element — the runtime hard-codes this name in start_plm_trace",
        );

        // The harness depends on the Privacy-Auditing-PLM event
        // provider for its event-id=14 / event-id=27 detection paths.
        // Sanity-check that the profile still references it; dropping
        // it (by name OR GUID) silently disables every meaningful
        // detection.
        let mentions_plm_provider = wprp
            .contains("Microsoft-Windows-Privacy-Auditing-PermissiveLearningMode")
            || wprp.contains("811a1ddb-2e69-5f25-adc0-4b186170e760");
        assert!(
            mentions_plm_provider,
            "EMBEDDED_WPRP must enable the Microsoft-Windows-Privacy-Auditing-PermissiveLearningMode \
             provider (GUID 811a1ddb-2e69-5f25-adc0-4b186170e760); without it the \
             event-id=14/27 detection pipeline has nothing to consume",
        );

        // The profile also wires the kernel collector for process/loader
        // events the parser uses to attribute access failures to a
        // specific application binary. Verify the collector reference
        // still exists.
        let has_kernel_collector = doc
            .descendants()
            .filter(|n| n.has_tag_name("SystemCollector"))
            .any(|n| n.attribute("Id") == Some("SC_Kernel"));
        assert!(
            has_kernel_collector,
            "EMBEDDED_WPRP must declare the SC_Kernel SystemCollector that the \
             AccessFailureProfile recording references",
        );
    }
}
