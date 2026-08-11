// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Fixed WPR start/cancel operations used only by the restricted elevated
//! child. The profile path passed here is always an elevated-created temporary
//! file containing `profile_gen::EMBEDDED_WPRP`. Start never cancels a
//! pre-existing host trace; a conflict fails closed so PLM cannot tear down a
//! peer recording.

use anyhow::Result;
use std::path::Path;
use std::process::ExitStatus;

use crate::wpr_path::wpr_command;

/// Trait for testable `wpr.exe` start/cancel invocations. Tests
/// supply a fake that returns canned exit codes; production uses
/// `WprExe`.
pub trait WprLauncher {
    fn start(&mut self, profile_arg: &str) -> Result<ExitStatus>;
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
        let mut cmd = wpr_command();
        let resolved = cmd.get_program().to_string_lossy().into_owned();
        let output = cmd
            .args(["-start", profile_arg, "-filemode"])
            .output()
            .map_err(|e| describe_wpr_spawn_error("start", &resolved, e))?;
        if !output.status.success() {
            return Err(describe_wpr_failure("start", &output));
        }
        Ok(output.status)
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

pub(crate) fn describe_wpr_failure(verb: &str, output: &std::process::Output) -> anyhow::Error {
    anyhow::anyhow!(
        "wpr -{verb} exited with {} (stdout: {}; stderr: {})",
        output.status,
        String::from_utf8_lossy(&output.stdout).trim(),
        String::from_utf8_lossy(&output.stderr).trim()
    )
}

fn describe_wpr_output_result(verb: &str, output: std::process::Output) -> Result<()> {
    if output.status.success() {
        Ok(())
    } else {
        Err(describe_wpr_failure(verb, &output))
    }
}

/// Cancel any pre-existing in-memory WPR session before starting a
/// new one. No-active-session and other non-zero exits are returned
/// as errors so callers can decide whether to ignore them.
///
/// Only one NT Kernel Logger session can exist host-wide, so this
/// necessarily terminates any concurrent recording (PLM's previous
/// run or an unrelated tool); we log a warning to stderr.
///
/// We deliberately do NOT gate this on `wpr -status` — its English-
/// only stdout match breaks on every localized Windows install.
/// Cancel is invoked only on the retry path after `wpr -start`
/// itself reports a conflict (locale-invariant).
pub fn cancel_existing_wpr_trace() -> Result<()> {
    eprintln!(
        "[plm] cancelling pre-existing WPR session via `wpr -cancel`; \
         any concurrent non-PLM WPR recording on this host has just been terminated. \
         (Only one NT Kernel Logger session can exist at a time.)"
    );
    let mut cmd = wpr_command();
    let resolved = cmd.get_program().to_string_lossy().into_owned();
    let output = cmd
        .arg("-cancel")
        .output()
        .map_err(|e| describe_wpr_spawn_error("cancel", &resolved, e))?;
    describe_wpr_output_result("cancel", output)
}

/// Start state machine parameterized on a `WprLauncher` for tests.
///
/// A non-zero result is returned directly. Automatically issuing `wpr
/// -cancel` here could destroy an unrelated host recording, so cancellation is
/// reserved for cleanup paths that already own the PLM singleton.
pub fn start_plm_trace_with<L: WprLauncher>(launcher: &mut L, wprp_path: &Path) -> Result<()> {
    let arg = format!("{}!AccessFailureProfile", wprp_path.display());
    let status = launcher.start(&arg)?;
    if !status.success() {
        anyhow::bail!(
            "wpr -start exited with {status}; refusing to cancel a pre-existing host WPR session"
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
    }
    impl FakeLauncher {
        fn new(codes: &[u32]) -> Self {
            Self {
                starts: codes.iter().map(|c| ExitStatus::from_raw(*c)).collect(),
                idx: 0,
            }
        }
    }
    impl WprLauncher for FakeLauncher {
        fn start(&mut self, _arg: &str) -> Result<ExitStatus> {
            let s = self.starts[self.idx];
            self.idx += 1;
            Ok(s)
        }
    }

    #[test]
    fn start_plm_trace_succeeds_on_zero_exit() {
        let mut f = FakeLauncher::new(&[0]);
        start_plm_trace_with(&mut f, &PathBuf::from("plm.wprp")).unwrap();
        assert_eq!(f.idx, 1);
    }

    #[test]
    fn start_plm_trace_fails_without_cancelling_or_retrying() {
        let mut f = FakeLauncher::new(&[1]);
        let err = start_plm_trace_with(&mut f, &PathBuf::from("plm.wprp")).unwrap_err();
        assert!(format!("{err}").contains("refusing to cancel"));
        assert_eq!(f.idx, 1);
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

    #[test]
    fn wpr_failure_includes_captured_diagnostics_for_pipe_transport() {
        let output = std::process::Output {
            status: ExitStatus::from_raw(1),
            stdout: b"start diagnostic".to_vec(),
            stderr: b"access denied".to_vec(),
        };
        let error = describe_wpr_failure("start", &output).to_string();
        assert!(error.contains("start diagnostic"));
        assert!(error.contains("access denied"));
    }

    fn output_with_status(status: u32, stdout: &[u8], stderr: &[u8]) -> std::process::Output {
        std::process::Output {
            status: ExitStatus::from_raw(status),
            stdout: stdout.to_vec(),
            stderr: stderr.to_vec(),
        }
    }

    #[test]
    fn cancel_existing_wpr_trace_output_succeeds_on_zero_exit() {
        let output = output_with_status(0, b"ignored stdout", b"ignored stderr");
        describe_wpr_output_result("cancel", output).unwrap();
    }

    #[test]
    fn cancel_existing_wpr_trace_output_propagates_diagnostics_on_nonzero_exit() {
        let output = output_with_status(42, b"no active session", b"wpr cancelled");
        let error = describe_wpr_output_result("cancel", output)
            .unwrap_err()
            .to_string();
        assert!(error.contains("wpr -cancel exited"));
        assert!(error.contains("no active session"));
        assert!(error.contains("wpr cancelled"));
    }

    #[test]
    fn cancel_spawn_not_found_error_is_actionable() {
        let error = describe_wpr_spawn_error(
            "cancel",
            "C:\\Windows\\System32\\wpr.exe",
            std::io::Error::new(std::io::ErrorKind::NotFound, "the system cannot find"),
        );
        let s = format!("{error}");
        assert!(s.contains("C:\\Windows\\System32\\wpr.exe"));
        assert!(s.contains("wpr -cancel"));
    }

    /// Whether `element` carries an attribute `name` whose (unescaped)
    /// value equals `value`. The embedded WPRP attribute values are plain
    /// ASCII with no XML entities, so a raw byte comparison is sufficient.
    fn attr_equals(element: &quick_xml::events::BytesStart<'_>, name: &[u8], value: &[u8]) -> bool {
        element
            .try_get_attribute(name)
            .ok()
            .flatten()
            .is_some_and(|a| a.value.as_ref() == value)
    }

    /// Pin that the embedded WPR profile (`profile_gen::EMBEDDED_WPRP`)
    /// is well-formed XML and still declares the `AccessFailureProfile`
    /// recording referenced by `start_plm_trace_with`. The profile is
    /// no longer a separate file — it lives as a raw string in
    /// `profile_gen.rs` — so this test is the only schema gate.
    #[test]
    fn plm_wprp_resource_is_well_formed_and_declares_access_failure_profile() {
        let wprp = crate::profile_gen::EMBEDDED_WPRP;

        // Single streaming pass over the embedded profile: reading through
        // to EOF without a parse error proves the document is well-formed
        // (mismatched or unclosed tags surface as an `Err`), while we
        // simultaneously record whether the two required elements appear.
        let mut reader = quick_xml::reader::Reader::from_str(wprp);
        let mut has_profile = false;
        let mut has_kernel_collector = false;
        loop {
            match reader
                .read_event()
                .expect("EMBEDDED_WPRP must parse as well-formed XML")
            {
                quick_xml::events::Event::Start(e) | quick_xml::events::Event::Empty(e) => {
                    match e.name().local_name().as_ref() {
                        // The recording name must stay `AccessFailureProfile`
                        // — `start_plm_trace_with` builds
                        // `<wprp_path>!AccessFailureProfile`.
                        b"Profile" if attr_equals(&e, b"Name", b"AccessFailureProfile") => {
                            has_profile = true;
                        }
                        // The AccessFailureProfile recording references the
                        // SC_Kernel system collector for process/loader events.
                        b"SystemCollector" if attr_equals(&e, b"Id", b"SC_Kernel") => {
                            has_kernel_collector = true;
                        }
                        _ => {}
                    }
                }
                quick_xml::events::Event::Eof => break,
                _ => {}
            }
        }
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
        assert!(
            wprp.contains("EP_Microsoft-Windows-Kernel-General")
                && wprp.contains("a68ca8b7-004f-d7b6-a698-07e2de0f1f5d"),
            "EMBEDDED_WPRP must enable Microsoft-Windows-Kernel-General for \
             learningModeLogging block events",
        );

        // The profile also wires the kernel collector for process/loader
        // events the parser uses to attribute access failures to a
        // specific application binary. Verify the collector reference
        // still exists.
        assert!(
            has_kernel_collector,
            "EMBEDDED_WPRP must declare the SC_Kernel SystemCollector that the \
             AccessFailureProfile recording references",
        );
    }
}
