// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Fixed WPR start operation used only by the restricted elevated
//! child. The profile path passed here is always an elevated-created temporary
//! file containing `profile_gen::EMBEDDED_WPRP`. Start never cancels a
//! pre-existing host trace; a conflict fails closed so PLM cannot tear down a
//! peer recording.

use anyhow::{Context, Result};
use std::io::Read;
use std::path::Path;
use std::process::{Command, ExitStatus, Output, Stdio};
use std::sync::mpsc::{self, Receiver, TryRecvError};
use std::time::{Duration, Instant};

use crate::wpr_path::wpr_command;

const WPR_CONTROL_TIMEOUT: Duration = Duration::from_secs(10 * 60);
const WPR_CONTROL_POLL_INTERVAL: Duration = Duration::from_millis(50);
const WPR_OUTPUT_DRAIN_TIMEOUT: Duration = Duration::from_secs(2);
const MAX_WPR_OUTPUT_BYTES: usize = 1024 * 1024;

#[derive(Debug)]
struct IndeterminateWprState;

impl std::fmt::Display for IndeterminateWprState {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("WPR state may have changed")
    }
}

impl std::error::Error for IndeterminateWprState {}

fn indeterminate_wpr_error(error: anyhow::Error) -> anyhow::Error {
    error.context(IndeterminateWprState)
}

pub(crate) fn may_have_changed_wpr_state(error: &anyhow::Error) -> bool {
    error.is::<IndeterminateWprState>()
}

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
        cmd.args(["-start", profile_arg, "-filemode"]);
        let output = run_wpr_command(cmd, "start", &resolved, WPR_CONTROL_TIMEOUT)?;
        classify_wpr_start_output(&output)
    }
}

fn classify_wpr_start_output(output: &Output) -> Result<ExitStatus> {
    if output.status.success() {
        Ok(output.status)
    } else {
        Err(indeterminate_wpr_error(describe_wpr_failure(
            "start", output,
        )))
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

pub(crate) fn run_wpr_command(
    mut command: Command,
    verb: &str,
    resolved: &str,
    timeout: Duration,
) -> Result<Output> {
    command.stdout(Stdio::piped()).stderr(Stdio::piped());
    let mut child = command
        .spawn()
        .map_err(|error| describe_wpr_spawn_error(verb, resolved, error))?;
    let Some(stdout) = child.stdout.take() else {
        terminate_child(&mut child);
        return Err(indeterminate_wpr_error(anyhow::anyhow!(
            "wpr -{verb} stdout was not captured"
        )));
    };
    let Some(stderr) = child.stderr.take() else {
        terminate_child(&mut child);
        return Err(indeterminate_wpr_error(anyhow::anyhow!(
            "wpr -{verb} stderr was not captured"
        )));
    };
    let mut stdout_reader = match spawn_output_reader(stdout, verb, "stdout") {
        Ok(reader) => reader,
        Err(error) => {
            terminate_child(&mut child);
            return Err(indeterminate_wpr_error(error));
        }
    };
    let mut stderr_reader = match spawn_output_reader(stderr, verb, "stderr") {
        Ok(reader) => reader,
        Err(error) => {
            terminate_child(&mut child);
            return Err(indeterminate_wpr_error(error));
        }
    };

    let deadline = Instant::now() + timeout;
    let status = loop {
        if let Err(error) = drain_output_readers(&mut stdout_reader, &mut stderr_reader) {
            terminate_child(&mut child);
            return Err(indeterminate_wpr_error(error.context(format!(
                "wpr -{verb} output read failed (stdout: {}; stderr: {})",
                stdout_reader.diagnostics(),
                stderr_reader.diagnostics()
            ))));
        }
        match child.try_wait() {
            Ok(Some(status)) => break status,
            Ok(None) if Instant::now() < deadline => {
                std::thread::sleep(WPR_CONTROL_POLL_INTERVAL);
            }
            Ok(None) => {
                terminate_child(&mut child);
                let drain_error =
                    finish_output_readers(&mut stdout_reader, &mut stderr_reader).err();
                return Err(indeterminate_wpr_error(anyhow::anyhow!(
                    "wpr -{verb} exceeded the {} second control timeout and was terminated \
                     (stdout: {}; stderr: {}; output drain: {})",
                    timeout.as_secs(),
                    stdout_reader.diagnostics(),
                    stderr_reader.diagnostics(),
                    drain_error
                        .map(|error| error.to_string())
                        .unwrap_or_else(|| "complete".to_string())
                )));
            }
            Err(error) => {
                terminate_child(&mut child);
                let _ = finish_output_readers(&mut stdout_reader, &mut stderr_reader);
                return Err(indeterminate_wpr_error(
                    anyhow::Error::new(error).context(format!("failed to poll wpr -{verb}")),
                ));
            }
        }
    };

    if let Err(error) = finish_output_readers(&mut stdout_reader, &mut stderr_reader) {
        return Err(indeterminate_wpr_error(error.context(format!(
            "wpr -{verb} output drain failed (stdout: {}; stderr: {})",
            stdout_reader.diagnostics(),
            stderr_reader.diagnostics()
        ))));
    }
    Ok(Output {
        status,
        stdout: stdout_reader.into_output(),
        stderr: stderr_reader.into_output(),
    })
}

enum ReaderMessage {
    Data(Vec<u8>),
    Truncated,
    Eof,
    Error(String),
}

struct OutputReader {
    receiver: Receiver<ReaderMessage>,
    output: Vec<u8>,
    done: bool,
    truncated: bool,
    stream_name: String,
}

impl OutputReader {
    fn drain(&mut self) -> Result<()> {
        loop {
            match self.receiver.try_recv() {
                Ok(ReaderMessage::Data(data)) => {
                    let remaining = MAX_WPR_OUTPUT_BYTES.saturating_sub(self.output.len());
                    self.output
                        .extend_from_slice(&data[..data.len().min(remaining)]);
                    self.truncated |= data.len() > remaining;
                }
                Ok(ReaderMessage::Truncated) => {
                    self.truncated = true;
                }
                Ok(ReaderMessage::Eof) => {
                    self.done = true;
                    return Ok(());
                }
                Ok(ReaderMessage::Error(error)) => {
                    anyhow::bail!("failed to read wpr {}: {error}", self.stream_name);
                }
                Err(TryRecvError::Empty) => return Ok(()),
                Err(TryRecvError::Disconnected) if self.done => return Ok(()),
                Err(TryRecvError::Disconnected) => {
                    anyhow::bail!("wpr {} reader exited before EOF", self.stream_name);
                }
            }
        }
    }

    fn diagnostics(&self) -> String {
        let suffix = if self.truncated { " [truncated]" } else { "" };
        format!("{}{}", String::from_utf8_lossy(&self.output).trim(), suffix)
    }

    fn into_output(self) -> Vec<u8> {
        self.output
    }
}

fn spawn_output_reader(
    mut stream: impl Read + Send + 'static,
    verb: &str,
    stream_name: &str,
) -> Result<OutputReader> {
    let (sender, receiver) = mpsc::sync_channel(64);
    std::thread::Builder::new()
        .name(format!("wpr-{verb}-{stream_name}"))
        .spawn(move || {
            let mut buffer = vec![0u8; 8192];
            let mut sent = 0usize;
            let mut reported_truncation = false;
            loop {
                match stream.read(&mut buffer) {
                    Ok(0) => {
                        let _ = sender.send(ReaderMessage::Eof);
                        break;
                    }
                    Ok(read) => {
                        let remaining = MAX_WPR_OUTPUT_BYTES.saturating_sub(sent);
                        if remaining != 0 {
                            let amount = read.min(remaining);
                            if sender
                                .send(ReaderMessage::Data(buffer[..amount].to_vec()))
                                .is_err()
                            {
                                break;
                            }
                            sent += amount;
                        }
                        if read > remaining && !reported_truncation {
                            if sender.send(ReaderMessage::Truncated).is_err() {
                                break;
                            }
                            reported_truncation = true;
                        }
                    }
                    Err(error) => {
                        let _ = sender.send(ReaderMessage::Error(error.to_string()));
                        break;
                    }
                }
            }
        })
        .with_context(|| format!("failed to start wpr -{verb} {stream_name} reader"))?;
    Ok(OutputReader {
        receiver,
        output: Vec::new(),
        done: false,
        truncated: false,
        stream_name: stream_name.to_string(),
    })
}

fn drain_output_readers(stdout: &mut OutputReader, stderr: &mut OutputReader) -> Result<()> {
    let stdout_result = stdout.drain();
    let stderr_result = stderr.drain();
    match (stdout_result, stderr_result) {
        (Ok(()), Ok(())) => Ok(()),
        (Err(stdout_error), Ok(())) => Err(stdout_error),
        (Ok(()), Err(stderr_error)) => Err(stderr_error),
        (Err(stdout_error), Err(stderr_error)) => Err(stdout_error).context(format!(
            "stderr output reader also failed: {stderr_error:#}"
        )),
    }
}

fn finish_output_readers(stdout: &mut OutputReader, stderr: &mut OutputReader) -> Result<()> {
    let deadline = Instant::now() + WPR_OUTPUT_DRAIN_TIMEOUT;
    while !stdout.done || !stderr.done {
        drain_output_readers(stdout, stderr)?;
        if stdout.done && stderr.done {
            return Ok(());
        }
        if Instant::now() >= deadline {
            anyhow::bail!(
                "timed out draining wpr output after the control process exited \
                 (stdout complete: {}; stderr complete: {})",
                stdout.done,
                stderr.done
            );
        }
        std::thread::sleep(WPR_CONTROL_POLL_INTERVAL);
    }
    Ok(())
}

fn terminate_child(child: &mut std::process::Child) {
    let _ = child.kill();
    let _ = child.wait();
}

/// Start state machine parameterized on a `WprLauncher` for tests.
///
/// A non-zero result is returned directly. Automatically issuing `wpr
/// -cancel` here could destroy an unrelated host recording, so PLM never
/// retries by cancelling host-wide WPR state.
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

    #[test]
    fn nonzero_start_exit_reports_indeterminate_wpr_state() {
        let output = std::process::Output {
            status: ExitStatus::from_raw(1),
            stdout: b"start diagnostic".to_vec(),
            stderr: b"start failed".to_vec(),
        };

        let error = classify_wpr_start_output(&output).unwrap_err();

        assert!(may_have_changed_wpr_state(&error));
        assert!(format!("{error:#}").contains("start failed"));
    }

    #[test]
    fn indeterminate_wrapper_preserves_original_error_chain() {
        let error = indeterminate_wpr_error(anyhow::Error::new(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "access denied",
        )));

        assert!(may_have_changed_wpr_state(&error));
        assert!(error.downcast_ref::<std::io::Error>().is_some());
    }

    #[test]
    fn reader_errors_preserve_both_stream_diagnostics() {
        let (stdout_sender, stdout_receiver) = mpsc::sync_channel(4);
        stdout_sender
            .send(ReaderMessage::Data(b"stdout detail".to_vec()))
            .unwrap();
        stdout_sender
            .send(ReaderMessage::Error("stdout failed".to_string()))
            .unwrap();
        let (stderr_sender, stderr_receiver) = mpsc::sync_channel(4);
        stderr_sender
            .send(ReaderMessage::Data(b"stderr detail".to_vec()))
            .unwrap();
        stderr_sender
            .send(ReaderMessage::Error("stderr failed".to_string()))
            .unwrap();
        let mut stdout = OutputReader {
            receiver: stdout_receiver,
            output: Vec::new(),
            done: false,
            truncated: false,
            stream_name: "stdout".to_string(),
        };
        let mut stderr = OutputReader {
            receiver: stderr_receiver,
            output: Vec::new(),
            done: false,
            truncated: false,
            stream_name: "stderr".to_string(),
        };

        drain_output_readers(&mut stdout, &mut stderr).unwrap_err();

        assert_eq!(stdout.diagnostics(), "stdout detail");
        assert_eq!(stderr.diagnostics(), "stderr detail");
    }

    #[test]
    fn oversized_output_is_capped_and_marked_truncated() {
        let mut stdout = spawn_output_reader(
            std::io::Cursor::new(vec![b'x'; MAX_WPR_OUTPUT_BYTES + 1]),
            "test",
            "stdout",
        )
        .unwrap();
        let mut stderr =
            spawn_output_reader(std::io::Cursor::new(Vec::new()), "test", "stderr").unwrap();

        finish_output_readers(&mut stdout, &mut stderr).unwrap();

        assert_eq!(stdout.output.len(), MAX_WPR_OUTPUT_BYTES);
        assert!(stdout.truncated);
        assert!(stdout.diagnostics().ends_with(" [truncated]"));
    }

    #[test]
    fn stop_spawn_not_found_error_is_actionable() {
        let error = describe_wpr_spawn_error(
            "stop",
            "C:\\Windows\\System32\\wpr.exe",
            std::io::Error::new(std::io::ErrorKind::NotFound, "the system cannot find"),
        );
        let s = format!("{error}");
        assert!(s.contains("C:\\Windows\\System32\\wpr.exe"));
        assert!(s.contains("wpr -stop"));
    }

    #[test]
    fn wpr_control_timeout_terminates_hung_process() {
        let mut command = Command::new("powershell.exe");
        command.args(["-NoProfile", "-Command", "Start-Sleep -Seconds 60"]);
        let started = Instant::now();

        let error = run_wpr_command(command, "test", "powershell.exe", Duration::from_millis(50))
            .unwrap_err();

        assert!(format!("{error:#}").contains("timeout"));
        assert!(may_have_changed_wpr_state(&error));
        assert!(started.elapsed() < Duration::from_secs(2));
    }

    #[test]
    fn pre_spawn_failure_does_not_report_indeterminate_wpr_state() {
        let command = Command::new(r"Z:\definitely-missing\wpr.exe");

        let error = run_wpr_command(
            command,
            "start",
            r"Z:\definitely-missing\wpr.exe",
            Duration::from_secs(1),
        )
        .unwrap_err();

        assert!(!may_have_changed_wpr_state(&error));
    }

    #[test]
    fn inherited_output_handle_cannot_block_control_completion() {
        let mut command = Command::new("powershell.exe");
        command.args([
            "-NoProfile",
            "-Command",
            "$p = Start-Process powershell.exe -NoNewWindow -PassThru -ArgumentList \
             '-NoProfile','-Command','Start-Sleep -Seconds 60'; Write-Output \"PID=$($p.Id)\"",
        ]);
        let started = Instant::now();

        let error =
            run_wpr_command(command, "test", "powershell.exe", Duration::from_secs(5)).unwrap_err();
        let message = format!("{error:#}");
        let pid = message
            .split("PID=")
            .nth(1)
            .and_then(|suffix| {
                suffix
                    .chars()
                    .take_while(char::is_ascii_digit)
                    .collect::<String>()
                    .parse::<u32>()
                    .ok()
            })
            .expect("descendant PID should be retained in partial stdout");
        let _ = Command::new("powershell.exe")
            .args([
                "-NoProfile",
                "-Command",
                &format!("Stop-Process -Id {pid} -Force -ErrorAction SilentlyContinue"),
            ])
            .status();

        assert!(message.contains("output drain failed"));
        assert!(may_have_changed_wpr_state(&error));
        assert!(started.elapsed() < Duration::from_secs(5));
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
