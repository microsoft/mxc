// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! `SeatbeltScriptRunner` — executes scripts inside Apple's Seatbelt
//! sandbox.
//!
//! The sandbox is applied via `sandbox_init()` inside `Command::pre_exec`,
//! then `/bin/sh` is exec'd directly. The child inherits the parent's
//! Mach bootstrap namespace so both CLI commands and GUI applications
//! (when `guiAccess = true`) work correctly. The exec path returns a
//! `SandboxProcess` whose stdio follows the requested `StdioMode`:
//! `Inherit` gives the child the host's own stdio (a real TTY when the
//! binary runs under a pty), while `Pipes` exposes stdout/stderr/stdin
//! handles the caller can stream and `Pty` exposes a caller-owned terminal.
//!
//! Compiled only on macOS — the rest of the workspace continues to build
//! on Windows / Linux unchanged.

use std::ffi::{CStr, CString};
use std::fmt::Write as FmtWrite;
use std::io::IsTerminal;
use std::os::fd::AsFd;
use std::os::unix::fs::OpenOptionsExt;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use crate::learning_mode_core::capture_output::{
    combine_capture_and_cleanup_results, combine_process_and_teardown_results,
    random_capture_suffix, remove_internal_capture_file, unique_denials_output_path,
    write_capture_denials_document,
};
use crate::learning_mode_core::capture_sibling_path;
use crate::mxc_common::interruptible_reader::{wrap_pipe, InterruptibleReader, ReadCanceller};
use crate::mxc_common::logger::Logger;
use crate::mxc_common::models::{
    CaptureDenialsErrorOutput, CaptureDenialsMode, CaptureDenialsOutput, ExecutionRequest,
    FailurePhase, ProxyAddress, SandboxOutputMetadata, ScriptResponse,
};
use crate::mxc_common::sandbox_process::{
    boxed_closer, cancel_and_join_discard, duplicate_and_take_native_stdio, spawn_discard,
    take_boxed_read, take_boxed_write, wait_with_timeout, NativeStdio, PtySize, SandboxBackend,
    SandboxProcess, StdioMode, StreamCloser, WaitError,
};
use crate::mxc_common::validator::{
    validate_common, validate_network_policy_support, NetworkPolicySupport,
};
use crate::mxc_pty::{LivePty, PtySize as UnixPtySize};

#[cfg(test)]
use crate::seatbelt_common::default_env::DEFAULT_SANDBOX_PATH;
use crate::seatbelt_common::default_env::{env_pairs, resolved_env};
use crate::seatbelt_common::denial_capture::{CollectedEvents, DenialCollector, MAX_TRACE_BYTES};
#[cfg(test)]
use crate::seatbelt_common::profile_builder::build_profile_with_proxy;
use crate::seatbelt_common::profile_builder::{build_profile_with_terminals, ProfileError};
use crate::seatbelt_common::profile_preparation::{
    classify_io_error, expand_tilde, prepare_capture_output_path, prepare_profile,
    resolve_policy_path,
};
use crate::seatbelt_common::run_marker::RunMarker;

/// How long cleanup may keep finding new processes in a run before it gives up.
const CLEANUP_TIMEOUT: Duration = Duration::from_secs(5);

fn exit_cleanup_timeout() -> Duration {
    #[cfg(test)]
    if let Some(timeout) = tests::EXIT_CLEANUP_TIMEOUT.get() {
        return timeout;
    }
    CLEANUP_TIMEOUT
}

/// Env var keys the cooperative proxy manages. When a proxy is active these
/// are stripped from the caller-supplied environment so sandboxed code cannot
/// override the `HTTP_PROXY` / `HTTPS_PROXY` / `ALL_PROXY` values we inject (or
/// re-enable a `NO_PROXY` bypass). `ALL_PROXY` is the catch-all curl/libcurl
/// and many HTTP clients honor for every scheme, so leaving it caller-settable
/// would let sandboxed code redirect or bypass the proxy. Mirrors the
/// Bubblewrap backend's `PROXY_ENV_KEYS`.
const PROXY_ENV_KEYS: &[&str] = &[
    "HTTP_PROXY",
    "HTTPS_PROXY",
    "ALL_PROXY",
    "http_proxy",
    "https_proxy",
    "all_proxy",
    "NO_PROXY",
    "no_proxy",
];

/// Proxy env var keys injected (pointing at the resolved proxy URL) when a
/// proxy is active. `NO_PROXY` is intentionally absent — see the module docs
/// and [`resolve_environment`].
const PROXY_INJECT_KEYS: &[&str] = &[
    "HTTP_PROXY",
    "HTTPS_PROXY",
    "ALL_PROXY",
    "http_proxy",
    "https_proxy",
    "all_proxy",
];

// ---------------------------------------------------------------------------
// FFI declarations for Apple's sandbox API (libsandbox.dylib).
//
// `sandbox_init` is declared in <sandbox.h> and marked deprecated since
// macOS 10.8, but is still shipped and used by first-party apps through
// macOS 15+.
// ---------------------------------------------------------------------------

/// Whether `sandbox_init` resolves in this process, as the exec path needs.
pub(crate) fn sandbox_init_available() -> bool {
    // SAFETY: `dlsym` only reads the NUL-terminated symbol name.
    !unsafe { libc::dlsym(libc::RTLD_SELF, c"sandbox_init".as_ptr()) }.is_null()
}

#[link(name = "sandbox")]
extern "C" {
    fn sandbox_init(
        profile: *const libc::c_char,
        flags: u64,
        errorbuf: *mut *mut libc::c_char,
    ) -> libc::c_int;

    fn sandbox_free_error(errorbuf: *mut libc::c_char);
}

/// Default shell used to execute `script_code`. `/bin/sh` is guaranteed
/// to exist and is on the SIP-protected path so it's always reachable
/// from inside the sandbox.
const DEFAULT_SHELL: &str = "/bin/sh";

/// Markers bracketing the generated profile in the log stream, so a reader can
/// slice it out. The `Seatbelt: ` prefix cannot collide with profile content:
/// rules start with `(` and profile comments with `;;`.
pub const PROFILE_LOG_BEGIN: &str = "Seatbelt: --- begin generated profile ---";
pub const PROFILE_LOG_END: &str = "Seatbelt: --- end generated profile ---";

#[derive(Default)]
pub struct SeatbeltScriptRunner;

impl SeatbeltScriptRunner {
    pub fn new() -> Self {
        Self
    }
}

impl SandboxBackend for SeatbeltScriptRunner {
    fn network_policy_support(&self) -> NetworkPolicySupport {
        // Seatbelt enforces a single outbound default (no CIDR/port/protocol
        // rules — `EGRESS_RULES` is intentionally omitted), a single inbound
        // default mapped to a local-IP inbound rule, and the
        // loopback-scoped runtime proxy. It has no per-peer proxy identity
        // concept (`PROXY_PEER_IDENTITY` is a ProcessContainer-only feature).
        NetworkPolicySupport::EGRESS_DEFAULT
            | NetworkPolicySupport::INGRESS_DEFAULT
            | NetworkPolicySupport::HOST_LOOPBACK
            | NetworkPolicySupport::RUNTIME_PROXY
    }

    fn validate(&self, request: &ExecutionRequest) -> Result<(), ScriptResponse> {
        validate_network_policy_support(request, self.network_policy_support())?;

        // Seatbelt's own invariants — the only home for them, so a caller that
        // builds an ExecutionRequest directly gets the same rules.
        crate::seatbelt_common::seatbelt_policy::validate_seatbelt_network_policy(&request.policy)
            .map_err(rejected_response)?;
        crate::seatbelt_common::seatbelt_policy::validate_seatbelt_ui_policy(request)
            .map_err(rejected_response)?;
        crate::seatbelt_common::seatbelt_policy::validate_seatbelt_capture_denials(request)
            .map_err(rejected_response)?;
        crate::seatbelt_common::seatbelt_policy::validate_seatbelt_reserved_names(request)
            .map_err(rejected_response)?;
        // Dry runs never reach spawn, so reject unresolvable paths here too.
        prepare_profile(request).map_err(profile_error_response)?;
        prepare_capture_output_path(request).map_err(profile_error_response)?;
        resolved_working_directory_opt(request).map_err(profile_error_response)?;

        Ok(())
    }

    fn spawn(
        &mut self,
        request: &ExecutionRequest,
        logger: &mut Logger,
        stdio: StdioMode,
    ) -> Result<Box<dyn SandboxProcess>, ScriptResponse> {
        validate_common(request)?;
        self.validate(request)?;

        // The caller manages the proxy. Scope the profile's reachability rule
        // to its address and inject HTTP_PROXY / HTTPS_PROXY. macOS has no
        // WinHTTP-style OS proxy policy,
        // so — like the Bubblewrap backend — enforcement is cooperative:
        // well-behaved HTTP clients honor the env vars; raw-socket clients
        // bypass them.
        let proxy_address = request.policy.network_proxy.address.as_ref();
        if let Some(address) = proxy_address {
            logger.log_line(&format!(
                "Unix network proxy active: {}",
                crate::mxc_common::proxy_env::redact_proxy_url(&address.to_url())
            ));
        }
        // Effective posture, not the raw flag: a `guiAccess` the UI policy
        // suppressed emits no GUI rules, so it must not cost the caller
        // streaming either.
        let gui_access = crate::seatbelt_common::seatbelt_policy::gui_access_effective(request);

        spawn_exec(request, gui_access, stdio, logger, proxy_address)
    }
}

/// Exec launch path: fork → sandbox_init → exec `/bin/sh -c <script>`. With
/// [`StdioMode::Pipes`] the child gets pipes and leads its own session, away
/// from the host's terminal; with
/// [`StdioMode::Inherit`] it inherits the process's stdio (a TTY when the
/// binary has one) and stays in the binary's session; with [`StdioMode::Pty`]
/// it gets a caller-owned terminal and leads its own session. `gui_access`
/// apps require inherited stdio. Cleanup finds the run's processes by the
/// profile's run marker, not by session or process group.
fn spawn_exec(
    request: &ExecutionRequest,
    gui_access: bool,
    stdio: StdioMode,
    logger: &mut Logger,
    proxy_address: Option<&ProxyAddress>,
) -> Result<Box<dyn SandboxProcess>, ScriptResponse> {
    if gui_access && stdio != StdioMode::Inherit {
        let mode = if stdio == StdioMode::Pipes {
            "pipes"
        } else {
            "a caller-owned PTY"
        };
        return Err(rejected_response(format!(
            "Seatbelt guiAccess requires inherited stdio and cannot use {mode}"
        )));
    }

    // Pipes → own session (setsid), detached from the host's terminal.
    // Inherit/GUI → keep the binary's session and controlling
    // terminal so the child sees a TTY exactly when the binary does.
    let new_session = stdio == StdioMode::Pipes;
    let capture_plan = plan_denial_capture(request).map_err(profile_error_response)?;
    let marker = RunMarker::new().map_err(|error| launch_failed_response(error.to_string()))?;
    let (mut command, pty) = build_sandbox_command(
        request,
        proxy_address,
        new_session,
        &marker,
        match stdio {
            StdioMode::Pty(size) => Some(size),
            _ => None,
        },
        capture_plan.as_ref().map(|plan| plan.tag.as_str()),
        logger,
    )?;

    // Always start from a cleared environment so untrusted sandboxed code never
    // inherits the host's env. When a proxy is active its HTTP_PROXY/HTTPS_PROXY
    // vars are injected here (and caller-supplied proxy vars stripped).
    //
    // The cwd is anchored and resolved to its physical path so `PWD` and the
    // default `HOME` match the directory the child actually starts in.
    let resolved_cwd = resolved_working_directory_opt(request).map_err(profile_error_response)?;
    let cwd = resolved_cwd
        .as_deref()
        .unwrap_or(UNRESOLVED_WORKING_DIRECTORY);
    let home_dir = resolved_cwd.as_deref();
    apply_clean_environment(&mut command, request, proxy_address, home_dir);

    // Also export `PWD` so the child's `getcwd()` uses its
    // fast `$PWD` path (a single stat) instead of walking parent directories
    // the sandbox may not let it read — which otherwise leaks
    // "getcwd: ... Operation not permitted" to stderr.
    command.current_dir(cwd);
    command.env("PWD", cwd);

    // Fail closed: never run a capture request without a live log stream.
    if capture_plan.as_ref().is_some_and(|plan| plan.allow_mode) {
        logger.warning_line(ALLOW_MODE_WARNING);
    }
    let capture = capture_plan
        .map(|plan| plan.start())
        .transpose()
        .map_err(launch_failed_response)?;

    match stdio {
        StdioMode::Pipes => {
            command
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped());
        }
        StdioMode::Inherit => {
            // The child inherits the binary's stdio directly (a TTY when the
            // binary has one) — no separate pty bridge.
            command
                .stdin(Stdio::inherit())
                .stdout(Stdio::inherit())
                .stderr(Stdio::inherit());
        }
        StdioMode::Pty(_) => {}
    }

    let mut child = match command.spawn() {
        Ok(child) => child,
        Err(error) => {
            return Err(discard_capture(
                capture,
                launch_failed_response(spawn_error(&error)),
            ))
        }
    };

    let (stdin, stdout, stderr) = match stdio {
        StdioMode::Pipes => (child.stdin.take(), child.stdout.take(), child.stderr.take()),
        StdioMode::Inherit => (None, None, None),
        StdioMode::Pty(_) => (None, None, None),
    };

    // Wrap the pipe reads so the caller can abandon a stream a backgrounded
    // descendant is holding open (see `SandboxProcess::stdout_closer`), without
    // killing the child. On failure, don't orphan the already-spawned sandboxed
    // process — kill and reap it before returning the error.
    let (stdout, stdout_canceller, stderr, stderr_canceller) =
        match (wrap_pipe(stdout), wrap_pipe(stderr)) {
            (Ok((out, out_canceller)), Ok((err, err_canceller))) => {
                (out, out_canceller, err, err_canceller)
            }
            (out_result, err_result) => {
                let _ = child.kill();
                let _ = child.wait();
                let error = out_result.err().or(err_result.err());
                let mut message = format!(
                    "Seatbelt: failed to wrap stdio pipes: {}",
                    error.map_or_else(|| "unknown error".to_string(), |e| e.to_string()),
                );
                if let Err(cleanup) = marker.kill_members(CLEANUP_TIMEOUT) {
                    message.push_str(&format!(
                        "; processes it started could not be terminated: {cleanup}"
                    ));
                }
                return Err(discard_capture(capture, launch_failed_response(message)));
            }
        };

    let started = Instant::now();
    Ok(Box::new(SeatbeltSandboxProcess {
        child,
        stdin,
        stdout,
        stderr,
        stdout_canceller,
        stderr_canceller,
        pty,
        timeout: timeout_from(request),
        started,
        timed_out: false,
        termination_error: None,
        marker,
        members_cleaned: false,
        cleanup_failures: Vec::new(),
        capture,
        capture_error: None,
        capture_warnings: Vec::new(),
        output_metadata: None,
    }))
}

struct DenialCapturePlan {
    tag: String,
    output_path: PathBuf,
    /// The `.seatbelt.log` path when `retainEtl` is set.
    trace_path: Option<PathBuf>,
    allow_mode: bool,
}

impl DenialCapturePlan {
    fn start(self) -> Result<ActiveDenialCapture, String> {
        let trace = match &self.trace_path {
            // Owner-only, like the reports: the trace holds the same paths.
            Some(path) => Some(
                std::fs::OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .mode(0o600)
                    .open(path)
                    .map_err(|error| {
                        format!(
                            "captureDenials could not create trace file {}: {error}",
                            path.display()
                        )
                    })?,
            ),
            None => None,
        };
        match DenialCollector::start(&self.tag, trace) {
            Ok(collector) => Ok(ActiveDenialCapture {
                collector,
                output_path: self.output_path,
                trace_path: self.trace_path,
            }),
            Err(error) => match self.trace_path.as_deref().map(remove_internal_capture_file) {
                Some(Err(cleanup)) => Err(format!("{error}; additionally {cleanup}")),
                _ => Err(error),
            },
        }
    }
}

struct ActiveDenialCapture {
    collector: DenialCollector,
    output_path: PathBuf,
    trace_path: Option<PathBuf>,
}

/// Stops `log stream` and deletes the trace when the workload never ran.
fn discard_capture(
    capture: Option<ActiveDenialCapture>,
    mut response: ScriptResponse,
) -> ScriptResponse {
    let Some(capture) = capture else {
        return response;
    };
    drop(capture.collector);
    if let Some(Err(error)) = capture
        .trace_path
        .as_deref()
        .map(remove_internal_capture_file)
    {
        response.error_message = format!("{}; additionally {error}", response.error_message);
    }
    response
}

impl ActiveDenialCapture {
    /// Stops `log stream`. Returns the collected events and the trace path if
    /// the trace was fully written; a partly written trace is removed.
    fn stop(self) -> (std::io::Result<CollectedEvents>, PathBuf, Option<PathBuf>) {
        let collected = self.collector.finish().map_err(|error| {
            std::io::Error::other(format!("captureDenials failed to collect denials: {error}"))
        });
        let Some(trace_path) = self.trace_path else {
            return (collected, self.output_path, None);
        };
        let trace_error = collected
            .as_ref()
            .ok()
            .and_then(|collected| collected.trace_error.clone());
        match trace_error {
            None => (collected, self.output_path, Some(trace_path)),
            Some(error) => {
                let error = std::io::Error::other(format!(
                    "captureDenials failed to write trace file {}: {error}",
                    trace_path.display()
                ));
                let result = combine_capture_and_cleanup_results(
                    Err(error),
                    remove_internal_capture_file(&trace_path),
                );
                (result, self.output_path, None)
            }
        }
    }
}

/// Picks the log tag and denials file path for a `captureDenials` request.
fn plan_denial_capture(
    request: &ExecutionRequest,
) -> Result<Option<DenialCapturePlan>, ProfileError> {
    let Some(config) = request
        .seatbelt
        .as_ref()
        .and_then(|config| config.capture_denials.as_ref())
    else {
        return Ok(None);
    };
    let configured_path = prepare_capture_output_path(request)?;
    let output_path =
        unique_denials_output_path(configured_path.as_deref()).map_err(ProfileError::Host)?;
    let trace_path = config
        .retain_etl
        .then(|| capture_sibling_path(&output_path, TRACE_SUFFIX))
        .transpose()
        .map_err(|error| ProfileError::Host(format!("captureDenials {error}")))?;
    Ok(Some(DenialCapturePlan {
        tag: format!(
            "mxc-capture-{}",
            random_capture_suffix().map_err(ProfileError::Host)?
        ),
        output_path,
        trace_path,
        allow_mode: config.mode == CaptureDenialsMode::Allow,
    }))
}

const TRACE_SUFFIX: &str = "seatbelt.log";

const ALLOW_MODE_WARNING: &str = "Seatbelt captureDenials mode 'allow' ran the workload without \
     enforcing default-denied operations; denials.json lists what would have been blocked";

/// A running Seatbelt-sandboxed process: the child plus, for the pipes path,
/// its parent-side pipe ends. See [`SandboxProcess`] for the contract.
struct SeatbeltSandboxProcess {
    child: std::process::Child,
    /// Pipe ends — `Some` only for [`StdioMode::Pipes`]; `None` for inherited
    /// stdio, where the streams are the binary's own. The
    /// reads are wrapped so they can be cancelled out-of-band (see the
    /// `*_canceller` fields).
    stdin: Option<std::process::ChildStdin>,
    stdout: Option<InterruptibleReader>,
    stderr: Option<InterruptibleReader>,
    /// Cancellers for the stdout/stderr reads (`Some` alongside the pipe ends),
    /// kept so [`stdout_closer`](SandboxProcess::stdout_closer) /
    /// [`stderr_closer`](SandboxProcess::stderr_closer) can mint closers even
    /// after the stream has been taken.
    stdout_canceller: Option<ReadCanceller>,
    stderr_canceller: Option<ReadCanceller>,
    /// Caller-owned primary PTY for direct exec mode.
    pty: Option<LivePty>,
    timeout: Option<Duration>,
    started: Instant,
    timed_out: bool,
    termination_error: Option<String>,
    /// Identifies every process in this run, including ones that left its
    /// session or process group.
    marker: RunMarker,
    /// The run's remaining processes were killed after the child exited.
    members_cleaned: bool,
    /// Reported through `warnings()`, so the exit code is kept.
    cleanup_failures: Vec<String>,
    /// Live `captureDenials` log stream; consumed by `wait()`.
    capture: Option<ActiveDenialCapture>,
    /// A failed capture, replayed by later `wait()` calls.
    capture_error: Option<(std::io::ErrorKind, String)>,
    capture_warnings: Vec<String>,
    output_metadata: Option<SandboxOutputMetadata>,
}

impl SeatbeltSandboxProcess {
    /// Drains the capture stream after the child exits and writes denials.json.
    fn finish_capture(&mut self, exit_code: Option<i32>) -> std::io::Result<()> {
        if let Some((kind, message)) = &self.capture_error {
            return Err(std::io::Error::new(*kind, message.clone()));
        }
        let Some(capture) = self.capture.take() else {
            return Ok(());
        };
        let (collected, output_path, trace_path) = capture.stop();
        let result = collected.and_then(|collected| {
            if self.termination_error.is_some() {
                // Caller-visible results carry only the error, so a report here
                // would be unreachable.
                return Err(std::io::Error::other(
                    "captureDenials did not write a report because the workload could not be \
                     terminated",
                ));
            }
            if !self.cleanup_failures.is_empty() {
                // Surviving processes can keep causing denials after collection ends.
                return Err(std::io::Error::other(format!(
                    "captureDenials did not write a report: {}",
                    self.cleanup_failures.join("; ")
                )));
            }
            self.write_capture(collected, &output_path, trace_path.as_deref(), exit_code)
        });
        let result = result.map_err(|error| match &trace_path {
            Some(path) => std::io::Error::new(
                error.kind(),
                format!(
                    "{error}; the captureDenials trace was kept at {}",
                    path.display()
                ),
            ),
            None => error,
        });
        if let Err(error) = &result {
            self.capture_error = Some((error.kind(), error.to_string()));
            if let Some(path) = &trace_path {
                self.output_metadata = Some(SandboxOutputMetadata {
                    capture_denials: None,
                    capture_denials_error: Some(CaptureDenialsErrorOutput {
                        message: error.to_string(),
                        etl_path: path.to_string_lossy().into_owned(),
                    }),
                });
            }
            // FFI waits expose only a status, so preserve capture diagnostics in warnings too.
            self.capture_warnings.push(if self.timed_out {
                format!("Seatbelt captureDenials failed after the run timed out: {error}")
            } else {
                format!("Seatbelt captureDenials failed: {error}")
            });
        }
        result
    }

    fn write_capture(
        &mut self,
        collected: CollectedEvents,
        output_path: &Path,
        trace_path: Option<&Path>,
        exit_code: Option<i32>,
    ) -> std::io::Result<()> {
        if !collected.drained {
            self.capture_warnings.push(
                "Seatbelt captureDenials could not confirm that all sandbox log events were \
                 received; denials.json may be incomplete"
                    .to_string(),
            );
        }
        if let (true, Some(path)) = (collected.trace_truncated, trace_path) {
            self.capture_warnings.push(format!(
                "Seatbelt captureDenials stopped writing trace file {} at its {} GiB limit; \
                 the denial report is not affected",
                path.display(),
                MAX_TRACE_BYTES >> 30
            ));
        }
        let pointer = write_capture_denials_document(
            collected.into_analysis(),
            exit_code.unwrap_or(-1),
            output_path,
        )?;
        let mut output = CaptureDenialsOutput::from(pointer);
        output.etl_path = trace_path.map(|path| path.to_string_lossy().into_owned());
        self.output_metadata = Some(SandboxOutputMetadata {
            capture_denials: Some(output),
            capture_denials_error: None,
        });
        Ok(())
    }
}

impl SandboxProcess for SeatbeltSandboxProcess {
    fn warnings(&self) -> Vec<String> {
        let mut warnings = self.cleanup_failures.clone();
        warnings.extend(self.capture_warnings.iter().cloned());
        warnings
    }

    fn output_metadata(&self) -> Option<&SandboxOutputMetadata> {
        self.output_metadata.as_ref()
    }

    fn take_native_stdio(&mut self) -> std::io::Result<Option<NativeStdio>> {
        if let Some(pty) = self.pty.as_ref() {
            let stdio = pty.take_native_stdio()?;
            return Ok(Some(NativeStdio {
                stdin: Some(stdio.stdin),
                stdout: Some(stdio.stdout),
                stderr: None,
            }));
        }
        let stdio = duplicate_and_take_native_stdio(
            &mut self.stdin,
            &mut self.stdout,
            &mut self.stderr,
            |stream| stream.as_fd().try_clone_to_owned(),
            InterruptibleReader::try_clone_owned_fd,
            InterruptibleReader::try_clone_owned_fd,
        )?;
        if stdio.is_some() {
            self.stdout_canceller.take();
            self.stderr_canceller.take();
        }
        Ok(stdio)
    }

    fn take_stdin(&mut self) -> Option<Box<dyn std::io::Write + Send>> {
        take_boxed_write(&mut self.stdin)
    }

    fn is_pty(&self) -> bool {
        self.pty.is_some()
    }

    fn pty_clone_reader(&self) -> std::io::Result<Box<dyn std::io::Read + Send>> {
        self.pty
            .as_ref()
            .ok_or_else(|| std::io::Error::other("Seatbelt process has no PTY"))?
            .try_clone_reader()
    }

    fn pty_clone_reader_with_closer(
        &self,
    ) -> std::io::Result<crate::mxc_common::sandbox_process::PtyReaderWithCloser> {
        let (reader, closer) = self
            .pty
            .as_ref()
            .ok_or_else(|| std::io::Error::other("Seatbelt process has no PTY"))?
            .try_clone_reader_with_canceller()?;
        Ok((reader, Some(Box::new(closer))))
    }

    fn pty_take_writer(&self) -> std::io::Result<Box<dyn std::io::Write + Send>> {
        self.pty
            .as_ref()
            .ok_or_else(|| std::io::Error::other("Seatbelt process has no PTY"))?
            .take_writer()
    }

    fn pty_resize(&self, size: PtySize) -> std::io::Result<()> {
        self.pty
            .as_ref()
            .ok_or_else(|| std::io::Error::other("Seatbelt process has no PTY"))?
            .resize(UnixPtySize {
                rows: size.rows,
                cols: size.cols,
                pixel_width: size.pixel_width,
                pixel_height: size.pixel_height,
            })
    }

    fn pty_size(&self) -> std::io::Result<PtySize> {
        let size = self
            .pty
            .as_ref()
            .ok_or_else(|| std::io::Error::other("Seatbelt process has no PTY"))?
            .size();
        Ok(PtySize {
            rows: size.rows,
            cols: size.cols,
            pixel_width: size.pixel_width,
            pixel_height: size.pixel_height,
        })
    }

    fn take_stdout(&mut self) -> Option<Box<dyn std::io::Read + Send>> {
        take_boxed_read(&mut self.stdout)
    }

    fn take_stderr(&mut self) -> Option<Box<dyn std::io::Read + Send>> {
        take_boxed_read(&mut self.stderr)
    }

    fn stdout_closer(&self) -> Option<Box<dyn StreamCloser>> {
        boxed_closer(&self.stdout_canceller)
    }

    fn stderr_closer(&self) -> Option<Box<dyn StreamCloser>> {
        boxed_closer(&self.stderr_canceller)
    }

    fn try_wait(&mut self) -> std::io::Result<Option<i32>> {
        if let Some(error) = self.termination_error.as_ref() {
            return Err(std::io::Error::other(error.clone()));
        }
        if self.timed_out {
            return Err(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "Seatbelt: process timed out",
            ));
        }
        // Status only; `wait`, `kill`, and drop clean up the run.
        if let Some(status) = self.child.try_wait()? {
            return Ok(Some(status.code().unwrap_or(-1)));
        }
        if self
            .timeout
            .is_some_and(|timeout| self.started.elapsed() >= timeout)
        {
            if let Err(error) = self.kill_for_timeout() {
                let error = format!(
                    "Seatbelt: process timed out, but its session could not be terminated: {error}"
                );
                self.termination_error = Some(error.clone());
                return Err(std::io::Error::other(error));
            }
            self.timed_out = true;
            return Err(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "Seatbelt: process timed out",
            ));
        }
        Ok(None)
    }

    fn id(&self) -> u32 {
        self.child.id()
    }

    fn kill(&mut self) -> std::io::Result<()> {
        // Only signal the child while it is unreaped; a reaped pid can be reused.
        // The marker scan still reaches the child if its status is unknown.
        let child_result = match self.child.try_wait() {
            Ok(Some(_)) => Ok(()),
            Ok(None) => self.child.kill(),
            Err(error) => Err(error),
        };
        let members_result = self.marker.kill_members(CLEANUP_TIMEOUT);
        child_result.and(members_result)
    }

    fn kill_for_timeout(&mut self) -> std::io::Result<()> {
        const REAP_TIMEOUT: Duration = Duration::from_secs(5);

        self.kill()?;
        match wait_with_timeout(&mut self.child, Some(REAP_TIMEOUT)) {
            Ok(_) => {}
            Err(WaitError::Timeout) => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    "Seatbelt: killed process did not become reapable within 5 seconds",
                ))
            }
            Err(WaitError::Io(error)) => return Err(error),
        }
        self.timed_out = true;
        Ok(())
    }

    fn wait(&mut self) -> std::io::Result<i32> {
        // Close our copy of any not-taken stdin so the child sees EOF and is
        // not blocked waiting for input the caller never intends to send.
        self.stdin.take();
        if let Some(pty) = self.pty.as_ref() {
            pty.close_writer();
        }

        // Drain (and discard) any not-taken stdout/stderr concurrently so the
        // child can't block on a full pipe (taken streams are the caller's
        // responsibility).
        let stdout_thread = spawn_discard(self.stdout.take());
        let stderr_thread = spawn_discard(self.stderr.take());
        let (pty_thread, pty_canceller, pty_setup_error) = match self.pty.as_ref() {
            Some(pty) => match pty.take_unclaimed_reader() {
                Ok(Some((reader, canceller))) => {
                    (spawn_discard(Some(reader)), Some(canceller), None)
                }
                Ok(None) => (None, None, None),
                Err(error) => (None, None, Some(error)),
            },
            None => (None, None, None),
        };

        let remaining_timeout = self
            .timeout
            .map(|timeout| timeout.saturating_sub(self.started.elapsed()));
        let result = if let Some(error) = pty_setup_error {
            let _ = self.kill();
            let _ = wait_with_timeout(&mut self.child, Some(Duration::from_secs(5)));
            Err(std::io::Error::other(format!(
                "Seatbelt: failed to prepare PTY output draining: {error}"
            )))
        } else if let Some(error) = self.termination_error.as_ref() {
            Err(std::io::Error::other(error.clone()))
        } else if self.timed_out {
            Err(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "Seatbelt: process timed out",
            ))
        } else {
            match wait_with_timeout(&mut self.child, remaining_timeout) {
                Ok(status) => {
                    self.clean_up_after_exit();
                    Ok(status.code().unwrap_or(-1))
                }
                Err(WaitError::Timeout) => {
                    if let Err(error) = self.kill_for_timeout() {
                        let error =
                            format!("Seatbelt: process timed out, but teardown failed: {error}");
                        self.termination_error = Some(error.clone());
                        Err(std::io::Error::other(error))
                    } else {
                        self.timed_out = true;
                        Err(std::io::Error::new(
                            std::io::ErrorKind::TimedOut,
                            "Seatbelt: process timed out",
                        ))
                    }
                }
                Err(WaitError::Io(error)) => {
                    // The child may still be running: kill+reap it (don't orphan
                    // the sandbox) before returning.
                    let _ = self.kill();
                    let _ = wait_with_timeout(&mut self.child, Some(Duration::from_secs(5)));
                    Err(std::io::Error::other(format!("wait failed: {error}")))
                }
            }
        };

        cancel_and_join_discard(stdout_thread, &self.stdout_canceller);
        cancel_and_join_discard(stderr_thread, &self.stderr_canceller);
        if let Some(pty) = self.pty.as_ref() {
            pty.finish_native_bridge();
        }
        cancel_and_join_discard(pty_thread, &pty_canceller);
        let capture_result = self.finish_capture(result.as_ref().ok().copied());
        combine_process_and_teardown_results(result, capture_result)
    }
}

impl SeatbeltSandboxProcess {
    /// Kills what the run left running once its child has exited. A failure
    /// becomes a warning so the caller still gets the exit code.
    fn clean_up_after_exit(&mut self) {
        if self.members_cleaned {
            return;
        }
        self.members_cleaned = true;
        if let Err(error) = self.marker.kill_members(exit_cleanup_timeout()) {
            self.cleanup_failures.push(format!(
                "Seatbelt: the process exited, but processes it started could not be \
                 terminated: {error}"
            ));
        }
    }
}

impl Drop for SeatbeltSandboxProcess {
    fn drop(&mut self) {
        // Don't leak a running sandboxed process or a zombie if the handle is
        // dropped without `wait()`, but never block destruction indefinitely
        // when macOS does not make a signalled child reapable.
        const DROP_REAP_TIMEOUT: Duration = Duration::from_secs(5);
        let _ = self.kill();
        let _ = wait_with_timeout(&mut self.child, Some(DROP_REAP_TIMEOUT));
        // Without `wait()` the caller never learns the trace path.
        if let Some(capture) = self.capture.take() {
            let trace_path = capture.trace_path.clone();
            drop(capture);
            if let Some(path) = trace_path {
                let _ = remove_internal_capture_file(&path);
            }
        }
    }
}

/// Build a `Command` that applies the sandbox via `sandbox_init()` in
/// `pre_exec`, then execs `/bin/sh -c <script>`. The child inherits the
/// parent's Mach bootstrap namespace, so both CLI and GUI applications
/// work correctly under the sandbox.
///
/// # Safety
///
/// `pre_exec` runs between `fork()` and `exec()`. Session/PTY setup uses
/// async-signal-safe syscalls before the pre-allocated `sandbox_init` call.
/// `sandbox_init` is not formally async-signal-safe but is used in this
/// pattern by Chromium and other production macOS sandboxes.
fn build_sandbox_command(
    request: &ExecutionRequest,
    proxy_address: Option<&ProxyAddress>,
    new_session: bool,
    marker: &RunMarker,
    pty_size: Option<PtySize>,
    capture_tag: Option<&str>,
    logger: &mut Logger,
) -> Result<(Command, Option<LivePty>), ScriptResponse> {
    let mut command = Command::new(DEFAULT_SHELL);
    command.arg("-c").arg(&request.script_code);

    // When requested (streaming path), put the child in its own session via
    // `setsid()`, away from the host's terminal. This runs before
    // `sandbox_init` so the detach happens regardless of the profile.
    //
    // SAFETY: `setsid` is async-signal-safe and runs after fork(), before
    // exec(); the child is not a process-group leader at this point, so it
    // succeeds.
    if new_session {
        unsafe {
            command.pre_exec(|| {
                libc::setsid();
                Ok(())
            });
        }
    }

    let pty = pty_size
        .map(|size| {
            LivePty::attach(
                &mut command,
                UnixPtySize {
                    rows: size.rows,
                    cols: size.cols,
                    pixel_width: size.pixel_width,
                    pixel_height: size.pixel_height,
                },
                &[],
            )
            .map_err(|error| {
                launch_failed_response(format!("Seatbelt: failed to allocate PTY: {error}"))
            })
        })
        .transpose()?;

    let terminal_paths = match &pty {
        Some(pty) => vec![pty.secondary_path().to_path_buf()],
        None if !new_session => inherited_terminal_paths().map_err(|error| {
            launch_failed_response(format!(
                "Seatbelt: failed to resolve inherited terminals: {error}"
            ))
        })?,
        None => Vec::new(),
    };
    let mut inputs = prepare_profile(request).map_err(profile_error_response)?;
    inputs.capture_tag = capture_tag.map(str::to_string);
    let mut profile =
        build_profile_with_terminals(request, proxy_address, &inputs, &terminal_paths)
            .map_err(profile_error_response)?;
    log_generated_profile(&profile, logger);
    // Last, so neither generated rules nor `profileOverride` can change it.
    let marker_rules = marker.profile_rules();
    log_run_marker_rules(&marker_rules, logger);
    profile.push_str(&marker_rules);
    let profile_cstr = CString::new(profile).map_err(|e| {
        rejected_response(format!("seatbelt profile contains embedded NUL byte: {e}"))
    })?;
    let _ = writeln!(logger, "Seatbelt: applying sandbox via sandbox_init");

    apply_profile_before_exec(&mut command, profile_cstr);

    Ok((command, pty))
}

/// Applies `profile` with `sandbox_init` in the child, after any earlier
/// `pre_exec` hooks and before `exec`.
pub(crate) fn apply_profile_before_exec(command: &mut Command, profile_cstr: CString) {
    // SAFETY: The closure runs after fork(), before exec(). We only call
    // sandbox_init with a pre-allocated CString — no Rust allocations
    // happen inside the closure. sandbox_init is used in this fork+exec
    // pattern by Chromium and other production macOS software.
    unsafe {
        command.pre_exec(move || {
            let mut errorbuf: *mut libc::c_char = std::ptr::null_mut();
            let rc = sandbox_init(profile_cstr.as_ptr(), 0, &mut errorbuf);
            if rc != 0 {
                // Extract error message using only libc calls (no allocation).
                if !errorbuf.is_null() {
                    let msg = CStr::from_ptr(errorbuf);
                    let bytes = msg.to_bytes();
                    // Write directly to stderr fd — no Rust allocation.
                    let prefix = b"Seatbelt: sandbox_init failed: ";
                    libc::write(2, prefix.as_ptr().cast(), prefix.len());
                    libc::write(2, bytes.as_ptr().cast(), bytes.len());
                    libc::write(2, b"\n".as_ptr().cast(), 1);
                    sandbox_free_error(errorbuf);
                }
                return Err(std::io::Error::from_raw_os_error(libc::EPERM));
            }
            Ok(())
        });
    }
}

fn inherited_terminal_paths() -> std::io::Result<Vec<PathBuf>> {
    let (stdin, stdout, stderr) = (std::io::stdin(), std::io::stdout(), std::io::stderr());
    let mut paths = Vec::new();
    for fd in [stdin.as_fd(), stdout.as_fd(), stderr.as_fd()] {
        if fd.is_terminal() {
            let path = nix::unistd::ttyname(fd).map_err(std::io::Error::from)?;
            if !paths.contains(&path) {
                paths.push(path);
            }
        }
    }
    Ok(paths)
}

/// Emit the generated profile to `logger` for `--debug` / `--log-file`.
///
/// One `writeln!` per line, unprefixed: the file sink stamps each write, and
/// keeping the lines verbatim makes the block copy-pasteable into
/// `profileOverride` or `sandbox-exec -f`.
fn log_generated_profile(profile: &str, logger: &mut Logger) {
    let _ = writeln!(logger, "{PROFILE_LOG_BEGIN}");
    for line in profile.lines() {
        let _ = writeln!(logger, "{line}");
    }
    let _ = writeln!(logger, "{PROFILE_LOG_END}");
}

/// Logged outside the copyable block: the rules belong to this run only.
fn log_run_marker_rules(rules: &str, logger: &mut Logger) {
    let _ = writeln!(
        logger,
        "Seatbelt: process cleanup rules for this run, added after the profile above:"
    );
    for line in rules.lines().filter(|line| line.starts_with('(')) {
        let _ = writeln!(logger, "Seatbelt:   {line}");
    }
}

/// A request this backend refuses.
// SDK v2: rejected (policy_validation). See docs/development/plans/sdk-v2-error-codes.md.
fn rejected_response(message: String) -> ScriptResponse {
    ScriptResponse::failed(FailurePhase::None, &message)
}

/// A fault while bringing the sandboxed child up, after the request was
/// accepted.
fn launch_failed_response(message: String) -> ScriptResponse {
    ScriptResponse::failed(FailurePhase::LaunchFailed, &message)
}

fn profile_error_response(error: ProfileError) -> ScriptResponse {
    match error {
        ProfileError::Policy(message) => rejected_response(message),
        ProfileError::Host(message) => launch_failed_response(message),
    }
}

/// The optional run timeout — `None` when `scriptTimeout` is 0 (wait forever).
fn timeout_from(request: &ExecutionRequest) -> Option<Duration> {
    if request.script_timeout == 0 {
        None
    } else {
        Some(Duration::from_millis(u64::from(request.script_timeout)))
    }
}

/// Message for a `Command::spawn` failure, calling out the likely cause
/// (`sandbox_init` rejecting the profile) when the OS reports a permission
/// error.
fn spawn_error(error: &std::io::Error) -> String {
    if error.kind() == std::io::ErrorKind::PermissionDenied {
        format!(
            "failed to spawn sandboxed process (sandbox_init likely rejected \
             the profile — check stderr for details): {error}"
        )
    } else {
        format!("failed to spawn sandboxed process: {error}")
    }
}

/// Where a child is started when the request resolves no directory. The
/// baseline profile always allows `/`, unlike the host process's cwd, which
/// under the deny-by-default profile may be unreadable and make `getcwd()`
/// fail, leaking a "getcwd: … Operation not permitted" line onto the child's
/// stderr. `HOME` deliberately does not follow it here: `/` is not writable.
const UNRESOLVED_WORKING_DIRECTORY: &str = "/";

/// Resolve the working directory for the sandboxed child, or `None` when the
/// request resolves none.
///
/// The same value feeds the environment, so the default `HOME` cannot name a
/// directory the child never entered.
fn resolved_working_directory_opt(
    request: &ExecutionRequest,
) -> Result<Option<String>, ProfileError> {
    let expand = |path: &str| expand_tilde(path).unwrap_or_else(|_| path.to_string());
    let Some(selected) = request
        .resolved_working_directory_with(|path| Path::new(&expand(path)).is_dir())
        .map(|resolved| expand(resolved.path))
    else {
        return Ok(None);
    };
    let absolute = absolute_working_directory(&selected).map_err(|e| {
        ProfileError::Host(format!(
            "failed to read the current directory to anchor the relative seatbelt working directory: {e}"
        ))
    })?;
    // Let the kernel walk the original path so `missing/..` cannot be folded away.
    match std::fs::metadata(&absolute) {
        Ok(meta) if meta.is_dir() => {}
        Ok(_) => {
            return Err(ProfileError::Policy(format!(
                "Seatbelt working directory '{absolute}' is not a directory"
            )))
        }
        Err(e) => {
            return Err(classify_io_error(
                format!("Seatbelt working directory '{absolute}' is not usable: {e}"),
                &e,
            ))
        }
    }
    resolve_policy_path(&absolute)
        .map(Some)
        .map_err(|error| match error {
            ProfileError::Policy(e) => {
                ProfileError::Policy(format!("Seatbelt working directory: {e}"))
            }
            ProfileError::Host(e) => ProfileError::Host(format!("Seatbelt working directory: {e}")),
        })
}

/// Anchor a resolved working directory to the launcher's directory when it is
/// relative.
fn absolute_working_directory(path: &str) -> std::io::Result<String> {
    absolute_working_directory_with(path, std::env::current_dir)
}

/// [`absolute_working_directory`] with an injectable launch directory. Only
/// consulted for a relative value: `chdir` accepts an absolute path even when
/// the launcher's own directory has been removed, so querying it eagerly would
/// reject a request that launches fine.
fn absolute_working_directory_with(
    path: &str,
    launch_dir: impl FnOnce() -> std::io::Result<PathBuf>,
) -> std::io::Result<String> {
    let candidate = Path::new(path);
    if candidate.is_absolute() {
        return Ok(path.to_string());
    }
    Ok(launch_dir()?.join(candidate).to_string_lossy().into_owned())
}

/// Populate `command`'s environment from a cleared baseline: never inherit the
/// host environment (matching the bubblewrap `--clearenv` and AppContainer
/// clean-block behaviour). [`resolved_env`] supplies the complete child
/// environment. When a proxy is active its `HTTP_PROXY` / `HTTPS_PROXY` /
/// `ALL_PROXY` vars are injected and caller-supplied proxy vars stripped (see
/// [`resolve_environment`]). `PWD` is set separately alongside the cwd.
fn apply_clean_environment(
    command: &mut Command,
    request: &ExecutionRequest,
    proxy_address: Option<&ProxyAddress>,
    working_directory: Option<&str>,
) {
    command.env_clear();
    for (key, value) in resolve_environment(request, proxy_address, working_directory) {
        command.env(key, value);
    }
}

/// Compute the final `(key, value)` environment for the sandboxed child: the
/// request's env, followed by the injected proxy vars.
///
/// When `proxy_address` is `Some`, any caller-supplied proxy vars
/// ([`PROXY_ENV_KEYS`]) are dropped so sandboxed code cannot override or
/// bypass the proxy, then the injected keys ([`PROXY_INJECT_KEYS`]:
/// `HTTP_PROXY` / `HTTPS_PROXY` / `ALL_PROXY` and their lowercase forms) are
/// set to the proxy URL.
///
/// `working_directory` is the directory the caller will start the child in, so
/// the default `HOME` names it; see [`resolved_env`].
fn resolve_environment(
    request: &ExecutionRequest,
    proxy_address: Option<&ProxyAddress>,
    working_directory: Option<&str>,
) -> Vec<(String, String)> {
    let resolved = resolved_env(request, working_directory);
    let strip_caller_proxy = proxy_address.is_some();
    let mut pairs: Vec<(String, String)> = env_pairs(&resolved)
        .into_iter()
        .filter(|(key, _)| !strip_caller_proxy || !PROXY_ENV_KEYS.contains(key))
        .map(|(key, value)| (key.to_string(), value.to_string()))
        .collect();
    if let Some(addr) = proxy_address {
        let url = addr.to_url();
        for key in PROXY_INJECT_KEYS {
            pairs.push((key.to_string(), url.clone()));
        }
    }
    pairs
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mxc_common::models::{
        ExecutionRequest, NetworkAction, NetworkEgressPolicy, ProxyAddress, SeatbeltConfig,
    };

    thread_local! {
        /// Shortens cleanup after a normal exit so a test can make it fail.
        pub(super) static EXIT_CLEANUP_TIMEOUT: std::cell::Cell<Option<Duration>> =
            const { std::cell::Cell::new(None) };
    }

    #[allow(clippy::field_reassign_with_default)]
    fn base_request() -> ExecutionRequest {
        let mut request = ExecutionRequest::default();
        request.experimental_enabled = true;
        request.seatbelt = Some(SeatbeltConfig::default());
        request
    }

    fn terminal_probe(
        request: &ExecutionRequest,
        code: &str,
        args: &[&str],
        with_pty: bool,
    ) -> std::process::Output {
        let mut request = request.clone();
        request.script_code = r#"exec /usr/bin/python3 -I -c "$@""#.to_string();
        let mut logger = Logger::new(crate::mxc_common::logger::Mode::Buffer);
        let (mut command, _pty) = build_sandbox_command(
            &request,
            None,
            !with_pty,
            &RunMarker::new().expect("run marker"),
            with_pty.then_some(PtySize::default()),
            None,
            &mut logger,
        )
        .expect("build probe command");
        command
            .arg("terminal-probe")
            .arg(code)
            .args(args)
            .current_dir("/")
            .env_clear()
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        if !with_pty {
            command.stdin(Stdio::null());
        }
        let mut child = command.spawn().expect("spawn terminal probe");
        if let Err(error) = wait_with_timeout(&mut child, Some(Duration::from_secs(20))) {
            let _ = child.kill();
            let _ = child.wait();
            match error {
                WaitError::Timeout => panic!("terminal probe timed out"),
                WaitError::Io(error) => panic!("terminal probe wait failed: {error}"),
            }
        }
        child.wait_with_output().expect("collect terminal probe")
    }

    fn assert_unrelated_terminal_denied(nested_pty: bool, gui_access: bool, with_pty: bool) {
        use std::os::fd::AsRawFd;

        use nix::fcntl::{fcntl, FcntlArg, FdFlag};

        let terminal = nix::pty::openpty(None, None).expect("allocate disposable host PTY");
        for fd in [&terminal.master, &terminal.slave] {
            fcntl(fd.as_raw_fd(), FcntlArg::F_SETFD(FdFlag::FD_CLOEXEC))
                .expect("do not inherit the host PTY");
        }
        let path = nix::unistd::ttyname(&terminal.slave).expect("host PTY path");
        for (read, write) in [(true, false), (false, true), (true, true)] {
            std::fs::OpenOptions::new()
                .read(read)
                .write(write)
                .open(&path)
                .expect("host can open the disposable terminal");
        }
        let mut request = base_request();
        request.seatbelt = Some(SeatbeltConfig {
            nested_pty,
            gui_access,
            ..Default::default()
        });
        request.policy.ui.disable = !gui_access;
        let output = terminal_probe(
            &request,
            r#"
import errno, fcntl, os, sys, termios
for mode in (os.O_RDONLY, os.O_WRONLY, os.O_RDWR):
    try:
        fd = os.open(sys.argv[1], mode | os.O_NOCTTY | os.O_NONBLOCK)
    except OSError as error:
        assert error.errno in (errno.EPERM, errno.EACCES), error
    else:
        os.close(fd)
        raise AssertionError("unrelated terminal opened")
if sys.argv[2] == "allow":
    master, slave = os.openpty()
    try:
        assert os.isatty(slave)
        termios.tcgetattr(slave)
        fcntl.ioctl(slave, termios.TIOCGETD, bytes(4))
    finally:
        os.close(slave)
        os.close(master)
else:
    try:
        master, slave = os.openpty()
    except OSError as error:
        assert error.errno in (errno.EPERM, errno.EACCES), error
    else:
        os.close(slave)
        os.close(master)
        raise AssertionError("nested PTY allocation allowed")
"#,
            &[
                path.to_str().expect("UTF-8 terminal path"),
                if nested_pty || gui_access {
                    "allow"
                } else {
                    "deny"
                },
            ],
            with_pty,
        );
        assert!(
            output.status.success(),
            "terminal isolation probe failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }

    #[test]
    fn nested_pty_cannot_open_unrelated_host_terminals() {
        assert_unrelated_terminal_denied(true, false, false);
    }

    #[test]
    fn nested_pty_disabled_cannot_open_unrelated_host_terminals() {
        assert_unrelated_terminal_denied(false, false, false);
    }

    #[test]
    fn gui_access_cannot_open_unrelated_host_terminals() {
        assert_unrelated_terminal_denied(false, true, false);
    }

    #[test]
    fn caller_owned_pty_cannot_open_unrelated_host_terminals() {
        assert_unrelated_terminal_denied(true, false, true);
    }

    #[test]
    fn preopened_terminal_keeps_stdio_and_controlling_tty() {
        let output = terminal_probe(
            &base_request(),
            r#"
import fcntl, os, termios
assert os.isatty(0)
termios.tcgetattr(0)
fcntl.ioctl(0, termios.TIOCGETD, bytes(4))
fd = os.open("/dev/tty", os.O_RDWR | os.O_NOCTTY)
termios.tcgetattr(fd)
os.close(fd)
"#,
            &[],
            true,
        );
        assert!(
            output.status.success(),
            "assigned terminal probe failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }

    #[test]
    fn gui_access_rejects_caller_owned_pty() {
        let mut logger = Logger::new(crate::mxc_common::logger::Mode::Buffer);
        let error = spawn_exec(
            &base_request(),
            true,
            StdioMode::Pty(PtySize::default()),
            &mut logger,
            None,
        )
        .err()
        .expect("guiAccess PTY must be rejected");
        assert!(error.error_message.contains("caller-owned PTY"));
        assert_eq!(error.failure_phase, FailurePhase::None);
        assert_eq!(error.exit_code, FailurePhase::None.failure_exit_code());
    }

    #[test]
    fn a_failed_launch_keeps_the_generic_backend_error_code() {
        let response = launch_failed_response("failed to spawn sandboxed process".into());
        assert_eq!(response.failure_phase, FailurePhase::LaunchFailed);
        assert_eq!(
            response.failure_phase.error_code(),
            crate::mxc_common::mxc_error::MxcErrorCode::BackendError
        );
        assert_eq!(response.exit_code, -1);
    }

    #[test]
    fn the_default_block_survives_the_proxy_rewrite() {
        // The 0.9 default block must not bypass the proxy stripping in
        // `resolve_environment`.
        let mut request = base_request();
        request.env = Some(vec!["HTTP_PROXY=http://attacker.example:9999".into()]);
        request.inherit_default_env = true;
        let addr = ProxyAddress::new("127.0.0.1".into(), 8888);
        let pairs = resolve_environment(&request, Some(&addr), None);

        assert!(pairs
            .iter()
            .any(|(k, v)| k == "PATH" && v == DEFAULT_SANDBOX_PATH));
        let proxies: Vec<_> = pairs
            .iter()
            .filter(|(k, _)| k == "HTTP_PROXY")
            .map(|(_, v)| v.as_str())
            .collect();
        assert_eq!(proxies, vec!["http://127.0.0.1:8888"]);
    }

    /// Capture what `log_generated_profile` puts into a buffering logger.
    fn logged_profile(profile: &str) -> String {
        use crate::mxc_common::logger::Mode;
        let mut logger = Logger::new(Mode::Buffer);
        log_generated_profile(profile, &mut logger);
        logger.get_buffer().to_string()
    }

    /// Slice the profile back out from between the markers.
    fn extract_profile(log: &str) -> String {
        let body = log
            .split_once(PROFILE_LOG_BEGIN)
            .expect("begin marker missing")
            .1
            .split_once(PROFILE_LOG_END)
            .expect("end marker missing")
            .0;
        body.trim_matches('\n').to_string()
    }

    #[test]
    fn logs_the_profile_verbatim_between_markers() {
        let profile = "(version 1)\n(deny default)\n;; --- comment ---\n(allow file-read*\n    (subpath \"/tmp\")\n)\n";
        assert_eq!(
            extract_profile(&logged_profile(profile)),
            profile.trim_end()
        );
    }

    #[test]
    fn logs_the_profile_one_line_per_write() {
        let profile = "(version 1)\n(deny default)\n(allow process-exec)\n";
        let log = logged_profile(profile);
        assert_eq!(
            log.lines().count(),
            5,
            "expected 3 profile lines plus 2 markers, got: {log}"
        );
    }

    #[test]
    fn profile_markers_cannot_collide_with_profile_content() {
        // Slicing is only sound if no profile line can reproduce a marker.
        for marker in [PROFILE_LOG_BEGIN, PROFILE_LOG_END] {
            assert!(marker.starts_with("Seatbelt: "), "got: {marker}");
            assert!(!marker.starts_with('('), "got: {marker}");
            assert!(!marker.starts_with(";;"), "got: {marker}");
        }
        assert_ne!(PROFILE_LOG_BEGIN, PROFILE_LOG_END);
    }

    #[test]
    fn logs_an_empty_profile_without_losing_the_markers() {
        // `profileOverride: ""` is degenerate but reachable.
        let log = logged_profile("");
        assert!(log.contains(PROFILE_LOG_BEGIN), "got: {log}");
        assert!(log.contains(PROFILE_LOG_END), "got: {log}");
        assert_eq!(extract_profile(&log), "");
    }

    #[test]
    fn logs_the_profile_the_backend_actually_built() {
        // Guards the seam: a re-derived or stale profile must not be logged.
        let mut request = base_request();
        request.policy.readonly_paths = vec!["/tmp/mxc-profile-log-probe".into()];
        let inputs = prepare_profile(&request).expect("profile inputs resolve");
        let profile = build_profile_with_proxy(&request, None, &inputs).expect("profile builds");

        assert_eq!(
            extract_profile(&logged_profile(&profile)),
            profile.trim_end()
        );
        assert!(profile.contains("mxc-profile-log-probe"), "got: {profile}");
    }

    /// Directly constructed requests must receive the same rejection as parsed
    /// requests, before the profile or any proxy is created.
    #[test]
    fn rejects_proxy_with_egress_allow_bypassing_the_parser() {
        let runner = SeatbeltScriptRunner::new();
        let mut request = base_request();
        request.policy.network_egress = Some(NetworkEgressPolicy {
            default: NetworkAction::Allow,
            ..Default::default()
        });
        request.policy.network_proxy.address = Some(ProxyAddress::from_url(
            "http://127.0.0.1:8080",
            "127.0.0.1".into(),
            8080,
        ));
        let err = runner.validate(&request).unwrap_err();
        assert!(
            err.error_message
                .contains("requires network.egress.default='deny'"),
            "{err:?}"
        );
    }

    #[test]
    fn rejects_remote_proxy_under_deny_bypassing_the_parser() {
        let mut request = base_request();
        request.policy.network_proxy.address = Some(ProxyAddress::from_url(
            "http://proxy.corp:3128",
            "proxy.corp".into(),
            3128,
        ));
        let runner = SeatbeltScriptRunner::new();
        let err = runner.validate(&request).unwrap_err();
        assert!(
            err.error_message
                .contains("runtimeConfig.networkProxy must name a loopback endpoint"),
            "{err:?}"
        );
    }

    #[test]
    fn accepts_loopback_proxy_under_deny_in_every_spelling() {
        let runner = SeatbeltScriptRunner::new();
        for host in ["127.0.0.1", "localhost", "[::1]", "::1"] {
            let mut request = base_request();
            request.policy.network_proxy.address = Some(ProxyAddress::from_url(
                "http://proxy:8080",
                host.into(),
                8080,
            ));
            assert!(runner.validate(&request).is_ok(), "rejected {host}");
        }
    }

    #[test]
    fn declares_directional_network_policy_support() {
        let runner = SeatbeltScriptRunner::new();
        let support = runner.network_policy_support();
        assert!(support.contains(NetworkPolicySupport::EGRESS_DEFAULT));
        assert!(support.contains(NetworkPolicySupport::INGRESS_DEFAULT));
        assert!(support.contains(NetworkPolicySupport::HOST_LOOPBACK));
        assert!(support.contains(NetworkPolicySupport::RUNTIME_PROXY));
        // No CIDR/port/protocol rule engine and no ProcessContainer-only
        // per-peer proxy identity concept.
        assert!(!support.contains(NetworkPolicySupport::EGRESS_RULES));
        assert!(!support.contains(NetworkPolicySupport::PROXY_PEER_IDENTITY));
    }

    #[test]
    fn rejects_host_loopback_allow_under_an_ingress_default_deny() {
        // The inexpressible pair: `hostLoopback: allow` promises inbound host
        // loopback, and the rule that would carry it is the blanket
        // `network-inbound` grant that `default: deny` withholds.
        let mut request = base_request();
        request.policy.network_egress =
            Some(crate::mxc_common::models::NetworkEgressPolicy::default());
        request.policy.network_ingress = Some(crate::mxc_common::models::NetworkIngressPolicy {
            default: crate::mxc_common::models::NetworkAction::Deny,
            host_loopback: crate::mxc_common::models::NetworkAction::Allow,
        });
        let runner = SeatbeltScriptRunner::new();
        let response = runner.validate(&request).unwrap_err();
        assert!(response.error_message.contains("hostLoopback='allow'"));
        assert!(response.error_message.contains("default='deny'"));
        assert!(!response.error_message.contains("inherit 'default'"));
        assert_eq!(response.failure_phase, FailurePhase::None);
        assert_eq!(response.exit_code, FailurePhase::None.failure_exit_code());
    }

    /// The other divergent pair is expressible and must be accepted: it is the
    /// only way to ask for a listener while keeping the container-to-host
    /// direction closed, which is what a runtime proxy's egress confinement
    /// rests on.
    #[test]
    fn accepts_host_loopback_deny_under_an_ingress_default_allow() {
        let mut request = base_request();
        request.policy.network_egress =
            Some(crate::mxc_common::models::NetworkEgressPolicy::default());
        request.policy.network_ingress = Some(crate::mxc_common::models::NetworkIngressPolicy {
            default: crate::mxc_common::models::NetworkAction::Allow,
            host_loopback: crate::mxc_common::models::NetworkAction::Deny,
        });
        let runner = SeatbeltScriptRunner::new();
        assert!(runner.validate(&request).is_ok());
    }

    /// The two divergent-pair decisions must survive the exact-contract parse,
    /// not just a hand-built `ContainerPolicy`. An adapter that dropped
    /// `ingress` would leave other backend tests green while silently losing
    /// the posture the caller asked for.
    fn validate_parsed(json: &str) -> Result<(), String> {
        use crate::mxc_common::config_parser::load_mxc_request_from_json;
        use crate::mxc_common::logger::Mode;
        use crate::mxc_common::state_aware_request::MxcRequest;

        let mut logger = Logger::new(Mode::Buffer);
        let parsed = load_mxc_request_from_json(json, &mut logger).expect("config parses");
        let mut request = match parsed {
            MxcRequest::OneShot(request) => request,
            _ => panic!("expected a one-shot request"),
        };
        request.seatbelt.get_or_insert_with(SeatbeltConfig::default);
        SeatbeltScriptRunner::new()
            .validate(&request)
            .map_err(|response| response.error_message)
    }

    fn v09_ingress_config(default: &str, host_loopback: &str) -> String {
        format!(
            r#"{{
                "version": "0.9.0-alpha",
                "containment": "seatbelt",
                "process": {{"commandLine": "echo hi"}},
                "network": {{
                    "egress": {{"default": "deny"}},
                    "ingress": {{"default": "{default}", "hostLoopback": "{host_loopback}"}}
                }}
            }}"#
        )
    }

    #[test]
    fn schema_v09_host_loopback_deny_under_ingress_default_allow_is_accepted() {
        assert!(validate_parsed(&v09_ingress_config("allow", "deny")).is_ok());
    }

    #[test]
    fn schema_v09_host_loopback_allow_under_ingress_default_deny_is_rejected() {
        let message = validate_parsed(&v09_ingress_config("deny", "allow")).unwrap_err();
        assert!(message.contains("hostLoopback='allow'"));
        assert!(message.contains("default='deny'"));
    }

    #[test]
    fn accepts_matching_ingress_default_and_host_loopback() {
        let mut request = base_request();
        request.policy.network_egress =
            Some(crate::mxc_common::models::NetworkEgressPolicy::default());
        request.policy.network_ingress = Some(crate::mxc_common::models::NetworkIngressPolicy {
            default: crate::mxc_common::models::NetworkAction::Allow,
            host_loopback: crate::mxc_common::models::NetworkAction::Allow,
        });
        let runner = SeatbeltScriptRunner::new();
        assert!(runner.validate(&request).is_ok());
    }

    /// Look up the last value set for `key` in a resolved env list.
    fn env_value<'a>(pairs: &'a [(String, String)], key: &str) -> Option<&'a str> {
        pairs
            .iter()
            .rev()
            .find(|(k, _)| k == key)
            .map(|(_, v)| v.as_str())
    }

    #[test]
    fn resolve_environment_without_proxy_passes_through() {
        let mut request = base_request();
        request.env = Some(vec!["FOO=bar".into(), "BAZ=qux".into()]);
        let pairs = resolve_environment(&request, None, None);
        assert_eq!(env_value(&pairs, "FOO"), Some("bar"));
        assert_eq!(env_value(&pairs, "BAZ"), Some("qux"));
        // No proxy vars injected.
        assert!(env_value(&pairs, "HTTP_PROXY").is_none());
    }

    #[test]
    fn resolve_environment_injects_proxy_url() {
        let request = base_request();
        let addr = ProxyAddress::new("127.0.0.1".into(), 8888);
        let pairs = resolve_environment(&request, Some(&addr), None);
        for key in [
            "HTTP_PROXY",
            "HTTPS_PROXY",
            "ALL_PROXY",
            "http_proxy",
            "https_proxy",
            "all_proxy",
        ] {
            assert_eq!(
                env_value(&pairs, key),
                Some("http://127.0.0.1:8888"),
                "{key} must point at the proxy"
            );
        }
    }

    #[test]
    fn resolve_environment_strips_caller_proxy_when_active() {
        let mut request = base_request();
        request.env = Some(vec![
            "HTTP_PROXY=http://attacker.example:9999".into(),
            "https_proxy=http://attacker.example:9999".into(),
            "ALL_PROXY=http://attacker.example:9999".into(),
            "NO_PROXY=localhost".into(),
            "KEEP=me".into(),
        ]);
        let addr = ProxyAddress::new("127.0.0.1".into(), 7777);
        let pairs = resolve_environment(&request, Some(&addr), None);
        // Legitimate non-proxy var is preserved.
        assert_eq!(env_value(&pairs, "KEEP"), Some("me"));
        // Caller-supplied proxy values are overridden with ours; NO_PROXY dropped.
        assert_eq!(
            env_value(&pairs, "HTTP_PROXY"),
            Some("http://127.0.0.1:7777")
        );
        assert_eq!(
            env_value(&pairs, "https_proxy"),
            Some("http://127.0.0.1:7777")
        );
        assert_eq!(
            env_value(&pairs, "ALL_PROXY"),
            Some("http://127.0.0.1:7777")
        );
        assert!(env_value(&pairs, "NO_PROXY").is_none());
        // The attacker's URL must not survive anywhere.
        assert!(!pairs.iter().any(|(_, v)| v.contains("attacker.example")));
    }

    #[test]
    fn resolve_environment_keeps_caller_proxy_when_inactive() {
        // With no proxy active the builder must not touch caller-supplied
        // vars whose keys happen to match PROXY_ENV_KEYS.
        let mut request = base_request();
        request.env = Some(vec!["HTTP_PROXY=http://caller.example:8080".into()]);
        let pairs = resolve_environment(&request, None, None);
        assert_eq!(
            env_value(&pairs, "HTTP_PROXY"),
            Some("http://caller.example:8080")
        );
    }

    /// An explicit directory wins; otherwise the first policy grant is used.
    /// Either is reported as its physical path.
    #[test]
    fn working_directory_resolves_explicit_then_policy_grant() {
        let dir = tempfile::tempdir().unwrap();
        let mut explicit = base_request();
        explicit.working_directory = dir.path().to_str().unwrap().into();
        let real = std::fs::canonicalize(dir.path()).unwrap();
        assert_eq!(
            resolved_working_directory_opt(&explicit)
                .unwrap()
                .as_deref(),
            real.to_str()
        );

        let mut policy_fallback = base_request();
        policy_fallback.policy.readwrite_paths = vec!["/tmp".into()];
        assert_eq!(
            resolved_working_directory_opt(&policy_fallback)
                .unwrap()
                .as_deref(),
            Some("/private/tmp")
        );
    }

    #[test]
    fn a_broken_working_directory_fails_validation() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir(dir.path().join("project")).unwrap();
        std::fs::write(dir.path().join("file"), b"x").unwrap();
        std::os::unix::fs::symlink("missing", dir.path().join("dangling")).unwrap();
        std::os::unix::fs::symlink("loop", dir.path().join("loop")).unwrap();
        for cwd in ["dangling", "loop", "missing", "missing/../project", "file"] {
            let mut request = base_request();
            request.working_directory = dir.path().join(cwd).to_str().unwrap().into();
            let response = SeatbeltScriptRunner::new()
                .validate(&request)
                .expect_err("dry runs must reject an unusable cwd");
            assert_eq!(response.failure_phase, FailurePhase::None, "{cwd}");
            let error = response.error_message;
            assert!(
                error.contains("Seatbelt working directory"),
                "{cwd}: {error}"
            );
        }
    }

    /// With nothing to resolve, the child still has to start somewhere, but
    /// `HOME` must not follow it there: `/` is not writable.
    #[test]
    fn an_unresolved_working_directory_does_not_become_home() {
        let request = base_request();
        assert_eq!(resolved_working_directory_opt(&request), Ok(None));
        assert_eq!(UNRESOLVED_WORKING_DIRECTORY, "/");

        let pairs = resolve_environment(&request, None, None);
        assert_eq!(
            env_value(&pairs, "HOME"),
            None,
            "HOME stays unset when no directory resolves"
        );
    }

    /// `HOME` follows the directory the runner will actually `chdir` into,
    /// including the `~` expansion, rather than being re-derived from the
    /// request.
    #[test]
    fn home_follows_the_directory_the_child_starts_in() {
        let request = base_request();
        let pairs = resolve_environment(&request, None, Some("/Users/someone/work"));
        assert_eq!(env_value(&pairs, "HOME"), Some("/Users/someone/work"));
    }

    /// A relative `process.cwd` is relative to the launching process.
    #[test]
    fn relative_working_directory_is_anchored_to_the_launching_process() {
        let launcher = || Ok(PathBuf::from("/tmp/launcher"));
        assert_eq!(
            absolute_working_directory_with("work", launcher).unwrap(),
            "/tmp/launcher/work"
        );
    }

    /// An absolute directory is passed through spelled exactly as written and
    /// needs no launch directory. `chdir` accepts it even from a launcher
    /// whose own directory has been removed, so a failure to read that
    /// directory must not fail the request: the panicking closure asserts it is
    /// never consulted.
    #[test]
    fn absolute_working_directory_is_left_untouched_without_querying_the_launcher() {
        let unused = || panic!("the launch directory must not be read for an absolute path");
        assert_eq!(
            absolute_working_directory_with("/tmp/mxc_work", unused).unwrap(),
            "/tmp/mxc_work"
        );
    }

    /// A relative value cannot be anchored without the launcher's directory, so
    /// that failure propagates rather than being silently left relative.
    #[test]
    fn relative_working_directory_propagates_a_missing_launch_directory() {
        let gone = || {
            Err(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                "launch directory removed",
            ))
        };
        let err = absolute_working_directory_with("work", gone).unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::NotFound);
    }

    /// Allow mode lets the read through, still lists it, and reports the
    /// written file and retained trace through `output_metadata` once `wait`
    /// returns.
    #[test]
    fn capture_denials_allow_mode_reports_after_wait() {
        use crate::mxc_common::models::{CaptureDenialsConfig, CaptureDenialsMode};

        let directory = tempfile::tempdir().unwrap();
        let directory = std::fs::canonicalize(directory.path()).unwrap();
        let secret = directory.join("secret.txt");
        std::fs::write(&secret, "visible").unwrap();
        let mut request = base_request();
        request.script_code = format!("cat '{}'; exit 3", secret.display());
        request.seatbelt.as_mut().unwrap().capture_denials = Some(CaptureDenialsConfig {
            mode: CaptureDenialsMode::Allow,
            output_path: Some(directory.join("denials.json").display().to_string()),
            retain_etl: true,
        });
        let mut logger = Logger::new(crate::mxc_common::logger::Mode::Buffer);

        let mut process = SeatbeltScriptRunner::new()
            .spawn(&request, &mut logger, StdioMode::Pipes)
            .expect("spawn");
        let mut stdout = String::new();
        std::io::Read::read_to_string(&mut process.take_stdout().unwrap(), &mut stdout).unwrap();
        assert_eq!(process.wait().unwrap(), 3);

        assert_eq!(stdout, "visible");
        assert!(logger.warnings().contains(&ALLOW_MODE_WARNING.to_string()));
        let pointer = process
            .output_metadata()
            .and_then(|metadata| metadata.capture_denials.as_ref())
            .expect("capture pointer");
        let document: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&pointer.output_path).unwrap()).unwrap();
        assert_eq!(document["summary"]["exitCode"], 3);
        assert!(document["denials"]
            .as_array()
            .unwrap()
            .iter()
            .any(|denial| denial["resource"] == secret.display().to_string()
                && denial["accessType"] == "read"));
        let trace = pointer.etl_path.as_deref().expect("etlPath");
        assert_eq!(
            trace,
            pointer.output_path.replace(".json", ".seatbelt.log"),
            "trace shares the report stem"
        );
        let trace = std::fs::read_to_string(trace).unwrap();
        assert!(trace.contains("secret.txt"), "{trace}");
    }

    fn exited_process_with_capture(output_path: PathBuf, retain: bool) -> SeatbeltSandboxProcess {
        let trace_path = retain.then(|| capture_sibling_path(&output_path, TRACE_SUFFIX).unwrap());
        let capture = DenialCapturePlan {
            tag: format!("mxc-capture-{}", random_capture_suffix().unwrap()),
            output_path,
            trace_path,
            allow_mode: false,
        }
        .start()
        .expect("log stream");
        SeatbeltSandboxProcess {
            child: Command::new("/usr/bin/true").spawn().unwrap(),
            stdin: None,
            stdout: None,
            stderr: None,
            stdout_canceller: None,
            stderr_canceller: None,
            pty: None,
            timeout: None,
            started: Instant::now(),
            timed_out: false,
            termination_error: None,
            marker: RunMarker::new().unwrap(),
            members_cleaned: false,
            cleanup_failures: Vec::new(),
            capture: Some(capture),
            capture_error: None,
            capture_warnings: Vec::new(),
            output_metadata: None,
        }
    }

    /// Runs a capture request whose `log stream` is replaced by `log`, checks
    /// that it was rejected before the workload ran, and returns the error.
    fn rejected_capture_start(log: &str, directory: &Path) -> String {
        use crate::mxc_common::models::CaptureDenialsConfig;
        use crate::seatbelt_common::denial_capture::test_tools;

        test_tools::set(test_tools::TestTools {
            log: Some(vec![
                "/bin/sh".to_string(),
                "-c".to_string(),
                log.to_string(),
            ]),
            timeout: Some(Duration::from_secs(1)),
            ..Default::default()
        });
        let sentinel = directory.join("workload-ran");
        let output_dir = directory.join("out");
        std::fs::create_dir(&output_dir).unwrap();
        let mut request = base_request();
        request.script_code = format!("touch '{}'", sentinel.display());
        request.policy.readwrite_paths = vec![directory.display().to_string()];
        request.seatbelt.as_mut().unwrap().capture_denials = Some(CaptureDenialsConfig {
            output_path: Some(output_dir.join("denials.json").display().to_string()),
            retain_etl: true,
            ..Default::default()
        });
        let mut logger = Logger::new(crate::mxc_common::logger::Mode::Buffer);
        let started = Instant::now();

        let error = match SeatbeltScriptRunner::new().spawn(&request, &mut logger, StdioMode::Pipes)
        {
            Ok(_) => panic!("the workload started without a ready log stream"),
            Err(response) => response.error_message,
        };

        assert!(started.elapsed() < Duration::from_secs(5));
        assert!(!sentinel.exists(), "the workload ran");
        let left: Vec<_> = std::fs::read_dir(&output_dir).unwrap().collect();
        assert!(left.is_empty(), "the trace was not removed: {left:?}");
        error
    }

    #[test]
    fn a_log_stream_that_never_becomes_ready_rejects_the_run() {
        let directory = tempfile::tempdir().unwrap();
        let directory = std::fs::canonicalize(directory.path()).unwrap();
        let pid_file = directory.join("collector.pid");

        let error = rejected_capture_start(
            &format!("echo $$ > '{}'; exec /bin/sleep 60", pid_file.display()),
            &directory,
        );

        assert!(error.contains("could not confirm within 1s"), "{error}");
        let pid: libc::pid_t = std::fs::read_to_string(&pid_file)
            .unwrap()
            .trim()
            .parse()
            .unwrap();
        let stopped = (0..100).any(|_| {
            // SAFETY: signal 0 only checks whether the process exists.
            let alive = unsafe { libc::kill(pid, 0) } == 0;
            if alive {
                std::thread::sleep(Duration::from_millis(20));
            }
            !alive
        });
        assert!(stopped, "the stand-in log stream was left running");
    }

    #[test]
    fn a_log_stream_that_exits_before_ready_rejects_the_run() {
        let directory = tempfile::tempdir().unwrap();
        let directory = std::fs::canonicalize(directory.path()).unwrap();

        let error = rejected_capture_start("echo 'log: not permitted' >&2; exit 1", &directory);

        assert!(error.contains("exited unexpectedly"), "{error}");
        assert!(error.contains("log: not permitted"), "{error}");
    }

    #[test]
    fn launch_failure_after_capture_start_removes_trace() {
        let directory = tempfile::tempdir().unwrap();
        let output_path = directory.path().join("denials.json");
        let trace_path = capture_sibling_path(&output_path, TRACE_SUFFIX).unwrap();
        let capture = DenialCapturePlan {
            tag: format!("mxc-capture-{}", random_capture_suffix().unwrap()),
            output_path,
            trace_path: Some(trace_path.clone()),
            allow_mode: false,
        }
        .start()
        .expect("log stream");
        assert!(trace_path.exists());

        let response = discard_capture(
            Some(capture),
            launch_failed_response("spawn failed".to_string()),
        );

        assert_eq!(response.error_message, "spawn failed");
        assert!(!trace_path.exists());
    }

    #[test]
    fn capture_after_termination_failure_skips_report_and_keeps_trace() {
        let directory = tempfile::tempdir().unwrap();
        let output = directory.path().join("denials.json");
        let mut process = exited_process_with_capture(output.clone(), true);
        process.termination_error = Some("session could not be terminated".to_string());

        let error = process.wait().unwrap_err().to_string();

        let trace = directory.path().join("denials.seatbelt.log");
        assert!(error.contains("session could not be terminated"), "{error}");
        assert!(error.contains("did not write a report"), "{error}");
        assert!(error.contains(&trace.display().to_string()), "{error}");
        assert!(trace.exists());
        assert!(!output.exists());
        assert!(!directory.path().join("denials.verbose.json").exists());
        let metadata = process.output_metadata().unwrap();
        assert!(metadata.capture_denials.is_none());
        let failure = metadata.capture_denials_error.as_ref().unwrap();
        assert_eq!(failure.etl_path, trace.display().to_string());
        assert!(failure.message.contains("did not write a report"));
    }

    #[test]
    fn capture_after_exit_cleanup_failure_skips_report_and_keeps_trace() {
        use crate::mxc_common::models::CaptureDenialsConfig;

        let directory = tempfile::tempdir().unwrap();
        let directory = std::fs::canonicalize(directory.path()).unwrap();
        let mut request = base_request();
        // Cleanup finds the leftover sleep, then fails because no time is left.
        request.script_code = "/bin/sleep 30 & exit 0".to_string();
        request.seatbelt.as_mut().unwrap().capture_denials = Some(CaptureDenialsConfig {
            output_path: Some(directory.join("denials.json").display().to_string()),
            retain_etl: true,
            ..Default::default()
        });
        EXIT_CLEANUP_TIMEOUT.set(Some(Duration::ZERO));
        let mut logger = Logger::new(crate::mxc_common::logger::Mode::Buffer);
        let mut process = SeatbeltScriptRunner::new()
            .spawn(&request, &mut logger, StdioMode::Pipes)
            .expect("spawn");

        let error = process.wait().unwrap_err().to_string();

        assert!(error.contains("did not write a report"), "{error}");
        assert!(error.contains("could not be terminated"), "{error}");
        let failure = process
            .output_metadata()
            .and_then(|metadata| metadata.capture_denials_error.as_ref())
            .expect("captureDenialsError");
        assert!(error.contains(&failure.etl_path), "{error}");
        assert!(Path::new(&failure.etl_path).exists());
        let reports: Vec<_> = std::fs::read_dir(&directory)
            .unwrap()
            .map(|entry| entry.unwrap().file_name())
            .filter(|name| name.to_string_lossy().ends_with(".json"))
            .collect();
        assert!(reports.is_empty(), "{reports:?}");
        assert!(process
            .warnings()
            .iter()
            .any(|warning| warning.contains("could not be terminated")));
    }

    #[test]
    fn capture_failure_after_timeout_is_a_warning() {
        let directory = tempfile::tempdir().unwrap();
        let output = directory.path().join("missing").join("denials.json");
        let mut process = exited_process_with_capture(output, false);
        process.timed_out = true;

        let error = process.wait().unwrap_err();

        assert_eq!(error.kind(), std::io::ErrorKind::TimedOut);
        assert!(error.to_string().contains("captureDenials"), "{error}");
        let warnings = process.warnings();
        assert_eq!(warnings.len(), 1, "{warnings:?}");
        assert!(warnings[0].contains("failed after the run timed out"));
        process.wait().unwrap_err();
        assert_eq!(process.warnings().len(), 1, "later waits don't repeat it");
    }

    #[test]
    fn capture_write_failure_is_repeated_by_later_waits() {
        use crate::mxc_common::models::CaptureDenialsConfig;

        let directory = tempfile::tempdir().unwrap();
        let output_dir = directory.path().join("out");
        std::fs::create_dir(&output_dir).unwrap();
        let mut request = base_request();
        request.script_code = "exit 0".to_string();
        request.seatbelt.as_mut().unwrap().capture_denials = Some(CaptureDenialsConfig {
            output_path: Some(output_dir.join("denials.json").display().to_string()),
            ..Default::default()
        });
        let mut logger = Logger::new(crate::mxc_common::logger::Mode::Buffer);
        let mut process = SeatbeltScriptRunner::new()
            .spawn(&request, &mut logger, StdioMode::Pipes)
            .expect("spawn");
        std::fs::remove_dir(&output_dir).unwrap();

        let first = process.wait().expect_err("report write must fail");
        let second = process
            .wait()
            .expect_err("a later wait must not report success");
        assert_eq!(first.to_string(), second.to_string());
        assert!(process.output_metadata().is_none());
    }
}
