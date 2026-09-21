// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Bubblewrap availability + version probing.
//!
//! Presence of `bwrap` on PATH is not sufficient: the argument vector built by
//! [`crate::bwrap_command`] uses flags that were added over the life of the
//! project, so an old `bwrap` would fail at spawn time with an opaque
//! "unknown option" error. This module probes `bwrap --version` once and
//! reports a precise, actionable reason when the host cannot run the backend.
//!
//! The parsing half is pure (no I/O), so it is unit-tested on every host; only
//! [`probe_bwrap`] shells out.

use std::ffi::OsStr;
use std::fmt;
use std::io;
use std::path::Path;
use std::process::Command;
use std::sync::{mpsc, Condvar, Mutex, OnceLock};
use std::thread;
use std::time::{Duration, Instant};

use crate::probe_exec::{self, CapturedOutput};

/// The minimum `bwrap` version the Bubblewrap backend supports.
///
/// This is the oldest release that has **every** flag
/// [`crate::bwrap_command::build_args_classified`] emits. The binding
/// constraints, in order of introduction:
///
/// | Flag         | First `bwrap` release |
/// |--------------|-----------------------|
/// | `--bind`, `--ro-bind`, `--dev`, `--proc`, `--tmpfs`, `--symlink`, `--chdir`, `--setenv`, `--unshare-*` | 0.1.0 |
/// | `--ro-bind-try` (deny-by-default baseline mounts) | 0.3.1 |
/// | `--die-with-parent` (descendants die with the sandbox) | 0.4.0 |
/// | `--clearenv` (minimal sandbox environment) | **0.5.0** |
///
/// `--clearenv` is therefore the flag that sets the floor. If the argument
/// builder ever adopts a newer flag, raise this constant in the same change.
pub const MIN_BWRAP_VERSION: BwrapVersion = BwrapVersion::new(0, 5, 0);

/// Why [`MIN_BWRAP_VERSION`] is the compatibility floor.
pub const MIN_BWRAP_VERSION_REASON: &str = "the sandbox uses `--clearenv`, added in bwrap 0.5.0";

const BWRAP_VERSION_TIMEOUT: Duration = Duration::from_secs(5);
/// The shared probe cap, named locally so the user-facing message can cite it.
const MAX_BWRAP_VERSION_OUTPUT_BYTES: usize = probe_exec::MAX_PROBE_OUTPUT_BYTES;

static CACHED_BWRAP_VERSION: OnceLock<BwrapVersion> = OnceLock::new();
static CACHED_BWRAP_PROBE_GATE: OnceLock<ProbeGate> = OnceLock::new();
static BWRAP_PROBE_GATE: OnceLock<ProbeGate> = OnceLock::new();

fn cached_probe_gate() -> &'static ProbeGate {
    CACHED_BWRAP_PROBE_GATE.get_or_init(ProbeGate::default)
}

fn probe_gate() -> &'static ProbeGate {
    BWRAP_PROBE_GATE.get_or_init(ProbeGate::default)
}

#[derive(Debug, Default)]
struct ProbeGate {
    in_flight: Mutex<bool>,
    available: Condvar,
}

#[derive(Debug)]
struct ProbeGatePermit<'a> {
    gate: &'a ProbeGate,
}

impl Drop for ProbeGatePermit<'_> {
    fn drop(&mut self) {
        self.gate.release();
    }
}

impl ProbeGate {
    fn acquire_until(&self, deadline: Instant) -> bool {
        let mut in_flight = self
            .in_flight
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        loop {
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return false;
            }

            if !*in_flight {
                *in_flight = true;
                return true;
            }

            let (next, wait_result) = self
                .available
                .wait_timeout(in_flight, remaining)
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            in_flight = next;
            if wait_result.timed_out() {
                return false;
            }
        }
    }

    fn release(&self) {
        let mut in_flight = self
            .in_flight
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        *in_flight = false;
        self.available.notify_all();
    }

    fn acquire_permit_until(&self, deadline: Instant) -> Option<ProbeGatePermit<'_>> {
        self.acquire_until(deadline)
            .then_some(ProbeGatePermit { gate: self })
    }
}

/// A `major.minor.patch` Bubblewrap version.
///
/// Ordering is the derived field order (major, then minor, then patch), which
/// is exactly the semantic precedence bwrap releases use.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct BwrapVersion {
    major: u32,
    minor: u32,
    patch: u32,
}

impl BwrapVersion {
    /// Construct a version from its components.
    pub const fn new(major: u32, minor: u32, patch: u32) -> Self {
        Self {
            major,
            minor,
            patch,
        }
    }
}

impl fmt::Display for BwrapVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}.{}.{}", self.major, self.minor, self.patch)
    }
}

/// Why the Bubblewrap backend cannot run on this host.
///
/// [`fmt::Display`] renders the user-facing reason, so callers (the runner's
/// `validate` and the engine's platform probe) share one message source.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BwrapUnavailable {
    /// No `bwrap` executable was found on `PATH`.
    NotFound,
    /// The `bwrap --version` probe failed to start or did not complete
    /// successfully (e.g. a permissions problem or a non-zero exit). Distinct
    /// from [`Self::NotFound`] so observed failures preserve their underlying
    /// cause. An executable found on `PATH` with a missing loader or shebang
    /// target maps here rather than to [`Self::NotFound`].
    ProbeFailed {
        /// Exit status of `bwrap --version`, when the process ran at all.
        status: Option<i32>,
        /// Captured stderr, or the OS error when the process could not start.
        detail: String,
    },
    /// `bwrap --version` ran but printed something we could not parse. We fail
    /// closed here: without a version we cannot assert the required flags exist.
    UnrecognizedVersion(String),
    /// `bwrap` is present but predates [`MIN_BWRAP_VERSION`].
    TooOld(BwrapVersion),
}

impl fmt::Display for BwrapUnavailable {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotFound => write!(
                f,
                "Bubblewrap (bwrap) is not installed or not on PATH. \
                 Install it via your package manager (e.g., apt install bubblewrap). \
                 Version {MIN_BWRAP_VERSION} or newer is required."
            ),
            Self::ProbeFailed { status, detail } => {
                write!(
                    f,
                    "The Bubblewrap (bwrap) availability probe `bwrap --version` "
                )?;
                match status {
                    Some(code) => write!(f, "exited with status {code}")?,
                    // Covers both a spawn failure and termination by a signal,
                    // neither of which yields an exit code.
                    None => write!(f, "failed without an exit status")?,
                }
                if !detail.is_empty() {
                    write!(f, ": {detail}")?;
                }
                write!(
                    f,
                    ". Version {MIN_BWRAP_VERSION} or newer is required; check \
                     PATH and the installation before using the Bubblewrap backend."
                )
            }
            Self::UnrecognizedVersion(output) => write!(
                f,
                "Could not determine the Bubblewrap (bwrap) version: \
                 `bwrap --version` printed {output:?}. \
                 Version {MIN_BWRAP_VERSION} or newer is required."
            ),
            Self::TooOld(found) => write!(
                f,
                "Bubblewrap (bwrap) {found} is too old: version {MIN_BWRAP_VERSION} or newer is \
                 required ({MIN_BWRAP_VERSION_REASON}). \
                 Upgrade the bubblewrap package."
            ),
        }
    }
}

impl std::error::Error for BwrapUnavailable {}

/// Probe the host for a usable `bwrap`.
///
/// Runs `bwrap --version` and validates the reported version against
/// [`MIN_BWRAP_VERSION`]. Successful advisory probes are cached.
pub fn probe_bwrap() -> Result<BwrapVersion, BwrapUnavailable> {
    probe_bwrap_cached(
        &CACHED_BWRAP_VERSION,
        cached_probe_gate(),
        BWRAP_VERSION_TIMEOUT,
        probe_bwrap_uncached_until,
    )
}

fn probe_bwrap_cached<F>(
    cache: &OnceLock<BwrapVersion>,
    gate: &ProbeGate,
    timeout: Duration,
    probe: F,
) -> Result<BwrapVersion, BwrapUnavailable>
where
    F: FnOnce(Instant, Duration) -> Result<BwrapVersion, BwrapUnavailable>,
{
    if let Some(version) = cache.get() {
        return Ok(*version);
    }

    let deadline = Instant::now() + timeout;
    let Some(_permit) = gate.acquire_permit_until(deadline) else {
        return Err(probe_timeout(timeout));
    };
    if let Some(version) = cache.get() {
        return Ok(*version);
    }

    let version = probe(deadline, timeout)?;
    let _ = cache.set(version);
    Ok(version)
}

/// Probe immediately without consulting the advisory success cache.
///
/// Execution validation uses this so a prior platform-support query cannot
/// approve a different executable after `PATH` or its contents change.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
pub(crate) fn probe_bwrap_uncached() -> Result<BwrapVersion, BwrapUnavailable> {
    probe_bwrap_uncached_until(
        Instant::now() + BWRAP_VERSION_TIMEOUT,
        BWRAP_VERSION_TIMEOUT,
    )
}

fn probe_bwrap_uncached_until(
    deadline: Instant,
    timeout: Duration,
) -> Result<BwrapVersion, BwrapUnavailable> {
    probe_bwrap_uncached_with(|| run_bwrap_version_until(deadline, timeout))
}

fn probe_bwrap_uncached_with<F>(run: F) -> Result<BwrapVersion, BwrapUnavailable>
where
    F: FnOnce() -> Result<ProbeOutput, BwrapUnavailable>,
{
    let output = run()?;
    check_probe_output(output)
}

#[derive(Debug)]
struct ProbeOutput {
    success: bool,
    status: Option<i32>,
    stdout: Vec<u8>,
    stderr: Vec<u8>,
}

fn run_bwrap_version_until(
    deadline: Instant,
    timeout: Duration,
) -> Result<ProbeOutput, BwrapUnavailable> {
    let gate = probe_gate();
    let Some(gate_permit) = gate.acquire_permit_until(deadline) else {
        return Err(probe_timeout(timeout));
    };

    let (sender, receiver) = mpsc::sync_channel(1);
    let worker = thread::Builder::new()
        .name("bwrap-probe".to_string())
        .spawn(move || {
            let _gate_permit = gate_permit;
            let result =
                run_version_command_until(Path::new("bwrap"), &["--version"], deadline, timeout);
            let _ = sender.send(result);
        });
    if let Err(err) = worker {
        return Err(BwrapUnavailable::ProbeFailed {
            status: None,
            detail: format!("failed to start the `bwrap --version` probe: {err}"),
        });
    }

    match receiver.recv_timeout(deadline.saturating_duration_since(Instant::now())) {
        Ok(result) => result,
        Err(mpsc::RecvTimeoutError::Timeout) => Err(probe_timeout(timeout)),
        Err(mpsc::RecvTimeoutError::Disconnected) => Err(probe_internal_error(
            "`bwrap --version` probe worker disconnected",
        )),
    }
}

fn probe_timeout(timeout: Duration) -> BwrapUnavailable {
    BwrapUnavailable::ProbeFailed {
        status: None,
        detail: format!("timed out after {}ms", timeout.as_millis()),
    }
}

#[cfg(all(test, unix))]
fn run_version_command_with_timeout(
    executable: &std::path::Path,
    args: &[&str],
    timeout: Duration,
) -> Result<ProbeOutput, BwrapUnavailable> {
    run_version_command_until(executable, args, Instant::now() + timeout, timeout)
}

fn run_version_command_until(
    executable: &Path,
    args: &[&str],
    deadline: Instant,
    timeout: Duration,
) -> Result<ProbeOutput, BwrapUnavailable> {
    // The public probe runs this entire operation in a deadline-watched worker,
    // so PATH lookup and spawn are bounded without assuming a fixed `env` path.
    // `probe_exec` owns the process group, the poll-bounded readers and the
    // termination sweep; this layer only decides what each outcome *means* for
    // `bwrap` specifically.
    let mut command = Command::new(executable);
    command.args(args);

    match probe_exec::run_bounded(&mut command, deadline) {
        Ok(captured) => finish_probe(
            captured.status,
            captured.stdout,
            captured.stderr,
            captured.cleanup_error,
        ),
        Err(probe_exec::ProbeFailure::Spawn(err)) => Err(classify_spawn_failure(executable, err)),
        Err(probe_exec::ProbeFailure::TimedOut { cleanup_error }) => {
            let suffix = cleanup_error
                .map(|err| format!("; failed to terminate it: {err}"))
                .unwrap_or_default();
            Err(BwrapUnavailable::ProbeFailed {
                status: None,
                detail: format!("timed out after {}ms{suffix}", timeout.as_millis()),
            })
        }
        Err(probe_exec::ProbeFailure::Wait { stage, error }) => {
            Err(BwrapUnavailable::ProbeFailed {
                status: None,
                detail: format!("failed while {} `bwrap --version`: {error}", stage.as_str()),
            })
        }
        Err(probe_exec::ProbeFailure::Internal(detail)) => Err(probe_internal_error(&detail)),
    }
}

fn finish_probe(
    status: std::process::ExitStatus,
    stdout: CapturedOutput,
    stderr: CapturedOutput,
    _cleanup_error: Option<io::Error>,
) -> Result<ProbeOutput, BwrapUnavailable> {
    // A completed version command is authoritative. Some setuid bwrap
    // installations reject signalling their post-exit process group with
    // EPERM; that cleanup diagnostic must not turn a valid version into an
    // unavailable backend.
    if stdout.truncated || stderr.truncated {
        return Err(BwrapUnavailable::ProbeFailed {
            status: status.code(),
            detail: format!(
                "`bwrap --version` output exceeded the {} byte limit",
                MAX_BWRAP_VERSION_OUTPUT_BYTES
            ),
        });
    }
    Ok(ProbeOutput {
        success: status.success(),
        status: status.code(),
        stdout: stdout.bytes,
        stderr: stderr.bytes,
    })
}

fn classify_spawn_failure(executable: &Path, err: io::Error) -> BwrapUnavailable {
    if err.kind() != io::ErrorKind::NotFound {
        return BwrapUnavailable::ProbeFailed {
            status: None,
            detail: err.to_string(),
        };
    }

    if executable_mentions_path(executable) {
        return if executable.exists() {
            BwrapUnavailable::ProbeFailed {
                status: None,
                detail: format!(
                    "`{}` was found but could not be executed ({err}); check for a missing interpreter or loader",
                    executable.display()
                ),
            }
        } else {
            BwrapUnavailable::NotFound
        };
    }

    if command_is_on_path(executable) {
        return BwrapUnavailable::ProbeFailed {
            status: None,
            detail: format!(
                "`{}` was found on PATH but could not be executed ({err}); check for a missing interpreter or loader",
                executable.display()
            ),
        };
    }
    BwrapUnavailable::NotFound
}

fn executable_mentions_path(executable: &Path) -> bool {
    executable.is_absolute() || executable.components().count() > 1
}

fn command_is_on_path(executable: &Path) -> bool {
    std::env::var_os("PATH")
        .map(|path| path_contains_executable(executable, &path))
        .unwrap_or(false)
}

fn path_contains_executable(executable: &Path, path: &OsStr) -> bool {
    std::env::split_paths(path).any(|entry| entry.join(executable).is_file())
}

fn probe_internal_error(detail: &str) -> BwrapUnavailable {
    BwrapUnavailable::ProbeFailed {
        status: None,
        detail: detail.to_string(),
    }
}

fn check_probe_output(output: ProbeOutput) -> Result<BwrapVersion, BwrapUnavailable> {
    if !output.success {
        return Err(BwrapUnavailable::ProbeFailed {
            status: output.status,
            detail: String::from_utf8_lossy(&output.stderr).trim().to_string(),
        });
    }

    // The version banner goes to stdout; `parse_version` owns its format.
    let stdout = String::from_utf8_lossy(&output.stdout);
    check_version_output(&stdout)
}

/// Validate a raw `bwrap --version` output string against
/// [`MIN_BWRAP_VERSION`]. Split out from [`probe_bwrap`] so the decision logic
/// is testable without a `bwrap` binary on the host.
fn check_version_output(output: &str) -> Result<BwrapVersion, BwrapUnavailable> {
    let version = parse_version(output)
        .ok_or_else(|| BwrapUnavailable::UnrecognizedVersion(output.trim().to_string()))?;

    if version < MIN_BWRAP_VERSION {
        return Err(BwrapUnavailable::TooOld(version));
    }
    Ok(version)
}

/// Parse the version out of a `bwrap --version` line such as
/// `"bubblewrap 0.11.2"`.
///
/// Anchored on the `bubblewrap` package name, which is what makes unrecognized
/// output fail closed: without it any numeric token in arbitrary output (say
/// `"some other tool 999"`) would be read as a version and clear the
/// minimum-version gate.
///
/// Lenient about what *surrounds* each number so distro-patched version strings
/// (`0.4.1-1`, a bare `0.6`) still resolve: the version token is split on `.`
/// and each of the (up to three) components contributes its leading digits.
/// Debian's `+really` marker is honored rather than ignored — see below.
///
/// Strict about components that are *present but not numeric*: only a component
/// that is genuinely absent defaults to `0`, so `"0.6.invalid"` is rejected
/// rather than silently read as `0.6.0`. Returns `None` whenever the version
/// cannot be determined, which callers treat as fail-closed.
fn parse_version(output: &str) -> Option<BwrapVersion> {
    // bwrap prints its autotools/meson `PACKAGE_STRING` — "bubblewrap <version>"
    // — and that leading name has been stable since 0.1.0.
    let mut tokens = output.split_whitespace();
    if !tokens.next()?.eq_ignore_ascii_case("bubblewrap") {
        return None;
    }
    let token = tokens.next()?;

    // Debian's `+really` marker means the package ships the version that
    // FOLLOWS it (used when a maintainer must ship an older upstream without
    // decreasing the package version). Reading the leading version would
    // over-report: `0.5.0+really0.4.1` is really 0.4.1, which predates
    // `--clearenv` and must not clear the gate.
    let token = token.rsplit_once("+really").map_or(token, |(_, real)| real);

    // `map_or(Some(0), ..)` is the absent-vs-unreadable split: an exhausted
    // iterator yields 0, a component `leading_number` rejects fails the parse.
    let mut components = token.split('.');
    let major = leading_number(components.next()?)?;
    let minor = components.next().map_or(Some(0), leading_number)?;
    let patch = components.next().map_or(Some(0), leading_number)?;

    // Components past the patch are not significant, but they must still look
    // like a version: `0.5.0.invalid` is an unrecognized banner, not 0.5.0.
    // Checking them (rather than rejecting on count) keeps a distro four-part
    // build such as `0.6.0.1` working.
    if !components.all(|extra| leading_number(extra).is_some()) {
        return None;
    }
    Some(BwrapVersion::new(major, minor, patch))
}

/// Parse the leading run of ASCII digits of `component`, ignoring any suffix
/// (so `"1-1"` yields `1`). Returns `None` when there is no leading digit or
/// the number overflows.
fn leading_number(component: &str) -> Option<u32> {
    let end = component
        .find(|c: char| !c.is_ascii_digit())
        .unwrap_or(component.len());
    component[..end].parse().ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_standard_version_output() {
        assert_eq!(
            parse_version("bubblewrap 0.11.2\n"),
            Some(BwrapVersion::new(0, 11, 2))
        );
    }

    #[test]
    fn parses_distro_patched_and_short_versions() {
        // Debian-style revision suffix and a two-component version.
        assert_eq!(
            parse_version("bubblewrap 0.4.1-1"),
            Some(BwrapVersion::new(0, 4, 1))
        );
        assert_eq!(
            parse_version("bubblewrap 0.6"),
            Some(BwrapVersion::new(0, 6, 0))
        );
    }

    #[test]
    fn honors_the_debian_really_marker() {
        // `X+reallyY` ships upstream Y, not X, so Y is the effective version.
        assert_eq!(
            parse_version("bubblewrap 0.11.0+really0.10.0"),
            Some(BwrapVersion::new(0, 10, 0))
        );
        assert_eq!(
            parse_version("bubblewrap 0.11.0+really0.10.0-1"),
            Some(BwrapVersion::new(0, 10, 0))
        );
    }

    #[test]
    fn really_marker_cannot_smuggle_a_below_floor_version_past_the_gate() {
        // Regression: reading the leading version accepted this as 0.5.0, even
        // though the installed bwrap is 0.4.1 and has no `--clearenv`.
        assert_eq!(
            check_version_output("bubblewrap 0.5.0+really0.4.1"),
            Err(BwrapUnavailable::TooOld(BwrapVersion::new(0, 4, 1)))
        );
    }

    #[test]
    fn rejects_output_without_a_version() {
        assert_eq!(parse_version(""), None);
        assert_eq!(parse_version("bwrap: command not found"), None);
    }

    #[test]
    fn rejects_present_but_nonnumeric_components() {
        // A component that exists but has no leading digit must fail closed
        // rather than silently defaulting to 0 — "0.6.invalid" is not 0.6.0.
        assert_eq!(parse_version("bubblewrap 0.6.invalid"), None);
        assert_eq!(parse_version("bubblewrap 0.beta.1"), None);
        assert_eq!(parse_version("bubblewrap 0.6."), None);
        // ...but a genuinely absent component still defaults to 0.
        assert_eq!(
            parse_version("bubblewrap 1"),
            Some(BwrapVersion::new(1, 0, 0))
        );
    }

    #[test]
    fn rejects_junk_after_the_patch_component() {
        // Regression: components past the patch were dropped unchecked, so
        // "0.5.0.invalid" cleared the gate as 0.5.0.
        assert_eq!(parse_version("bubblewrap 0.5.0.invalid"), None);
        assert_eq!(
            check_version_output("bubblewrap 0.5.0.invalid"),
            Err(BwrapUnavailable::UnrecognizedVersion(
                "bubblewrap 0.5.0.invalid".to_string()
            ))
        );
        // A numeric fourth component is a plausible distro build, not junk.
        assert_eq!(
            parse_version("bubblewrap 0.6.0.1"),
            Some(BwrapVersion::new(0, 6, 0))
        );
    }

    #[test]
    fn rejects_components_that_overflow_u32() {
        // Shared contract with the SDK parser: an out-of-range component is a
        // malformed banner, not a very new bwrap. Both sides must fail closed
        // so the SDK gate cannot admit what this one rejects.
        assert_eq!(parse_version("bubblewrap 99999999999999999999.0.0"), None);
        assert_eq!(parse_version("bubblewrap 0.4294967296.0"), None);
        assert_eq!(
            parse_version("bubblewrap 4294967295.0.0"),
            Some(BwrapVersion::new(4_294_967_295, 0, 0))
        );
    }

    #[test]
    fn ordering_is_semantic() {
        assert!(BwrapVersion::new(0, 4, 9) < BwrapVersion::new(0, 5, 0));
        assert!(BwrapVersion::new(0, 11, 0) > BwrapVersion::new(0, 9, 9));
        assert!(BwrapVersion::new(1, 0, 0) > BwrapVersion::new(0, 99, 99));
    }

    #[test]
    fn accepts_minimum_and_newer_versions() {
        assert_eq!(
            check_version_output("bubblewrap 0.5.0"),
            Ok(MIN_BWRAP_VERSION)
        );
        assert_eq!(
            check_version_output("bubblewrap 0.11.2"),
            Ok(BwrapVersion::new(0, 11, 2))
        );
    }

    #[test]
    fn rejects_versions_below_the_minimum() {
        // 0.4.1 has `--ro-bind-try` but not `--clearenv`.
        assert_eq!(
            check_version_output("bubblewrap 0.4.1"),
            Err(BwrapUnavailable::TooOld(BwrapVersion::new(0, 4, 1)))
        );
    }

    #[test]
    fn fails_closed_on_unparsable_output() {
        assert_eq!(
            check_version_output("some other tool\n"),
            Err(BwrapUnavailable::UnrecognizedVersion(
                "some other tool".to_string()
            ))
        );
    }

    #[test]
    fn fails_closed_on_a_stray_number_in_unrelated_output() {
        // Regression: searching for any numeric token let unrelated output
        // clear the gate — "some other tool 999" parsed as 999.0.0. Anchoring
        // on the `bubblewrap` package name is what keeps this fail-closed.
        assert_eq!(parse_version("some other tool 999"), None);
        assert_eq!(parse_version("bwrap 0.11.2"), None);
        assert_eq!(
            check_version_output("some other tool 999"),
            Err(BwrapUnavailable::UnrecognizedVersion(
                "some other tool 999".to_string()
            ))
        );
    }

    #[test]
    fn messages_name_the_required_version() {
        for err in [
            BwrapUnavailable::NotFound,
            BwrapUnavailable::ProbeFailed {
                status: Some(126),
                detail: "permission denied".to_string(),
            },
            BwrapUnavailable::UnrecognizedVersion("junk".to_string()),
            BwrapUnavailable::TooOld(BwrapVersion::new(0, 4, 1)),
        ] {
            let message = err.to_string();
            assert!(
                message.contains(&MIN_BWRAP_VERSION.to_string()),
                "message should name the minimum version: {message}"
            );
        }
    }

    #[test]
    fn probe_failure_message_preserves_status_and_stderr() {
        // A broken-but-present bwrap must not be reported as "not installed":
        // that remediation would send the user to their package manager for a
        // package they already have.
        let message = BwrapUnavailable::ProbeFailed {
            status: Some(126),
            detail: "bwrap: permission denied".to_string(),
        }
        .to_string();
        assert!(message.contains("126"), "status should survive: {message}");
        assert!(
            message.contains("bwrap: permission denied"),
            "stderr should survive: {message}"
        );
        assert!(
            !message.contains("not installed"),
            "must not claim the package is missing: {message}"
        );
    }

    #[test]
    fn probe_failure_message_handles_a_missing_status() {
        // Spawn failures that are not `NotFound` (permissions, loader errors)
        // and signal-terminated runs both lack an exit status, so the wording
        // must not claim the process never ran.
        let message = BwrapUnavailable::ProbeFailed {
            status: None,
            detail: "Permission denied (os error 13)".to_string(),
        }
        .to_string();
        assert!(
            message.contains("failed without an exit status"),
            "should describe the missing status: {message}"
        );
        assert!(
            message.contains("os error 13"),
            "OS error should survive: {message}"
        );
    }

    #[test]
    fn probe_gate_serializes_callers_within_their_deadline() {
        let gate = std::sync::Arc::new(ProbeGate::default());
        assert!(gate.acquire_until(Instant::now() + Duration::from_secs(1)));

        let waiting_gate = std::sync::Arc::clone(&gate);
        let (waiting_tx, waiting_rx) = mpsc::channel();
        let waiter = thread::spawn(move || {
            waiting_tx.send(()).unwrap();
            let acquired = waiting_gate.acquire_until(Instant::now() + Duration::from_secs(5));
            if acquired {
                waiting_gate.release();
            }
            acquired
        });

        waiting_rx.recv().unwrap();
        gate.release();
        assert!(waiter.join().unwrap());
    }

    #[test]
    fn probe_gate_does_not_create_a_retry_after_the_deadline() {
        let gate = ProbeGate::default();
        assert!(gate.acquire_until(Instant::now() + Duration::from_millis(25)));
        assert!(!gate.acquire_until(Instant::now() + Duration::from_millis(10)));
        gate.release();
    }

    #[test]
    fn probe_gate_permit_releases_on_panic() {
        let gate = std::sync::Arc::new(ProbeGate::default());
        let panicking_gate = std::sync::Arc::clone(&gate);
        let worker = thread::spawn(move || {
            let _permit = panicking_gate
                .acquire_permit_until(Instant::now() + Duration::from_millis(50))
                .expect("permit should be acquired");
            panic!("simulated panic while probe is in-flight");
        });
        assert!(worker.join().is_err());

        assert!(
            gate.acquire_until(Instant::now() + Duration::from_millis(50)),
            "panic should release the gate"
        );
        gate.release();
    }

    #[cfg(unix)]
    #[test]
    fn missing_binary_spawn_failure_is_classified_as_not_found() {
        // A spawn failure with ENOENT means the binary is absent from PATH.
        // Regression: when the probe used `/usr/bin/env bwrap`, a missing
        // `/usr/bin/env` (e.g. NixOS) produced ProbeFailed instead of NotFound.
        let error = run_version_command_with_timeout(
            std::path::Path::new("this-binary-does-not-exist-on-any-path"),
            &["--version"],
            Duration::from_secs(1),
        )
        .unwrap_err();
        assert_eq!(error, BwrapUnavailable::NotFound);
    }

    #[cfg(unix)]
    #[test]
    fn expired_deadline_does_not_launch_the_probe_command() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().unwrap();
        let script = dir.path().join("bwrap");
        let marker = dir.path().join("launched");
        std::fs::write(&script, "#!/bin/sh\nprintf launched > \"$1\"\n").unwrap();
        let mut permissions = std::fs::metadata(&script).unwrap().permissions();
        permissions.set_mode(0o755);
        std::fs::set_permissions(&script, permissions).unwrap();

        let marker_arg = marker.to_string_lossy();
        let timeout = Duration::from_millis(50);
        let error = run_version_command_until(
            &script,
            &[marker_arg.as_ref()],
            Instant::now() - Duration::from_millis(1),
            timeout,
        )
        .unwrap_err();

        assert_eq!(error, probe_timeout(timeout));
        assert!(
            !marker.exists(),
            "an expired worker launched the probe command after the caller returned"
        );
    }

    #[cfg(unix)]
    #[test]
    fn missing_interpreter_is_classified_as_probe_failure() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().unwrap();
        let script = dir.path().join("bwrap");
        std::fs::write(&script, "#!/this/interpreter/does/not/exist\nexit 0\n").unwrap();
        let mut permissions = std::fs::metadata(&script).unwrap().permissions();
        permissions.set_mode(0o755);
        std::fs::set_permissions(&script, permissions).unwrap();

        let error =
            run_version_command_with_timeout(&script, &["--version"], Duration::from_secs(1))
                .unwrap_err();
        assert!(matches!(
            error,
            BwrapUnavailable::ProbeFailed { status: None, detail }
                if detail.contains("missing interpreter or loader")
        ));
    }

    #[cfg(unix)]
    #[test]
    fn subprocess_probe_preserves_reader_results_until_all_are_ready() {
        for _ in 0..50 {
            let output = run_version_command_with_timeout(
                std::path::Path::new("/bin/sh"),
                &["-c", "printf 'bubblewrap 0.5.0\\n'"],
                Duration::from_secs(1),
            )
            .unwrap();
            assert_eq!(check_probe_output(output), Ok(MIN_BWRAP_VERSION));
        }
    }

    #[cfg(unix)]
    #[test]
    fn subprocess_probe_times_out_and_terminates_the_child() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().unwrap();
        let script = dir.path().join("bwrap");
        std::fs::write(&script, "#!/bin/sh\nwhile true; do :; done\n").unwrap();
        let mut permissions = std::fs::metadata(&script).unwrap().permissions();
        permissions.set_mode(0o755);
        std::fs::set_permissions(&script, permissions).unwrap();

        let error =
            run_version_command_with_timeout(&script, &["--version"], Duration::from_millis(250))
                .unwrap_err();
        assert!(matches!(
            error,
            BwrapUnavailable::ProbeFailed {
                status: None,
                detail,
            } if detail.contains("timed out after 250ms")
        ));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn subprocess_probe_terminates_a_descendant_holding_the_pipes_open() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().unwrap();
        let script = dir.path().join("bwrap");
        std::fs::write(
            &script,
            "#!/bin/sh\n(while true; do :; done) &\necho 'bubblewrap 0.5.0'\nexit 0\n",
        )
        .unwrap();
        let mut permissions = std::fs::metadata(&script).unwrap().permissions();
        permissions.set_mode(0o755);
        std::fs::set_permissions(&script, permissions).unwrap();

        let started = Instant::now();
        let output =
            run_version_command_with_timeout(&script, &["--version"], Duration::from_millis(30))
                .unwrap();
        assert!(started.elapsed() < Duration::from_secs(1));
        assert_eq!(check_probe_output(output), Ok(MIN_BWRAP_VERSION));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn subprocess_probe_terminates_a_descendant_with_closed_pipes() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().unwrap();
        let script = dir.path().join("bwrap");
        let pid_file = dir.path().join("descendant.pid");
        std::fs::write(
            &script,
            "#!/bin/sh\n(while true; do :; done) >/dev/null 2>&1 &\necho \"$!\" > \"$1\"\necho 'bubblewrap 0.5.0'\nexit 0\n",
        )
        .unwrap();
        let mut permissions = std::fs::metadata(&script).unwrap().permissions();
        permissions.set_mode(0o755);
        std::fs::set_permissions(&script, permissions).unwrap();

        let pid_file_arg = pid_file.to_string_lossy();
        let output = run_version_command_with_timeout(
            &script,
            &[pid_file_arg.as_ref()],
            Duration::from_secs(1),
        )
        .unwrap();
        assert_eq!(check_probe_output(output), Ok(MIN_BWRAP_VERSION));

        let pid: u32 = std::fs::read_to_string(pid_file)
            .unwrap()
            .trim()
            .parse()
            .unwrap();
        let poll_deadline = Instant::now() + Duration::from_secs(1);
        let terminated = loop {
            let terminated = match std::fs::read_to_string(format!("/proc/{pid}/stat")) {
                Ok(stat) => {
                    stat.rfind(") ")
                        .and_then(|index| stat[index + 2..].chars().next())
                        == Some('Z')
                }
                Err(err) if err.kind() == io::ErrorKind::NotFound => true,
                Err(err) => panic!("failed to inspect probe descendant {pid}: {err}"),
            };
            if terminated || Instant::now() >= poll_deadline {
                break terminated;
            }
            thread::sleep(Duration::from_millis(10));
        };
        assert!(terminated, "probe descendant {pid} is still running");
    }

    #[test]
    fn uncached_probe_maps_injected_process_outcomes() {
        let version = probe_bwrap_uncached_with(|| {
            Ok(ProbeOutput {
                success: true,
                status: Some(0),
                stdout: b"bubblewrap 0.5.0\n".to_vec(),
                stderr: Vec::new(),
            })
        })
        .unwrap();
        assert_eq!(version, MIN_BWRAP_VERSION);

        let failure = BwrapUnavailable::ProbeFailed {
            status: Some(126),
            detail: "permission denied".to_string(),
        };
        assert_eq!(
            probe_bwrap_uncached_with(|| Err(failure.clone())),
            Err(failure)
        );
    }

    #[test]
    fn probe_output_preserves_nonzero_status_and_stderr() {
        let error = check_probe_output(ProbeOutput {
            success: false,
            status: Some(126),
            stdout: Vec::new(),
            stderr: b"permission denied".to_vec(),
        })
        .unwrap_err();
        assert!(matches!(
            error,
            BwrapUnavailable::ProbeFailed {
                detail,
                ..
            } if detail == "permission denied"
        ));
    }

    #[cfg(unix)]
    #[test]
    fn successful_probe_ignores_post_exit_group_cleanup_failure() {
        use std::os::unix::process::ExitStatusExt;

        let output = finish_probe(
            std::process::ExitStatus::from_raw(0),
            CapturedOutput {
                bytes: b"bubblewrap 0.5.0\n".to_vec(),
                truncated: false,
            },
            CapturedOutput {
                bytes: Vec::new(),
                truncated: false,
            },
            Some(io::Error::from_raw_os_error(nix::libc::EPERM)),
        )
        .unwrap();
        assert_eq!(check_probe_output(output), Ok(MIN_BWRAP_VERSION));
    }

    #[test]
    fn successful_probe_result_is_cached() {
        let cache = OnceLock::new();
        let gate = ProbeGate::default();
        let first = probe_bwrap_cached(&cache, &gate, Duration::from_secs(1), |_, _| {
            Ok(MIN_BWRAP_VERSION)
        })
        .unwrap();
        assert_eq!(first, MIN_BWRAP_VERSION);

        let second = probe_bwrap_cached(&cache, &gate, Duration::from_secs(1), |_, _| {
            panic!("successful probe should be reused from the cache")
        })
        .unwrap();
        assert_eq!(second, MIN_BWRAP_VERSION);
    }

    #[test]
    fn expired_probe_gate_deadline_does_not_start_probe() {
        let gate = ProbeGate::default();
        assert!(gate
            .acquire_permit_until(Instant::now() - Duration::from_millis(1))
            .is_none());
        assert!(!*gate
            .in_flight
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner()));
    }

    #[test]
    fn failed_probe_result_is_not_cached() {
        let cache = OnceLock::new();
        let gate = ProbeGate::default();
        assert_eq!(
            probe_bwrap_cached(&cache, &gate, Duration::from_secs(1), |_, _| {
                Err(BwrapUnavailable::NotFound)
            }),
            Err(BwrapUnavailable::NotFound)
        );
        assert_eq!(
            probe_bwrap_cached(&cache, &gate, Duration::from_secs(1), |_, _| {
                Ok(MIN_BWRAP_VERSION)
            }),
            Ok(MIN_BWRAP_VERSION)
        );
    }

    #[test]
    fn concurrent_cached_callers_reuse_the_first_success() {
        let cache = std::sync::Arc::new(OnceLock::new());
        let gate = std::sync::Arc::new(ProbeGate::default());
        let (started_tx, started_rx) = mpsc::channel();
        let synchronization = std::sync::Arc::new(std::sync::Barrier::new(2));
        let first_cache = std::sync::Arc::clone(&cache);
        let first_gate = std::sync::Arc::clone(&gate);
        let first_synchronization = std::sync::Arc::clone(&synchronization);
        let first = thread::spawn(move || {
            probe_bwrap_cached(&first_cache, &first_gate, Duration::from_secs(1), |_, _| {
                started_tx.send(()).unwrap();
                first_synchronization.wait();
                Ok(MIN_BWRAP_VERSION)
            })
        });

        started_rx.recv().unwrap();
        let second_cache = std::sync::Arc::clone(&cache);
        let second_gate = std::sync::Arc::clone(&gate);
        let second_synchronization = std::sync::Arc::clone(&synchronization);
        let second = thread::spawn(move || {
            second_synchronization.wait();
            probe_bwrap_cached(
                &second_cache,
                &second_gate,
                Duration::from_secs(1),
                |_, _| panic!("queued advisory caller should reuse the first success"),
            )
        });

        assert_eq!(first.join().unwrap(), Ok(MIN_BWRAP_VERSION));
        assert_eq!(second.join().unwrap(), Ok(MIN_BWRAP_VERSION));
    }

    #[test]
    fn concurrent_cached_callers_remain_deadline_bounded_after_failure() {
        let cache = std::sync::Arc::new(OnceLock::new());
        let gate = std::sync::Arc::new(ProbeGate::default());
        let (started_tx, started_rx) = mpsc::channel();
        let (release_tx, release_rx) = mpsc::channel();
        let first_cache = std::sync::Arc::clone(&cache);
        let first_gate = std::sync::Arc::clone(&gate);
        let first = thread::spawn(move || {
            probe_bwrap_cached(&first_cache, &first_gate, Duration::from_secs(1), |_, _| {
                started_tx.send(()).unwrap();
                release_rx.recv().unwrap();
                Err(BwrapUnavailable::NotFound)
            })
        });

        started_rx.recv().unwrap();
        let timeout = Duration::from_millis(50);
        let started = Instant::now();
        let second = probe_bwrap_cached(&cache, &gate, timeout, |_, _| {
            panic!("caller whose cache wait expired must not start a probe")
        });
        assert_eq!(second, Err(probe_timeout(timeout)));
        assert!(
            started.elapsed() < Duration::from_secs(5),
            "cache wait exceeded its deadline by an unreasonable margin"
        );

        release_tx.send(()).unwrap();
        assert_eq!(first.join().unwrap(), Err(BwrapUnavailable::NotFound));
    }
}
