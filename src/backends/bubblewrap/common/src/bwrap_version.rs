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

use std::fmt;
use std::fs::File;
use std::io::{self, Read, Seek};
use std::process::{Command, Output, Stdio};
use std::time::{Duration, Instant};

/// How long a `bwrap` probe may run before it is treated as a failure.
///
/// Platform detection is synchronous, so without a bound a `bwrap` that hangs
/// — a wrapper script on PATH, a binary on a stalled network mount — blocks
/// the caller indefinitely. Mirrors `BWRAP_VERSION_TIMEOUT_MS` in the
/// TypeScript SDK (`sdk/node/src/platform.ts`).
pub const PROBE_TIMEOUT: Duration = Duration::from_secs(5);

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
/// | `--clearenv` (minimal sandbox environment) | **0.5.0** |
///
/// `--clearenv` is therefore the flag that sets the floor. If the argument
/// builder ever adopts a newer flag, raise this constant in the same change.
pub const MIN_BWRAP_VERSION: BwrapVersion = BwrapVersion::new(0, 5, 0);

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
    /// `bwrap` could not be found — the spawn failed with
    /// [`std::io::ErrorKind::NotFound`].
    NotFound,
    /// `bwrap` was found but `bwrap --version` did not complete successfully
    /// (e.g. a permissions problem, a dynamic-loader failure, or a non-zero
    /// exit). Distinct from [`Self::NotFound`] so the reported remediation is
    /// not the misleading "install the package", and so the underlying cause is
    /// preserved rather than discarded.
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
                write!(f, "Bubblewrap (bwrap) is present but `bwrap --version` ")?;
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
                    ". Version {MIN_BWRAP_VERSION} or newer is required; fix the \
                     installation before using the Bubblewrap backend."
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
                 required (the sandbox uses `--clearenv`, added in bwrap 0.5.0). \
                 Upgrade the bubblewrap package."
            ),
        }
    }
}

impl std::error::Error for BwrapUnavailable {}

/// Probe the host for a usable `bwrap`.
///
/// Runs `bwrap --version` and validates the reported version against
/// [`MIN_BWRAP_VERSION`]. Returns the detected version on success.
pub fn probe_bwrap() -> Result<BwrapVersion, BwrapUnavailable> {
    let spawn_failure = |err: io::Error| match err.kind() {
        // `ENOENT` covers both an absent binary and a present-but-unusable
        // one (missing ELF interpreter / shebang target), so confirm the
        // binary is really absent before blaming the package manager.
        io::ErrorKind::NotFound if !bwrap_exists_on_path() => BwrapUnavailable::NotFound,
        _ => BwrapUnavailable::ProbeFailed {
            status: None,
            detail: err.to_string(),
        },
    };

    let mut command = Command::new("bwrap");
    command.arg("--version");
    let output = match run_with_deadline(&mut command, PROBE_TIMEOUT).map_err(spawn_failure)? {
        Some(output) => output,
        None => {
            return Err(BwrapUnavailable::ProbeFailed {
                status: None,
                detail: format!(
                    "did not respond within {}s and was killed",
                    PROBE_TIMEOUT.as_secs()
                ),
            })
        }
    };

    if !output.status.success() {
        return Err(BwrapUnavailable::ProbeFailed {
            status: output.status.code(),
            detail: String::from_utf8_lossy(&output.stderr).trim().to_string(),
        });
    }

    // The version banner goes to stdout; `parse_version` owns its format.
    let stdout = String::from_utf8_lossy(&output.stdout);
    check_version_output(&stdout)
}

/// Run `command` to completion, or kill it and return `None` if it outlives
/// `timeout`.
///
/// Output is collected through temporary files rather than pipes on purpose.
/// A pipe only reaches EOF once *every* write end is closed, so a `bwrap`
/// wrapper that backgrounds a process inheriting stdout would keep a
/// `read_to_end` blocked long after the direct child exited — reintroducing
/// the exact hang this deadline exists to prevent. Reading a file always
/// terminates, and a descendant that keeps writing to it after we return is
/// harmless because the file is already unlinked.
///
/// The timeout path never blocks: the child is signalled and reaped
/// asynchronously, so the deadline holds even against a process the kernel
/// will not interrupt.
pub fn run_with_deadline(command: &mut Command, timeout: Duration) -> io::Result<Option<Output>> {
    const POLL_INTERVAL: Duration = Duration::from_millis(25);

    let stdout = tempfile::tempfile()?;
    let stderr = tempfile::tempfile()?;
    let mut child = command
        .stdin(Stdio::null())
        .stdout(stdout.try_clone()?)
        .stderr(stderr.try_clone()?)
        .spawn()?;

    let deadline = Instant::now() + timeout;
    let outcome = loop {
        match child.try_wait()? {
            Some(status) => break Some(status),
            None if Instant::now() < deadline => std::thread::sleep(POLL_INTERVAL),
            None => {
                let _ = child.kill();
                // Reap on a detached thread rather than blocking here. A
                // process wedged in uninterruptible I/O — the stalled-mount
                // case this deadline exists for — leaves the signal pending,
                // and a `wait()` on it would never return. The thread still
                // collects the zombie once the kernel lets go, but the caller
                // gets its deadline back either way.
                std::thread::spawn(move || {
                    let _ = child.wait();
                });
                break None;
            }
        }
    };

    let Some(status) = outcome else {
        return Ok(None);
    };
    Ok(Some(Output {
        status,
        stdout: read_capped(stdout)?,
        stderr: read_capped(stderr)?,
    }))
}

/// Cap on retained probe output. `bwrap --version` prints one line and a
/// failure prints a short diagnostic, so anything past this is a runaway
/// writer rather than something worth parsing — read a bounded snapshot
/// instead of letting the allocation follow the file.
const MAX_PROBE_OUTPUT: u64 = 64 * 1024;

fn read_capped(mut file: File) -> io::Result<Vec<u8>> {
    file.rewind()?;
    let mut buf = Vec::new();
    file.take(MAX_PROBE_OUTPUT).read_to_end(&mut buf)?;
    Ok(buf)
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

/// Whether a `bwrap` candidate exists anywhere on `PATH`.
///
/// Linux returns `ENOENT` both for a genuinely absent binary and for one that
/// exists but cannot be executed (a missing ELF interpreter or script shebang
/// target), so the spawn error alone cannot tell [`BwrapUnavailable::NotFound`]
/// from [`BwrapUnavailable::ProbeFailed`]. A candidate on `PATH` means the
/// package is installed and the failure is a broken install.
fn bwrap_exists_on_path() -> bool {
    std::env::var_os("PATH")
        .is_some_and(|path| std::env::split_paths(&path).any(|dir| dir.join("bwrap").exists()))
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

    /// A `bwrap` wrapper that backgrounds a process keeps the inherited output
    /// handle open after the direct child exits. Draining a *pipe* in that
    /// situation blocks until the descendant exits, which is how a probe with a
    /// wait deadline can still hang; collecting into a file cannot.
    #[test]
    #[cfg(unix)]
    fn deadline_holds_when_a_descendant_inherits_the_output_handles() {
        let mut command = Command::new("sh");
        command.args(["-c", "sleep 10 & echo 'bubblewrap 0.11.0'"]);

        let started = Instant::now();
        let output = run_with_deadline(&mut command, Duration::from_secs(5))
            .expect("probe should not error")
            .expect("the direct child exits immediately");

        assert!(
            started.elapsed() < Duration::from_secs(5),
            "returned only after {:?}; the descendant blocked the drain",
            started.elapsed()
        );
        assert_eq!(
            String::from_utf8_lossy(&output.stdout).trim(),
            "bubblewrap 0.11.0"
        );
    }

    /// A verbose command must not translate into an allocation that follows
    /// the output. Deliberately bounded so the test cannot fill the disk.
    #[test]
    #[cfg(unix)]
    fn output_beyond_the_cap_is_truncated() {
        let mut command = Command::new("sh");
        command.args(["-c", "yes diagnostic | head -c 200000"]);

        let output = run_with_deadline(&mut command, Duration::from_secs(5))
            .expect("probe should not error")
            .expect("the command exits on its own");

        assert_eq!(
            output.stdout.len() as u64,
            MAX_PROBE_OUTPUT,
            "expected the read to stop at the cap"
        );
    }

    #[test]
    #[cfg(unix)]
    fn deadline_kills_a_command_that_outlives_it() {
        let mut command = Command::new("sh");
        command.args(["-c", "sleep 10"]);

        let started = Instant::now();
        let outcome = run_with_deadline(&mut command, Duration::from_millis(200))
            .expect("probe should not error");

        assert!(outcome.is_none(), "expected the deadline to fire");
        assert!(
            started.elapsed() < Duration::from_secs(5),
            "took {:?} to give up",
            started.elapsed()
        );
    }
}
