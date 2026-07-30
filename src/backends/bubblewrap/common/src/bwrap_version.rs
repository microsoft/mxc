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
use std::process::{Command, Stdio};

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
    let output = Command::new("bwrap")
        .arg("--version")
        .stdin(Stdio::null())
        .output()
        .map_err(|err| match err.kind() {
            // `ENOENT` covers both an absent binary and a present-but-unusable
            // one (missing ELF interpreter / shebang target), so confirm the
            // binary is really absent before blaming the package manager.
            std::io::ErrorKind::NotFound if !bwrap_exists_on_path() => BwrapUnavailable::NotFound,
            _ => BwrapUnavailable::ProbeFailed {
                status: None,
                detail: err.to_string(),
            },
        })?;

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
}
