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
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord)]
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

    /// The major component.
    pub const fn major(&self) -> u32 {
        self.major
    }

    /// The minor component.
    pub const fn minor(&self) -> u32 {
        self.minor
    }

    /// The patch component.
    pub const fn patch(&self) -> u32 {
        self.patch
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
    /// `bwrap --version` could not be executed, or exited non-zero.
    NotFound,
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
        .map_err(|_| BwrapUnavailable::NotFound)?;

    if !output.status.success() {
        return Err(BwrapUnavailable::NotFound);
    }

    // bwrap prints its autotools/meson `PACKAGE_STRING` (e.g. "bubblewrap
    // 0.11.2") on stdout; the leading name has been stable since 0.1.0.
    let stdout = String::from_utf8_lossy(&output.stdout);
    check_version_output(&stdout)
}

/// Validate a raw `bwrap --version` output string against
/// [`MIN_BWRAP_VERSION`]. Split out from [`probe_bwrap`] so the decision logic
/// is testable without a `bwrap` binary on the host.
pub fn check_version_output(output: &str) -> Result<BwrapVersion, BwrapUnavailable> {
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
/// Deliberately lenient about what surrounds the number so distro-patched
/// version strings (`0.4.1-1`, `0.11.0+really0.10.0`, a bare `0.6`) still
/// resolve: the first whitespace-separated token starting with a digit is
/// taken, split on `.`, and each of the (up to three) components contributes
/// its leading digits. Returns `None` when no such token exists.
pub fn parse_version(output: &str) -> Option<BwrapVersion> {
    let token = output
        .split_whitespace()
        .find(|token| token.starts_with(|c: char| c.is_ascii_digit()))?;

    let mut components = token.split('.').map(leading_number);
    let major = components.next().flatten()?;
    let minor = components.next().flatten().unwrap_or(0);
    let patch = components.next().flatten().unwrap_or(0);
    Some(BwrapVersion::new(major, minor, patch))
}

/// Parse the leading run of ASCII digits of `component`, ignoring any suffix
/// (so `"1-1"` yields `1`). Returns `None` when there is no leading digit or
/// the number overflows.
fn leading_number(component: &str) -> Option<u32> {
    let digits: String = component.chars().take_while(char::is_ascii_digit).collect();
    digits.parse().ok()
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
        // Debian-style revision suffix, a "+really" epoch fixup, and a
        // two-component version must all resolve.
        assert_eq!(
            parse_version("bubblewrap 0.4.1-1"),
            Some(BwrapVersion::new(0, 4, 1))
        );
        assert_eq!(
            parse_version("bubblewrap 0.11.0+really0.10.0"),
            Some(BwrapVersion::new(0, 11, 0))
        );
        assert_eq!(
            parse_version("bubblewrap 0.6"),
            Some(BwrapVersion::new(0, 6, 0))
        );
    }

    #[test]
    fn rejects_output_without_a_version() {
        assert_eq!(parse_version(""), None);
        assert_eq!(parse_version("bwrap: command not found"), None);
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
    fn messages_name_the_required_version() {
        for err in [
            BwrapUnavailable::NotFound,
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
}
