// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Reapply the documented security descriptor on `\Device\Null`.
//!
//! See `set-null-acl-plan.md` (Tessera) for full background. Briefly:
//! on downlevel Windows builds that pre-date the
//! `Feature_AgenticAppContainerBfsSupport` ship, AppContainer / LPAC
//! processes cannot open `\Device\Null` — every tool that writes to
//! `NUL` (which is most of them) fails with `ERROR_ACCESS_DENIED`.
//! The fix is to reapply the security descriptor the feature would
//! have set at boot; this module does exactly that and nothing else.
//!
//! The target SD is a literal constant ([`TARGET_SDDL`]); it is
//! re-parsed at runtime via
//! `ConvertStringSecurityDescriptorToSecurityDescriptorW` and compared
//! structurally against the current SD before any write. If the
//! current SD already matches, the apply path is a no-op.
//!
//! Three CLI verbs land here:
//!
//! * [`run_apply`] — `prepare-null-device`
//! * [`run_verify`] — `verify-null-device`
//! * [`run_dump`] — `dump-null-device`
//!
//! No `unprepare` verb: a reboot restores the kernel default SD,
//! which is the documented recovery path.

mod device;
mod privileges;
mod sd;
mod sddl;

#[cfg(test)]
mod tests;

use std::path::PathBuf;

use serde::Serialize;
use serde_json::json;

use crate::log;

/// Error type covering everything the apply / verify / dump paths can
/// fail with. Mapped to numeric exit codes by `cli::run` via
/// [`NullDeviceError::exit_code`].
#[derive(Debug, thiserror::Error)]
pub enum NullDeviceError {
    /// `CreateFileW("\\\\.\\NUL", ...)` failed.
    #[error("could not open \\Device\\Null: {0}")]
    OpenFailed(String),
    /// `SeSecurityPrivilege` is required for SACL writes/reads, and
    /// the current token does not hold it.
    #[error("required privilege missing: {0}")]
    PrivilegeMissing(String),
    /// `GetKernelObjectSecurity` failed.
    #[error("GetKernelObjectSecurity failed: {0}")]
    ReadFailed(String),
    /// `SetKernelObjectSecurity` failed.
    #[error("SetKernelObjectSecurity failed: {0}")]
    WriteFailed(String),
    /// Parsing [`TARGET_SDDL`] failed — should never happen with the
    /// in-tree literal; would indicate a Windows API regression.
    #[error("could not parse target SDDL: {0}")]
    SddlParseFailed(String),
    /// Best-effort serialisation of the current SD back to SDDL
    /// failed (`dump`).
    #[error("could not serialise security descriptor to SDDL: {0}")]
    SddlSerializeFailed(String),
}

impl NullDeviceError {
    fn exit_code(&self) -> i32 {
        match self {
            NullDeviceError::OpenFailed(_) => 2,
            NullDeviceError::PrivilegeMissing(_) => 3,
            NullDeviceError::WriteFailed(_) => 4,
            NullDeviceError::SddlParseFailed(_) => 5,
            NullDeviceError::ReadFailed(_) | NullDeviceError::SddlSerializeFailed(_) => 1,
        }
    }
}

/// Outcome of a `prepare-null-device` invocation; controls the JSON
/// payload and exit code reported to the caller.
#[derive(Debug)]
enum ApplyOutcome {
    /// The current SD already matched the target. No write happened.
    NoChange,
    /// The current SD did not match; the target was applied. Carries
    /// the `Drift` value that drove the apply, for logging.
    Applied { drift: sd::Drift },
    /// The current SD did not match the *target*, but matched the
    /// SACL-stripped target (i.e. we ran with `--no-sacl` and the
    /// current SD has no SACL but its DACL/owner/group already
    /// match). No write happened.
    NoChangeNoSacl,
    /// SACL was skipped (`--no-sacl`); DACL/owner/group differed from
    /// target and were applied.
    AppliedNoSacl { drift: sd::Drift },
}

impl ApplyOutcome {
    fn exit_code(&self) -> i32 {
        match self {
            ApplyOutcome::NoChange | ApplyOutcome::NoChangeNoSacl => 0,
            ApplyOutcome::Applied { .. } | ApplyOutcome::AppliedNoSacl { .. } => 0,
        }
    }

    fn label(&self) -> &'static str {
        match self {
            ApplyOutcome::NoChange => "no-change",
            ApplyOutcome::Applied { .. } => "applied",
            ApplyOutcome::NoChangeNoSacl => "no-change-no-sacl",
            ApplyOutcome::AppliedNoSacl { .. } => "applied-no-sacl",
        }
    }

    /// Human-readable drift label for logging. `"n/a"` when no write
    /// happened.
    fn drift_label(&self) -> &'static str {
        match self {
            ApplyOutcome::NoChange | ApplyOutcome::NoChangeNoSacl => "n/a",
            ApplyOutcome::Applied { drift } | ApplyOutcome::AppliedNoSacl { drift } => {
                drift.label()
            }
        }
    }
}

/// Wire-format record for the `prepare-null-device` JSONL log and
/// (without `ts`) the `--json` stdout payload. Field names here are
/// the public contract for log consumers; see the
/// `apply_log_record_field_names` unit test.
#[derive(Serialize)]
struct ApplyLogRecord<'a> {
    #[serde(skip_serializing_if = "Option::is_none")]
    ts: Option<String>,
    op: &'static str,
    want_sacl: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    result: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    drift: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
}

/// Entry point for the `prepare-null-device` subcommand.
pub fn run_apply(want_sacl: bool, quiet: bool, json: bool, log_path: Option<&str>) -> i32 {
    let log_path = log_path
        .map(PathBuf::from)
        .unwrap_or_else(log::default_null_device_log_path);

    let result = apply(want_sacl);

    match &result {
        Ok(outcome) => {
            let log_rec = ApplyLogRecord {
                ts: Some(now_rfc3339()),
                op: "prepare-null-device",
                want_sacl,
                result: Some(outcome.label()),
                drift: Some(outcome.drift_label()),
                error: None,
            };
            log::append_jsonl(
                &log_path,
                &serde_json::to_string(&log_rec).unwrap_or_default(),
            );
            if json {
                let stdout_rec = ApplyLogRecord {
                    ts: None,
                    op: "prepare-null-device",
                    want_sacl,
                    result: Some(outcome.label()),
                    drift: Some(outcome.drift_label()),
                    error: None,
                };
                println!("{}", serde_json::to_string(&stdout_rec).unwrap_or_default());
            } else if !quiet {
                println!("prepare-null-device: {}", outcome.label());
            }
            outcome.exit_code()
        }
        Err(e) => {
            let log_rec = ApplyLogRecord {
                ts: Some(now_rfc3339()),
                op: "prepare-null-device",
                want_sacl,
                result: None,
                drift: None,
                error: Some(format!("{e}")),
            };
            log::append_jsonl(
                &log_path,
                &serde_json::to_string(&log_rec).unwrap_or_default(),
            );
            eprintln!("error: {e}");
            e.exit_code()
        }
    }
}

/// Entry point for the `verify-null-device` subcommand.
pub fn run_verify(json: bool) -> i32 {
    match verify() {
        Ok(verdict) => {
            if json {
                let rec = json!({
                    "op": "verify-null-device",
                    "drift": verdict.label(),
                });
                println!("{rec}");
            } else {
                println!("verify-null-device: {}", verdict.label());
            }
            match verdict {
                sd::Drift::Match => 0,
                _ => 1,
            }
        }
        Err(e) => {
            eprintln!("error: {e}");
            e.exit_code()
        }
    }
}

/// Entry point for the `dump-null-device` subcommand.
pub fn run_dump(json: bool) -> i32 {
    match dump() {
        Ok(sddl) => {
            if json {
                let rec = json!({
                    "op": "dump-null-device",
                    "sddl": sddl,
                });
                println!("{rec}");
            } else {
                println!("{sddl}");
            }
            0
        }
        Err(e) => {
            eprintln!("error: {e}");
            e.exit_code()
        }
    }
}

fn apply(want_sacl: bool) -> Result<ApplyOutcome, NullDeviceError> {
    if want_sacl {
        privileges::enable_se_security_privilege()?;
    }

    let target = sddl::parse_target_sd()?;

    let h = device::open_null(want_sacl)?;
    let current = sd::read_current_sd(h.as_handle(), want_sacl)?;
    let drift = sd::diff(&current, &target, want_sacl);

    if drift == sd::Drift::Match {
        return Ok(if want_sacl {
            ApplyOutcome::NoChange
        } else {
            ApplyOutcome::NoChangeNoSacl
        });
    }

    sd::write_target_sd(h.as_handle(), &target, want_sacl)?;
    Ok(if want_sacl {
        ApplyOutcome::Applied { drift }
    } else {
        ApplyOutcome::AppliedNoSacl { drift }
    })
}

fn verify() -> Result<sd::Drift, NullDeviceError> {
    // Verify always asks for SACL coverage so it can detect SACL
    // drift. If the caller lacks `SeSecurityPrivilege` the open will
    // fail with `PrivilegeMissing`, which is the right signal.
    privileges::enable_se_security_privilege()?;
    let target = sddl::parse_target_sd()?;
    let h = device::open_null(true)?;
    let current = sd::read_current_sd(h.as_handle(), true)?;
    Ok(sd::diff(&current, &target, true))
}

fn dump() -> Result<String, NullDeviceError> {
    privileges::enable_se_security_privilege()?;
    let h = device::open_null(true)?;
    let current = sd::read_current_sd(h.as_handle(), true)?;
    sd::sd_to_sddl(&current)
}

/// Format the current time as an RFC 3339 UTC timestamp with
/// second precision, e.g. `2026-05-27T03:06:56Z`.
///
/// Pure-std implementation — we don't pull in `chrono`/`time`/`jiff`
/// for a single once-per-boot log line. Uses Howard Hinnant's
/// civil-from-days algorithm to convert the Unix epoch-second to a
/// `(year, month, day)` triple; see
/// <https://howardhinnant.github.io/date_algorithms.html>.
fn now_rfc3339() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    format_epoch_seconds_as_rfc3339(secs)
}

fn format_epoch_seconds_as_rfc3339(secs: u64) -> String {
    let days = (secs / 86_400) as i64;
    let secs_of_day = (secs % 86_400) as u32;
    let hour = secs_of_day / 3600;
    let minute = (secs_of_day % 3600) / 60;
    let second = secs_of_day % 60;

    let (y, m, d) = civil_from_days(days);
    format!("{y:04}-{m:02}-{d:02}T{hour:02}:{minute:02}:{second:02}Z")
}

/// Howard Hinnant's `civil_from_days`. `z` is days since 1970-01-01.
/// Returns `(year, month, day)` in the proleptic Gregorian calendar.
fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u64; // [0, 146096]
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365; // [0, 399]
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100); // [0, 365]
    let mp = (5 * doy + 2) / 153; // [0, 11]
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32; // [1, 31]
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32; // [1, 12]
    let y = if m <= 2 { y + 1 } else { y };
    (y, m, d)
}
