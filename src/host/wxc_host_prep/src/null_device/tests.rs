// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Unit tests for the null-device module.
//!
//! Tests that *don't* require admin or mutate `\Device\Null`:
//!
//! * SDDL round-trip parses cleanly.
//! * `diff` of identical SDs returns `Match`.
//! * `diff` against an empty SD returns the appropriate `OwnerDiffers`.
//!
//! Tests that *do* mutate machine state (apply / verify against the
//! real `\Device\Null`) live in
//! `wxc_host_prep/tests/null_device_integration.rs` behind `#[ignore]`.

use super::*;

#[test]
fn target_sddl_parses() {
    let sd = sddl::parse_target_sd().expect("target SDDL must parse");
    // Round-trip back to SDDL to prove the parse produced a usable SD.
    let s = sd::sd_to_sddl(&sd).expect("serialise back to SDDL");
    // Windows canonicalises the rights letters of an allow ACE to
    // X-then-W-then-R order, so the target's literal `GRGWGX` comes
    // back as `GXGWGR`. Substring checks below match the canonical
    // output, not the source SDDL.
    assert!(s.contains("(A;;GXGWGR;;;WD)"), "missing WD allow ACE: {s}");
    assert!(s.contains("(A;;FA;;;SY)"), "missing SY full-access: {s}");
    assert!(s.contains("(A;;FA;;;BA)"), "missing BA full-access: {s}");
    assert!(s.contains("(A;;GXGR;;;RC)"), "missing RC allow ACE: {s}");
    assert!(s.contains("(A;;GXGWGR;;;AC)"), "missing AC allow ACE: {s}");
    assert!(
        s.contains("(A;;GXGWGR;;;S-1-15-2-2)"),
        "missing S-1-15-2-2 allow ACE: {s}"
    );
    assert!(s.contains("(ML;;NW;;;LW)"), "missing mandatory label: {s}");
}

#[test]
fn diff_of_target_with_itself_is_match() {
    let a = sddl::parse_target_sd().expect("parse target");
    let b = sddl::parse_target_sd().expect("parse target");
    assert_eq!(sd::diff(&a, &b, true), sd::Drift::Match);
    assert_eq!(sd::diff(&a, &b, false), sd::Drift::Match);
}

#[test]
fn drift_label_strings_are_stable() {
    // Wire-format guarantee: callers (logs, JSON output) may match
    // these strings. Don't rename them lightly.
    assert_eq!(sd::Drift::Match.label(), "match");
    assert_eq!(sd::Drift::OwnerDiffers.label(), "owner-differs");
    assert_eq!(sd::Drift::GroupDiffers.label(), "group-differs");
    assert_eq!(sd::Drift::DaclDiffers.label(), "dacl-differs");
    assert_eq!(sd::Drift::SaclDiffers.label(), "sacl-differs");
}

#[test]
fn apply_log_record_field_names() {
    // Wire-format guarantee: log consumers parse these field names.
    // Don't rename them lightly. Also pins which fields appear on
    // the success vs error path.
    let success = ApplyLogRecord {
        ts: Some("2026-05-27T03:06:56Z".to_string()),
        op: "prepare-null-device",
        want_sacl: true,
        result: Some("applied"),
        drift: Some("dacl-differs"),
        error: None,
    };
    let s = serde_json::to_string(&success).unwrap();
    assert_eq!(
        s,
        r#"{"ts":"2026-05-27T03:06:56Z","op":"prepare-null-device","want_sacl":true,"result":"applied","drift":"dacl-differs"}"#
    );

    let failure = ApplyLogRecord {
        ts: Some("2026-05-27T03:06:56Z".to_string()),
        op: "prepare-null-device",
        want_sacl: false,
        result: None,
        drift: None,
        error: Some("could not open".to_string()),
    };
    let s = serde_json::to_string(&failure).unwrap();
    assert_eq!(
        s,
        r#"{"ts":"2026-05-27T03:06:56Z","op":"prepare-null-device","want_sacl":false,"error":"could not open"}"#
    );
}

#[test]
fn apply_log_record_escapes_quotes_in_error() {
    // Reviewer hot-spot: error messages can include arbitrary Win32
    // text (file paths with backslashes, locale strings, embedded
    // quotes). serde_json handles escaping correctly; this test
    // pins that we still rely on it after future refactors.
    let rec = ApplyLogRecord {
        ts: None,
        op: "prepare-null-device",
        want_sacl: true,
        result: None,
        drift: None,
        error: Some(r#"oops "quoted" and C:\path\to\file"#.to_string()),
    };
    let s = serde_json::to_string(&rec).unwrap();
    // serde escapes both `"` and `\`.
    assert!(
        s.contains(r#""oops \"quoted\" and C:\\path\\to\\file""#),
        "got: {s}"
    );
    // And the result is valid JSON.
    let _round_trip: serde_json::Value = serde_json::from_str(&s).expect("valid JSON");
}

#[test]
fn rfc3339_known_epochs() {
    // Locks the RFC3339 formatter against three well-known epoch
    // values so a future refactor can't silently regress to the
    // `"epoch:<secs>"` placeholder.
    assert_eq!(format_epoch_seconds_as_rfc3339(0), "1970-01-01T00:00:00Z");
    assert_eq!(
        format_epoch_seconds_as_rfc3339(946_684_800),
        "2000-01-01T00:00:00Z"
    );
    assert_eq!(
        format_epoch_seconds_as_rfc3339(1_577_836_800),
        "2020-01-01T00:00:00Z"
    );
    // Leap-day handling: 2020-02-29T12:34:56Z.
    assert_eq!(
        format_epoch_seconds_as_rfc3339(1_582_979_696),
        "2020-02-29T12:34:56Z"
    );
}
