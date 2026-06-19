// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! End-to-end negative-path test harness for `mxc-learning-mode-shim`.
//!
//! Run on a VM after installing + starting the shim:
//!
//! ```text
//! shim-security-test
//! ```
//!
//! Exits 0 if every negative-path assertion passes; non-zero with a
//! diagnostic message if any check fails.

#[cfg(target_os = "windows")]
use learning_mode_windows::session::{extend_via_shim, open_via_shim, SessionError};

#[derive(Debug)]
struct TestResult {
    name: &'static str,
    passed: bool,
    detail: String,
}

#[cfg(target_os = "windows")]
fn main() -> std::process::ExitCode {
    println!("== shim-security-test ==\n");

    let results = vec![
        test_open_against_inaccessible_pid(),
        test_extend_with_unknown_session_name(),
    ];

    let mut failed = false;
    for r in &results {
        let tag = if r.passed { "PASS" } else { "FAIL" };
        println!("  [{tag}] {}", r.name);
        if !r.detail.is_empty() {
            println!("         {}", r.detail);
        }
        if !r.passed {
            failed = true;
        }
    }
    println!();
    if failed {
        println!("== FAILED ==");
        std::process::ExitCode::from(1)
    } else {
        println!("== ALL PASS ==");
        std::process::ExitCode::SUCCESS
    }
}

#[cfg(not(target_os = "windows"))]
fn main() {
    eprintln!("shim-security-test is Windows-only.");
    std::process::exit(2);
}

#[cfg(target_os = "windows")]
fn test_open_against_inaccessible_pid() -> TestResult {
    // PID 0 is the System Idle process; the OS does not allow
    // OpenProcess against it for any caller, including LocalSystem.
    // The shim's impersonate-then-OpenProcess check must therefore
    // reject any OpenDenialSession(0) with `unauthorized`, regardless
    // of who's calling.
    const INACCESSIBLE_PID: u32 = 0;
    match open_via_shim(INACCESSIBLE_PID, None) {
        Ok(_session) => TestResult {
            name: "open_via_shim against inaccessible PID (0) is rejected",
            passed: false,
            detail: "shim returned Ok — security check is NOT firing! VULN.".to_string(),
        },
        Err(SessionError::ShimError { code, message }) if code == "unauthorized" => TestResult {
            name: "open_via_shim against inaccessible PID (0) is rejected",
            passed: true,
            detail: format!("shim correctly rejected: code=unauthorized, message=`{message}`"),
        },
        Err(SessionError::ShimError { code, message }) => TestResult {
            name: "open_via_shim against inaccessible PID (0) is rejected",
            passed: false,
            detail: format!(
                "wrong code: expected `unauthorized`, got `{code}` (message: {message})"
            ),
        },
        Err(other) => TestResult {
            name: "open_via_shim against inaccessible PID (0) is rejected",
            passed: false,
            detail: format!("expected ShimError(unauthorized), got transport error: {other}"),
        },
    }
}

#[cfg(target_os = "windows")]
fn test_extend_with_unknown_session_name() -> TestResult {
    let fake_session = "mxc-denials-this-session-was-never-opened-by-anyone-aaaabbbbccccdddd";
    let self_pid = std::process::id();
    match extend_via_shim(fake_session, &[self_pid]) {
        Ok(()) => TestResult {
            name: "extend_via_shim with unrecorded session name is rejected",
            passed: false,
            detail: "shim returned Ok — ownership map check is NOT firing! VULN.".to_string(),
        },
        Err(SessionError::ShimError { code, message }) if code == "unknownSession" => TestResult {
            name: "extend_via_shim with unrecorded session name is rejected",
            passed: true,
            detail: format!(
                "shim correctly rejected: code=unknownSession, message=`{message}`"
            ),
        },
        Err(SessionError::ShimError { code, message }) => TestResult {
            name: "extend_via_shim with unrecorded session name is rejected",
            passed: false,
            detail: format!(
                "wrong code: expected `unknownSession`, got `{code}` (message: {message})"
            ),
        },
        Err(other) => TestResult {
            name: "extend_via_shim with unrecorded session name is rejected",
            passed: false,
            detail: format!("expected ShimError(unknownSession), got transport error: {other}"),
        },
    }
}
