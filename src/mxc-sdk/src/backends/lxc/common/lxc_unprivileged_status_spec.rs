// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use super::validate_unprivileged_status;
use std::io;
use std::process::{ExitStatus, Output};

#[cfg(unix)]
use std::os::unix::process::ExitStatusExt;
#[cfg(windows)]
use std::os::windows::process::ExitStatusExt;

#[test]
fn exact_target_reported_unprivileged_is_accepted() {
    let stdout = "NAME UNPRIVILEGED\nother false\ntarget true\ntarget-extra false\n";
    let output = Output {
        status: ExitStatus::from_raw(0),
        stdout: stdout.as_bytes().to_vec(),
        stderr: Vec::new(),
    };

    let result = validate_unprivileged_status("target", Ok(output));

    assert!(
        result.is_ok(),
        "target reported true but admission was refused: {result:?}\n{stdout}"
    );
}

#[test]
fn target_without_true_status_is_rejected() {
    for stdout in [
        "NAME UNPRIVILEGED\ntarget false\nother true\n",
        "NAME UNPRIVILEGED\ntarget unknown\n",
        "NAME UNPRIVILEGED\ntarget\n",
        "NAME UNPRIVILEGED\n",
        "NAME UNPRIVILEGED\nother true\n",
        "NAME UNPRIVILEGED\ntarget-extra true\n",
    ] {
        let output = Output {
            status: ExitStatus::from_raw(0),
            stdout: stdout.as_bytes().to_vec(),
            stderr: Vec::new(),
        };

        let result = validate_unprivileged_status("target", Ok(output));

        assert!(
            result.is_err(),
            "target did not report true but admission was allowed: {result:?}\n{stdout}"
        );
    }
}

#[test]
fn unsuccessful_status_command_is_rejected() {
    #[cfg(unix)]
    let status = ExitStatus::from_raw(256);
    #[cfg(windows)]
    let status = ExitStatus::from_raw(1);

    let stdout = "NAME UNPRIVILEGED\ntarget true\n";
    let output = Output {
        status,
        stdout: stdout.as_bytes().to_vec(),
        stderr: Vec::new(),
    };

    let result = validate_unprivileged_status("target", Ok(output));

    assert!(
        result.is_err(),
        "the failed status command allowed target: {result:?}\n{stdout}"
    );
}

#[test]
fn status_command_spawn_error_is_rejected() {
    let result = validate_unprivileged_status("target", Err(io::ErrorKind::NotFound.into()));

    assert!(
        result.is_err(),
        "a NotFound spawn error allowed target: {result:?}"
    );
}
