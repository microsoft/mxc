// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Integration tests that drive the `mxc_ffi` C ABI as an external consumer
//! would — constructing C strings, calling the `extern "C"` entry points, and
//! freeing the results.

use std::ffi::{CStr, CString};

use mxc_ffi::{mxc_run, mxc_run_result_free, mxc_version, MxcRunResult};

/// An empty, all-null result to hand to `mxc_run`.
fn zeroed_result() -> MxcRunResult {
    // SAFETY: `MxcRunResult` is `repr(C)` of `i32`s and nullable pointers, so an
    // all-zero value is valid (null pointers, zero status).
    unsafe { std::mem::zeroed() }
}

#[test]
fn extern_run_rejects_malformed_policy() {
    let policy = CString::new("not json").unwrap();
    let command = CString::new("echo hi").unwrap();
    let mut out = zeroed_result();
    // SAFETY: valid C strings and a valid out pointer.
    let status = unsafe { mxc_run(policy.as_ptr(), command.as_ptr(), &mut out) };

    assert_eq!(status, mxc_ffi::MXC_STATUS_MALFORMED_REQUEST);
    assert_eq!(out.status, status);
    assert!(!out.error_utf8.is_null());
    // SAFETY: `error_utf8` is a valid C string filled by `mxc_run`.
    let msg = unsafe { CStr::from_ptr(out.error_utf8) }.to_str().unwrap();
    assert!(msg.contains("policy"), "unexpected message: {msg}");
    assert!(out.stdout_utf8.is_null());

    // SAFETY: `out` was filled by `mxc_run`; frees its owned strings.
    unsafe { mxc_run_result_free(&mut out) };
    assert!(out.error_utf8.is_null());
}

#[test]
fn extern_version_matches_crate() {
    let p = mxc_version();
    assert!(!p.is_null());
    // SAFETY: `mxc_version` returns a valid static C string (never freed).
    let v = unsafe { CStr::from_ptr(p) }.to_str().unwrap();
    assert_eq!(v, env!("CARGO_PKG_VERSION"));
}

/// A real run requires a host backend; on Windows that means an elevated,
/// host-prepped host (see docs/host-prep.md), so this is `#[ignore]`d.
#[cfg(target_os = "windows")]
#[test]
#[ignore = "requires an elevated, host-prepped Windows host (see docs/host-prep.md)"]
fn extern_run_executes_command() {
    let policy = CString::new(
        r#"{"version":"0.7.0-alpha","filesystem":{"readwritePaths":["C:\\Windows\\Temp"]}}"#,
    )
    .unwrap();
    let command = CString::new("cmd /c echo hello-ffi").unwrap();
    let mut out = zeroed_result();
    // SAFETY: valid C strings and a valid out pointer.
    let status = unsafe { mxc_run(policy.as_ptr(), command.as_ptr(), &mut out) };

    assert_eq!(status, mxc_ffi::MXC_STATUS_SUCCESS, "status={status}");
    assert_eq!(out.exit_code, 0);
    assert_eq!(out.timed_out, 0);
    // SAFETY: on success `stdout_utf8` is a valid C string.
    let stdout = unsafe { CStr::from_ptr(out.stdout_utf8) }.to_str().unwrap();
    assert!(stdout.contains("hello-ffi"), "stdout={stdout}");

    // SAFETY: `out` was filled by `mxc_run`.
    unsafe { mxc_run_result_free(&mut out) };
}
