// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Integration tests that drive the `mxc_ffi` C ABI as an external consumer
//! would — constructing C strings, calling the `extern "C"` entry points, and
//! freeing the results.

use std::ffi::{CStr, CString};
use std::ptr;

use mxc_ffi::{
    mxc_available_backends_json, mxc_error_detail_free, mxc_platform_support_json, mxc_run,
    mxc_run_request, mxc_run_result_free, mxc_sandbox_stderr_closer, mxc_sandbox_stdout_closer,
    mxc_sandbox_warnings_json, mxc_spawn_request, mxc_stream_closer_close, mxc_stream_closer_free,
    mxc_string_free, mxc_version, MxcErrorDetail, MxcRunResult, MxcSandbox,
};

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
    assert!(!out.error.message_utf8.is_null());
    // SAFETY: the message is a valid C string filled by `mxc_run`.
    let msg = unsafe { CStr::from_ptr(out.error.message_utf8) }
        .to_str()
        .unwrap();
    assert!(msg.contains("policy"), "unexpected message: {msg}");
    assert!(out.stdout_utf8.is_null());

    // SAFETY: `out` was filled by `mxc_run`; frees its owned strings.
    unsafe { mxc_run_result_free(&mut out) };
    assert!(out.error.message_utf8.is_null());
}

#[test]
fn extern_version_matches_crate() {
    let p = mxc_version();
    assert!(!p.is_null());
    // SAFETY: `mxc_version` returns a valid static C string (never freed).
    let v = unsafe { CStr::from_ptr(p) }.to_str().unwrap();
    assert_eq!(v, env!("CARGO_PKG_VERSION"));
}

#[test]
fn extern_discovery_returns_owned_json() {
    let backends = mxc_available_backends_json();
    assert!(!backends.is_null());
    // SAFETY: the entry point returned a valid owned C string.
    let backends_json = unsafe { CStr::from_ptr(backends) }.to_str().unwrap();
    let backends_value: serde_json::Value = serde_json::from_str(backends_json).unwrap();
    assert!(backends_value.is_array());

    let support = mxc_platform_support_json();
    assert!(!support.is_null());
    // SAFETY: the entry point returned a valid owned C string.
    let support_json = unsafe { CStr::from_ptr(support) }.to_str().unwrap();
    let support_value: serde_json::Value = serde_json::from_str(support_json).unwrap();
    assert!(support_value.get("isSupported").is_some());
    assert!(support_value.get("availableMethods").is_some());

    // SAFETY: both strings are owned results from the FFI.
    unsafe {
        mxc_string_free(backends);
        mxc_string_free(support);
    }
}

#[test]
fn extern_streaming_warning_and_closer_preconditions_are_safe() {
    let mut warnings = ptr::dangling_mut();
    // SAFETY: null sandbox/closer handles are deliberate precondition tests;
    // warnings points to writable pointer storage.
    unsafe {
        assert_eq!(
            mxc_sandbox_warnings_json(ptr::null_mut(), &mut warnings),
            mxc_ffi::MXC_STATUS_NULL_ARGUMENT
        );
        assert!(warnings.is_null());
        assert!(mxc_sandbox_stdout_closer(ptr::null_mut()).is_null());
        assert!(mxc_sandbox_stderr_closer(ptr::null_mut()).is_null());
        assert_eq!(
            mxc_stream_closer_close(ptr::null_mut()),
            mxc_ffi::MXC_STATUS_NULL_ARGUMENT
        );
        mxc_stream_closer_free(ptr::null_mut());
    }
}

#[test]
fn extern_run_request_maps_capture_denials_to_process_container() {
    let request = CString::new(
        r#"{
            "policy": { "version": "0.7.0-alpha" },
            "command": "echo hi",
            "containment": {
                "type": "processContainer",
                "captureDenials": {}
            }
        }"#,
    )
    .unwrap();
    let mut out = zeroed_result();
    // SAFETY: a valid C string and writable result storage.
    let status = unsafe { mxc_run_request(request.as_ptr(), &mut out) };

    assert_eq!(status, mxc_ffi::MXC_STATUS_MALFORMED_REQUEST);
    // SAFETY: the message is a valid C string filled by `mxc_run_request`.
    let message = unsafe { CStr::from_ptr(out.error.message_utf8) }
        .to_str()
        .unwrap();
    assert!(
        message.contains("processContainer.captureDenials requires schema version 0.8"),
        "unexpected message: {message}"
    );

    // SAFETY: `out` was filled by `mxc_run_request`.
    unsafe { mxc_run_result_free(&mut out) };
}

#[test]
fn extern_run_request_rejects_null_result_before_parsing() {
    // Invalid UTF-8 would win if the request were parsed before the mandatory
    // result pointer was checked.
    let invalid_utf8 = [0xff_u8, 0];
    // SAFETY: the byte buffer is NUL-terminated and the result pointer is null.
    let status = unsafe { mxc_run_request(invalid_utf8.as_ptr().cast(), ptr::null_mut()) };

    assert_eq!(status, mxc_ffi::MXC_STATUS_NULL_ARGUMENT);
}

#[test]
fn extern_spawn_request_maps_capture_denials_to_process_container() {
    let request = CString::new(
        r#"{
            "policy": { "version": "0.7.0-alpha" },
            "command": "echo hi",
            "containment": {
                "type": "processContainer",
                "captureDenials": {}
            }
        }"#,
    )
    .unwrap();
    let mut handle: *mut MxcSandbox = ptr::null_mut();
    // SAFETY: `MxcErrorDetail` contains integers and nullable pointers.
    let mut error: MxcErrorDetail = unsafe { std::mem::zeroed() };
    // SAFETY: valid request and writable fresh out-parameters.
    let status = unsafe { mxc_spawn_request(request.as_ptr(), &mut handle, &mut error) };

    assert_eq!(status, mxc_ffi::MXC_STATUS_MALFORMED_REQUEST);
    assert!(handle.is_null());
    // SAFETY: the message is a valid C string filled by `mxc_spawn_request`.
    let message = unsafe { CStr::from_ptr(error.message_utf8) }
        .to_str()
        .unwrap();
    assert!(
        message.contains("processContainer.captureDenials requires schema version 0.8"),
        "unexpected message: {message}"
    );

    // SAFETY: `error` was filled by `mxc_spawn_request`.
    unsafe { mxc_error_detail_free(&mut error) };
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
