// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Integration tests that drive the `mxc_ffi` C ABI as an external consumer
//! would — constructing C strings, calling the `extern "C"` entry points, and
//! freeing the results.

use std::ffi::{CStr, CString};
use std::ptr;

use mxc_ffi::{
    mxc_available_backends_json, mxc_platform_support_json, mxc_run_request, mxc_run_result_free,
    mxc_sandbox_stderr_closer, mxc_sandbox_stdout_closer, mxc_sandbox_warnings_json,
    mxc_stream_closer_close, mxc_stream_closer_free, mxc_string_free, mxc_version, MxcRunResult,
};
#[cfg(target_os = "windows")]
use mxc_ffi::{
    mxc_error_detail_free, mxc_probe_request_json, mxc_probe_request_json_with_error,
    mxc_probe_sandbox_request_json_with_error, MxcErrorDetail,
};
#[cfg(target_os = "linux")]
use mxc_ffi::{mxc_error_detail_free, mxc_spawn_request, MxcErrorDetail, MxcSandbox};

/// An empty, all-null result to hand to `mxc_run_request`.
fn zeroed_result() -> MxcRunResult {
    // SAFETY: `MxcRunResult` is `repr(C)` of `i32`s and nullable pointers, so an
    // all-zero value is valid (null pointers, zero status).
    unsafe { std::mem::zeroed() }
}

#[test]
fn extern_run_rejects_malformed_request() {
    let request = CString::new("not json").unwrap();
    let mut out = zeroed_result();
    // SAFETY: valid C string and a valid out pointer.
    let status = unsafe { mxc_run_request(request.as_ptr(), &mut out) };

    assert_eq!(status, mxc_ffi::MXC_STATUS_MALFORMED_REQUEST);
    assert_eq!(out.status, status);
    assert!(!out.error.message_utf8.is_null());
    // SAFETY: the message is a valid C string filled by `mxc_run_request`.
    let msg = unsafe { CStr::from_ptr(out.error.message_utf8) }
        .to_str()
        .unwrap();
    assert!(msg.contains("request"), "unexpected message: {msg}");
    assert!(out.stdout_utf8.is_null());

    // SAFETY: `out` was filled by `mxc_run_request`; frees its owned strings.
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
    for capability in backends_value
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|backend| backend.get("capabilities"))
        .flat_map(|capabilities| capabilities.as_array().into_iter().flatten())
    {
        assert!(matches!(
            capability.as_str(),
            Some(
                "captureDenials"
                    | "filesystemDeniedPaths"
                    | "filesystemEnumeratePaths"
                    | "ingressHostLoopbackAllow"
                    | "proxyEnforcement"
            )
        ));
    }

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

#[cfg(target_os = "windows")]
#[test]
fn extern_request_probe_parses_and_returns_owned_json() {
    let request = CString::new(
        r#"{
            "version": "0.9.0-alpha",
            "containment": "processcontainer",
            "process": { "commandLine": "cmd /c exit 0" }
        }"#,
    )
    .unwrap();

    // SAFETY: the request is a valid NUL-terminated UTF-8 string.
    let output = unsafe { mxc_probe_request_json(request.as_ptr()) };
    assert!(!output.is_null());
    // SAFETY: a non-null probe result is an owned NUL-terminated UTF-8 string.
    let json = unsafe { CStr::from_ptr(output) }.to_str().unwrap();
    let value: serde_json::Value = serde_json::from_str(json).unwrap();
    assert!(value.get("warnings").is_some());
    assert!(value.get("probes").is_some());

    // SAFETY: `output` is an owned result from the FFI.
    unsafe { mxc_string_free(output) };
}

#[cfg(target_os = "windows")]
#[test]
fn extern_request_probe_accepts_null_as_default_request() {
    // SAFETY: null is the documented default-request input.
    let output = unsafe { mxc_probe_request_json(ptr::null()) };
    assert!(!output.is_null());
    // SAFETY: `output` is an owned result from the FFI.
    unsafe { mxc_string_free(output) };
}

#[cfg(target_os = "windows")]
#[test]
fn extern_request_probe_rejects_malformed_and_unsupported_requests() {
    for (request, expected_status, expected_detail) in [
        (
            "not json",
            mxc_ffi::MXC_STATUS_MALFORMED_REQUEST,
            "Configuration parse error",
        ),
        (
            r#"{
            "version": "0.9.0-alpha",
            "containment": "wslc",
            "process": { "commandLine": "echo hi" }
        }"#,
            mxc_ffi::MXC_STATUS_UNSUPPORTED_CONTAINMENT,
            "ProcessContainer",
        ),
        (
            r#"{
            "version": "0.9.0-alpha",
            "phase": "exec",
            "sandboxId": "wslc:test",
            "process": { "commandLine": "echo hi" }
        }"#,
            mxc_ffi::MXC_STATUS_MALFORMED_REQUEST,
            "one-shot",
        ),
    ] {
        let request = CString::new(request).unwrap();
        let mut output = ptr::null_mut();
        // SAFETY: this all-null representation is valid for MxcErrorDetail.
        let mut error: MxcErrorDetail = unsafe { std::mem::zeroed() };
        // SAFETY: the request is a valid NUL-terminated UTF-8 string.
        let status =
            unsafe { mxc_probe_request_json_with_error(request.as_ptr(), &mut output, &mut error) };
        assert_eq!(status, expected_status);
        assert!(output.is_null());
        assert!(!error.message_utf8.is_null());
        // SAFETY: the detailed probe filled a valid owned C string.
        let message = unsafe { CStr::from_ptr(error.message_utf8) }.to_string_lossy();
        assert!(
            message.contains(expected_detail),
            "unexpected detail for status {status}: {message}"
        );
        // SAFETY: the detailed probe initialized this owned error detail.
        unsafe { mxc_error_detail_free(&mut error) };

        // The compatibility ABI remains null-only for existing consumers.
        // SAFETY: the request remains a valid NUL-terminated UTF-8 string.
        assert!(unsafe { mxc_probe_request_json(request.as_ptr()) }.is_null());
    }
}

#[cfg(target_os = "windows")]
#[test]
fn extern_binding_request_probe_uses_the_canonical_interchange() {
    let request = CString::new(
        r#"{
            "policy": {},
            "command": "cmd /c exit 0",
            "containment": { "type": "processContainer" }
        }"#,
    )
    .unwrap();
    let mut output = ptr::null_mut();
    // SAFETY: this all-null representation is valid for MxcErrorDetail.
    let mut error: MxcErrorDetail = unsafe { std::mem::zeroed() };

    // SAFETY: the request is a valid C string and both out-parameters are writable.
    let status = unsafe {
        mxc_probe_sandbox_request_json_with_error(request.as_ptr(), &mut output, &mut error)
    };

    assert_eq!(status, mxc_ffi::MXC_STATUS_SUCCESS);
    assert!(!output.is_null());
    assert!(error.message_utf8.is_null());
    // SAFETY: both values were initialized by the FFI call.
    unsafe {
        mxc_string_free(output);
        mxc_error_detail_free(&mut error);
    }
}

#[cfg(target_os = "windows")]
#[test]
fn extern_binding_request_probe_rejects_non_process_container() {
    let request = CString::new(
        r#"{
            "policy": {},
            "command": "echo hi",
            "containment": {
                "type": "wslc",
                "image": "python:3.12"
            }
        }"#,
    )
    .unwrap();
    let mut output = ptr::null_mut();
    // SAFETY: this all-null representation is valid for MxcErrorDetail.
    let mut error: MxcErrorDetail = unsafe { std::mem::zeroed() };

    // SAFETY: the request is a valid C string and both out-parameters are writable.
    let status = unsafe {
        mxc_probe_sandbox_request_json_with_error(request.as_ptr(), &mut output, &mut error)
    };

    assert_eq!(status, mxc_ffi::MXC_STATUS_UNSUPPORTED_CONTAINMENT);
    assert!(output.is_null());
    assert!(!error.message_utf8.is_null());
    // SAFETY: the detailed probe filled a valid owned C string.
    let message = unsafe { CStr::from_ptr(error.message_utf8) }.to_string_lossy();
    assert!(message.contains("got wslc"), "unexpected detail: {message}");
    // SAFETY: the FFI call initialized this owned error detail.
    unsafe { mxc_error_detail_free(&mut error) };
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
fn extern_run_request_rejects_null_result_before_parsing() {
    // Invalid UTF-8 would win if the request were parsed before the mandatory
    // result pointer was checked.
    let invalid_utf8 = [0xff_u8, 0];
    // SAFETY: the byte buffer is NUL-terminated and the result pointer is null.
    let status = unsafe { mxc_run_request(invalid_utf8.as_ptr().cast(), ptr::null_mut()) };

    assert_eq!(status, mxc_ffi::MXC_STATUS_NULL_ARGUMENT);
}

/// A real run requires a host backend; on Windows that means an elevated,
/// host-prepped host (see docs/host-prep.md), so this is `#[ignore]`d.
#[cfg(target_os = "windows")]
#[test]
#[ignore = "requires an elevated, host-prepped Windows host (see docs/host-prep.md)"]
fn extern_run_executes_command() {
    let request = CString::new(
        r#"{
            "policy":{
                "filesystem":{"readwritePaths":["C:\\Windows\\Temp"]}
            },
            "command":"cmd /c echo hello-ffi"
        }"#,
    )
    .unwrap();
    let mut out = zeroed_result();
    // SAFETY: valid C string and a valid out pointer.
    let status = unsafe { mxc_run_request(request.as_ptr(), &mut out) };

    assert_eq!(status, mxc_ffi::MXC_STATUS_SUCCESS, "status={status}");
    assert_eq!(out.exit_code, 0);
    assert_eq!(out.timed_out, 0);
    // SAFETY: on success `stdout_utf8` is a valid C string.
    let stdout = unsafe { CStr::from_ptr(out.stdout_utf8) }.to_str().unwrap();
    assert!(stdout.contains("hello-ffi"), "stdout={stdout}");

    // SAFETY: `out` was filled by `mxc_run_request`.
    unsafe { mxc_run_result_free(&mut out) };
}

/// Pins that `mxc_spawn_request` reaches the LXC backend rather than refusing
/// the containment.
///
/// The empty distribution makes LXC refuse before creating a container, so the
/// result is the same on every Linux host.
#[cfg(target_os = "linux")]
#[test]
fn extern_spawn_request_reaches_the_lxc_backend() {
    let request = CString::new(
        r#"{
            "policy": {},
            "command": "echo hello-lxc",
            "containment": { "type": "lxc", "distribution": "", "release": "" }
        }"#,
    )
    .unwrap();
    let mut handle: *mut MxcSandbox = ptr::null_mut();
    // SAFETY: `MxcErrorDetail` contains integers and nullable pointers.
    let mut error: MxcErrorDetail = unsafe { std::mem::zeroed() };
    // SAFETY: valid request and writable fresh out-parameters.
    let status = unsafe { mxc_spawn_request(request.as_ptr(), &mut handle, &mut error) };

    assert_ne!(
        status,
        mxc_ffi::MXC_STATUS_UNSUPPORTED_CONTAINMENT,
        "the engine must route LXC to a real backend arm on Linux"
    );
    assert!(handle.is_null());
    // SAFETY: the message is a valid C string filled by `mxc_spawn_request`.
    let message = unsafe { CStr::from_ptr(error.message_utf8) }
        .to_str()
        .unwrap();
    // Only the LXC backend produces a message opening with `LXC`.
    assert!(message.starts_with("LXC"), "unexpected message: {message}");

    // SAFETY: `error` was filled by `mxc_spawn_request`.
    unsafe { mxc_error_detail_free(&mut error) };
}
