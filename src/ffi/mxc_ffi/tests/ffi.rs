// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Integration tests that drive the `mxc_ffi` C ABI as an external consumer
//! would — constructing C strings, calling the `extern "C"` entry points, and
//! freeing the results.

use std::ffi::{CStr, CString};
use std::ptr;

use mxc_ffi::{
    mxc_available_backends_json, mxc_platform_support_json, mxc_run_request, mxc_run_result_free,
    mxc_run_typed, mxc_sandbox_stderr_closer, mxc_sandbox_stdout_closer, mxc_sandbox_warnings_json,
    mxc_spawn_typed, mxc_stream_closer_close, mxc_stream_closer_free, mxc_string_free, mxc_version,
    MxcEnvironment, MxcErrorDetail, MxcRunResult, MxcTypedOneShotRequest, MxcUtf8Slice,
    MXC_CONTAINMENT_PROCESS, MXC_TYPED_ABI_VERSION_1,
};

/// An empty, all-null result to hand to `mxc_run_request`.
fn zeroed_result() -> MxcRunResult {
    // SAFETY: `MxcRunResult` is `repr(C)` of `i32`s and nullable pointers, so an
    // all-zero value is valid (null pointers, zero status).
    unsafe { std::mem::zeroed() }
}

fn typed_request(command: &str) -> MxcTypedOneShotRequest {
    MxcTypedOneShotRequest {
        abi_version: MXC_TYPED_ABI_VERSION_1,
        struct_size: std::mem::size_of::<MxcTypedOneShotRequest>(),
        policy: ptr::null(),
        command: MxcUtf8Slice {
            data: command.as_ptr(),
            len: command.len(),
        },
        containment: MXC_CONTAINMENT_PROCESS,
        process_container: ptr::null(),
        seatbelt: ptr::null(),
        lxc: ptr::null(),
        wslc: ptr::null(),
        container_name: ptr::null(),
        working_directory: ptr::null(),
        environment: MxcEnvironment {
            is_set: 0,
            entries: ptr::null(),
            len: 0,
        },
        inherit_default_env: 0,
        experimental: 0,
    }
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

#[test]
fn extern_typed_run_rejects_null_result_before_reading_request() {
    // SAFETY: both null pointers are deliberate precondition inputs.
    let status = unsafe { mxc_run_typed(ptr::null(), ptr::null_mut()) };
    assert_eq!(status, mxc_ffi::MXC_STATUS_NULL_ARGUMENT);
}

#[test]
fn extern_typed_run_rejects_unknown_abi_revision() {
    let mut request = typed_request("echo hello");
    request.abi_version = 99;
    let mut out = zeroed_result();
    // SAFETY: request and output pointers are valid for the duration of the call.
    let status = unsafe { mxc_run_typed(&request, &mut out) };

    assert_eq!(status, mxc_ffi::MXC_STATUS_MALFORMED_REQUEST);
    assert_eq!(out.status, status);
    // SAFETY: failure populated a valid owned C string.
    let message = unsafe { CStr::from_ptr(out.error.message_utf8) }
        .to_str()
        .unwrap();
    assert!(message.contains("ABI version"), "{message}");
    // SAFETY: `out` was filled by `mxc_run_typed`.
    unsafe { mxc_run_result_free(&mut out) };
}

#[test]
fn extern_typed_spawn_initializes_outputs_before_validation() {
    let mut request = typed_request("echo hello");
    request.struct_size = 0;
    let mut handle = ptr::dangling_mut();
    // SAFETY: all-zero is a valid empty detail.
    let mut error: MxcErrorDetail = unsafe { std::mem::zeroed() };
    // SAFETY: request and out-parameters are valid for the duration of the call.
    let status = unsafe { mxc_spawn_typed(&request, &mut handle, &mut error) };

    assert_eq!(status, mxc_ffi::MXC_STATUS_MALFORMED_REQUEST);
    assert!(handle.is_null());
    assert!(!error.message_utf8.is_null());
    // SAFETY: the standalone detail was filled by `mxc_spawn_typed`.
    unsafe { mxc_ffi::mxc_error_detail_free(&mut error) };
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
