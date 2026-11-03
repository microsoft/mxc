// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use std::ffi::{CStr, CString};
use std::mem::MaybeUninit;
use std::ptr;

use mxc_ffi::*;
use mxc_sdk::v1::{dev, ErrorCode};
use serde_json::json;

const ONE_SHOT: &str = r#"{"version":"1.1.0-alpha","containment":"microvm","microvm":{"image":"mcr.microsoft.com/azurelinux/base/core:3.0"},"process":{"commandLine":"true"}}"#;
const EXEC: &str = r#"{"version":"1.1.0-alpha","phase":"exec","sandboxId":"microvm:0123456789abcdef0123456789abcdef","process":{"commandLine":"true"}}"#;

type Spawn = unsafe extern "C" fn(
    *const std::ffi::c_char,
    i32,
    *mut *mut MxcSandbox,
    *mut MxcErrorDetail,
) -> i32;

fn assert_rejected_detail(status: i32, expected: i32, detail: &mut MxcErrorDetail) {
    assert!(
        !detail.message_utf8.is_null(),
        "status {status} supplied no error"
    );
    // SAFETY: every tested entry point initializes the supplied error storage.
    let message = unsafe { CStr::from_ptr(detail.message_utf8) }
        .to_string_lossy()
        .into_owned();
    assert!(detail.operation_utf8.is_null());
    assert!(detail.native_code_utf8.is_null());
    // SAFETY: detail owns only allocations returned by this library.
    unsafe { mxc_error_detail_free(detail) };
    assert_eq!(status, expected, "{message}");
    assert!(message.contains("only through Rust mxc_sdk::v1::dev JSON APIs"));
}

fn assert_spawn_rejected(spawn: Spawn, json: &str, expected: i32) {
    let request = CString::new(json).unwrap();
    for experimental in [0, 1] {
        let mut handle = ptr::dangling_mut();
        let mut detail = MaybeUninit::uninit();
        // SAFETY: request and both output locations are valid; no live handle is overwritten.
        let status = unsafe {
            spawn(
                request.as_ptr(),
                experimental,
                &mut handle,
                detail.as_mut_ptr(),
            )
        };
        assert!(handle.is_null());
        // SAFETY: the entry point initialized detail.
        let mut detail = unsafe { detail.assume_init() };
        assert_rejected_detail(status, expected, &mut detail);
    }
}

#[test]
fn one_shot_pipe_and_stdin_exports_reject_microvm() {
    for spawn in [mxc_spawn_json as Spawn, mxc_spawn_with_stdin_json] {
        assert_spawn_rejected(spawn, ONE_SHOT, MXC_STATUS_UNSUPPORTED_CONTAINMENT);
        assert_spawn_rejected(
            spawn,
            &ONE_SHOT.replace("microvm", "micro\\u0076m"),
            MXC_STATUS_UNSUPPORTED_CONTAINMENT,
        );
    }
}

#[test]
fn malformed_contract_version_and_phase_errors_are_preserved() {
    for json in [
        "{",
        r#"{"version":"99.0.0"}"#,
        r#"{"version":"1.1.0-alpha","phase":"unknown"}"#,
        r#"{"version":"1.1.0-alpha","containment":"microvm","unknown":true}"#,
    ] {
        let json = CString::new(json).unwrap();
        let mut handle = ptr::null_mut();
        let mut detail = MaybeUninit::uninit();
        // SAFETY: request and output pointers are valid.
        let status = unsafe { mxc_spawn_json(json.as_ptr(), 1, &mut handle, detail.as_mut_ptr()) };
        assert!(handle.is_null());
        // SAFETY: the entry point initialized detail.
        let mut detail = unsafe { detail.assume_init() };
        // SAFETY: detail owns only allocations returned by this library.
        unsafe { mxc_error_detail_free(&mut detail) };
        assert_eq!(status, MXC_STATUS_MALFORMED_REQUEST);
    }
}

#[test]
fn filesystem_validation_preserves_malformed_request_errors() {
    let filesystem = json!({"readonlyPaths": ["\u{0}"]});
    let mut one_shot: serde_json::Value = serde_json::from_str(ONE_SHOT).unwrap();
    one_shot["filesystem"] = filesystem.clone();
    for spawn in [mxc_spawn_json as Spawn, mxc_spawn_with_stdin_json] {
        let request = CString::new(one_shot.to_string()).unwrap();
        let mut handle = ptr::null_mut();
        let mut detail = MaybeUninit::uninit();
        // SAFETY: request and output pointers are valid.
        let status = unsafe { spawn(request.as_ptr(), 1, &mut handle, detail.as_mut_ptr()) };
        assert!(handle.is_null());
        // SAFETY: the entry point initialized detail.
        let mut detail = unsafe { detail.assume_init() };
        assert_eq!(status, MXC_STATUS_MALFORMED_REQUEST);
        // SAFETY: the error string is owned by detail.
        assert!(unsafe { CStr::from_ptr(detail.message_utf8) }
            .to_string_lossy()
            .contains("embedded NUL"));
        // SAFETY: detail owns only allocations returned by this library.
        unsafe { mxc_error_detail_free(&mut detail) };
    }
    let provision = CString::new(
        json!({
            "version": "1.1.0-alpha", "phase": "provision", "containment": "microvm",
            "microvm": {"image": "mcr.microsoft.com/azurelinux/base/core:3.0"},
            "filesystem": filesystem
        })
        .to_string(),
    )
    .unwrap();
    let mut result = MaybeUninit::<MxcStateAwareResult>::uninit();
    // SAFETY: request and result storage are valid for this call.
    let status = unsafe { mxc_run_state_aware_json(provision.as_ptr(), 0, 1, result.as_mut_ptr()) };
    // SAFETY: the entry point initialized result.
    let mut result = unsafe { result.assume_init() };
    assert_eq!(status, MXC_STATUS_MALFORMED_REQUEST);
    // SAFETY: the error string is owned by result.
    assert!(unsafe { CStr::from_ptr(result.error.message_utf8) }
        .to_string_lossy()
        .contains("embedded NUL"));
    // SAFETY: the result was populated by this library.
    unsafe { mxc_state_aware_result_free(&mut result) };
}

#[test]
fn lifecycle_pipe_and_stdin_exports_reject_microvm() {
    for spawn in [
        mxc_exec_state_aware_json as Spawn,
        mxc_exec_state_aware_with_stdin_json,
    ] {
        assert_spawn_rejected(spawn, EXEC, MXC_STATUS_UNSUPPORTED_PHASE);
        assert_spawn_rejected(
            spawn,
            &EXEC.replace("microvm", "micro\\u0076m"),
            MXC_STATUS_UNSUPPORTED_PHASE,
        );
    }
}

#[test]
fn pty_exports_reject_microvm() {
    for (spawn, json, expected) in [
        (
            mxc_spawn_pty_json as unsafe extern "C" fn(_, _, _, _, _, _) -> _,
            ONE_SHOT,
            MXC_STATUS_UNSUPPORTED_CONTAINMENT,
        ),
        (mxc_state_aware_exec_pty, EXEC, MXC_STATUS_UNSUPPORTED_PHASE),
    ] {
        let request = CString::new(json).unwrap();
        let mut handle = ptr::dangling_mut();
        let mut detail = MaybeUninit::uninit();
        // SAFETY: the string, dimensions, and output locations meet the entry point contract.
        let status = unsafe {
            spawn(
                request.as_ptr(),
                1,
                24,
                80,
                &mut handle,
                detail.as_mut_ptr(),
            )
        };
        assert!(handle.is_null());
        // SAFETY: the entry point initialized detail.
        let mut detail = unsafe { detail.assume_init() };
        assert_rejected_detail(status, expected, &mut detail);
    }
}

#[test]
fn lifecycle_envelope_export_rejects_all_microvm_phases_and_dry_runs() {
    for phase in ["provision", "start", "exec", "stop", "deprovision"] {
        let request = match phase {
            "provision" => json!({
                "version": "1.1.0-alpha", "phase": phase, "containment": "microvm",
                "microvm": {"image": "mcr.microsoft.com/azurelinux/base/core:3.0"}
            })
            .to_string(),
            "exec" => EXEC.to_owned(),
            _ => json!({
                "version": "1.1.0-alpha", "phase": phase,
                "sandboxId": "microvm:0123456789abcdef0123456789abcdef"
            })
            .to_string(),
        };
        let request = CString::new(request).unwrap();
        for dry_run in [0, 1] {
            let mut result = MaybeUninit::<MxcStateAwareResult>::uninit();
            // SAFETY: request is valid and result is writable storage.
            let status = unsafe {
                mxc_run_state_aware_json(request.as_ptr(), dry_run, 1, result.as_mut_ptr())
            };
            // SAFETY: the entry point initialized result.
            let mut result = unsafe { result.assume_init() };
            assert_eq!(status, result.status);
            assert!(result.response_json_utf8.is_null());
            assert_rejected_detail(status, MXC_STATUS_UNSUPPORTED_PHASE, &mut result.error);
            // SAFETY: the result was populated; its error strings were already freed.
            unsafe { mxc_state_aware_result_free(&mut result) };
        }
    }
}

#[test]
fn captured_and_attached_lifecycle_exports_reject_microvm() {
    let request = CString::new(EXEC).unwrap();
    let mut result = MaybeUninit::<MxcRunResult>::uninit();
    // SAFETY: request is valid and result is writable storage.
    let status = unsafe { mxc_run_state_aware_exec_json(request.as_ptr(), 1, result.as_mut_ptr()) };
    // SAFETY: the entry point initialized result.
    let mut result = unsafe { result.assume_init() };
    assert!(result.stdout_utf8.is_null());
    assert!(result.stderr_utf8.is_null());
    assert_rejected_detail(status, MXC_STATUS_UNSUPPORTED_PHASE, &mut result.error);
    // SAFETY: the result was populated; its error strings were already freed.
    unsafe { mxc_run_result_free(&mut result) };

    let mut outcome = MxcExecOutcome {
        timed_out: 42,
        exit_code: 43,
    };
    let mut detail = MaybeUninit::uninit();
    // SAFETY: request, outcome, and detail are valid for this call.
    let status = unsafe {
        mxc_exec_state_aware_attached_json(request.as_ptr(), 1, &mut outcome, detail.as_mut_ptr())
    };
    assert_eq!((outcome.timed_out, outcome.exit_code), (42, 43));
    // SAFETY: the entry point initialized detail.
    let mut detail = unsafe { detail.assume_init() };
    assert_rejected_detail(status, MXC_STATUS_UNSUPPORTED_PHASE, &mut detail);
}

#[test]
fn baseline_microvm_one_shot_capture_still_reaches_the_rust_backend() {
    let mut request: serde_json::Value = serde_json::from_str(ONE_SHOT).unwrap();
    // Backend policy rejects this before loading a runtime or creating a VM.
    request["process"]["timeout"] = json!(3_600_001);
    let request = request.to_string();
    let expected = dev::run_json(&request, dev::JsonOptions { experimental: true }).unwrap_err();
    let expected = match expected.code {
        ErrorCode::PolicyValidation => MXC_STATUS_POLICY_VALIDATION,
        ErrorCode::BackendUnavailable => MXC_STATUS_BACKEND_UNAVAILABLE,
        other => panic!("unexpected baseline Rust capture error: {other:?}"),
    };
    assert_spawn_rejected(mxc_spawn_json, &request, MXC_STATUS_UNSUPPORTED_CONTAINMENT);
    let request = CString::new(request).unwrap();
    let mut result = MaybeUninit::<MxcRunResult>::uninit();
    // SAFETY: request is valid and result is writable storage.
    let status = unsafe { mxc_run_json(request.as_ptr(), 1, result.as_mut_ptr()) };
    // SAFETY: the entry point initialized result.
    let mut result = unsafe { result.assume_init() };
    // SAFETY: the result was populated by this library.
    unsafe { mxc_run_result_free(&mut result) };
    assert_eq!(status, expected);
}

#[test]
fn one_shot_capture_export_cannot_bypass_the_lifecycle_boundary() {
    let request = CString::new(EXEC).unwrap();
    let mut result = MaybeUninit::<MxcRunResult>::uninit();
    // SAFETY: request is valid and result is writable storage.
    let status = unsafe { mxc_run_json(request.as_ptr(), 1, result.as_mut_ptr()) };
    // SAFETY: the entry point initialized result.
    let mut result = unsafe { result.assume_init() };
    // SAFETY: the result was populated by this library.
    unsafe { mxc_run_result_free(&mut result) };
    assert_eq!(status, MXC_STATUS_MALFORMED_REQUEST);
}
