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

type PtySpawn = unsafe extern "C" fn(
    *const std::ffi::c_char,
    i32,
    u16,
    u16,
    *mut *mut MxcSandbox,
    *mut MxcErrorDetail,
) -> i32;

enum Call {
    Spawn(Spawn),
    Pty(PtySpawn, u16, u16),
    Envelope(bool),
    Capture,
    Attached,
}

fn failure_detail(status: i32, detail: &mut MxcErrorDetail) -> (i32, String) {
    assert_ne!(status, MXC_STATUS_SUCCESS);
    assert!(!detail.message_utf8.is_null());
    // SAFETY: the tested entry point initialized this owned error detail.
    let message = unsafe { CStr::from_ptr(detail.message_utf8) }
        .to_str()
        .unwrap()
        .to_owned();
    // SAFETY: the strings were allocated by this library.
    unsafe { mxc_error_detail_free(detail) };
    (status, message)
}

fn call_failure(call: Call, json: &str, experimental: i32) -> (i32, String) {
    let request = CString::new(json).unwrap();
    // SAFETY: the C string and fresh output storage remain valid throughout each call.
    unsafe {
        match call {
            Call::Spawn(_) | Call::Pty(_, _, _) => {
                let mut handle = ptr::dangling_mut();
                let mut detail = MaybeUninit::uninit();
                let status = match call {
                    Call::Spawn(spawn) => spawn(
                        request.as_ptr(),
                        experimental,
                        &mut handle,
                        detail.as_mut_ptr(),
                    ),
                    Call::Pty(spawn, rows, cols) => spawn(
                        request.as_ptr(),
                        experimental,
                        rows,
                        cols,
                        &mut handle,
                        detail.as_mut_ptr(),
                    ),
                    _ => unreachable!(),
                };
                assert!(handle.is_null());
                failure_detail(status, &mut detail.assume_init())
            }
            Call::Envelope(dry_run) => {
                let mut result = MaybeUninit::<MxcStateAwareResult>::uninit();
                let status = mxc_run_state_aware_json(
                    request.as_ptr(),
                    i32::from(dry_run),
                    experimental,
                    result.as_mut_ptr(),
                );
                let mut result = result.assume_init();
                assert_eq!(status, result.status);
                assert!(result.response_json_utf8.is_null());
                let failure = failure_detail(status, &mut result.error);
                mxc_state_aware_result_free(&mut result);
                failure
            }
            Call::Capture => {
                let mut result = MaybeUninit::<MxcRunResult>::uninit();
                let status = mxc_run_state_aware_exec_json(
                    request.as_ptr(),
                    experimental,
                    result.as_mut_ptr(),
                );
                let mut result = result.assume_init();
                assert!(result.stdout_utf8.is_null());
                assert!(result.stderr_utf8.is_null());
                let failure = failure_detail(status, &mut result.error);
                mxc_run_result_free(&mut result);
                failure
            }
            Call::Attached => {
                let mut outcome = MxcExecOutcome {
                    timed_out: 42,
                    exit_code: 43,
                };
                let mut detail = MaybeUninit::uninit();
                let status = mxc_exec_state_aware_attached_json(
                    request.as_ptr(),
                    experimental,
                    &mut outcome,
                    detail.as_mut_ptr(),
                );
                assert_eq!((outcome.timed_out, outcome.exit_code), (42, 43));
                failure_detail(status, &mut detail.assume_init())
            }
        }
    }
}

#[test]
fn permitted_public_spawns_normalize_and_probe_each_surviving_path_once() {
    use mxc_sdk::mxc_common::config_parser::filesystem_test_support::observe;

    // This backend is permitted by the binding but has no streaming arm, so no VM is started.
    let path = std::env::current_dir()
        .unwrap()
        .to_str()
        .unwrap()
        .to_owned();
    let request = json!({
        "version": "1.1.0-alpha", "containment": "windows_sandbox",
        "process": {"commandLine": "true"},
        "filesystem": {"readonlyPaths": [path.clone()], "readwritePaths": [path]},
        "_comment": {"containment": "microvm", "sandboxId": "microvm:unused"},
    })
    .to_string();
    for spawn in [mxc_spawn_json as Spawn, mxc_spawn_with_stdin_json] {
        for experimental in [0, 1] {
            let ((status, message), normalizations, metadata) =
                observe(|| call_failure(Call::Spawn(spawn), &request, experimental));
            assert_eq!(
                status,
                if experimental == 0 {
                    MXC_STATUS_BACKEND_UNAVAILABLE
                } else {
                    MXC_STATUS_UNSUPPORTED_CONTAINMENT
                },
                "{message}"
            );
            assert_eq!((normalizations, metadata), (1, 1));
        }
    }
}

#[test]
fn wrong_entry_points_preserve_the_owning_phase_and_root_errors() {
    let provision = r#"{"version":"1.1.0-alpha","phase":"provision","containment":"microvm","microvm":{"image":"mcr.microsoft.com/azurelinux/base/core:3.0"}}"#;
    let start = r#"{"version":"1.1.0-alpha","phase":"start","sandboxId":"microvm:0123456789abcdef0123456789abcdef"}"#;
    let one_shot_error =
        "expected a one-shot request; lifecycle requests use the state-aware JSON entry points";
    let lifecycle_error =
        "expected a state-aware lifecycle request (with a 'phase' field), got a one-shot config";
    let envelope_error = "the exec phase does not return an envelope; run it through one of the exec entry points instead — attached to this process's stdio, or streaming with the caller driving the pipes";
    for experimental in [0, 1] {
        for call in [
            Call::Spawn(mxc_spawn_json),
            Call::Spawn(mxc_spawn_with_stdin_json),
            Call::Pty(mxc_spawn_pty_json, 24, 80),
        ] {
            assert_eq!(
                call_failure(call, EXEC, experimental),
                (MXC_STATUS_MALFORMED_REQUEST, one_shot_error.to_owned())
            );
        }
        for call in [
            Call::Envelope(false),
            Call::Envelope(true),
            Call::Spawn(mxc_exec_state_aware_json),
            Call::Spawn(mxc_exec_state_aware_with_stdin_json),
            Call::Pty(mxc_state_aware_exec_pty, 24, 80),
            Call::Capture,
            Call::Attached,
        ] {
            assert_eq!(
                call_failure(call, ONE_SHOT, experimental),
                (MXC_STATUS_MALFORMED_REQUEST, lifecycle_error.to_owned())
            );
        }
        for (request, phase) in [(provision, "provision"), (start, "start")] {
            for call in [
                Call::Spawn(mxc_exec_state_aware_json),
                Call::Spawn(mxc_exec_state_aware_with_stdin_json),
                Call::Pty(mxc_state_aware_exec_pty, 24, 80),
                Call::Capture,
            ] {
                assert_eq!(
                    call_failure(call, request, experimental),
                    (
                        MXC_STATUS_MALFORMED_REQUEST,
                        format!("live exec requires the exec phase, got {phase}")
                    )
                );
            }
            assert_eq!(
                call_failure(Call::Attached, request, experimental),
                (
                    MXC_STATUS_MALFORMED_REQUEST,
                    format!("an attached exec requires the exec phase, got {phase}")
                )
            );
        }
        assert_eq!(
            call_failure(Call::Envelope(false), EXEC, experimental),
            (MXC_STATUS_MALFORMED_REQUEST, envelope_error.to_owned())
        );
    }
}

#[test]
fn pty_dimension_errors_keep_priority_over_json_and_authorization() {
    for (spawn, request, authorized_status) in [
        (
            mxc_spawn_pty_json as PtySpawn,
            ONE_SHOT,
            MXC_STATUS_UNSUPPORTED_CONTAINMENT,
        ),
        (mxc_state_aware_exec_pty, EXEC, MXC_STATUS_UNSUPPORTED_PHASE),
    ] {
        for experimental in [0, 1] {
            for dimension in [0, 1, 32767, 32768, 65535] {
                for (rows, cols) in [(dimension, 80), (24, dimension)] {
                    let valid = (1..=32767).contains(&dimension);
                    let (status, message) =
                        call_failure(Call::Pty(spawn, rows, cols), request, experimental);
                    if valid {
                        assert_eq!(
                            status,
                            if experimental == 0 {
                                MXC_STATUS_BACKEND_UNAVAILABLE
                            } else {
                                authorized_status
                            },
                            "{message}"
                        );
                    } else {
                        let expected = if dimension == 0
                            && std::ptr::fn_addr_eq(spawn, mxc_state_aware_exec_pty as PtySpawn)
                        {
                            "PTY rows and columns must be non-zero"
                        } else {
                            "PTY rows and columns must be between 1 and 32767"
                        };
                        assert_eq!(
                            (status, message),
                            (MXC_STATUS_MALFORMED_REQUEST, expected.to_owned())
                        );
                        assert_eq!(
                            call_failure(Call::Pty(spawn, rows, cols), "{", experimental),
                            (MXC_STATUS_MALFORMED_REQUEST, expected.to_owned())
                        );
                    }
                }
            }
        }
    }
}

#[test]
fn invalid_lifecycle_pty_dimensions_never_normalize_or_probe() {
    use mxc_sdk::mxc_common::config_parser::filesystem_test_support::observe;

    let request = json!({
        "version": "1.1.0-alpha", "phase": "provision", "containment": "microvm",
        "microvm": {"image": "mcr.microsoft.com/azurelinux/base/core:3.0"},
        "filesystem": {"readonlyPaths": [std::env::current_dir().unwrap()]},
    })
    .to_string();
    for experimental in [0, 1] {
        for dimension in [0, 32768, 65535] {
            for (rows, cols) in [(dimension, 80), (24, dimension)] {
                let ((status, _), normalizations, metadata) = observe(|| {
                    call_failure(
                        Call::Pty(mxc_state_aware_exec_pty, rows, cols),
                        &request,
                        experimental,
                    )
                });
                assert_eq!(status, MXC_STATUS_MALFORMED_REQUEST);
                assert_eq!((normalizations, metadata), (0, 0));
            }
        }
    }
}

#[test]
fn wrong_operation_delegates_normalization_exactly_once() {
    use mxc_sdk::mxc_common::config_parser::filesystem_test_support::observe;

    let request = json!({
        "version": "1.1.0-alpha", "phase": "provision", "containment": "microvm",
        "microvm": {"image": "mcr.microsoft.com/azurelinux/base/core:3.0"},
        "filesystem": {"readonlyPaths": [std::env::current_dir().unwrap()]},
    })
    .to_string();
    for experimental in [0, 1] {
        for call in [
            Call::Spawn(mxc_exec_state_aware_json),
            Call::Spawn(mxc_exec_state_aware_with_stdin_json),
            Call::Pty(mxc_state_aware_exec_pty, 24, 80),
            Call::Capture,
            Call::Attached,
        ] {
            let ((status, message), normalizations, metadata) =
                observe(|| call_failure(call, &request, experimental));
            assert_eq!(status, MXC_STATUS_MALFORMED_REQUEST, "{message}");
            assert_eq!((normalizations, metadata), (1, 1));
        }
    }
}

#[test]
fn malformed_or_ambiguous_selectors_cannot_bypass_authoritative_validation() {
    let mut requests = Vec::new();
    for replacement in [
        r#""phase":null"#,
        r#""phase":7"#,
        r#""phase":{}"#,
        r#""phase":"""#,
        r#""phase":"unknown""#,
        r#""phase":"start","phase":"exec""#,
        r#""phase":"exec","phase":"start""#,
        r#""phase":"exec","ph\u0061se":"exec""#,
    ] {
        requests.push(EXEC.replace(r#""phase":"exec""#, replacement));
    }
    for replacement in [
        r#""containment":null"#,
        r#""containment":7"#,
        r#""containment":{}"#,
        r#""containment":"""#,
        r#""containment":"MicroVM""#,
        r#""containment":"microvm","containment":"process""#,
        r#""containment":"process","containment":"microvm""#,
        r#""containment":"microvm","contain\u006dent":"microvm""#,
    ] {
        requests.push(ONE_SHOT.replace(r#""containment":"microvm""#, replacement));
    }
    for replacement in [
        r#""sandboxId":null"#,
        r#""sandboxId":7"#,
        r#""sandboxId":{}"#,
        r#""sandboxId":"microvm:a","sandboxId":"iso:a""#,
        r#""sandboxId":"iso:a","sandboxId":"microvm:a""#,
        r#""sandboxId":"microvm:a","sandbox\u0049d":"microvm:a""#,
    ] {
        requests.push(EXEC.replace(
            r#""sandboxId":"microvm:0123456789abcdef0123456789abcdef""#,
            replacement,
        ));
    }
    requests.extend([
        ONE_SHOT.replace(r#""containment":"microvm","#, ""),
        EXEC.replace(
            r#""sandboxId":"microvm:0123456789abcdef0123456789abcdef","#,
            "",
        ),
        EXEC.replace(r#""phase":"exec","#, ""),
        format!("{ONE_SHOT} {{}}"),
        format!("{EXEC} {{}}"),
        ONE_SHOT.replace(
            r#""version":"1.1.0-alpha""#,
            r#""version":"99.0.0","version":"1.1.0-alpha""#,
        ),
        EXEC.replace(
            r#""version":"1.1.0-alpha""#,
            r#""version":"1.1.0-alpha","version":"99.0.0""#,
        ),
        "{".to_owned(),
        "[]".to_owned(),
    ]);
    for request in requests {
        for experimental in [0, 1] {
            for call in [
                Call::Spawn(mxc_spawn_json),
                Call::Spawn(mxc_spawn_with_stdin_json),
                Call::Pty(mxc_spawn_pty_json, 24, 80),
                Call::Envelope(false),
                Call::Envelope(true),
                Call::Spawn(mxc_exec_state_aware_json),
                Call::Spawn(mxc_exec_state_aware_with_stdin_json),
                Call::Pty(mxc_state_aware_exec_pty, 24, 80),
                Call::Capture,
                Call::Attached,
            ] {
                let (status, message) = call_failure(call, &request, experimental);
                assert_eq!(status, MXC_STATUS_MALFORMED_REQUEST, "{request}: {message}");
            }
        }
    }
}

#[test]
fn escaped_phase_and_selector_keys_keep_the_rust_only_exclusion() {
    let request = EXEC
        .replace("sandboxId", "sandbox\\u0049d")
        .replace(r#""exec""#, r#""e\u0078ec""#)
        .replace("microvm:", "micro\\u0076m:")
        .replace(
            r#""commandLine":"true""#,
            r#""commandLine":"true","timeout":3600001"#,
        );
    for experimental in [0, 1] {
        for call in [
            Call::Spawn(mxc_exec_state_aware_json),
            Call::Spawn(mxc_exec_state_aware_with_stdin_json),
            Call::Pty(mxc_state_aware_exec_pty, 24, 80),
            Call::Envelope(true),
            Call::Capture,
            Call::Attached,
        ] {
            let (status, message) = call_failure(call, &request, experimental);
            assert_eq!(
                status,
                if experimental == 0 {
                    MXC_STATUS_BACKEND_UNAVAILABLE
                } else {
                    MXC_STATUS_UNSUPPORTED_PHASE
                },
                "{message}"
            );
            if experimental != 0 {
                assert!(message.contains("only through Rust mxc_sdk::v1::dev JSON APIs"));
            }
        }
    }
    let request = ONE_SHOT
        .replace("containment", "contain\\u006dent")
        .replace("microvm", "micro\\u0076m")
        .replace(
            r#""commandLine":"true""#,
            r#""commandLine":"true","timeout":3600001"#,
        );
    for spawn in [mxc_spawn_json as Spawn, mxc_spawn_with_stdin_json] {
        assert_spawn_rejected(spawn, &request, MXC_STATUS_UNSUPPORTED_CONTAINMENT);
    }
}

#[test]
fn lifecycle_pty_preserves_pointer_utf8_and_zero_dimension_precedence() {
    let invalid_utf8 = [0xff_u8, 0];
    for experimental in [0, 1] {
        for dimension in [0, 1, 32767, 32768, 65535] {
            for (rows, cols) in [(dimension, 80), (24, dimension)] {
                for request in [ptr::null(), invalid_utf8.as_ptr().cast()] {
                    let mut handle = ptr::dangling_mut();
                    let mut detail = MaybeUninit::uninit();
                    // SAFETY: deliberately invalid framing with valid fresh output storage.
                    let status = unsafe {
                        mxc_state_aware_exec_pty(
                            request,
                            experimental,
                            rows,
                            cols,
                            &mut handle,
                            detail.as_mut_ptr(),
                        )
                    };
                    assert!(handle.is_null());
                    // SAFETY: the C entry point initialized the error storage.
                    let mut detail = unsafe { detail.assume_init() };
                    let expected = if dimension == 0 {
                        MXC_STATUS_MALFORMED_REQUEST
                    } else if request.is_null() {
                        MXC_STATUS_NULL_ARGUMENT
                    } else {
                        MXC_STATUS_INVALID_UTF8
                    };
                    let (status, message) = failure_detail(status, &mut detail);
                    assert_eq!(status, expected, "{message}");
                    // SAFETY: null output must win over the deliberately invalid request.
                    assert_eq!(
                        unsafe {
                            mxc_state_aware_exec_pty(
                                request,
                                experimental,
                                rows,
                                cols,
                                ptr::null_mut(),
                                ptr::null_mut(),
                            )
                        },
                        MXC_STATUS_NULL_ARGUMENT
                    );
                }
            }
        }
    }
}

fn assert_rejected_detail(
    status: i32,
    authorized_status: i32,
    experimental: i32,
    detail: &mut MxcErrorDetail,
) {
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
    if experimental == 0 {
        assert_eq!(status, MXC_STATUS_BACKEND_UNAVAILABLE, "{message}");
        assert_eq!(
            message,
            "the 'microvm' backend is experimental; enable experimental features to use it"
        );
    } else {
        assert_eq!(status, authorized_status, "{message}");
        assert!(message.contains("only through Rust mxc_sdk::v1::dev JSON APIs"));
    }
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
        assert_rejected_detail(status, expected, experimental, &mut detail);
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
        for experimental in [0, 1] {
            let mut handle = ptr::null_mut();
            let mut detail = MaybeUninit::uninit();
            // SAFETY: request and output pointers are valid.
            let status = unsafe {
                mxc_spawn_json(
                    json.as_ptr(),
                    experimental,
                    &mut handle,
                    detail.as_mut_ptr(),
                )
            };
            assert!(handle.is_null());
            // SAFETY: the entry point initialized detail.
            let mut detail = unsafe { detail.assume_init() };
            // SAFETY: detail owns only allocations returned by this library.
            unsafe { mxc_error_detail_free(&mut detail) };
            assert_eq!(status, MXC_STATUS_MALFORMED_REQUEST);
        }
    }
}

#[test]
fn filesystem_validation_preserves_malformed_request_errors() {
    let filesystem = json!({"readonlyPaths": ["\u{0}"]});
    let mut one_shot: serde_json::Value = serde_json::from_str(ONE_SHOT).unwrap();
    one_shot["filesystem"] = filesystem.clone();
    for (spawn, experimental) in [
        (mxc_spawn_json as Spawn, 0),
        (mxc_spawn_json as Spawn, 1),
        (mxc_spawn_with_stdin_json as Spawn, 0),
        (mxc_spawn_with_stdin_json as Spawn, 1),
    ] {
        let request = CString::new(one_shot.to_string()).unwrap();
        let mut handle = ptr::null_mut();
        let mut detail = MaybeUninit::uninit();
        // SAFETY: request and output pointers are valid.
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
    for experimental in [0, 1] {
        let mut result = MaybeUninit::<MxcStateAwareResult>::uninit();
        // SAFETY: request and result storage are valid for this call.
        let status = unsafe {
            mxc_run_state_aware_json(provision.as_ptr(), 0, experimental, result.as_mut_ptr())
        };
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
        for experimental in [0, 1] {
            let mut handle = ptr::dangling_mut();
            let mut detail = MaybeUninit::uninit();
            // SAFETY: the string, dimensions, and output locations meet the entry point contract.
            let status = unsafe {
                spawn(
                    request.as_ptr(),
                    experimental,
                    24,
                    80,
                    &mut handle,
                    detail.as_mut_ptr(),
                )
            };
            assert!(handle.is_null());
            // SAFETY: the entry point initialized detail.
            let mut detail = unsafe { detail.assume_init() };
            assert_rejected_detail(status, expected, experimental, &mut detail);
        }
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
        for (dry_run, experimental) in [(0, 0), (0, 1), (1, 0), (1, 1)] {
            let mut result = MaybeUninit::<MxcStateAwareResult>::uninit();
            // SAFETY: request is valid and result is writable storage.
            let status = unsafe {
                mxc_run_state_aware_json(
                    request.as_ptr(),
                    dry_run,
                    experimental,
                    result.as_mut_ptr(),
                )
            };
            // SAFETY: the entry point initialized result.
            let mut result = unsafe { result.assume_init() };
            assert_eq!(status, result.status);
            assert!(result.response_json_utf8.is_null());
            if phase == "exec" && dry_run == 0 {
                let (status, message) = failure_detail(status, &mut result.error);
                assert_eq!(status, MXC_STATUS_MALFORMED_REQUEST);
                assert!(message.starts_with("the exec phase does not return an envelope;"));
                // SAFETY: the error strings were already freed.
                unsafe { mxc_state_aware_result_free(&mut result) };
                continue;
            }
            assert_rejected_detail(
                status,
                MXC_STATUS_UNSUPPORTED_PHASE,
                experimental,
                &mut result.error,
            );
            // SAFETY: the result was populated; its error strings were already freed.
            unsafe { mxc_state_aware_result_free(&mut result) };
        }
    }
}

#[test]
fn captured_and_attached_lifecycle_exports_reject_microvm() {
    let request = CString::new(EXEC).unwrap();
    for experimental in [0, 1] {
        let mut result = MaybeUninit::<MxcRunResult>::uninit();
        // SAFETY: request is valid and result is writable storage.
        let status = unsafe {
            mxc_run_state_aware_exec_json(request.as_ptr(), experimental, result.as_mut_ptr())
        };
        // SAFETY: the entry point initialized result.
        let mut result = unsafe { result.assume_init() };
        assert!(result.stdout_utf8.is_null());
        assert!(result.stderr_utf8.is_null());
        assert_rejected_detail(
            status,
            MXC_STATUS_UNSUPPORTED_PHASE,
            experimental,
            &mut result.error,
        );
        // SAFETY: the result was populated; its error strings were already freed.
        unsafe { mxc_run_result_free(&mut result) };

        let mut outcome = MxcExecOutcome {
            timed_out: 42,
            exit_code: 43,
        };
        let mut detail = MaybeUninit::uninit();
        // SAFETY: request, outcome, and detail are valid for this call.
        let status = unsafe {
            mxc_exec_state_aware_attached_json(
                request.as_ptr(),
                experimental,
                &mut outcome,
                detail.as_mut_ptr(),
            )
        };
        assert_eq!((outcome.timed_out, outcome.exit_code), (42, 43));
        // SAFETY: the entry point initialized detail.
        let mut detail = unsafe { detail.assume_init() };
        assert_rejected_detail(
            status,
            MXC_STATUS_UNSUPPORTED_PHASE,
            experimental,
            &mut detail,
        );
    }
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
