// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use super::*;
use std::ffi::{CStr, CString};

fn assert_empty(detail: &MxcErrorDetail) {
    assert!(detail.message_utf8.is_null());
    assert!(detail.operation_utf8.is_null());
    assert!(detail.native_code_utf8.is_null());
    assert!(detail.remediation_utf8.is_null());
    assert!(detail.details_json_utf8.is_null());
}

#[test]
fn preparation_ffi_initializes_outputs_and_rejects_null_or_invalid_utf8_inputs() {
    let request = CString::new("{}").unwrap();
    let failures = CString::new(r#"{"formatVersion":1,"results":[]}"#).unwrap();
    let invalid = [0xffu8, 0];
    for (request, failures, expected) in [
        (ptr::null(), failures.as_ptr(), MXC_STATUS_NULL_ARGUMENT),
        (request.as_ptr(), ptr::null(), MXC_STATUS_NULL_ARGUMENT),
        (
            invalid.as_ptr().cast(),
            failures.as_ptr(),
            MXC_STATUS_INVALID_UTF8,
        ),
        (
            request.as_ptr(),
            invalid.as_ptr().cast(),
            MXC_STATUS_INVALID_UTF8,
        ),
    ] {
        let mut output = ptr::dangling_mut();
        let mut error = MxcErrorDetail::none();
        let status =
            unsafe { mxc_prepare_policy_json(request, failures, 0, &mut output, &mut error) };
        assert_eq!(status, expected);
        assert!(output.is_null());
        assert!(!error.message_utf8.is_null());
        unsafe {
            mxc_error_detail_free(&mut error);
            mxc_error_detail_free(&mut error);
        }
        assert_empty(&error);
    }
    let mut error = MxcErrorDetail::none();
    assert_eq!(
        unsafe {
            mxc_prepare_policy_json(
                request.as_ptr(),
                failures.as_ptr(),
                0,
                ptr::null_mut(),
                &mut error,
            )
        },
        MXC_STATUS_NULL_ARGUMENT,
    );
    assert_empty(&error);
}

#[test]
fn preparation_ffi_limits_and_parse_failures_do_not_return_input_as_ordinary_errors() {
    let empty = r#"{"formatVersion":1,"results":[]}"#;
    let oversized_request = format!("INPUT_SECRET_MARKER{}", "x".repeat(8 * 1024 * 1024));
    let oversized_failures = format!("INPUT_SECRET_MARKER{}", "x".repeat(4 * 1024 * 1024));
    for (request, failures) in [
        (&*oversized_request, empty),
        ("{}", &*oversized_failures),
        ("{}", "INPUT_SECRET_MARKER"),
        (
            r#"{"version":"1.0.0","process":{"commandLine":"INPUT_SECRET_MARKER"},"INPUT_SECRET_MARKER":true}"#,
            empty,
        ),
    ] {
        let request = CString::new(request).unwrap();
        let failures = CString::new(failures).unwrap();
        let mut output = ptr::dangling_mut();
        let mut error = MxcErrorDetail::none();
        let status = unsafe {
            mxc_prepare_policy_json(
                request.as_ptr(),
                failures.as_ptr(),
                1,
                &mut output,
                &mut error,
            )
        };
        assert_eq!(status, MXC_STATUS_MALFORMED_REQUEST);
        assert!(output.is_null());
        let message = unsafe { CStr::from_ptr(error.message_utf8) }
            .to_str()
            .unwrap();
        assert!(!message.contains("INPUT_SECRET_MARKER"));
        unsafe { mxc_error_detail_free(&mut error) };
        assert_empty(&error);
        assert_eq!(
            unsafe {
                mxc_prepare_policy_json(
                    request.as_ptr(),
                    failures.as_ptr(),
                    0,
                    &mut output,
                    ptr::null_mut(),
                )
            },
            MXC_STATUS_MALFORMED_REQUEST,
        );
        assert!(output.is_null());
    }
}

#[test]
fn preparation_json_output_uses_existing_string_and_error_ownership() {
    let json = r#"{"requestJson":"{\"allowed\":true}","changes":[{"operation":"add","path":"/allowed","before":null,"after":true}]}"#;
    let mut output = ptr::null_mut();
    let mut detail = MxcErrorDetail::none();
    assert_eq!(
        write_json_outcome(Ok(alloc_cstring(json.as_bytes())), &mut output, &mut detail),
        MXC_STATUS_SUCCESS,
    );
    let serialized = unsafe { CStr::from_ptr(output) }.to_str().unwrap();
    let prepared = mxc_sdk::v1::dev::PreparedPolicyRequest::from_json(serialized).unwrap();
    assert_eq!(prepared.request_json, r#"{"allowed":true}"#);
    assert_eq!(prepared.changes[0].before, serde_json::Value::Null);
    assert_empty(&detail);
    unsafe { mxc_string_free(output) };
    output = ptr::null_mut();
    let mut error = Error::new(
        ErrorCode::PolicyValidation,
        "Policy preparation failed safely.",
    );
    error.details = Some(Box::new(serde_json::json!({
        "policyFeedbackError": {"code":"unsafeReplay","reason":"unsupported observation"}
    })));
    assert_eq!(
        write_json_outcome(Err(json_error(error.clone())), &mut output, &mut detail),
        MXC_STATUS_POLICY_VALIDATION,
    );
    assert!(output.is_null());
    assert_eq!(
        serde_json::from_str::<serde_json::Value>(
            unsafe { CStr::from_ptr(detail.details_json_utf8) }
                .to_str()
                .unwrap()
        )
        .unwrap(),
        *error.details.unwrap(),
    );
    unsafe { mxc_error_detail_free(&mut detail) };
    assert_empty(&detail);
}
