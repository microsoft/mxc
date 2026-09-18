// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use mxc_sdk::sandbox::{exec, provision, start, stop};
use mxc_sdk::ErrorCode;

#[test]
fn operation_specific_functions_take_routing_out_of_band() {
    let start_error = start(
        "nosuchbackend:abc123",
        r#"{"version":"0.9.0-alpha"}"#,
        false,
    )
    .unwrap_err();
    assert_eq!(start_error.code, ErrorCode::UnsupportedContainment);

    let stop_error = stop("no-prefix", r#"{"version":"0.9.0-alpha"}"#, false).unwrap_err();
    assert_eq!(stop_error.code, ErrorCode::MalformedId);

    match exec(
        "wsb:0a1b2c3d",
        r#"{"version":"0.9.0-alpha","process":{"commandLine":"echo hi"}}"#,
        false,
    ) {
        Ok(_) => panic!("the experimental gate must reject exec"),
        Err(error) => assert_eq!(error.code, ErrorCode::BackendUnavailable),
    }
}

#[test]
fn legacy_dispatch_fields_are_rejected() {
    for json in [
        r#"{"version":"0.9.0-alpha","phase":"provision","containment":"wslc"}"#,
        r#"{"version":"0.9.0-alpha","containment":"wslc","sandboxId":"wslc:abc"}"#,
    ] {
        let error = provision(json, true).unwrap_err();
        assert_eq!(error.code, ErrorCode::MalformedRequest);
        assert!(error.message.contains("unknown field"));
    }
}

#[test]
fn provision_does_not_require_a_process() {
    let json = r#"{"version":"0.9.0-alpha","containment":"windows_sandbox"}"#;
    if let Err(error) = provision(json, true) {
        assert_ne!(error.code, ErrorCode::MalformedRequest, "{}", error.message);
    }
}

#[test]
fn exec_requires_process_command_line() {
    match exec("wsb:0a1b2c3d", r#"{"version":"0.9.0-alpha"}"#, true) {
        Ok(_) => panic!("exec without process.commandLine must fail"),
        Err(error) => assert_eq!(error.code, ErrorCode::MalformedRequest),
    }
}

#[test]
fn direct_provision_payload_diagnostics_survive_the_sdk_boundary() {
    for fields in [
        r#""appId":null"#,
        r#""appId":17"#,
        r#""appId":"first","appId":"second""#,
        r#""appIdd":"typo""#,
    ] {
        let json = format!(
            "{{\n  \"version\":\"0.9.0-alpha\",\n  \
             \"containment\":\"isolation_session\",\n  \
             \"experimental\":{{\"isolation_session\":{{{fields}}}}}\n}}"
        );
        let error = provision(&json, true).unwrap_err();
        assert_eq!(error.code, ErrorCode::MalformedRequest, "{fields}");
        assert!(error.message.contains("experimental.isolation_session"));
        assert!(error.message.contains("line "));
        assert!(error.message.contains("column "));
    }
}

#[test]
fn experimental_backend_is_refused_without_optin() {
    let error = provision(
        r#"{"version":"0.9.0-alpha","containment":"windows_sandbox"}"#,
        false,
    )
    .unwrap_err();
    assert_eq!(error.code, ErrorCode::BackendUnavailable);
}
