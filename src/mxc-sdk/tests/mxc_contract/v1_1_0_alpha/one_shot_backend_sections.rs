// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use crate::common::assert_invalid;

#[test]
fn registry_authoring_preserves_the_optional_copy_on_write_choice() {
    let request: crate::OneShotRequest = serde_json::from_str(
        r#"{
            "version":"1.1.0-alpha",
            "process":{"commandLine":"echo"},
            "processContainer":{"registry":{"HKCU":[
                {"path":"Software\\Contoso\\Default"},
                {"path":"Software\\Contoso\\Private","copyOnWrite":true},
                {"path":"Software\\Contoso\\Shared","copyOnWrite":false}
            ]}}
        }"#,
    )
    .unwrap();
    let keys = request
        .process_container.into_option().unwrap()
        .registry.into_option().unwrap()
        .hkcu.into_option().unwrap();
    assert_eq!(keys[0].path.as_str(), r"Software\Contoso\Default");
    assert_eq!(keys[0].copy_on_write.as_ref(), None);
    assert_eq!(keys[1].copy_on_write.as_ref(), Some(&true));
    assert_eq!(keys[2].copy_on_write.as_ref(), Some(&false));
}

#[test]
fn registry_authoring_rejects_malformed_and_unknown_fields() {
    for registry in [
        r#"null"#,
        r#"{"HKLM":[]}"#,
        r#"{"hkcu":[]}"#,
        r#"{"HKCU":null}"#,
        r#"{"HKCU":["Software\\Contoso"]}"#,
        r#"{"HKCU":[{}]}"#,
        r#"{"HKCU":[{"path":""}]}"#,
        r#"{"HKCU":[{"path":null}]}"#,
        r#"{"HKCU":[{"path":"Software\\Contoso","copyOnWrite":null}]}"#,
        r#"{"HKCU":[{"path":"Software\\Contoso","copyOnWrite":"false"}]}"#,
        r#"{"HKCU":[{"path":"Software\\Contoso","copyOnWrite":false,"unknown":true}]}"#,
    ] {
        assert_invalid(&format!(
            r#"{{
                "version":"1.1.0-alpha",
                "process":{{"commandLine":"echo"}},
                "processContainer":{{"registry":{registry}}}
            }}"#
        ));
    }
}

#[test]
fn published_contracts_do_not_accept_registry_policy() {
    let json = r#"{
        "version":"1.0.0",
        "process":{"commandLine":"echo"},
        "processContainer":{"registry":{"HKCU":[{"path":"Software\\Contoso"}]}}
    }"#;
    assert!(serde_json::from_str::<
        mxc_sdk::mxc_contract::published::v1_0_0::OneShotRequest,
    >(json)
    .is_err());
    assert!(serde_json::from_str::<
        mxc_sdk::mxc_contract::published::v0_9_0_alpha::OneShotRequest,
    >(&json.replace("1.0.0", "0.9.0-alpha"))
    .is_err());
}

#[test]
fn rejects_state_aware_backend_sections() {
    let isolation_session = r#"{
        "version": "1.1.0-alpha",
        "process": {"commandLine": "echo"},
        "isolationSession": {"provision": {}}
    }"#;
    let wslc = r#"{
        "version": "1.1.0-alpha",
        "process": {"commandLine": "echo"},
        "wslc": {"provision": {}}
    }"#;

    assert_invalid(isolation_session);
    assert_invalid(wslc);
}
