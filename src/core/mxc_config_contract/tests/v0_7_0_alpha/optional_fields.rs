// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use crate::common::{assert_invalid_cases, assert_valid};
use mxc_config_contract::published::v0_7_0_alpha::Request;

#[test]
fn accepts_empty_optional_objects() {
    for field in [
        r#""lifecycle": {}"#,
        r#""filesystem": {}"#,
        r#""fallback": {}"#,
        r#""network": {}"#,
        r#""ui": {}"#,
        r#""containment": "processcontainer", "processContainer": {}"#,
        r#""containment": "processcontainer", "processContainer": {"ui": {}}"#,
        r#""containment": "seatbelt", "seatbelt": {}"#,
    ] {
        let json = format!(
            r#"{{
                "version": "0.7.0-alpha",
                "process": {{"commandLine": "echo"}},
                {field}
            }}"#
        );

        assert_valid(&json);
    }
}

#[test]
fn accepts_empty_optional_array_for_process_env() {
    let json = r#"{
        "version": "0.7.0-alpha",
        "process": {"commandLine": "echo", "env": []}
    }"#;

    assert_valid(json);
}

#[test]
fn accepts_empty_optional_arrays() {
    for field in [
        r#""filesystem": {"readwritePaths": []}"#,
        r#""filesystem": {"readonlyPaths": []}"#,
        r#""filesystem": {"deniedPaths": []}"#,
        r#""network": {"allowedHosts": []}"#,
        r#""network": {"blockedHosts": []}"#,
        r#""containment": "processcontainer", "processContainer": {"capabilities": []}"#,
        r#""containment": "seatbelt", "seatbelt": {"extraMachLookups": []}"#,
    ] {
        let json = format!(
            r#"{{
                "version": "0.7.0-alpha",
                "process": {{"commandLine": "echo"}},
                {field}
            }}"#
        );

        assert_valid(&json);
    }
}

#[test]
fn accepts_absent_optional_fields() {
    let json = r#"{
            "version": "0.7.0-alpha",
            "process": {"commandLine": "echo"}
        }"#;

    serde_json::from_str::<Request>(json).unwrap();
}

#[test]
fn rejects_null_optional_fields() {
    let version = r#""version": "0.7.0-alpha""#;
    let process = r#""process": {"commandLine": "echo"}"#;
    let version_and_process = format!("{version}, {process}");

    assert_invalid_cases(
        [
            (
                "containerId",
                version_and_process.as_str(),
                r#""containerId": null"#,
            ),
            (
                "containment",
                version_and_process.as_str(),
                r#""containment": null"#,
            ),
            (
                "lifecycle",
                version_and_process.as_str(),
                r#""lifecycle": null"#,
            ),
            (
                "filesystem",
                version_and_process.as_str(),
                r#""filesystem": null"#,
            ),
            (
                "fallback",
                version_and_process.as_str(),
                r#""fallback": null"#,
            ),
            (
                "network",
                version_and_process.as_str(),
                r#""network": null"#,
            ),
            ("ui", version_and_process.as_str(), r#""ui": null"#),
            (
                "processContainer",
                version_and_process.as_str(),
                r#""processContainer": null"#,
            ),
            (
                "appContainer",
                version_and_process.as_str(),
                r#""appContainer": null"#,
            ),
            ("lxc", version_and_process.as_str(), r#""lxc": null"#),
            (
                "macos_sandbox",
                version_and_process.as_str(),
                r#""macos_sandbox": null"#,
            ),
            (
                "seatbelt",
                version_and_process.as_str(),
                r#""seatbelt": null"#,
            ),
            (
                "seatbelt.profileOverride",
                version_and_process.as_str(),
                r#""seatbelt": {"profileOverride": null}"#,
            ),
            (
                "seatbelt.guiAccess",
                version_and_process.as_str(),
                r#""seatbelt": {"guiAccess": null}"#,
            ),
            (
                "seatbelt.launchMethod",
                version_and_process.as_str(),
                r#""seatbelt": {"launchMethod": null}"#,
            ),
            (
                "seatbelt.nestedPty",
                version_and_process.as_str(),
                r#""seatbelt": {"nestedPty": null}"#,
            ),
            (
                "seatbelt.keychainAccess",
                version_and_process.as_str(),
                r#""seatbelt": {"keychainAccess": null}"#,
            ),
            (
                "seatbelt.extraMachLookups",
                version_and_process.as_str(),
                r#""seatbelt": {"extraMachLookups": null}"#,
            ),
            (
                "lifecycle.destroyOnExit",
                version_and_process.as_str(),
                r#""lifecycle": {"destroyOnExit": null}"#,
            ),
            (
                "lifecycle.preservePolicy",
                version_and_process.as_str(),
                r#""lifecycle": {"preservePolicy": null}"#,
            ),
            (
                "process.cwd",
                version,
                r#""process": {"commandLine": "echo", "cwd": null}"#,
            ),
            (
                "process.env",
                version,
                r#""process": {"commandLine": "echo", "env": null}"#,
            ),
            (
                "process.timeout",
                version,
                r#""process": {"commandLine": "echo", "timeout": null}"#,
            ),
            (
                "filesystem.readwritePaths",
                version_and_process.as_str(),
                r#""filesystem": {"readwritePaths": null}"#,
            ),
            (
                "filesystem.readonlyPaths",
                version_and_process.as_str(),
                r#""filesystem": {"readonlyPaths": null}"#,
            ),
            (
                "filesystem.deniedPaths",
                version_and_process.as_str(),
                r#""filesystem": {"deniedPaths": null}"#,
            ),
            (
                "fallback.allowDaclMutation",
                version_and_process.as_str(),
                r#""fallback": {"allowDaclMutation": null}"#,
            ),
            (
                "network.defaultPolicy",
                version_and_process.as_str(),
                r#""network": {"defaultPolicy": null}"#,
            ),
            (
                "network.enforcementMode",
                version_and_process.as_str(),
                r#""network": {"enforcementMode": null}"#,
            ),
            (
                "network.allowedHosts",
                version_and_process.as_str(),
                r#""network": {"allowedHosts": null}"#,
            ),
            (
                "network.blockedHosts",
                version_and_process.as_str(),
                r#""network": {"blockedHosts": null}"#,
            ),
            (
                "network.allowLocalNetwork",
                version_and_process.as_str(),
                r#""network": {"allowLocalNetwork": null}"#,
            ),
            (
                "network.proxy",
                version_and_process.as_str(),
                r#""network": {"proxy": null}"#,
            ),
            (
                "ui.disable",
                version_and_process.as_str(),
                r#""ui": {"disable": null}"#,
            ),
            (
                "ui.clipboard",
                version_and_process.as_str(),
                r#""ui": {"clipboard": null}"#,
            ),
            (
                "ui.injection",
                version_and_process.as_str(),
                r#""ui": {"injection": null}"#,
            ),
            (
                "processContainer.leastPrivilege",
                version_and_process.as_str(),
                r#""processContainer": {"leastPrivilege": null}"#,
            ),
            (
                "processContainer.capabilities",
                version_and_process.as_str(),
                r#""processContainer": {"capabilities": null}"#,
            ),
            (
                "processContainer.ui",
                version_and_process.as_str(),
                r#""processContainer": {"ui": null}"#,
            ),
            (
                "processContainer.ui.isolation",
                version_and_process.as_str(),
                r#""processContainer": {"ui": {"isolation": null}}"#,
            ),
            (
                "processContainer.ui.desktopSystemControl",
                version_and_process.as_str(),
                r#""processContainer": {"ui": {"desktopSystemControl": null}}"#,
            ),
            (
                "processContainer.ui.systemSettings",
                version_and_process.as_str(),
                r#""processContainer": {"ui": {"systemSettings": null}}"#,
            ),
            (
                "processContainer.ui.ime",
                version_and_process.as_str(),
                r#""processContainer": {"ui": {"ime": null}}"#,
            ),
        ],
        "null optional field",
    );
}
