// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
use crate::common::{assert_invalid, assert_valid};

#[test]
fn accepts_complete_seatbelt_object() {
    let json = r#"{
        "version": "0.8.0-alpha",
        "containment": "seatbelt",
        "seatbelt": {
            "profileOverride": "none",
            "guiAccess": false,
            "launchMethod": "exec",
            "nestedPty": false,
            "keychainAccess": false,
            "extraMachLookups": ["com.apple.securityd", "com.apple.coreservices.launchservicesd"]
        },
        "process": {"commandLine": "echo"}
    }"#;

    assert_valid(json);
}

#[test]
fn accepts_every_seatbelt_launch_method() {
    for launch_method in ["exec", "open"] {
        let json = format!(
            r#"{{
                "version": "0.8.0-alpha",
                "containment": "seatbelt",
                "seatbelt": {{
                    "launchMethod": "{launch_method}"
                }},
                "process": {{"commandLine": "echo"}}
            }}"#
        );

        assert_valid(&json);
    }
}

#[test]
fn rejects_invalid_seatbelt_launch_method() {
    let json = r#"{
            "version": "0.8.0-alpha",
            "containment": "seatbelt",
            "seatbelt": {
                "launchMethod": "invalid"
            },
            "process": {"commandLine": "echo"}
        }"#;

    assert_invalid(json);
}

#[test]
fn accepts_empty_profile_override() {
    let json = r#"{
        "version": "0.8.0-alpha",
        "seatbelt": {
            "profileOverride": ""
        },
        "process": {"commandLine": "echo"}
    }"#;

    assert_valid(json);
}

#[test]
fn rejects_non_string_extra_mach_lookup_items() {
    for extra_mach_lookup in ["true", "false", "0", "1", "[]", "{}"] {
        let json = format!(
            r#"{{
                "version": "0.8.0-alpha",
                "seatbelt": {{
                    "extraMachLookups": [{extra_mach_lookup}]
                }},
                "process": {{"commandLine": "echo"}}
            }}"#
        );

        assert_invalid(&json);
    }
}

#[test]
fn rejects_non_array_extra_mach_lookups() {
    for extra_mach_lookup in ["true", "false", "0", "1", "\"string\"", "{}"] {
        let json = format!(
            r#"{{
                "version": "0.8.0-alpha",
                "seatbelt": {{
                    "extraMachLookups": {extra_mach_lookup}
                }},
                "process": {{"commandLine": "echo"}}
            }}"#
        );

        assert_invalid(&json);
    }
}

#[test]
fn rejects_non_string_profile_override_values() {
    for profile_override in ["true", "false", "0", "1", "[]", "{}"] {
        let json = format!(
            r#"{{
                "version": "0.8.0-alpha",
                "seatbelt": {{
                    "profileOverride": {profile_override}
                }},
                "process": {{"commandLine": "echo"}}
            }}"#
        );

        assert_invalid(&json);
    }
}

#[test]
fn rejects_non_boolean_gui_access_values() {
    for gui_access in ["0", "1", "\"string\"", "[]", "{}"] {
        let json = format!(
            r#"{{
                "version": "0.8.0-alpha",
                "seatbelt": {{
                    "guiAccess": {gui_access}
                }},
                "process": {{"commandLine": "echo"}}
            }}"#
        );

        assert_invalid(&json);
    }
}

#[test]
fn rejects_non_boolean_nested_pty_values() {
    for nested_pty in ["0", "1", "\"string\"", "[]", "{}"] {
        let json = format!(
            r#"{{
                "version": "0.8.0-alpha",
                "seatbelt": {{
                    "nestedPty": {nested_pty}
                }},
                "process": {{"commandLine": "echo"}}
            }}"#
        );

        assert_invalid(&json);
    }
}

#[test]
fn rejects_non_boolean_keychain_access_values() {
    for keychain_access in ["0", "1", "\"string\"", "[]", "{}"] {
        let json = format!(
            r#"{{
                "version": "0.8.0-alpha",
                "seatbelt": {{
                    "keychainAccess": {keychain_access}
                }},
                "process": {{"commandLine": "echo"}}
            }}"#
        );

        assert_invalid(&json);
    }
}

#[test]
fn rejects_unknown_seatbelt_field() {
    let json = r#"{
        "version": "0.8.0-alpha",
        "seatbelt": {
            "unknownField": "value"
        },
        "process": {"commandLine": "echo"}
    }"#;

    assert_invalid(json);
}

#[test]
fn accepts_macos_sandbox_section_alias() {
    let json = r#"{
        "version": "0.8.0-alpha",
        "containment": "macos_sandbox",
        "macos_sandbox": {
            "profileOverride": "none"
        },
        "process": {"commandLine": "echo"}
    }"#;

    assert_valid(json);
}

#[test]
fn rejects_seatbelt_and_macos_sandbox_section_alias_together() {
    let json = r#"{
        "version": "0.8.0-alpha",
        "seatbelt": {
            "profileOverride": "none"
        },
        "macos_sandbox": {
            "profileOverride": "none"
        },
        "process": {"commandLine": "echo"}
    }"#;

    assert_invalid(json);
}
