// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.
use crate::common::{assert_invalid, assert_valid};

#[test]
fn accepts_complete_seatbelt_object() {
    let json = r#"{
        "version": "1.1.0-alpha",
        "seatbelt": {
            "profileOverride": "none",
            "guiAccess": false,
            "nestedPty": false,
            "keychainAccess": false,
            "extraMachLookups": ["com.apple.securityd", "com.apple.coreservices.launchservicesd"]
        },
        "process": {"commandLine": "echo"}
    }"#;

    assert_valid(json);
}

#[test]
fn rejects_seatbelt_launch_method() {
    for launch_method in ["exec", "open", "invalid"] {
        let json = format!(
            r#"{{
                "version": "1.1.0-alpha",
                "seatbelt": {{
                    "launchMethod": "{launch_method}"
                }},
                "process": {{"commandLine": "echo"}}
            }}"#
        );

        assert_invalid(&json);
    }
}

#[test]
fn accepts_empty_profile_override() {
    let json = r#"{
        "version": "1.1.0-alpha",
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
                "version": "1.1.0-alpha",
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
                "version": "1.1.0-alpha",
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
                "version": "1.1.0-alpha",
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
                "version": "1.1.0-alpha",
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
                "version": "1.1.0-alpha",
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
                "version": "1.1.0-alpha",
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
        "version": "1.1.0-alpha",
        "seatbelt": {
            "unknownField": "value"
        },
        "process": {"commandLine": "echo"}
    }"#;

    assert_invalid(json);
}

#[test]
fn rejects_macos_sandbox_section_alias() {
    let json = r#"{
        "version": "1.1.0-alpha",
        "macos_sandbox": {
            "profileOverride": "none"
        },
        "process": {"commandLine": "echo"}
    }"#;

    assert_invalid(json);
}

#[test]
fn rejects_seatbelt_and_macos_sandbox_section_alias_together() {
    let json = r#"{
        "version": "1.1.0-alpha",
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

#[test]
fn accepts_seatbelt_capture_denials() {
    for body in [
        r#"{}"#,
        r#"{"mode": "block"}"#,
        r#"{"mode": "allow", "outputPath": "/tmp/denials.json"}"#,
        r#"{"retainEtl": true}"#,
    ] {
        let json = format!(
            r#"{{
                "version": "1.1.0-alpha",
                "seatbelt": {{"captureDenials": {body}}},
                "process": {{"commandLine": "echo"}}
            }}"#
        );

        assert_valid(&json);
    }
}

#[test]
fn rejects_invalid_seatbelt_capture_denials() {
    for body in [
        r#"true"#,
        r#"{"mode": "audit"}"#,
        r#"{"outputPath": 1}"#,
        r#"{"retainEtl": "yes"}"#,
    ] {
        let json = format!(
            r#"{{
                "version": "1.1.0-alpha",
                "seatbelt": {{"captureDenials": {body}}},
                "process": {{"commandLine": "echo"}}
            }}"#
        );

        assert_invalid(&json);
    }
}

#[test]
fn accepts_seatbelt_custom_rules() {
    for body in [
        r#""customIoKits": {}"#,
        r#""customIoKits": {"default": "deny", "allow": ["AGXDeviceUserClient", "IOSurface*"], "deny": []}"#,
        r#""customMachLookups": {"default": "allow", "deny": ["com.example.*"]}"#,
        r#""customMachRegisters": {}"#,
        r#""customMachRegisters": {"global": {"allow": ["com.example.a"]}, "local": {"default": "allow"}}"#,
        r#""customPosixShm": {}"#,
        r#""customPosixShm": {"default": "deny", "read": ["apple.shm.*"], "readWrite": ["/app.rw"], "own": ["/app.*"], "deny": ["/app.secret"]}"#,
        r#""customPosixShm": {"default": "readWrite", "create": ["/app.c*"]}"#,
    ] {
        let json = format!(
            r#"{{
                "version": "1.1.0-alpha",
                "seatbelt": {{{body}}},
                "process": {{"commandLine": "echo"}}
            }}"#
        );

        assert_valid(&json);
    }
}

#[test]
fn rejects_invalid_seatbelt_custom_rules() {
    for body in [
        r#""customIoKits": true"#,
        r#""customIoKits": {"default": "audit"}"#,
        r#""customMachLookups": {"allow": "com.example.a"}"#,
        r#""customMachLookups": {"extra": []}"#,
        r#""customMachRegisters": {"global": {"default": "allow"}, "session": {}}"#,
        r#""customMachRegisters": {"default": "allow"}"#,
        r#""customPosixShm": true"#,
        r#""customPosixShm": {"allow": ["/app"]}"#,
        r#""customPosixShm": {"readWrite": "/app"}"#,
        r#""customPosixShm": {"default": "allow"}"#,
    ] {
        let json = format!(
            r#"{{
                "version": "1.1.0-alpha",
                "seatbelt": {{{body}}},
                "process": {{"commandLine": "echo"}}
            }}"#
        );

        assert_invalid(&json);
    }
}
