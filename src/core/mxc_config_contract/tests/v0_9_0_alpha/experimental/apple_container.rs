// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use crate::common::{assert_invalid, assert_valid};

fn request(fields: &str) -> String {
    format!(
        r#"{{
            "version": "0.9.0-alpha",
            "containment": "apple_container",
            "experimental": {{
                "apple_container": {{{fields}}}
            }},
            "process": {{"commandLine": "echo"}}
        }}"#
    )
}

#[test]
fn accepts_required_image_and_optional_resources() {
    assert_valid(&request(r#""image": "docker.io/library/alpine:3.23""#));
    assert_valid(&request(
        r#""image": "docker.io/library/alpine:3.23", "cpuCount": 1, "memoryMb": 1"#,
    ));
    assert_valid(&request(&format!(
        r#""image": "docker.io/library/alpine:3.23", "cpuCount": {}, "memoryMb": {}"#,
        u32::MAX,
        u64::MAX
    )));
}

#[test]
fn rejects_missing_empty_or_non_string_image() {
    for fields in [
        "",
        r#""image": """#,
        r#""image": null"#,
        r#""image": 123"#,
        r#""image": true"#,
        r#""image": []"#,
        r#""image": {}"#,
    ] {
        assert_invalid(&request(fields));
    }
}

#[test]
fn rejects_invalid_resource_values() {
    for field in ["cpuCount", "memoryMb"] {
        for value in ["0", "-1", "1.5", r#""1""#, "true", "[]", "{}"] {
            assert_invalid(&request(&format!(
                r#""image": "docker.io/library/alpine:3.23", "{field}": {value}"#
            )));
        }
    }
    assert_invalid(&request(
        r#""image": "docker.io/library/alpine:3.23", "cpuCount": 4294967296"#,
    ));
    assert_invalid(&request(
        r#""image": "docker.io/library/alpine:3.23", "memoryMb": 18446744073709551616"#,
    ));
}

#[test]
fn rejects_unknown_or_duplicate_fields() {
    assert_invalid(&request(
        r#""image": "docker.io/library/alpine:3.23", "unknown": true"#,
    ));
    assert_invalid(&request(r#""image": "first", "image": "second""#));
}
