// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

// Pure provider-definition code generation shared between `build.rs` and the
// crate's unit tests.
//
// Cargo never runs `#[cfg(test)]` modules inside a build script, so the logic
// lives here and is pulled into both `build.rs` and a `#[cfg(test)]` module in
// `lib.rs` via `include!`. That keeps the GUID validation and code-generation
// behaviour unit-testable with `cargo test`.

/// Parses `s` as a strict, canonical hyphenated GUID
/// (`xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx`) and returns its lowercase canonical
/// form.
///
/// Validation is delegated to the `uuid` crate. Because `uuid`'s parser is
/// lenient (it also accepts braced `{...}`, `urn:uuid:`, and unhyphenated
/// 32-hex forms), we additionally require the input to already be in the
/// canonical hyphenated shape (case-insensitively). This keeps the accepted
/// grammar identical to the original hand-rolled validator and guarantees the
/// returned string is a bare hyphenated GUID — safe to interpolate into the
/// generated Rust source that is `include!()`'d.
fn canonicalize_guid(s: &str) -> Option<String> {
    let canonical = uuid::Uuid::try_parse(s).ok()?.as_hyphenated().to_string();
    s.eq_ignore_ascii_case(&canonical).then_some(canonical)
}

/// Validates that `s` is a well-formed, canonical hyphenated GUID
/// (`xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx`). Prevents code injection via the
/// environment variable since the value is interpolated into generated Rust
/// source that is `include!()`'d.
///
/// Only referenced from the unit tests; `generate_provider_def` calls
/// `canonicalize_guid` directly. `allow(dead_code)` keeps the build script
/// (which `include!`s this file but never calls the helper) warning-clean.
#[allow(dead_code)]
fn is_valid_guid(s: &str) -> bool {
    canonicalize_guid(s).is_some()
}

/// Generate two registration handles with the same provider name/GUID.
/// Each group is optional and independently validated; neither substitutes
/// for the other's private build input.
fn generate_provider_def(group_guid: Option<&str>, core_group_guid: Option<&str>) -> String {
    let mut definition = String::new();
    for (handle, guid, input) in [
        (
            "MXC_PROVIDER",
            group_guid,
            "MXC_TELEMETRY_PROVIDER_GROUP_GUID",
        ),
        (
            "MXC_CORE_PROVIDER",
            core_group_guid,
            "MXC_TELEMETRY_CORE_PROVIDER_GROUP_GUID",
        ),
    ] {
        let group = match guid {
            Some(guid) if !guid.is_empty() => {
                let canonical = canonicalize_guid(guid)
                    .unwrap_or_else(|| panic!("{input} is not a valid GUID"));
                format!(", group_id(\"{canonical}\")")
            }
            _ => String::new(),
        };
        definition.push_str(&format!(
            "tracelogging::define_provider!({handle}, \"Microsoft.MXC\"{group});\n"
        ));
    }
    definition.push_str(&format!(
        "pub const IS_UTC_ROUTED: bool = {};\n\
         pub(crate) const IS_CORE_UTC_ROUTED: bool = {};\n",
        matches!(group_guid, Some(guid) if !guid.is_empty()),
        matches!(core_group_guid, Some(guid) if !guid.is_empty()),
    ));
    definition
}

/// Validate the opt-in for local-only keyword-classification tests.
fn local_keyword_test_enabled(
    value: Option<&str>,
    permitted: bool,
    group_guid: Option<&str>,
    core_group_guid: Option<&str>,
) -> bool {
    match value {
        None | Some("") => false,
        Some("1") => {
            assert!(
                permitted
                    && !matches!(group_guid, Some(guid) if !guid.is_empty())
                    && !matches!(core_group_guid, Some(guid) if !guid.is_empty()),
                "MXC_TELEMETRY_TEST_KEYWORDS requires a local-only Windows debug test-support build"
            );
            true
        }
        Some(_) => panic!("MXC_TELEMETRY_TEST_KEYWORDS must be unset, empty, or 1"),
    }
}

/// Each registration's metadata follows its own routing input. Ordinary local
/// registrations use keyword 1 and privacy tag 0. The guarded local test mode
/// supplies real metadata for both handles without routing either one.
fn generate_event_metadata_consts(
    group_guid: Option<&str>,
    core_group_guid: Option<&str>,
    test_keywords: bool,
) -> String {
    let (keyword, privacy) =
        if matches!(group_guid, Some(guid) if !guid.is_empty()) || test_keywords {
            ("0x0000_4000_0000_0000", "0x0000_0000_0200_0000")
        } else {
            ("0x1", "0x0")
        };
    let (core_keyword, core_privacy) =
        if matches!(core_group_guid, Some(guid) if !guid.is_empty()) || test_keywords {
            ("0x0000_8000_0000_0000", "0x0000_0000_0100_0000")
        } else {
            ("0x1", "0x0")
        };
    format!(
        "pub(crate) const MXC_EVENT_KEYWORD: u64 = {keyword};\n\
         pub(crate) const MXC_PRIVACY_TAG: u64 = {privacy};\n\
         pub(crate) const MXC_CRITICAL_EVENT_KEYWORD: u64 = {core_keyword};\n\
         pub(crate) const MXC_CRITICAL_PRIVACY_TAG: u64 = {core_privacy};\n"
    )
}
