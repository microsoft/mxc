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

/// Routing metadata carried by the signed telemetry component.
#[allow(dead_code)]
struct ComponentMetadata {
    group: String,
    keyword: u64,
    privacy_tag: u64,
    critical_keyword: u64,
    critical_privacy_tag: u64,
    privacy_product: u16,
    privacy_data_category: u16,
}

/// Parses `1;<group>;<keyword>;<privacy>;<critical keyword>;<critical privacy>;<product>;<category>`
/// where the numbers are `0x`-prefixed hex.
#[allow(dead_code)]
fn parse_component_metadata(text: &str) -> Result<ComponentMetadata, String> {
    let parts: Vec<&str> = text.split(';').collect();
    if parts.len() != 8 || parts[0] != "1" {
        return Err("unsupported metadata format".into());
    }
    let hex = |value: &str| {
        value
            .strip_prefix("0x")
            .and_then(|digits| u64::from_str_radix(&digits.replace('_', ""), 16).ok())
            .ok_or_else(|| "malformed numeric metadata".to_string())
    };
    let small = |value: &str| {
        hex(value).and_then(|n| u16::try_from(n).map_err(|_| "metadata value out of range".into()))
    };
    Ok(ComponentMetadata {
        group: canonicalize_guid(parts[1]).ok_or("malformed group metadata")?,
        keyword: hex(parts[2])?,
        privacy_tag: hex(parts[3])?,
        critical_keyword: hex(parts[4])?,
        critical_privacy_tag: hex(parts[5])?,
        privacy_product: small(parts[6])?,
        privacy_data_category: small(parts[7])?,
    })
}

/// Generate one registration for all MXC events, optionally in the WinExt group.
fn generate_provider_def(group_guid: Option<&str>) -> String {
    let group = match group_guid {
        Some(guid) if !guid.is_empty() => {
            let canonical = canonicalize_guid(guid)
                .expect("MXC_TELEMETRY_PROVIDER_GROUP_GUID is not a valid GUID");
            format!(", group_id(\"{canonical}\")")
        }
        _ => String::new(),
    };
    format!(
        "tracelogging::define_provider!(MXC_PROVIDER, \"Microsoft.MXC\"{group});\n\
         pub const IS_UTC_ROUTED: bool = {};\n",
        matches!(group_guid, Some(guid) if !guid.is_empty()),
    )
}

/// Validate the opt-in for local-only keyword-classification tests.
fn local_keyword_test_enabled(
    value: Option<&str>,
    permitted: bool,
    group_guid: Option<&str>,
) -> bool {
    match value {
        None | Some("") => false,
        Some("1") => {
            assert!(
                permitted
                    && !matches!(group_guid, Some(guid) if !guid.is_empty()),
                "MXC_TELEMETRY_TEST_KEYWORDS requires a local-only Windows debug test-support build"
            );
            true
        }
        Some(_) => panic!("MXC_TELEMETRY_TEST_KEYWORDS must be unset, empty, or 1"),
    }
}

/// Event metadata passed to the crate as compile-time environment variables.
#[derive(Debug, PartialEq)]
struct EventMetadata {
    keyword: u64,
    privacy_tag: u64,
    critical_keyword: u64,
    critical_privacy_tag: u64,
    privacy_product: u16,
    privacy_data_category: u16,
    eligible: bool,
}

/// Both event categories use the single registration's routing input.
/// Local builds use keyword 1 and privacy tag 0 unless the guarded test mode
/// enables metadata validation without routing. Component metadata overrides
/// every value.
fn event_metadata(
    group_guid: Option<&str>,
    test_keywords: bool,
    component: Option<&ComponentMetadata>,
) -> EventMetadata {
    let routed = matches!(group_guid, Some(guid) if !guid.is_empty()) || test_keywords;
    let (keyword, privacy_tag, critical_keyword, critical_privacy_tag) = match component {
        Some(c) => (
            c.keyword,
            c.privacy_tag,
            c.critical_keyword,
            c.critical_privacy_tag,
        ),
        None if routed => (
            0x0000_4000_0000_0000,
            0x0000_0000_0200_0000,
            0x0000_8000_0000_0000,
            0x0000_0000_0100_0000,
        ),
        None => (1, 0, 1, 0),
    };
    let (privacy_product, privacy_data_category) = component
        .map(|c| (c.privacy_product, c.privacy_data_category))
        .unwrap_or((11, 1));
    EventMetadata {
        keyword,
        privacy_tag,
        critical_keyword,
        critical_privacy_tag,
        privacy_product,
        privacy_data_category,
        eligible: routed,
    }
}

/// Cargo directives that set the compile-time environment read by `mod.rs`.
#[allow(dead_code)]
fn metadata_rustc_env(metadata: &EventMetadata) -> Vec<String> {
    [
        ("MXC_BUILD_EVENT_KEYWORD", metadata.keyword.to_string()),
        ("MXC_BUILD_PRIVACY_TAG", metadata.privacy_tag.to_string()),
        (
            "MXC_BUILD_CRITICAL_EVENT_KEYWORD",
            metadata.critical_keyword.to_string(),
        ),
        (
            "MXC_BUILD_CRITICAL_PRIVACY_TAG",
            metadata.critical_privacy_tag.to_string(),
        ),
        (
            "MXC_BUILD_PRIVACY_PRODUCT",
            metadata.privacy_product.to_string(),
        ),
        (
            "MXC_BUILD_PRIVACY_DATA_CATEGORY",
            metadata.privacy_data_category.to_string(),
        ),
        (
            "MXC_BUILD_REQUIRED_COLLECTION_ELIGIBLE",
            u8::from(metadata.eligible).to_string(),
        ),
    ]
    .into_iter()
    .map(|(name, value)| format!("cargo::rustc-env={name}={value}"))
    .collect()
}
