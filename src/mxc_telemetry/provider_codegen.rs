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

/// Generate the `tracelogging::define_provider!` invocation that is written to
/// `provider_def.rs`.
///
/// When `group_guid` is a non-empty, well-formed GUID the provider joins that
/// ETW provider group (internal Microsoft builds route through the telemetry
/// pipeline); otherwise a plain provider definition is produced (public/OSS
/// builds — local ETW only). The GUID is emitted in its canonical lowercase
/// hyphenated form.
///
/// # Panics
///
/// Panics if `group_guid` is `Some(non-empty)` but not a valid GUID, so a
/// malformed value fails the build rather than emitting invalid generated
/// source.
fn generate_provider_def(group_guid: Option<&str>) -> String {
    match group_guid {
        Some(guid) if !guid.is_empty() => {
            let canonical = canonicalize_guid(guid)
                .expect("MXC_TELEMETRY_PROVIDER_GROUP_GUID is not a valid GUID");
            format!(
                "tracelogging::define_provider!(\
                 MXC_PROVIDER, \"Microsoft.MXC\", \
                 group_id(\"{canonical}\"));\n"
            )
        }
        _ => "tracelogging::define_provider!(\
              MXC_PROVIDER, \"Microsoft.MXC\");\n"
            .to_string(),
    }
}

/// Generate the per-event metadata constants (`MXC_EVENT_KEYWORD` and
/// `MXC_PRIVACY_TAG`) written alongside the provider definition.
///
/// These constants are derived from the **same** `group_guid` signal as
/// [`generate_provider_def`] so a build can never end up telemetry-routed
/// (joined to the group) but untagged, or tagged but not routed:
///
/// - No group GUID (default: public/OSS/local dev builds) → the provider is
///   local ETW only. `MXC_EVENT_KEYWORD` is a provider-local bit with no UTC
///   meaning, and `MXC_PRIVACY_TAG` is `0` — Microsoft's own WSL OSS
///   TraceLogging configuration follows the same pattern, defining these
///   telemetry constants as zero for non-official builds.
/// - A valid group GUID (a deliberate, internal-only opt-in) → the provider
///   joins the Microsoft telemetry pipeline via UTC, so the events are
///   correctly tagged for it: `MXC_EVENT_KEYWORD` is
///   `MICROSOFT_KEYWORD_MEASURES` and `MXC_PRIVACY_TAG` is
///   `PDT_PRODUCT_AND_SERVICE_USAGE`, matching WIL's
///   `traceloggingconfig.h`/`MicrosoftTelemetry.h` conventions.
///
/// The event field list (`PartA_PrivTags`) stays present in both modes so the
/// wire schema is identical regardless of build — only the constant values
/// differ.
fn generate_event_metadata_consts(group_guid: Option<&str>) -> String {
    let telemetry_enabled = matches!(group_guid, Some(guid) if !guid.is_empty());
    if telemetry_enabled {
        "pub(crate) const MXC_EVENT_KEYWORD: u64 = 0x0000_4000_0000_0000; // MICROSOFT_KEYWORD_MEASURES\n\
         pub(crate) const MXC_PRIVACY_TAG: u64 = 0x0000_0000_0200_0000; // PDT_PRODUCT_AND_SERVICE_USAGE\n"
            .to_string()
    } else {
        "pub(crate) const MXC_EVENT_KEYWORD: u64 = 0x1; // provider-local, no UTC meaning\n\
         pub(crate) const MXC_PRIVACY_TAG: u64 = 0x0; // not telemetry-classified (local ETW only)\n"
            .to_string()
    }
}
