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
