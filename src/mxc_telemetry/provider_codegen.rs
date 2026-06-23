// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

// Pure provider-definition code generation shared between `build.rs` and the
// crate's unit tests.
//
// Cargo never runs `#[cfg(test)]` modules inside a build script, so the logic
// lives here and is pulled into both `build.rs` and a `#[cfg(test)]` module in
// `lib.rs` via `include!`. That keeps the GUID validation and code-generation
// behaviour unit-testable with `cargo test`.

/// Validates that `s` is a well-formed GUID (xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx).
/// Prevents code injection via the environment variable since the value is
/// interpolated into generated Rust source that is `include!()`'d.
fn is_valid_guid(s: &str) -> bool {
    let parts: Vec<&str> = s.split('-').collect();
    parts.len() == 5
        && parts[0].len() == 8
        && parts[1].len() == 4
        && parts[2].len() == 4
        && parts[3].len() == 4
        && parts[4].len() == 12
        && s.chars().all(|c| c.is_ascii_hexdigit() || c == '-')
}

/// Generate the `tracelogging::define_provider!` invocation that is written to
/// `provider_def.rs`.
///
/// When `group_guid` is a non-empty, well-formed GUID the provider joins that
/// ETW provider group (internal Microsoft builds route through the telemetry
/// pipeline); otherwise a plain provider definition is produced (public/OSS
/// builds — local ETW only).
///
/// # Panics
///
/// Panics if `group_guid` is `Some(non-empty)` but not a valid GUID, so a
/// malformed value fails the build rather than emitting invalid generated
/// source.
fn generate_provider_def(group_guid: Option<&str>) -> String {
    match group_guid {
        Some(guid) if !guid.is_empty() => {
            assert!(
                is_valid_guid(guid),
                "MXC_TELEMETRY_PROVIDER_GROUP_GUID is not a valid GUID"
            );
            format!(
                "tracelogging::define_provider!(\
                 MXC_PROVIDER, \"Microsoft.MXC\", \
                 group_id(\"{guid}\"));\n"
            )
        }
        _ => "tracelogging::define_provider!(\
              MXC_PROVIDER, \"Microsoft.MXC\");\n"
            .to_string(),
    }
}
