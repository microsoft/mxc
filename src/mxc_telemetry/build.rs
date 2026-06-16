// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Build script for `mxc_telemetry`.
//!
//! Generates `provider_def.rs` containing the `define_provider!` invocation.
//! The `MXC_TELEMETRY_PROVIDER_GROUP_GUID` environment variable controls
//! whether a `group_id(...)` option is included — internal Microsoft builds
//! set this to the Microsoft telemetry group GUID so events route through the
//! telemetry pipeline, while public/OSS builds omit it (plain ETW only).
//!
//! The provider GUID itself is **not** specified here. The `tracelogging`
//! crate derives it deterministically from the provider name
//! (`"Microsoft.MXC"`) using the standard ETW name-hash algorithm — the same
//! algorithm used by `<TraceLoggingProvider.h>`, WIL's
//! `IMPLEMENT_TRACELOGGING_CLASS`, and .NET's `EventSource`. For
//! `"Microsoft.MXC"` the derived GUID is
//! `{7f10def4-a258-5fea-510e-2c3bb976687f}`. Keeping the name and GUID in
//! lockstep this way prevents drift and avoids hard-coding a literal.

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

fn main() {
    println!("cargo::rerun-if-env-changed=MXC_TELEMETRY_PROVIDER_GROUP_GUID");

    let out = std::path::PathBuf::from(std::env::var("OUT_DIR").unwrap());

    let provider_def = match std::env::var("MXC_TELEMETRY_PROVIDER_GROUP_GUID") {
        Ok(guid) if !guid.is_empty() => {
            assert!(
                is_valid_guid(&guid),
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
    };

    std::fs::write(out.join("provider_def.rs"), provider_def).unwrap();
}
