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
//!
//! The pure code-generation logic lives in `provider_codegen.rs` so it can be
//! unit-tested from `lib.rs` (Cargo never runs build-script test modules).

include!("provider_codegen.rs");

fn main() {
    println!("cargo::rerun-if-env-changed=MXC_TELEMETRY_PROVIDER_GROUP_GUID");

    let out = std::path::PathBuf::from(std::env::var("OUT_DIR").unwrap());

    // The `tracelogging` provider only emits on Windows; on every other target
    // the crate compiles to no-ops. Honor (and validate) the group GUID only
    // for Windows builds so a stray or malformed environment value cannot break
    // cross-platform builds — e.g. a CI host that exports the variable globally
    // while cross-compiling the Linux/macOS binaries.
    let target_os = std::env::var("CARGO_CFG_TARGET_OS").unwrap_or_default();
    let group_guid = if target_os == "windows" {
        std::env::var("MXC_TELEMETRY_PROVIDER_GROUP_GUID").ok()
    } else {
        None
    };

    let provider_def = generate_provider_def(group_guid.as_deref());

    std::fs::write(out.join("provider_def.rs"), provider_def).unwrap();
}
