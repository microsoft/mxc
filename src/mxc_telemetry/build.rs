// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Build script for `mxc_telemetry`.
//!
//! Generates `provider_def.rs` containing the `define_provider!` invocation
//! plus the paired event-metadata constants (`MXC_EVENT_KEYWORD`,
//! `MXC_PRIVACY_TAG`). The `MXC_TELEMETRY_PROVIDER_GROUP_GUID` environment
//! variable is the single switch that drives all three together:
//!
//! - **Unset** (default: public/OSS/local dev builds) — no `group_id(...)`,
//!   plain local ETW only; `MXC_EVENT_KEYWORD` is a provider-local bit and
//!   `MXC_PRIVACY_TAG` is `0` (not telemetry-classified).
//! - **Set** to the real Microsoft telemetry group GUID (internal builds
//!   that deliberately opt into routing these events through UTC) —
//!   `group_id(...)` is present and `MXC_EVENT_KEYWORD`/`MXC_PRIVACY_TAG`
//!   become the Measures keyword and the Product-and-Service-Usage privacy
//!   tag, matching WIL's conventions.
//!
//! Tying all three to one signal means a build can never end up
//! telemetry-routed-but-untagged or tagged-but-not-routed.
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

    let mut provider_def = generate_provider_def(group_guid.as_deref());
    provider_def.push_str(&generate_event_metadata_consts(group_guid.as_deref()));

    std::fs::write(out.join("provider_def.rs"), provider_def).unwrap();
}
