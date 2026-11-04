// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Build script for `mxc_telemetry`.
//!
//! Generates `provider_def.rs` containing the `define_provider!` invocation
//! plus event-metadata constants (`MXC_EVENT_KEYWORD`,
//! `MXC_CRITICAL_EVENT_KEYWORD`, `MXC_PRIVACY_TAG`, `MXC_CRITICAL_PRIVACY_TAG`).
//! All events use one `Microsoft.MXC` registration. The private
//! `MXC_TELEMETRY_PROVIDER_GROUP_GUID` input supplies its WinExt group.
//! Event and request-contract selection controls Measures/Usage versus
//! Critical Data/Performance metadata, not provider routing or consent.
//! Without a group, ordinary local builds use keyword 1 and privacy tag 0.
//!
//! `MXC_TELEMETRY_TEST_KEYWORDS=1` enables category-mask and privacy-tag validation
//! only in local-only Windows debug test-support builds. It never enables routing.
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

include!("../src/core/mxc_telemetry/provider_codegen.rs");
include!("build_mxc_telemetry_component.rs");

// Picks the telemetry component. `MXC_TELEMETRY_COMPONENT_PATH` names a DLL;
// set it empty to force an unrouted build. When it is unset, release builds on
// Windows use the signed DLL bundled in `resources/telemetry-component/` for
// the build host's architecture. Debug builds stay unrouted so tests and local
// development never emit under the routing group.
fn component_path(telemetry_target: bool) -> Option<std::path::PathBuf> {
    if !telemetry_target {
        return None;
    }
    if let Some(path) = std::env::var_os("MXC_TELEMETRY_COMPONENT_PATH") {
        return (!path.is_empty()).then(|| std::path::PathBuf::from(path));
    }
    if std::env::var("PROFILE").as_deref() != Ok("release") {
        return None;
    }
    let host = std::env::var("HOST").unwrap_or_default();
    let arch = if host.starts_with("x86_64") {
        "x64"
    } else if host.starts_with("aarch64") {
        "arm64"
    } else {
        return None;
    };
    let manifest = std::env::var_os("CARGO_MANIFEST_DIR")?;
    let bundled = std::path::Path::new(&manifest)
        .join("resources")
        .join("telemetry-component")
        .join(arch)
        .join("mxc_telemetry.dll");
    bundled.is_file().then_some(bundled)
}

pub(crate) fn run() {
    println!("cargo::rerun-if-env-changed=MXC_TELEMETRY_PROVIDER_GROUP_GUID");
    println!("cargo::rerun-if-env-changed=MXC_TELEMETRY_CORE_PROVIDER_GROUP_GUID");
    println!("cargo::rerun-if-env-changed=MXC_TELEMETRY_TEST_KEYWORDS");
    println!("cargo::rerun-if-env-changed=MXC_TELEMETRY_COMPONENT_PATH");

    let out = std::path::PathBuf::from(std::env::var("OUT_DIR").unwrap());

    // The `tracelogging` provider only emits on Windows; on every other target
    // the crate compiles to no-ops. Honor (and validate) the group GUID only
    // for Windows builds so a stray or malformed environment value cannot break
    // cross-platform builds — e.g. a CI host that exports the variable globally
    // while cross-compiling the Linux/macOS binaries.
    // Single place to extend when another target gains a telemetry provider.
    let telemetry_target = std::env::var("CARGO_CFG_TARGET_OS").unwrap_or_default() == "windows";
    let component_path = component_path(telemetry_target);
    let component = match component_path {
        Some(path) => {
            println!("cargo::rerun-if-changed={}", path.to_string_lossy());
            Some(read_component_metadata(&path))
        }
        None => None,
    };
    let group_guid = if telemetry_target {
        std::env::var("MXC_TELEMETRY_PROVIDER_GROUP_GUID").ok()
    } else {
        None
    };
    assert!(
        component.is_none() || group_guid.as_deref().is_none_or(str::is_empty),
        "set either MXC_TELEMETRY_COMPONENT_PATH or MXC_TELEMETRY_PROVIDER_GROUP_GUID, not both"
    );
    let group_guid = component.as_ref().map(|c| c.group.clone()).or(group_guid);
    if telemetry_target {
        assert!(
            std::env::var_os("MXC_TELEMETRY_CORE_PROVIDER_GROUP_GUID")
                .is_none_or(|value| value.is_empty()),
            "MXC_TELEMETRY_CORE_PROVIDER_GROUP_GUID is no longer supported; \
             configure the WinExt group through MXC_TELEMETRY_PROVIDER_GROUP_GUID"
        );
    }

    let test_keywords = local_keyword_test_enabled(
        std::env::var("MXC_TELEMETRY_TEST_KEYWORDS").ok().as_deref(),
        telemetry_target
            && std::env::var_os("CARGO_CFG_DEBUG_ASSERTIONS").is_some()
            && std::env::var_os("CARGO_FEATURE_TEST_SUPPORT").is_some()
            && component.is_none(),
        group_guid.as_deref(),
    );
    let provider_def = generate_provider_def(group_guid.as_deref());
    let metadata = event_metadata(group_guid.as_deref(), test_keywords, component.as_ref());
    for directive in metadata_rustc_env(&metadata) {
        println!("{directive}");
    }

    std::fs::write(out.join("provider_def.rs"), provider_def).unwrap();
}
