// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Build script for plm — embeds Windows VersionInfo and, on release
//! Windows builds, a `requireAdministrator` application manifest.
//!
//! `plm.exe` starts / stops NT Kernel Logger ETW sessions via wpr.exe,
//! which requires Administrator. Rather than perform a runtime UAC
//! self-relaunch (which was the design of the reverted 666b08d and
//! violated the "wxc-exec never runs elevated" invariant MGudgin
//! called out in PR#584), we make `plm.exe` itself the elevated
//! helper — analog of `wxc-host-prep.exe`, and hence its new location
//! under `src/host/plm/`. The unelevated `wxc-exec --audit` invokes
//! `plm.exe` via `ShellExecuteExW`+`runas`, the OS shows one UAC
//! prompt at plm's launch, and plm's whole lifetime (including the
//! console-control handler that fires on Ctrl+C) runs elevated.
//!
//! The manifest is only embedded in release builds. Embedding it in
//! debug builds would UAC-gate every `cargo test` / `cargo run` and
//! Windows refuses to launch an unelevated `requireAdministrator`
//! binary at all (error 740) — which would break the unit tests. The
//! runtime `IsUserAnAdmin` posture is unchanged: any privileged code
//! path is still gated in code.

fn main() {
    mxc_build_common::embed_version_info("MXC permissive learning mode", "plm.exe");

    #[cfg(target_os = "windows")]
    embed_admin_manifest();
}

#[cfg(target_os = "windows")]
fn embed_admin_manifest() {
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-env-changed=PROFILE");

    let profile = std::env::var("PROFILE").unwrap_or_default();
    if profile != "release" {
        return;
    }

    use embed_manifest::manifest::{ExecutionLevel, SupportedOS};
    use embed_manifest::{embed_manifest, new_manifest};

    let manifest = new_manifest("Microsoft.MxcPlm")
        .requested_execution_level(ExecutionLevel::RequireAdministrator)
        .supported_os(SupportedOS::Windows10..);

    embed_manifest(manifest).expect("failed to embed application manifest");
}
