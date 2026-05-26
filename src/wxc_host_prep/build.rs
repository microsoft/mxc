// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

// Build script for `wxc_host_prep`:
//
// 1. Embed the standard MXC Windows VersionInfo resource (ProductName,
//    FileDescription, ProductVersion + git short hash, ...) via
//    `mxc_build_common::embed_version_info`. No-op on non-Windows.
// 2. Embed a Windows application manifest declaring
//    `requireAdministrator`. Putting elevation in the manifest is the
//    design point that lets us delete the hand-rolled `ShellExecuteExW`
//    self-elevation dance from `system_drive_prep`: the OS loader prompts
//    for UAC at process start, and the binary either runs elevated or
//    fails to start. SYSTEM principals (e.g. a scheduled task running
//    `prepare-null-device` at boot) satisfy the requirement trivially
//    without any UAC interaction.
//
//    The manifest is only embedded in release builds. Embedding it in
//    debug builds would force every `cargo test` / `cargo run` to UAC,
//    and Windows refuses to launch an unelevated `requireAdministrator`
//    binary at all (error 740) — which would make the bin's unit tests
//    unrunnable. In debug the runtime `elevation_check::require_elevated`
//    guard still rejects non-elevated invocations of the privileged
//    subcommands, so the security posture is unchanged for any code path
//    that actually touches the registry / file system.

fn main() {
    mxc_build_common::embed_version_info("MXC host setup helper", "wxc-host-prep.exe");

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

    let manifest = new_manifest("Microsoft.WxcHostPrep")
        .requested_execution_level(ExecutionLevel::RequireAdministrator)
        .supported_os(SupportedOS::Windows10..);

    embed_manifest(manifest).expect("failed to embed application manifest");
}
