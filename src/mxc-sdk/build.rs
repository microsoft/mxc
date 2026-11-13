// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#[path = "build/build_isolation_session_bindings.rs"]
mod build_isolation_session_bindings;
#[allow(dead_code)]
#[path = "build/build_mxc_build_common.rs"]
mod build_mxc_build_common;
#[path = "build/build_mxc_common.rs"]
mod build_mxc_common;
#[path = "build/build_mxc_telemetry.rs"]
mod build_mxc_telemetry;
#[cfg(feature = "link-wslcsdk")]
#[path = "build/build_wslc_common.rs"]
mod build_wslc_common;
#[path = "build/verify_nvx_runtime_signatures.rs"]
mod verify_nvx_runtime_signatures;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    build(
        &std::path::PathBuf::from(std::env::var("CARGO_MANIFEST_DIR")?),
        true,
    )
}

pub(crate) fn build(
    source_dir: &std::path::Path,
    build_sidecars: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    println!("cargo:rustc-check-cfg=cfg(mxc_internal)");
    if !build_sidecars {
        println!("cargo:rustc-cfg=mxc_internal");
    }
    println!(
        "cargo:rustc-env=MXC_SDK_SOURCE_DIR={}",
        source_dir.display()
    );
    build_isolation_session_bindings::run(source_dir);
    build_mxc_telemetry::run(source_dir);
    verify_nvx_runtime_signatures::run()?;
    #[cfg(feature = "link-wslcsdk")]
    build_wslc_common::run(source_dir);
    build_mxc_common::run(source_dir)?;
    if !build_sidecars {
        return Ok(());
    }
    build_mxc_build_common::embed_version_info_for_binary(
        "wxc-windows-sandbox-daemon",
        "Windows Sandbox integration daemon",
        "wxc-windows-sandbox-daemon.exe",
    )?;
    build_mxc_build_common::embed_version_info_for_binary(
        "wxc-windows-sandbox-guest",
        "Windows Sandbox guest agent",
        "wxc-windows-sandbox-guest.exe",
    )?;
    build_mxc_build_common::embed_version_info_for_binary(
        "wxc-wslc-daemon",
        "WSL Container integration daemon",
        "wxc-wslc-daemon.exe",
    )?;
    Ok(())
}
