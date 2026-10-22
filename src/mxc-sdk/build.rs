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
#[path = "build/build_nvx_bundled.rs"]
mod build_nvx_bundled;
#[cfg(feature = "link-wslcsdk")]
#[path = "build/build_wslc_common.rs"]
mod build_wslc_common;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    build_isolation_session_bindings::run();
    build_mxc_telemetry::run();
    build_nvx_bundled::run();
    #[cfg(feature = "link-wslcsdk")]
    build_wslc_common::run();
    build_mxc_common::run()?;
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
