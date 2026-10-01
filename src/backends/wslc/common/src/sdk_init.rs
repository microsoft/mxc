// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! COM and WSLc SDK bring-up, below the runner and the image handling that both need it.

use std::fmt::Write;

use wxc_common::logger::Logger;
use wxc_common::models::ScriptResponse;

use crate::container_steps::sdk_error;
use crate::error::WslcError;
use crate::wslc_bindings::*;

/// Initialize COM and load the WSLC SDK at runtime.
///
/// # Safety
/// Must be called once per process before any other WSLC SDK functions.
/// The returned `WslcSdk` holds raw function pointers loaded from `wslcsdk.dll`;
/// callers must keep it alive for the duration of all SDK use.
pub unsafe fn init_and_load_sdk(logger: &mut Logger) -> Result<&'static WslcSdk, ScriptResponse> {
    // Accept exactly what `ComApartment` accepts, so a probe and a spawn on
    // the same thread can never disagree: an STA caller
    // (`RPC_E_CHANGED_MODE`) reuses its existing apartment rather than
    // being refused here after `platform_support()` advertised WSLC.
    //
    // The initialization is deliberately *not* balanced. The SDK, its
    // objects, and its callback threads stay live for as long as the
    // returned handle, so releasing the apartment when this function
    // returns could tear the MTA down under a running container. Balancing
    // it means tying the apartment to `StartedContainer`'s lifetime, which
    // is cross-thread — see the ownership follow-up noted on the PR.
    match ComApartment::enter() {
        Ok(com) => std::mem::forget(com),
        Err(e) => {
            return Err(WslcError::Host(format!("COM initialization failed: {e}")).into_response())
        }
    }
    let _ = writeln!(logger, "[WSLC] COM initialized");

    let sdk = match WslcSdk::shared() {
        Ok(s) => s,
        Err(e) => return Err(WslcError::Unavailable(e).into_response()),
    };

    // Prerequisites check
    let mut missing = WslcComponentFlags::WSLC_COMPONENT_FLAG_NONE;
    let hr = sdk.WslcGetMissingComponents(&mut missing);
    if hr != S_OK {
        return Err(sdk_error("WslcGetMissingComponents failed", hr, ""));
    }
    if missing.any_missing() {
        return Err(WslcError::Unavailable(prerequisite_error(missing)).into_response());
    }
    let _ = writeln!(logger, "[WSLC] Runtime check passed");

    Ok(sdk)
}

/// Builds a user-facing prerequisite error for the components `WslcGetMissingComponents`
/// reports as missing. `missing` may combine multiple bits, and the guidance is branched
/// per-component so a user missing only `VirtualMachinePlatform` isn't told to update WSL
/// (which doesn't enable that Windows optional feature), and vice versa. `SdkNeedsUpdate`
/// points at MXC rather than WSL, since it means MXC's SDK is the stale side.
pub(crate) fn prerequisite_error(missing: WslcComponentFlags) -> String {
    let needs_vmp =
        missing.0 & WslcComponentFlags::WSLC_COMPONENT_FLAG_VIRTUAL_MACHINE_PLATFORM.0 != 0;
    let needs_wsl_package = missing.0 & WslcComponentFlags::WSLC_COMPONENT_FLAG_WSL_PACKAGE.0 != 0;
    let needs_sdk_update =
        missing.0 & WslcComponentFlags::WSLC_COMPONENT_FLAG_SDK_NEEDS_UPDATE.0 != 0;

    let mut guidance = Vec::new();
    if needs_vmp {
        guidance.push(
            "enable the \"Virtual Machine Platform\" Windows optional feature (Settings > \
             Apps > Optional features > More Windows features, or run `dism.exe /online \
             /enable-feature /featurename:VirtualMachinePlatform /all`) and restart"
                .to_string(),
        );
    }
    if needs_wsl_package {
        guidance
            .push("install WSL 2.9.9 or newer and run `wsl --update --pre-release`".to_string());
    }
    if needs_sdk_update {
        // MXC's vendored SDK is behind the installed WSL, so the fix is on MXC's
        // side — telling the user to install WSL would send them the wrong way.
        guidance.push(
            "update MXC — the WSLc SDK it ships is too old for your installed version of WSL"
                .to_string(),
        );
    }
    if guidance.is_empty() {
        guidance.push("ensure WSL2 and the WSLC SDK are installed".to_string());
    }

    format!(
        "WSLC runtime unavailable. Missing components: {}. Please {}.",
        missing,
        guidance.join("; "),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prerequisite_error_for_wsl_package_missing() {
        let msg = prerequisite_error(WslcComponentFlags::WSLC_COMPONENT_FLAG_WSL_PACKAGE);
        assert!(msg.contains("WslPackage"));
        assert!(msg.contains("wsl --update"));
        assert!(!msg.contains("Virtual Machine Platform"));
    }

    #[test]
    fn prerequisite_error_for_virtual_machine_platform_missing() {
        let msg =
            prerequisite_error(WslcComponentFlags::WSLC_COMPONENT_FLAG_VIRTUAL_MACHINE_PLATFORM);
        assert!(msg.contains("VirtualMachinePlatform"));
        assert!(msg.contains("Virtual Machine Platform"));
        assert!(!msg.contains("wsl --update"));
    }

    #[test]
    fn prerequisite_error_for_combined_missing_components() {
        let combined = WslcComponentFlags(
            WslcComponentFlags::WSLC_COMPONENT_FLAG_VIRTUAL_MACHINE_PLATFORM.0
                | WslcComponentFlags::WSLC_COMPONENT_FLAG_WSL_PACKAGE.0,
        );
        let msg = prerequisite_error(combined);
        assert!(msg.contains("Virtual Machine Platform"));
        assert!(msg.contains("wsl --update"));
    }

    #[test]
    fn prerequisite_error_for_sdk_needs_update() {
        let msg = prerequisite_error(WslcComponentFlags::WSLC_COMPONENT_FLAG_SDK_NEEDS_UPDATE);
        assert!(msg.contains("update MXC"));
        assert!(!msg.contains("wsl --update"));
    }

    #[test]
    fn prerequisite_error_for_sdk_update_combined_with_another_component() {
        let combined = WslcComponentFlags(
            WslcComponentFlags::WSLC_COMPONENT_FLAG_SDK_NEEDS_UPDATE.0
                | WslcComponentFlags::WSLC_COMPONENT_FLAG_WSL_PACKAGE.0,
        );
        let msg = prerequisite_error(combined);
        assert!(msg.contains("update MXC"));
        assert!(msg.contains("wsl --update"));
    }

    #[test]
    fn prerequisite_error_falls_back_for_unrecognized_components() {
        let msg = prerequisite_error(WslcComponentFlags(0x8000));
        assert!(msg.contains("ensure WSL2 and the WSLC SDK are installed"));
    }
}
