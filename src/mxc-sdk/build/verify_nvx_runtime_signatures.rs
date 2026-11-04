// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Checks Microsoft signatures on both crate-provided and staged NVX runtime files.
//! Fails Windows x64 MicroVM builds when signature trust cannot be verified.

#[cfg(all(windows, feature = "microvm"))]
#[path = "../src/backends/nvx/signature_verification.rs"]
pub(crate) mod signature_verification;

pub(crate) fn run() -> Result<(), Box<dyn std::error::Error>> {
    println!("cargo:rerun-if-env-changed=DEP_ACI_EDGE_SANDBOXES_AGENT_ARTIFACTS_DIR");
    if std::env::var_os("CARGO_FEATURE_MICROVM").is_none()
        || std::env::var("CARGO_CFG_TARGET_OS").as_deref() != Ok("windows")
        || std::env::var("CARGO_CFG_TARGET_ARCH").as_deref() != Ok("x86_64")
    {
        return Ok(());
    }
    #[cfg(all(windows, feature = "microvm"))]
    {
        let artifacts = std::env::var_os("DEP_ACI_EDGE_SANDBOXES_AGENT_ARTIFACTS_DIR")
            .ok_or("the crate-staged NVX bundle is required for signature verification")?;
        let artifacts = std::path::PathBuf::from(artifacts);
        let out = std::path::PathBuf::from(
            std::env::var_os("OUT_DIR").ok_or("OUT_DIR is required for NVX validation")?,
        );
        let profile = out
            .ancestors()
            .nth(3)
            .ok_or("cannot locate the Cargo profile for NVX validation")?;
        for directory in [artifacts, profile.join("aci-edge-sandboxes")] {
            for name in ["aci_edge_agent.dll", "openvmm.exe", "direct-images.exe"] {
                println!(
                    "cargo:rerun-if-changed={}",
                    directory.join("bin").join(name).display()
                );
            }
            let _verified = signature_verification::verify_bundle(&directory)?;
        }
        Ok(())
    }
    #[cfg(not(all(windows, feature = "microvm")))]
    Err("NVX Windows x64 signature verification requires a Windows build host".into())
}
