// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Checks approved file hashes and Microsoft signatures on the crate-provided and staged runtime.
//! Embeds raw samples of the verified files for lightweight runtime checks.

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
        use std::fmt::Write;

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
        let sample_directory = out.join("nvx-fingerprints");
        std::fs::create_dir_all(&sample_directory)?;
        let mut fingerprints = String::from("&[\n");
        for (index, directory) in [artifacts, profile.join("aci-edge-sandboxes")]
            .into_iter()
            .enumerate()
        {
            println!("cargo:rerun-if-changed={}", directory.display());
            let mut verified = signature_verification::verify_bundle(&directory, None)?;
            if index == 0 {
                for (file_index, fingerprint) in verified.fingerprints()?.into_iter().enumerate() {
                    let samples = sample_directory.join(format!("{file_index:03}.bin"));
                    std::fs::write(&samples, fingerprint.samples.as_ref())?;
                    writeln!(
                        fingerprints,
                        "    BundleFingerprint {{ path: {:?}, length: {}, samples: std::borrow::Cow::Borrowed(include_bytes!({:?})) }},",
                        fingerprint.path, fingerprint.length, samples
                    )?;
                }
            }
        }
        fingerprints.push_str("]\n");
        std::fs::write(out.join("nvx_bundle_fingerprints.rs"), fingerprints)?;
        Ok(())
    }
    #[cfg(not(all(windows, feature = "microvm")))]
    Err("NVX Windows x64 signature verification requires a Windows build host".into())
}
