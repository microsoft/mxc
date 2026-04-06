// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Build script for wslc_common — links against the WSLC SDK.
//!
//! The SDK lib path is resolved from:
//! 1. `WSLC_SDK_PATH` environment variable (if set)
//! 2. `external/wslc-sdk/runtimes/win-{arch}/` relative to the repo root

fn main() {
    let arch = match std::env::var("CARGO_CFG_TARGET_ARCH").as_deref() {
        Ok("x86_64") => "x64",
        Ok("aarch64") => "arm64",
        _ => {
            println!("cargo:warning=WSLC SDK: unsupported target architecture, skipping link");
            return;
        }
    };

    let sdk_path = if let Ok(path) = std::env::var("WSLC_SDK_PATH") {
        std::path::PathBuf::from(path)
    } else {
        let manifest_dir = std::env::var("CARGO_MANIFEST_DIR").unwrap();
        std::path::PathBuf::from(manifest_dir)
            .join("..")
            .join("..")
            .join("external")
            .join("wslc-sdk")
            .join("runtimes")
            .join(format!("win-{}", arch))
    };

    if !sdk_path.join("wslcsdk.lib").exists() {
        println!(
            "cargo:warning=WSLC SDK lib not found at {}. WSLC features will not link.",
            sdk_path.display()
        );
        return;
    }

    println!("cargo:rustc-link-search=native={}", sdk_path.display());
    println!("cargo:rustc-link-lib=dylib=wslcsdk");
    println!("cargo:rerun-if-env-changed=WSLC_SDK_PATH");
}
