// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#[path = "../mxc-sdk/build.rs"]
#[allow(dead_code)]
mod sdk_build;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let source_dir = std::path::PathBuf::from(std::env::var("CARGO_MANIFEST_DIR")?)
        .join("../mxc-sdk")
        .canonicalize()?;
    sdk_build::build(&source_dir, false)
}
