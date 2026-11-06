// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#[path = "../mxc-sdk/build.rs"]
#[allow(dead_code)]
mod sdk_build;

pub(crate) use sdk_build::{nanvix_build_common, nanvix_common};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let source_dir =
        std::path::PathBuf::from(std::env::var("CARGO_MANIFEST_DIR")?).join("../mxc-sdk");
    sdk_build::build(&source_dir, true)
}
