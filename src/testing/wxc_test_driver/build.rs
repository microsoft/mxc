// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#[path = "../../mxc-sdk/build/build_mxc_build_common.rs"]
mod mxc_build_common;

fn main() {
    mxc_build_common::embed_version_info("MXC test configuration driver", "wxc-test-driver.exe");
}
