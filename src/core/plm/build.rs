// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Build script for plm — embeds Windows VersionInfo.

fn main() {
    mxc_build_common::embed_version_info("MXC permissive learning mode", "plm.exe");
}
