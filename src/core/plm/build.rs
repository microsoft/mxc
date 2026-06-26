// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Build script for plm — embeds Windows VersionInfo.
//!
//! The WPR profile is no longer staged here: `profile_gen::EMBEDDED_WPRP`
//! holds the canonical bytes, and `plm` writes them next to its own
//! executable on first use when the file is missing.

fn main() {
    mxc_build_common::embed_version_info("MXC permissive learning mode", "plm.exe");
}
