// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Build script for the public, `asInvoker` PLM binary.
//!
//! PLM elevates only its hidden fixed-operation WPR child at runtime. Do not
//! add a `requireAdministrator` manifest here: parsing ETLs and touching
//! caller-selected output/configuration paths must stay under the caller token.

fn main() {
    mxc_build_common::embed_version_info("MXC permissive learning mode", "plm.exe");
}
