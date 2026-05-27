// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

fn main() {
    mxc_build_common::embed_version_info(
        "WinHTTP proxy policy shim for sandbox networking",
        "winhttp-proxy-shim.exe",
    );
}
