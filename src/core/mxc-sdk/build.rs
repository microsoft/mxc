// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

fn main() {
    #[cfg(all(windows, feature = "isolation_session"))]
    stage_isolation_session_runtime();
}

#[cfg(all(windows, feature = "isolation_session"))]
fn stage_isolation_session_runtime() {
    let manifest_dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let sdk_dir = manifest_dir
        .join("..")
        .join("..")
        .join("..")
        .join("external")
        .join("windows-sdk")
        .join("isolation-session");
    let _ = mxc_build_common::stage_isolation_session_runtime(&sdk_dir);
}
