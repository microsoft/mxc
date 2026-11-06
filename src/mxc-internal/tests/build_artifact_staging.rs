// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#[allow(
    dead_code,
    reason = "Build helper tests use only the artifact staging subset"
)]
#[path = "../../mxc-sdk/src/backends/nanvix/common/mod.rs"]
mod nanvix_common;

#[allow(
    dead_code,
    reason = "Build helper tests do not invoke the build-script entry points"
)]
#[path = "../../mxc-sdk/build/build_nanvix_build_common.rs"]
mod nanvix_build_common;
