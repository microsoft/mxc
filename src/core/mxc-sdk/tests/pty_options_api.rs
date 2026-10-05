// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use mxc_sdk::v1::{
    self, ContainerId, ContainerRequest, ExecutionRequest, MxcPtyProcess, MxcPtySize,
    SpawnInContainerWithPtyOptions, SpawnWithPtyOptions,
};

#[test]
fn pty_entry_points_take_dimensions_from_operation_options() {
    let _: fn(ContainerRequest, SpawnWithPtyOptions) -> Result<MxcPtyProcess, mxc_sdk::v1::Error> =
        v1::spawn_with_pty;
    let _: fn(
        &ContainerId,
        ExecutionRequest,
        SpawnInContainerWithPtyOptions,
    ) -> Result<MxcPtyProcess, mxc_sdk::v1::Error> = v1::container::spawn_in_container_with_pty;

    let default_size = SpawnWithPtyOptions::default().size;
    assert_eq!(default_size, MxcPtySize::default());
    assert_eq!((default_size.rows, default_size.cols), (24, 80));
    assert_eq!(
        SpawnInContainerWithPtyOptions::default().size,
        MxcPtySize::default()
    );

    let options = SpawnWithPtyOptions {
        size: MxcPtySize {
            rows: 40,
            cols: 120,
            pixel_width: 0,
            pixel_height: 0,
        },
        ..Default::default()
    };
    let native_size: wxc_common::sandbox_process::PtySize = options.size.into();
    assert_eq!((native_size.rows, native_size.cols), (40, 120));
}
