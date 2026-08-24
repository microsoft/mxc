// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Backend-specific request configuration.

pub(crate) mod process_container;

#[doc(inline)]
pub use process_container::{
    CaptureDenialsConfig, CaptureDenialsMode, ProcessContainerConfig,
    ProcessContainerNetworkConfig, ProcessContainerUiConfig, ProcessContainerUiIsolation,
};
