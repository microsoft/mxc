// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Backend-specific request configuration.

pub(crate) mod lxc;
pub(crate) mod process_container;
pub(crate) mod seatbelt;
pub(crate) mod wslc;

#[doc(inline)]
pub use lxc::LxcConfig;
#[doc(inline)]
pub use process_container::{
    CaptureDenials, CaptureDenialsMode, ProcessContainerConfig, ProcessContainerFilesystem,
    ProcessContainerNetwork, ProcessContainerSystemSettings, ProcessContainerUi,
    ProcessContainerUiIsolation,
};
#[doc(inline)]
pub use seatbelt::SeatbeltConfig;
#[doc(inline)]
pub use wslc::WslcConfig;
