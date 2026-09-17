// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Backend-specific request configuration.

pub(crate) mod lxc;
pub(crate) mod process_container;
pub(crate) mod seatbelt;

#[doc(inline)]
pub use lxc::Lxc;
#[doc(inline)]
pub use process_container::{
    CaptureDenials, CaptureDenialsMode, ProcessContainer, ProcessContainerFilesystem,
    ProcessContainerNetwork, ProcessContainerSystemSettings, ProcessContainerUi,
    ProcessContainerUiIsolation,
};
#[doc(inline)]
pub use seatbelt::Seatbelt;
