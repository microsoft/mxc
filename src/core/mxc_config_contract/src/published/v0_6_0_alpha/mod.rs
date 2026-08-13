// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Immutable wire types for the published `0.6.0-alpha` configuration contract.
//!
//! These types validate the JSON structure and value constraints of the
//! published contract. They preserve omitted optional fields for a later
//! adapter to default and normalize.

mod network;
mod primitives;
mod request;

pub use network::{DefaultNetworkPolicy, Network, NetworkEnforcementMode, NetworkProxy};
pub use primitives::{NonEmptyString, OptionalField, True};
pub use request::{
    Containment, Fallback, Filesystem, Lifecycle, Lxc, Process, ProcessContainer,
    ProcessContainerUi, ProcessContainerUiIsolation, Request, Ui, UiClipboard, Version,
};
