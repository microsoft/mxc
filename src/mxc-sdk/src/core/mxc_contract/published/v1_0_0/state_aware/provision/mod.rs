// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

string_marker! {
    /// The `provision` phase of the state-aware configuration contract.
    pub struct ProvisionPhase => "provision";
}

/// A validated provision request selected by its concrete containment backend.
#[derive(Debug)]
pub enum ProvisionRequest {
    /// An IsolationSession provision request.
    IsolationSession(IsolationSessionProvisionRequest),
    /// A WSLC provision request.
    Wslc(WslcProvisionRequest),
}

mod containment;
mod isolation_session;
mod wslc;

pub use containment::{probe_containment, Containment, ContainmentProbeError};
pub use isolation_session::{
    IsolationSessionContainment, IsolationSessionNetwork, IsolationSessionNetworkAllow,
    IsolationSessionNetworkEgress, IsolationSessionNetworkIngress, IsolationSessionProvision,
    IsolationSessionProvisionRequest, StateAwareIsolationSession,
};
pub use wslc::{StateAwareWslc, WslcContainment, WslcProvision, WslcProvisionRequest};
