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
    /// A Kata provision request.
    Kata(KataProvisionRequest),
    /// A Windows Sandbox provision request.
    WindowsSandbox(WindowsSandboxProvisionRequest),
    /// A MicroVM provision request.
    MicroVm(MicroVmProvisionRequest),
    /// A WSLC provision request.
    Wslc(WslcProvisionRequest),
    /// A development-only W365 Agents provision request.
    W365Agents(W365AgentsProvisionRequest),
}

mod containment;
mod isolation_session;
mod kata;
mod microvm;
mod w365_agents;
mod windows_sandbox;
mod wslc;

pub use containment::{probe_containment, Containment, ContainmentProbeError};
pub use isolation_session::{
    IsolationSessionContainment, IsolationSessionNetwork, IsolationSessionNetworkAllow,
    IsolationSessionNetworkEgress, IsolationSessionNetworkIngress, IsolationSessionProvision,
    IsolationSessionProvisionRequest, StateAwareIsolationSession,
};
pub use kata::{KataContainment, KataProvisionRequest};
pub use microvm::{
    MicroVmContainment, MicroVmProvision, MicroVmProvisionRequest, StateAwareMicroVm,
};
pub use w365_agents::{
    StateAwareW365AgentsProvision, W365AgentsContainment, W365AgentsGuid, W365AgentsProvision,
    W365AgentsProvisionRequest, W365AgentsUserType,
};
pub use windows_sandbox::{WindowsSandboxContainment, WindowsSandboxProvisionRequest};
pub use wslc::{StateAwareWslc, WslcContainment, WslcProvision, WslcProvisionRequest};
