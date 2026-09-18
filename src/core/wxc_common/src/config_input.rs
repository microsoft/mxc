// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Internal common input assembled by exact contract adapters and typed SDK builders.

use crate::models::NetworkEnforcementCompatibility;
use crate::wire;
use mxc_config_contract::ContractVersion;

#[derive(Debug, Clone)]
pub(crate) struct ConfigInput {
    pub(crate) schema: Option<String>,
    pub(crate) comment: Option<serde_json::Value>,
    pub(crate) source_contract: ContractVersion,
    pub(crate) network_enforcement_compatibility: NetworkEnforcementCompatibility,
    pub(crate) phase: Option<wire::Phase>,
    pub(crate) sandbox_id: Option<String>,
    pub(crate) container_id: Option<String>,
    pub(crate) containment: Option<wire::Containment>,
    pub(crate) process: Option<wire::Process>,
    pub(crate) lifecycle: Option<wire::Lifecycle>,
    pub(crate) process_container: Option<wire::ProcessContainer>,
    pub(crate) lxc: Option<wire::Lxc>,
    pub(crate) filesystem: Option<wire::Filesystem>,
    pub(crate) fallback: Option<wire::Fallback>,
    pub(crate) network: Option<wire::Network>,
    pub(crate) runtime_config: Option<wire::RuntimeConfig>,
    pub(crate) ui: Option<wire::Ui>,
    pub(crate) seatbelt: Option<wire::Seatbelt>,
    pub(crate) telemetry: Option<wire::Telemetry>,
    pub(crate) experimental: Option<wire::Experimental>,
}
