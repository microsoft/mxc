// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Common request intermediate representation assembled by exact contract adapters.

use crate::models::{DefaultEnvCompatibility, NetworkEnforcementCompatibility};
use crate::wire;
use mxc_config_contract::ContractVersion;

#[derive(Debug, Clone)]
pub(crate) struct CommonRequestIR {
    pub(crate) schema: Option<String>,
    pub(crate) comment: Option<serde_json::Value>,
    pub(crate) source_contract: ContractVersion,
    pub(crate) network_enforcement_compatibility: NetworkEnforcementCompatibility,
    pub(crate) default_env_compatibility: DefaultEnvCompatibility,
    pub(crate) phase: Option<wire::Phase>,
    pub(crate) sandbox_id: Option<String>,
    pub(crate) container_id: Option<String>,
    pub(crate) containment: Option<wire::Containment>,
    pub(crate) process: Option<wire::Process>,
    pub(crate) lifecycle: Option<wire::Lifecycle>,
    pub(crate) process_container: Option<wire::ProcessContainer>,
    pub(crate) lxc: Option<wire::Lxc>,
    pub(crate) wslc: Option<wire::Wslc>,
    pub(crate) filesystem: Option<wire::Filesystem>,
    pub(crate) fallback: Option<wire::Fallback>,
    pub(crate) network: Option<wire::Network>,
    pub(crate) runtime_config: Option<wire::RuntimeConfig>,
    pub(crate) ui: Option<wire::Ui>,
    pub(crate) seatbelt: Option<wire::Seatbelt>,
    pub(crate) telemetry: Option<wire::Telemetry>,
    pub(crate) test_feature: Option<wire::TestFeature>,
    pub(crate) windows_sandbox: Option<wire::WindowsSandbox>,
    pub(crate) hyperlight: Option<wire::Hyperlight>,
}
