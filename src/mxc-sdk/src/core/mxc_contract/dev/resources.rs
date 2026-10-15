// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use super::primitives::OptionalField;
use std::num::{NonZeroU32, NonZeroU64};

string_enum! {
    /// Scheduling priority for the workload.
    #[derive(Debug)]
    pub enum ResourcePriority {
        /// The host's normal priority.
        Normal => ["normal"],
        /// Below normal priority.
        Low => ["low"],
        /// The lowest priority the host offers.
        Idle => ["idle"],
    }
}

/// Resource limits for the workload, and a request for its resource usage.
///
/// Supplying this object, even empty, asks the backend to report the
/// workload's resource usage with its result. Every field is optional; an
/// omitted field leaves that resource unlimited.
#[derive(Debug, serde::Deserialize)]
#[cfg_attr(feature = "schema-gen", derive(schemars::JsonSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Resources {
    /// CPU time each process in the workload may use, in milliseconds.
    #[serde(default)]
    pub cpu_time_ms: OptionalField<NonZeroU64>,
    /// Memory each process in the workload may commit, in megabytes.
    #[serde(default)]
    pub memory_mb: OptionalField<NonZeroU64>,
    /// Number of processes the workload may run at the same time.
    #[serde(default)]
    pub max_processes: OptionalField<NonZeroU32>,
    /// Scheduling priority for every process in the workload.
    #[serde(default)]
    pub priority: OptionalField<ResourcePriority>,
}
