// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Windows Sandbox VM lifecycle primitives.
//!
//! [`vm`] launches and probes the VM, [`rendezvous`] discovers the guest, and
//! [`bridge`] relays executions. Consumers own retry, reuse, and idle-teardown
//! policy. The transient [`WindowsSandboxRunner`] composes these primitives for
//! one-shot execution.

pub mod bridge;
pub mod constants;
pub mod control_plane;
pub mod ipc_exec;
pub mod rendezvous;
pub mod vm;

#[cfg(windows)]
mod error;
#[cfg(windows)]
mod one_shot;
#[cfg(windows)]
mod policy;
#[cfg(windows)]
mod state_aware;
#[cfg(windows)]
mod teardown;

#[cfg(windows)]
pub use one_shot::WindowsSandboxRunner;
