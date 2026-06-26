// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Windows Sandbox VM lifecycle primitives.
//!
//! Reusable, host-side building blocks for driving a Windows Sandbox VM
//! through its lifecycle, independent of any particular consumer (the warm
//! `wxc-windows-sandbox-daemon`, a transient one-shot runner, or a
//! state-aware backend). The crate is split into three responsibilities:
//!
//! - [`vm`] — generate the `.wsb` configuration, launch/teardown
//!   `WindowsSandbox.exe`, and probe whether a VM is running.
//! - [`rendezvous`] — wait for the guest agent to publish its address via a
//!   file in a mapped folder.
//! - [`bridge`] — establish the TCP channels to the guest agent and relay an
//!   execution over them.
//!
//! Orchestration policy (retries, warm-connection reuse, idle teardown) is
//! intentionally *not* part of this crate: it belongs to the individual
//! consumers that compose these primitives.
//!
//! This crate depends on [`windows_sandbox_common`] only for the wire
//! protocol (`sandbox_protocol`); it never depends on a consumer crate, so
//! backend integrations (`ScriptRunner` / `StatefulSandboxBackend`) can be
//! built on top of it without introducing a dependency cycle.
//!
//! The transient one-shot `ScriptRunner` ([`WindowsSandboxRunner`]) lives in
//! this crate (Windows-only) for exactly that reason: it composes the
//! lifecycle primitives and depends on `wxc_common`, which `windows_sandbox_common`
//! must not.

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
mod teardown;

#[cfg(windows)]
pub use one_shot::WindowsSandboxRunner;
