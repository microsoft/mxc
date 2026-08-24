// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! `bwrap_common` — shared library for the Bubblewrap sandbox backend.
//!
//! - [`bwrap_command`] builds the `bwrap` CLI argument vector from a
//!   [`ExecutionRequest`](wxc_common::models::ExecutionRequest). It is
//!   platform-agnostic (pure argument generation) so it compiles and is
//!   fully unit-tested on every host.
//! - [`bwrap_version`] probes the host `bwrap` and checks it is new enough to
//!   understand every flag [`bwrap_command`] emits. Shared by the runner's
//!   `validate` and the engine's platform-support probe.
//! - `network_rules` validates rule addresses and builds the egress plan the
//!   sandbox's own network namespace is programmed with. Platform-agnostic for
//!   the same reason as [`bwrap_command`].
//! - [`bwrap_runner`] is gated to `target_os = "linux"` since it actually
//!   spawns the `bwrap` binary.

pub mod bwrap_command;
#[cfg(target_os = "linux")]
pub mod bwrap_runner;
pub mod bwrap_version;
/// Consumed only by the Linux-gated runner and proxy modules.
#[cfg(target_os = "linux")]
pub(crate) mod network_rules;
/// Only [`proxy_network::probe_proxy_enforcement`] is reachable outside the
/// crate; every other item stays `pub(crate)`.
#[cfg(target_os = "linux")]
pub mod proxy_network;
