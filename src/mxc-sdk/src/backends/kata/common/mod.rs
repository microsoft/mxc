// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! `kata_common` - the Kata Containers backend.
//!
//! The backend drives `containerd-shim-kata-v2` directly, with no containerd
//! daemon and no Kubernetes. [`protobuf`], [`ttrpc`], and [`task_api`] are the
//! client for the shim's `containerd.task.v2.Task` service. [`sandbox`] owns a
//! VM and its host resources, [`execution`] runs a process in it,
//! [`kata_runner`] exposes both as a create-and-run backend, and
//! [`state_aware`] exposes them as container lifecycle operations.

pub(crate) mod error;
pub(crate) mod execution;
pub(crate) mod host;
pub(crate) mod kata_runner;
pub(crate) mod loopdev;
pub(crate) mod mounts;
pub(crate) mod netns;
pub(crate) mod oci;
pub(crate) mod policy;
pub(crate) mod protobuf;
pub(crate) mod rootfs;
pub(crate) mod sandbox;
pub(crate) mod shim;
pub(crate) mod state_aware;
pub(crate) mod task_api;
pub(crate) mod ttrpc;

pub use kata_runner::KataBackend;
pub use state_aware::KataStateAwareRunner;
