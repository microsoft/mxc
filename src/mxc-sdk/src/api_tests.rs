// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Public API exclusion checks.
//!
//! The typed creation-change notification API is a deferred proposal.
//!
//! ```compile_fail
//! use mxc_sdk::v1::{DenialCaptureMode, FilesystemAccess, NetworkScope, PolicyChange};
//! ```
//!
//! ```compile_fail
//! fn proposed_changes(process: &mxc_sdk::v1::MxcProcess) {
//!     let _ = process.policy_changes();
//! }
//! ```
//!
//! Published V1 option literals remain valid.
//!
//! ```
//! use mxc_sdk::v1::{RunOptions, SpawnOptions};
//! let _ = RunOptions { telemetry: None };
//! let _ = SpawnOptions { telemetry: None };
//! ```
//!
//! Creation mutation is selected through the revised options, not new V1 methods.
//!
//! ```compile_fail
//! use mxc_sdk::v1::{run_with_policy_mutation, spawn_with_policy_mutation};
//! ```
//!
//! ```compile_fail
//! use mxc_sdk::v1::{
//!     available_tools_policy, temporary_files_policy, user_profile_policy,
//!     FilesystemPolicyResult, ToolsPolicyOptions, ToolsPolicyContainerType,
//! };
//! ```
//!
//! ```compile_fail
//! use mxc_sdk::v1::policy::{
//!     available_tools_policy, temporary_files_policy, user_profile_policy,
//!     FilesystemPolicyResult, ToolsPolicyOptions, ToolsPolicyContainerType,
//! };
//! ```
//!
//! ```compile_fail
//! use mxc_sdk::__ffi::exec_attached;
//! ```
//!
//! ```compile_fail
//! use mxc_sdk::__ffi::exec_attached_json;
//! ```
//!
//! ```compile_fail
//! use mxc_sdk::probe;
//! ```
//!
//! ```compile_fail
//! use mxc_sdk::sandbox;
//! ```
//!
//! ```compile_fail
//! use mxc_sdk::v1::container::exec_in_attached;
//! ```
//!
//! ```compile_fail
//! use mxc_sdk::v1::exec_attached;
//! ```
//!
//! ```compile_fail
//! use mxc_sdk::v1::run_in_container;
//! ```
//!
//! ```compile_fail
//! use mxc_sdk::v1::spawn_in_container;
//! ```
//!
//! ```compile_fail
//! use mxc_sdk::v1::run_json;
//! ```
//!
//! ```compile_fail
//! use mxc_sdk::v1::run_lifecycle_json;
//! ```
//!
//! ```compile_fail
//! use mxc_sdk::v1::execute_lifecycle;
//! ```
//!
//! ```compile_fail
//! use mxc_sdk::v1::execute_lifecycle_json;
//! ```
//!
//! ```compile_fail
//! use mxc_sdk::v1::spawn_container_json;
//! ```
//!
//! ```compile_fail
//! use mxc_sdk::v1::spawn_with_pty_json;
//! ```
//!
//! ```compile_fail
//! use mxc_sdk::v1::spawn_in_container_with_pty_json;
//! ```
