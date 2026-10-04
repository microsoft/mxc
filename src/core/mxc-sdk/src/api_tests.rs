// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Public API exclusion checks.
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
