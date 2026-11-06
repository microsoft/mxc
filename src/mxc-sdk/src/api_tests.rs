// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Public API exclusion checks.
//!
//! ```compile_fail,E0603
//! use mxc_sdk::implementation;
//! ```
//!
//! ```compile_fail,E0603
//! use mxc_sdk::mxc_common;
//! ```
//!
//! ```compile_fail,E0603
//! use mxc_sdk::mxc_contract;
//! ```
//!
//! ```compile_fail,E0603
//! use mxc_sdk::mxc_engine;
//! ```
//!
//! ```compile_fail,E0603
//! use mxc_sdk::mxc_pty;
//! ```
//!
//! ```compile_fail,E0603
//! use mxc_sdk::mxc_schema_support;
//! ```
//!
//! ```compile_fail,E0603
//! use mxc_sdk::mxc_telemetry;
//! ```
//!
//! ```compile_fail,E0603
//! use mxc_sdk::learning_mode_core;
//! ```
//!
//! ```compile_fail,E0603
//! use mxc_sdk::learning_mode_windows;
//! ```
//!
//! ```compile_fail,E0603
//! use mxc_sdk::plm;
//! ```
//!
//! ```compile_fail,E0603
//! use mxc_sdk::process_security_environment_spec;
//! ```
//!
//! ```compile_fail,E0603
//! use mxc_sdk::bwrap_common;
//! ```
//!
//! ```compile_fail,E0603
//! use mxc_sdk::lxc_common;
//! ```
//!
//! ```compile_fail,E0603
//! use mxc_sdk::seatbelt_common;
//! ```
//!
//! ```compile_fail,E0603
//! use mxc_sdk::__ffi;
//! ```
//!
//! ```compile_fail,E0603
//! use mxc_sdk::core_modules;
//! ```
//!
//! ```compile_fail,E0603
//! use mxc_sdk::backend_modules;
//! ```
//!
//! ```compile_fail,E0603
//! use mxc_sdk::process_container_common;
//! ```
//!
//! ```compile_fail,E0603
//! use mxc_sdk::windows_sandbox_common;
//! ```
//!
//! ```compile_fail,E0603
//! use mxc_sdk::windows_sandbox_lifecycle;
//! ```
//!
//! ```compile_fail,E0603
//! use mxc_sdk::wslc_common;
//! ```
//!
//! ```compile_fail,E0603
//! use mxc_sdk::isolation_session_common;
//! ```
//!
//! ```compile_fail,E0603
//! use mxc_sdk::isolation_session_bindings;
//! ```
//!
//! ```compile_fail,E0603
//! use mxc_sdk::hyperlight_common;
//! ```
//!
//! ```compile_fail,E0603
//! use mxc_sdk::nanvix_common;
//! ```
//!
//! ```compile_fail,E0603
//! use mxc_sdk::nanvix_runner;
//! ```
//!
//! ```compile_fail,E0603
//! use mxc_sdk::nanvix_binaries;
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
