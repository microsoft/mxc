// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Azure Container Instances (ACI) sandbox backend: runs a create-and-run
//! request in a Linux sandbox VM that ACI hosts, and captures its output.

mod credentials;
mod gateway;
mod policy;
mod proto;
pub mod runner;
mod service;
