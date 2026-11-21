// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Data describing configured restrictions, without inspecting or changing the host.

use serde::{Deserialize, Serialize};

/// Advisory context for processes launched with the described MXC request.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[non_exhaustive]
pub struct ExecutionContext {
    pub backend: String,
    pub filesystem: FilesystemContext,
    pub network: NetworkContext,
    pub process: ProcessContext,
    pub limitations: Vec<String>,
}

/// Explicit filesystem rules. Entries retain their original spelling and order.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[non_exhaustive]
pub struct FilesystemContext {
    pub readwrite_paths: Vec<String>,
    pub readonly_paths: Vec<String>,
    pub denied_paths: Vec<String>,
    pub enumerate_paths: Vec<String>,
    pub notes: Vec<String>,
}

/// Configured network posture, not a connectivity or host-capability test.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[non_exhaustive]
pub struct NetworkContext {
    pub egress_default: Option<String>,
    pub ingress_default: Option<String>,
    pub host_loopback: Option<String>,
    pub egress_allow: Option<Vec<NetworkRuleContext>>,
    pub egress_deny: Option<Vec<NetworkRuleContext>>,
    pub proxy_configured: Option<bool>,
    pub notes: Vec<String>,
}

/// One configured CIDR and protocol/port rule.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[non_exhaustive]
pub struct NetworkRuleContext {
    pub to: Option<Vec<NetworkPeerContext>>,
    pub ports: Option<Vec<NetworkPortContext>>,
}

/// A CIDR selector and its exclusions.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[non_exhaustive]
pub struct NetworkPeerContext {
    pub cidr: String,
    pub except: Option<Vec<String>>,
}

/// A protocol and optional inclusive port range.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[non_exhaustive]
pub struct NetworkPortContext {
    pub protocol: Option<String>,
    pub port: Option<u16>,
    pub end_port: Option<u16>,
}

/// Process settings without command text or environment variable values.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[non_exhaustive]
pub struct ProcessContext {
    pub working_directory: Option<String>,
    pub environment_mode: String,
    pub timeout_ms: Option<u32>,
    pub notes: Vec<String>,
}

pub(crate) struct ContextInput {
    pub backend: super::models::ContainmentBackend,
    pub filesystem: FilesystemContext,
    pub network: NetworkContext,
    pub process: ProcessContext,
    pub capture_allows_access: bool,
}
