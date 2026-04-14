// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! `AgentSessionRunner` — executes scripts in an IsoEnvBroker Agent Session.
//!
//! Uses the `Windows.AI.IsolationEnvironment.Session` WinRT API to create an
//! isolated Windows session with a dedicated agent user account and run
//! processes within it.
//!
//! This module has two layers:
//! - `AgentSessionManager`: reusable core, methods map 1:1 to the Session API lifecycle.
//! - `AgentSessionRunner`: thin `ScriptRunner` impl for v0.1 that calls all lifecycle
//!   steps per invocation.

// TODO: remove once AgentSessionRunner::run() is implemented (CP6).
#![allow(dead_code)]

use crate::models::{CodexRequest, NetworkPolicy};

// -- Error messages for unsupported policy fields ----------------------------

pub(crate) const ERR_FILESYSTEM_POLICY: &str =
    "filesystem policy is not supported by the agent session backend";
pub(crate) const ERR_NETWORK_POLICY: &str =
    "network policy is not supported by the agent session backend";
pub(crate) const ERR_PROXY_POLICY: &str =
    "network proxy is not supported by the agent session backend";

/// Validates that the request does not contain policy fields unsupported by
/// the agent session backend. Returns `Ok(())` if valid, or `Err(message)`.
pub(crate) fn validate_policy(request: &CodexRequest) -> Result<(), String> {
    if !request.policy.readwrite_paths.is_empty()
        || !request.policy.readonly_paths.is_empty()
        || !request.policy.denied_paths.is_empty()
    {
        return Err(ERR_FILESYSTEM_POLICY.to_string());
    }
    if !request.policy.allowed_hosts.is_empty()
        || !request.policy.blocked_hosts.is_empty()
        || request.policy.default_network_policy != NetworkPolicy::Allow
    {
        return Err(ERR_NETWORK_POLICY.to_string());
    }
    if request.policy.network_proxy.is_enabled() {
        return Err(ERR_PROXY_POLICY.to_string());
    }
    Ok(())
}

// -- Process options (intermediate struct for testability) --------------------

/// Redirect flags for worker process I/O.
pub(crate) const REDIRECT_STDOUT: u32 = 0x2;
pub(crate) const REDIRECT_STDERR: u32 = 0x4;

/// Intermediate representation of process creation options, decoupled from
/// both `CodexRequest` (MXC-specific) and WinRT types (OS-specific).
/// Built from `CodexRequest`, later converted to WinRT options.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ProcessOptions {
    /// Full path to the executable (e.g., `C:\Windows\System32\cmd.exe`).
    pub process_path: String,
    /// Command-line arguments (e.g., `/c echo hello`).
    pub arguments: String,
    /// Execution timeout in milliseconds. 0 = no timeout.
    pub timeout_ms: u32,
    /// Working directory for the child process. Empty = default.
    pub working_directory: String,
    /// Environment variables as (name, value) pairs.
    pub env_vars: Vec<(String, String)>,
    /// Bitfield of I/O redirect flags.
    pub redirect_flags: u32,
}

/// Builds `ProcessOptions` from a `CodexRequest`.
///
/// The command line is wrapped with `cmd.exe /c` so that shell features
/// (pipes, redirections, chained commands) work correctly — same pattern
/// as the LXC backend's `/bin/sh -c`.
pub(crate) fn build_process_options(request: &CodexRequest) -> ProcessOptions {
    let env_vars: Vec<(String, String)> = request
        .env
        .iter()
        .filter_map(|entry| {
            let mut parts = entry.splitn(2, '=');
            let name = parts.next()?.to_string();
            let value = parts.next().unwrap_or("").to_string();
            if name.is_empty() {
                None
            } else {
                Some((name, value))
            }
        })
        .collect();

    ProcessOptions {
        process_path: r"C:\Windows\System32\cmd.exe".to_string(),
        arguments: format!("/c {}", request.script_code),
        timeout_ms: request.script_timeout,
        working_directory: request.working_directory.clone(),
        env_vars,
        redirect_flags: REDIRECT_STDOUT | REDIRECT_STDERR,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::{CodexRequest, ContainerPolicy, NetworkPolicy, ProxyAddress, ProxyConfig};

    #[test]
    fn policy_rejects_readwrite_paths() {
        let request = CodexRequest {
            policy: ContainerPolicy {
                readwrite_paths: vec!["C:\\data".to_string()],
                ..Default::default()
            },
            ..Default::default()
        };
        let err = validate_policy(&request).unwrap_err();
        assert!(err.contains(ERR_FILESYSTEM_POLICY));
    }

    #[test]
    fn policy_rejects_readonly_paths() {
        let request = CodexRequest {
            policy: ContainerPolicy {
                readonly_paths: vec!["C:\\data".to_string()],
                ..Default::default()
            },
            ..Default::default()
        };
        let err = validate_policy(&request).unwrap_err();
        assert!(err.contains(ERR_FILESYSTEM_POLICY));
    }

    #[test]
    fn policy_rejects_denied_paths() {
        let request = CodexRequest {
            policy: ContainerPolicy {
                denied_paths: vec!["C:\\secret".to_string()],
                ..Default::default()
            },
            ..Default::default()
        };
        let err = validate_policy(&request).unwrap_err();
        assert!(err.contains(ERR_FILESYSTEM_POLICY));
    }

    #[test]
    fn policy_rejects_allowed_hosts() {
        let request = CodexRequest {
            policy: ContainerPolicy {
                allowed_hosts: vec!["example.com".to_string()],
                ..Default::default()
            },
            ..Default::default()
        };
        let err = validate_policy(&request).unwrap_err();
        assert!(err.contains(ERR_NETWORK_POLICY));
    }

    #[test]
    fn policy_rejects_blocked_hosts() {
        let request = CodexRequest {
            policy: ContainerPolicy {
                blocked_hosts: vec!["evil.com".to_string()],
                ..Default::default()
            },
            ..Default::default()
        };
        let err = validate_policy(&request).unwrap_err();
        assert!(err.contains(ERR_NETWORK_POLICY));
    }

    #[test]
    fn policy_rejects_network_block_policy() {
        let request = CodexRequest {
            policy: ContainerPolicy {
                default_network_policy: NetworkPolicy::Block,
                ..Default::default()
            },
            ..Default::default()
        };
        let err = validate_policy(&request).unwrap_err();
        assert!(err.contains(ERR_NETWORK_POLICY));
    }

    #[test]
    fn policy_rejects_proxy() {
        let request = CodexRequest {
            policy: ContainerPolicy {
                network_proxy: ProxyConfig {
                    address: Some(ProxyAddress::new("127.0.0.1".to_string(), 8080)),
                    builtin_test_server: false,
                },
                ..Default::default()
            },
            ..Default::default()
        };
        let err = validate_policy(&request).unwrap_err();
        assert!(err.contains(ERR_PROXY_POLICY));
    }

    #[test]
    fn policy_allows_defaults() {
        let request = CodexRequest::default();
        assert!(validate_policy(&request).is_ok());
    }

    // ====== ProcessOptions / option building tests ======

    #[test]
    fn options_wraps_command_with_cmd_exe() {
        let request = CodexRequest {
            script_code: "echo hello".to_string(),
            ..Default::default()
        };
        let opts = build_process_options(&request);
        assert_eq!(opts.process_path, r"C:\Windows\System32\cmd.exe");
        assert_eq!(opts.arguments, "/c echo hello");
    }

    #[test]
    fn options_maps_timeout() {
        let request = CodexRequest {
            script_code: "echo hi".to_string(),
            script_timeout: 30000,
            ..Default::default()
        };
        let opts = build_process_options(&request);
        assert_eq!(opts.timeout_ms, 30000);
    }

    #[test]
    fn options_maps_working_directory() {
        let request = CodexRequest {
            script_code: "echo hi".to_string(),
            working_directory: r"C:\Windows".to_string(),
            ..Default::default()
        };
        let opts = build_process_options(&request);
        assert_eq!(opts.working_directory, r"C:\Windows");
    }

    #[test]
    fn options_parses_env_vars() {
        let request = CodexRequest {
            script_code: "echo hi".to_string(),
            env: vec![
                "FOO=bar".to_string(),
                "PATH=C:\\bin;C:\\tools".to_string(),
            ],
            ..Default::default()
        };
        let opts = build_process_options(&request);
        assert_eq!(opts.env_vars.len(), 2);
        assert_eq!(opts.env_vars[0], ("FOO".to_string(), "bar".to_string()));
        assert_eq!(
            opts.env_vars[1],
            ("PATH".to_string(), r"C:\bin;C:\tools".to_string())
        );
    }

    #[test]
    fn options_skips_malformed_env_vars() {
        let request = CodexRequest {
            script_code: "echo hi".to_string(),
            env: vec![
                "GOOD=value".to_string(),
                "=no_name".to_string(),
                "ALSO_GOOD=".to_string(),
            ],
            ..Default::default()
        };
        let opts = build_process_options(&request);
        assert_eq!(opts.env_vars.len(), 2);
        assert_eq!(opts.env_vars[0].0, "GOOD");
        assert_eq!(opts.env_vars[1], ("ALSO_GOOD".to_string(), String::new()));
    }

    #[test]
    fn options_sets_redirect_flags() {
        let request = CodexRequest {
            script_code: "echo hi".to_string(),
            ..Default::default()
        };
        let opts = build_process_options(&request);
        assert_eq!(opts.redirect_flags, REDIRECT_STDOUT | REDIRECT_STDERR);
    }
}
