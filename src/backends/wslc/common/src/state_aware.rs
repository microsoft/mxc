// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! `StatefulSandboxBackend` impl for the state-aware WSLc lifecycle.
//!
//! Each lifecycle phase (`provision` / `start` / `exec` / `stop` /
//! `deprovision`) runs as a separate short-lived `wxc-exec` process. Because the
//! WSLc SDK has no cross-process re-attach, this backend does **not** touch the
//! SDK directly: it translates the public `experimental.wslc.*` wire model plus
//! the cross-cutting `policy` section into [`daemon_protocol`] frames and drives
//! the long-lived `wxc-wslc-daemon` (which owns the live session/container
//! handles) over an owner-only named pipe via [`DaemonClient`].
//!
//! Windows-only: the daemon and its pipe transport are a Windows feature.

use std::io::Write;

use wxc_common::models::{ExecutionRequest, NetworkPolicy};
use wxc_common::mxc_error::MxcError;
use wxc_common::state_aware_backend::{
    null_pipe_handle, DeprovisionResult, ExecHandle, ProvisionResult, StartResult,
    StatefulSandboxBackend, StopResult,
};
use wxc_common::wire::WslcProvisionPhase;

use crate::daemon_client::{DaemonClient, DaemonError};
use crate::daemon_protocol::{
    DeprovisionConfig, ErrKind, ExecConfig, NetworkMode, ProvisionConfig, StartConfig, StopConfig,
    VolumeMount,
};
use crate::policy::{
    exec_proxy_url, validate_exec_policy, validate_post_provision_policy, validate_provision_policy,
};

/// Default image when a provision request omits `experimental.wslc.provision.image`.
const DEFAULT_IMAGE: &str = "alpine:latest";

/// State-aware WSLc backend. Zero-sized: every phase opens a fresh
/// [`DaemonClient`] connection (the daemon holds all persistent state).
#[derive(Debug, Default, Clone, Copy)]
pub struct WslcStateAwareRunner;

impl WslcStateAwareRunner {
    pub fn new() -> Self {
        Self
    }
}

impl StatefulSandboxBackend for WslcStateAwareRunner {
    const ID_PREFIX: &'static str = "wslc";
    const BACKEND_KEY: &'static str = "wslc";

    type ProvisionConfig = WslcProvisionPhase;
    type StartConfig = ();
    type ExecConfig = ();
    type StopConfig = ();
    type DeprovisionConfig = ();
    type ProvisionMetadata = ();
    type StartMetadata = ();
    type StopMetadata = ();
    type DeprovisionMetadata = ();

    fn provision(
        &mut self,
        request: &ExecutionRequest,
        config: Option<WslcProvisionPhase>,
    ) -> Result<ProvisionResult<()>, MxcError> {
        let image = config
            .as_ref()
            .and_then(|c| c.image.clone())
            .unwrap_or_else(|| DEFAULT_IMAGE.to_string());
        let image_tar_path = config.and_then(|c| c.image_tar_path);
        let volumes = build_daemon_volumes(request)?;
        let network = map_network(request);

        let client = connect_daemon()?;
        let sandbox_id = client
            .provision(ProvisionConfig {
                image,
                image_tar_path,
                volumes,
                network,
            })
            .map_err(map_daemon_error)?;

        // The daemon mints a fully `wslc:`-prefixed id; return it verbatim so
        // later phases present the daemon's own map key.
        Ok(ProvisionResult {
            sandbox_id,
            metadata: None,
        })
    }

    fn start(
        &mut self,
        sandbox_id: &str,
        _request: &ExecutionRequest,
        _config: Option<()>,
    ) -> Result<StartResult<()>, MxcError> {
        let client = connect_daemon()?;
        client
            .start(StartConfig {
                sandbox_id: sandbox_id.to_string(),
            })
            .map_err(map_daemon_error)?;
        Ok(StartResult { metadata: None })
    }

    fn stop(
        &mut self,
        sandbox_id: &str,
        _request: &ExecutionRequest,
        _config: Option<()>,
    ) -> Result<StopResult<()>, MxcError> {
        let client = connect_daemon()?;
        client
            .stop(StopConfig {
                sandbox_id: sandbox_id.to_string(),
            })
            .map_err(map_daemon_error)?;
        Ok(StopResult { metadata: None })
    }

    fn deprovision(
        &mut self,
        sandbox_id: &str,
        _request: &ExecutionRequest,
        _config: Option<()>,
    ) -> Result<DeprovisionResult<()>, MxcError> {
        let client = connect_daemon()?;
        client
            .deprovision(DeprovisionConfig {
                sandbox_id: sandbox_id.to_string(),
            })
            .map_err(map_daemon_error)?;
        Ok(DeprovisionResult { metadata: None })
    }

    /// Runs one command in the warm container. The daemon buffers the run to
    /// completion and returns the captured stdout/stderr plus the exit code;
    /// this relays the buffers to the executor's own stdio, then hands back an
    /// [`ExecHandle`] with sentinel pipe handles and a waiter that yields the
    /// already-captured exit code (so the dispatcher's `relay_exec_to_stdio` is
    /// a thin call-through, mirroring the IsolationSession backend).
    fn exec(
        &mut self,
        sandbox_id: &str,
        request: &ExecutionRequest,
        _config: Option<()>,
    ) -> Result<ExecHandle, MxcError> {
        // Cooperative proxy: inject HTTP(S)_PROXY (and scrub caller-supplied
        // proxy vars). The url-form requirement is enforced in `validate_exec`.
        let env = if request.policy.network_proxy.is_enabled() {
            let proxy_url = exec_proxy_url(request).ok_or_else(|| {
                MxcError::policy_validation(
                    "WSLc: network.proxy requires the 'url' form (a routable proxy URL)",
                )
            })?;
            split_env(&wxc_common::proxy_env::apply_cooperative_proxy_env(
                &request.env,
                &proxy_url,
            ))
        } else {
            split_env(&request.env)
        };

        let client = connect_daemon()?;
        let result = client
            .exec(ExecConfig {
                sandbox_id: sandbox_id.to_string(),
                script_code: request.script_code.clone(),
                working_directory: request.working_directory.clone(),
                env,
                timeout_ms: request.script_timeout,
            })
            .map_err(map_daemon_error)?;

        // Relay the daemon-captured buffers to our own stdio. Best-effort:
        // a failed local write must not mask the container's exit code.
        if !result.stdout.is_empty() {
            let mut out = std::io::stdout();
            let _ = out.write_all(&result.stdout);
            let _ = out.flush();
        }
        if !result.stderr.is_empty() {
            let mut err = std::io::stderr();
            let _ = err.write_all(&result.stderr);
            let _ = err.flush();
        }

        let exit_code = result.exit_code;
        Ok(ExecHandle {
            stdout: null_pipe_handle(),
            stderr: null_pipe_handle(),
            stdin: null_pipe_handle(),
            waiter: Box::new(move || Ok(exit_code)),
            terminator: Box::new(|| {}),
        })
    }

    fn validate_provision(
        &self,
        request: &ExecutionRequest,
        _config: Option<&WslcProvisionPhase>,
    ) -> Result<(), MxcError> {
        validate_provision_policy(request)
    }

    fn validate_start(
        &self,
        sandbox_id: &str,
        request: &ExecutionRequest,
        _config: Option<&()>,
    ) -> Result<(), MxcError> {
        validate_sandbox_id(sandbox_id)?;
        validate_post_provision_policy(request)
    }

    fn validate_exec(
        &self,
        sandbox_id: &str,
        request: &ExecutionRequest,
        _config: Option<&()>,
    ) -> Result<(), MxcError> {
        validate_sandbox_id(sandbox_id)?;
        validate_exec_policy(request)
    }

    fn validate_stop(
        &self,
        sandbox_id: &str,
        request: &ExecutionRequest,
        _config: Option<&()>,
    ) -> Result<(), MxcError> {
        validate_sandbox_id(sandbox_id)?;
        validate_post_provision_policy(request)
    }

    fn validate_deprovision(
        &self,
        sandbox_id: &str,
        request: &ExecutionRequest,
        _config: Option<&()>,
    ) -> Result<(), MxcError> {
        validate_sandbox_id(sandbox_id)?;
        validate_post_provision_policy(request)
    }
}

/// Discover (or spawn) the daemon. A discovery/spawn failure is a
/// `backend_unavailable` — the backend cannot service any phase without it.
fn connect_daemon() -> Result<DaemonClient, MxcError> {
    DaemonClient::connect().map_err(|e| {
        MxcError::backend_unavailable(format!("failed to reach the WSLc daemon: {e:#}"))
    })
}

/// Map a typed [`DaemonError`] onto the matching wire-format [`MxcError`] code.
/// The daemon's `NotProvisioned` / `NotStarted` tokens carry straight across;
/// transient and protocol conditions collapse to `backend_error`.
fn map_daemon_error(err: DaemonError) -> MxcError {
    match err {
        DaemonError::Daemon { kind, message } => match kind {
            ErrKind::NotProvisioned => MxcError::not_provisioned(message),
            ErrKind::NotStarted => MxcError::not_started(message),
            ErrKind::Busy | ErrKind::NotReady | ErrKind::Protocol | ErrKind::Backend => {
                MxcError::backend_error(message)
            }
        },
        DaemonError::Transport(e) => MxcError::backend_error(format!("{e:#}")),
    }
}

/// Validate the `wslc:<id>` shape. The dispatcher already routes by prefix; this
/// is defence in depth so a malformed id surfaces as `malformed_id` rather than
/// a confusing daemon-side `not_provisioned`.
fn validate_sandbox_id(sandbox_id: &str) -> Result<(), MxcError> {
    match sandbox_id.split_once(':') {
        Some((prefix, rest))
            if prefix == <WslcStateAwareRunner as StatefulSandboxBackend>::ID_PREFIX
                && !rest.is_empty() =>
        {
            Ok(())
        }
        _ => Err(MxcError::malformed_id(format!(
            "expected wslc:<id>, got {sandbox_id:?}"
        ))),
    }
}

/// Build daemon volume mounts from the request's filesystem policy. Overlapping
/// denied paths are rejected earlier in `validate_provision`; an invalid mount
/// path (e.g. a UNC share) surfaces here as `policy_validation`.
fn build_daemon_volumes(request: &ExecutionRequest) -> Result<Vec<VolumeMount>, MxcError> {
    let mounts = crate::policy_mapping::build_volume_mounts(
        &request.policy.readwrite_paths,
        &request.policy.readonly_paths,
    )
    .map_err(MxcError::policy_validation)?;
    Ok(mounts
        .into_iter()
        .map(|m| VolumeMount {
            host: m.windows_path,
            container: m.container_path,
            read_only: m.read_only,
        })
        .collect())
}

/// Map the request's default network policy to the daemon's binary network
/// mode. Per-host filtering is rejected in validation, so only the default
/// policy participates: `Block` → isolated, `Allow` → bridged NAT.
fn map_network(request: &ExecutionRequest) -> NetworkMode {
    match request.policy.default_network_policy {
        NetworkPolicy::Block => NetworkMode::None,
        NetworkPolicy::Allow => NetworkMode::Bridged,
    }
}

/// Split `"KEY=VALUE"` env entries into `(name, value)` pairs (the daemon's
/// `ExecConfig.env` shape). An entry without `=` becomes `(entry, "")`.
fn split_env(env: &[String]) -> Vec<(String, String)> {
    env.iter()
        .map(|entry| match entry.split_once('=') {
            Some((k, v)) => (k.to_string(), v.to_string()),
            None => (entry.clone(), String::new()),
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use wxc_common::models::ContainerPolicy;

    #[test]
    fn backend_key_matches_wire_format() {
        assert_eq!(
            <WslcStateAwareRunner as StatefulSandboxBackend>::BACKEND_KEY,
            "wslc"
        );
    }

    #[test]
    fn id_prefix_matches_wire_format() {
        assert_eq!(
            <WslcStateAwareRunner as StatefulSandboxBackend>::ID_PREFIX,
            "wslc"
        );
    }

    #[test]
    fn validate_sandbox_id_accepts_prefixed_id() {
        validate_sandbox_id("wslc:abc123").unwrap();
    }

    #[test]
    fn validate_sandbox_id_rejects_wrong_prefix() {
        let err = validate_sandbox_id("iso:abc123").unwrap_err();
        assert_eq!(err.code, wxc_common::mxc_error::MxcErrorCode::MalformedId);
    }

    #[test]
    fn validate_sandbox_id_rejects_empty_tail() {
        assert!(validate_sandbox_id("wslc:").is_err());
    }

    #[test]
    fn validate_sandbox_id_rejects_bare_token() {
        assert!(validate_sandbox_id("abc123").is_err());
    }

    #[test]
    fn map_network_maps_block_to_none() {
        let req = ExecutionRequest {
            policy: ContainerPolicy {
                default_network_policy: NetworkPolicy::Block,
                ..Default::default()
            },
            ..Default::default()
        };
        assert_eq!(map_network(&req), NetworkMode::None);
    }

    #[test]
    fn map_network_maps_allow_to_bridged() {
        let req = ExecutionRequest {
            policy: ContainerPolicy {
                default_network_policy: NetworkPolicy::Allow,
                ..Default::default()
            },
            ..Default::default()
        };
        assert_eq!(map_network(&req), NetworkMode::Bridged);
    }

    #[test]
    fn build_daemon_volumes_maps_rw_and_ro() {
        let req = ExecutionRequest {
            policy: ContainerPolicy {
                readwrite_paths: vec!["C:\\src".to_string()],
                readonly_paths: vec!["D:\\data".to_string()],
                ..Default::default()
            },
            ..Default::default()
        };
        let volumes = build_daemon_volumes(&req).unwrap();
        assert_eq!(volumes.len(), 2);
        assert_eq!(volumes[0].host, "C:\\src");
        assert_eq!(volumes[0].container, "/mnt/c/src");
        assert!(!volumes[0].read_only);
        assert_eq!(volumes[1].container, "/mnt/d/data");
        assert!(volumes[1].read_only);
    }

    #[test]
    fn build_daemon_volumes_rejects_unc_path() {
        let req = ExecutionRequest {
            policy: ContainerPolicy {
                readwrite_paths: vec!["\\\\server\\share".to_string()],
                ..Default::default()
            },
            ..Default::default()
        };
        let err = build_daemon_volumes(&req).unwrap_err();
        assert_eq!(
            err.code,
            wxc_common::mxc_error::MxcErrorCode::PolicyValidation
        );
    }

    #[test]
    fn split_env_splits_pairs_and_bare_keys() {
        let env = vec![
            "PATH=/usr/bin".to_string(),
            "EMPTY=".to_string(),
            "BARE".to_string(),
            "URL=http://a=b".to_string(),
        ];
        let pairs = split_env(&env);
        assert_eq!(pairs[0], ("PATH".to_string(), "/usr/bin".to_string()));
        assert_eq!(pairs[1], ("EMPTY".to_string(), String::new()));
        assert_eq!(pairs[2], ("BARE".to_string(), String::new()));
        // Only the first '=' splits; the value keeps the rest verbatim.
        assert_eq!(pairs[3], ("URL".to_string(), "http://a=b".to_string()));
    }

    #[test]
    fn map_daemon_error_preserves_not_provisioned() {
        let err = map_daemon_error(DaemonError::Daemon {
            kind: ErrKind::NotProvisioned,
            message: "unknown sandbox".to_string(),
        });
        assert_eq!(
            err.code,
            wxc_common::mxc_error::MxcErrorCode::NotProvisioned
        );
    }

    #[test]
    fn map_daemon_error_preserves_not_started() {
        let err = map_daemon_error(DaemonError::Daemon {
            kind: ErrKind::NotStarted,
            message: "not started".to_string(),
        });
        assert_eq!(err.code, wxc_common::mxc_error::MxcErrorCode::NotStarted);
    }

    #[test]
    fn map_daemon_error_collapses_busy_to_backend_error() {
        let err = map_daemon_error(DaemonError::Daemon {
            kind: ErrKind::Busy,
            message: "busy".to_string(),
        });
        assert_eq!(err.code, wxc_common::mxc_error::MxcErrorCode::BackendError);
    }
}
