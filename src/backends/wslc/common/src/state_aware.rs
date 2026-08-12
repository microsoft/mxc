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

use wxc_common::logger::{Logger, Mode};
use wxc_common::models::{ContainerPolicy, ExecutionRequest, NetworkPolicy};
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
        let provision_config = build_provision_config(request, config)?;

        let client = connect_daemon()?;
        let sandbox_id = client
            .provision(provision_config)
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
        // proxy vars). `exec_proxy_url` yields the routable URL only when the
        // proxy is enabled *and* in the required `url` form — `validate_exec`
        // has already rejected the non-`url` form before we get here, so a
        // `None` here means the proxy is disabled, not malformed.
        let env = match exec_proxy_url(request) {
            Some(proxy_url) => split_env(&wxc_common::proxy_env::apply_cooperative_proxy_env(
                &request.env,
                proxy_url,
            )),
            None => split_env(&request.env),
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

/// Validate the `wslc:<32 lowercase hex>` shape. The dispatcher already routes
/// by prefix; this is defence in depth so a malformed id surfaces as
/// `malformed_id` rather than a confusing daemon-side `not_provisioned`. The
/// grammar mirrors the daemon-minted id (`wslc:` + a UUID simple form).
fn validate_sandbox_id(sandbox_id: &str) -> Result<(), MxcError> {
    let malformed = || {
        MxcError::malformed_id(format!(
            "expected wslc:<32 lowercase hex>, got {sandbox_id:?}"
        ))
    };
    let (prefix, rest) = sandbox_id.split_once(':').ok_or_else(malformed)?;
    let is_lower_hex = rest.len() == 32
        && rest
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b));
    if prefix == <WslcStateAwareRunner as StatefulSandboxBackend>::ID_PREFIX && is_lower_hex {
        Ok(())
    } else {
        Err(malformed())
    }
}

/// Build the daemon `ProvisionConfig` from the request + phase config without
/// contacting the daemon. Runs the same normalization/delegation + volume/network
/// mapping as `provision`, so the forwarded config (image, imageTarPath, volumes,
/// network) can be observed directly by a host-independent test — catching a
/// serialization/forwarding regression that an E2E run would only surface on a
/// live WSL host.
fn build_provision_config(
    request: &ExecutionRequest,
    config: Option<WslcProvisionPhase>,
) -> Result<ProvisionConfig, MxcError> {
    let image = config
        .as_ref()
        .and_then(|c| c.image.clone())
        .unwrap_or_else(|| DEFAULT_IMAGE.to_string());
    let image_tar_path = config.and_then(|c| c.image_tar_path);

    // Object-identity normalization (D6) + delegation (D3), mirroring the
    // one-shot runner: tighten rw/ro/denied aliases of the same host object to
    // the strictest intent, then reject any path the caller cannot access. The
    // daemon must mount the tightened policy, so a writable alias of a readonly
    // object never leaks and a persistent daemon never mounts a path the phase
    // caller could not delegate.
    let normalized = normalize_and_check_delegation(request)?;
    let normalized_request;
    let request = match normalized {
        Some(policy) => {
            normalized_request = ExecutionRequest {
                policy,
                ..request.clone()
            };
            &normalized_request
        }
        None => request,
    };

    // Re-run the denied-path overlap check on the *normalized* lists, mirroring
    // the one-shot runner order (wsl_container_runner.rs). Normalization can
    // tighten a mounted alias into `deniedPaths`; if that alias is nested under
    // another mounted parent the raw pre-normalization check in
    // `validate_provision_policy` cannot see it, and the daemon would mount the
    // parent leaving the deny reachable through it. Fail closed here.
    crate::policy_mapping::validate_denied_path_overlap(
        &request.policy.readwrite_paths,
        &request.policy.readonly_paths,
        &request.policy.denied_paths,
    )
    .map_err(MxcError::policy_validation)?;

    let volumes = build_daemon_volumes(request)?;
    let network = map_network(request);
    Ok(ProvisionConfig {
        image,
        image_tar_path,
        volumes,
        network,
    })
}

/// Object-identity normalization (D6) then delegation check (D3) for the
/// provision phase, mirroring the one-shot runner order. Returns the tightened
/// policy when aliasing required a change, else `None`; either check maps its
/// `String` error to a `policy_validation` envelope.
fn normalize_and_check_delegation(
    request: &ExecutionRequest,
) -> Result<Option<ContainerPolicy>, MxcError> {
    let mut logger = Logger::new(Mode::Buffer);
    let normalized =
        wxc_common::filesystem_object::normalize_object_conflicts(&request.policy, &mut logger)
            .map_err(MxcError::policy_validation)?;
    // Surface any normalization notes (policy tightening / unresolved paths) on
    // stderr rather than dropping the buffer: stdout carries the phase envelope,
    // so these diagnostics must not go there.
    let notes = logger.get_buffer();
    if !notes.is_empty() {
        eprint!("{notes}");
    }
    let policy = normalized.as_ref().unwrap_or(&request.policy);
    wxc_common::filesystem_access::check_delegation(policy).map_err(MxcError::policy_validation)?;
    Ok(normalized)
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
        validate_sandbox_id("wslc:0123456789abcdef0123456789abcdef").unwrap();
    }

    #[test]
    fn validate_sandbox_id_rejects_wrong_prefix() {
        let err = validate_sandbox_id("iso:0123456789abcdef0123456789abcdef").unwrap_err();
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
    fn validate_sandbox_id_rejects_non_hex_tail() {
        // Nonempty but not the 32-hex grammar: reaches the daemon today and is
        // misreported as not_provisioned rather than malformed_id.
        assert!(validate_sandbox_id("wslc:not-a-uuid").is_err());
    }

    #[test]
    fn validate_sandbox_id_rejects_wrong_length() {
        assert!(validate_sandbox_id("wslc:abc123").is_err());
        assert!(validate_sandbox_id("wslc:0123456789abcdef0123456789abcdef0").is_err());
    }

    #[test]
    fn validate_sandbox_id_rejects_uppercase_hex() {
        assert!(validate_sandbox_id("wslc:0123456789ABCDEF0123456789abcdef").is_err());
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
    fn build_provision_config_forwards_image_and_tar_path() {
        let phase = WslcProvisionPhase {
            image: Some("custom/image:tag".to_string()),
            image_tar_path: Some("C:\\images\\custom.tar".to_string()),
        };
        let cfg = build_provision_config(&ExecutionRequest::default(), Some(phase)).unwrap();
        assert_eq!(cfg.image, "custom/image:tag");
        assert_eq!(
            cfg.image_tar_path.as_deref(),
            Some("C:\\images\\custom.tar")
        );
    }

    #[test]
    fn build_provision_config_defaults_image_and_omits_tar_when_absent() {
        let cfg = build_provision_config(&ExecutionRequest::default(), None).unwrap();
        assert_eq!(cfg.image, DEFAULT_IMAGE);
        assert!(cfg.image_tar_path.is_none());
    }

    #[test]
    fn build_provision_config_rejects_denied_overlap_after_normalization() {
        // Guard: `build_provision_config` must re-run the denied-path overlap
        // check on the (post-normalization) lists, mirroring the one-shot
        // runner. A `deniedPaths` entry nested under a mounted parent has no
        // masking primitive on WSLc's flat mount surface, so it must be
        // rejected here even though the surrounding dispatcher also validates.
        let req = ExecutionRequest {
            policy: ContainerPolicy {
                readwrite_paths: vec!["C:\\parent".to_string()],
                denied_paths: vec!["C:\\parent\\secret".to_string()],
                ..Default::default()
            },
            ..Default::default()
        };
        let err = build_provision_config(&req, None).unwrap_err();
        assert_eq!(
            err.code,
            wxc_common::mxc_error::MxcErrorCode::PolicyValidation
        );
        assert!(err.message.contains("deniedPaths"), "got: {}", err.message);
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
    fn normalize_and_check_delegation_empty_policy_is_none() {
        let req = ExecutionRequest::default();
        assert!(normalize_and_check_delegation(&req).unwrap().is_none());
    }

    #[test]
    fn normalize_and_check_delegation_tightens_rw_alias_of_ro() {
        // The same host object listed both readwrite and readonly must be
        // tightened to readonly (D6) before the daemon mounts it, so a writable
        // alias of a readonly object never leaks.
        let dir = tempfile::tempdir().unwrap();
        let d = dir.path().to_str().unwrap().to_string();
        let req = ExecutionRequest {
            policy: ContainerPolicy {
                readwrite_paths: vec![d.clone()],
                readonly_paths: vec![d.clone()],
                ..Default::default()
            },
            ..Default::default()
        };
        let tightened = normalize_and_check_delegation(&req)
            .unwrap()
            .expect("aliasing conflict should tighten the policy");
        assert!(tightened.readwrite_paths.is_empty());
        assert_eq!(tightened.readonly_paths, vec![d]);
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
