// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! `StatefulSandboxBackend` impl for the state-aware WSLc lifecycle.
//!
//! Each lifecycle phase (`provision` / `start` / `exec` / `stop` /
//! `deprovision`) runs as a separate short-lived `wxc-exec` process. Because the
//! WSLc SDK has no cross-process re-attach, this backend does **not** touch the
//! SDK directly: it translates the public `wslc.*` wire model plus
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
    null_pipe_handle, DeprovisionResult, ExecConsumer, ExecHandle, ExecOutcome, ProvisionResult,
    StartResult, StatefulSandboxBackend, StopResult,
};
use wxc_common::state_aware_request::SectionRoot;
use wxc_common::validator::{validate_state_aware_network_policy_support, NetworkPolicySupport};
use wxc_common::wire::WslcProvisionPhase;

use crate::container_steps::OutStream;
use crate::daemon_client::{DaemonClient, DaemonError};
use crate::daemon_protocol::{
    DeprovisionConfig, ErrKind, ExecConfig, NetworkMode, ProvisionConfig, StartConfig, StopConfig,
    VolumeMount,
};
use crate::policy::{
    exec_proxy_url, validate_exec_policy, validate_post_provision_policy, validate_provision_policy,
};

/// Default image when a provision request omits `wslc.provision.image`.
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
    const SECTION_ROOT: SectionRoot = SectionRoot::Stable;

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

    /// Runs one command in the warm container, relaying its stdout/stderr to the
    /// calling process's own stdio **live** as the daemon streams it, then hands
    /// back an
    /// [`ExecHandle`] with sentinel pipe handles and a waiter that yields the
    /// captured exit code (so the dispatcher's `relay_exec_to_stdio` is a thin
    /// call-through, mirroring the IsolationSession and Windows Sandbox backends).
    fn exec(
        &mut self,
        sandbox_id: &str,
        request: &ExecutionRequest,
        _config: Option<()>,
        consumer: ExecConsumer,
    ) -> Result<ExecHandle, MxcError> {
        // Before any work: this backend relays to the executor's stdio, so it
        // cannot return exec streams to the caller, and running the workload first
        // would make the refusal a lie about what has already happened.
        if consumer == ExecConsumer::Library {
            return Err(wxc_common::state_aware_backend::unsupported_library_exec(
                "WSLc",
            ));
        }

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

        // Relay each chunk to our own stdio as it arrives. Hold the stdout/stderr
        // locks for the whole relay so we don't reacquire the handle per chunk,
        // and coalesce flushes: `std::io::Stdout`/`Stderr` are line-buffered, so
        // newline-terminated output already reaches the consumer promptly; we only
        // force a flush for a chunk that does *not* end in a newline (progress
        // output — prompts, spinners) so it isn't stranded in the line buffer.
        // This avoids a flush syscall per bulk chunk while preserving low latency.
        // Best-effort: a failed local write must not mask the container's exit code.
        let stdout = std::io::stdout();
        let stderr = std::io::stderr();
        let exit_code = {
            let mut out = stdout.lock();
            let mut err = stderr.lock();
            let result = client.exec_streaming(
                ExecConfig {
                    sandbox_id: sandbox_id.to_string(),
                    script_code: request.script_code.clone(),
                    working_directory: request.working_directory.clone(),
                    env,
                    timeout_ms: request.script_timeout,
                },
                |stream, bytes| match stream {
                    OutStream::Stdout => {
                        let _ = out.write_all(bytes);
                        if bytes.last() != Some(&b'\n') {
                            let _ = out.flush();
                        }
                    }
                    OutStream::Stderr => {
                        let _ = err.write_all(bytes);
                        if bytes.last() != Some(&b'\n') {
                            let _ = err.flush();
                        }
                    }
                },
            );
            let _ = out.flush();
            let _ = err.flush();
            // Drop the locks before mapping the error so error conversion never
            // contends with the writers we just held.
            drop((out, err));
            result.map_err(map_daemon_error)?
        };

        Ok(ExecHandle {
            stdout: null_pipe_handle(),
            stderr: null_pipe_handle(),
            stdin: null_pipe_handle(),
            stdin_closer: None,
            // `Exited`, not `TimedOut`: this backend relays internally and has
            // already run the workload to completion by the time it returns, so
            // `exit_code` is whatever the container reported — including for a
            // workload the daemon timed out. Reporting a timeout as such needs
            // the `Library` path this backend does not have yet.
            waiter: Box::new(move || Ok(ExecOutcome::Exited(exit_code))),
            // Nothing to terminate: the workload is already gone. `Ok(())` is
            // the truthful answer here, not a placeholder.
            terminator: Box::new(|| Ok(())),
        })
    }

    fn validate_provision(
        &self,
        request: &ExecutionRequest,
        _config: Option<&WslcProvisionPhase>,
    ) -> Result<(), MxcError> {
        validate_state_aware_network_policy_support(request, NetworkPolicySupport::LEGACY)?;
        validate_provision_policy(request)
    }

    fn validate_start(
        &self,
        sandbox_id: &str,
        request: &ExecutionRequest,
        _config: Option<&()>,
    ) -> Result<(), MxcError> {
        validate_sandbox_id(sandbox_id)?;
        validate_state_aware_network_policy_support(request, NetworkPolicySupport::LEGACY)?;
        validate_post_provision_policy(request)
    }

    fn validate_exec(
        &self,
        sandbox_id: &str,
        request: &ExecutionRequest,
        _config: Option<&()>,
    ) -> Result<(), MxcError> {
        validate_sandbox_id(sandbox_id)?;
        validate_state_aware_network_policy_support(request, NetworkPolicySupport::LEGACY)?;
        validate_exec_policy(request)
    }

    fn validate_stop(
        &self,
        sandbox_id: &str,
        request: &ExecutionRequest,
        _config: Option<&()>,
    ) -> Result<(), MxcError> {
        validate_sandbox_id(sandbox_id)?;
        validate_state_aware_network_policy_support(request, NetworkPolicySupport::LEGACY)?;
        validate_post_provision_policy(request)
    }

    fn validate_deprovision(
        &self,
        sandbox_id: &str,
        request: &ExecutionRequest,
        _config: Option<&()>,
    ) -> Result<(), MxcError> {
        validate_sandbox_id(sandbox_id)?;
        validate_state_aware_network_policy_support(request, NetworkPolicySupport::LEGACY)?;
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

    // WSLc provision-time filesystem-policy gate (D6 normalization → D3
    // delegation → denied-path overlap), shared verbatim with the one-shot
    // runner via `policy_mapping::apply_provision_policy_gate`. The daemon must
    // mount the tightened policy, so a writable alias of a readonly object never
    // leaks and a persistent daemon never mounts a path the phase caller could
    // not delegate.
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

    let volumes = build_daemon_volumes(request)?;
    let network = map_network(request);
    Ok(ProvisionConfig {
        image,
        image_tar_path,
        volumes,
        network,
    })
}

/// State-aware adapter over the shared WSLc provision policy gate
/// ([`crate::policy_mapping::apply_provision_policy_gate`]): runs the full
/// three-step gate (D6 normalization → D3 delegation → denied-path overlap),
/// buffering normalization diagnostics and surfacing them on stderr (stdout
/// carries the phase envelope), and maps the gate's `String` error to a
/// `policy_validation` [`MxcError`]. Returns the tightened policy when
/// normalization changed something, else `None`.
fn normalize_and_check_delegation(
    request: &ExecutionRequest,
) -> Result<Option<ContainerPolicy>, MxcError> {
    let mut logger = Logger::new(Mode::Buffer);
    let result = crate::policy_mapping::apply_provision_policy_gate(request, &mut logger);
    // Surface any normalization notes (policy tightening / unresolved paths) on
    // stderr even when the gate then fails, rather than dropping the buffer.
    let notes = logger.get_buffer();
    if !notes.is_empty() {
        eprint!("{notes}");
    }
    result.map_err(MxcError::policy_validation)
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
    use wxc_common::models::{ContainerPolicy, NetworkEgressPolicy};

    /// A `Library` exec is refused before the backend touches the daemon.
    ///
    /// This backend writes the workload's output to *this process's* stdout and
    /// stderr, so it cannot return exec streams to the caller. The refusal has to come
    /// first: the workload is arbitrary and may not be idempotent, so refusing
    /// after running it would report "unsupported" for something that already
    /// happened, with its output delivered somewhere the caller never asked for.
    ///
    /// The sandbox id is well-formed but names nothing, and there is no daemon
    /// to connect to. Any error other than the refusal means the guard ran too
    /// late — the code reached the daemon before checking who was asking.
    #[test]
    fn a_library_exec_is_refused_before_the_workload_runs() {
        let mut runner = WslcStateAwareRunner::new();
        let err = runner
            .exec(
                "wslc:0123456789abcdef0123456789abcdef",
                &ExecutionRequest::default(),
                None,
                ExecConsumer::Library,
            )
            .expect_err("a streams-consuming caller must be refused");
        assert!(
            err.message.contains("cannot return exec streams"),
            "expected the shared refusal before any daemon work, got: {}",
            err.message
        );
        assert!(
            err.message.contains("Nothing has been run"),
            "the refusal must state that no workload ran: {}",
            err.message
        );
    }

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
    fn post_provision_hooks_reject_raw_directional_network_fields() {
        let runner = WslcStateAwareRunner::new();
        let request = ExecutionRequest {
            policy: ContainerPolicy {
                network_egress: Some(NetworkEgressPolicy::default()),
                ..Default::default()
            },
            ..Default::default()
        };
        let id = "wslc:0123456789abcdef0123456789abcdef";

        assert!(runner.validate_start(id, &request, None).is_err());
        assert!(runner.validate_exec(id, &request, None).is_err());
        assert!(runner.validate_stop(id, &request, None).is_err());
        assert!(runner.validate_deprovision(id, &request, None).is_err());
    }

    /// Enumerating all five hooks (rather than testing the shared validator) is
    /// what catches a hook that forgets to call its validator at all.
    #[test]
    fn every_validate_hook_rejects_supplied_ui() {
        let runner = WslcStateAwareRunner::new();
        let request = ExecutionRequest {
            policy: ContainerPolicy {
                ui_specified: true,
                ..Default::default()
            },
            ..Default::default()
        };
        let id = "wslc:0123456789abcdef0123456789abcdef";

        let results = [
            ("provision", runner.validate_provision(&request, None)),
            ("start", runner.validate_start(id, &request, None)),
            ("exec", runner.validate_exec(id, &request, None)),
            ("stop", runner.validate_stop(id, &request, None)),
            (
                "deprovision",
                runner.validate_deprovision(id, &request, None),
            ),
        ];
        for (phase, result) in results {
            let err = result.expect_err(&format!("{phase} must reject a supplied ui"));
            assert_eq!(
                err.code,
                wxc_common::mxc_error::MxcErrorCode::PolicyValidation
            );
            assert!(
                err.message.contains("ui section is not supported"),
                "{phase}: {}",
                err.message
            );
        }
    }

    /// Refused at provision, the only phase where the network posture is
    /// settable — so neither can be silently dropped into the daemon's
    /// `ProvisionConfig`, which carries only the binary [`NetworkMode`].
    #[test]
    fn validate_provision_rejects_unimplementable_network_posture() {
        let runner = WslcStateAwareRunner::new();
        for (policy, needle) in [
            (
                ContainerPolicy {
                    allow_local_network: true,
                    ..Default::default()
                },
                "allowLocalNetwork",
            ),
            (
                ContainerPolicy {
                    network_enforcement_mode: wxc_common::models::NetworkEnforcementMode::Firewall,
                    ..Default::default()
                },
                "enforcementMode",
            ),
        ] {
            let request = ExecutionRequest {
                policy,
                ..Default::default()
            };
            let err = runner
                .validate_provision(&request, None)
                .expect_err(&format!("provision must reject {needle}"));
            assert_eq!(
                err.code,
                wxc_common::mxc_error::MxcErrorCode::PolicyValidation
            );
            assert!(err.message.contains(needle), "got: {}", err.message);
        }
    }

    /// Guards against over-rejection. Each value is the near-miss of a rejected
    /// one, so a gate that flipped between value- and presence-based would fail
    /// here only.
    #[test]
    fn validate_provision_accepts_the_postures_wslc_can_honour() {
        let runner = WslcStateAwareRunner::new();
        for (label, policy) in [
            (
                "explicit capabilities enforcement mode",
                ContainerPolicy {
                    network_enforcement_mode:
                        wxc_common::models::NetworkEnforcementMode::Capabilities,
                    ..Default::default()
                },
            ),
            (
                "explicit allowLocalNetwork=false",
                ContainerPolicy {
                    allow_local_network: false,
                    ..Default::default()
                },
            ),
            (
                "absent ui",
                ContainerPolicy {
                    ui_specified: false,
                    ..Default::default()
                },
            ),
        ] {
            let request = ExecutionRequest {
                policy,
                ..Default::default()
            };
            assert!(
                runner.validate_provision(&request, None).is_ok(),
                "{label} is honoured by WSLc and must not be rejected"
            );
        }
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

    #[cfg(windows)]
    #[test]
    fn provision_delegation_tightens_rw_alias_of_denied_and_drops_mount() {
        // A writable path that resolves to the same object as a `denied` entry
        // (here a case-variant string on case-insensitive NTFS) must tighten to
        // denied, and the daemon volumes must be built from that tightened policy
        // — otherwise the writable alias would still be mounted, granting access
        // the deny was meant to block.
        let dir = tempfile::tempdir().unwrap();
        let denied = dir.path().to_str().unwrap().to_string();
        let rw_alias = denied.to_uppercase();
        let raw = ExecutionRequest {
            policy: ContainerPolicy {
                readwrite_paths: vec![rw_alias],
                denied_paths: vec![denied],
                ..Default::default()
            },
            ..Default::default()
        };
        // Pre-fix behaviour the bug relied on: the raw request WOULD mount the
        // alias writable.
        let raw_mounts = build_daemon_volumes(&raw).unwrap();
        assert_eq!(raw_mounts.len(), 1);
        assert!(!raw_mounts[0].read_only);

        let tightened = normalize_and_check_delegation(&raw)
            .unwrap()
            .expect("rw alias of a denied object should tighten");
        assert!(tightened.readwrite_paths.is_empty());
        assert!(!tightened.denied_paths.is_empty());
        let tightened_req = ExecutionRequest {
            policy: tightened,
            ..raw.clone()
        };
        assert!(build_daemon_volumes(&tightened_req).unwrap().is_empty());
    }

    #[cfg(windows)]
    #[test]
    fn provision_delegation_rejects_inaccessible_path() {
        // A delegated path the invoking user cannot access must fail closed
        // before provisioning mounts anything. `C:\mxc_invalid<name` is an
        // illegal name → ERROR_INVALID_NAME → not-accessible (not merely
        // missing), so delegation rejects it.
        let req = ExecutionRequest {
            policy: ContainerPolicy {
                readonly_paths: vec!["C:\\mxc_invalid<name".to_string()],
                ..Default::default()
            },
            ..Default::default()
        };
        let err = normalize_and_check_delegation(&req).unwrap_err();
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
