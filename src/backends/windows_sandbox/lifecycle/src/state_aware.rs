// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! `StatefulSandboxBackend` impl for the Windows Sandbox backend.
//!
//! Windows Sandbox has no OS-level session service to persist a sandbox across
//! the separate `wxc-exec` processes that drive each lifecycle phase. Instead a
//! detached **host-side daemon** (`wxc-windows-sandbox-daemon.exe`) holds the
//! single live VM — and crucially its single guest control connection (the
//! guest exits the moment that connection drops) — from `start` until `stop`.
//!
//! State lives in two durable records under `%TEMP%\wxc-wsb\state-aware` (see
//! [`crate::control_plane`]): a per-sandbox `record.json` (lifecycle state +
//! immutable filesystem-policy snapshot) and a global `daemon.json` (the live
//! daemon's pid, IPC port, and auth nonce). Each phase is a fresh process that
//! reads those records to find and command the daemon.
//!
//! Phase semantics (4a — exec is stubbed until 4b):
//! - **provision**: pure bookkeeping. Validate + snapshot the filesystem
//!   policy, mint `wsb:<token>`, write the per-sandbox record. No VM, no daemon.
//! - **start**: spawn the detached daemon, which launches the VM and connects
//!   the guest, then writes `daemon.json`. Returns only once the daemon reports
//!   ready. Single-slot: rejected if another sandbox is already active.
//! - **stop**: command the daemon to tear down its VM and exit.
//! - **deprovision**: ensure the daemon is gone, then remove the per-sandbox
//!   scratch + record.
//!
//! A process-global named mutex ([`TransitionLock`]) serialises start / stop /
//! deprovision across phase processes so two concurrent transitions can never
//! double-spawn, kill the wrong target, or write contradictory records.

use std::io::{BufRead, BufReader, Write};
use std::net::{Ipv4Addr, SocketAddr, TcpStream};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use wxc_common::id::mint_random_token;
use wxc_common::models::ExecutionRequest;
use wxc_common::mxc_error::MxcError;
use wxc_common::process_util::resolve_sibling_binary;
use wxc_common::state_aware_backend::{
    DeprovisionResult, ExecHandle, ProvisionResult, StartResult, StatefulSandboxBackend, StopResult,
};

use crate::control_plane::{
    self, daemon_record_path, generate_nonce, live_daemon, process_creation_time,
    read_daemon_record, read_sandbox_record, sandbox_dir, sandbox_record_path, MappedFolderRecord,
    SandboxRecord, SandboxState, TransitionLock, IPC_OK, IPC_STOP,
};
use crate::error::OneShotError;
use crate::policy;
use crate::WindowsSandboxRunner;

/// `DETACHED_PROCESS` — the spawned daemon gets no console.
const DETACHED_PROCESS: u32 = 0x0000_0008;
/// `CREATE_NEW_PROCESS_GROUP` — isolates the daemon from the caller's console
/// Ctrl-C / process-group signals so killing the caller cannot orphan a VM.
const CREATE_NEW_PROCESS_GROUP: u32 = 0x0000_0200;

/// How long to wait for the cross-process transition mutex. A concurrent
/// `start` holds it for the whole VM boot, so a contending phase may wait
/// several minutes.
const TRANSITION_LOCK_TIMEOUT: Duration = Duration::from_secs(600);

/// How long to wait for the daemon to report ready (VM boot + guest rendezvous
/// + connect). First cold boot can take minutes.
const START_READY_TIMEOUT: Duration = Duration::from_secs(420);

/// Poll interval while waiting for the daemon to become ready.
const START_POLL_INTERVAL: Duration = Duration::from_millis(500);

/// How long to wait for the daemon process to exit after a STOP command.
const DAEMON_EXIT_TIMEOUT: Duration = Duration::from_secs(60);

/// Poll interval while waiting for the daemon to exit.
const DAEMON_EXIT_POLL_INTERVAL: Duration = Duration::from_millis(200);

/// Timeout for connecting to the daemon's localhost IPC port.
const IPC_CONNECT_TIMEOUT: Duration = Duration::from_secs(5);

/// Timeout for an IPC request/response round-trip.
const IPC_IO_TIMEOUT: Duration = Duration::from_secs(10);

/// Parse the `wsb:<token>` form of a state-aware `sandbox_id`, returning the
/// bare token. Surfaces format mismatches as [`MxcError::malformed_id`].
fn extract_token(sandbox_id: &str) -> Result<&str, MxcError> {
    let prefix = <WindowsSandboxRunner as StatefulSandboxBackend>::ID_PREFIX;
    match sandbox_id.split_once(':') {
        Some((p, rest)) if p == prefix && !rest.is_empty() => Ok(rest),
        _ => Err(MxcError::malformed_id(format!(
            "expected {}:<token>, got {:?}",
            prefix, sandbox_id
        ))),
    }
}

/// Map a [`OneShotError`] from policy planning to the wire error model. Policy
/// rejections become `policy_validation`; anything else is a backend error.
fn map_policy_error(e: OneShotError) -> MxcError {
    match e {
        OneShotError::Policy(msg) => MxcError::policy_validation(msg),
        other => MxcError::backend_error(format!("{other:?}")),
    }
}

/// Reject any non-default policy on a post-provision phase. The filesystem
/// policy is captured once at provision and is immutable thereafter; the
/// backend has no primitive to change it (or to honor network/proxy policy)
/// after the fact, so surfacing it later is a `policy_validation` error rather
/// than a silent ignore. Mirrors isolation_session's post-provision rejection.
fn reject_post_provision_policy(request: &ExecutionRequest) -> Result<(), MxcError> {
    let p = &request.policy;
    if !p.readwrite_paths.is_empty()
        || !p.readonly_paths.is_empty()
        || !p.denied_paths.is_empty()
        || !p.allowed_hosts.is_empty()
        || !p.blocked_hosts.is_empty()
        || p.network_proxy.is_enabled()
    {
        return Err(MxcError::policy_validation(
            "Windows Sandbox filesystem/network policy is fixed at provision; it cannot be \
             supplied or changed on a later phase",
        ));
    }
    Ok(())
}

/// Send a single nonce-authenticated line command to the daemon and return its
/// trimmed response line.
fn ipc_command(port: u16, verb: &str, nonce: &str) -> Result<String, MxcError> {
    let addr = SocketAddr::from((Ipv4Addr::LOCALHOST, port));
    let stream = TcpStream::connect_timeout(&addr, IPC_CONNECT_TIMEOUT)
        .map_err(|e| MxcError::backend_error(format!("connect daemon IPC on {addr}: {e}")))?;
    stream
        .set_read_timeout(Some(IPC_IO_TIMEOUT))
        .and_then(|()| stream.set_write_timeout(Some(IPC_IO_TIMEOUT)))
        .map_err(|e| MxcError::backend_error(format!("set IPC timeouts: {e}")))?;

    let mut writer = &stream;
    writeln!(writer, "{verb} {nonce}")
        .map_err(|e| MxcError::backend_error(format!("send {verb} to daemon: {e}")))?;

    let mut reader = BufReader::new(&stream);
    let mut line = String::new();
    reader
        .read_line(&mut line)
        .map_err(|e| MxcError::backend_error(format!("read daemon response: {e}")))?;
    Ok(line.trim().to_string())
}

/// Spawn the detached daemon for `token` with the given auth `nonce`.
fn spawn_daemon(token: &str, nonce: &str) -> Result<std::process::Child, MxcError> {
    use std::os::windows::process::CommandExt;

    let daemon_path = resolve_sibling_binary("wxc-windows-sandbox-daemon.exe")
        .map_err(|e| MxcError::backend_error(format!("locate daemon binary: {e}")))?;

    Command::new(&daemon_path)
        .arg("--token")
        .arg(token)
        .arg("--nonce")
        .arg(nonce)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .creation_flags(DETACHED_PROCESS | CREATE_NEW_PROCESS_GROUP)
        .spawn()
        .map_err(|e| MxcError::backend_error(format!("spawn daemon {daemon_path:?}: {e}")))
}

/// Wait for the daemon process described by `pid` / `creation_time` to exit,
/// up to [`DAEMON_EXIT_TIMEOUT`]. PID-reuse-safe: a recycled PID with a
/// different creation time counts as gone.
fn wait_daemon_gone(pid: u32, creation_time: u64) -> Result<(), MxcError> {
    let deadline = Instant::now() + DAEMON_EXIT_TIMEOUT;
    loop {
        if process_creation_time(pid) != Some(creation_time) {
            return Ok(());
        }
        if Instant::now() >= deadline {
            return Err(MxcError::backend_error(format!(
                "daemon pid {pid} did not exit within {:?} after STOP",
                DAEMON_EXIT_TIMEOUT
            )));
        }
        std::thread::sleep(DAEMON_EXIT_POLL_INTERVAL);
    }
}

impl StatefulSandboxBackend for WindowsSandboxRunner {
    const ID_PREFIX: &'static str = "wsb";
    const BACKEND_KEY: &'static str = "windows_sandbox";

    type ProvisionConfig = ();
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
        _config: Option<()>,
    ) -> Result<ProvisionResult<()>, MxcError> {
        // Validate + snapshot the filesystem policy. No side effects on reject.
        let plan = policy::plan_policy(request).map_err(map_policy_error)?;

        let token = mint_random_token();
        let sandbox_id = format!("{}:{}", Self::ID_PREFIX, token);

        let dir = sandbox_dir(&token);
        std::fs::create_dir_all(&dir)
            .map_err(|e| MxcError::backend_error(format!("create sandbox dir {dir:?}: {e}")))?;

        let mapped_folders: Vec<MappedFolderRecord> = plan
            .mapped_folders
            .iter()
            .map(|m| MappedFolderRecord {
                host: m.host.clone(),
                sandbox: m.sandbox.clone(),
                read_only: m.read_only,
            })
            .collect();

        let record = SandboxRecord::new_provisioned(sandbox_id.clone(), mapped_folders);
        control_plane::atomic_write_json(&sandbox_record_path(&token), &record)
            .map_err(|e| MxcError::backend_error(format!("write sandbox record: {e}")))?;

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
        let token = extract_token(sandbox_id)?;
        let _lock = TransitionLock::acquire(TRANSITION_LOCK_TIMEOUT)
            .map_err(|e| MxcError::backend_error(format!("{e}")))?;

        let mut record = read_sandbox_record(token)
            .map_err(|e| MxcError::backend_error(format!("{e}")))?
            .ok_or_else(|| {
                MxcError::not_provisioned(format!("sandbox {sandbox_id} is not provisioned"))
            })?;

        // Single-slot guard. A live daemon means a sandbox is already running.
        if let Some(d) = live_daemon().map_err(|e| MxcError::backend_error(format!("{e}")))? {
            if d.active_sandbox_id == sandbox_id {
                return Err(MxcError::already_started(format!(
                    "sandbox {sandbox_id} is already started"
                )));
            }
            return Err(MxcError::backend_unavailable(format!(
                "another Windows Sandbox ({}) is already active; only one is supported",
                d.active_sandbox_id
            )));
        }

        // A stale (dead) daemon record cannot belong to a live daemon — remove
        // it so the readiness poll below cannot latch onto leftover state.
        let _ = std::fs::remove_file(daemon_record_path());

        let nonce = generate_nonce();
        let mut child = spawn_daemon(token, &nonce)?;

        // Wait for the daemon to publish a ready record matching our nonce and
        // sandbox, or to die trying.
        let deadline = Instant::now() + START_READY_TIMEOUT;
        loop {
            if let Some(d) = live_daemon().map_err(|e| MxcError::backend_error(format!("{e}")))? {
                if d.nonce == nonce && d.active_sandbox_id == sandbox_id && d.ready {
                    break;
                }
            }
            match child.try_wait() {
                Ok(Some(status)) => {
                    return Err(MxcError::backend_error(format!(
                        "daemon exited during start ({status}); see daemon logs"
                    )));
                }
                Ok(None) => {}
                Err(e) => {
                    return Err(MxcError::backend_error(format!("poll daemon: {e}")));
                }
            }
            if Instant::now() >= deadline {
                // The daemon serves IPC throughout boot, so ask it to gracefully
                // tear down its (possibly half-launched) VM rather than orphaning
                // a live VM with a blind kill. Fall back to kill if no reachable
                // record exists.
                if let Ok(Some(d)) = read_daemon_record() {
                    if d.nonce == nonce && d.active_sandbox_id == sandbox_id {
                        let _ = ipc_command(d.ipc_port, IPC_STOP, &d.nonce);
                        let _ = wait_daemon_gone(d.pid, d.pid_creation_time);
                    }
                }
                let _ = child.kill();
                let _ = std::fs::remove_file(daemon_record_path());
                return Err(MxcError::backend_error(format!(
                    "daemon did not become ready within {:?}",
                    START_READY_TIMEOUT
                )));
            }
            std::thread::sleep(START_POLL_INTERVAL);
        }

        record.state = SandboxState::Started;
        control_plane::atomic_write_json(&sandbox_record_path(token), &record)
            .map_err(|e| MxcError::backend_error(format!("update sandbox record: {e}")))?;

        Ok(StartResult { metadata: None })
    }

    fn exec(
        &mut self,
        sandbox_id: &str,
        _request: &ExecutionRequest,
        _config: Option<()>,
    ) -> Result<ExecHandle, MxcError> {
        // Validate the id shape so a malformed id fails consistently with the
        // other phases even though exec is not yet wired to the guest.
        let _token = extract_token(sandbox_id)?;
        Err(MxcError::backend_error(
            "Windows Sandbox state-aware exec is not yet implemented (Phase 4b)",
        ))
    }

    fn stop(
        &mut self,
        sandbox_id: &str,
        _request: &ExecutionRequest,
        _config: Option<()>,
    ) -> Result<StopResult<()>, MxcError> {
        let token = extract_token(sandbox_id)?;
        let _lock = TransitionLock::acquire(TRANSITION_LOCK_TIMEOUT)
            .map_err(|e| MxcError::backend_error(format!("{e}")))?;

        let mut record = read_sandbox_record(token)
            .map_err(|e| MxcError::backend_error(format!("{e}")))?
            .ok_or_else(|| {
                MxcError::not_provisioned(format!("sandbox {sandbox_id} is not provisioned"))
            })?;

        match live_daemon().map_err(|e| MxcError::backend_error(format!("{e}")))? {
            Some(d) if d.active_sandbox_id == sandbox_id => {
                let resp = ipc_command(d.ipc_port, IPC_STOP, &d.nonce)?;
                if resp != IPC_OK {
                    return Err(MxcError::backend_error(format!(
                        "daemon rejected STOP: {resp}"
                    )));
                }
                wait_daemon_gone(d.pid, d.pid_creation_time)?;
                let _ = std::fs::remove_file(daemon_record_path());
            }
            _ => {
                // No live daemon holds this sandbox. If the record never
                // reached Started (or was already stopped), this is a no-op
                // already-stopped; otherwise reconcile the crashed-daemon case
                // by recording Stopped.
                if record.state != SandboxState::Started {
                    return Err(MxcError::already_stopped(format!(
                        "sandbox {sandbox_id} is not started"
                    )));
                }
            }
        }

        record.state = SandboxState::Stopped;
        control_plane::atomic_write_json(&sandbox_record_path(token), &record)
            .map_err(|e| MxcError::backend_error(format!("update sandbox record: {e}")))?;

        Ok(StopResult { metadata: None })
    }

    fn deprovision(
        &mut self,
        sandbox_id: &str,
        _request: &ExecutionRequest,
        _config: Option<()>,
    ) -> Result<DeprovisionResult<()>, MxcError> {
        let token = extract_token(sandbox_id)?;
        let _lock = TransitionLock::acquire(TRANSITION_LOCK_TIMEOUT)
            .map_err(|e| MxcError::backend_error(format!("{e}")))?;

        if read_sandbox_record(token)
            .map_err(|e| MxcError::backend_error(format!("{e}")))?
            .is_none()
        {
            return Err(MxcError::not_provisioned(format!(
                "sandbox {sandbox_id} is not provisioned"
            )));
        }

        // If a daemon still holds this sandbox, it owns a live VM that MUST be
        // torn down before we delete the records that let us find it again. A
        // failed stop here is fatal: deleting the records would orphan the VM
        // and strand the single-instance slot.
        if let Some(d) = live_daemon().map_err(|e| MxcError::backend_error(format!("{e}")))? {
            if d.active_sandbox_id == sandbox_id {
                let resp = ipc_command(d.ipc_port, IPC_STOP, &d.nonce)?;
                if resp != IPC_OK {
                    return Err(MxcError::backend_error(format!(
                        "daemon rejected STOP during deprovision: {resp}"
                    )));
                }
                wait_daemon_gone(d.pid, d.pid_creation_time)?;
                let _ = std::fs::remove_file(daemon_record_path());
            }
        }

        let dir = sandbox_dir(token);
        if let Err(e) = std::fs::remove_dir_all(&dir) {
            if e.kind() != std::io::ErrorKind::NotFound {
                return Err(MxcError::backend_error(format!(
                    "remove sandbox dir {dir:?}: {e}"
                )));
            }
        }

        Ok(DeprovisionResult { metadata: None })
    }

    fn validate_provision(
        &self,
        request: &ExecutionRequest,
        _config: Option<&()>,
    ) -> Result<(), MxcError> {
        policy::plan_policy(request)
            .map(|_| ())
            .map_err(map_policy_error)
    }

    fn validate_start(
        &self,
        sandbox_id: &str,
        request: &ExecutionRequest,
        _config: Option<&()>,
    ) -> Result<(), MxcError> {
        extract_token(sandbox_id)?;
        reject_post_provision_policy(request)
    }

    fn validate_exec(
        &self,
        sandbox_id: &str,
        request: &ExecutionRequest,
        _config: Option<&()>,
    ) -> Result<(), MxcError> {
        extract_token(sandbox_id)?;
        reject_post_provision_policy(request)
    }

    fn validate_stop(
        &self,
        sandbox_id: &str,
        request: &ExecutionRequest,
        _config: Option<&()>,
    ) -> Result<(), MxcError> {
        extract_token(sandbox_id)?;
        reject_post_provision_policy(request)
    }

    fn validate_deprovision(
        &self,
        sandbox_id: &str,
        request: &ExecutionRequest,
        _config: Option<&()>,
    ) -> Result<(), MxcError> {
        extract_token(sandbox_id)?;
        reject_post_provision_policy(request)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use wxc_common::models::{ContainerPolicy, NetworkPolicy};
    use wxc_common::mxc_error::MxcErrorCode;

    #[test]
    fn backend_key_matches_wire_format() {
        assert_eq!(
            <WindowsSandboxRunner as StatefulSandboxBackend>::BACKEND_KEY,
            "windows_sandbox"
        );
    }

    #[test]
    fn id_prefix_matches_wire_format() {
        assert_eq!(
            <WindowsSandboxRunner as StatefulSandboxBackend>::ID_PREFIX,
            "wsb"
        );
    }

    #[test]
    fn extract_token_unwraps_wsb_prefix() {
        assert_eq!(extract_token("wsb:deadbeef").unwrap(), "deadbeef");
    }

    #[test]
    fn extract_token_rejects_other_prefix() {
        let err = extract_token("iso:abc").unwrap_err();
        assert_eq!(err.code, MxcErrorCode::MalformedId);
    }

    #[test]
    fn extract_token_rejects_missing_colon() {
        let err = extract_token("wsbabc").unwrap_err();
        assert_eq!(err.code, MxcErrorCode::MalformedId);
    }

    #[test]
    fn extract_token_rejects_empty_token() {
        let err = extract_token("wsb:").unwrap_err();
        assert_eq!(err.code, MxcErrorCode::MalformedId);
    }

    #[test]
    fn reject_post_provision_policy_accepts_default() {
        let req = ExecutionRequest::default();
        reject_post_provision_policy(&req).unwrap();
    }

    #[test]
    fn reject_post_provision_policy_rejects_readwrite() {
        let req = ExecutionRequest {
            policy: ContainerPolicy {
                readwrite_paths: vec!["C:\\work".into()],
                ..Default::default()
            },
            ..Default::default()
        };
        let err = reject_post_provision_policy(&req).unwrap_err();
        assert_eq!(err.code, MxcErrorCode::PolicyValidation);
    }

    #[test]
    fn reject_post_provision_policy_rejects_denied_paths() {
        let req = ExecutionRequest {
            policy: ContainerPolicy {
                denied_paths: vec!["C:\\secret".into()],
                ..Default::default()
            },
            ..Default::default()
        };
        let err = reject_post_provision_policy(&req).unwrap_err();
        assert_eq!(err.code, MxcErrorCode::PolicyValidation);
    }

    #[test]
    fn map_policy_error_maps_policy_to_validation() {
        let err = map_policy_error(OneShotError::Policy("nope".into()));
        assert_eq!(err.code, MxcErrorCode::PolicyValidation);
    }

    #[test]
    fn validate_start_rejects_non_default_network() {
        let backend = WindowsSandboxRunner::new();
        let req = ExecutionRequest {
            policy: ContainerPolicy {
                allowed_hosts: vec!["example.com".into()],
                default_network_policy: NetworkPolicy::Block,
                ..Default::default()
            },
            ..Default::default()
        };
        let err = backend
            .validate_start("wsb:abcd1234", &req, None)
            .unwrap_err();
        assert_eq!(err.code, MxcErrorCode::PolicyValidation);
    }

    #[test]
    fn exec_stub_returns_backend_error() {
        let mut backend = WindowsSandboxRunner::new();
        let err = backend
            .exec("wsb:abcd1234", &ExecutionRequest::default(), None)
            .unwrap_err();
        assert_eq!(err.code, MxcErrorCode::BackendError);
    }

    #[test]
    fn exec_stub_rejects_malformed_id_first() {
        let mut backend = WindowsSandboxRunner::new();
        let err = backend
            .exec("iso:abc", &ExecutionRequest::default(), None)
            .unwrap_err();
        assert_eq!(err.code, MxcErrorCode::MalformedId);
    }
}
