// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Starting and stopping the Kata shim process.
//!
//! `containerd-shim-kata-v2 start`, run with the bundle as its working
//! directory, binds the shim's ttrpc socket, spawns the long-lived shim
//! process, prints the socket address, and exits. The long-lived process owns
//! the VM. It outlives MXC's call, which is what lets a sandbox be started in
//! one call and used in a later one.
//!
//! The shim never contacts containerd here. It would publish task events to
//! `-address` only when `TTRPC_ADDRESS` is set, and MXC unsets it.

use std::io::Read;
use std::os::unix::process::CommandExt;
use std::path::Path;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};

use crate::kata_common::error::KataError;
use crate::kata_common::mounts;

/// containerd namespace the shim is told it runs in. It scopes nothing here;
/// the shim only needs a valid, non-empty name.
pub(crate) const NAMESPACE: &str = "mxc";

/// How long `start` may take to print the address and exit.
const START_TIMEOUT: Duration = Duration::from_secs(30);
/// How long the shim may take to exit after `Shutdown`.
const EXIT_TIMEOUT: Duration = Duration::from_secs(30);
const POLL: Duration = Duration::from_millis(25);

/// Directories the shim keeps per sandbox id. They are the shim's, but the ids
/// are unique to MXC, so a leftover can be removed once the shim is gone.
const KATA_STATE_DIR: &str = "/run/kata";
const KATA_SHARED_DIR: &str = "/run/kata-containers/shared/sandboxes";

/// A process, identified so a recycled pid is not mistaken for it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct ProcessIdentity {
    pub(crate) pid: u32,
    /// Start time in clock ticks since boot, from `/proc/<pid>/stat`.
    pub(crate) start_ticks: u64,
}

/// What `/proc/<pid>/stat` says about a process.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ProcStat {
    zombie: bool,
    start_ticks: u64,
}

/// Parses `/proc/<pid>/stat`. The command name is parenthesized and may hold
/// spaces and parentheses, so fields are counted from the last `)`.
fn parse_stat(stat: &str) -> Option<ProcStat> {
    let rest = &stat[stat.rfind(')')? + 1..];
    let fields: Vec<&str> = rest.split_whitespace().collect();
    // `fields[0]` is the state (field 3 of the file); starttime is field 22.
    Some(ProcStat {
        zombie: matches!(fields.first()?.chars().next()?, 'Z' | 'X'),
        start_ticks: fields.get(19)?.parse().ok()?,
    })
}

impl ProcessIdentity {
    /// Identifies a running process, or `None` when it does not exist.
    pub(crate) fn of(pid: u32) -> Option<Self> {
        let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
        let parsed = parse_stat(&stat)?;
        (!parsed.zombie).then_some(Self {
            pid,
            start_ticks: parsed.start_ticks,
        })
    }

    /// Whether this exact process is still running.
    pub(crate) fn is_alive(&self) -> bool {
        Self::of(self.pid).is_some_and(|now| now == *self)
    }

    /// SIGKILLs this process's whole group, but only while the process itself
    /// is still the one identified, so a recycled pid or group id is never
    /// signalled. The shim leads a group containing the VMM and its helpers.
    pub(crate) fn kill_group(&self) {
        if !self.is_alive() {
            return;
        }
        // SAFETY: `getpgid` and `killpg` take plain integers.
        let pgid = unsafe { libc::getpgid(self.pid as i32) };
        if pgid > 0 {
            unsafe { libc::killpg(pgid, libc::SIGKILL) };
        }
    }

    /// Waits for this process to exit. Returns whether it did in time.
    pub(crate) fn wait_for_exit(&self, timeout: Duration) -> bool {
        let deadline = Instant::now() + timeout;
        while self.is_alive() {
            if Instant::now() >= deadline {
                return false;
            }
            std::thread::sleep(POLL);
        }
        true
    }
}

/// A running shim.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct Shim {
    /// The shim's ttrpc address, `unix:///run/containerd/s/<hash>`.
    pub(crate) address: String,
    pub(crate) process: ProcessIdentity,
}

/// The arguments of `containerd-shim-kata-v2 start`.
pub(crate) fn start_args(sandbox_id: &str, address_hint: &Path) -> Vec<String> {
    vec![
        "-namespace".to_string(),
        NAMESPACE.to_string(),
        "-id".to_string(),
        sandbox_id.to_string(),
        // containerd's own address. Unused without containerd; the shim hashes
        // it into the socket name.
        "-address".to_string(),
        address_hint.display().to_string(),
        // Unused: the shim publishes no events here. A no-op binary is valid.
        "-publish-binary".to_string(),
        "true".to_string(),
        "start".to_string(),
    ]
}

/// Starts the shim for the sandbox whose bundle is `bundle`. A shim that
/// started but cannot be returned is killed, so no VM runs unrecorded.
pub(crate) fn start(
    shim_binary: &Path,
    sandbox_id: &str,
    bundle: &Path,
    address_hint: &Path,
) -> Result<Shim, KataError> {
    let launched = launch(shim_binary, sandbox_id, bundle, address_hint);
    if launched.is_err() {
        kill_unowned(bundle);
    }
    launched
}

/// Kills the shim recorded in the bundle's `shim.pid`, if it is running. The
/// bundle was cleared before the start, so the file is from this start.
fn kill_unowned(bundle: &Path) {
    let identity = std::fs::read_to_string(bundle.join("shim.pid"))
        .ok()
        .and_then(|text| text.trim().parse::<u32>().ok())
        .and_then(ProcessIdentity::of);
    if let Some(identity) = identity {
        identity.kill_group();
    }
}

fn launch(
    shim_binary: &Path,
    sandbox_id: &str,
    bundle: &Path,
    address_hint: &Path,
) -> Result<Shim, KataError> {
    let mut child = Command::new(shim_binary)
        .args(start_args(sandbox_id, address_hint))
        .current_dir(bundle)
        .env_remove("TTRPC_ADDRESS")
        .env_remove("KATA_CONF_FILE")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        // Its own process group, which the shim and the VMM inherit, so the
        // whole VM can be killed together if it will not stop.
        .process_group(0)
        .spawn()
        .map_err(|e| {
            KataError::unavailable(format!("cannot run {}: {e}", shim_binary.display()))
        })?;

    let deadline = Instant::now() + START_TIMEOUT;
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break status,
            Ok(None) if Instant::now() < deadline => std::thread::sleep(POLL),
            Ok(None) => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(KataError::failed(format!(
                    "{} start did not finish within {}s",
                    shim_binary.display(),
                    START_TIMEOUT.as_secs()
                )));
            }
            Err(e) => return Err(KataError::failed(format!("waiting for the shim: {e}"))),
        }
    };
    let mut stdout = String::new();
    let mut stderr = String::new();
    if let Some(mut pipe) = child.stdout.take() {
        let _ = pipe.read_to_string(&mut stdout);
    }
    if let Some(mut pipe) = child.stderr.take() {
        let _ = pipe.read_to_string(&mut stderr);
    }
    if !status.success() {
        return Err(KataError::failed(format!(
            "{} start failed ({status}): {}",
            shim_binary.display(),
            stderr.trim()
        )));
    }

    let address = stdout.trim().to_string();
    if !address.starts_with("unix://") {
        return Err(KataError::failed(format!(
            "{} start printed {address:?} instead of a unix:// address",
            shim_binary.display()
        )));
    }
    let pid = std::fs::read_to_string(bundle.join("shim.pid"))
        .map_err(|e| KataError::failed(format!("the shim wrote no shim.pid: {e}")))?
        .trim()
        .parse::<u32>()
        .map_err(|e| KataError::failed(format!("shim.pid is not a pid: {e}")))?;
    let process = ProcessIdentity::of(pid).ok_or_else(|| {
        KataError::failed(format!(
            "the shim process {pid} exited right after it started"
        ))
    })?;
    Ok(Shim { address, process })
}

/// Stops the shim, escalating to killing its process group when it does not
/// exit. Returns once nothing of the shim is left, or the failure to get there.
pub(crate) fn stop(
    shim: &Shim,
    task_client: &crate::kata_common::task_api::TaskClient,
    sandbox_id: &str,
) -> Result<(), KataError> {
    // A refused or failed Shutdown is not fatal, and the escalation below
    // covers a stuck shim. There is nothing to ask once the shim is gone.
    if shim.process.is_alive() {
        let _ = task_client.shutdown(sandbox_id, true);
    }
    if !shim.process.wait_for_exit(EXIT_TIMEOUT) {
        shim.process.kill_group();
        if !shim.process.wait_for_exit(EXIT_TIMEOUT) {
            return Err(KataError::failed(format!(
                "the Kata shim (pid {}) did not exit after Shutdown or SIGKILL",
                shim.process.pid
            )));
        }
    }
    Ok(())
}

/// Runs `containerd-shim-kata-v2 delete`, which containerd runs after a shim
/// shuts down. It removes the shim's socket file and cleans up whatever the
/// shim's persisted state says is left, including after a shim that was killed.
pub(crate) fn delete(
    shim_binary: &Path,
    sandbox_id: &str,
    bundle: &Path,
    address_hint: &Path,
) -> Result<(), String> {
    let mut args = start_args(sandbox_id, address_hint);
    args.pop(); // the `start` subcommand
    args.extend([
        "-bundle".to_string(),
        bundle.display().to_string(),
        "delete".to_string(),
    ]);
    let mut child = Command::new(shim_binary)
        .args(args)
        .current_dir(bundle)
        .env_remove("TTRPC_ADDRESS")
        .env_remove("KATA_CONF_FILE")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| format!("cannot run {} delete: {e}", shim_binary.display()))?;
    let deadline = Instant::now() + START_TIMEOUT;
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break status,
            Ok(None) if Instant::now() < deadline => std::thread::sleep(POLL),
            Ok(None) => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(format!("{} delete did not finish", shim_binary.display()));
            }
            Err(e) => return Err(format!("waiting for the shim delete: {e}")),
        }
    };
    if status.success() {
        return Ok(());
    }
    let mut stderr = String::new();
    if let Some(mut pipe) = child.stderr.take() {
        let _ = pipe.read_to_string(&mut stderr);
    }
    Err(format!(
        "{} delete failed ({status}): {}",
        shim_binary.display(),
        stderr.trim()
    ))
}

/// Removes what the shim leaves for `sandbox_id`: its directories, and the
/// ttrpc socket file at `address`. Call after the shim has exited, and after
/// [`delete`], which does the same when it works.
pub(crate) fn remove_leftovers(sandbox_id: &str, address: Option<&str>) {
    if let Some(socket) = address.and_then(|a| a.strip_prefix("unix://")) {
        let _ = std::fs::remove_file(socket);
    }
    for dir in [KATA_STATE_DIR, KATA_SHARED_DIR] {
        let path = Path::new(dir).join(sandbox_id);
        // Not deleted while a mount stays: that would delete what it exposes.
        if path.exists() && mounts::unmount_all(&path).is_ok() {
            let _ = std::fs::remove_dir_all(&path);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_command_line_matches_what_containerd_runs() {
        let args = start_args(
            "mxc-kata-1a2b3c4d",
            Path::new("/run/mxc-kata/x/containerd.sock"),
        );
        assert_eq!(
            args,
            [
                "-namespace",
                "mxc",
                "-id",
                "mxc-kata-1a2b3c4d",
                "-address",
                "/run/mxc-kata/x/containerd.sock",
                "-publish-binary",
                "true",
                "start"
            ]
        );
    }

    #[test]
    fn proc_stat_is_parsed_from_the_last_parenthesis() {
        // Field 22 (starttime) is 123456; the command name holds spaces and ")".
        let stat = "42 (my (odd) cmd) S 1 42 42 0 -1 4194560 1 0 0 0 0 0 0 0 20 0 1 0 123456 \
                    1000 100 18446744073709551615";
        assert_eq!(
            parse_stat(stat),
            Some(ProcStat {
                zombie: false,
                start_ticks: 123456
            })
        );
        let zombie = stat.replace(") S ", ") Z ");
        assert!(parse_stat(&zombie).unwrap().zombie);
        assert_eq!(parse_stat("garbage"), None);
        assert_eq!(parse_stat("1 (x) S 1"), None);
    }

    #[test]
    fn the_current_process_is_alive_and_a_wrong_start_time_is_not() {
        let me = ProcessIdentity::of(std::process::id()).expect("this process exists");
        assert!(me.is_alive());
        let recycled = ProcessIdentity {
            start_ticks: me.start_ticks + 1,
            ..me
        };
        assert!(!recycled.is_alive());
        // Killing a group through a stale identity must do nothing.
        recycled.kill_group();
        assert!(me.is_alive());
    }

    #[test]
    fn waiting_for_a_gone_process_returns_immediately() {
        let gone = ProcessIdentity {
            pid: u32::MAX - 1,
            start_ticks: 1,
        };
        assert!(gone.wait_for_exit(Duration::from_millis(10)));
    }

    #[test]
    fn a_shim_that_cannot_be_executed_is_reported_as_unavailable() {
        let dir = tempfile::tempdir().unwrap();
        let err = start(
            Path::new("/nonexistent/containerd-shim-kata-v2"),
            "mxc-kata-test",
            dir.path(),
            &dir.path().join("sock"),
        )
        .unwrap_err();
        assert!(matches!(err, KataError::Unavailable(_)), "{err:?}");
    }

    #[test]
    fn a_shim_that_fails_to_start_reports_its_stderr() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let fake = dir.path().join("shim");
        std::fs::write(&fake, "#!/bin/sh\necho 'boom: bad config' >&2\nexit 3\n").unwrap();
        std::fs::set_permissions(&fake, std::fs::Permissions::from_mode(0o755)).unwrap();
        let err = start(&fake, "mxc-kata-test", dir.path(), &dir.path().join("sock")).unwrap_err();
        assert!(err.message().contains("boom: bad config"), "{err:?}");
    }

    #[test]
    fn a_start_that_fails_after_the_shim_launched_kills_the_shim() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let fake = dir.path().join("shim");
        std::fs::write(
            &fake,
            "#!/bin/sh\nsleep 60 </dev/null >/dev/null 2>&1 &\necho $! > shim.pid\necho nonsense\n",
        )
        .unwrap();
        std::fs::set_permissions(&fake, std::fs::Permissions::from_mode(0o755)).unwrap();
        let err = start(&fake, "mxc-kata-test", dir.path(), &dir.path().join("sock")).unwrap_err();
        assert!(err.message().contains("unix://"), "{err:?}");

        let pid: u32 = std::fs::read_to_string(dir.path().join("shim.pid"))
            .unwrap()
            .trim()
            .parse()
            .unwrap();
        let deadline = Instant::now() + Duration::from_secs(5);
        while ProcessIdentity::of(pid).is_some() {
            assert!(
                Instant::now() < deadline,
                "the launched shim is still running"
            );
            std::thread::sleep(POLL);
        }
    }

    #[test]
    fn a_shim_that_prints_no_address_is_rejected() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let fake = dir.path().join("shim");
        std::fs::write(&fake, "#!/bin/sh\necho nonsense\n").unwrap();
        std::fs::set_permissions(&fake, std::fs::Permissions::from_mode(0o755)).unwrap();
        let err = start(&fake, "mxc-kata-test", dir.path(), &dir.path().join("sock")).unwrap_err();
        assert!(err.message().contains("unix://"), "{err:?}");
    }
}
