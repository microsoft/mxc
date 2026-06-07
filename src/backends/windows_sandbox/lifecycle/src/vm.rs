//! Windows Sandbox VM lifecycle management.
//!
//! Generates .wsb configuration files and launches/tears down
//! `WindowsSandbox.exe`.

use std::fmt::Write;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use tokio::process::Command;

/// Path where the guest binary is mapped inside the sandbox.
const SANDBOX_GUEST_DIR: &str = r"C:\Sandbox-Guest";

/// Path where the rendezvous directory is mapped inside the sandbox.
const SANDBOX_RENDEZVOUS_DIR: &str = r"C:\Sandbox-Rendezvous";

/// Path where Python is mapped inside the sandbox.
const SANDBOX_PYTHON_DIR: &str = r"C:\Sandbox-Python";

/// Name of the guest binary that runs inside the sandbox.
const GUEST_BINARY: &str = "wxc-windows-sandbox-guest.exe";

/// A host folder mapped into the sandbox, derived from the request's
/// filesystem policy (`readwrite_paths` / `readonly_paths`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MappedFolder {
    /// Host-side absolute path (must exist).
    pub host: String,
    /// Path the folder is exposed at inside the guest.
    pub sandbox: String,
    /// Whether the guest gets read-only access.
    pub read_only: bool,
}

/// Maximum time (seconds) to wait for sandbox processes to exit during teardown.
const TEARDOWN_POLL_TIMEOUT_SECS: u64 = 30;

/// Cooldown (seconds) after sandbox processes exit for Hyper-V backend cleanup.
const TEARDOWN_COOLDOWN_SECS: u64 = 5;

/// Polling interval (seconds) when checking for sandbox process exit.
const TEARDOWN_POLL_INTERVAL_SECS: u64 = 2;

/// Maximum time (seconds) to poll for the VM's host processes to appear after
/// `launch()` returns, so we can record ownership proof before the long
/// rendezvous wait. `launch()` returns while the VM boots in the background, so
/// the durable host processes may take a moment to appear.
const LAUNCH_PROOF_TIMEOUT_SECS: u64 = 30;

/// Polling interval (milliseconds) while waiting for the VM's host processes to
/// appear after launch.
const LAUNCH_PROOF_POLL_INTERVAL_MS: u64 = 500;

/// Discover the host's Python installation directory.
///
/// Checks `python.exe` on PATH, then falls back to common install locations.
/// Returns the directory containing `python.exe`.
pub fn find_host_python() -> Result<PathBuf> {
    // Try PATH first via `where python`.
    if let Ok(output) = std::process::Command::new("where").arg("python").output() {
        if output.status.success() {
            let stdout = String::from_utf8_lossy(&output.stdout);
            for line in stdout.lines() {
                let p = PathBuf::from(line.trim());
                if p.file_name().map(|f| f.to_ascii_lowercase()) != Some("python.exe".into()) {
                    continue;
                }
                if let Some(dir) = p.parent() {
                    if is_real_python(dir) {
                        return Ok(dir.to_path_buf());
                    }
                }
            }
        }
    }

    // Common install locations.
    let candidates = [
        r"C:\Python312",
        r"C:\Python311",
        r"C:\Python310",
        r"C:\Program Files\Python312",
        r"C:\Program Files\Python311",
        r"C:\Program Files\Python310",
    ];
    for dir in &candidates {
        let path = PathBuf::from(dir);
        if is_real_python(&path) {
            return Ok(path);
        }
    }

    // User-scoped installs.
    if let Ok(local_app_data) = std::env::var("LOCALAPPDATA") {
        let base = PathBuf::from(local_app_data)
            .join("Programs")
            .join("Python");
        if base.exists() {
            for entry in std::fs::read_dir(&base).into_iter().flatten().flatten() {
                let dir = entry.path();
                if is_real_python(&dir) {
                    return Ok(dir);
                }
            }
        }
    }

    anyhow::bail!(
        "Python installation not found on host. Install Python and ensure python.exe is on PATH."
    )
}

/// Returns true if `dir` contains a real Python installation (not a
/// Windows Store stub).  The WindowsApps stub passes `exists()` but
/// fails when invoked, so we run `python --version` to verify.
fn is_real_python(dir: &Path) -> bool {
    let python = dir.join("python.exe");
    if !python.exists() {
        return false;
    }
    // WindowsApps stubs live under Microsoft\WindowsApps — skip them
    // outright since they always fail when invoked from another context.
    if dir.to_string_lossy().contains("Microsoft\\WindowsApps") {
        eprintln!("[daemon] skipping Windows Store stub at {:?}", dir);
        return false;
    }
    // Belt-and-suspenders: verify it actually runs.
    std::process::Command::new(&python)
        .arg("--version")
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .map(|status| status.success())
        .unwrap_or(false)
}

/// Generate a .wsb configuration file in `output_dir` and a bootstrap script
/// in `rendezvous_dir`.
///
/// The .wsb maps three fixed folders into the sandbox:
///   - `guest_dir` (read-only)        → `C:\sandbox-guest`
///   - `rendezvous_dir` (read-write) → `C:\sandbox-rendezvous`
///   - `python_dir` (read-only)      → `C:\sandbox-python`
///
/// `extra_mapped` are additional host folders to expose inside the guest,
/// derived from the request's filesystem policy, each mapped at the same
/// absolute path inside the guest (host parity).
///
/// The LogonCommand runs a bootstrap script that adds Python to PATH then
/// starts the guest agent. (Network isolation is enforced by the guest agent
/// itself once the host connects — see `guest::firewall::lockdown` — so the
/// bootstrap does not touch the firewall.)
pub fn generate_wsb(
    guest_dir: &Path,
    rendezvous_dir: &Path,
    python_dir: &Path,
    output_dir: &Path,
    extra_mapped: &[MappedFolder],
) -> Result<PathBuf> {
    // Write the bootstrap script into the rendezvous dir (read-write inside
    // the sandbox) so it can be executed by the LogonCommand.
    let bootstrap_content = format!(
        r#"@echo off
set "LOG={rendezvous}\bootstrap.log"

echo [bootstrap] Starting at %date% %time% >> "%LOG%" 2>&1

echo [bootstrap] Adding mapped Python to PATH... >> "%LOG%" 2>&1
set "PATH={python};{python}\Scripts;%PATH%"

echo [bootstrap] Disabling Python bytecode cache (read-only mapped dir)... >> "%LOG%" 2>&1
set "PYTHONDONTWRITEBYTECODE=1"
set "PYTHONNOUSERSITE=1"

echo [bootstrap] PATH=%PATH% >> "%LOG%" 2>&1
where python >> "%LOG%" 2>&1
python --version >> "%LOG%" 2>&1

echo [bootstrap] Starting sandbox guest... >> "%LOG%" 2>&1
{guest}\{binary} >> "%LOG%" 2>&1
echo [bootstrap] Guest exited with code %ERRORLEVEL% >> "%LOG%" 2>&1
"#,
        rendezvous = SANDBOX_RENDEZVOUS_DIR,
        python = SANDBOX_PYTHON_DIR,
        guest = SANDBOX_GUEST_DIR,
        binary = GUEST_BINARY,
    );
    let bootstrap_path = rendezvous_dir.join("bootstrap.cmd");
    std::fs::write(&bootstrap_path, bootstrap_content)
        .with_context(|| format!("write bootstrap script {:?}", bootstrap_path))?;

    let mut mapped_xml = String::new();
    for folder in extra_mapped {
        let _ = write!(
            mapped_xml,
            "\n    <MappedFolder>\n      <HostFolder>{host}</HostFolder>\n      \
             <SandboxFolder>{sandbox}</SandboxFolder>\n      \
             <ReadOnly>{ro}</ReadOnly>\n    </MappedFolder>",
            host = xml_escape(&folder.host),
            sandbox = xml_escape(&folder.sandbox),
            ro = folder.read_only,
        );
    }

    let wsb_content = format!(
        r#"<Configuration>
  <MappedFolders>
    <MappedFolder>
      <HostFolder>{host_guest}</HostFolder>
      <SandboxFolder>{sandbox_guest}</SandboxFolder>
      <ReadOnly>true</ReadOnly>
    </MappedFolder>
    <MappedFolder>
      <HostFolder>{host_rendezvous}</HostFolder>
      <SandboxFolder>{sandbox_rendezvous}</SandboxFolder>
      <ReadOnly>false</ReadOnly>
    </MappedFolder>
    <MappedFolder>
      <HostFolder>{host_python}</HostFolder>
      <SandboxFolder>{sandbox_python}</SandboxFolder>
      <ReadOnly>true</ReadOnly>
    </MappedFolder>{mapped_xml}
  </MappedFolders>
  <LogonCommand>
    <Command>{sandbox_rendezvous}\bootstrap.cmd</Command>
  </LogonCommand>
  <vGPU>Disable</vGPU>
  <Networking>Enable</Networking>
</Configuration>"#,
        host_guest = guest_dir.display(),
        host_rendezvous = rendezvous_dir.display(),
        host_python = python_dir.display(),
        sandbox_guest = SANDBOX_GUEST_DIR,
        sandbox_rendezvous = SANDBOX_RENDEZVOUS_DIR,
        sandbox_python = SANDBOX_PYTHON_DIR,
        mapped_xml = mapped_xml,
    );

    let wsb_path = output_dir.join("wxc-windows-sandbox.wsb");
    std::fs::write(&wsb_path, wsb_content)
        .with_context(|| format!("write .wsb file {:?}", wsb_path))?;

    Ok(wsb_path)
}

/// Minimal XML text escaping for the `&`, `<`, and `>` metacharacters that
/// can legitimately appear in Windows paths (e.g. `&` in a folder name).
fn xml_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
}

/// Launch Windows Sandbox with the given .wsb file.
///
/// `WindowsSandbox.exe` is a standard Windows component; it returns
/// immediately while the sandbox boots in the background.
pub async fn launch(wsb_path: &Path) -> Result<()> {
    eprintln!("[daemon] launching WindowsSandbox.exe with {:?}", wsb_path);

    let status = Command::new("WindowsSandbox.exe")
        .arg(wsb_path)
        .status()
        .await
        .context("spawn WindowsSandbox.exe")?;

    if !status.success() {
        anyhow::bail!(
            "WindowsSandbox.exe exited with {}",
            status.code().unwrap_or(-1)
        );
    }
    Ok(())
}

/// Capture the ownership proof for a VM this daemon just launched: the
/// identities (PID + creation time) of its Windows Sandbox host processes.
///
/// `launch()` returns while the VM is still booting, so this polls (up to
/// [`LAUNCH_PROOF_TIMEOUT_SECS`]) until at least one host process appears.
/// Returns whatever was found when the budget elapses — possibly empty if the
/// processes never materialised, which the caller logs but does not treat as
/// fatal (the proof is refreshed again once the guest connects).
///
/// Safe to record as proof only when the caller knows it actually launched the
/// VM: the host permits a single sandbox VM, and startup reconcile guarantees
/// no foreign VM was running, so any host process present after a successful
/// launch belongs to us.
pub async fn capture_launch_proof() -> Vec<crate::control_plane::VmProcId> {
    let deadline =
        tokio::time::Instant::now() + std::time::Duration::from_secs(LAUNCH_PROOF_TIMEOUT_SECS);
    loop {
        if let Ok(procs) = enumerate_sandbox_vm_processes().await {
            if !procs.is_empty() {
                return procs;
            }
        }
        if tokio::time::Instant::now() >= deadline {
            return Vec::new();
        }
        tokio::time::sleep(std::time::Duration::from_millis(
            LAUNCH_PROOF_POLL_INTERVAL_MS,
        ))
        .await;
    }
}

/// Tear down a Windows Sandbox VM by terminating an already-planned kill set.
///
/// **The kill set is computed upstream by [`crate::control_plane::plan_kill_set`].**
/// This function is the OS-touching half of the teardown: it issues the
/// terminations and polls for confirmation. Splitting the pure plan from the
/// effectful kill collapses the previous asymmetry between the one-shot path
/// (which fails safe by leaking on empty seed) and the daemon path (which used
/// to enumerate-and-kill on empty seed, killing foreign VMs that appeared in
/// the snapshot-to-kill window after the daemon's own VM crashed — review
/// finding B1).
///
/// Returns a [`TeardownOutcome`] tri-state so callers can correctly decide
/// whether to delete the durable daemon / one-shot record afterward (review
/// finding NB-3 promoted to blocking):
///
/// - [`TeardownOutcome::ConfirmedGone`]: the polling loop saw `Some(false)`
///   from the liveness probe within the budget — every `WindowsSandbox*` host
///   process this run launched is gone. The record may be removed.
/// - [`TeardownOutcome::StillRunning(remaining)`]: the polling budget elapsed
///   with at least one host process still alive. The record MUST be preserved
///   so the next daemon's [`crate::control_plane::classify_startup`] can
///   reclaim by positive proof intersection.
/// - [`TeardownOutcome::ProbeFailed`]: the liveness probe itself failed
///   (Toolhelp32 hiccup) so the post-kill state is unknown. Preserve the
///   record on the same reasoning.
///
/// Best-effort — process-termination errors are logged but not propagated;
/// the outcome reflects what the *polling loop* can confirm. Only the
/// `WindowsSandbox*` host processes are treated as liveness indicators; the
/// SYSTEM-owned `vmmem*` Hyper-V memory residue is intentionally NOT awaited.
pub async fn teardown_via_plan(
    kill_set: &[crate::control_plane::VmProcId],
) -> crate::control_plane::TeardownOutcome {
    use crate::control_plane::TeardownOutcome;

    eprintln!(
        "[wsb-vm] tearing down sandbox ({} target process(es))",
        kill_set.len()
    );
    crate::control_plane::terminate_processes(kill_set);

    // Poll until the sandbox host processes are fully gone (up to 30s).
    // Only `WindowsSandbox*` count as live — `vmmem*` residue is harmless
    // (see `is_sandbox_vm_running`). We do NOT kill anything newly observed
    // here; we only wait for the snapshot we already terminated to disappear.
    let deadline =
        tokio::time::Instant::now() + std::time::Duration::from_secs(TEARDOWN_POLL_TIMEOUT_SECS);
    loop {
        match is_sandbox_vm_running().await {
            Some(false) => {
                eprintln!("[wsb-vm] all sandbox host processes confirmed gone");
                // Cooldown for Hyper-V backend / VHDX release.
                tokio::time::sleep(std::time::Duration::from_secs(TEARDOWN_COOLDOWN_SECS)).await;
                return TeardownOutcome::ConfirmedGone;
            }
            Some(true) => {
                if tokio::time::Instant::now() >= deadline {
                    let remaining = enumerate_sandbox_vm_processes().await.unwrap_or_default();
                    eprintln!(
                        "[wsb-vm] WARNING: {} sandbox host process(es) still running after {}s; \
                         preserving record so the next daemon can reclaim",
                        remaining.len(),
                        TEARDOWN_POLL_TIMEOUT_SECS
                    );
                    return TeardownOutcome::StillRunning(remaining);
                }
            }
            None => {
                if tokio::time::Instant::now() >= deadline {
                    eprintln!(
                        "[wsb-vm] WARNING: liveness probe failed during teardown wait; preserving \
                         record"
                    );
                    return TeardownOutcome::ProbeFailed;
                }
            }
        }
        tokio::time::sleep(std::time::Duration::from_secs(TEARDOWN_POLL_INTERVAL_SECS)).await;
    }
}

/// Check whether a Windows Sandbox VM is currently running.
///
/// Returns:
/// - `Some(true)`  — at least one `WindowsSandbox*` host process is live.
/// - `Some(false)` — the snapshot succeeded and contained no `WindowsSandbox*`
///   host processes (confirmed empty).
/// - `None`        — the Toolhelp32 snapshot itself failed; the live set is
///   unknown. Callers that gate a destructive or record-deleting decision on
///   this MUST treat `None` as "unknown" (refuse / preserve), not as "no VM".
///
/// Only the `WindowsSandbox*` host processes are considered. The `vmmem*`
/// Hyper-V memory processes are deliberately excluded: they linger as
/// harmless residue after the host processes exit and do not block a fresh
/// sandbox launch.
pub async fn is_sandbox_vm_running() -> Option<bool> {
    crate::control_plane::enumerate_pids_with_prefix("WindowsSandbox")
        .map(|pids| !pids.is_empty())
        .ok()
}

/// Enumerate the currently-running Windows Sandbox host processes, returning
/// each one's identity (PID paired with creation time).
///
/// Only the `WindowsSandbox*` host processes are reported, matching
/// [`is_sandbox_vm_running`]; `vmmem*` residue is excluded. The returned
/// identities form the *positive ownership proof* recorded in the daemon record
/// and matched against on a later daemon's startup reconcile.
///
/// Returns `Err` if the enumeration itself could not be performed (the Toolhelp32
/// snapshot failed). Callers that gate a destructive decision on the result MUST
/// treat an `Err` as "unknown" rather than "no VM", so they fail safe (refuse)
/// instead of proceeding blind.
pub async fn enumerate_sandbox_vm_processes() -> Result<Vec<crate::control_plane::VmProcId>> {
    crate::control_plane::enumerate_processes_with_prefix("WindowsSandbox")
}

// ---------------------------------------------------------------------------
// Shared "launch a managed VM and connect to its guest" sequence (review M7)
// ---------------------------------------------------------------------------

/// Caller-provided bookkeeping hooks for [`launch_managed_vm`]. Both the
/// one-shot runner (`one_shot::drive`) and the state-aware daemon
/// (`daemon::launch_and_connect`) used to inline an identical
/// nonce-write -> launch -> capture-proof -> rendezvous -> connect
/// sequence around their own per-caller ownership / proof
/// bookkeeping; this trait factors out the bookkeeping seam so the
/// shared sequence lives in one place.
///
/// The two methods correspond to the two transitions a managed launch
/// goes through that callers need to react to:
///   1. [`set_ownership`](Self::set_ownership) -- VM-ownership state
///      transitions (`LaunchInFlight` -> `LaunchSucceededNoProof` ->
///      `Owned(proof)`); callers update their own ownership record so
///      cleanup tears down (or leaks) the VM correctly.
///   2. [`persist_proof`](Self::persist_proof) -- a non-empty
///      capture-launch-proof is available and must be persisted
///      durably (one-shot writes a per-run marker file; daemon writes
///      the daemon record). Failing to persist is treated as fatal
///      (the launch is aborted) so cleanup never leaves a VM with no
///      durable trail to reclaim it.
pub trait LaunchObserver {
    /// Notify the caller that the launch sequence has reached a new
    /// VM-ownership state. Always called in the order
    /// `LaunchInFlight` -> `LaunchSucceededNoProof` -> `Owned(proof)`
    /// (the third only on a non-empty proof).
    fn set_ownership(&mut self, state: crate::control_plane::VmOwnership);

    /// Persist `proof` durably. Called at most once per launch, only
    /// when `capture_launch_proof` returns a non-empty proof. A
    /// non-`Ok` return is fatal -- [`launch_managed_vm`] propagates
    /// the error and the caller's teardown then runs from the
    /// in-memory `Owned(proof)` ownership state.
    fn persist_proof(&mut self, proof: &[crate::control_plane::VmProcId]) -> anyhow::Result<()>;

    /// Optional: caller-specific warning when `capture_launch_proof`
    /// returns empty. Default is a generic stderr line so callers do
    /// not need to repeat boilerplate; override when a more specific
    /// message is useful (e.g. one-shot wants to mention that the
    /// pre-launch marker preserves a reclaim-by-launcher-liveness
    /// fallback).
    fn note_empty_proof(&self) {
        eprintln!(
            "[wsb-vm] WARNING: no WindowsSandbox* host processes appeared within \
             capture_launch_proof's budget; staying at LaunchSucceededNoProof. Teardown will \
             enumerate-kill if any host processes are visible at exit. If the launcher hard-dies \
             before exit, the VM may require manual cleanup."
        );
    }
}

/// Drive the boot half of a managed Windows Sandbox VM lifecycle:
/// write the per-launch guest nonce, launch the VM, capture ownership
/// proof, wait for rendezvous, and connect to the guest agent. Calls
/// back into the caller via [`LaunchObserver`] at each ownership
/// transition and (on non-empty proof) at the proof-persistence step.
///
/// The returned [`bridge::GuestConnection`] is fully ready for EXEC
/// dispatch -- preamble + Ready have been validated as part of
/// `bridge::connect_to_guest`.
///
/// Used by both:
///   * `one_shot::drive` -- one-shot disposable VM per call;
///     observer writes a per-run marker file.
///   * `daemon::launch_and_connect` -- long-lived state-aware
///     daemon; observer writes the daemon record.
///
/// Each caller's pre-launch bookkeeping (rendezvous-dir setup, .wsb
/// generation, config-dir DACL, etc.) is still per-caller because
/// those steps differ structurally (one-shot uses a per-run
/// directory; daemon uses a fixed `wxc-wsb-stateaware-*` set). The
/// helper assumes `wsb_path` already exists and `rendezvous_dir`
/// already has its owner-only DACL applied.
pub async fn launch_managed_vm(
    wsb_path: &Path,
    rendezvous_dir: &Path,
    nonce: &windows_sandbox_common::auth::Nonce,
    rendezvous_timeout: std::time::Duration,
    rendezvous_poll_interval: std::time::Duration,
    connect_timeout: std::time::Duration,
    observer: &mut dyn LaunchObserver,
) -> Result<(crate::bridge::GuestConnection, std::net::SocketAddr)> {
    // Write the per-launch guest authentication nonce into the (already
    // owner-only DACL'd) rendezvous directory BEFORE launching the VM.
    // The guest reads + deletes the file at boot and verifies the nonce
    // on every accept; see `windows_sandbox_common::auth` for the full
    // threat model and the same-user-trusted scope (review C2 + A).
    windows_sandbox_common::auth::write_nonce_file(rendezvous_dir, nonce)
        .context("write guest nonce file")?;

    // Mark the launch in flight BEFORE the call. If we are cancelled
    // here or `launch()` errors, ownership is ambiguous (a foreign VM
    // could have won the single-instance contest), so cleanup must leak
    // rather than kill.
    observer.set_ownership(crate::control_plane::VmOwnership::LaunchInFlight);

    launch(wsb_path).await.context("launch VM")?;

    // `launch()` returned Ok: by the OS single-instance guarantee plus
    // startup reconcile, the running VM is ours. Record that immediately
    // so even if the host processes are slow to appear (or we are
    // cancelled before proof), cleanup tears the VM down by enumeration
    // instead of leaking it.
    observer.set_ownership(crate::control_plane::VmOwnership::LaunchSucceededNoProof);

    // Capture ownership proof now, before the long rendezvous wait.
    // Persist it via the observer so a crash mid-boot leaves a durable
    // reclaim trail. If proof is empty (slow Hyper-V worker spawn, AV
    // scanning the bootstrap, loaded host), stay at
    // `LaunchSucceededNoProof` rather than overwriting with
    // `Owned(Vec::new())` -- review finding B2 explains why: empty Owned
    // proof would defeat intersection-only teardown semantics and leak
    // the VM at exit.
    let proof = capture_launch_proof().await;
    if proof.is_empty() {
        observer.note_empty_proof();
    } else {
        observer.set_ownership(crate::control_plane::VmOwnership::Owned(proof.clone()));
        // A persist failure is fatal: better to fail the launch now
        // (cleanup runs from in-memory Owned(proof) state) than to
        // proceed and have a later cleanup find no durable trail.
        observer.persist_proof(&proof)?;
    }

    let addr = crate::rendezvous::wait_for_rendezvous(
        rendezvous_dir,
        rendezvous_timeout,
        rendezvous_poll_interval,
    )
    .await
    .context("rendezvous failed")?;

    let conn = crate::bridge::connect_to_guest(addr, connect_timeout, nonce)
        .await
        .context("connect to guest agent")?;

    Ok((conn, addr))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generate_wsb_creates_file() {
        let dir = tempfile::tempdir().unwrap();
        let guest_dir = dir.path().join("guest");
        let rendezvous_dir = dir.path().join("rendezvous");
        let python_dir = dir.path().join("python");
        std::fs::create_dir_all(&guest_dir).unwrap();
        std::fs::create_dir_all(&rendezvous_dir).unwrap();
        std::fs::create_dir_all(&python_dir).unwrap();

        let wsb_path =
            generate_wsb(&guest_dir, &rendezvous_dir, &python_dir, dir.path(), &[]).unwrap();
        assert!(wsb_path.exists());

        let content = std::fs::read_to_string(&wsb_path).unwrap();
        assert!(content.contains("<Configuration>"));
        assert!(content.contains("bootstrap.cmd"));
        assert!(content.contains(SANDBOX_PYTHON_DIR));
        assert!(content.contains(&guest_dir.display().to_string()));
        assert!(content.contains(&rendezvous_dir.display().to_string()));
        assert!(content.contains(&python_dir.display().to_string()));

        // Verify bootstrap script was created in the rendezvous dir.
        let bootstrap = rendezvous_dir.join("bootstrap.cmd");
        assert!(bootstrap.exists());
        let bootstrap_content = std::fs::read_to_string(&bootstrap).unwrap();
        assert!(bootstrap_content.contains(SANDBOX_PYTHON_DIR));
        assert!(bootstrap_content.contains(GUEST_BINARY));
        // No policy => no extra mapped folders and no firewall step.
        assert!(!bootstrap_content.contains("netsh advfirewall"));
    }

    #[test]
    fn generate_wsb_emits_extra_mapped_folders() {
        let dir = tempfile::tempdir().unwrap();
        let guest_dir = dir.path().join("guest");
        let rendezvous_dir = dir.path().join("rendezvous");
        let python_dir = dir.path().join("python");
        std::fs::create_dir_all(&guest_dir).unwrap();
        std::fs::create_dir_all(&rendezvous_dir).unwrap();
        std::fs::create_dir_all(&python_dir).unwrap();

        let mapped = vec![
            MappedFolder {
                host: r"C:\work\proj".to_string(),
                sandbox: r"C:\work\proj".to_string(),
                read_only: false,
            },
            MappedFolder {
                host: r"C:\data\ref".to_string(),
                sandbox: r"C:\data\ref".to_string(),
                read_only: true,
            },
        ];
        let wsb_path = generate_wsb(
            &guest_dir,
            &rendezvous_dir,
            &python_dir,
            dir.path(),
            &mapped,
        )
        .unwrap();
        let content = std::fs::read_to_string(&wsb_path).unwrap();
        assert!(content.contains(r"C:\work\proj"));
        assert!(content.contains(r"C:\data\ref"));
        // The read-only flag is rendered per folder.
        assert!(content.contains("<ReadOnly>true</ReadOnly>"));
        assert!(content.contains("<ReadOnly>false</ReadOnly>"));
    }

    #[test]
    fn xml_escape_escapes_metacharacters() {
        assert_eq!(xml_escape(r"C:\a&b"), r"C:\a&amp;b");
        assert_eq!(xml_escape("a<b>c"), "a&lt;b&gt;c");
    }

    #[test]
    fn find_host_python_returns_valid_dir() {
        // This test only passes on machines with Python installed.
        if let Ok(dir) = find_host_python() {
            assert!(dir.join("python.exe").exists());
        }
    }
}
