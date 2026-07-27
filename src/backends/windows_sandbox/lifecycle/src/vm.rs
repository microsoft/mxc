//! Windows Sandbox VM lifecycle management.
//!
//! Generates .wsb configuration files and launches/tears down
//! `WindowsSandbox.exe`.

use std::fmt::Write;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use tokio::process::Command;

const SANDBOX_GUEST_DIR: &str = r"C:\Sandbox-Guest";

const SANDBOX_RENDEZVOUS_DIR: &str = r"C:\Sandbox-Rendezvous";

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

const TEARDOWN_POLL_TIMEOUT_SECS: u64 = 30;

const TEARDOWN_COOLDOWN_SECS: u64 = 5;

const TEARDOWN_POLL_INTERVAL_SECS: u64 = 2;

const LAUNCH_PROOF_TIMEOUT_SECS: u64 = 30;

const LAUNCH_PROOF_POLL_INTERVAL_MS: u64 = 500;

/// Generate a .wsb file plus bootstrap script.
pub fn generate_wsb(
    guest_dir: &Path,
    rendezvous_dir: &Path,
    output_dir: &Path,
    extra_mapped: &[MappedFolder],
) -> Result<PathBuf> {
    let bootstrap_content = format!(
        r#"@echo off
set "LOG={rendezvous}\bootstrap.log"
:: Truncate any prior bootstrap.log content on this boot so its
:: contents cannot accumulate across runs on the host.
type nul > "%LOG%"

echo [bootstrap] Starting at %date% %time% >> "%LOG%" 2>&1

echo [bootstrap] PATH=%PATH% >> "%LOG%" 2>&1

echo [bootstrap] Starting sandbox guest... >> "%LOG%" 2>&1
{guest}\{binary} >> "%LOG%" 2>&1
echo [bootstrap] Guest exited with code %ERRORLEVEL% >> "%LOG%" 2>&1
"#,
        rendezvous = SANDBOX_RENDEZVOUS_DIR,
        guest = SANDBOX_GUEST_DIR,
        binary = GUEST_BINARY,
    );
    let bootstrap_path = rendezvous_dir.join("bootstrap.cmd");
    write_fresh(&bootstrap_path, &bootstrap_content)
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
    </MappedFolder>{mapped_xml}
  </MappedFolders>
  <LogonCommand>
    <Command>{sandbox_rendezvous}\bootstrap.cmd</Command>
  </LogonCommand>
  <vGPU>Disable</vGPU>
  <Networking>Enable</Networking>
</Configuration>"#,
        host_guest = xml_escape(&guest_dir.display().to_string()),
        host_rendezvous = xml_escape(&rendezvous_dir.display().to_string()),
        sandbox_guest = SANDBOX_GUEST_DIR,
        sandbox_rendezvous = SANDBOX_RENDEZVOUS_DIR,
        mapped_xml = mapped_xml,
    );

    let wsb_path = output_dir.join("wxc-windows-sandbox.wsb");
    write_fresh(&wsb_path, &wsb_content)
        .with_context(|| format!("write .wsb file {:?}", wsb_path))?;

    Ok(wsb_path)
}

/// Minimal XML text escaping for Windows paths.
fn xml_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
}

/// Write a generated file as a fresh create so inherited DACLs are reapplied.
fn write_fresh(path: &Path, content: &str) -> std::io::Result<()> {
    match std::fs::remove_file(path) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(e),
    }
    std::fs::write(path, content)
}

/// Launch Windows Sandbox with the given .wsb file.
pub(crate) async fn launch(wsb_path: &Path) -> Result<()> {
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

/// Capture PID+creation-time proof for host processes this launch owns.
pub(crate) async fn capture_launch_proof() -> Vec<crate::control_plane::VmProcId> {
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

/// Terminate a precomputed kill set and confirm sandbox host processes exit.
pub async fn teardown_via_plan(
    kill_set: &[crate::control_plane::VmProcId],
) -> crate::control_plane::TeardownOutcome {
    use crate::control_plane::TeardownOutcome;

    eprintln!(
        "[wsb-vm] tearing down sandbox ({} target process(es))",
        kill_set.len()
    );
    crate::control_plane::terminate_processes(kill_set);

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

/// Check whether any `WindowsSandbox*` host process is running.
pub async fn is_sandbox_vm_running() -> Option<bool> {
    crate::control_plane::enumerate_pids_with_prefix("WindowsSandbox")
        .map(|pids| !pids.is_empty())
        .ok()
}

/// Enumerate running `WindowsSandbox*` host processes with PID-reuse proof.
pub async fn enumerate_sandbox_vm_processes() -> Result<Vec<crate::control_plane::VmProcId>> {
    crate::control_plane::enumerate_processes_with_prefix("WindowsSandbox")
}

// ---------------------------------------------------------------------------
// Shared "launch a managed VM and connect to its guest" sequence
// ---------------------------------------------------------------------------

/// Caller hooks for the shared managed-VM launch sequence.
pub trait LaunchObserver: Send {
    fn set_ownership(&mut self, state: crate::control_plane::VmOwnership);

    /// Persist non-empty VM process proof durably.
    fn persist_proof(&mut self, proof: &[crate::control_plane::VmProcId]) -> anyhow::Result<()>;

    /// Optional warning hook when no launch proof was captured.
    fn note_empty_proof(&self) {
        eprintln!(
            "[wsb-vm] WARNING: no WindowsSandbox* host processes appeared within \
             capture_launch_proof's budget; staying at LaunchSucceededNoProof. Teardown will \
             enumerate-kill any host processes visible at exit, but teardown-on-exit is NOT \
             guaranteed: a launcher hard-kill in this window (TerminateProcess/OOM/power-loss) can \
             orphan the VM with no proof, wedging the machine-wide-singleton backend. Clear it by \
             closing the sandbox window or re-running with --force-reclaim."
        );
    }
}

/// Launch a managed VM and return a guest connection ready for EXEC dispatch.
pub async fn launch_managed_vm(
    wsb_path: &Path,
    rendezvous_dir: &Path,
    nonce: &windows_sandbox_common::auth::Nonce,
    rendezvous_timeout: std::time::Duration,
    rendezvous_poll_interval: std::time::Duration,
    connect_timeout: std::time::Duration,
    observer: &mut dyn LaunchObserver,
) -> Result<(crate::bridge::GuestConnection, std::net::SocketAddr)> {
    windows_sandbox_common::auth::write_nonce_file(rendezvous_dir, nonce)
        .context("write guest nonce file")?;

    observer.set_ownership(crate::control_plane::VmOwnership::LaunchInFlight);

    launch(wsb_path).await.context("launch VM")?;

    observer.set_ownership(crate::control_plane::VmOwnership::LaunchSucceededNoProof);

    // Non-empty proof is durable reclaim state; empty proof stays as
    // LaunchSucceededNoProof so teardown can still enumerate this live run.
    let proof = capture_launch_proof().await;
    if proof.is_empty() {
        observer.note_empty_proof();
    } else {
        observer.set_ownership(crate::control_plane::VmOwnership::Owned(proof.clone()));
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
        std::fs::create_dir_all(&guest_dir).unwrap();
        std::fs::create_dir_all(&rendezvous_dir).unwrap();

        let wsb_path = generate_wsb(&guest_dir, &rendezvous_dir, dir.path(), &[]).unwrap();
        assert!(wsb_path.exists());

        let content = std::fs::read_to_string(&wsb_path).unwrap();
        assert!(content.contains("<Configuration>"));
        assert!(content.contains("bootstrap.cmd"));
        assert!(content.contains(&guest_dir.display().to_string()));
        assert!(content.contains(&rendezvous_dir.display().to_string()));

        let bootstrap = rendezvous_dir.join("bootstrap.cmd");
        assert!(bootstrap.exists());
        let bootstrap_content = std::fs::read_to_string(&bootstrap).unwrap();
        assert!(bootstrap_content.contains(GUEST_BINARY));
        assert!(!bootstrap_content.contains("netsh advfirewall"));
        assert!(!bootstrap_content.contains("python"));
    }

    #[test]
    fn generate_wsb_emits_extra_mapped_folders() {
        let dir = tempfile::tempdir().unwrap();
        let guest_dir = dir.path().join("guest");
        let rendezvous_dir = dir.path().join("rendezvous");
        std::fs::create_dir_all(&guest_dir).unwrap();
        std::fs::create_dir_all(&rendezvous_dir).unwrap();

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
        let wsb_path = generate_wsb(&guest_dir, &rendezvous_dir, dir.path(), &mapped).unwrap();
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
}
