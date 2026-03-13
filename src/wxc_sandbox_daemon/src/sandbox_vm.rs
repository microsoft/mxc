//! Windows Sandbox VM lifecycle management.
//!
//! Generates .wsb configuration files and launches/tears down
//! `WindowsSandbox.exe`.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use tokio::process::Command;

/// Generate a .wsb configuration file in `output_dir`.
///
/// The .wsb maps two folders into the sandbox:
///   - `agent_dir` (read-only)  → `C:\sandbox-agent`
///   - `rendezvous_dir` (read-write) → `C:\sandbox-rendezvous`
///
/// The LogonCommand launches the guest agent binary.
pub fn generate_wsb(
    agent_dir: &Path,
    rendezvous_dir: &Path,
    output_dir: &Path,
) -> Result<PathBuf> {
    let wsb_content = format!(
        r#"<Configuration>
  <MappedFolders>
    <MappedFolder>
      <HostFolder>{}</HostFolder>
      <SandboxFolder>C:\sandbox-agent</SandboxFolder>
      <ReadOnly>true</ReadOnly>
    </MappedFolder>
    <MappedFolder>
      <HostFolder>{}</HostFolder>
      <SandboxFolder>C:\sandbox-rendezvous</SandboxFolder>
      <ReadOnly>false</ReadOnly>
    </MappedFolder>
  </MappedFolders>
  <LogonCommand>
    <Command>C:\sandbox-agent\wxc-sandbox-agent.exe</Command>
  </LogonCommand>
  <Networking>Enable</Networking>
</Configuration>"#,
        agent_dir.display(),
        rendezvous_dir.display(),
    );

    let wsb_path = output_dir.join("wxc-sandbox.wsb");
    std::fs::write(&wsb_path, wsb_content)
        .with_context(|| format!("write .wsb file {:?}", wsb_path))?;

    Ok(wsb_path)
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

/// Tear down any running Windows Sandbox instance.
///
/// Uses `taskkill` to terminate `WindowsSandbox.exe` and the sandbox VM
/// processes.  Best-effort — errors are logged but not propagated.
pub async fn teardown() {
    eprintln!("[daemon] tearing down sandbox");

    // WindowsSandbox.exe hosts the UI; killing it closes the sandbox.
    let _ = Command::new("taskkill")
        .args(["/F", "/IM", "WindowsSandbox.exe"])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .await;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generate_wsb_creates_file() {
        let dir = tempfile::tempdir().unwrap();
        let agent_dir = dir.path().join("agent");
        let rendezvous_dir = dir.path().join("rendezvous");
        std::fs::create_dir_all(&agent_dir).unwrap();
        std::fs::create_dir_all(&rendezvous_dir).unwrap();

        let wsb_path = generate_wsb(&agent_dir, &rendezvous_dir, dir.path()).unwrap();
        assert!(wsb_path.exists());

        let content = std::fs::read_to_string(&wsb_path).unwrap();
        assert!(content.contains("<Configuration>"));
        assert!(content.contains("wxc-sandbox-agent.exe"));
        assert!(content.contains(&agent_dir.display().to_string()));
        assert!(content.contains(&rendezvous_dir.display().to_string()));
    }
}
