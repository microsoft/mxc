//! Windows Sandbox VM lifecycle management.
//!
//! Generates .wsb configuration files and launches/tears down
//! `WindowsSandbox.exe`.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use tokio::process::Command;

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
/// The .wsb maps three folders into the sandbox:
///   - `agent_dir` (read-only)       → `C:\sandbox-agent`
///   - `rendezvous_dir` (read-write) → `C:\sandbox-rendezvous`
///   - `python_dir` (read-only)      → `C:\sandbox-python`
///
/// The LogonCommand runs a bootstrap script that adds Python to PATH
/// then starts the guest agent.
pub fn generate_wsb(
    agent_dir: &Path,
    rendezvous_dir: &Path,
    python_dir: &Path,
    output_dir: &Path,
) -> Result<PathBuf> {
    // Write the bootstrap script into the rendezvous dir (read-write inside
    // the sandbox) so it can be executed by the LogonCommand.
    let bootstrap_content = r#"@echo off
set "LOG=C:\sandbox-rendezvous\bootstrap.log"

echo [bootstrap] Starting at %date% %time% >> "%LOG%" 2>&1

echo [bootstrap] Adding mapped Python to PATH... >> "%LOG%" 2>&1
set "PATH=C:\sandbox-python;C:\sandbox-python\Scripts;%PATH%"

echo [bootstrap] Disabling Python bytecode cache (read-only mapped dir)... >> "%LOG%" 2>&1
set "PYTHONDONTWRITEBYTECODE=1"
set "PYTHONNOUSERSITE=1"

echo [bootstrap] PATH=%PATH% >> "%LOG%" 2>&1
where python >> "%LOG%" 2>&1
python --version >> "%LOG%" 2>&1

echo [bootstrap] Starting sandbox agent... >> "%LOG%" 2>&1
C:\sandbox-agent\wxc-sandbox-agent.exe >> "%LOG%" 2>&1
echo [bootstrap] Agent exited with code %ERRORLEVEL% >> "%LOG%" 2>&1
"#;
    let bootstrap_path = rendezvous_dir.join("bootstrap.cmd");
    std::fs::write(&bootstrap_path, bootstrap_content)
        .with_context(|| format!("write bootstrap script {:?}", bootstrap_path))?;

    let wsb_content = format!(
        r#"<Configuration>
  <MappedFolders>
    <MappedFolder>
      <HostFolder>{agent}</HostFolder>
      <SandboxFolder>C:\sandbox-agent</SandboxFolder>
      <ReadOnly>true</ReadOnly>
    </MappedFolder>
    <MappedFolder>
      <HostFolder>{rendezvous}</HostFolder>
      <SandboxFolder>C:\sandbox-rendezvous</SandboxFolder>
      <ReadOnly>false</ReadOnly>
    </MappedFolder>
    <MappedFolder>
      <HostFolder>{python}</HostFolder>
      <SandboxFolder>C:\sandbox-python</SandboxFolder>
      <ReadOnly>true</ReadOnly>
    </MappedFolder>
  </MappedFolders>
  <LogonCommand>
    <Command>C:\sandbox-rendezvous\bootstrap.cmd</Command>
  </LogonCommand>
  <vGPU>Disable</vGPU>
  <Networking>Enable</Networking>
</Configuration>"#,
        agent = agent_dir.display(),
        rendezvous = rendezvous_dir.display(),
        python = python_dir.display(),
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
/// Kills all sandbox and related Hyper-V processes, then polls until they
/// are fully gone before returning. Best-effort — errors are logged but
/// not propagated.
pub async fn teardown() {
    eprintln!("[daemon] tearing down sandbox");

    // Kill the sandbox UI and session processes.
    for process_name in [
        "WindowsSandbox.exe",
        "WindowsSandboxServer",
        "WindowsSandboxRemoteSession",
    ] {
        let _ = Command::new("taskkill")
            .args(["/F", "/IM", process_name])
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .await;
    }

    // Poll until sandbox-related processes are fully gone (up to 30s).
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(30);
    loop {
        let still_running = is_any_sandbox_process_running().await;
        if !still_running {
            eprintln!("[daemon] all sandbox processes terminated");
            break;
        }
        if tokio::time::Instant::now() >= deadline {
            eprintln!(
                "[daemon] warning: sandbox processes still running after 30s, proceeding anyway"
            );
            break;
        }
        tokio::time::sleep(std::time::Duration::from_secs(2)).await;
    }

    // Additional cooldown for Hyper-V backend / VHDX release.
    tokio::time::sleep(std::time::Duration::from_secs(5)).await;
}

/// Check if any sandbox-related processes are still running.
async fn is_any_sandbox_process_running() -> bool {
    // Use PowerShell to check for sandbox and its backing VM processes.
    let output = Command::new("powershell")
        .args([
            "-NoProfile",
            "-Command",
            "Get-Process -Name 'WindowsSandbox*','vmmemWindowsSandbox' -ErrorAction SilentlyContinue | Measure-Object | Select-Object -ExpandProperty Count",
        ])
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null())
        .output()
        .await;

    match output {
        Ok(out) => {
            let count_str = String::from_utf8_lossy(&out.stdout).trim().to_string();
            count_str.parse::<u32>().unwrap_or(0) > 0
        }
        Err(_) => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generate_wsb_creates_file() {
        let dir = tempfile::tempdir().unwrap();
        let agent_dir = dir.path().join("agent");
        let rendezvous_dir = dir.path().join("rendezvous");
        let python_dir = dir.path().join("python");
        std::fs::create_dir_all(&agent_dir).unwrap();
        std::fs::create_dir_all(&rendezvous_dir).unwrap();
        std::fs::create_dir_all(&python_dir).unwrap();

        let wsb_path = generate_wsb(&agent_dir, &rendezvous_dir, &python_dir, dir.path()).unwrap();
        assert!(wsb_path.exists());

        let content = std::fs::read_to_string(&wsb_path).unwrap();
        assert!(content.contains("<Configuration>"));
        assert!(content.contains("bootstrap.cmd"));
        assert!(content.contains("sandbox-python"));
        assert!(content.contains(&agent_dir.display().to_string()));
        assert!(content.contains(&rendezvous_dir.display().to_string()));
        assert!(content.contains(&python_dir.display().to_string()));

        // Verify bootstrap script was created in the rendezvous dir.
        let bootstrap = rendezvous_dir.join("bootstrap.cmd");
        assert!(bootstrap.exists());
        let bootstrap_content = std::fs::read_to_string(&bootstrap).unwrap();
        assert!(bootstrap_content.contains("sandbox-python"));
        assert!(bootstrap_content.contains("wxc-sandbox-agent.exe"));
    }

    #[test]
    fn find_host_python_returns_valid_dir() {
        // This test only passes on machines with Python installed.
        if let Ok(dir) = find_host_python() {
            assert!(dir.join("python.exe").exists());
        }
    }
}
