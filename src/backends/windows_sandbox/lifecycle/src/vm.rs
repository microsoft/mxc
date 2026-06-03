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

/// Tear down any running Windows Sandbox instance.
///
/// Kills the sandbox host processes, then polls until they are gone before
/// returning. Best-effort — errors are logged but not propagated.
///
/// Only the `WindowsSandbox*` host processes are treated as liveness
/// indicators. The `vmmemWindowsSandbox` / `vmmemCmZygote` Hyper-V memory
/// processes are intentionally NOT awaited: they are SYSTEM-owned, linger
/// after the host processes exit, and are harmless residue — a subsequent
/// sandbox launch succeeds while they are still present. Polling on them
/// only wasted the full teardown timeout.
///
/// TODO: `taskkill /F /IM` kills ALL sandbox instances system-wide, not
/// just ours. If the user has a manual sandbox open, we'd kill it. Scope
/// teardown to only our process tree or track the sandbox PID at launch.
pub async fn teardown() {
    eprintln!("[daemon] tearing down sandbox");

    // Kill the sandbox UI and session processes. The `.exe` suffix is
    // REQUIRED: `taskkill /IM` matches the full image name, so omitting it
    // (e.g. `WindowsSandboxServer`) silently fails to find the process. The
    // UI client `WindowsSandbox.exe` typically exits shortly after launch,
    // so `WindowsSandboxServer.exe` + `WindowsSandboxRemoteSession.exe` are
    // the processes that actually keep the VM (and its single-instance slot)
    // alive — they must be killed by their exact image names.
    for process_name in [
        "WindowsSandbox.exe",
        "WindowsSandboxServer.exe",
        "WindowsSandboxRemoteSession.exe",
    ] {
        match Command::new("taskkill")
            .args(["/F", "/IM", process_name])
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .await
        {
            Ok(status) if !status.success() => {
                // Non-zero exit from taskkill is expected when the process
                // isn't running — not an error worth logging.
            }
            Err(err) => {
                eprintln!(
                    "[daemon] failed to run taskkill for {}: {}",
                    process_name, err
                );
            }
            _ => {}
        }
    }

    // Poll until the sandbox host processes are fully gone (up to 30s).
    // Only `WindowsSandbox*` count as live — `vmmem*` residue is harmless
    // (see `is_sandbox_vm_running`).
    let deadline =
        tokio::time::Instant::now() + std::time::Duration::from_secs(TEARDOWN_POLL_TIMEOUT_SECS);
    loop {
        let still_running = is_sandbox_vm_running().await;
        if !still_running {
            eprintln!("[daemon] all sandbox processes terminated");
            break;
        }
        if tokio::time::Instant::now() >= deadline {
            eprintln!(
                "[daemon] warning: sandbox processes still running after {}s, proceeding anyway",
                TEARDOWN_POLL_TIMEOUT_SECS
            );
            break;
        }
        tokio::time::sleep(std::time::Duration::from_secs(TEARDOWN_POLL_INTERVAL_SECS)).await;
    }

    // Additional cooldown for Hyper-V backend / VHDX release.
    tokio::time::sleep(std::time::Duration::from_secs(TEARDOWN_COOLDOWN_SECS)).await;
}

/// Check whether a Windows Sandbox VM is currently running.
///
/// Only the `WindowsSandbox*` host processes are considered. The
/// `vmmem*` Hyper-V memory processes are deliberately excluded: they
/// linger as harmless residue after the host processes exit and do not
/// block a fresh sandbox launch, so treating them as "running" would
/// cause teardown to wait out its full timeout for nothing.
pub async fn is_sandbox_vm_running() -> bool {
    // Use PowerShell to check for the sandbox host processes.
    let output = Command::new("powershell")
        .args([
            "-NoProfile",
            "-Command",
            "Get-Process -Name 'WindowsSandbox*' -ErrorAction SilentlyContinue | Measure-Object | Select-Object -ExpandProperty Count",
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

/// Enumerate the currently-running Windows Sandbox host processes, returning
/// each one's identity (PID paired with creation time).
///
/// Only the `WindowsSandbox*` host processes are reported, matching
/// [`is_sandbox_vm_running`]; `vmmem*` residue is excluded. The returned
/// identities form the *positive ownership proof* recorded in the daemon record
/// and matched against on a later daemon's startup reconcile.
///
/// Returns `Err` if the enumeration itself could not be performed (the
/// PowerShell probe failed to run or exited non-zero). Callers that gate a
/// destructive decision on the result MUST treat an `Err` as "unknown" rather
/// than "no VM", so they fail safe (refuse) instead of proceeding blind.
pub async fn enumerate_sandbox_vm_processes() -> Result<Vec<crate::control_plane::VmProcId>> {
    let out = Command::new("powershell")
        .args([
            "-NoProfile",
            "-Command",
            "Get-Process -Name 'WindowsSandbox*' -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Id",
        ])
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null())
        .output()
        .await
        .context("run WindowsSandbox process enumeration")?;

    if !out.status.success() {
        anyhow::bail!(
            "WindowsSandbox process enumeration exited with {}",
            out.status
        );
    }
    let text = String::from_utf8_lossy(&out.stdout);
    let mut procs = Vec::new();
    for line in text.lines() {
        let Ok(pid) = line.trim().parse::<u32>() else {
            continue;
        };
        // Pair each PID with its creation time. If the process exited between
        // enumeration and this query, skip it — it is no longer part of a live
        // VM and contributes nothing to an ownership match.
        if let Some(creation_time) = crate::control_plane::process_creation_time(pid) {
            procs.push(crate::control_plane::VmProcId { pid, creation_time });
        }
    }
    Ok(procs)
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
