//! Rendezvous file polling.
//!
//! The guest agent writes `<ip>:<port>` to a file in a MappedFolder.
//! We poll until the file appears and contains a valid address.

use std::net::SocketAddr;
use std::path::Path;
use std::time::Duration;

use anyhow::{Context, Result};

/// Maximum time to wait for the guest agent's rendezvous file. First VM boot
/// can take several minutes on a loaded host; 360s covers worst-case cold
/// starts. Shared by every consumer that calls [`wait_for_rendezvous`]
/// (the one-shot runner and the state-aware daemon) so tuning the budget
/// for a slower CI environment happens in one place.
pub const RENDEZVOUS_TIMEOUT: Duration = Duration::from_secs(360);

/// Polling interval while waiting for the rendezvous file to appear. Shared
/// across one-shot + state-aware so the I/O cadence is uniform.
pub const RENDEZVOUS_POLL_INTERVAL: Duration = Duration::from_millis(500);

/// Maximum time to wait for the host's TCP connect to the guest agent after
/// the rendezvous file appears. Connect should be near-instant on localhost
/// (the guest agent is already serving by the time we read the rendezvous
/// file); the 30s budget tolerates a slow Hyper-V NAT bring-up window
/// without hanging the caller. Shared across one-shot + state-aware.
pub const GUEST_CONNECT_TIMEOUT: Duration = Duration::from_secs(30);

/// Poll `rendezvous_dir/rendezvous.txt` until it contains a valid `ip:port`.
///
/// Retries every `poll_interval` for up to `timeout`.
pub async fn wait_for_rendezvous(
    rendezvous_dir: &Path,
    timeout: std::time::Duration,
    poll_interval: std::time::Duration,
) -> Result<SocketAddr> {
    let file_path = rendezvous_dir.join("rendezvous.txt");
    let deadline = tokio::time::Instant::now() + timeout;

    loop {
        if tokio::time::Instant::now() >= deadline {
            anyhow::bail!(
                "timed out waiting for rendezvous file {:?} after {:?}",
                file_path,
                timeout
            );
        }

        if file_path.exists() {
            if let Ok(content) = tokio::fs::read_to_string(&file_path).await {
                let trimmed = content.trim();
                if let Ok(addr) = trimmed.parse::<SocketAddr>() {
                    eprintln!("[daemon] rendezvous: guest at {}", addr);
                    return Ok(addr);
                }
            }
        }

        tokio::time::sleep(poll_interval).await;
    }
}

/// Delete the rendezvous file so a fresh sandbox will write a new one.
pub async fn cleanup(rendezvous_dir: &Path) -> Result<()> {
    let file_path = rendezvous_dir.join("rendezvous.txt");
    if file_path.exists() {
        tokio::fs::remove_file(&file_path)
            .await
            .with_context(|| format!("delete rendezvous file {:?}", file_path))?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[tokio::test]
    async fn wait_for_rendezvous_success() {
        let dir = tempfile::tempdir().unwrap();

        // Write a valid address after a short delay.
        let dir_path = dir.path().to_path_buf();
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(50)).await;
            tokio::fs::write(dir_path.join("rendezvous.txt"), "192.168.1.100:12345")
                .await
                .unwrap();
        });

        let addr = wait_for_rendezvous(
            dir.path(),
            Duration::from_secs(5),
            Duration::from_millis(20),
        )
        .await
        .unwrap();

        assert_eq!(addr, "192.168.1.100:12345".parse().unwrap());
    }

    #[tokio::test]
    async fn wait_for_rendezvous_timeout() {
        let dir = tempfile::tempdir().unwrap();

        let result = wait_for_rendezvous(
            dir.path(),
            Duration::from_millis(100),
            Duration::from_millis(20),
        )
        .await;

        assert!(result.is_err());
    }
}
