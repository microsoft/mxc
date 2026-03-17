//! Guest firewall lockdown via `netsh`.
//!
//! After the host connections are established, we lock down the sandbox's
//! firewall so untrusted scripts have zero network access.

use std::net::IpAddr;

use anyhow::{Context, Result};
use tokio::process::Command;

/// Lock down the Windows Firewall inside the sandbox so that only the
/// already-established host connections survive.
///
/// 1. Delete all existing rules.
/// 2. Allow inbound on our listen port from the host IP.
/// 3. Allow outbound to the host IP.
/// 4. Set default policy to block-all for both directions.
pub async fn lockdown(host_ip: IpAddr, listen_port: u16) -> Result<()> {
    let host = host_ip.to_string();
    let port = listen_port.to_string();

    // Delete all existing firewall rules.
    run_netsh(&["advfirewall", "firewall", "delete", "rule", "name=all"])
        .await
        .context("delete existing rules")?;

    // Allow inbound from host to our listen port.
    run_netsh(&[
        "advfirewall",
        "firewall",
        "add",
        "rule",
        "name=WxcAgentIn",
        "dir=in",
        "action=allow",
        "protocol=TCP",
        &format!("localport={}", port),
        &format!("remoteip={}", host),
    ])
    .await
    .context("add inbound allow rule")?;

    // Allow outbound to host.
    run_netsh(&[
        "advfirewall",
        "firewall",
        "add",
        "rule",
        "name=WxcAgentOut",
        "dir=out",
        "action=allow",
        "protocol=TCP",
        &format!("remoteip={}", host),
    ])
    .await
    .context("add outbound allow rule")?;

    // Block everything else.
    run_netsh(&[
        "advfirewall",
        "set",
        "allprofiles",
        "firewallpolicy",
        "blockinbound,blockoutbound",
    ])
    .await
    .context("set default block policy")?;

    Ok(())
}

/// Run a `netsh` command, returning an error if it exits non-zero.
async fn run_netsh(args: &[&str]) -> Result<()> {
    let status = Command::new("netsh")
        .args(args)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::piped())
        .status()
        .await
        .with_context(|| format!("spawn netsh {:?}", args))?;

    if !status.success() {
        anyhow::bail!(
            "netsh {:?} exited with {}",
            args,
            status.code().unwrap_or(-1)
        );
    }
    Ok(())
}
