//! Guest firewall lockdown via `netsh`.
//!
//! After the host connections are established, we lock down the sandbox's
//! firewall so untrusted scripts have zero network access.

use std::net::IpAddr;

use anyhow::{Context, Result};
use tokio::process::Command;

/// Pre-authorise the agent by program path before bind so an inbound firewall
/// prompt cannot block unattended runs. [`lockdown`] replaces this temporary
/// rule after the host connects.
pub async fn pre_authorize() -> Result<()> {
    let exe = std::env::current_exe().context("resolve guest executable path")?;
    let program = exe.to_string_lossy();

    run_netsh(&[
        "advfirewall",
        "firewall",
        "add",
        "rule",
        "name=WxcAgentPreAuth",
        "dir=in",
        "action=allow",
        "protocol=TCP",
        "profile=any",
        "enable=yes",
        &format!("program={}", program),
    ])
    .await
    .context("add pre-authorization inbound allow rule")?;

    Ok(())
}

/// Restrict traffic to the established host connection and block everything
/// else. The outbound rule uses the listener's source port so scripts cannot
/// open new connections to arbitrary host services.
pub async fn lockdown(host_ip: IpAddr, listen_port: u16) -> Result<()> {
    let host = host_ip.to_string();
    let port = listen_port.to_string();

    run_netsh(&["advfirewall", "firewall", "delete", "rule", "name=all"])
        .await
        .context("delete existing rules")?;

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

    run_netsh(&[
        "advfirewall",
        "firewall",
        "add",
        "rule",
        "name=WxcAgentOut",
        "dir=out",
        "action=allow",
        "protocol=TCP",
        &format!("localport={}", port),
        &format!("remoteip={}", host),
    ])
    .await
    .context("add outbound allow rule")?;

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
