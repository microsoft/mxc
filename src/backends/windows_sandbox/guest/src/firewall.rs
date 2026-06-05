//! Guest firewall lockdown via `netsh`.
//!
//! After the host connections are established, we lock down the sandbox's
//! firewall so untrusted scripts have zero network access.

use std::net::IpAddr;

use anyhow::{Context, Result};
use tokio::process::Command;

/// Pre-authorize the guest agent in Windows Firewall *before* it binds its
/// listener, so Windows does not raise an interactive "Do you want to allow
/// this app?" prompt when the host first connects inbound. Without this rule
/// the prompt blocks unattended/automated runs and can intermittently stall
/// the per-exec data-stream reconnections.
///
/// The listener uses an OS-assigned (ephemeral) port that isn't known until
/// after `bind`, and the host can connect as soon as the rendezvous file is
/// written — so we authorize by **program path** rather than port to close
/// the race entirely (the rule exists before the listener does). The guest
/// runs from a space-free mapped path (`C:\sandbox-guest\...`), so the
/// `program=` token needs no special quoting.
///
/// This rule is intentionally broad and short-lived: [`lockdown`] later
/// deletes all rules (including this one) and replaces it with a tight
/// host-IP/port-scoped rule once the connections are established.
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

/// Lock down the Windows Firewall inside the sandbox so that only the
/// already-established host connections survive.
///
/// 1. Delete all existing rules.
/// 2. Allow inbound on our listen port from the host IP only.
/// 3. Allow outbound to the host IP **only on the same `listen_port` source
///    port** — i.e. response packets on the connections established to our
///    listener. Untrusted scripts opening *new* outbound connections to the
///    host (SMB, dev servers, RDP, etc.) use ephemeral source ports and are
///    blocked by the default outbound-block policy.
/// 4. Set default policy to block-all for both directions.
///
/// The previous (overly broad) rule allowed all outbound TCP to `host_ip`
/// regardless of source port, which let untrusted workloads reach arbitrary
/// host services on the same IP — defeating the stated "block all network"
/// isolation (review finding C1).
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

    // Allow outbound to host only when the source port is our listen port
    // (i.e., response packets on a host-initiated connection to our
    // listener). Without `localport=` this rule would permit any outbound
    // TCP to the host IP — letting untrusted scripts open new connections
    // to arbitrary host services. With the source-port restriction, only
    // already-accepted-by-us connections can send response packets; new
    // outbound from the script (which uses ephemeral source ports) is
    // blocked by the default block-outbound policy below.
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
