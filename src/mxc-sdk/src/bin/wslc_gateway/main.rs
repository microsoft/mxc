// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! WSLC egress gateway: the only process in MXC's gateway image.
//!
//! It runs beside one proxied workload and is that workload's only network
//! path. It reads its policy from `MXC_GATEWAY_POLICY` once at start and
//! serves, on the workload's network, a CIDR and port filtering HTTP proxy (or
//! a relay to a custom proxy) and DNS. It optionally relays host loopback and
//! port mappings. It runs until the container stops; if any part fails, it
//! exits and the workload loses network access.

#[cfg(target_os = "linux")]
mod dns;
#[cfg(target_os = "linux")]
mod netlink;
#[cfg(target_os = "linux")]
mod proxy;
#[cfg(target_os = "linux")]
mod relay;

#[cfg(target_os = "linux")]
#[tokio::main(flavor = "current_thread")]
async fn main() {
    if let Err(e) = run().await {
        println!("FATAL {e}");
        std::process::exit(1);
    }
}

#[cfg(not(target_os = "linux"))]
fn main() {
    eprintln!("mxc-wslc-gateway runs only in MXC's Linux gateway image");
    std::process::exit(1);
}

#[cfg(target_os = "linux")]
async fn run() -> Result<(), String> {
    use mxc_sdk::wslc_gateway_policy::{Policy, POLICY_ENV};
    use std::net::{Ipv4Addr, SocketAddrV4};
    use std::sync::Arc;
    use tokio::task::JoinSet;

    let raw = std::env::var(POLICY_ENV).map_err(|_| format!("{POLICY_ENV} is not set"))?;
    let policy: Arc<Policy> =
        Arc::new(serde_json::from_str(&raw).map_err(|e| format!("invalid policy: {e}"))?);
    raise_fd_limit();
    let mut tasks = JoinSet::new();

    // Host loopback setup comes first, so a failure (such as missing
    // NET_ADMIN) leaves nothing listening.
    if let Some(hl) = &policy.host_loopback {
        let ifindex = netlink::interface_with_address(policy.workload_address)
            .map_err(|e| format!("find the workload interface: {e}"))?;
        netlink::add_address(ifindex, hl.relay_address, hl.prefix_length)
            .map_err(|e| format!("add the relay address: {e}"))?;
        netlink::redirect_to_relay(hl.relay_address, relay::HOST_LOOPBACK_PORT)
            .map_err(|e| format!("install the relay redirect: {e}"))?;
        let listener = relay::bind(SocketAddrV4::new(
            Ipv4Addr::UNSPECIFIED,
            relay::HOST_LOOPBACK_PORT,
        ))
        .await?;
        tasks.spawn(relay::host_loopback(listener, hl.relay_address));
        println!(
            "host loopback: {} relays TCP to Windows loopback",
            hl.relay_address
        );
    }

    let proxy_address = SocketAddrV4::new(policy.workload_address, policy.proxy_port);
    let listener = relay::bind(proxy_address).await?;
    match &policy.custom_proxy {
        Some(custom) => {
            let target = relay::Target::custom_proxy(custom);
            println!("custom proxy: {proxy_address} relays to {target}");
            tasks.spawn(relay::fixed(listener, target, "custom proxy"));
        }
        None => {
            println!("filtering proxy on {proxy_address}");
            tasks.spawn(proxy::serve(listener, policy.clone()));
        }
    }

    for mapping in &policy.port_mappings {
        let listener = relay::bind(SocketAddrV4::new(
            policy.egress_address,
            mapping.listen_port,
        ))
        .await?;
        let target = relay::Target::port_mapping(mapping);
        println!(
            "port mapping: {}:{} relays to {target}",
            policy.egress_address, mapping.listen_port
        );
        tasks.spawn(relay::fixed(listener, target, "port mapping"));
    }

    let dns = dns::Server::bind(policy.clone()).await?;
    println!(
        "dns on {}:53 ({})",
        policy.workload_address,
        if policy.forward_dns {
            "forwarding"
        } else {
            "local names only"
        }
    );
    tasks.spawn(dns.serve());
    println!("READY");
    match tasks.join_next().await {
        Some(Ok(Err(e))) => Err(e),
        Some(Err(e)) => Err(format!("a listener failed: {e}")),
        Some(Ok(Ok(()))) | None => Err("a listener stopped".to_string()),
    }
}

/// Every proxied connection holds two descriptors, so use the hard limit.
#[cfg(target_os = "linux")]
fn raise_fd_limit() {
    let mut limit = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    // SAFETY: `limit` is a valid rlimit for both calls.
    unsafe {
        if libc::getrlimit(libc::RLIMIT_NOFILE, &mut limit) == 0 && limit.rlim_cur < limit.rlim_max
        {
            limit.rlim_cur = limit.rlim_max;
            libc::setrlimit(libc::RLIMIT_NOFILE, &limit);
        }
    }
}
