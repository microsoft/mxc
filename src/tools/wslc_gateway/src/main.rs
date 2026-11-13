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
#[macro_use]
mod logger;
#[cfg(target_os = "linux")]
mod dns;
// Shared with the WSLC backend; the gateway doesn't link mxc_sdk.
#[cfg(target_os = "linux")]
#[allow(dead_code)]
#[path = "../../../mxc-sdk/src/backends/wslc/gateway_policy.rs"]
mod gateway_policy;
#[cfg(target_os = "linux")]
mod netlink;
#[cfg(target_os = "linux")]
mod proxy;
#[cfg(target_os = "linux")]
mod relay;

#[cfg(target_os = "linux")]
#[tokio::main(flavor = "current_thread")]
async fn main() {
    logger::init();
    let result = run().await;
    if let Err(e) = &result {
        log!("FATAL {e}");
    }
    logger::flush();
    std::process::exit(if result.is_ok() { 0 } else { 1 });
}

#[cfg(not(target_os = "linux"))]
fn main() {
    eprintln!("mxc-wslc-gateway runs only in MXC's Linux gateway image");
    std::process::exit(1);
}

/// Serves until a listener fails (an error) or the container is stopped.
#[cfg(target_os = "linux")]
async fn run() -> Result<(), String> {
    use crate::gateway_policy::{Policy, POLICY_ENV};
    use std::net::{Ipv4Addr, SocketAddrV4};
    use std::sync::Arc;
    use tokio::signal::unix::{signal, SignalKind};
    use tokio::task::JoinSet;

    let raw = std::env::var(POLICY_ENV).map_err(|_| format!("{POLICY_ENV} is not set"))?;
    let policy: Policy = serde_json::from_str(&raw).map_err(|e| format!("invalid policy: {e}"))?;
    policy
        .validate()
        .map_err(|e| format!("invalid policy: {e}"))?;
    let policy = Arc::new(policy);
    raise_fd_limit();
    let listen = |kind| signal(kind).map_err(|e| format!("install signal handler: {e}"));
    let (mut terminate, mut interrupt) = (
        listen(SignalKind::terminate())?,
        listen(SignalKind::interrupt())?,
    );
    let net = Arc::new(relay::System);
    let mut tasks = JoinSet::new();

    let proxy_address = SocketAddrV4::new(policy.workload_address, policy.proxy_port);
    let listener = relay::bind(proxy_address).await?;
    match &policy.custom_proxy {
        Some(custom) => {
            let target = relay::Target::custom_proxy(custom);
            log!("custom proxy: {proxy_address} relays to {target}");
            tasks.spawn(relay::fixed(listener, target, "custom proxy", net.clone()));
        }
        None => {
            log!("filtering proxy on {proxy_address}");
            tasks.spawn(proxy::serve(listener, policy.clone(), net.clone()));
        }
    }

    for mapping in &policy.port_mappings {
        let listener = relay::bind(SocketAddrV4::new(
            policy.egress_address,
            mapping.listen_port,
        ))
        .await?;
        let target = relay::Target::port_mapping(mapping);
        log!(
            "port mapping: {}:{} relays to {target}",
            policy.egress_address,
            mapping.listen_port
        );
        tasks.spawn(relay::fixed(listener, target, "port mapping", net.clone()));
    }

    let dns = dns::Server::bind(policy.clone()).await?;
    log!(
        "dns on {}:53 ({})",
        policy.workload_address,
        if policy.forward_dns {
            "forwarding"
        } else {
            "local names only"
        }
    );
    tasks.spawn(dns.serve());

    // Bound last on any free port, so it can't take a port the policy names.
    if let Some(hl) = &policy.host_loopback {
        let listener = relay::bind(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0)).await?;
        let port = listener
            .local_addr()
            .map_err(|e| format!("host loopback listener: {e}"))?
            .port();
        let ifindex = netlink::interface_with_address(policy.workload_address)
            .map_err(|e| format!("find the workload interface: {e}"))?;
        netlink::add_address(ifindex, hl.relay_address, hl.prefix_length)
            .map_err(|e| format!("add the relay address: {e}"))?;
        netlink::redirect_to_relay(hl.relay_address, port)
            .map_err(|e| format!("install the relay redirect: {e}"))?;
        tasks.spawn(relay::host_loopback(
            listener,
            hl.relay_address,
            net.clone(),
        ));
        log!(
            "host loopback: {} relays TCP to Windows loopback",
            hl.relay_address
        );
    }

    log!("READY");
    tokio::select! {
        finished = tasks.join_next() => match finished {
            Some(Ok(Err(e))) => Err(e),
            Some(Err(e)) => Err(format!("a listener failed: {e}")),
            Some(Ok(Ok(()))) | None => Err("a listener stopped".to_string()),
        },
        _ = terminate.recv() => Ok(()),
        _ = interrupt.recv() => Ok(()),
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
