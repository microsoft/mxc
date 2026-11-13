// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Filtering HTTP proxy: `CONNECT` and absolute-form `http://` requests, one
//! request per connection, allowed or denied by the egress rules.

use crate::gateway_policy::{Action, Policy, HOST_LOOPBACK_NAME};
use crate::relay::{accept_loop, splice, Network};
use std::io;
use std::net::Ipv4Addr;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

const MAX_HEAD: usize = 16 * 1024;
/// Whole request head, so a client can't hold a slot by trickling bytes.
const HEAD_TIMEOUT: Duration = Duration::from_secs(10);
/// Lookup and every connection attempt together.
const UPSTREAM_TIMEOUT: Duration = Duration::from_secs(30);

pub async fn serve<N: Network>(
    listener: TcpListener,
    policy: Arc<Policy>,
    net: Arc<N>,
) -> Result<(), String> {
    accept_loop(listener, "proxy", move |client, _| {
        let (policy, net) = (policy.clone(), net.clone());
        async move {
            if let Err(e) = handle(client, &policy, &*net).await {
                log!("PROXY error: {e}");
            }
        }
    })
    .await
}

#[derive(Debug, PartialEq)]
struct Request {
    connect: bool,
    host: String,
    port: u16,
    /// Request head to send upstream; empty for `CONNECT`.
    head: Vec<u8>,
}

async fn handle<N: Network>(mut client: TcpStream, policy: &Policy, net: &N) -> io::Result<()> {
    let Some((request, rest)) = read_request(&mut client).await? else {
        return respond(&mut client, 400, "bad request").await;
    };
    let opened = tokio::time::timeout(UPSTREAM_TIMEOUT, open_upstream(&request, policy, net))
        .await
        .unwrap_or_else(|_| Err((504, "upstream timed out".to_string())));
    let mut upstream = match opened {
        Ok(s) => s,
        Err((code, message)) => return respond(&mut client, code, &message).await,
    };
    if request.connect {
        client
            .write_all(b"HTTP/1.1 200 Connection established\r\n\r\n")
            .await?;
    } else {
        upstream.write_all(&request.head).await?;
    }
    upstream.write_all(&rest).await?;
    splice(client, upstream).await;
    Ok(())
}

/// Connects to the request's target if the policy allows it, or returns the
/// status and message to refuse it with.
async fn open_upstream<N: Network>(
    request: &Request,
    policy: &Policy,
    net: &N,
) -> Result<TcpStream, (u16, String)> {
    let (host, port) = (request.host.as_str(), request.port);
    let target = format!("{host}:{port}");
    let is_host_loopback = host.eq_ignore_ascii_case(HOST_LOOPBACK_NAME)
        || policy
            .host_loopback
            .is_some_and(|h| host == h.relay_address.to_string());
    if is_host_loopback {
        if policy.host_loopback.is_none() {
            log!("DENY  {target:?} (host loopback denied)");
            return Err((403, "host loopback denied".to_string()));
        }
        return net
            .connect(HOST_LOOPBACK_NAME, port)
            .await
            .map_err(|e| (502, format!("connect failed: {e}")));
    }

    let candidates = match host.parse::<Ipv4Addr>() {
        Ok(ip) => vec![ip],
        // A lookup reaches the upstream resolver, so it needs the same
        // permission as forwarded DNS.
        Err(_) if !policy.forward_dns => {
            log!("DENY  {target:?} (name lookups denied)");
            return Err((403, "name lookups are denied by policy".to_string()));
        }
        Err(_) => net.lookup(host, port).await,
    };
    let mut refusal = None;
    for ip in candidates {
        let (action, why) = policy.egress.check(ip, port);
        if action == Action::Deny {
            log!("DENY  {target:?} -> {ip} ({why})");
            refusal.get_or_insert((403, format!("{ip}:{port} denied by {why}")));
            continue;
        }
        // Connect to the checked address rather than resolving the name again.
        match net.connect(&ip.to_string(), port).await {
            Ok(upstream) => return Ok(upstream),
            Err(e) => refusal = Some((502, format!("connect to {ip}:{port} failed: {e}"))),
        }
    }
    Err(refusal.unwrap_or_else(|| (502, "name did not resolve".to_string())))
}

/// Reads up to the end of the request head. Returns the request and any bytes
/// read past the head.
async fn read_request(
    client: &mut (impl AsyncRead + Unpin),
) -> io::Result<Option<(Request, Vec<u8>)>> {
    tokio::time::timeout(HEAD_TIMEOUT, read_head(client))
        .await
        .unwrap_or_else(|_| Err(io::ErrorKind::TimedOut.into()))
}

async fn read_head(
    client: &mut (impl AsyncRead + Unpin),
) -> io::Result<Option<(Request, Vec<u8>)>> {
    let mut buf = Vec::new();
    let mut chunk = [0u8; 4096];
    let end = loop {
        if let Some(i) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            break i + 4;
        }
        if buf.len() > MAX_HEAD {
            return Ok(None);
        }
        let n = client.read(&mut chunk).await?;
        if n == 0 {
            return Ok(None);
        }
        buf.extend_from_slice(&chunk[..n]);
    };
    Ok(parse_head(&buf[..end]).map(|r| (r, buf[end..].to_vec())))
}

/// Header values may hold non-UTF-8 bytes, so header lines are forwarded as is.
fn parse_head(head: &[u8]) -> Option<Request> {
    let mut lines = head
        .split(|&b| b == b'\n')
        .map(|l| l.strip_suffix(b"\r").unwrap_or(l));
    let mut parts = std::str::from_utf8(lines.next()?).ok()?.split(' ');
    let (method, target, version) = (parts.next()?, parts.next()?, parts.next()?);

    if method.eq_ignore_ascii_case("CONNECT") {
        let (host, port) = split_host_port(target, 443)?;
        return Some(Request {
            connect: true,
            host,
            port,
            head: Vec::new(),
        });
    }

    let (scheme, after) = target.split_at_checked(7)?;
    if !scheme.eq_ignore_ascii_case("http://") {
        return None;
    }
    let (authority, path) = after.split_at(after.find(['/', '?']).unwrap_or(after.len()));
    let (host, port) = split_host_port(authority, 80)?;
    let path = match path.chars().next() {
        None => "/".to_string(),
        Some('?') => format!("/{path}"),
        Some(_) => path.to_string(),
    };
    // The upstream sees the checked host, not whatever Host the client sent.
    let host_header = if port == 80 {
        host.clone()
    } else {
        format!("{host}:{port}")
    };
    // One request per connection, so a reused connection can't reach a host
    // that wasn't checked.
    let mut out = format!("{method} {path} {version}\r\nHost: {host_header}\r\n").into_bytes();
    for line in lines.filter(|l| !l.is_empty()) {
        let name = line
            .split(|&b| b == b':')
            .next()
            .unwrap_or_default()
            .trim_ascii()
            .to_ascii_lowercase();
        let dropped = name == b"host"
            || name.starts_with(b"proxy-")
            || name == b"connection"
            || name == b"keep-alive";
        if !dropped {
            out.extend_from_slice(line);
            out.extend_from_slice(b"\r\n");
        }
    }
    out.extend_from_slice(b"Connection: close\r\n\r\n");
    Some(Request {
        connect: false,
        host,
        port,
        head: out,
    })
}

/// IPv6 literals and userinfo are rejected. A trailing root dot is dropped.
fn split_host_port(s: &str, default_port: u16) -> Option<(String, u16)> {
    if s.starts_with('[') || s.contains('@') {
        return None;
    }
    let (host, port) = match s.rsplit_once(':') {
        Some((h, p)) => (h, p.parse().ok()?),
        None => (s, default_port),
    };
    let host = host.strip_suffix('.').unwrap_or(host);
    (!host.is_empty()).then(|| (host.to_string(), port))
}

async fn respond(
    client: &mut (impl AsyncWrite + Unpin),
    code: u16,
    message: &str,
) -> io::Result<()> {
    let reason = match code {
        400 => "Bad Request",
        403 => "Forbidden",
        504 => "Gateway Timeout",
        _ => "Bad Gateway",
    };
    let body = format!("mxc-gateway: {message}\n");
    let response = format!(
        "HTTP/1.1 {code} {reason}\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    client.write_all(response.as_bytes()).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::gateway_policy::{Egress, HostLoopback, Rule, Target};
    use crate::relay::fake::{upstream, Fake};
    use std::net::SocketAddr;

    const ESTABLISHED: &str = "HTTP/1.1 200 Connection established\r\n\r\n";

    fn rule(cidr: &str) -> Rule {
        Rule {
            to: vec![Target {
                cidr: cidr.parse().unwrap(),
                except: vec![],
            }],
            ports: None,
        }
    }

    fn policy(forward_dns: bool, host_loopback: bool) -> Policy {
        Policy {
            workload_address: Ipv4Addr::new(10, 231, 1, 2),
            egress_address: Ipv4Addr::new(10, 231, 2, 2),
            proxy_port: 3128,
            forward_dns,
            egress: Egress {
                default: Action::Deny,
                allow: vec![rule("30.0.0.0/8")],
                deny: vec![rule("30.1.0.0/16")],
            },
            host_loopback: host_loopback.then_some(HostLoopback {
                relay_address: Ipv4Addr::new(10, 231, 1, 3),
                prefix_length: 24,
            }),
            custom_proxy: None,
            port_mappings: vec![],
        }
    }

    async fn start(policy: Policy, net: Fake) -> (SocketAddr, Arc<Fake>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let net = Arc::new(net);
        tokio::spawn(serve(listener, Arc::new(policy), net.clone()));
        (address, net)
    }

    async fn exchange(address: SocketAddr, request: &str) -> String {
        let mut client = TcpStream::connect(address).await.unwrap();
        client.write_all(request.as_bytes()).await.unwrap();
        client.shutdown().await.unwrap();
        let mut response = String::new();
        client.read_to_string(&mut response).await.unwrap();
        response
    }

    fn dialed(net: &Fake) -> Vec<String> {
        net.dialed.lock().unwrap().clone()
    }

    #[tokio::test]
    async fn allowed_connects_relay_bytes_after_the_head() {
        let (windows, received) = upstream().await;
        let mut net = Fake::default();
        net.routes.insert("30.0.0.1:443".into(), windows);
        let (address, net) = start(policy(false, false), net).await;
        let response = exchange(address, "CONNECT 30.0.0.1:443 HTTP/1.1\r\n\r\nhello").await;
        assert_eq!(response, format!("{ESTABLISHED}reply"));
        assert_eq!(received.await.unwrap(), b"hello");
        assert_eq!(dialed(&net), ["30.0.0.1:443"]);
    }

    #[tokio::test]
    async fn denied_addresses_are_never_dialed() {
        let (address, net) = start(policy(true, false), Fake::default()).await;
        for (target, why) in [
            ("127.0.0.1", "reserved range"),
            ("30.1.0.1", "deny rule"),
            ("40.0.0.1", "default"),
        ] {
            let response =
                exchange(address, &format!("CONNECT {target}:443 HTTP/1.1\r\n\r\n")).await;
            assert!(response.starts_with("HTTP/1.1 403 "), "{response}");
            assert!(response.contains(why), "{response}");
        }
        assert!(dialed(&net).is_empty());
    }

    #[tokio::test]
    async fn http_requests_reach_the_checked_host_with_its_host_header() {
        let (server, received) = upstream().await;
        let mut net = Fake::default();
        net.names
            .insert("Example.COM".into(), vec![Ipv4Addr::new(30, 0, 0, 1)]);
        net.routes.insert("30.0.0.1:8080".into(), server);
        let (address, _) = start(policy(true, false), net).await;
        let response = exchange(
            address,
            "POST HTTP://Example.COM.:8080?q=1 HTTP/1.1\r\nHost: evil.test\r\n\
             Content-Length: 4\r\n\r\nbody",
        )
        .await;
        assert_eq!(response, "reply");
        assert_eq!(
            String::from_utf8(received.await.unwrap()).unwrap(),
            "POST /?q=1 HTTP/1.1\r\nHost: Example.COM:8080\r\nContent-Length: 4\r\n\
             Connection: close\r\n\r\nbody"
        );
    }

    #[tokio::test]
    async fn every_address_of_a_name_is_checked_and_tried_in_order() {
        let (server, _) = upstream().await;
        let ip = |last| Ipv4Addr::new(30, 0, 0, last);
        let mut net = Fake::default();
        net.names.insert(
            "multi".into(),
            vec![Ipv4Addr::new(30, 1, 0, 1), ip(1), ip(2)],
        );
        net.names
            .insert("denied".into(), vec![Ipv4Addr::new(30, 1, 0, 1)]);
        net.names
            .insert("down".into(), vec![Ipv4Addr::new(30, 1, 0, 1), ip(1)]);
        net.routes.insert("30.0.0.2:443".into(), server);
        let (address, net) = start(policy(true, false), net).await;

        let response = exchange(address, "CONNECT multi:443 HTTP/1.1\r\n\r\n").await;
        assert_eq!(response, format!("{ESTABLISHED}reply"));
        assert_eq!(dialed(&net), ["30.0.0.1:443", "30.0.0.2:443"]);

        for (name, status) in [("denied", "403"), ("down", "502"), ("missing", "502")] {
            let response = exchange(address, &format!("CONNECT {name}:443 HTTP/1.1\r\n\r\n")).await;
            assert!(
                response.starts_with(&format!("HTTP/1.1 {status} ")),
                "{name}: {response}"
            );
        }
    }

    #[tokio::test]
    async fn host_loopback_is_relayed_without_lookups_only_when_allowed() {
        for target in ["host.wslc.internal.:5432", "10.231.1.3:5432"] {
            let (windows, _) = upstream().await;
            let mut net = Fake::default();
            net.routes
                .insert(format!("{HOST_LOOPBACK_NAME}:5432"), windows);
            let (address, net) = start(policy(false, true), net).await;
            let response = exchange(address, &format!("CONNECT {target} HTTP/1.1\r\n\r\n")).await;
            assert_eq!(response, format!("{ESTABLISHED}reply"), "{target}");
            assert!(net.lookups.lock().unwrap().is_empty());
        }

        let (address, net) = start(policy(true, false), Fake::default()).await;
        let response = exchange(address, "CONNECT HOST.wslc.internal:5432 HTTP/1.1\r\n\r\n").await;
        assert!(response.starts_with("HTTP/1.1 403 "), "{response}");
        assert!(dialed(&net).is_empty());
    }

    #[tokio::test]
    async fn names_are_not_looked_up_unless_dns_is_forwarded() {
        let (address, net) = start(policy(false, false), Fake::default()).await;
        let response = exchange(address, "CONNECT localhost:443 HTTP/1.1\r\n\r\n").await;
        assert!(response.starts_with("HTTP/1.1 403 "), "{response}");
        assert!(response.contains("name lookups are denied"), "{response}");
        assert!(net.lookups.lock().unwrap().is_empty());
    }

    #[tokio::test(start_paused = true)]
    async fn a_trickled_head_times_out() {
        let (mut server, mut client) = tokio::io::duplex(64);
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(Duration::from_secs(1)).await;
                if client.write_all(b"a").await.is_err() {
                    break;
                }
            }
        });
        let result = tokio::time::timeout(2 * HEAD_TIMEOUT, read_request(&mut server))
            .await
            .expect("the head deadline covers the whole head");
        assert_eq!(result.unwrap_err().kind(), io::ErrorKind::TimedOut);
    }

    #[test]
    fn connect_requests_name_the_target_and_default_to_port_443() {
        let r =
            parse_head(b"CONNECT example.com.:8443 HTTP/1.1\r\nHost: example.com\r\n\r\n").unwrap();
        assert_eq!(
            (r.connect, r.host.as_str(), r.port),
            (true, "example.com", 8443)
        );
        assert!(r.head.is_empty());
        assert_eq!(
            parse_head(b"CONNECT example.com HTTP/1.1\r\n\r\n")
                .unwrap()
                .port,
            443
        );
    }

    #[test]
    fn http_requests_are_rewritten_for_one_request_per_connection() {
        let r = parse_head(
            b"GET http://10.1.2.3:8080/a?b HTTP/1.1\r\nHost: 10.1.2.3\r\nProxy-Authorization: x\r\n\
              Connection: keep-alive\r\nKeep-Alive: 5\r\nX-Label: caf\xE9\r\nAccept: */*\r\n\r\n",
        )
        .unwrap();
        assert_eq!(
            (r.connect, r.host.as_str(), r.port),
            (false, "10.1.2.3", 8080)
        );
        assert_eq!(
            r.head,
            b"GET /a?b HTTP/1.1\r\nHost: 10.1.2.3:8080\r\nX-Label: caf\xE9\r\nAccept: */*\r\n\
              Connection: close\r\n\r\n"
        );
        // A bare LF ends the line, so it can't smuggle a Host header upstream.
        let r =
            parse_head(b"GET http://a.example/ HTTP/1.1\r\nX: y\nHost: b.example\r\n\r\n").unwrap();
        assert_eq!(
            r.head,
            b"GET / HTTP/1.1\r\nHost: a.example\r\nX: y\r\nConnection: close\r\n\r\n"
        );
        for (target, path) in [
            ("http://example.com", "/"),
            ("HTTP://example.com?x=1", "/?x=1"),
        ] {
            let r = parse_head(format!("GET {target} HTTP/1.1\r\n\r\n").as_bytes()).unwrap();
            assert_eq!((r.host.as_str(), r.port), ("example.com", 80));
            assert!(
                r.head.starts_with(
                    format!("GET {path} HTTP/1.1\r\nHost: example.com\r\n").as_bytes()
                ),
                "{target}"
            );
        }
    }

    #[test]
    fn unsupported_requests_are_rejected() {
        for head in [
            "GET /relative HTTP/1.1\r\n\r\n",
            "GET https://example.com/ HTTP/1.1\r\n\r\n",
            "CONNECT [::1]:443 HTTP/1.1\r\n\r\n",
            "CONNECT :443 HTTP/1.1\r\n\r\n",
            "CONNECT .:443 HTTP/1.1\r\n\r\n",
            "CONNECT example.com:99999 HTTP/1.1\r\n\r\n",
            "GET http://user@example.com/ HTTP/1.1\r\n\r\n",
            "GARBAGE\r\n\r\n",
        ] {
            assert_eq!(parse_head(head.as_bytes()), None, "{head:?}");
        }
        assert_eq!(
            parse_head(b"GET http://caf\xE9.com/ HTTP/1.1\r\n\r\n"),
            None
        );
    }
}
