// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Filtering HTTP proxy: `CONNECT` and absolute-form `http://` requests, one
//! request per connection, allowed or denied by the egress rules.

use crate::relay::{accept_loop, connect, splice};
use mxc_sdk::wslc_gateway_policy::{Action, Policy, HOST_LOOPBACK_NAME};
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

const MAX_HEAD: usize = 16 * 1024;
const HEAD_TIMEOUT: Duration = Duration::from_secs(10);

pub async fn serve(listener: TcpListener, policy: Arc<Policy>) -> Result<(), String> {
    accept_loop(listener, "proxy", move |client, _| {
        let policy = policy.clone();
        async move {
            if let Err(e) = handle(client, &policy).await {
                println!("PROXY error: {e}");
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

async fn handle(mut client: TcpStream, policy: &Policy) -> std::io::Result<()> {
    let Some((request, rest)) = read_request(&mut client).await? else {
        return respond(&mut client, 400, "bad request").await;
    };
    let target = format!("{}:{}", request.host, request.port);

    let is_host_loopback = request.host.eq_ignore_ascii_case(HOST_LOOPBACK_NAME)
        || policy
            .host_loopback
            .is_some_and(|h| request.host == h.relay_address.to_string());
    let upstream_host = if is_host_loopback {
        if policy.host_loopback.is_none() {
            println!("DENY  {target} (host loopback denied)");
            return respond(&mut client, 403, "host loopback denied").await;
        }
        HOST_LOOPBACK_NAME.to_string()
    } else {
        let Some(ip) = resolve(&request.host, request.port).await else {
            println!("DENY  {target} (no IPv4 address)");
            return respond(&mut client, 502, "name did not resolve").await;
        };
        let (action, why) = policy.egress.check(ip, request.port);
        if action == Action::Deny {
            println!("DENY  {target} -> {ip} ({why})");
            let message = format!("{ip}:{} denied by {why}", request.port);
            return respond(&mut client, 403, &message).await;
        }
        println!("ALLOW {target} -> {ip} ({why})");
        // Connect to the checked address rather than resolving the name again.
        ip.to_string()
    };

    let mut upstream = match connect(&upstream_host, request.port).await {
        Ok(s) => s,
        Err(e) => return respond(&mut client, 502, &format!("connect failed: {e}")).await,
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

async fn resolve(host: &str, port: u16) -> Option<Ipv4Addr> {
    if let Ok(ip) = host.parse() {
        return Some(ip);
    }
    tokio::net::lookup_host((host, port))
        .await
        .ok()?
        .find_map(|a| match a {
            SocketAddr::V4(v4) => Some(*v4.ip()),
            SocketAddr::V6(_) => None,
        })
}

/// Reads up to the end of the request head. Returns the request and any bytes
/// read past the head.
async fn read_request(client: &mut TcpStream) -> std::io::Result<Option<(Request, Vec<u8>)>> {
    let mut buf = Vec::new();
    let mut chunk = [0u8; 4096];
    let end = loop {
        if let Some(i) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            break i + 4;
        }
        if buf.len() > MAX_HEAD {
            return Ok(None);
        }
        let n = tokio::time::timeout(HEAD_TIMEOUT, client.read(&mut chunk))
            .await
            .unwrap_or_else(|_| Err(std::io::ErrorKind::TimedOut.into()))?;
        if n == 0 {
            return Ok(None);
        }
        buf.extend_from_slice(&chunk[..n]);
    };
    Ok(parse_head(&String::from_utf8_lossy(&buf[..end])).map(|r| (r, buf[end..].to_vec())))
}

fn parse_head(head: &str) -> Option<Request> {
    let mut lines = head.split("\r\n");
    let mut parts = lines.next()?.split(' ');
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

    let after = target.strip_prefix("http://")?;
    let (authority, path) = after.split_at(after.find('/').unwrap_or(after.len()));
    let (host, port) = split_host_port(authority, 80)?;
    let path = if path.is_empty() { "/" } else { path };
    // One request per connection, so a reused connection can't reach a host
    // that wasn't checked.
    let mut out = format!("{method} {path} {version}\r\n");
    for line in lines.filter(|l| !l.is_empty()) {
        let name = line
            .split(':')
            .next()
            .unwrap_or("")
            .trim()
            .to_ascii_lowercase();
        if !(name.starts_with("proxy-") || name == "connection" || name == "keep-alive") {
            out.push_str(line);
            out.push_str("\r\n");
        }
    }
    out.push_str("Connection: close\r\n\r\n");
    Some(Request {
        connect: false,
        host,
        port,
        head: out.into_bytes(),
    })
}

/// IPv6 literals and userinfo are rejected.
fn split_host_port(s: &str, default_port: u16) -> Option<(String, u16)> {
    if s.starts_with('[') || s.contains('@') {
        return None;
    }
    let (host, port) = match s.rsplit_once(':') {
        Some((h, p)) => (h, p.parse().ok()?),
        None => (s, default_port),
    };
    (!host.is_empty()).then(|| (host.to_string(), port))
}

async fn respond(client: &mut TcpStream, code: u16, message: &str) -> std::io::Result<()> {
    let reason = match code {
        400 => "Bad Request",
        403 => "Forbidden",
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

    #[test]
    fn connect_requests_name_the_target_and_default_to_port_443() {
        let r =
            parse_head("CONNECT example.com:8443 HTTP/1.1\r\nHost: example.com\r\n\r\n").unwrap();
        assert_eq!(
            (r.connect, r.host.as_str(), r.port),
            (true, "example.com", 8443)
        );
        assert!(r.head.is_empty());
        assert_eq!(
            parse_head("CONNECT example.com HTTP/1.1\r\n\r\n")
                .unwrap()
                .port,
            443
        );
    }

    #[test]
    fn http_requests_are_rewritten_for_one_request_per_connection() {
        let r = parse_head(
            "GET http://10.1.2.3:8080/a?b HTTP/1.1\r\nHost: 10.1.2.3\r\nProxy-Authorization: x\r\n\
             Connection: keep-alive\r\nKeep-Alive: 5\r\nAccept: */*\r\n\r\n",
        )
        .unwrap();
        assert_eq!(
            (r.connect, r.host.as_str(), r.port),
            (false, "10.1.2.3", 8080)
        );
        assert_eq!(
            String::from_utf8(r.head).unwrap(),
            "GET /a?b HTTP/1.1\r\nHost: 10.1.2.3\r\nAccept: */*\r\nConnection: close\r\n\r\n"
        );
        let bare = parse_head("GET http://example.com HTTP/1.1\r\n\r\n").unwrap();
        assert_eq!(bare.port, 80);
        assert!(bare.head.starts_with(b"GET / HTTP/1.1\r\n"));
    }

    #[test]
    fn unsupported_requests_are_rejected() {
        for head in [
            "GET /relative HTTP/1.1\r\n\r\n",
            "GET https://example.com/ HTTP/1.1\r\n\r\n",
            "CONNECT [::1]:443 HTTP/1.1\r\n\r\n",
            "CONNECT :443 HTTP/1.1\r\n\r\n",
            "CONNECT example.com:99999 HTTP/1.1\r\n\r\n",
            "GET http://user@example.com/ HTTP/1.1\r\n\r\n",
            "GARBAGE\r\n\r\n",
        ] {
            assert_eq!(parse_head(head), None, "{head:?}");
        }
    }
}
