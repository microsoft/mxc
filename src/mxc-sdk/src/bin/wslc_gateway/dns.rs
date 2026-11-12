// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! DNS over UDP and TCP on the workload's network. Answers the host loopback and custom proxy
//! names itself, and forwards or refuses everything else.

use crate::gateway_policy::{Policy, HOST_LOOPBACK_NAME};
use crate::relay::accept_loop;
use std::io;
use std::net::{Ipv4Addr, SocketAddrV4};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::sync::Semaphore;

const TYPE_A: u16 = 1;
const RCODE_REFUSED: u8 = 5;
const FORWARD_TIMEOUT: Duration = Duration::from_secs(4);
const TCP_IDLE_TIMEOUT: Duration = Duration::from_secs(10);
/// UDP queries beyond this are dropped; clients retry.
const MAX_UDP_IN_FLIGHT: usize = 256;

pub struct Server {
    udp: UdpSocket,
    tcp: TcpListener,
    resolver: Arc<Resolver>,
}

impl Server {
    pub async fn bind(policy: Arc<Policy>) -> Result<Self, String> {
        let address = SocketAddrV4::new(policy.workload_address, 53);
        let udp = UdpSocket::bind(address)
            .await
            .map_err(|e| format!("bind UDP {address}: {e}"))?;
        let tcp = TcpListener::bind(address)
            .await
            .map_err(|e| format!("bind TCP {address}: {e}"))?;
        let upstream = upstream_nameserver().map(|ip| SocketAddrV4::new(ip, 53));
        Ok(Self {
            udp,
            tcp,
            resolver: Arc::new(Resolver { policy, upstream }),
        })
    }

    /// Serves UDP and TCP until either fails.
    pub async fn serve(self) -> Result<(), String> {
        tokio::try_join!(
            serve_udp(self.udp, self.resolver.clone()),
            serve_tcp(self.tcp, self.resolver)
        )
        .map(|_| ())
    }
}

struct Resolver {
    policy: Arc<Policy>,
    upstream: Option<SocketAddrV4>,
}

#[derive(Clone, Copy)]
enum Transport {
    Udp,
    Tcp,
}

impl Resolver {
    /// Forwards over the transport the query arrived on, so a truncated UDP
    /// reply makes the client retry over TCP end to end. `None` drops it.
    async fn answer(&self, query: &[u8], transport: Transport) -> Option<Vec<u8>> {
        match decide(&self.policy, query, self.upstream)? {
            Answer::Reply(reply) => Some(reply),
            Answer::Forward(upstream) => match transport {
                Transport::Udp => forward_udp(query, upstream).await,
                Transport::Tcp => forward_tcp(query, upstream).await,
            },
        }
    }
}

async fn serve_udp(socket: UdpSocket, resolver: Arc<Resolver>) -> Result<(), String> {
    let socket = Arc::new(socket);
    let in_flight = Arc::new(Semaphore::new(MAX_UDP_IN_FLIGHT));
    let mut buf = vec![0u8; 65535];
    loop {
        let (n, peer) = socket
            .recv_from(&mut buf)
            .await
            .map_err(|e| format!("DNS: receive: {e}"))?;
        let Ok(permit) = in_flight.clone().try_acquire_owned() else {
            continue;
        };
        let query = buf[..n].to_vec();
        let (socket, resolver) = (socket.clone(), resolver.clone());
        tokio::spawn(async move {
            if let Some(reply) = resolver.answer(&query, Transport::Udp).await {
                let _ = socket.send_to(&reply, peer).await;
            }
            drop(permit);
        });
    }
}

/// Answers length-prefixed queries in order until the client goes idle.
async fn serve_tcp(listener: TcpListener, resolver: Arc<Resolver>) -> Result<(), String> {
    accept_loop(listener, "DNS", move |mut client, _| {
        let resolver = resolver.clone();
        async move {
            while let Some(query) = read_message(&mut client).await {
                let Some(reply) = resolver.answer(&query, Transport::Tcp).await else {
                    break;
                };
                if write_message(&mut client, &reply).await.is_err() {
                    break;
                }
            }
        }
    })
    .await
}

async fn read_message(stream: &mut (impl AsyncRead + Unpin)) -> Option<Vec<u8>> {
    tokio::time::timeout(TCP_IDLE_TIMEOUT, async {
        let len = stream.read_u16().await.ok()?;
        let mut message = vec![0u8; len.into()];
        stream.read_exact(&mut message).await.ok()?;
        Some(message)
    })
    .await
    .ok()?
}

async fn write_message(stream: &mut (impl AsyncWrite + Unpin), message: &[u8]) -> io::Result<()> {
    let len = u16::try_from(message.len()).map_err(|_| io::ErrorKind::InvalidData)?;
    let mut framed = Vec::with_capacity(message.len() + 2);
    framed.extend_from_slice(&len.to_be_bytes());
    framed.extend_from_slice(message);
    stream.write_all(&framed).await
}

#[derive(Debug, PartialEq)]
enum Answer {
    Reply(Vec<u8>),
    Forward(SocketAddrV4),
}

/// `None` drops a malformed query.
fn decide(policy: &Policy, query: &[u8], upstream: Option<SocketAddrV4>) -> Option<Answer> {
    let (name, qtype, question_end) = parse_question(query)?;
    let custom_proxy_name = policy.custom_proxy.as_ref().and_then(|p| p.name.as_deref());
    let local = if name.eq_ignore_ascii_case(HOST_LOOPBACK_NAME) {
        Some(policy.host_loopback.map(|h| h.relay_address))
    } else if custom_proxy_name.is_some_and(|n| n.eq_ignore_ascii_case(&name)) {
        Some(Some(policy.workload_address))
    } else {
        None
    };
    let answer = match (local, upstream) {
        (Some(Some(ip)), _) => {
            println!("DNS  {name} -> {ip} (local)");
            reply(query, question_end, 0, (qtype == TYPE_A).then_some(ip))
        }
        (Some(None), _) => {
            println!("DNS  {name} refused (host loopback denied)");
            reply(query, question_end, RCODE_REFUSED, None)
        }
        (None, Some(upstream)) if policy.forward_dns => {
            println!("DNS  {name} forwarded");
            return Some(Answer::Forward(upstream));
        }
        (None, _) => {
            println!("DNS  {name} refused");
            reply(query, question_end, RCODE_REFUSED, None)
        }
    };
    Some(Answer::Reply(answer))
}

/// Returns the single question's name, type and end offset.
fn parse_question(q: &[u8]) -> Option<(String, u16, usize)> {
    if q.len() < 12 || q[2] & 0x80 != 0 || u16::from_be_bytes([q[4], q[5]]) != 1 {
        return None;
    }
    let mut labels = Vec::new();
    let mut i = 12;
    loop {
        let len = *q.get(i)? as usize;
        i += 1;
        if len == 0 {
            break;
        }
        if len > 63 {
            return None;
        }
        labels.push(String::from_utf8_lossy(q.get(i..i + len)?).into_owned());
        i += len;
    }
    let qtype = u16::from_be_bytes([*q.get(i)?, *q.get(i + 1)?]);
    q.get(i + 2..i + 4)?;
    Some((labels.join("."), qtype, i + 4))
}

fn reply(query: &[u8], question_end: usize, rcode: u8, a: Option<Ipv4Addr>) -> Vec<u8> {
    let mut r = Vec::with_capacity(question_end + 16);
    r.extend_from_slice(&query[..2]);
    // Response, opcode 0, recursion desired copied, recursion available.
    r.push(0x80 | (query[2] & 0x01));
    r.push(0x80 | rcode);
    r.extend_from_slice(&[0, 1, 0, a.is_some() as u8, 0, 0, 0, 0]);
    r.extend_from_slice(&query[12..question_end]);
    if let Some(ip) = a {
        // Name pointer to the question, type A, class IN, TTL 60, length 4.
        r.extend_from_slice(&[0xC0, 0x0C, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4]);
        r.extend_from_slice(&ip.octets());
    }
    r
}

async fn forward_udp(query: &[u8], upstream: SocketAddrV4) -> Option<Vec<u8>> {
    let socket = UdpSocket::bind("0.0.0.0:0").await.ok()?;
    socket.connect(upstream).await.ok()?;
    socket.send(query).await.ok()?;
    let mut buf = vec![0u8; 65535];
    let n = tokio::time::timeout(FORWARD_TIMEOUT, socket.recv(&mut buf))
        .await
        .ok()?
        .ok()?;
    buf.truncate(n);
    Some(buf)
}

async fn forward_tcp(query: &[u8], upstream: SocketAddrV4) -> Option<Vec<u8>> {
    tokio::time::timeout(FORWARD_TIMEOUT, async {
        let mut stream = TcpStream::connect(upstream).await.ok()?;
        write_message(&mut stream, query).await.ok()?;
        read_message(&mut stream).await
    })
    .await
    .ok()?
}

/// Docker's resolver, from the gateway's own `/etc/resolv.conf`.
fn upstream_nameserver() -> Option<Ipv4Addr> {
    std::fs::read_to_string("/etc/resolv.conf")
        .ok()?
        .lines()
        .find_map(|l| {
            l.strip_prefix("nameserver")
                .and_then(|ip| ip.trim().parse().ok())
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::gateway_policy::{Action, CustomProxy, Egress, HostLoopback};

    const UPSTREAM: SocketAddrV4 = SocketAddrV4::new(Ipv4Addr::new(127, 0, 0, 11), 53);

    fn policy(forward_dns: bool, host_loopback: bool, proxy_name: Option<&str>) -> Policy {
        Policy {
            workload_address: Ipv4Addr::new(10, 231, 1, 2),
            egress_address: Ipv4Addr::new(10, 231, 2, 2),
            proxy_port: 3128,
            forward_dns,
            egress: Egress {
                default: Action::Deny,
                allow: vec![],
                deny: vec![],
            },
            host_loopback: host_loopback.then_some(HostLoopback {
                relay_address: Ipv4Addr::new(10, 231, 1, 3),
                prefix_length: 24,
            }),
            custom_proxy: proxy_name.map(|n| CustomProxy {
                name: Some(n.to_string()),
                address: None,
                port: 8080,
            }),
            port_mappings: vec![],
        }
    }

    fn query(name: &str, qtype: u16) -> Vec<u8> {
        let mut q = vec![0x12, 0x34, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0];
        for label in name.split('.') {
            q.push(label.len() as u8);
            q.extend_from_slice(label.as_bytes());
        }
        q.push(0);
        q.extend_from_slice(&qtype.to_be_bytes());
        q.extend_from_slice(&[0, 1]);
        q
    }

    fn reply_of(answer: Option<Answer>) -> Vec<u8> {
        match answer {
            Some(Answer::Reply(r)) => r,
            other => panic!("expected a local reply, got {other:?}"),
        }
    }

    fn rcode(reply: &[u8]) -> u8 {
        reply[3] & 0x0F
    }

    #[test]
    fn host_loopback_resolves_to_the_relay_address_only_when_allowed() {
        let q = query("Host.WSLC.Internal", TYPE_A);
        let allowed = reply_of(decide(&policy(true, true, None), &q, Some(UPSTREAM)));
        assert_eq!((rcode(&allowed), allowed[7]), (0, 1));
        assert_eq!(&allowed[allowed.len() - 4..], &[10, 231, 1, 3]);
        assert_eq!(&allowed[..2], &q[..2]);

        let denied = reply_of(decide(&policy(true, false, None), &q, Some(UPSTREAM)));
        assert_eq!((rcode(&denied), denied[7]), (RCODE_REFUSED, 0));
    }

    #[test]
    fn the_custom_proxy_name_resolves_to_the_gateway() {
        let q = query("proxy.corp", TYPE_A);
        let r = reply_of(decide(&policy(false, false, Some("proxy.corp")), &q, None));
        assert_eq!(&r[r.len() - 4..], &[10, 231, 1, 2]);
        let aaaa = reply_of(decide(
            &policy(false, false, Some("proxy.corp")),
            &query("proxy.corp", 28),
            None,
        ));
        assert_eq!((rcode(&aaaa), aaaa[7]), (0, 0));
    }

    #[test]
    fn other_names_are_forwarded_only_when_allowed() {
        let q = query("example.com", TYPE_A);
        assert_eq!(
            decide(&policy(true, false, None), &q, Some(UPSTREAM)),
            Some(Answer::Forward(UPSTREAM))
        );
        assert_eq!(
            rcode(&reply_of(decide(
                &policy(false, false, None),
                &q,
                Some(UPSTREAM)
            ))),
            RCODE_REFUSED
        );
        assert_eq!(
            rcode(&reply_of(decide(&policy(true, false, None), &q, None))),
            RCODE_REFUSED
        );
    }

    #[test]
    fn malformed_queries_are_dropped() {
        let p = policy(true, true, None);
        let mut response = query("example.com", TYPE_A);
        response[2] |= 0x80;
        let mut truncated = query("example.com", TYPE_A);
        truncated.truncate(truncated.len() - 3);
        let mut two_questions = query("example.com", TYPE_A);
        two_questions[5] = 2;
        for q in [vec![0; 11], response, truncated, two_questions] {
            assert_eq!(decide(&p, &q, Some(UPSTREAM)), None);
        }
    }

    #[tokio::test]
    async fn one_tcp_connection_gets_local_and_forwarded_answers() {
        let upstream = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let std::net::SocketAddr::V4(upstream_address) = upstream.local_addr().unwrap() else {
            unreachable!()
        };
        tokio::spawn(async move {
            let (mut stream, _) = upstream.accept().await.unwrap();
            let mut reply = read_message(&mut stream).await.unwrap();
            reply[2] |= 0x80;
            write_message(&mut stream, &reply).await.unwrap();
        });

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let resolver = Arc::new(Resolver {
            policy: Arc::new(policy(true, true, None)),
            upstream: Some(upstream_address),
        });
        tokio::spawn(serve_tcp(listener, resolver));

        let mut client = TcpStream::connect(address).await.unwrap();
        write_message(&mut client, &query("host.wslc.internal", TYPE_A))
            .await
            .unwrap();
        let local = read_message(&mut client).await.unwrap();
        assert_eq!(&local[local.len() - 4..], &[10, 231, 1, 3]);

        let q = query("example.com", TYPE_A);
        write_message(&mut client, &q).await.unwrap();
        let forwarded = read_message(&mut client).await.unwrap();
        assert_eq!((forwarded[2] & 0x80, &forwarded[12..]), (0x80, &q[12..]));
    }
}
