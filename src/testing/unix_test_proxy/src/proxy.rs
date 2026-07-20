// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Minimal HTTP proxy for testing — supports CONNECT tunnels and HTTP
//! forwarding, with optional allow / block host filtering enforced at the
//! proxy.
//!
//! Adapted from `wxc_test_proxy::proxy` and extended with host filtering for
//! the cooperative proxy used by Bubblewrap and Seatbelt.

use std::sync::Arc;

use http_body_util::{BodyExt, Full};
use hyper::body::{Bytes, Incoming};
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Method, Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use tokio::net::{TcpListener, TcpStream};

type BoxError = Box<dyn std::error::Error + Send + Sync>;

/// Default policy applied when the `allow` list is empty.
///
/// - `Allow` — permit any host that isn't explicitly blocked.
/// - `Block` — deny any host that isn't explicitly allowed.
///
/// When the `allow` list is non-empty, the default policy is irrelevant: only
/// listed hosts are permitted (subject to `block` taking precedence).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum DefaultPolicy {
    #[default]
    Allow,
    Block,
}

/// Host-name filter applied at the proxy layer.
///
/// Matching is case-insensitive and uses exact host comparison (no suffix
/// matching). The port portion of `host:port` is stripped before lookup.
///
/// Behavior:
/// - If `block` contains the host, the request is denied.
/// - Otherwise, if `allow` is non-empty: the host must be in `allow`.
/// - Otherwise (empty `allow`): the request is permitted iff `default` is
///   [`DefaultPolicy::Allow`].
#[derive(Debug, Default)]
pub struct HostFilter {
    allow: Vec<String>,
    block: Vec<String>,
    default: DefaultPolicy,
}

impl HostFilter {
    pub fn new(allow: Vec<String>, block: Vec<String>, default: DefaultPolicy) -> Self {
        Self {
            allow: allow.into_iter().map(|h| h.to_lowercase()).collect(),
            block: block.into_iter().map(|h| h.to_lowercase()).collect(),
            default,
        }
    }

    /// Returns `true` if traffic to `host` is permitted.
    pub fn permits(&self, host: &str) -> bool {
        let host = strip_port(host).to_lowercase();
        if self.block.iter().any(|h| h == &host) {
            return false;
        }
        if !self.allow.is_empty() {
            return self.allow.iter().any(|h| h == &host);
        }
        // Empty allow list: the default policy decides.
        self.default == DefaultPolicy::Allow
    }
}

fn strip_port(host_port: &str) -> &str {
    // Bracketed IPv6 form: "[::1]" or "[::1]:443" -> "::1". Always return the
    // inner address so it can be matched against an allowlist entry stored
    // without brackets (e.g. `allowedHosts: ["::1"]`).
    if let Some(stripped) = host_port.strip_prefix('[') {
        if let Some(end) = stripped.find(']') {
            return &stripped[..end];
        }
    }
    // Plain "host:port" or unbracketed IPv6 (which has multiple colons).
    if let Some(idx) = host_port.rfind(':') {
        // If the prefix before the rightmost colon already contains a colon,
        // this is an unbracketed IPv6 literal with no port — leave intact.
        if host_port[..idx].contains(':') {
            return host_port;
        }
        return &host_port[..idx];
    }
    host_port
}

fn empty_response(status: StatusCode) -> Response<Full<Bytes>> {
    Response::builder()
        .status(status)
        .body(Full::new(Bytes::new()))
        .unwrap()
}

/// Start the test proxy. Binds to `bind_addr:0` (OS-assigned port) and
/// returns the actual port the listener is bound to. The accept loop runs
/// in a background tokio task and applies `filter` to every request.
pub async fn start(bind_addr: &str, filter: Arc<HostFilter>) -> std::io::Result<u16> {
    let listener = TcpListener::bind((bind_addr, 0)).await?;
    let port = listener.local_addr()?.port();

    tokio::spawn(async move {
        loop {
            match listener.accept().await {
                Ok((stream, _)) => {
                    let filter = filter.clone();
                    tokio::spawn(async move {
                        let io = TokioIo::new(stream);
                        let svc = service_fn(move |req| handle_request(req, filter.clone()));
                        let _ = http1::Builder::new()
                            .preserve_header_case(true)
                            .title_case_headers(true)
                            .serve_connection(io, svc)
                            .with_upgrades()
                            .await;
                    });
                }
                Err(err) => {
                    eprintln!("[unix-test-proxy] accept error: {}", err);
                }
            }
        }
    });

    Ok(port)
}

async fn handle_request(
    req: Request<Incoming>,
    filter: Arc<HostFilter>,
) -> Result<Response<Full<Bytes>>, BoxError> {
    if req.method() == Method::CONNECT {
        return handle_connect(req, filter).await;
    }
    handle_forward(req, filter).await
}

async fn handle_connect(
    req: Request<Incoming>,
    filter: Arc<HostFilter>,
) -> Result<Response<Full<Bytes>>, BoxError> {
    let authority = req
        .uri()
        .authority()
        .ok_or("CONNECT missing authority")?
        .to_string();

    if !filter.permits(&authority) {
        eprintln!("[unix-test-proxy] BLOCK CONNECT {}", authority);
        return Ok(empty_response(StatusCode::FORBIDDEN));
    }

    eprintln!("[unix-test-proxy] CONNECT {}", authority);

    let server = TcpStream::connect(&authority).await.map_err(|err| {
        eprintln!("[unix-test-proxy] connect error for {}: {}", authority, err);
        err
    })?;

    let target = authority.clone();
    tokio::spawn(async move {
        let upgraded = match hyper::upgrade::on(req).await {
            Ok(upgraded) => upgraded,
            Err(err) => {
                eprintln!("[unix-test-proxy] upgrade failed for {}: {}", target, err);
                return;
            }
        };

        let mut client = TokioIo::new(upgraded);
        let mut server = server;
        if let Ok((from_client, from_server)) =
            tokio::io::copy_bidirectional(&mut client, &mut server).await
        {
            eprintln!(
                "[unix-test-proxy] tunnel closed {} (client: {} bytes, server: {} bytes)",
                target, from_client, from_server
            );
        }
    });

    Ok(empty_response(StatusCode::OK))
}

async fn handle_forward(
    req: Request<Incoming>,
    filter: Arc<HostFilter>,
) -> Result<Response<Full<Bytes>>, BoxError> {
    let uri = req.uri().clone();
    let method = req.method().clone();

    let host = uri.host().ok_or("missing host in URI")?;
    if !filter.permits(host) {
        eprintln!("[unix-test-proxy] BLOCK {} {}", method, uri);
        return Ok(empty_response(StatusCode::FORBIDDEN));
    }

    let port = uri.port_u16().unwrap_or(80);
    let addr = format!("{}:{}", host, port);

    eprintln!("[unix-test-proxy] {} {}", method, uri);

    let stream = TcpStream::connect(&addr).await.map_err(|err| {
        eprintln!(
            "[unix-test-proxy] forward connect error for {}: {}",
            addr, err
        );
        err
    })?;

    let io = TokioIo::new(stream);
    let (mut sender, conn) = hyper::client::conn::http1::handshake(io).await?;

    tokio::spawn(async move {
        if let Err(err) = conn.await {
            eprintln!("[unix-test-proxy] forward connection error: {}", err);
        }
    });

    let path = uri.path_and_query().map(|pq| pq.as_str()).unwrap_or("/");

    let mut forward_req = Request::builder()
        .method(method)
        .uri(path)
        .header("Host", format!("{}:{}", host, port));

    for (key, value) in req.headers() {
        if key != "host" {
            forward_req = forward_req.header(key, value);
        }
    }

    let body = req.collect().await?.to_bytes();
    let forward_req = forward_req.body(Full::new(body))?;

    let resp = sender.send_request(forward_req).await?;

    let status = resp.status();
    let headers = resp.headers().clone();
    let resp_body = resp.collect().await?.to_bytes();

    let mut response = Response::builder().status(status);
    for (key, value) in headers.iter() {
        response = response.header(key, value);
    }

    Ok(response.body(Full::new(resp_body))?)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn allow_list_empty_permits_everything_when_default_allow() {
        let f = HostFilter::new(vec![], vec![], DefaultPolicy::Allow);
        assert!(f.permits("example.com"));
        assert!(f.permits("api.github.com"));
    }

    #[test]
    fn allow_list_empty_denies_everything_when_default_block() {
        let f = HostFilter::new(vec![], vec![], DefaultPolicy::Block);
        assert!(!f.permits("example.com"));
        assert!(!f.permits("api.github.com"));
    }

    #[test]
    fn allow_list_permits_only_listed_hosts() {
        let f = HostFilter::new(vec!["api.github.com".into()], vec![], DefaultPolicy::Allow);
        assert!(f.permits("api.github.com"));
        assert!(!f.permits("example.com"));
    }

    #[test]
    fn allow_list_permits_only_listed_hosts_under_default_block() {
        // Non-empty allow list with default=block behaves the same as with
        // default=allow: only listed hosts are permitted.
        let f = HostFilter::new(vec!["api.github.com".into()], vec![], DefaultPolicy::Block);
        assert!(f.permits("api.github.com"));
        assert!(!f.permits("example.com"));
    }

    #[test]
    fn block_list_denies_listed_hosts() {
        let f = HostFilter::new(
            vec![],
            vec!["evil.example.com".into()],
            DefaultPolicy::Allow,
        );
        assert!(!f.permits("evil.example.com"));
        assert!(f.permits("api.github.com"));
    }

    #[test]
    fn block_list_takes_precedence_over_allow_list() {
        let f = HostFilter::new(
            vec!["api.github.com".into()],
            vec!["api.github.com".into()],
            DefaultPolicy::Allow,
        );
        assert!(!f.permits("api.github.com"));
    }

    #[test]
    fn block_list_takes_precedence_over_default_allow() {
        let f = HostFilter::new(
            vec![],
            vec!["evil.example.com".into()],
            DefaultPolicy::Allow,
        );
        assert!(!f.permits("evil.example.com"));
    }

    #[test]
    fn matching_is_case_insensitive() {
        let f = HostFilter::new(vec!["API.GitHub.com".into()], vec![], DefaultPolicy::Allow);
        assert!(f.permits("api.github.com"));
        assert!(f.permits("API.GITHUB.COM"));
    }

    #[test]
    fn host_with_port_is_handled() {
        let f = HostFilter::new(vec!["api.github.com".into()], vec![], DefaultPolicy::Allow);
        assert!(f.permits("api.github.com:443"));
        assert!(!f.permits("example.com:80"));
    }

    #[test]
    fn strip_port_handles_ipv6_literal() {
        // Bracketed IPv6 with port -> bare address (matches an allowlist
        // entry of "::1" or "fe80::1").
        assert_eq!(strip_port("[::1]:443"), "::1");
        assert_eq!(strip_port("[::1]"), "::1");
        assert_eq!(strip_port("[fe80::1]:8080"), "fe80::1");
        // Unbracketed IPv6 has no port and must be preserved verbatim.
        assert_eq!(strip_port("::1"), "::1");
        // Plain hostname:port and bare hostname.
        assert_eq!(strip_port("api.github.com:443"), "api.github.com");
        assert_eq!(strip_port("api.github.com"), "api.github.com");
    }

    #[test]
    fn ipv6_literal_allowlist_matches_bracketed_form() {
        // A user-supplied allowlist entry of "::1" should permit a CONNECT
        // to the bracketed form "[::1]:443" emitted by HTTP clients.
        let f = HostFilter::new(vec!["::1".into()], vec![], DefaultPolicy::Allow);
        assert!(f.permits("[::1]:443"));
        assert!(f.permits("[::1]"));
        assert!(!f.permits("[fe80::1]:443"));
    }
}
