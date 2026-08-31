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

/// Hosts the proxy answers itself instead of dialing out, so a test cannot
/// fail for a reason unrelated to containment.
///
/// Two names are served because filtering runs first: a blocked
/// [`SELF_SERVED_BLOCKED_ORIGIN`] yields 403 when enforcement works and 200
/// when it does not, never an unreachable-host error that would pass by
/// accident. `.invalid` (RFC 6761) never resolves, so neither name reaches the
/// network; CONNECT to either is refused (501).
pub const SELF_SERVED_ORIGIN: &str = "mxc-test.invalid";

/// Companion to [`SELF_SERVED_ORIGIN`], by convention the one a test denies.
pub const SELF_SERVED_BLOCKED_ORIGIN: &str = "mxc-blocked.invalid";

/// Body returned for a self-served host, so a test can assert on content
/// rather than only on the status code.
pub const SELF_SERVED_BODY: &str = "MXC_TEST_ORIGIN_OK";

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

fn text_response(status: StatusCode, body: &str) -> Response<Full<Bytes>> {
    Response::builder()
        .status(status)
        .header("Content-Type", "text/plain")
        .body(Full::new(Bytes::from(body.to_string())))
        .unwrap()
}

/// Whether `host` (possibly `host:port`) is one of the self-served origins.
fn is_self_served(host: &str) -> bool {
    let host = strip_port(host);
    [SELF_SERVED_ORIGIN, SELF_SERVED_BLOCKED_ORIGIN]
        .iter()
        .any(|served| host.eq_ignore_ascii_case(served))
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

    // A tunnel would have to present a TLS identity for this name, which the
    // proxy has none for. Say so rather than failing later on a name that by
    // definition cannot resolve.
    if is_self_served(&authority) {
        eprintln!(
            "[unix-test-proxy] CONNECT to a self-served origin is unsupported; use plain http://"
        );
        return Ok(empty_response(StatusCode::NOT_IMPLEMENTED));
    }

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

    // Answered here rather than dialed, but only after filtering, so an
    // allow/block list governs it like any other host.
    if is_self_served(host) {
        eprintln!("[unix-test-proxy] SERVE {} {}", method, uri);
        return Ok(text_response(StatusCode::OK, SELF_SERVED_BODY));
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
    fn the_self_served_origin_is_recognised_with_and_without_a_port() {
        assert!(is_self_served(SELF_SERVED_ORIGIN));
        assert!(is_self_served(SELF_SERVED_BLOCKED_ORIGIN));
        assert!(is_self_served(&format!("{SELF_SERVED_ORIGIN}:80")));
        assert!(is_self_served(&SELF_SERVED_ORIGIN.to_uppercase()));
        assert!(!is_self_served("example.com"));
    }

    /// The self-served origins must stay reserved. A resolvable name would let
    /// a test reach the network and reintroduce the flake it exists to remove.
    #[test]
    fn the_self_served_origins_use_a_reserved_tld() {
        for host in [SELF_SERVED_ORIGIN, SELF_SERVED_BLOCKED_ORIGIN] {
            assert!(
                host.ends_with(".invalid"),
                "{host} must sit under the RFC 6761 .invalid TLD"
            );
        }
        assert_ne!(SELF_SERVED_ORIGIN, SELF_SERVED_BLOCKED_ORIGIN);
    }

    /// Serving happens after filtering, so a denied self-served host is a real
    /// control: enforcement gives 403 while a broken filter gives a live 200.
    #[test]
    fn the_self_served_origin_is_still_subject_to_filtering() {
        let blocked = HostFilter::new(
            vec![],
            vec![SELF_SERVED_BLOCKED_ORIGIN.into()],
            DefaultPolicy::Allow,
        );
        assert!(!blocked.permits(SELF_SERVED_BLOCKED_ORIGIN));
        assert!(blocked.permits(SELF_SERVED_ORIGIN));

        let unlisted = HostFilter::new(
            vec![SELF_SERVED_ORIGIN.into()],
            vec![],
            DefaultPolicy::Allow,
        );
        assert!(!unlisted.permits(SELF_SERVED_BLOCKED_ORIGIN));

        let allowed = HostFilter::new(
            vec![SELF_SERVED_ORIGIN.into()],
            vec![],
            DefaultPolicy::Block,
        );
        assert!(allowed.permits(SELF_SERVED_ORIGIN));
    }

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
