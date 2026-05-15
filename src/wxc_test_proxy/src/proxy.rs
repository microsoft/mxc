// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Minimal HTTP proxy for testing — supports CONNECT tunnels and HTTP forwarding.

use http_body_util::{BodyExt, Full};
use hyper::body::{Bytes, Incoming};
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Method, Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use tokio::net::{TcpListener, TcpStream};

type BoxError = Box<dyn std::error::Error + Send + Sync>;

fn empty_response(status: StatusCode) -> Response<Full<Bytes>> {
    Response::builder()
        .status(status)
        .body(Full::new(Bytes::new()))
        .unwrap()
}

/// Start the test proxy. Binds to port 0 (OS-assigned) and returns the actual port.
pub async fn start() -> u16 {
    let listener = TcpListener::bind(("127.0.0.1", 0))
        .await
        .unwrap_or_else(|err| {
            eprintln!("Test proxy failed to bind: {}", err);
            std::process::exit(1);
        });

    let port = listener.local_addr().unwrap().port();

    tokio::spawn(async move {
        loop {
            if let Ok((stream, _)) = listener.accept().await {
                tokio::spawn(async move {
                    let io = TokioIo::new(stream);
                    let _ = http1::Builder::new()
                        .preserve_header_case(true)
                        .title_case_headers(true)
                        .serve_connection(io, service_fn(handle_request))
                        .with_upgrades()
                        .await;
                });
            }
        }
    });

    port
}

async fn handle_request(
    req: Request<Incoming>,
) -> Result<Response<Full<Bytes>>, BoxError> {
    if req.method() == Method::CONNECT {
        return handle_connect(req).await;
    }

    // HTTP forwarding — forward GET/POST/etc to the target
    handle_forward(req).await
}

async fn handle_connect(
    req: Request<Incoming>,
) -> Result<Response<Full<Bytes>>, BoxError> {
    let authority = req
        .uri()
        .authority()
        .ok_or("CONNECT missing authority")?
        .to_string();

    eprintln!("[wxc-test-proxy] CONNECT {}", authority);

    let server = TcpStream::connect(&authority).await.map_err(|err| {
        eprintln!("[wxc-test-proxy] connect error for {}: {}", authority, err);
        err
    })?;

    let target = authority.clone();
    tokio::spawn(async move {
        let upgraded = match hyper::upgrade::on(req).await {
            Ok(upgraded) => upgraded,
            Err(err) => {
                eprintln!("[wxc-test-proxy] upgrade failed for {}: {}", target, err);
                return;
            }
        };

        let mut client = TokioIo::new(upgraded);
        let mut server = server;
        if let Ok((from_client, from_server)) =
            tokio::io::copy_bidirectional(&mut client, &mut server).await
        {
            eprintln!(
                "[wxc-test-proxy] tunnel closed {} (client: {} bytes, server: {} bytes)",
                target, from_client, from_server
            );
        }
    });

    Ok(empty_response(StatusCode::OK))
}

async fn handle_forward(
    req: Request<Incoming>,
) -> Result<Response<Full<Bytes>>, BoxError> {
    let uri = req.uri().clone();
    let method = req.method().clone();

    eprintln!("[wxc-test-proxy] {} {}", method, uri);

    // Extract host from the absolute URI
    let host = uri.host().ok_or("missing host in URI")?;
    let port = uri.port_u16().unwrap_or(80);
    let addr = format!("{}:{}", host, port);

    // Connect to target
    let stream = TcpStream::connect(&addr).await.map_err(|err| {
        eprintln!("[wxc-test-proxy] forward connect error for {}: {}", addr, err);
        err
    })?;

    let io = TokioIo::new(stream);
    let (mut sender, conn) = hyper::client::conn::http1::handshake(io).await?;

    tokio::spawn(async move {
        if let Err(err) = conn.await {
            eprintln!("[wxc-test-proxy] forward connection error: {}", err);
        }
    });

    // Build the forwarded request with a relative URI (path + query only)
    let path = uri
        .path_and_query()
        .map(|pq| pq.as_str())
        .unwrap_or("/");

    let mut forward_req = Request::builder()
        .method(method)
        .uri(path)
        .header("Host", format!("{}:{}", host, port));

    // Copy headers from original request
    for (key, value) in req.headers() {
        if key != "host" {
            forward_req = forward_req.header(key, value);
        }
    }

    let body = req.collect().await?.to_bytes();
    let forward_req = forward_req.body(Full::new(body))?;

    let resp = sender.send_request(forward_req).await?;

    // Collect response body and forward back
    let status = resp.status();
    let headers = resp.headers().clone();
    let resp_body = resp.collect().await?.to_bytes();

    let mut response = Response::builder().status(status);
    for (key, value) in headers.iter() {
        response = response.header(key, value);
    }

    eprintln!(
        "[wxc-test-proxy] forwarded {} → {} ({} bytes)",
        uri, status, resp_body.len()
    );

    Ok(response.body(Full::new(resp_body))?)
}
