// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Minimal HTTP CONNECT proxy for testing.

use http_body_util::Empty;
use hyper::body::Incoming;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Method, Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use tokio::net::{TcpListener, TcpStream};

type BoxError = Box<dyn std::error::Error + Send + Sync>;
type ProxyResponse = Response<Empty<bytes::Bytes>>;

fn empty_response(status: StatusCode) -> ProxyResponse {
    let mut resp = Response::new(Empty::new());
    *resp.status_mut() = status;
    resp
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

async fn handle_request(req: Request<Incoming>) -> Result<ProxyResponse, BoxError> {
    if req.method() != Method::CONNECT {
        eprintln!(
            "[wxc-test-proxy] rejected non-CONNECT: {} {}",
            req.method(),
            req.uri()
        );
        return Ok(empty_response(StatusCode::METHOD_NOT_ALLOWED));
    }

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
