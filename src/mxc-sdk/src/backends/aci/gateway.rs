// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! gRPC calls to a sandbox's gateway over HTTP/2 and TLS.

use std::future::Future;
use std::time::Duration;

use bytes::Bytes;
use http::{HeaderMap, HeaderValue};
use tokio::io::{AsyncRead, AsyncWrite};

use crate::mxc_common::mxc_error::MxcError;
use crate::mxc_common::script_runner::RunCancellation;

use super::credentials::Secret;
use super::proto::{
    self, ExecSandboxRequest, ExecSandboxResponse, SandboxState, WaitForReadyResponse,
};

const SERVICE: &str = "aci.sandboxgateway.SandboxGatewayService";
const DEFAULT_PORT: u16 = 443;
const CONNECT_TIMEOUT: Duration = Duration::from_secs(30);
/// Extra time for a call beyond the deadline it gives the gateway, so the
/// gateway's own deadline response normally arrives first.
const CALL_SLACK: Duration = Duration::from_secs(10);
const STATE_CALL_TIMEOUT: Duration = Duration::from_secs(30);
const CANCELLATION_POLL: Duration = Duration::from_millis(100);
const WINDOW_SIZE: u32 = 4 * 1024 * 1024;
const SMALL_RESPONSE_LIMIT: usize = 64 * 1024;
const STATUS_MESSAGE_LIMIT: usize = 512;

/// Combined stdout and stderr MXC accepts from one command, as for NVX.
pub(super) const CAPTURE_LIMIT_BYTES: usize = 64 * 1024 * 1024;

pub(super) const GRPC_DEADLINE_EXCEEDED: u32 = 4;
const GRPC_PERMISSION_DENIED: u32 = 7;
const GRPC_UNIMPLEMENTED: u32 = 12;
const GRPC_UNAUTHENTICATED: u32 = 16;

/// The gateway address and bearer token from a sandbox connection string.
#[derive(Debug, Clone)]
pub(super) struct GatewayAddress {
    host: String,
    port: u16,
    token: Secret,
}

impl GatewayAddress {
    /// Parses `address=<host>[:<port>];token=<token>;token_type=bearer`.
    /// Errors never include the connection string, which carries the token.
    pub fn parse(connection_string: &Secret) -> Result<Self, MxcError> {
        let invalid = |what: &str| {
            MxcError::backend_error(format!(
                "ACI returned a sandbox connection string with {what}"
            ))
        };
        let mut address = None;
        let mut token = None;
        for part in connection_string
            .expose()
            .split(';')
            .filter(|part| !part.is_empty())
        {
            let (key, value) = part
                .split_once('=')
                .ok_or_else(|| invalid("a malformed entry"))?;
            match key.to_ascii_lowercase().as_str() {
                "address" => address = Some(value),
                "token" => token = Some(value),
                "token_type" if !value.eq_ignore_ascii_case("bearer") => {
                    return Err(invalid("a token type other than bearer"));
                }
                _ => {}
            }
        }
        let address = address.ok_or_else(|| invalid("no gateway address"))?;
        let (host, port) = match address.rsplit_once(':') {
            Some((host, port)) => (
                host,
                port.parse::<u16>()
                    .ok()
                    .filter(|&port| port != 0)
                    .ok_or_else(|| invalid("an invalid gateway port"))?,
            ),
            None => (address, DEFAULT_PORT),
        };
        let valid_host = !host.is_empty()
            && host.len() <= 253
            && host.split('.').all(|label| {
                !label.is_empty()
                    && !label.starts_with('-')
                    && !label.ends_with('-')
                    && label
                        .bytes()
                        .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
            });
        if !valid_host {
            return Err(invalid("an invalid gateway host name"));
        }
        let token = token
            .filter(|token| !token.is_empty())
            .ok_or_else(|| invalid("no bearer token"))?;
        Ok(Self {
            host: host.to_owned(),
            port,
            token: Secret::new(token.to_owned(), "gateway token")?,
        })
    }

    fn authority(&self) -> String {
        if self.port == DEFAULT_PORT {
            self.host.clone()
        } else {
            format!("{}:{}", self.host, self.port)
        }
    }
}

/// A gRPC status other than OK.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct GrpcStatus {
    pub code: u32,
    pub message: String,
}

impl GrpcStatus {
    fn name(&self) -> &'static str {
        match self.code {
            1 => "CANCELLED",
            2 => "UNKNOWN",
            3 => "INVALID_ARGUMENT",
            4 => "DEADLINE_EXCEEDED",
            5 => "NOT_FOUND",
            7 => "PERMISSION_DENIED",
            8 => "RESOURCE_EXHAUSTED",
            9 => "FAILED_PRECONDITION",
            12 => "UNIMPLEMENTED",
            13 => "INTERNAL",
            14 => "UNAVAILABLE",
            16 => "UNAUTHENTICATED",
            _ => "OTHER",
        }
    }

    /// The error for a call that ended with this status.
    pub fn into_error(self, method: &str) -> MxcError {
        let detail = if self.message.is_empty() {
            String::new()
        } else {
            format!(": {}", self.message)
        };
        let message = format!(
            "ACI gateway {method} failed with gRPC status {} ({}){detail}",
            self.name(),
            self.code
        );
        match self.code {
            GRPC_UNIMPLEMENTED => MxcError::backend_unavailable(format!(
                "{message}; the sandbox gateway in this region does not support the call"
            )),
            GRPC_UNAUTHENTICATED | GRPC_PERMISSION_DENIED => MxcError::backend_error(format!(
                "{message}; the gateway rejected the sandbox token"
            )),
            _ => MxcError::backend_error(message),
        }
    }
}

/// How an `ExecSandbox` call ended.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum ExecReply {
    Completed(ExecSandboxResponse),
    /// The command was still running at its deadline.
    TimedOut,
}

/// How a unary call ended.
#[derive(Debug, PartialEq, Eq)]
enum CallOutcome {
    /// The gateway answered with a message or a non-OK status.
    Reply(Result<Vec<u8>, GrpcStatus>),
    /// The gateway did not answer within the call's deadline.
    DeadlinePassed,
}

/// Calls a sandbox's gateway, one connection per call.
#[derive(Debug, Clone)]
pub(super) struct Gateway {
    address: GatewayAddress,
}

impl Gateway {
    pub fn new(address: GatewayAddress) -> Self {
        Self { address }
    }

    /// Waits up to `wait_seconds` for the guest to become ready. The gateway
    /// may end the wait sooner, with or without an error status.
    pub fn wait_for_ready(
        &self,
        wait_seconds: u32,
        cancellation: Option<&RunCancellation>,
    ) -> Result<Result<WaitForReadyResponse, GrpcStatus>, MxcError> {
        let wait = Duration::from_secs(u64::from(wait_seconds));
        let reply = self
            .call(
                "WaitForReady",
                &proto::encode_wait_for_ready(wait_seconds),
                Some(wait),
                SMALL_RESPONSE_LIMIT,
                cancellation,
            )?
            .reply("WaitForReady", wait)?;
        match reply {
            Ok(message) => WaitForReadyResponse::decode(&message)
                .map(Ok)
                .map_err(|error| malformed("WaitForReady", &error)),
            Err(status) => Ok(Err(status)),
        }
    }

    /// The sandbox's target and current state and any failure message.
    pub fn sandbox_state(&self) -> Result<SandboxState, MxcError> {
        let message = self
            .call(
                "GetSandbox",
                &[],
                Some(STATE_CALL_TIMEOUT),
                SMALL_RESPONSE_LIMIT,
                None,
            )?
            .reply("GetSandbox", STATE_CALL_TIMEOUT)?
            .map_err(|status| status.into_error("GetSandbox"))?;
        SandboxState::decode(&message).map_err(|error| malformed("GetSandbox", &error))
    }

    /// Runs a command and waits for it to exit, until `timeout` passes, or
    /// until `cancellation` is requested.
    pub fn exec(
        &self,
        request: &ExecSandboxRequest,
        timeout: Option<Duration>,
        cancellation: Option<&RunCancellation>,
    ) -> Result<ExecReply, MxcError> {
        let outcome = self.call(
            "ExecSandbox",
            &request.encode(),
            timeout,
            proto::framed_len(CAPTURE_LIMIT_BYTES + 64),
            cancellation,
        )?;
        let message = match outcome {
            CallOutcome::DeadlinePassed => return Ok(ExecReply::TimedOut),
            CallOutcome::Reply(Ok(message)) => message,
            CallOutcome::Reply(Err(status)) if status.code == GRPC_DEADLINE_EXCEEDED => {
                return Ok(ExecReply::TimedOut)
            }
            CallOutcome::Reply(Err(status)) => return Err(status.into_error("ExecSandbox")),
        };
        let response = ExecSandboxResponse::decode(&message)
            .map_err(|error| malformed("ExecSandbox", &error))?;
        if response.stdout.len().saturating_add(response.stderr.len()) > CAPTURE_LIMIT_BYTES {
            return Err(capture_limit_error());
        }
        Ok(ExecReply::Completed(response))
    }

    /// Makes one unary call. `deadline` is sent to the gateway as
    /// `grpc-timeout`; the call itself gives up [`CALL_SLACK`] later.
    fn call(
        &self,
        method: &str,
        message: &[u8],
        deadline: Option<Duration>,
        response_limit: usize,
        cancellation: Option<&RunCancellation>,
    ) -> Result<CallOutcome, MxcError> {
        let address = &self.address;
        block_on(async move {
            let exchange = async {
                let io = connect(address).await?;
                unary(
                    io,
                    &address.authority(),
                    &address.token,
                    method,
                    message,
                    deadline,
                    response_limit,
                )
                .await
            };
            let give_up = async {
                match deadline {
                    Some(deadline) => tokio::time::sleep(deadline + CALL_SLACK).await,
                    None => std::future::pending().await,
                }
            };
            let cancelled = async {
                match cancellation {
                    Some(cancellation) => loop {
                        if let Err(error) = cancellation.check() {
                            break error;
                        }
                        tokio::time::sleep(CANCELLATION_POLL).await;
                    },
                    None => std::future::pending().await,
                }
            };
            tokio::select! {
                reply = exchange => reply.map(CallOutcome::Reply).map_err(|error| error.into_mxc(method)),
                () = give_up => Ok(CallOutcome::DeadlinePassed),
                error = cancelled => Err(error),
            }
        })?
    }
}

impl CallOutcome {
    /// The reply of a call whose deadline is not a workload timeout.
    fn reply(
        self,
        method: &str,
        deadline: Duration,
    ) -> Result<Result<Vec<u8>, GrpcStatus>, MxcError> {
        match self {
            Self::Reply(reply) => Ok(reply),
            Self::DeadlinePassed => Err(MxcError::backend_error(format!(
                "ACI gateway {method} did not respond within {} s",
                (deadline + CALL_SLACK).as_secs()
            ))),
        }
    }
}

fn malformed(method: &str, error: &str) -> MxcError {
    MxcError::backend_error(format!(
        "ACI gateway returned a malformed {method} response: {error}"
    ))
}

pub(super) fn capture_limit_error() -> MxcError {
    MxcError::backend_error(format!(
        "ACI gateway: combined stdout/stderr capture limit of {CAPTURE_LIMIT_BYTES} bytes exceeded"
    ))
}

/// Why a call ended without a gRPC status.
#[derive(Debug)]
enum CallError {
    Transport(String),
    Protocol(String),
    TooLarge,
}

impl CallError {
    fn into_mxc(self, method: &str) -> MxcError {
        match self {
            Self::Transport(error) => {
                MxcError::backend_error(format!("ACI gateway {method} failed: {error}"))
            }
            Self::Protocol(error) => malformed(method, &error),
            Self::TooLarge if method == "ExecSandbox" => capture_limit_error(),
            Self::TooLarge => malformed(method, "the response is too large"),
        }
    }
}

fn transport(error: impl std::fmt::Display) -> CallError {
    CallError::Transport(error.to_string())
}

/// Runs `future` on a private runtime in a scoped thread, so callers may
/// themselves be inside an async runtime.
fn block_on<F>(future: F) -> Result<F::Output, MxcError>
where
    F: Future + Send,
    F::Output: Send,
{
    std::thread::scope(|scope| {
        scope
            .spawn(|| {
                tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .map(|runtime| runtime.block_on(future))
                    .map_err(|error| {
                        MxcError::backend_error(format!(
                            "cannot start the ACI gateway client: {error}"
                        ))
                    })
            })
            .join()
            .unwrap_or_else(|_| Err(MxcError::backend_error("the ACI gateway client panicked")))
    })
}

async fn connect(
    address: &GatewayAddress,
) -> Result<tokio_native_tls::TlsStream<tokio::net::TcpStream>, CallError> {
    let tcp = tokio::time::timeout(
        CONNECT_TIMEOUT,
        tokio::net::TcpStream::connect((address.host.as_str(), address.port)),
    )
    .await
    .map_err(|_| CallError::Transport("timed out connecting to the gateway".into()))?
    .map_err(transport)?;
    let _ = tcp.set_nodelay(true);
    let connector = native_tls::TlsConnector::builder()
        .request_alpns(&["h2"])
        .build()
        .map_err(transport)?;
    let tls = tokio::time::timeout(
        CONNECT_TIMEOUT,
        tokio_native_tls::TlsConnector::from(connector).connect(&address.host, tcp),
    )
    .await
    .map_err(|_| CallError::Transport("timed out negotiating TLS with the gateway".into()))?
    .map_err(transport)?;
    match tls.get_ref().negotiated_alpn() {
        Ok(Some(protocol)) if protocol == b"h2" => Ok(tls),
        _ => Err(CallError::Transport(
            "the gateway did not negotiate HTTP/2".into(),
        )),
    }
}

/// Stops the HTTP/2 connection task when the call ends or is abandoned.
struct AbortOnDrop(tokio::task::JoinHandle<()>);

impl Drop for AbortOnDrop {
    fn drop(&mut self) {
        self.0.abort();
    }
}

/// Makes one unary gRPC call over `io` and returns the response message or
/// the non-OK status.
async fn unary<IO>(
    io: IO,
    authority: &str,
    token: &Secret,
    method: &str,
    message: &[u8],
    deadline: Option<Duration>,
    response_limit: usize,
) -> Result<Result<Vec<u8>, GrpcStatus>, CallError>
where
    IO: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let (client, connection) = h2::client::Builder::new()
        .initial_window_size(WINDOW_SIZE)
        .initial_connection_window_size(WINDOW_SIZE)
        .handshake::<_, Bytes>(io)
        .await
        .map_err(transport)?;
    let _connection = AbortOnDrop(tokio::spawn(async move {
        let _ = connection.await;
    }));
    let mut client = client.ready().await.map_err(transport)?;

    let mut request = http::Request::builder()
        .method(http::Method::POST)
        .uri(format!("https://{authority}/{SERVICE}/{method}"))
        .header(http::header::CONTENT_TYPE, "application/grpc")
        .header(http::header::TE, "trailers")
        .header(
            http::header::USER_AGENT,
            concat!("mxc/", env!("CARGO_PKG_VERSION")),
        )
        .body(())
        .map_err(|error| CallError::Protocol(error.to_string()))?;
    let mut authorization = HeaderValue::try_from(format!("Bearer {}", token.expose()))
        .map_err(|_| CallError::Protocol("the gateway token is not a valid header".into()))?;
    authorization.set_sensitive(true);
    request
        .headers_mut()
        .insert(http::header::AUTHORIZATION, authorization);
    if let Some(deadline) = deadline {
        request
            .headers_mut()
            .insert("grpc-timeout", grpc_timeout(deadline));
    }

    let (response, mut stream) = client.send_request(request, false).map_err(transport)?;
    let framed = proto::frame(message).map_err(CallError::Protocol)?;
    stream
        .send_data(Bytes::from(framed), true)
        .map_err(transport)?;
    let (parts, mut body) = response.await.map_err(transport)?.into_parts();
    if parts.status != http::StatusCode::OK {
        return Err(CallError::Transport(format!(
            "the gateway returned HTTP {}",
            parts.status
        )));
    }
    // A response without a message carries its status in the headers.
    if let Some(status) = grpc_status(&parts.headers)? {
        return Ok(status.map(|()| Vec::new()));
    }

    let limit = proto::framed_len(response_limit);
    let mut received = Vec::new();
    while let Some(chunk) = body.data().await {
        let chunk = chunk.map_err(transport)?;
        let _ = body.flow_control().release_capacity(chunk.len());
        if received.len().saturating_add(chunk.len()) > limit {
            return Err(CallError::TooLarge);
        }
        received.extend_from_slice(&chunk);
        if proto::frame_length(&received)
            .map_err(CallError::Protocol)?
            .is_some_and(|length| length > response_limit)
        {
            return Err(CallError::TooLarge);
        }
    }
    let trailers = body
        .trailers()
        .await
        .map_err(transport)?
        .unwrap_or_default();
    match grpc_status(&trailers)? {
        Some(Ok(())) => proto::unframe(&received)
            .map(|message| Ok(message.to_vec()))
            .map_err(CallError::Protocol),
        Some(Err(status)) => Ok(Err(status)),
        None => Err(CallError::Protocol(
            "the response ended without a grpc-status".into(),
        )),
    }
}

/// The `grpc-timeout` header for `deadline`, in milliseconds.
fn grpc_timeout(deadline: Duration) -> HeaderValue {
    // The header allows at most eight digits.
    let millis = deadline.as_millis().clamp(1, 99_999_999);
    HeaderValue::from_str(&format!("{millis}m")).expect("digits and a unit are a valid header")
}

/// Reads `grpc-status` and `grpc-message`, if present.
fn grpc_status(headers: &HeaderMap) -> Result<Option<Result<(), GrpcStatus>>, CallError> {
    let Some(code) = headers.get("grpc-status") else {
        return Ok(None);
    };
    let code = code
        .to_str()
        .ok()
        .and_then(|code| code.parse::<u32>().ok())
        .ok_or_else(|| CallError::Protocol("the grpc-status is not a number".into()))?;
    if code == 0 {
        return Ok(Some(Ok(())));
    }
    let message = headers
        .get("grpc-message")
        .map(|value| status_message(value.as_bytes()))
        .unwrap_or_default();
    Ok(Some(Err(GrpcStatus { code, message })))
}

/// Decodes a percent-encoded `grpc-message`. The gateway sends JSON with a
/// message and correlation ID, which are kept for support requests.
fn status_message(encoded: &[u8]) -> String {
    let mut decoded = Vec::with_capacity(encoded.len());
    let mut index = 0;
    while index < encoded.len() {
        let hex = |offset: usize| {
            encoded
                .get(index + offset)
                .and_then(|&byte| char::from(byte).to_digit(16))
        };
        match (encoded[index], hex(1), hex(2)) {
            (b'%', Some(high), Some(low)) => {
                decoded.push((high * 16 + low) as u8);
                index += 3;
            }
            (byte, _, _) => {
                decoded.push(byte);
                index += 1;
            }
        }
    }
    let text = String::from_utf8_lossy(&decoded);
    #[derive(serde::Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct Detail {
        message: Option<String>,
        correlation_id: Option<String>,
    }
    let text = match serde_json::from_str::<Detail>(&text) {
        Ok(Detail {
            message: Some(message),
            correlation_id,
        }) => match correlation_id {
            Some(id) => format!("{message} (correlation ID {id})"),
            None => message,
        },
        _ => text.into_owned(),
    };
    super::service::bounded(&text)
        .chars()
        .take(STATUS_MESSAGE_LIMIT + 3)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mxc_common::mxc_error::MxcErrorCode;

    fn address() -> GatewayAddress {
        GatewayAddress::parse(&secret(
            "address=gateway.example.com;token=eyJ0.eyJ1.sig;token_type=bearer",
        ))
        .unwrap()
    }

    fn secret(value: &str) -> Secret {
        Secret::new(value.to_owned(), "connection string").unwrap()
    }

    #[test]
    fn connection_strings_yield_the_gateway_and_token() {
        let parsed = address();
        assert_eq!(parsed.host, "gateway.example.com");
        assert_eq!(parsed.port, 443);
        assert_eq!(parsed.authority(), "gateway.example.com");
        assert_eq!(parsed.token.expose(), "eyJ0.eyJ1.sig");
        let parsed =
            GatewayAddress::parse(&secret("TOKEN=t;Address=sandbox-1.example.net:8443")).unwrap();
        assert_eq!(parsed.authority(), "sandbox-1.example.net:8443");
    }

    #[test]
    fn malformed_connection_strings_are_rejected_without_echoing_the_token() {
        for value in [
            "token=secret-token",
            "address=gateway.example.com",
            "address=gateway.example.com;token=",
            "address=gateway.example.com;token=secret-token;token_type=basic",
            "address=gateway.example.com:0;token=secret-token",
            "address=gateway.example.com:x;token=secret-token",
            "address=gate/way;token=secret-token",
            "address=-bad.example.com;token=secret-token",
            "address=user@host;token=secret-token",
            "address=;token=secret-token",
            "garbage;token=secret-token",
        ] {
            let error = GatewayAddress::parse(&secret(value)).unwrap_err();
            assert_eq!(error.code, MxcErrorCode::BackendError, "{value}");
            assert!(!error.message.contains("secret-token"), "{error}");
        }
    }

    #[test]
    fn grpc_timeouts_use_milliseconds_within_eight_digits() {
        assert_eq!(grpc_timeout(Duration::from_secs(30)), "30000m");
        assert_eq!(grpc_timeout(Duration::from_secs(3_600)), "3600000m");
        assert_eq!(grpc_timeout(Duration::ZERO), "1m");
        assert_eq!(grpc_timeout(Duration::from_secs(1_000_000)), "99999999m");
    }

    #[test]
    fn status_messages_are_decoded_and_bounded() {
        assert_eq!(
            status_message(
                b"{\"errorCode\":13,\"message\":\"An internal error occurred.\",\"correlationId\":\"c5e8\"}"
            ),
            "An internal error occurred. (correlation ID c5e8)"
        );
        assert_eq!(status_message(b"Deadline%20Exceeded"), "Deadline Exceeded");
        assert_eq!(status_message(b"100%"), "100%");
        assert!(status_message("x".repeat(5000).as_bytes()).len() <= STATUS_MESSAGE_LIMIT + 3);
    }

    #[test]
    fn statuses_map_to_mxc_errors() {
        let status = |code| GrpcStatus {
            code,
            message: "detail".to_owned(),
        };
        let unavailable = status(GRPC_UNIMPLEMENTED).into_error("ExecSandbox");
        assert_eq!(unavailable.code, MxcErrorCode::BackendUnavailable);
        assert!(unavailable.message.contains("UNIMPLEMENTED (12): detail"));
        for code in [GRPC_UNAUTHENTICATED, GRPC_PERMISSION_DENIED] {
            let error = status(code).into_error("ExecSandbox");
            assert_eq!(error.code, MxcErrorCode::BackendError);
            assert!(
                error.message.contains("rejected the sandbox token"),
                "{error}"
            );
        }
        let internal = status(13).into_error("WaitForReady");
        assert_eq!(
            internal.message,
            "ACI gateway WaitForReady failed with gRPC status INTERNAL (13): detail"
        );
    }

    /// Serves one unary call on `io` with `respond`, which returns the
    /// response headers, data, and trailers.
    async fn serve_one(
        io: tokio::io::DuplexStream,
        respond: impl FnOnce(
                http::Request<h2::RecvStream>,
                Vec<u8>,
            ) -> (http::response::Builder, Option<Vec<u8>>, Option<HeaderMap>)
            + Send
            + 'static,
    ) {
        let mut connection = h2::server::handshake(io).await.unwrap();
        let (mut request, mut responder) = connection.accept().await.unwrap().unwrap();
        let driver = tokio::spawn(async move { while connection.accept().await.is_some() {} });
        let mut body = Vec::new();
        while let Some(chunk) = request.body_mut().data().await {
            let chunk = chunk.unwrap();
            let _ = request
                .body_mut()
                .flow_control()
                .release_capacity(chunk.len());
            body.extend_from_slice(&chunk);
        }
        let (builder, data, trailers) = respond(request, body);
        let end_after_headers = data.is_none() && trailers.is_none();
        let mut stream = responder
            .send_response(builder.body(()).unwrap(), end_after_headers)
            .unwrap();
        if let Some(data) = data {
            stream
                .send_data(Bytes::from(data), trailers.is_none())
                .unwrap();
        }
        if let Some(trailers) = trailers {
            stream.send_trailers(trailers).unwrap();
        }
        // Keep the connection alive until the client finishes reading.
        let _ = tokio::time::timeout(Duration::from_secs(5), driver).await;
    }

    fn ok_trailers() -> HeaderMap {
        let mut trailers = HeaderMap::new();
        trailers.insert("grpc-status", HeaderValue::from_static("0"));
        trailers
    }

    fn grpc_response() -> http::response::Builder {
        http::Response::builder()
            .status(200)
            .header("content-type", "application/grpc")
    }

    async fn call_local(
        method: &'static str,
        message: Vec<u8>,
        deadline: Option<Duration>,
        limit: usize,
        respond: impl FnOnce(
                http::Request<h2::RecvStream>,
                Vec<u8>,
            ) -> (http::response::Builder, Option<Vec<u8>>, Option<HeaderMap>)
            + Send
            + 'static,
    ) -> Result<Result<Vec<u8>, GrpcStatus>, CallError> {
        let (client, server) = tokio::io::duplex(1 << 20);
        let server = tokio::spawn(serve_one(server, respond));
        let token = Secret::new("eyJ0.eyJ1.sig".to_owned(), "token").unwrap();
        let reply = unary(
            client,
            "gateway.example.com",
            &token,
            method,
            &message,
            deadline,
            limit,
        )
        .await;
        server.abort();
        reply
    }

    #[tokio::test]
    async fn unary_calls_send_grpc_headers_and_decode_the_reply() {
        let request = ExecSandboxRequest {
            command: "/bin/sh".to_owned(),
            args: vec!["-c".to_owned(), "echo hi".to_owned()],
            working_directory: None,
            environment: Vec::new(),
            timeout_seconds: Some(5),
        };
        let expected_body = proto::frame(&request.encode()).unwrap();
        let response = ExecSandboxResponse {
            exit_code: 3,
            stdout: b"hi\n".to_vec(),
            stderr: b"err\n".to_vec(),
            timed_out: false,
        };
        let response_message = proto::tests::encode_exec_response(&response);
        let reply = call_local(
            "ExecSandbox",
            request.encode(),
            Some(Duration::from_secs(5)),
            CAPTURE_LIMIT_BYTES,
            move |request, body| {
                assert_eq!(request.method(), http::Method::POST);
                assert_eq!(
                    request.uri().path(),
                    "/aci.sandboxgateway.SandboxGatewayService/ExecSandbox"
                );
                let headers = request.headers();
                assert_eq!(headers["content-type"], "application/grpc");
                assert_eq!(headers["te"], "trailers");
                assert_eq!(headers["authorization"], "Bearer eyJ0.eyJ1.sig");
                assert_eq!(headers["grpc-timeout"], "5000m");
                assert_eq!(body, expected_body);
                (
                    grpc_response(),
                    Some(proto::frame(&response_message).unwrap()),
                    Some(ok_trailers()),
                )
            },
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(ExecSandboxResponse::decode(&reply).unwrap(), response);
    }

    #[tokio::test]
    async fn statuses_in_headers_or_trailers_are_reported() {
        let reply = call_local("ExecSandbox", Vec::new(), None, 1024, |_, _| {
            (
                grpc_response()
                    .header("grpc-status", "4")
                    .header("grpc-message", "Deadline Exceeded"),
                None,
                None,
            )
        })
        .await
        .unwrap();
        assert_eq!(
            reply,
            Err(GrpcStatus {
                code: GRPC_DEADLINE_EXCEEDED,
                message: "Deadline Exceeded".to_owned()
            })
        );

        let reply = call_local("WaitForReady", Vec::new(), None, 1024, |_, _| {
            let mut trailers = HeaderMap::new();
            trailers.insert("grpc-status", HeaderValue::from_static("13"));
            trailers.insert(
                "grpc-message",
                HeaderValue::from_static("%7B%22message%22:%22An internal error occurred.%22%7D"),
            );
            (grpc_response(), Some(Vec::new()), Some(trailers))
        })
        .await
        .unwrap();
        assert_eq!(reply.unwrap_err().message, "An internal error occurred.");
    }

    #[tokio::test]
    async fn oversized_or_malformed_responses_fail() {
        let error = call_local("ExecSandbox", Vec::new(), None, 16, |_, _| {
            (
                grpc_response(),
                Some(proto::frame(&[0u8; 64]).unwrap()),
                Some(ok_trailers()),
            )
        })
        .await
        .unwrap_err();
        assert!(matches!(error, CallError::TooLarge), "{error:?}");

        let error = call_local("ExecSandbox", Vec::new(), None, 1024, |_, _| {
            (
                grpc_response(),
                Some(vec![0, 0, 0, 0, 9, 1]),
                Some(ok_trailers()),
            )
        })
        .await
        .unwrap_err();
        assert!(matches!(error, CallError::Protocol(_)), "{error:?}");

        let error = call_local("ExecSandbox", Vec::new(), None, 1024, |_, _| {
            (grpc_response(), Some(proto::frame(&[]).unwrap()), None)
        })
        .await
        .unwrap_err();
        assert!(matches!(error, CallError::Protocol(_)), "{error:?}");

        let error = call_local("ExecSandbox", Vec::new(), None, 1024, |_, _| {
            (http::Response::builder().status(503), None, None)
        })
        .await
        .unwrap_err();
        assert!(
            matches!(&error, CallError::Transport(message) if message.contains("503")),
            "{error:?}"
        );
    }

    #[test]
    fn block_on_works_inside_an_async_runtime() {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let value = runtime.block_on(async { block_on(async { 7 }).unwrap() });
        assert_eq!(value, 7);
    }

    #[test]
    fn exec_honors_cancellation_while_waiting_for_the_gateway() {
        // A TEST-NET address never answers, so only cancellation ends the call.
        let gateway =
            Gateway::new(GatewayAddress::parse(&secret("address=192.0.2.1:9;token=t")).unwrap());
        let cancellation = RunCancellation::default();
        assert!(cancellation.request());
        let request = ExecSandboxRequest {
            command: "/bin/sh".to_owned(),
            args: Vec::new(),
            working_directory: None,
            environment: Vec::new(),
            timeout_seconds: None,
        };
        let started = std::time::Instant::now();
        let error = gateway
            .exec(&request, None, Some(&cancellation))
            .unwrap_err();
        assert_eq!(error.message, "execution cancelled");
        assert!(cancellation.was_cancelled());
        assert!(started.elapsed() < Duration::from_secs(5));
    }

    #[test]
    fn calls_that_outlive_their_deadline_are_reported() {
        let error = CallOutcome::DeadlinePassed
            .reply("GetSandbox", Duration::from_secs(30))
            .unwrap_err();
        assert_eq!(error.code, MxcErrorCode::BackendError);
        assert_eq!(
            error.message,
            "ACI gateway GetSandbox did not respond within 40 s"
        );
    }
}
