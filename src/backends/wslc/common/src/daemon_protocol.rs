// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Control protocol between a `wxc-exec` phase process and the long-lived
//! `wxc-wslc-daemon`.
//!
//! State-aware WSLc runs each lifecycle phase (provision / start / exec / stop /
//! deprovision) as a **separate** short-lived `wxc-exec` process, but the WSLc
//! SDK has no cross-process re-attach: `WslcSession` / `WslcContainer` handles
//! are obtainable only via `WslcCreate*` and are in-process. A persistent
//! per-user daemon therefore owns the handles, and the phase processes drive it
//! over this protocol.
//!
//! # Framing
//! Every message is length-prefixed: a 4-byte little-endian `u32` frame length
//! followed by that many bytes of JSON ([`serde_json`]). The same framing
//! carries both the control frames ([`DaemonRequest`] / [`DaemonResponse`]) and
//! the exec data-phase [`StreamFrame`]s, so the wire has a single, trivially
//! testable structure.
//!
//! # Layering
//! These are the daemon's **own internal** config structs, deliberately
//! separate from the public `experimental.wslc.*` wire schema. The state-aware
//! backend (a later PR) is the translator between the public wire model and
//! this protocol; keeping them decoupled lets the daemon + IPC ship and be
//! fully tested without touching the wire schema or its CI gates.

use serde::de::DeserializeOwned;
use serde::ser::Error as _;
use serde::{Deserialize, Serialize};

/// Upper bound on a single decoded frame (16 MiB). Guards the decoder against a
/// hostile or corrupt length prefix demanding an unbounded allocation.
pub const MAX_FRAME_SIZE: usize = 16 * 1024 * 1024;

/// Control-channel wire-protocol version. The daemon and client are shipped
/// from the same build, so in normal operation both sides always match; the
/// version guards against a stale daemon left running by a different mxc
/// install. Bump only for incompatible changes to framing or message shape.
pub const PROTOCOL_VERSION: u32 = 3;

// ---------------------------------------------------------------------------
// Per-phase config structs (daemon-internal; NOT the public wire schema)
// ---------------------------------------------------------------------------

/// One host→container directory mount, mirroring the one-shot runner's volume
/// handling. Paths are host-absolute; `container` is the in-container mount
/// point.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VolumeMount {
    pub host: String,
    pub container: String,
    pub read_only: bool,
}

/// One host→container port forward, mirroring the one-shot runner's port
/// handling. Only TCP is supported today (the wire model rejects `udp`), so no
/// protocol field is carried — the daemon programs every entry as TCP.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PortMapping {
    pub windows_port: u16,
    pub container_port: u16,
}

/// Container network mode. Mirrors exactly what the one-shot WSLc runner
/// supports — no host-filtering / egress allow-deny (the SDK grants no
/// `CAP_NET_ADMIN` and cannot give VM-level enforcement without breaking other
/// security promises, so there is no iptables path).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NetworkMode {
    /// Isolated: no container networking.
    #[default]
    None,
    /// Bridged (NAT) networking.
    Bridged,
}

/// Inputs to `provision`: ensure the shared session (booting the WSL2 utility VM
/// on first provision), resolve the image, and create the container. Mirrors the
/// session/container-level fields of the one-shot `WslcConfig` plus the
/// container's volume and network policy.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProvisionConfig {
    /// Container image reference (e.g. `alpine:latest`).
    pub image: String,
    /// Optional local tar to import as the image instead of pulling.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub image_tar_path: Option<String>,
    /// Host↔container directory mounts.
    #[serde(default)]
    pub volumes: Vec<VolumeMount>,
    /// Container network mode.
    #[serde(default)]
    pub network: NetworkMode,
    /// Host↔container port forwards (TCP). Empty = no forwarding.
    #[serde(default)]
    pub port_mappings: Vec<PortMapping>,
}

/// Inputs to `start`: the container was created at provision; start boots it.
/// Carries only the sandbox id — network/volume policy is immutable post-provision.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StartConfig {
    pub sandbox_id: String,
}

/// Inputs to `exec`: run one command in the started container and stream its
/// stdio back over the pipe.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExecConfig {
    pub sandbox_id: String,
    /// Command line to run inside the container (shell-interpreted, mirroring
    /// the one-shot runner's `script_code`).
    pub script_code: String,
    /// Working directory inside the container (empty = container default).
    #[serde(default)]
    pub working_directory: String,
    /// Environment variables applied to the process, as `(name, value)` pairs.
    #[serde(default)]
    pub env: Vec<(String, String)>,
    /// Timeout in milliseconds (0 = no timeout).
    #[serde(default)]
    pub timeout_ms: u32,
}

/// Inputs to `stop`: stop the running container, keeping it created for a later
/// `start`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StopConfig {
    pub sandbox_id: String,
}

/// Inputs to `deprovision`: delete the container and drop its refcount; the
/// daemon releases the shared session once the last container is gone.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeprovisionConfig {
    pub sandbox_id: String,
}

// ---------------------------------------------------------------------------
// Control frames
// ---------------------------------------------------------------------------

/// A control request sent by a phase process to the daemon.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum DaemonRequest {
    /// Ensure session + create container. Replies [`DaemonResponse::Provisioned`].
    Provision(ProvisionConfig),
    /// Boot the created container. Replies [`DaemonResponse::Ok`].
    Start(StartConfig),
    /// Run a command and stream its stdio. After an [`DaemonResponse::Ok`]
    /// admission, both sides exchange [`StreamFrame`]s until [`StreamFrame::Exit`].
    Exec(ExecConfig),
    /// Stop the running container. Replies [`DaemonResponse::Ok`].
    Stop(StopConfig),
    /// Delete the container (refcount--). Replies [`DaemonResponse::Ok`].
    Deprovision(DeprovisionConfig),
    /// Liveness probe. Replies [`DaemonResponse::Pong`].
    Ping,
}

/// The daemon's reply to a [`DaemonRequest`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum DaemonResponse {
    /// `provision` succeeded; carries the minted sandbox id (the addressable
    /// handle a later phase presents).
    Provisioned { sandbox_id: String },
    /// Generic success (start / stop / deprovision, and exec admission).
    Ok,
    /// Reply to [`DaemonRequest::Ping`].
    Pong,
    /// The request failed or was refused. `kind` is a stable machine-readable
    /// token (see [`ErrKind`]); `message` is human-readable detail.
    Err { kind: ErrKind, message: String },
}

/// Stable, machine-readable classification of a [`DaemonResponse::Err`], so the
/// client can map daemon failures onto the appropriate `MxcError` variant
/// without string-matching.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ErrKind {
    /// The referenced sandbox id is unknown to the daemon.
    NotProvisioned,
    /// The sandbox exists but is not in a state that permits the request
    /// (e.g. exec before start).
    NotStarted,
    /// Another exec already holds the container's single-flight slot.
    Busy,
    /// The container/session is still coming up.
    NotReady,
    /// The client speaks a different protocol version than this daemon.
    Protocol,
    /// A backend/SDK-level failure while servicing the request.
    Backend,
}

// ---------------------------------------------------------------------------
// Exec data-phase stream frames
// ---------------------------------------------------------------------------

/// A frame exchanged during the exec data phase (after an admitted
/// [`DaemonRequest::Exec`]). Client→daemon carries [`StreamFrame::Stdin`];
/// daemon→client carries [`StreamFrame::Stdout`] / [`StreamFrame::Stderr`] and
/// a terminal [`StreamFrame::Exit`] (or [`StreamFrame::Error`]).
///
/// The raw byte payloads are base64-encoded on the wire (see [`base64_bytes`]).
/// serde_json renders a `Vec<u8>` as a JSON array of decimal integers (`[104,
/// 105, ...]`), roughly **4 bytes of wire per payload byte**, and since
/// [`MAX_FRAME_SIZE`] is measured against the *encoded* frame that would cut
/// effective throughput to ~1/4. base64 is ~1.33x instead, while keeping the
/// single uniform JSON framing (no separate binary path to test).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum StreamFrame {
    /// Client→daemon: bytes to write to the process stdin. An empty payload
    /// signals stdin EOF.
    Stdin {
        #[serde(with = "base64_bytes")]
        data: Vec<u8>,
    },
    /// Daemon→client: bytes read from the process stdout.
    Stdout {
        #[serde(with = "base64_bytes")]
        data: Vec<u8>,
    },
    /// Daemon→client: bytes read from the process stderr.
    Stderr {
        #[serde(with = "base64_bytes")]
        data: Vec<u8>,
    },
    /// Daemon→client: terminal frame; the process exited with `code`. No more
    /// stream frames follow.
    Exit { code: i32 },
    /// Daemon→client: terminal frame; the exec failed before or during the run.
    Error { message: String },
}

/// serde adapter that (de)serializes a `Vec<u8>` as a base64 string rather than
/// a JSON integer array. Used for the [`StreamFrame`] byte payloads to keep the
/// exec data phase compact over the wire.
mod base64_bytes {
    use base64::{engine::general_purpose::STANDARD, Engine as _};
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(bytes: &[u8], serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&STANDARD.encode(bytes))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Vec<u8>, D::Error> {
        let encoded = String::deserialize(deserializer)?;
        STANDARD.decode(&encoded).map_err(serde::de::Error::custom)
    }
}

// ---------------------------------------------------------------------------
// Framing helpers (generic over any serde message type)
// ---------------------------------------------------------------------------

/// Serialize `msg` into a length-prefixed frame: `[len: u32 LE][json: len bytes]`.
pub fn encode_frame<T: Serialize>(msg: &T) -> Result<Vec<u8>, serde_json::Error> {
    let json = serde_json::to_vec(msg)?;
    if json.len() > MAX_FRAME_SIZE {
        return Err(serde_json::Error::custom(
            "message too large for protocol framing",
        ));
    }
    let len = json.len() as u32;
    let mut frame = Vec::with_capacity(4 + json.len());
    frame.extend_from_slice(&len.to_le_bytes());
    frame.extend_from_slice(&json);
    Ok(frame)
}

/// Result of attempting to decode one frame from the front of a byte buffer.
#[derive(Debug, PartialEq, Eq)]
pub enum DecodeResult<T> {
    /// A complete message was decoded; drain `consumed` bytes from the front of
    /// the buffer before decoding again.
    Message { message: T, consumed: usize },
    /// The buffer does not yet hold a full frame; read more bytes and retry.
    Incomplete,
}

/// Try to decode one message of type `T` from the front of `buf`.
///
/// Returns [`DecodeResult::Incomplete`] when fewer than `4 + len` bytes are
/// present. A length prefix exceeding [`MAX_FRAME_SIZE`] is a hard error rather
/// than an unbounded wait.
pub fn decode_frame<T: DeserializeOwned>(buf: &[u8]) -> Result<DecodeResult<T>, serde_json::Error> {
    if buf.len() < 4 {
        return Ok(DecodeResult::Incomplete);
    }
    let len = u32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]) as usize;
    if len > MAX_FRAME_SIZE {
        return Err(serde_json::Error::custom("frame length exceeds maximum"));
    }
    let total = 4 + len;
    if buf.len() < total {
        return Ok(DecodeResult::Incomplete);
    }
    let message: T = serde_json::from_slice(&buf[4..total])?;
    Ok(DecodeResult::Message {
        message,
        consumed: total,
    })
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn roundtrip<T>(msg: T)
    where
        T: Serialize + DeserializeOwned + PartialEq + std::fmt::Debug,
    {
        let frame = encode_frame(&msg).unwrap();
        match decode_frame::<T>(&frame).unwrap() {
            DecodeResult::Message { message, consumed } => {
                assert_eq!(message, msg);
                assert_eq!(consumed, frame.len());
            }
            DecodeResult::Incomplete => panic!("expected a complete message"),
        }
    }

    #[test]
    fn roundtrip_provision() {
        roundtrip(DaemonRequest::Provision(ProvisionConfig {
            image: "alpine:latest".to_string(),
            image_tar_path: Some(r"C:\images\alpine.tar".to_string()),
            volumes: vec![VolumeMount {
                host: r"C:\work".to_string(),
                container: "/work".to_string(),
                read_only: true,
            }],
            network: NetworkMode::Bridged,
            port_mappings: vec![PortMapping {
                windows_port: 8080,
                container_port: 80,
            }],
        }));
    }

    #[test]
    fn roundtrip_each_request_variant() {
        roundtrip(DaemonRequest::Start(StartConfig {
            sandbox_id: "wslc:abc123".to_string(),
        }));
        roundtrip(DaemonRequest::Exec(ExecConfig {
            sandbox_id: "wslc:abc123".to_string(),
            script_code: "echo hi".to_string(),
            working_directory: "/work".to_string(),
            env: vec![("PATH".to_string(), "/usr/bin".to_string())],
            timeout_ms: 30_000,
        }));
        roundtrip(DaemonRequest::Stop(StopConfig {
            sandbox_id: "wslc:abc123".to_string(),
        }));
        roundtrip(DaemonRequest::Deprovision(DeprovisionConfig {
            sandbox_id: "wslc:abc123".to_string(),
        }));
        roundtrip(DaemonRequest::Ping);
    }

    #[test]
    fn roundtrip_each_response_variant() {
        roundtrip(DaemonResponse::Provisioned {
            sandbox_id: "wslc:abc123".to_string(),
        });
        roundtrip(DaemonResponse::Ok);
        roundtrip(DaemonResponse::Pong);
        for kind in [
            ErrKind::NotProvisioned,
            ErrKind::NotStarted,
            ErrKind::Busy,
            ErrKind::NotReady,
            ErrKind::Protocol,
            ErrKind::Backend,
        ] {
            roundtrip(DaemonResponse::Err {
                kind,
                message: "detail".to_string(),
            });
        }
    }

    #[test]
    fn roundtrip_stream_frames() {
        roundtrip(StreamFrame::Stdin {
            data: b"input".to_vec(),
        });
        roundtrip(StreamFrame::Stdout {
            data: b"out".to_vec(),
        });
        roundtrip(StreamFrame::Stderr {
            data: b"err".to_vec(),
        });
        roundtrip(StreamFrame::Exit { code: 42 });
        roundtrip(StreamFrame::Error {
            message: "spawn failed".to_string(),
        });
    }

    #[test]
    fn stream_frame_bytes_roundtrip_including_non_utf8() {
        // Arbitrary bytes (incl. non-UTF8, NUL, 0xFF) must survive the base64
        // wire encoding exactly.
        let raw: Vec<u8> = (0u16..=255).map(|b| b as u8).collect();
        roundtrip(StreamFrame::Stdout { data: raw.clone() });
        roundtrip(StreamFrame::Stderr { data: raw.clone() });
        roundtrip(StreamFrame::Stdin { data: raw });
    }

    #[test]
    fn stream_frame_payload_is_base64_not_integer_array() {
        // Guards the compact wire encoding: the payload is a base64 string, not
        // serde_json's default `[104, 105, ...]` integer array (~4x larger).
        let json = serde_json::to_string(&StreamFrame::Stdout {
            data: b"hi".to_vec(),
        })
        .unwrap();
        assert!(
            json.contains("\"data\":\"aGk=\""),
            "unexpected wire: {json}"
        );
        assert!(
            !json.contains('['),
            "payload must not be an integer array: {json}"
        );
    }

    #[test]
    fn network_mode_defaults_to_none() {
        assert_eq!(NetworkMode::default(), NetworkMode::None);
    }

    #[test]
    fn decode_incomplete_header() {
        let r: DecodeResult<DaemonRequest> = decode_frame(&[0u8; 3]).unwrap();
        assert_eq!(r, DecodeResult::Incomplete);
    }

    #[test]
    fn decode_incomplete_body() {
        // Header claims 100 bytes; only 10 present.
        let mut buf = Vec::new();
        buf.extend_from_slice(&100u32.to_le_bytes());
        buf.extend_from_slice(&[0u8; 10]);
        let r: DecodeResult<DaemonRequest> = decode_frame(&buf).unwrap();
        assert_eq!(r, DecodeResult::Incomplete);
    }

    #[test]
    fn decode_empty_buffer_is_incomplete() {
        let r: DecodeResult<DaemonRequest> = decode_frame(&[]).unwrap();
        assert_eq!(r, DecodeResult::Incomplete);
    }

    #[test]
    fn decode_rejects_oversized_length_prefix() {
        let mut buf = Vec::new();
        buf.extend_from_slice(&(MAX_FRAME_SIZE as u32 + 1).to_le_bytes());
        let r: Result<DecodeResult<DaemonRequest>, _> = decode_frame(&buf);
        assert!(r.is_err());
    }

    #[test]
    fn frame_length_prefix_matches_payload() {
        let frame = encode_frame(&DaemonRequest::Ping).unwrap();
        let declared = u32::from_le_bytes([frame[0], frame[1], frame[2], frame[3]]) as usize;
        assert_eq!(declared, frame.len() - 4);
    }

    #[test]
    fn two_frames_decode_sequentially() {
        let f1 = encode_frame(&DaemonRequest::Ping).unwrap();
        let f2 = encode_frame(&DaemonResponse::Pong).unwrap();
        let mut buf = Vec::new();
        buf.extend_from_slice(&f1);
        buf.extend_from_slice(&f2);

        let consumed = match decode_frame::<DaemonRequest>(&buf).unwrap() {
            DecodeResult::Message { message, consumed } => {
                assert_eq!(message, DaemonRequest::Ping);
                consumed
            }
            DecodeResult::Incomplete => panic!("expected first frame"),
        };
        match decode_frame::<DaemonResponse>(&buf[consumed..]).unwrap() {
            DecodeResult::Message {
                message,
                consumed: c2,
            } => {
                assert_eq!(message, DaemonResponse::Pong);
                assert_eq!(consumed + c2, buf.len());
            }
            DecodeResult::Incomplete => panic!("expected second frame"),
        }
    }

    #[test]
    fn decode_rejects_malformed_json_body() {
        let mut buf = Vec::new();
        let body = b"{ not json";
        buf.extend_from_slice(&(body.len() as u32).to_le_bytes());
        buf.extend_from_slice(body);
        let r: Result<DecodeResult<DaemonRequest>, _> = decode_frame(&buf);
        assert!(r.is_err());
    }
}
