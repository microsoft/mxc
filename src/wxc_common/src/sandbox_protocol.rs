//! Control protocol shared between the sandbox daemon and guest agent.
//!
//! All messages are length-prefixed: a 4-byte little-endian `u32` frame length
//! followed by that many bytes of JSON (serde_json).  This keeps the framing
//! trivial while still allowing structured payloads.

use serde::ser::Error as _;
use serde::{Deserialize, Serialize};

const MAX_FRAME_SIZE: usize = 16 * 1024 * 1024; // 16 MB

// ---------------------------------------------------------------------------
// Message types
// ---------------------------------------------------------------------------

/// Envelope sent on the **control** channel.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "type")]
pub enum ControlMessage {
    /// Agent → Host: the sandbox is ready to accept EXEC commands.
    Ready,

    /// Host → Agent: execute a script.
    Exec(ExecRequest),

    /// Agent → Host: script finished.
    Exit(ExitNotification),

    /// Agent → Host: new data streams are ready to be connected.
    ///
    /// Sent after the agent has re-opened its TCP listener for the next
    /// set of stdin/stdout/stderr connections following an [`Exit`].
    StreamsReady,

    /// Either direction: keepalive probe.
    Ping,

    /// Either direction: keepalive reply.
    Pong,
}

/// Payload for [`ControlMessage::Exec`].
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ExecRequest {
    /// Unique identifier correlating the stdin/stdout/stderr connections.
    pub exec_id: String,
    /// Command line to execute (e.g. `python -c "print('hi')"`).
    pub script_code: String,
    /// Working directory inside the sandbox (empty = agent default).
    pub working_directory: String,
    /// Timeout in milliseconds (0 = no timeout).
    pub timeout_ms: u32,
}

/// Payload for [`ControlMessage::Exit`].
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ExitNotification {
    /// Correlates with the original [`ExecRequest::exec_id`].
    pub exec_id: String,
    /// Process exit code (negative values indicate error/timeout).
    pub exit_code: i32,
    /// Optional error message (e.g. if the process could not be spawned).
    pub error_message: String,
}

// ---------------------------------------------------------------------------
// Framing helpers
// ---------------------------------------------------------------------------

/// Serialize a [`ControlMessage`] into a length-prefixed frame.
///
/// Layout: `[len: u32 LE][json: len bytes]`
pub fn encode_message(msg: &ControlMessage) -> Result<Vec<u8>, serde_json::Error> {
    let json = serde_json::to_vec(msg)?;
    if json.len() > u32::MAX as usize {
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

/// Result of attempting to decode a frame from a byte buffer.
#[derive(Debug, PartialEq, Eq)]
pub enum DecodeResult {
    /// A complete message was decoded; `consumed` bytes should be drained
    /// from the front of the buffer.
    Message {
        message: ControlMessage,
        consumed: usize,
    },
    /// The buffer does not yet contain a full frame.
    Incomplete,
}

/// Try to decode one [`ControlMessage`] from the front of `buf`.
///
/// Returns [`DecodeResult::Incomplete`] if fewer than `4 + len` bytes are
/// available.  On success the caller should drain `consumed` bytes from
/// the buffer before calling again.
pub fn decode_message(buf: &[u8]) -> Result<DecodeResult, serde_json::Error> {
    if buf.len() < 4 {
        return Ok(DecodeResult::Incomplete);
    }
    let len = u32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]) as usize;
    if len > MAX_FRAME_SIZE {
        return Err(serde_json::Error::custom("frame too large"));
    }
    let total = 4 + len;
    if buf.len() < total {
        return Ok(DecodeResult::Incomplete);
    }
    let message: ControlMessage = serde_json::from_slice(&buf[4..total])?;
    Ok(DecodeResult::Message {
        message,
        consumed: total,
    })
}

// ---------------------------------------------------------------------------
// Daemon IPC result (line-based protocol between wxc-exec and daemon)
// ---------------------------------------------------------------------------

/// Placeholder for empty base64 fields in the RESULT protocol line.
/// Avoids ambiguous whitespace splitting when stdout or stderr is empty.
const EMPTY_BASE64_PLACEHOLDER: &str = "-";

/// Result sent from the daemon to wxc-exec over the IPC channel.
///
/// Wire format: `RESULT <exit-code> <stdout-b64> <stderr-b64> [error-message]\n`
/// Empty stdout/stderr fields are represented as `"-"`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DaemonResult {
    pub exit_code: i32,
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
    pub error_message: String,
}

impl DaemonResult {
    /// Format as a protocol line for sending over IPC.
    pub fn to_line(&self) -> String {
        let stdout_b64 = if self.stdout.is_empty() {
            EMPTY_BASE64_PLACEHOLDER.to_string()
        } else {
            crate::string_util::base64_encode(&self.stdout)
        };
        let stderr_b64 = if self.stderr.is_empty() {
            EMPTY_BASE64_PLACEHOLDER.to_string()
        } else {
            crate::string_util::base64_encode(&self.stderr)
        };
        format!(
            "RESULT {} {} {} {}\n",
            self.exit_code, stdout_b64, stderr_b64, self.error_message
        )
    }

    /// Parse a protocol line received from the daemon.
    ///
    /// Expects format: `RESULT <exit-code> <stdout-b64> <stderr-b64> [error-message]`
    /// (without the trailing newline — caller should trim first).
    pub fn parse(line: &str) -> Result<Self, String> {
        let rest = line
            .strip_prefix("RESULT ")
            .ok_or_else(|| format!("expected RESULT prefix, got: {}", line))?;

        let parts: Vec<&str> = rest.splitn(4, ' ').collect();
        if parts.len() < 3 {
            return Err(format!(
                "malformed RESULT: expected at least 3 fields, got {}",
                parts.len()
            ));
        }

        let exit_code = parts[0].parse::<i32>().unwrap_or(-1);
        let stdout = decode_base64_field(parts[1]);
        let stderr = decode_base64_field(parts[2]);
        let error_message = if parts.len() == 4 {
            parts[3].to_string()
        } else {
            String::new()
        };

        Ok(Self {
            exit_code,
            stdout,
            stderr,
            error_message,
        })
    }
}

/// Decode a base64 field, returning empty Vec for the placeholder.
fn decode_base64_field(field: &str) -> Vec<u8> {
    if field == EMPTY_BASE64_PLACEHOLDER {
        return Vec::new();
    }
    crate::string_util::base64_decode(field).unwrap_or_default()
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_ready() {
        let msg = ControlMessage::Ready;
        let frame = encode_message(&msg).unwrap();
        let result = decode_message(&frame).unwrap();
        assert_eq!(
            result,
            DecodeResult::Message {
                message: msg,
                consumed: frame.len(),
            }
        );
    }

    #[test]
    fn roundtrip_exec() {
        let msg = ControlMessage::Exec(ExecRequest {
            exec_id: "abc-123".to_string(),
            script_code: "python -c \"print('hello')\"".to_string(),
            working_directory: "C:\\temp".to_string(),
            timeout_ms: 30000,
        });
        let frame = encode_message(&msg).unwrap();
        let result = decode_message(&frame).unwrap();
        assert_eq!(
            result,
            DecodeResult::Message {
                message: msg,
                consumed: frame.len(),
            }
        );
    }

    #[test]
    fn roundtrip_exit() {
        let msg = ControlMessage::Exit(ExitNotification {
            exec_id: "abc-123".to_string(),
            exit_code: 42,
            error_message: String::new(),
        });
        let frame = encode_message(&msg).unwrap();
        let result = decode_message(&frame).unwrap();
        assert_eq!(
            result,
            DecodeResult::Message {
                message: msg,
                consumed: frame.len(),
            }
        );
    }

    #[test]
    fn roundtrip_exit_with_error() {
        let msg = ControlMessage::Exit(ExitNotification {
            exec_id: "err-1".to_string(),
            exit_code: -1,
            error_message: "spawn failed: file not found".to_string(),
        });
        let frame = encode_message(&msg).unwrap();
        let result = decode_message(&frame).unwrap();
        assert_eq!(
            result,
            DecodeResult::Message {
                message: msg,
                consumed: frame.len(),
            }
        );
    }

    #[test]
    fn roundtrip_streams_ready() {
        let msg = ControlMessage::StreamsReady;
        let frame = encode_message(&msg).unwrap();
        let result = decode_message(&frame).unwrap();
        assert_eq!(
            result,
            DecodeResult::Message {
                message: msg,
                consumed: frame.len(),
            }
        );
    }

    #[test]
    fn roundtrip_ping_pong() {
        for msg in [ControlMessage::Ping, ControlMessage::Pong] {
            let frame = encode_message(&msg).unwrap();
            let result = decode_message(&frame).unwrap();
            assert_eq!(
                result,
                DecodeResult::Message {
                    message: msg,
                    consumed: frame.len(),
                }
            );
        }
    }

    #[test]
    fn decode_incomplete_header() {
        assert_eq!(decode_message(&[0u8; 3]).unwrap(), DecodeResult::Incomplete);
    }

    #[test]
    fn decode_incomplete_body() {
        // Header says 100 bytes, but we only have 10.
        let mut buf = Vec::new();
        buf.extend_from_slice(&100u32.to_le_bytes());
        buf.extend_from_slice(&[0u8; 10]);
        assert_eq!(decode_message(&buf).unwrap(), DecodeResult::Incomplete);
    }

    #[test]
    fn decode_empty_buffer() {
        assert_eq!(decode_message(&[]).unwrap(), DecodeResult::Incomplete);
    }

    #[test]
    fn multiple_messages_in_buffer() {
        let msg1 = ControlMessage::Ping;
        let msg2 = ControlMessage::Pong;
        let frame1 = encode_message(&msg1).unwrap();
        let frame2 = encode_message(&msg2).unwrap();

        let mut buf = Vec::new();
        buf.extend_from_slice(&frame1);
        buf.extend_from_slice(&frame2);

        // Decode first message.
        let result1 = decode_message(&buf).unwrap();
        let consumed1 = match &result1 {
            DecodeResult::Message { consumed, .. } => *consumed,
            _ => panic!("expected message"),
        };
        assert_eq!(
            result1,
            DecodeResult::Message {
                message: msg1,
                consumed: consumed1,
            }
        );

        // Decode second message from remaining buffer.
        let result2 = decode_message(&buf[consumed1..]).unwrap();
        assert_eq!(
            result2,
            DecodeResult::Message {
                message: msg2,
                consumed: buf.len() - consumed1,
            }
        );
    }

    #[test]
    fn frame_length_is_correct() {
        let msg = ControlMessage::Exec(ExecRequest {
            exec_id: "x".to_string(),
            script_code: "echo hi".to_string(),
            working_directory: String::new(),
            timeout_ms: 0,
        });
        let frame = encode_message(&msg).unwrap();

        // First 4 bytes = LE u32 length of the JSON payload.
        let declared_len = u32::from_le_bytes([frame[0], frame[1], frame[2], frame[3]]) as usize;
        assert_eq!(declared_len, frame.len() - 4);
    }

    #[test]
    fn daemon_result_roundtrip_with_output() {
        let result = DaemonResult {
            exit_code: 0,
            stdout: b"hello world".to_vec(),
            stderr: b"some warning".to_vec(),
            error_message: String::new(),
        };
        let line = result.to_line();
        let parsed = DaemonResult::parse(line.trim()).unwrap();
        assert_eq!(parsed, result);
    }

    #[test]
    fn daemon_result_roundtrip_empty_output() {
        let result = DaemonResult {
            exit_code: 42,
            stdout: Vec::new(),
            stderr: Vec::new(),
            error_message: "something failed".to_string(),
        };
        let line = result.to_line();
        let parsed = DaemonResult::parse(line.trim()).unwrap();
        assert_eq!(parsed, result);
    }

    #[test]
    fn daemon_result_parse_rejects_malformed() {
        assert!(DaemonResult::parse("RESULT 0").is_err());
        assert!(DaemonResult::parse("ERROR something").is_err());
        assert!(DaemonResult::parse("garbage").is_err());
    }
}
