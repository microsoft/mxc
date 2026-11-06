// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Protobuf encoding for the `aci.sandboxgateway.SandboxGatewayService`
//! messages that MXC uses, and gRPC message framing.
//!
//! Only the fields MXC reads or writes are modeled. Decoding skips unknown
//! fields, as protobuf requires, and rejects truncated or malformed input.

/// The gRPC length-prefixed message header: a compression flag and a
/// big-endian 32-bit length.
const FRAME_HEADER_LEN: usize = 5;

const WIRE_VARINT: u8 = 0;
const WIRE_FIXED64: u8 = 1;
const WIRE_LEN: u8 = 2;
const WIRE_FIXED32: u8 = 5;

/// A process to run with `ExecSandbox`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct ExecSandboxRequest {
    pub command: String,
    pub args: Vec<String>,
    pub working_directory: Option<String>,
    pub environment: Vec<(String, String)>,
    pub timeout_seconds: Option<i32>,
}

/// The completed process reported by `ExecSandbox`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(super) struct ExecSandboxResponse {
    pub exit_code: i32,
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
    pub timed_out: bool,
}

/// Guest readiness reported by `WaitForReady`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(super) struct WaitForReadyResponse {
    pub ready: bool,
    pub current_state: String,
    pub reason: String,
    pub error_code: String,
}

/// The sandbox state reported by `GetSandbox`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(super) struct SandboxState {
    pub target_state: String,
    pub current_state: String,
    pub failure_message: String,
}

impl ExecSandboxRequest {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        put_bytes(&mut out, 3, self.command.as_bytes());
        for arg in &self.args {
            put_bytes(&mut out, 4, arg.as_bytes());
        }
        if let Some(directory) = &self.working_directory {
            put_bytes(&mut out, 5, directory.as_bytes());
        }
        for (key, value) in &self.environment {
            let mut entry = Vec::new();
            put_bytes(&mut entry, 1, key.as_bytes());
            put_bytes(&mut entry, 2, value.as_bytes());
            put_bytes(&mut out, 6, &entry);
        }
        if let Some(timeout) = self.timeout_seconds {
            put_int32(&mut out, 7, timeout);
        }
        out
    }
}

/// Encodes `WaitForReadyRequest`.
pub(super) fn encode_wait_for_ready(timeout_seconds: u32) -> Vec<u8> {
    let mut out = Vec::new();
    put_tag(&mut out, 3, WIRE_VARINT);
    put_varint(&mut out, u64::from(timeout_seconds));
    out
}

impl ExecSandboxResponse {
    pub fn decode(message: &[u8]) -> Result<Self, String> {
        let mut response = Self::default();
        for field in Fields::new(message) {
            match field? {
                // Protobuf int32 values are sign-extended; truncation restores them.
                (1, Value::Varint(value)) => response.exit_code = value as i32,
                (2, Value::Bytes(bytes)) => response.stdout = bytes.to_vec(),
                (3, Value::Bytes(bytes)) => response.stderr = bytes.to_vec(),
                (4, Value::Varint(value)) => response.timed_out = value != 0,
                (1..=4, _) => {
                    return Err("ExecSandboxResponse has a field of the wrong type".into())
                }
                _ => {}
            }
        }
        Ok(response)
    }
}

impl WaitForReadyResponse {
    pub fn decode(message: &[u8]) -> Result<Self, String> {
        let mut response = Self::default();
        for field in Fields::new(message) {
            match field? {
                (1, Value::Varint(value)) => response.ready = value != 0,
                (2, Value::Bytes(bytes)) => response.current_state = text(bytes),
                (3, Value::Bytes(bytes)) => response.reason = text(bytes),
                (4, Value::Bytes(bytes)) => response.error_code = text(bytes),
                (1..=4, _) => {
                    return Err("WaitForReadyResponse has a field of the wrong type".into())
                }
                _ => {}
            }
        }
        Ok(response)
    }
}

impl SandboxState {
    /// Decodes `GetSandboxResponse`, whose field 1 is the sandbox definition.
    pub fn decode(message: &[u8]) -> Result<Self, String> {
        let mut state = Self::default();
        for field in Fields::new(message) {
            match field? {
                (1, Value::Bytes(definition)) => {
                    for field in Fields::new(definition) {
                        match field? {
                            (6, Value::Bytes(bytes)) => state.target_state = text(bytes),
                            (7, Value::Bytes(bytes)) => state.current_state = text(bytes),
                            (8, Value::Bytes(bytes)) => state.failure_message = text(bytes),
                            (6..=8, _) => {
                                return Err("SandboxDefinition has a field of the wrong type".into())
                            }
                            _ => {}
                        }
                    }
                }
                (1, _) => return Err("GetSandboxResponse has a field of the wrong type".into()),
                _ => {}
            }
        }
        Ok(state)
    }
}

/// Wraps an encoded message in an uncompressed gRPC frame.
pub(super) fn frame(message: &[u8]) -> Result<Vec<u8>, String> {
    let length = u32::try_from(message.len())
        .map_err(|_| "the gRPC request message is too large".to_owned())?;
    let mut out = Vec::with_capacity(FRAME_HEADER_LEN + message.len());
    out.push(0);
    out.extend_from_slice(&length.to_be_bytes());
    out.extend_from_slice(message);
    Ok(out)
}

/// The length of the message whose frame starts `body`, once its header has
/// arrived.
pub(super) fn frame_length(body: &[u8]) -> Result<Option<usize>, String> {
    let Some(header) = body.get(..FRAME_HEADER_LEN) else {
        return Ok(None);
    };
    if header[0] != 0 {
        return Err("the gateway sent a compressed gRPC message, which MXC did not request".into());
    }
    let length = u32::from_be_bytes([header[1], header[2], header[3], header[4]]);
    usize::try_from(length)
        .map(Some)
        .map_err(|_| "the gRPC response message is too large".to_owned())
}

/// Extracts the single message of a unary gRPC response body.
pub(super) fn unframe(body: &[u8]) -> Result<&[u8], String> {
    let length = frame_length(body)?.ok_or("the gRPC response has no message")?;
    let message = &body[FRAME_HEADER_LEN..];
    if message.len() != length {
        return Err(format!(
            "the gRPC response frame declares {length} bytes but carries {}",
            message.len()
        ));
    }
    Ok(message)
}

/// The bytes a unary response with a `message_len`-byte message occupies.
pub(super) fn framed_len(message_len: usize) -> usize {
    FRAME_HEADER_LEN.saturating_add(message_len)
}

fn text(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).into_owned()
}

fn put_tag(out: &mut Vec<u8>, field: u32, wire_type: u8) {
    put_varint(out, (u64::from(field) << 3) | u64::from(wire_type));
}

fn put_varint(out: &mut Vec<u8>, mut value: u64) {
    loop {
        let byte = (value & 0x7f) as u8;
        value >>= 7;
        if value == 0 {
            out.push(byte);
            return;
        }
        out.push(byte | 0x80);
    }
}

fn put_bytes(out: &mut Vec<u8>, field: u32, bytes: &[u8]) {
    put_tag(out, field, WIRE_LEN);
    put_varint(out, bytes.len() as u64);
    out.extend_from_slice(bytes);
}

fn put_int32(out: &mut Vec<u8>, field: u32, value: i32) {
    put_tag(out, field, WIRE_VARINT);
    // Protobuf sign-extends negative int32 values to 64 bits.
    put_varint(out, i64::from(value) as u64);
}

#[derive(Debug, PartialEq, Eq)]
enum Value<'a> {
    Varint(u64),
    Bytes(&'a [u8]),
    Fixed,
}

/// Iterates over the `(field number, value)` pairs of a message.
struct Fields<'a> {
    input: &'a [u8],
    failed: bool,
}

impl<'a> Fields<'a> {
    fn new(input: &'a [u8]) -> Self {
        Self {
            input,
            failed: false,
        }
    }

    fn varint(&mut self) -> Result<u64, String> {
        let mut value = 0u64;
        for (index, byte) in self.input.iter().enumerate().take(10) {
            // The tenth byte may contribute only the highest bit.
            if index == 9 && *byte > 1 {
                break;
            }
            value |= u64::from(byte & 0x7f) << (7 * index);
            if byte & 0x80 == 0 {
                self.input = &self.input[index + 1..];
                return Ok(value);
            }
        }
        Err("malformed protobuf varint".into())
    }

    fn take(&mut self, length: usize) -> Result<&'a [u8], String> {
        if length > self.input.len() {
            return Err("truncated protobuf field".into());
        }
        let (taken, rest) = self.input.split_at(length);
        self.input = rest;
        Ok(taken)
    }

    fn next_field(&mut self) -> Result<(u32, Value<'a>), String> {
        let key = self.varint()?;
        let field = u32::try_from(key >> 3)
            .ok()
            .filter(|&field| field != 0)
            .ok_or("invalid protobuf field number")?;
        let value = match (key & 7) as u8 {
            WIRE_VARINT => Value::Varint(self.varint()?),
            WIRE_FIXED64 => {
                self.take(8)?;
                Value::Fixed
            }
            WIRE_LEN => {
                let length = usize::try_from(self.varint()?)
                    .map_err(|_| "protobuf field length overflows".to_owned())?;
                Value::Bytes(self.take(length)?)
            }
            WIRE_FIXED32 => {
                self.take(4)?;
                Value::Fixed
            }
            other => return Err(format!("unsupported protobuf wire type {other}")),
        };
        Ok((field, value))
    }
}

impl<'a> Iterator for Fields<'a> {
    type Item = Result<(u32, Value<'a>), String>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.failed || self.input.is_empty() {
            return None;
        }
        let field = self.next_field();
        self.failed = field.is_err();
        Some(field)
    }
}

#[cfg(test)]
pub(super) mod tests {
    use super::*;

    /// Encodes `ExecSandboxResponse` the way the gateway does.
    pub(crate) fn encode_exec_response(response: &ExecSandboxResponse) -> Vec<u8> {
        let mut out = Vec::new();
        if response.exit_code != 0 {
            put_int32(&mut out, 1, response.exit_code);
        }
        if !response.stdout.is_empty() {
            put_bytes(&mut out, 2, &response.stdout);
        }
        if !response.stderr.is_empty() {
            put_bytes(&mut out, 3, &response.stderr);
        }
        if response.timed_out {
            put_tag(&mut out, 4, WIRE_VARINT);
            put_varint(&mut out, 1);
        }
        out
    }

    pub(crate) fn encode_wait_response(ready: bool, state: &str) -> Vec<u8> {
        let mut out = Vec::new();
        put_tag(&mut out, 1, WIRE_VARINT);
        put_varint(&mut out, u64::from(ready));
        put_bytes(&mut out, 2, state.as_bytes());
        // A startup duration the gateway adds after the fields MXC reads.
        put_tag(&mut out, 5, WIRE_VARINT);
        put_varint(&mut out, 662);
        out
    }

    pub(crate) fn encode_sandbox_state(current: &str, failure: &str) -> Vec<u8> {
        let mut definition = Vec::new();
        put_tag(&mut definition, 1, WIRE_VARINT);
        put_varint(&mut definition, 1);
        put_bytes(&mut definition, 5, b"mcr.microsoft.com/example:1");
        put_bytes(&mut definition, 6, b"running");
        put_bytes(&mut definition, 7, current.as_bytes());
        put_bytes(&mut definition, 8, failure.as_bytes());
        // A newer field than MXC models.
        put_tag(&mut definition, 9, WIRE_VARINT);
        put_varint(&mut definition, 700);
        let mut out = Vec::new();
        put_bytes(&mut out, 1, &definition);
        out
    }

    #[test]
    fn exec_request_matches_the_gateway_field_layout() {
        let request = ExecSandboxRequest {
            command: "/bin/sh".to_owned(),
            args: vec!["-c".to_owned(), "echo hi".to_owned()],
            working_directory: Some("/tmp".to_owned()),
            environment: vec![("FOO".to_owned(), "bar".to_owned())],
            timeout_seconds: Some(30),
        };
        let mut expected = vec![0x1a, 7];
        expected.extend_from_slice(b"/bin/sh");
        expected.extend_from_slice(&[0x22, 2]);
        expected.extend_from_slice(b"-c");
        expected.extend_from_slice(&[0x22, 7]);
        expected.extend_from_slice(b"echo hi");
        expected.extend_from_slice(&[0x2a, 4]);
        expected.extend_from_slice(b"/tmp");
        expected.extend_from_slice(&[0x32, 10, 0x0a, 3]);
        expected.extend_from_slice(b"FOO");
        expected.extend_from_slice(&[0x12, 3]);
        expected.extend_from_slice(b"bar");
        expected.extend_from_slice(&[0x38, 30]);
        assert_eq!(request.encode(), expected);

        let minimal = ExecSandboxRequest {
            command: "/bin/sh".to_owned(),
            args: Vec::new(),
            working_directory: None,
            environment: Vec::new(),
            timeout_seconds: None,
        };
        assert_eq!(minimal.encode(), [&[0x1a, 7][..], b"/bin/sh"].concat());
    }

    #[test]
    fn wait_for_ready_request_uses_field_three() {
        assert_eq!(encode_wait_for_ready(60), [0x18, 60]);
        assert_eq!(encode_wait_for_ready(300), [0x18, 0xac, 0x02]);
    }

    #[test]
    fn exec_response_round_trips_negative_exit_codes_and_raw_bytes() {
        for response in [
            ExecSandboxResponse::default(),
            ExecSandboxResponse {
                exit_code: 3,
                stdout: b"out\n".to_vec(),
                stderr: b"err\n".to_vec(),
                timed_out: false,
            },
            ExecSandboxResponse {
                exit_code: -1,
                stdout: Vec::new(),
                stderr: b"An error occurred trying to start process".to_vec(),
                timed_out: true,
            },
            ExecSandboxResponse {
                exit_code: 137,
                stdout: vec![0xff, 0, 0xfe],
                stderr: Vec::new(),
                timed_out: false,
            },
        ] {
            let encoded = encode_exec_response(&response);
            assert_eq!(ExecSandboxResponse::decode(&encoded).unwrap(), response);
        }
        // -1 is sign-extended to ten bytes on the wire.
        assert_eq!(
            encode_exec_response(&ExecSandboxResponse {
                exit_code: -1,
                ..Default::default()
            })
            .len(),
            11
        );
    }

    #[test]
    fn responses_skip_unknown_fields_of_every_wire_type() {
        let mut message = encode_exec_response(&ExecSandboxResponse {
            exit_code: 7,
            ..Default::default()
        });
        put_tag(&mut message, 20, WIRE_VARINT);
        put_varint(&mut message, 5);
        put_tag(&mut message, 21, WIRE_FIXED64);
        message.extend_from_slice(&[0; 8]);
        put_tag(&mut message, 22, WIRE_FIXED32);
        message.extend_from_slice(&[0; 4]);
        put_bytes(&mut message, 23, b"future");
        assert_eq!(ExecSandboxResponse::decode(&message).unwrap().exit_code, 7);

        let wait = WaitForReadyResponse::decode(&encode_wait_response(true, "running")).unwrap();
        assert!(wait.ready);
        assert_eq!(wait.current_state, "running");

        let state = SandboxState::decode(&encode_sandbox_state("creating", "pull failed")).unwrap();
        assert_eq!(state.target_state, "running");
        assert_eq!(state.current_state, "creating");
        assert_eq!(state.failure_message, "pull failed");
    }

    #[test]
    fn malformed_messages_are_rejected() {
        for message in [
            vec![0x08],          // truncated varint
            vec![0x12, 5, b'a'], // truncated bytes
            vec![0x0b],          // start-group wire type
            vec![0x00, 0x00],    // field number zero
            vec![0x10, 0x01],    // stdout as a varint
            vec![0x08; 11],      // over-long varint
            vec![0x09, 0, 0, 0], // truncated fixed64
        ] {
            assert!(
                ExecSandboxResponse::decode(&message).is_err(),
                "{message:?} was accepted"
            );
        }
        assert!(SandboxState::decode(&[0x08, 1]).is_err());
    }

    #[test]
    fn frames_carry_exactly_one_uncompressed_message() {
        let framed = frame(b"abc").unwrap();
        assert_eq!(framed, [0, 0, 0, 0, 3, b'a', b'b', b'c']);
        assert_eq!(unframe(&framed).unwrap(), b"abc");
        assert_eq!(frame_length(&framed[..4]).unwrap(), None);
        assert_eq!(frame_length(&framed).unwrap(), Some(3));
        assert_eq!(framed_len(3), framed.len());

        let mut compressed = framed.clone();
        compressed[0] = 1;
        assert!(frame_length(&compressed).is_err());
        assert!(unframe(&framed[..6]).is_err());
        let mut trailing = framed.clone();
        trailing.push(0);
        assert!(unframe(&trailing).is_err());
        assert!(unframe(&[]).is_err());
    }
}
