// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Minimal protobuf wire-format encoder and decoder.
//!
//! The shim's Task API uses a dozen small messages with scalar, string, bytes,
//! repeated-string, and nested-message fields. This module covers exactly
//! that. Encoding follows proto3: a field holding its default value is left
//! out, except for nested messages and repeated fields, which are always
//! written when the caller asks for them. Decoding skips unknown fields.

use std::fmt;

const WIRE_VARINT: u64 = 0;
const WIRE_FIXED64: u64 = 1;
const WIRE_LEN: u64 = 2;
const WIRE_FIXED32: u64 = 5;

/// Why a buffer could not be decoded.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum DecodeError {
    /// The buffer ended in the middle of a field.
    Truncated,
    /// A varint ran past ten bytes.
    VarintTooLong,
    /// A wire type this decoder does not handle (groups) or an invalid tag.
    UnsupportedWireType(u64),
    /// A string field held bytes that are not UTF-8.
    InvalidUtf8,
    /// A field had a different wire type than the message definition.
    WrongWireType { field: u32 },
}

impl fmt::Display for DecodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Truncated => f.write_str("truncated protobuf message"),
            Self::VarintTooLong => f.write_str("protobuf varint is longer than 10 bytes"),
            Self::UnsupportedWireType(t) => write!(f, "unsupported protobuf wire type {t}"),
            Self::InvalidUtf8 => f.write_str("protobuf string field is not valid UTF-8"),
            Self::WrongWireType { field } => {
                write!(f, "protobuf field {field} has an unexpected wire type")
            }
        }
    }
}

impl std::error::Error for DecodeError {}

/// Builds one message.
#[derive(Debug, Default, Clone)]
pub(crate) struct Encoder {
    buf: Vec<u8>,
}

impl Encoder {
    pub(crate) fn new() -> Self {
        Self::default()
    }

    fn varint(&mut self, mut value: u64) {
        while value >= 0x80 {
            self.buf.push((value as u8 & 0x7f) | 0x80);
            value >>= 7;
        }
        self.buf.push(value as u8);
    }

    fn tag(&mut self, field: u32, wire: u64) {
        self.varint((u64::from(field) << 3) | wire);
    }

    /// A string field, omitted when empty.
    pub(crate) fn string(&mut self, field: u32, value: &str) -> &mut Self {
        if !value.is_empty() {
            self.bytes(field, value.as_bytes());
        }
        self
    }

    /// A bytes field, omitted when empty.
    pub(crate) fn bytes(&mut self, field: u32, value: &[u8]) -> &mut Self {
        if !value.is_empty() {
            self.tag(field, WIRE_LEN);
            self.varint(value.len() as u64);
            self.buf.extend_from_slice(value);
        }
        self
    }

    /// An unsigned integer field (`uint32`, `uint64`, `int64` of a
    /// non-negative value), omitted when zero.
    pub(crate) fn uint(&mut self, field: u32, value: u64) -> &mut Self {
        if value != 0 {
            self.tag(field, WIRE_VARINT);
            self.varint(value);
        }
        self
    }

    /// A bool field, omitted when false.
    pub(crate) fn boolean(&mut self, field: u32, value: bool) -> &mut Self {
        self.uint(field, u64::from(value))
    }

    /// One element of a repeated string field. Unlike [`Encoder::string`] an
    /// empty element is kept, because position is meaningful.
    pub(crate) fn repeated_string(&mut self, field: u32, value: &str) -> &mut Self {
        self.tag(field, WIRE_LEN);
        self.varint(value.len() as u64);
        self.buf.extend_from_slice(value.as_bytes());
        self
    }

    /// A nested message, or one element of a repeated message field. Written
    /// even when the nested message is empty, because presence is meaningful.
    pub(crate) fn message(&mut self, field: u32, inner: &Encoder) -> &mut Self {
        self.tag(field, WIRE_LEN);
        self.varint(inner.buf.len() as u64);
        self.buf.extend_from_slice(&inner.buf);
        self
    }

    pub(crate) fn finish(self) -> Vec<u8> {
        self.buf
    }
}

/// The payload of one decoded field.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Value<'a> {
    Varint(u64),
    Fixed64(u64),
    Fixed32(u32),
    Bytes(&'a [u8]),
}

/// One decoded field.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Field<'a> {
    pub(crate) number: u32,
    pub(crate) value: Value<'a>,
}

impl<'a> Field<'a> {
    pub(crate) fn varint(&self) -> Result<u64, DecodeError> {
        match self.value {
            Value::Varint(v) => Ok(v),
            _ => Err(DecodeError::WrongWireType { field: self.number }),
        }
    }

    pub(crate) fn bytes(&self) -> Result<&'a [u8], DecodeError> {
        match self.value {
            Value::Bytes(b) => Ok(b),
            _ => Err(DecodeError::WrongWireType { field: self.number }),
        }
    }

    pub(crate) fn string(&self) -> Result<String, DecodeError> {
        std::str::from_utf8(self.bytes()?)
            .map(str::to_owned)
            .map_err(|_| DecodeError::InvalidUtf8)
    }
}

/// Iterates over the fields of one encoded message.
#[derive(Debug, Clone)]
pub(crate) struct Decoder<'a> {
    buf: &'a [u8],
}

impl<'a> Decoder<'a> {
    pub(crate) fn new(buf: &'a [u8]) -> Self {
        Self { buf }
    }

    fn varint(&mut self) -> Result<u64, DecodeError> {
        let mut value = 0u64;
        for (index, byte) in self.buf.iter().enumerate() {
            if index == 10 {
                return Err(DecodeError::VarintTooLong);
            }
            value |= u64::from(byte & 0x7f) << (7 * index);
            if byte & 0x80 == 0 {
                self.buf = &self.buf[index + 1..];
                return Ok(value);
            }
        }
        if self.buf.len() >= 10 {
            Err(DecodeError::VarintTooLong)
        } else {
            Err(DecodeError::Truncated)
        }
    }

    fn take(&mut self, len: usize) -> Result<&'a [u8], DecodeError> {
        if self.buf.len() < len {
            return Err(DecodeError::Truncated);
        }
        let (head, rest) = self.buf.split_at(len);
        self.buf = rest;
        Ok(head)
    }

    fn next_field(&mut self) -> Result<Field<'a>, DecodeError> {
        let key = self.varint()?;
        let number = u32::try_from(key >> 3).map_err(|_| DecodeError::UnsupportedWireType(key))?;
        if number == 0 {
            return Err(DecodeError::UnsupportedWireType(key));
        }
        let value = match key & 7 {
            WIRE_VARINT => Value::Varint(self.varint()?),
            WIRE_FIXED64 => {
                let raw = self.take(8)?;
                Value::Fixed64(u64::from_le_bytes(raw.try_into().expect("8 bytes")))
            }
            WIRE_LEN => {
                let len = usize::try_from(self.varint()?).map_err(|_| DecodeError::Truncated)?;
                Value::Bytes(self.take(len)?)
            }
            WIRE_FIXED32 => {
                let raw = self.take(4)?;
                Value::Fixed32(u32::from_le_bytes(raw.try_into().expect("4 bytes")))
            }
            other => return Err(DecodeError::UnsupportedWireType(other)),
        };
        Ok(Field { number, value })
    }
}

impl<'a> Iterator for Decoder<'a> {
    type Item = Result<Field<'a>, DecodeError>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.buf.is_empty() {
            return None;
        }
        let item = self.next_field();
        if item.is_err() {
            // One error ends the stream; the rest of the buffer is not
            // trustworthy.
            self.buf = &[];
        }
        Some(item)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fields(buf: &[u8]) -> Vec<Field<'_>> {
        Decoder::new(buf).collect::<Result<_, _>>().unwrap()
    }

    #[test]
    fn encodes_the_documented_varint_example() {
        // Field 1 = 150 is the worked example in the protobuf encoding guide.
        let mut e = Encoder::new();
        e.uint(1, 150);
        assert_eq!(e.finish(), [0x08, 0x96, 0x01]);
    }

    #[test]
    fn encodes_the_documented_string_example() {
        // Field 2 = "testing" is the worked example in the protobuf encoding guide.
        let mut e = Encoder::new();
        e.string(2, "testing");
        assert_eq!(
            e.finish(),
            [0x12, 0x07, 0x74, 0x65, 0x73, 0x74, 0x69, 0x6e, 0x67]
        );
    }

    #[test]
    fn proto3_defaults_are_omitted() {
        let mut e = Encoder::new();
        e.string(1, "").bytes(2, &[]).uint(3, 0).boolean(4, false);
        assert!(e.finish().is_empty());
    }

    #[test]
    fn repeated_strings_and_nested_messages_are_always_written() {
        let mut inner = Encoder::new();
        inner.string(1, "x");
        let mut e = Encoder::new();
        e.repeated_string(4, "")
            .message(5, &Encoder::new())
            .message(6, &inner);
        assert_eq!(
            e.finish(),
            [0x22, 0x00, 0x2a, 0x00, 0x32, 0x03, 0x0a, 0x01, b'x']
        );
    }

    #[test]
    fn round_trips_every_wire_type_the_decoder_reads() {
        let mut inner = Encoder::new();
        inner.uint(1, 7);
        let mut e = Encoder::new();
        e.uint(1, u64::MAX)
            .string(2, "héllo")
            .bytes(3, &[0, 1, 2])
            .message(4, &inner);
        let buf = e.finish();
        let got = fields(&buf);
        assert_eq!(got[0].varint().unwrap(), u64::MAX);
        assert_eq!(got[1].string().unwrap(), "héllo");
        assert_eq!(got[2].bytes().unwrap(), [0, 1, 2]);
        let nested = got[3].bytes().unwrap();
        assert_eq!(fields(nested)[0].varint().unwrap(), 7);
    }

    #[test]
    fn fixed_width_fields_are_decoded_so_unknown_fields_can_be_skipped() {
        // field 1 fixed64, field 2 fixed32
        let mut buf = vec![0x09];
        buf.extend_from_slice(&5u64.to_le_bytes());
        buf.push(0x15);
        buf.extend_from_slice(&6u32.to_le_bytes());
        let got = fields(&buf);
        assert_eq!(got[0].value, Value::Fixed64(5));
        assert_eq!(got[1].value, Value::Fixed32(6));
    }

    #[test]
    fn truncated_and_malformed_input_is_rejected() {
        let cases: [(&[u8], DecodeError); 4] = [
            (&[0x08], DecodeError::Truncated),
            (&[0x12, 0x05, b'a'], DecodeError::Truncated),
            (
                &[
                    0x08, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x01,
                ],
                DecodeError::VarintTooLong,
            ),
            (&[0x0b], DecodeError::UnsupportedWireType(3)),
        ];
        for (buf, want) in cases {
            let err = Decoder::new(buf).find_map(Result::err).expect("an error");
            assert_eq!(err, want, "{buf:02x?}");
        }
    }

    #[test]
    fn a_decode_error_ends_the_stream() {
        let mut d = Decoder::new(&[0x08, 0x01, 0x0b, 0x08, 0x02]);
        assert!(d.next().unwrap().is_ok());
        assert!(d.next().unwrap().is_err());
        assert!(d.next().is_none());
    }

    #[test]
    fn a_string_field_that_is_not_utf8_is_an_error() {
        let buf = [0x0a, 0x01, 0xff];
        let field = fields(&buf)[0];
        assert_eq!(field.string(), Err(DecodeError::InvalidUtf8));
    }

    #[test]
    fn reading_a_field_as_the_wrong_type_is_an_error() {
        let buf = [0x08, 0x01];
        let field = fields(&buf)[0];
        assert_eq!(field.bytes(), Err(DecodeError::WrongWireType { field: 1 }));
    }
}
