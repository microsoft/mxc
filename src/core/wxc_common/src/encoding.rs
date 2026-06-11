// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use base64::{engine::general_purpose::STANDARD, Engine as _};

/// Decode a Base64-encoded string to raw bytes.
///
/// Uses the standard Base64 alphabet (RFC 4648) with required padding.
/// Returns a [`base64::DecodeError`] when `input` is not valid Base64.
pub fn base64_decode(input: &str) -> Result<Vec<u8>, base64::DecodeError> {
    STANDARD.decode(input)
}

/// Encode raw bytes to a Base64 string.
///
/// Uses the standard Base64 alphabet (RFC 4648) with padding. The output is
/// always valid input for [`base64_decode`].
pub fn base64_encode(input: &[u8]) -> String {
    STANDARD.encode(input)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base64_encode_empty() {
        assert_eq!(base64_encode(b""), "");
    }

    #[test]
    fn base64_encode_simple_string() {
        assert_eq!(base64_encode(b"Hello World"), "SGVsbG8gV29ybGQ=");
    }

    #[test]
    fn base64_decode_empty() {
        assert_eq!(base64_decode("").unwrap(), b"");
    }

    #[test]
    fn base64_decode_valid() {
        assert_eq!(base64_decode("SGVsbG8gV29ybGQ=").unwrap(), b"Hello World");
    }

    #[test]
    fn base64_decode_invalid() {
        assert!(base64_decode("Invalid!!!Base64").is_err());
    }

    #[test]
    fn base64_roundtrip() {
        let original = b"Hello World";
        let decoded = base64_decode(&base64_encode(original)).unwrap();
        assert_eq!(decoded, original);
    }

    #[test]
    fn base64_roundtrip_binary() {
        let original: Vec<u8> = (0u8..=255).collect();
        let decoded = base64_decode(&base64_encode(&original)).unwrap();
        assert_eq!(decoded, original);
    }
}
