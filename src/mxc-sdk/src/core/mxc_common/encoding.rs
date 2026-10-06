// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use base64::{engine::general_purpose::STANDARD, Engine as _};

/// Decode a Base64-encoded string to raw bytes.
pub fn base64_decode(input: &str) -> Result<Vec<u8>, base64::DecodeError> {
    STANDARD.decode(input)
}

/// Encode raw bytes to a Base64 string.
pub fn base64_encode(input: &[u8]) -> String {
    STANDARD.encode(input)
}

/// Encode raw bytes as lowercase hexadecimal.
pub fn lowercase_hex(input: &[u8]) -> String {
    const HEX_DIGITS: &[u8; 16] = b"0123456789abcdef";

    let mut encoded = String::with_capacity(input.len() * 2);
    for &byte in input {
        encoded.push(HEX_DIGITS[(byte >> 4) as usize] as char);
        encoded.push(HEX_DIGITS[(byte & 0x0f) as usize] as char);
    }
    encoded
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
    fn lowercase_hex_encodes_each_nibble() {
        assert_eq!(lowercase_hex(&[0x00, 0x01, 0xab, 0xff]), "0001abff");
    }

    #[test]
    fn lowercase_hex_encodes_empty_input() {
        assert_eq!(lowercase_hex(&[]), "");
    }
}
