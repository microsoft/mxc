// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use sha2::{Digest, Sha256};

use crate::encoding::lowercase_hex;

/// Compute the SHA-256 digest of `input`.
pub fn sha256(input: &[u8]) -> [u8; 32] {
    Sha256::digest(input).into()
}

/// Compute the SHA-256 digest of `input` as lowercase hexadecimal.
pub fn sha256_hex(input: &[u8]) -> String {
    lowercase_hex(&sha256(input))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sha256_hex_matches_known_vector() {
        assert_eq!(
            sha256_hex(b"abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }
}
