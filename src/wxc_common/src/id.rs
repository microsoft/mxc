// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Sandbox-id helpers for state-aware backends.
//!
//! `mint_random_token` is the Rust-side mirror of the SDK's
//! `randomBytes(4).toString("hex")` pattern: 4 bytes of OS randomness rendered as
//! 8 lowercase hex chars. The default `StatefulSandboxBackend::provision` body
//! composes it with the backend's `ID_PREFIX` to mint synthetic sandbox ids for
//! stateless-underneath backends. Future helpers (e.g. prefix parsing) live in
//! this module too.

/// Returns a fresh 8-character lowercase-hex token derived from 4 bytes of
/// OS randomness.
///
/// Panics if the OS RNG is unavailable, which on modern desktop targets does
/// not occur outside catastrophic system failure.
pub fn mint_random_token() -> String {
    let mut buf = [0u8; 4];
    getrandom::getrandom(&mut buf).expect("OS getrandom call failed");
    format!("{:08x}", u32::from_be_bytes(buf))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    #[test]
    fn token_is_eight_lowercase_hex_chars() {
        for _ in 0..64 {
            let t = mint_random_token();
            assert_eq!(t.len(), 8, "token {:?} not 8 chars", t);
            assert!(
                t.chars()
                    .all(|c| c.is_ascii_digit() || ('a'..='f').contains(&c)),
                "token {:?} contains non-lowercase-hex chars",
                t,
            );
        }
    }

    #[test]
    fn token_can_render_a_full_zero_byte_run() {
        // {:08x} must zero-pad: u32::from_be_bytes([0,0,0,0]) renders to "00000000".
        let s = format!("{:08x}", u32::from_be_bytes([0, 0, 0, 0]));
        assert_eq!(s, "00000000");
    }

    #[test]
    fn token_is_parseable_as_hex_u32() {
        for _ in 0..16 {
            let t = mint_random_token();
            u32::from_str_radix(&t, 16).expect("token must be valid hex");
        }
    }

    #[test]
    fn distinct_calls_produce_distinct_tokens() {
        // 4 bytes of randomness -> 32-bit space; 1024 draws have a birthday-paradox
        // collision probability of roughly 1024^2 / 2^33 ~= 1.2e-4. The bound below
        // tolerates a couple of collisions to avoid flake without losing the
        // property we care about (the source is genuinely random, not constant).
        let n = 1024;
        let mut set = HashSet::with_capacity(n);
        for _ in 0..n {
            set.insert(mint_random_token());
        }
        assert!(
            set.len() >= n - 4,
            "{} collisions in {} draws — RNG output not random",
            n - set.len(),
            n,
        );
    }
}
