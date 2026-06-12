// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Shared helper for capturing a sandboxed child's stdout/stderr.
//!
//! Capturing is bounded and never blocks the child: reading continues past the
//! cap (discarding the overflow) so a chatty child can't stall on a full pipe,
//! and invalid UTF-8 is replaced (lossy) rather than dropping the whole stream.

use std::io::Read;

/// Maximum number of bytes retained from a captured stream (~1 MiB). Output
/// beyond this is read and discarded so the child never blocks, but is not
/// stored.
pub const MAX_CAPTURED_BYTES: usize = 1024 * 1024;

/// Drain `reader` to a UTF-8 (lossy) `String`, retaining at most
/// [`MAX_CAPTURED_BYTES`].
///
/// Reading continues to EOF even after the cap is reached (the overflow is
/// discarded) so the child can never block on a full pipe buffer. Invalid
/// UTF-8 is replaced with `U+FFFD` instead of discarding the stream, and the
/// decode happens once over the whole buffer so multibyte sequences split
/// across reads are not corrupted.
pub fn read_capped_lossy<R: Read>(mut reader: R) -> String {
    let mut buf: Vec<u8> = Vec::new();
    let mut chunk = [0u8; 8192];
    loop {
        match reader.read(&mut chunk) {
            Ok(0) => break,
            Ok(n) => {
                if buf.len() < MAX_CAPTURED_BYTES {
                    let take = n.min(MAX_CAPTURED_BYTES - buf.len());
                    buf.extend_from_slice(&chunk[..take]);
                }
                // Past the cap: keep reading and discarding so the child's
                // pipe never fills and it can run to completion.
            }
            Err(ref e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(_) => break,
        }
    }
    String::from_utf8_lossy(&buf).into_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keeps_valid_prefix_of_non_utf8() {
        let mut data = b"hello ".to_vec();
        data.push(0xFF); // invalid UTF-8 byte
        data.extend_from_slice(b" world");
        let out = read_capped_lossy(&data[..]);
        assert!(out.starts_with("hello "), "got: {out:?}");
        assert!(out.contains("world"), "got: {out:?}");
    }

    #[test]
    fn caps_but_drains_overflow() {
        let data = vec![b'a'; MAX_CAPTURED_BYTES + 4096];
        let out = read_capped_lossy(&data[..]);
        assert_eq!(out.len(), MAX_CAPTURED_BYTES);
    }

    #[test]
    fn decodes_multibyte_split_across_reads() {
        // 8192-byte chunk boundary: place a 3-byte char straddling it.
        let mut data = vec![b'x'; 8191];
        data.extend_from_slice("☃".as_bytes()); // U+2603, 3 bytes
        let out = read_capped_lossy(&data[..]);
        assert!(out.contains('☃'), "snowman should survive the boundary");
        assert!(!out.contains('\u{FFFD}'), "no replacement chars expected");
    }
}
