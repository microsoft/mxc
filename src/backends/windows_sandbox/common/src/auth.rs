// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Per-launch nonce handshake between the host and in-VM guest agent.
//!
//! The nonce authenticates each boot/reconnect socket before any protocol
//! bytes are exchanged, closing the cross-user accept-race window on shared
//! hosts. Same-user processes remain in the Windows Sandbox trust boundary.

use std::path::Path;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

/// Length in bytes of the per-launch nonce.
pub const NONCE_LEN_IN_BYTES: usize = 32;

/// Bootstrap file used to pass the launch nonce into the guest.
pub const NONCE_FILENAME: &str = "nonce.bin";

/// Guest boot timeout for reading [`NONCE_FILENAME`].
pub const NONCE_READ_TIMEOUT: Duration = Duration::from_secs(15);

/// Per-launch authentication nonce. Intentionally opaque so it is not logged by
/// derived formatters.
#[derive(Clone)]
pub struct Nonce([u8; NONCE_LEN_IN_BYTES]);

/// Logical channel tag written after the nonce. The guest pairs sockets by this
/// role instead of TCP accept order.
#[repr(u8)]
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum ChannelRole {
    Control = 0,
    Stdin = 1,
    Stdout = 2,
    Stderr = 3,
}

impl ChannelRole {
    pub fn from_wire(b: u8) -> Option<Self> {
        match b {
            0 => Some(Self::Control),
            1 => Some(Self::Stdin),
            2 => Some(Self::Stdout),
            3 => Some(Self::Stderr),
            _ => None,
        }
    }

    pub fn to_wire(self) -> u8 {
        self as u8
    }

    pub fn label(self) -> &'static str {
        match self {
            Self::Control => "control",
            Self::Stdin => "stdin",
            Self::Stdout => "stdout",
            Self::Stderr => "stderr",
        }
    }
}

impl Nonce {
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        let arr: [u8; NONCE_LEN_IN_BYTES] = bytes.try_into().ok()?;
        Some(Self(arr))
    }

    pub fn as_bytes(&self) -> &[u8; NONCE_LEN_IN_BYTES] {
        &self.0
    }

    /// Compare two fixed-length nonces without data-dependent early exit.
    /// Returns `true` only when every byte matches.
    pub fn constant_time_eq(&self, other: &Nonce) -> bool {
        let mut diff: u8 = 0;
        for i in 0..NONCE_LEN_IN_BYTES {
            diff |= self.0[i] ^ other.0[i];
        }
        diff == 0
    }
}

/// Generate a fresh per-launch nonce using the OS RNG.
///
/// Returns an error instead of panicking if the OS CSPRNG is unavailable, so a
/// failure on this security-sensitive path is handled by the caller rather than
/// aborting the process.
pub fn generate_nonce() -> Result<Nonce, getrandom::Error> {
    let mut buf = [0u8; NONCE_LEN_IN_BYTES];
    getrandom::getrandom(&mut buf)?;
    Ok(Nonce(buf))
}

/// Reason a nonce + role handshake failed.
#[derive(Debug)]
pub enum HandshakeError {
    Read(std::io::Error),
    Mismatch,
    Write(std::io::Error),
    RoleRead(std::io::Error),
    RoleUnknown(u8),
    RoleWrite(std::io::Error),
}

impl std::fmt::Display for HandshakeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            HandshakeError::Read(e) => write!(f, "read nonce from peer: {e}"),
            HandshakeError::Mismatch => write!(f, "peer presented an incorrect nonce"),
            HandshakeError::Write(e) => write!(f, "write nonce to peer: {e}"),
            HandshakeError::RoleRead(e) => write!(f, "read role byte from peer: {e}"),
            HandshakeError::RoleUnknown(b) => {
                write!(f, "peer declared unknown channel role 0x{b:02x}")
            }
            HandshakeError::RoleWrite(e) => write!(f, "write role byte to peer: {e}"),
        }
    }
}

impl std::error::Error for HandshakeError {}

/// Host-side: write the nonce and channel role tag first on a new TCP stream.
pub async fn write_nonce(
    stream: &mut TcpStream,
    nonce: &Nonce,
    role: ChannelRole,
) -> Result<(), HandshakeError> {
    stream
        .write_all(nonce.as_bytes())
        .await
        .map_err(HandshakeError::Write)?;
    stream
        .write_all(&[role.to_wire()])
        .await
        .map_err(HandshakeError::RoleWrite)
}

/// Guest-side: authenticate a new TCP stream and decode its channel role.
pub async fn verify_nonce(
    stream: &mut TcpStream,
    expected: &Nonce,
) -> Result<ChannelRole, HandshakeError> {
    let mut buf = [0u8; NONCE_LEN_IN_BYTES];
    stream
        .read_exact(&mut buf)
        .await
        .map_err(HandshakeError::Read)?;
    let got = Nonce::from_bytes(&buf)
        .expect("read_exact filled the nonce buffer, Nonce::from_bytes must succeed");
    if !expected.constant_time_eq(&got) {
        return Err(HandshakeError::Mismatch);
    }
    let mut role_buf = [0u8; 1];
    stream
        .read_exact(&mut role_buf)
        .await
        .map_err(HandshakeError::RoleRead)?;
    ChannelRole::from_wire(role_buf[0]).ok_or(HandshakeError::RoleUnknown(role_buf[0]))
}

/// Host-side: create the nonce file in an already-secured rendezvous directory.
pub fn write_nonce_file(dir: &Path, nonce: &Nonce) -> std::io::Result<()> {
    let path = dir.join(NONCE_FILENAME);
    match std::fs::remove_file(&path) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(e),
    }
    std::fs::write(path, nonce.as_bytes())
}

/// Guest-side: read and delete the nonce file.
pub async fn read_and_consume_nonce_file(dir: &Path, timeout: Duration) -> std::io::Result<Nonce> {
    let path = dir.join(NONCE_FILENAME);
    let deadline = tokio::time::Instant::now() + timeout;
    loop {
        match tokio::fs::read(&path).await {
            Ok(bytes) => {
                // Delete before validation so a malformed file is not retried forever.
                let delete_err = tokio::fs::remove_file(&path).await.err();
                let nonce = Nonce::from_bytes(&bytes).ok_or_else(|| {
                    std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        format!(
                            "nonce file {path:?} is {} bytes, expected {NONCE_LEN_IN_BYTES}",
                            bytes.len()
                        ),
                    )
                })?;
                if let Some(e) = delete_err {
                    // Best-effort: the nonce has already been read into memory.
                    eprintln!(
                        "[guest][auth] WARNING: nonce file {path:?} delete after read failed: {e}"
                    );
                }
                return Ok(nonce);
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                if tokio::time::Instant::now() >= deadline {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::NotFound,
                        format!(
                            "nonce file {path:?} did not appear within {timeout:?}; check the \
                             host wrote it before launching the VM"
                        ),
                    ));
                }
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
            Err(e) => return Err(e),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn from_bytes_requires_exact_length() {
        assert!(Nonce::from_bytes(&[0u8; NONCE_LEN_IN_BYTES]).is_some());
        assert!(Nonce::from_bytes(&[0u8; NONCE_LEN_IN_BYTES - 1]).is_none());
        assert!(Nonce::from_bytes(&[0u8; NONCE_LEN_IN_BYTES + 1]).is_none());
        assert!(Nonce::from_bytes(&[]).is_none());
    }

    #[test]
    fn constant_time_eq_matches_equal_bytes() {
        let a = Nonce::from_bytes(&[0xAA; NONCE_LEN_IN_BYTES]).unwrap();
        let b = Nonce::from_bytes(&[0xAA; NONCE_LEN_IN_BYTES]).unwrap();
        assert!(a.constant_time_eq(&b));
    }

    #[test]
    fn constant_time_eq_rejects_one_bit_diff() {
        let a_bytes = [0xAA; NONCE_LEN_IN_BYTES];
        let mut b_bytes = a_bytes;
        b_bytes[NONCE_LEN_IN_BYTES - 1] ^= 0x01;
        let a = Nonce::from_bytes(&a_bytes).unwrap();
        let b = Nonce::from_bytes(&b_bytes).unwrap();
        assert!(!a.constant_time_eq(&b));
    }

    #[test]
    fn constant_time_eq_rejects_total_mismatch() {
        let a = Nonce::from_bytes(&[0x00; NONCE_LEN_IN_BYTES]).unwrap();
        let b = Nonce::from_bytes(&[0xFF; NONCE_LEN_IN_BYTES]).unwrap();
        assert!(!a.constant_time_eq(&b));
    }

    #[test]
    fn channel_role_roundtrip() {
        for role in [
            ChannelRole::Control,
            ChannelRole::Stdin,
            ChannelRole::Stdout,
            ChannelRole::Stderr,
        ] {
            assert_eq!(ChannelRole::from_wire(role.to_wire()), Some(role));
        }
    }

    #[test]
    fn channel_role_rejects_unknown_wire_bytes() {
        for b in [4u8, 5, 7, 0x10, 0x80, 0xFE, 0xFF] {
            assert!(ChannelRole::from_wire(b).is_none(), "byte {b:#x} accepted");
        }
    }

    #[test]
    fn channel_role_label_is_stable() {
        // The bridge logs use these labels; diagnostics depend on them being
        // canonical.
        assert_eq!(ChannelRole::Control.label(), "control");
        assert_eq!(ChannelRole::Stdin.label(), "stdin");
        assert_eq!(ChannelRole::Stdout.label(), "stdout");
        assert_eq!(ChannelRole::Stderr.label(), "stderr");
    }

    #[test]
    fn generated_nonces_differ_with_overwhelming_probability() {
        // 256 bits of OS entropy; a collision across 1024 draws has probability
        // ~2^-237, indistinguishable from impossible. We just assert two
        // sequential generations differ (catches a wholly broken RNG that
        // returns a constant).
        let a = generate_nonce().unwrap();
        let b = generate_nonce().unwrap();
        assert!(!a.constant_time_eq(&b));
    }

    /// The per-launch `nonce.bin` written into an owner-only rendezvous dir
    /// is itself owner-only (so a cross-user reader cannot recover the nonce),
    /// and is **deleted on read** by the guest-side consume (bounding in-VM
    /// exposure to the running guest process's memory).
    #[cfg(windows)]
    #[test]
    fn nonce_file_is_owner_only_and_deleted_after_read() {
        let unique = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir = std::env::temp_dir().join(format!(
            "wxc-wsb-noncetest-{}-{}",
            std::process::id(),
            unique
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("create temp dir");
        // Secure the dir owner-only + inheritable, mirroring how the launch path
        // prepares the rendezvous dir before writing the nonce.
        wxc_common::filesystem_dacl::set_owner_only_dacl(&dir, true).expect("secure dir");

        let nonce = generate_nonce().expect("generate nonce");
        write_nonce_file(&dir, &nonce).expect("write nonce file");

        let path = dir.join(NONCE_FILENAME);
        assert!(path.exists(), "nonce file must exist after write");
        // Created fresh inside the owner-only dir, the file is owned by us; a
        // cross-user reader cannot open it.
        assert!(
            wxc_common::filesystem_dacl::owner_is_self(&path).expect("read owner"),
            "nonce.bin must be owned by us (inherited owner-only DACL)"
        );

        // Reading consumes (deletes) the file.
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("build runtime");
        let read = rt
            .block_on(read_and_consume_nonce_file(
                &dir,
                std::time::Duration::from_secs(5),
            ))
            .expect("read nonce");
        assert!(
            read.constant_time_eq(&nonce),
            "round-tripped nonce must match"
        );
        assert!(!path.exists(), "nonce.bin must be deleted after read");

        let _ = std::fs::remove_dir_all(&dir);
    }
}
