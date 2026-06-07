// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Per-launch nonce handshake between the host daemon and the in-VM guest
//! agent.
//!
//! ## Threat model addressed
//!
//! Without this handshake the guest binds `0.0.0.0:0` and accepts the
//! four boot connections (control + stdin/stdout/stderr) plus the
//! per-exec data-stream reconnects in **arrival order**, with only an
//! 8-byte magic/version preamble for protocol identification (no
//! authentication). On the host side the firewall lockdown
//! ([`crate::firewall`] in the guest crate) restricts the guest-side
//! socket to the host IP — but **every process under any other user
//! account on the host shares that IP**. A process owned by a *different*
//! user can therefore race `TcpStream::connect` against the legitimate
//! daemon at startup or per reconnect, steal stdout/stderr, inject
//! stdin, or wedge the boot by taking the control slot first. The
//! 8-byte preamble cannot defend against this because the attacker is a
//! real `wxc`-aware peer that sends the correct magic/version — it just
//! isn't the daemon that launched this VM. (Review finding C2.)
//!
//! ## Scope (what this protects, what it does NOT)
//!
//! This handshake defends against **cross-user** hijack on a shared
//! host. The nonce file (`nonce.bin`) and the daemon record
//! (`daemon.json`) are written with an owner-only DACL via
//! [`wxc_common::filesystem_dacl::set_owner_only_dacl`], whose own
//! threat model explicitly states that **processes running under the
//! same user account are trusted** (they can already read each other's
//! files, attach debuggers, etc., independently of MXC's protections).
//!
//! As a direct consequence: a same-user attacker who can read the
//! rendezvous folder can recover the nonce and successfully present it.
//! That is **out of scope** for this fix and consistent with the rest
//! of the Windows Sandbox backend's security model — the design target
//! is a single-user developer workstation where same-user processes are
//! already inside the trust boundary, not a multi-tenant host where
//! same-user isolation would have to be enforced. Hardening the
//! same-user case would require (a) keeping the nonce off disk
//! entirely (e.g. inherited pipe handles) and (b) reworking the
//! cross-process daemon discovery surface to match — both are real
//! engineering work outside the scope of this handshake.
//!
//! ## Fix
//!
//! Pair a freshly minted 32-byte cryptographic nonce with every sandbox
//! launch. The nonce never leaves in-memory state once the guest reads
//! the bootstrap file, and is required as the **first 32 bytes** of every
//! socket the guest accepts. A peer that does not present the nonce is
//! treated as hostile and the connection is closed before any protocol
//! bytes are exchanged.
//!
//! ## Lifecycle
//!
//! ```text
//!   Host                                          Guest
//!    │                                              │
//!    │  generate_nonce()  →  Nonce                  │
//!    │  write to <rendezvous_dir>/nonce.bin         │
//!    │  (parent dir is owner-only DACL, so the      │
//!    │   file is too via inheritance — see          │
//!    │   "Scope" above for what owner-only does     │
//!    │   and does NOT defend)                       │
//!    │  launch VM ──────────────────────────────►   │
//!    │                                              │ read & verify_nonce_file
//!    │                                              │ (then DELETE the file
//!    │                                              │  immediately so even an
//!    │                                              │  in-VM compromise after
//!    │                                              │  bind cannot recover it)
//!    │                                              │ bind 0.0.0.0:0
//!    │                                              │ write rendezvous.txt
//!    │   ◄──────────────── rendezvous.txt           │
//!    │                                              │
//!    │  for each of {control,stdin,stdout,stderr}:  │
//!    │  ─── TcpStream::connect ─────────────────►   │ accept
//!    │  ─── write Nonce (32 bytes) ─────────────►   │ read 32 bytes
//!    │                                              │ constant_time_eq cmp
//!    │                                              │ ✓ → keep socket
//!    │                                              │ ✗ → drop socket, retry accept
//! ```
//!
//! The same handshake is applied on the post-`StreamsReady` 3-stream
//! reconnects so a cross-user hijacker cannot steal a per-exec data
//! stream either.
//!
//! ## Why not TLS?
//!
//! A localhost mutual-TLS channel would also defeat cross-user hijack
//! and add transport confidentiality / integrity. The nonce handshake
//! is chosen here because (a) the guest-side cert provisioning channel
//! does not exist yet (and adding one is materially more work than
//! this), (b) the threat is **cross-user hijack**, not eavesdropping on
//! the wire — both peers' loopback traffic is unobservable to
//! network-level attackers anyway — and (c) the secrecy of the nonce
//! is bounded by the in-VM lifetime of one boot, so a `mmap` /
//! page-cache snoop window is small. TLS is left as a future
//! hardening.

use std::path::Path;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

/// Length in bytes of the per-launch nonce. 32 bytes / 256 bits matches the
/// strength of common KEK / IKM sizes; brute-force is intractable.
pub const NONCE_LEN: usize = 32;

/// File the host writes the nonce to before launching the VM, inside the
/// rendezvous directory (which already has an owner-only inheritable DACL
/// applied by the one-shot runner / daemon).
pub const NONCE_FILENAME: &str = "nonce.bin";

/// Upper bound on how long the guest waits to read the nonce file at boot
/// before treating it as a fatal misconfiguration. The host writes the file
/// before launch so by the time the guest is up the file is definitely
/// there; the timeout exists to catch a misconfigured deploy rather than to
/// pace a healthy boot.
pub const NONCE_READ_TIMEOUT: Duration = Duration::from_secs(15);

/// Per-launch authentication nonce. 32 bytes of OS-RNG entropy that the
/// host writes once to the rendezvous folder, the guest reads + deletes at
/// boot, and both peers exchange as the first frame of every TCP
/// connection. Use [`from_bytes`](Self::from_bytes) /
/// [`as_bytes`](Self::as_bytes) for I/O and [`constant_time_eq`](Self::constant_time_eq)
/// for verification.
///
/// The struct is intentionally opaque (does not derive `Debug`,
/// `Serialize`, `Display`) so a stray `eprintln!` or log macro cannot
/// disclose the nonce to host stderr / a log file. Add an explicit
/// redacted formatter when one is actually needed.
#[derive(Clone)]
pub struct Nonce([u8; NONCE_LEN]);

/// Role tag exchanged after the nonce so the guest assigns each accepted
/// socket to the correct logical channel by **identity, not by accept
/// order**.
///
/// Without this tag the guest assumed accept-FIFO order matched the
/// host's connect order. That assumption held on most runs but
/// intermittently broke on Hyper-V vNIC paths (or under any kernel /
/// firewall scheduling that delivered the second listen-queue entry
/// before the first under unrelated load) — when it did, the guest's
/// "stdout" stream was paired with the host's "stdin" socket (and so
/// on), every byte the child wrote vanished into a reader nobody
/// consulted, and the host's stdout reader blocked forever on a socket
/// the guest never wrote to. The symptom was a small-payload exec
/// returning `exit 0` with empty stdout roughly 20–30% of the time on
/// the very first exec after `start`.
///
/// One byte after the nonce on every TCP connection (boot and reconnect)
/// is now a `ChannelRole`. The guest reads it under the same auth
/// timeout, drops the socket on an unknown / duplicate / EOF role, and
/// assigns the surviving sockets to the host-declared logical channels.
#[repr(u8)]
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum ChannelRole {
    Control = 0,
    Stdin = 1,
    Stdout = 2,
    Stderr = 3,
}

impl ChannelRole {
    /// Decode the wire byte. Returns `None` for any unknown value so the
    /// guest fails closed on a malformed (or wrong-version) host.
    pub fn from_wire(b: u8) -> Option<Self> {
        match b {
            0 => Some(Self::Control),
            1 => Some(Self::Stdin),
            2 => Some(Self::Stdout),
            3 => Some(Self::Stderr),
            _ => None,
        }
    }

    /// Encode as the single wire byte sent after the nonce.
    pub fn to_wire(self) -> u8 {
        self as u8
    }

    /// Human-readable label for diagnostics.
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
    /// Wrap an already-materialised byte buffer (e.g. read from
    /// `nonce.bin`) into a [`Nonce`]. Returns `None` if the slice is the
    /// wrong length so the caller fails closed.
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        let arr: [u8; NONCE_LEN] = bytes.try_into().ok()?;
        Some(Self(arr))
    }

    /// View the nonce as a byte slice for I/O. Callers should write
    /// exactly [`NONCE_LEN`] bytes to a socket and not log the result.
    pub fn as_bytes(&self) -> &[u8; NONCE_LEN] {
        &self.0
    }

    /// Compare two nonces in constant time. A naïve `==` would short-circuit
    /// on the first differing byte, exposing the matched prefix length via
    /// a timing side channel; over localhost the resolution is sub-µs but
    /// across many guess attempts the side channel is real.
    pub fn constant_time_eq(&self, other: &Nonce) -> bool {
        let mut diff: u8 = 0;
        for i in 0..NONCE_LEN {
            // Wrapping XOR -> OR into accumulator. The whole-array iteration
            // means the work done does not depend on where the bytes differ.
            diff |= self.0[i] ^ other.0[i];
        }
        diff == 0
    }
}

/// Generate a fresh per-launch nonce using the OS RNG. Panics only on
/// `getrandom` failure, which on a modern host implies the kernel is
/// broken in a way that no in-process recovery makes sense.
pub fn generate_nonce() -> Nonce {
    let mut buf = [0u8; NONCE_LEN];
    getrandom::getrandom(&mut buf).expect("OS getrandom failed (kernel CSPRNG broken)");
    Nonce(buf)
}

/// Reason a nonce + role handshake failed.
#[derive(Debug)]
pub enum HandshakeError {
    /// Could not read the full [`NONCE_LEN`] bytes from the peer (EOF, I/O
    /// error, or timeout).
    Read(std::io::Error),
    /// Read [`NONCE_LEN`] bytes but they did not match the expected nonce.
    Mismatch,
    /// Could not write the full [`NONCE_LEN`] bytes to the peer (broken pipe
    /// / timeout). Only used host-side.
    Write(std::io::Error),
    /// Could not read the trailing role byte (EOF or I/O error during the
    /// post-nonce read). Treated identically to a nonce-read failure by
    /// the caller — drop the socket and wait for the legitimate peer to
    /// retry.
    RoleRead(std::io::Error),
    /// Role byte did not decode to any known [`ChannelRole`] — the peer is
    /// speaking a newer / unknown protocol and we fail closed.
    RoleUnknown(u8),
    /// Could not write the role byte (host-side only).
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

/// Write the nonce **and** the channel role tag to a freshly-accepted TCP
/// stream as the first [`NONCE_LEN`]+1 bytes. Host-side helper used by
/// every host->guest connect.
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

/// Read the first [`NONCE_LEN`] bytes from a freshly-accepted TCP stream,
/// constant-time compare against the expected nonce, then read and decode
/// the trailing role byte. Guest-side helper used by every accept.
///
/// On any handshake failure the stream is left for the caller to drop.
/// The caller must not write anything to the socket before this returns
/// Ok — even an error frame could leak structural information about our
/// protocol to a hostile peer.
pub async fn verify_nonce(
    stream: &mut TcpStream,
    expected: &Nonce,
) -> Result<ChannelRole, HandshakeError> {
    let mut buf = [0u8; NONCE_LEN];
    stream
        .read_exact(&mut buf)
        .await
        .map_err(HandshakeError::Read)?;
    let got = Nonce::from_bytes(&buf)
        .expect("read_exact filled NONCE_LEN bytes, Nonce::from_bytes must succeed");
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

/// Host-side: write the nonce to `<dir>/nonce.bin` before launching the
/// VM. The directory must already have an owner-only inheritable DACL
/// applied; the file inherits it.
pub fn write_nonce_file(dir: &Path, nonce: &Nonce) -> std::io::Result<()> {
    let path = dir.join(NONCE_FILENAME);
    std::fs::write(path, nonce.as_bytes())
}

/// Guest-side: read `<dir>/nonce.bin` and **immediately delete** the file.
///
/// The delete-after-read pattern bounds the in-VM exposure of the nonce:
/// after this returns, the nonce only exists in the running guest
/// process's memory. A later in-VM compromise that gains filesystem read
/// access cannot recover it; only a memory-read primitive into the guest
/// process can.
///
/// `timeout` bounds how long we poll for the file's appearance. The host
/// writes the file before launching the VM so it is normally present by
/// the time the guest boots; the timeout exists to surface a
/// misconfigured deploy with a clear error rather than to pace healthy
/// boots.
pub async fn read_and_consume_nonce_file(dir: &Path, timeout: Duration) -> std::io::Result<Nonce> {
    let path = dir.join(NONCE_FILENAME);
    let deadline = tokio::time::Instant::now() + timeout;
    loop {
        match tokio::fs::read(&path).await {
            Ok(bytes) => {
                // Delete first, then validate. If validation fails (wrong
                // length) we still want the file gone so a re-read does not
                // see a partial-write.
                let delete_err = tokio::fs::remove_file(&path).await.err();
                let nonce = Nonce::from_bytes(&bytes).ok_or_else(|| {
                    std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        format!(
                            "nonce file {path:?} is {} bytes, expected {NONCE_LEN}",
                            bytes.len()
                        ),
                    )
                })?;
                if let Some(e) = delete_err {
                    // Best-effort: log but don't fail. The file's owner-only
                    // DACL keeps it from leaking to other guest users (the
                    // guest runs as a single Sandbox user anyway).
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
        assert!(Nonce::from_bytes(&[0u8; NONCE_LEN]).is_some());
        assert!(Nonce::from_bytes(&[0u8; NONCE_LEN - 1]).is_none());
        assert!(Nonce::from_bytes(&[0u8; NONCE_LEN + 1]).is_none());
        assert!(Nonce::from_bytes(&[]).is_none());
    }

    #[test]
    fn constant_time_eq_matches_equal_bytes() {
        let a = Nonce::from_bytes(&[0xAA; NONCE_LEN]).unwrap();
        let b = Nonce::from_bytes(&[0xAA; NONCE_LEN]).unwrap();
        assert!(a.constant_time_eq(&b));
    }

    #[test]
    fn constant_time_eq_rejects_one_bit_diff() {
        let a_bytes = [0xAA; NONCE_LEN];
        let mut b_bytes = a_bytes;
        b_bytes[NONCE_LEN - 1] ^= 0x01;
        let a = Nonce::from_bytes(&a_bytes).unwrap();
        let b = Nonce::from_bytes(&b_bytes).unwrap();
        assert!(!a.constant_time_eq(&b));
    }

    #[test]
    fn constant_time_eq_rejects_total_mismatch() {
        let a = Nonce::from_bytes(&[0x00; NONCE_LEN]).unwrap();
        let b = Nonce::from_bytes(&[0xFF; NONCE_LEN]).unwrap();
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
        // The bridge logs use these labels; review-stage diagnostics depend
        // on them being canonical.
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
        let a = generate_nonce();
        let b = generate_nonce();
        assert!(!a.constant_time_eq(&b));
    }
}
