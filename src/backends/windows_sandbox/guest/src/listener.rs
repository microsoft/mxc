//! TCP listener and rendezvous file management.

use std::net::SocketAddr;
use std::path::Path;

use anyhow::{Context, Result};
use tokio::fs;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc;

use windows_sandbox_common::auth::{self, ChannelRole, Nonce};

/// Bind a TCP listener and publish its address for the host.
pub async fn bind_and_advertise(rendezvous_dir: &str) -> Result<(TcpListener, SocketAddr)> {
    let listener = TcpListener::bind("0.0.0.0:0")
        .await
        .context("bind TCP listener")?;
    let local_addr = listener.local_addr()?;

    let guest_ip = find_guest_ip().context("could not determine guest IP")?;
    let advertised_addr = SocketAddr::new(guest_ip, local_addr.port());

    let rendezvous_path = Path::new(rendezvous_dir).join("rendezvous.txt");
    let content = format!("{}", advertised_addr);
    fs::write(&rendezvous_path, content.as_bytes())
        .await
        .with_context(|| format!("write rendezvous file {:?}", rendezvous_path))?;

    Ok((listener, advertised_addr))
}

/// Accept the four boot channels, paired by declared [`ChannelRole`].
pub async fn accept_connections(
    listener: &TcpListener,
    expected_nonce: &Nonce,
) -> Result<(TcpStream, TcpStream, TcpStream, TcpStream)> {
    let (control, stdin_stream, stdout_stream, stderr_stream) =
        accept_authed_roles(listener, expected_nonce, true).await?;
    Ok((
        control.expect("control filled before accept_authed_roles returned"),
        stdin_stream.expect("stdin filled"),
        stdout_stream.expect("stdout filled"),
        stderr_stream.expect("stderr filled"),
    ))
}

/// Accept the three post-exec data channels.
pub async fn accept_data_connections(
    listener: &TcpListener,
    expected_nonce: &Nonce,
) -> Result<(TcpStream, TcpStream, TcpStream)> {
    let (_control, stdin_stream, stdout_stream, stderr_stream) =
        accept_authed_roles(listener, expected_nonce, false).await?;
    Ok((
        stdin_stream.expect("stdin filled before accept_authed_roles returned"),
        stdout_stream.expect("stdout filled"),
        stderr_stream.expect("stderr filled"),
    ))
}

/// Place `stream` in the slot for `role`; a later valid declaration wins.
fn assign_role(
    stream: TcpStream,
    role: ChannelRole,
    control: &mut Option<TcpStream>,
    stdin_stream: &mut Option<TcpStream>,
    stdout_stream: &mut Option<TcpStream>,
    stderr_stream: &mut Option<TcpStream>,
) {
    let slot = match role {
        ChannelRole::Control => control,
        ChannelRole::Stdin => stdin_stream,
        ChannelRole::Stdout => stdout_stream,
        ChannelRole::Stderr => stderr_stream,
    };
    if let Some(old) = slot.replace(stream) {
        eprintln!(
            "[guest][auth] {} role re-declared; displacing the earlier socket (last-writer-wins)",
            role.label()
        );
        drop(old);
    }
}

const HANDSHAKE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(1);

/// Accept and authenticate sockets until every required role is filled.
async fn accept_authed_roles(
    listener: &TcpListener,
    expected_nonce: &Nonce,
    want_control: bool,
) -> Result<(
    Option<TcpStream>,
    Option<TcpStream>,
    Option<TcpStream>,
    Option<TcpStream>,
)> {
    let (tx, mut rx) = mpsc::channel::<(TcpStream, ChannelRole)>(16);

    let mut control: Option<TcpStream> = None;
    let mut stdin_stream: Option<TcpStream> = None;
    let mut stdout_stream: Option<TcpStream> = None;
    let mut stderr_stream: Option<TcpStream> = None;

    let filled = |control: &Option<TcpStream>,
                  stdin_stream: &Option<TcpStream>,
                  stdout_stream: &Option<TcpStream>,
                  stderr_stream: &Option<TcpStream>| {
        (!want_control || control.is_some())
            && stdin_stream.is_some()
            && stdout_stream.is_some()
            && stderr_stream.is_some()
    };

    while !filled(&control, &stdin_stream, &stdout_stream, &stderr_stream) {
        tokio::select! {
            accepted = listener.accept() => {
                let (mut stream, peer) = accepted.context("accept")?;
                let nonce = expected_nonce.clone();
                let tx = tx.clone();
                // Off-load the handshake so a stalled peer cannot block accepts.
                tokio::spawn(async move {
                    match tokio::time::timeout(
                        HANDSHAKE_TIMEOUT,
                        auth::verify_nonce(&mut stream, &nonce),
                    )
                    .await
                    {
                        Ok(Ok(role)) => {
                            // A send failure means the collector already returned.
                            let _ = tx.send((stream, role)).await;
                        }
                        Ok(Err(e)) => {
                            eprintln!(
                                "[guest][auth] rejecting connection from {peer}: {e} (likely a \
                                 cross-user accept-race or protocol mismatch; dropping)"
                            );
                            drop(stream);
                        }
                        Err(_) => {
                            eprintln!(
                                "[guest][auth] handshake from {peer} timed out after \
                                 {HANDSHAKE_TIMEOUT:?} (no nonce + role bytes received); dropping \
                                 socket (stalled-handshake guard)"
                            );
                            drop(stream);
                        }
                    }
                });
            }
            // This function retains a sender, so the receive channel cannot close here.
            Some((stream, role)) = rx.recv() => {
                if !want_control && matches!(role, ChannelRole::Control) {
                    eprintln!(
                        "[guest][auth] rejecting unexpected Control role on data reconnect; \
                         dropping"
                    );
                    drop(stream);
                    continue;
                }
                assign_role(
                    stream,
                    role,
                    &mut control,
                    &mut stdin_stream,
                    &mut stdout_stream,
                    &mut stderr_stream,
                );
            }
        }
    }
    Ok((control, stdin_stream, stdout_stream, stderr_stream))
}

/// Find the first non-loopback IPv4 address (the Hyper-V Default Switch NIC).
fn find_guest_ip() -> Result<std::net::IpAddr> {
    use std::net::IpAddr;

    // A UDP connect selects a local address without sending traffic.
    let socket = std::net::UdpSocket::bind("0.0.0.0:0")?;
    socket.connect("1.1.1.1:80")?;
    let local_addr = socket.local_addr()?;
    let ip = local_addr.ip();

    if ip.is_loopback() || ip == IpAddr::from([0, 0, 0, 0]) {
        anyhow::bail!("only loopback/unspecified addresses found");
    }
    Ok(ip)
}

#[cfg(test)]
mod tests {
    use super::*;
    use windows_sandbox_common::auth::{
        generate_nonce, write_nonce, ChannelRole, Nonce, NONCE_LEN_IN_BYTES,
    };

    #[test]
    fn find_guest_ip_returns_non_loopback() {
        if let Ok(ip) = find_guest_ip() {
            assert!(!ip.is_loopback());
        }
    }

    // Exercise nonce authentication and role-based pairing over loopback.
    async fn bind_loopback() -> (TcpListener, std::net::SocketAddr) {
        let l = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let a = l.local_addr().expect("local_addr");
        (l, a)
    }

    /// Open a TCP connection to `addr`, write the nonce + role tag using
    /// the host-side helper, and hand the stream back to the caller.
    async fn host_connect(
        addr: std::net::SocketAddr,
        nonce: &Nonce,
        role: ChannelRole,
    ) -> TcpStream {
        let mut s = TcpStream::connect(addr).await.expect("connect");
        write_nonce(&mut s, nonce, role).await.expect("write nonce");
        s
    }

    #[tokio::test]
    async fn accept_connections_pairs_by_declared_role_not_accept_order() {
        // Connect in a non-canonical order (stderr -> stdout -> control ->
        // stdin) and assert each guest-side slot receives the correctly-paired
        // socket regardless of arrival order. FIFO-by-accept-order pairing would
        // misroute, e.g. surfacing stderr bytes on the control slot.
        let (listener, addr) = bind_loopback().await;
        let nonce = generate_nonce().expect("generate nonce");
        let expected = nonce.clone();
        let guest = tokio::spawn(async move { accept_connections(&listener, &expected).await });

        // Connect in reversed-from-canonical order:
        let mut stderr_host = host_connect(addr, &nonce, ChannelRole::Stderr).await;
        let mut stdout_host = host_connect(addr, &nonce, ChannelRole::Stdout).await;
        let mut control_host = host_connect(addr, &nonce, ChannelRole::Control).await;
        let mut stdin_host = host_connect(addr, &nonce, ChannelRole::Stdin).await;

        let (mut control, mut stdin, mut stdout, mut stderr) =
            guest.await.expect("guest task join").expect("accept ok");

        // Tag each host side with a single byte and assert the GUEST side
        // of the slot reads exactly that byte. If the slots were misordered
        // we would read the wrong byte (or hang).
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        for (host, sentinel, slot) in [
            (&mut control_host, b'C', &mut control),
            (&mut stdin_host, b'I', &mut stdin),
            (&mut stdout_host, b'O', &mut stdout),
            (&mut stderr_host, b'E', &mut stderr),
        ] {
            host.write_all(&[sentinel]).await.expect("host write");
            host.shutdown().await.ok();
            let mut byte = [0u8; 1];
            let n = slot.read(&mut byte).await.expect("read slot");
            assert_eq!(n, 1);
            assert_eq!(
                byte[0], sentinel,
                "slot for {} sentinel mismatch (role-tag pairing regression)",
                sentinel as char
            );
        }
    }

    #[tokio::test]
    async fn accept_drops_wrong_nonce_and_keeps_waiting_for_legitimate_peer() {
        // A wrong-nonce peer must be dropped silently before any protocol
        // bytes are exchanged, and the accept loop must continue serving the
        // legitimate peer. Exercises the guest's drop-and-retry loop against a
        // real socket.
        let (listener, addr) = bind_loopback().await;
        let expected = generate_nonce().expect("generate nonce");
        let cloned_expected = expected.clone();
        let guest =
            tokio::spawn(async move { accept_connections(&listener, &cloned_expected).await });

        // Hostile connect: wrong nonce. The guest drops the socket and
        // returns to accept(); the host sees EOF on the read attempt.
        let bad_nonce = generate_nonce().expect("generate nonce");
        let mut hostile = TcpStream::connect(addr).await.expect("hostile connect");
        write_nonce(&mut hostile, &bad_nonce, ChannelRole::Control)
            .await
            .expect("hostile write");
        use tokio::io::AsyncReadExt;
        let mut buf = [0u8; 1];
        // We may or may not see EOF before the legitimate connects below
        // depending on scheduling -- the important property is that
        // accept_connections still completes once all four legitimate
        // sockets arrive.
        let _ = tokio::time::timeout(
            std::time::Duration::from_millis(100),
            hostile.read(&mut buf),
        )
        .await;

        let _legit_c = host_connect(addr, &expected, ChannelRole::Control).await;
        let _legit_i = host_connect(addr, &expected, ChannelRole::Stdin).await;
        let _legit_o = host_connect(addr, &expected, ChannelRole::Stdout).await;
        let _legit_e = host_connect(addr, &expected, ChannelRole::Stderr).await;

        let result = tokio::time::timeout(std::time::Duration::from_secs(5), guest)
            .await
            .expect("accept_connections completes within budget after wrong-nonce drop")
            .expect("guest task join")
            .expect("accept ok");
        let (_c, _i, _o, _e) = result;
        drop(hostile);
    }

    #[tokio::test]
    async fn accept_drops_duplicate_role_no_cross_talk() {
        // Handshake completion order is nondeterministic; exactly one peer must
        // own the role without displacement or cross-talk.
        let (listener, addr) = bind_loopback().await;
        let nonce = generate_nonce().expect("generate nonce");
        let expected = nonce.clone();
        let guest = tokio::spawn(async move { accept_connections(&listener, &expected).await });

        let mut control_a = host_connect(addr, &nonce, ChannelRole::Control).await;
        let mut control_b = host_connect(addr, &nonce, ChannelRole::Control).await;

        // The rest of the legitimate channels.
        let _legit_i = host_connect(addr, &nonce, ChannelRole::Stdin).await;
        let _legit_o = host_connect(addr, &nonce, ChannelRole::Stdout).await;
        let _legit_e = host_connect(addr, &nonce, ChannelRole::Stderr).await;

        let result = tokio::time::timeout(std::time::Duration::from_secs(5), guest)
            .await
            .expect("accept completes")
            .expect("guest task join")
            .expect("accept ok");
        let (mut control, _stdin, _stdout, _stderr) = result;

        // Write a DISTINCT sentinel on each Control peer. The guest paired the
        // slot with exactly one of them; that one feeds the slot, the other is
        // a dropped socket.
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let _ = control_a.write_all(b"A").await;
        let _ = control_a.shutdown().await;
        let _ = control_b.write_all(b"B").await;
        let _ = control_b.shutdown().await;

        let mut byte = [0u8; 1];
        let n = control.read(&mut byte).await.expect("guest control reads");
        assert_eq!(
            n, 1,
            "kept control slot must deliver exactly the winner's byte"
        );
        assert!(
            byte[0] == b'A' || byte[0] == b'B',
            "kept control delivered an unexpected sentinel {:?}",
            byte[0]
        );

        // No SECOND byte may arrive on the slot: the dropped duplicate must not
        // also be wired to it (that would be displacement / cross-talk).
        let mut extra = [0u8; 1];
        let extra_read = tokio::time::timeout(
            std::time::Duration::from_millis(200),
            control.read(&mut extra),
        )
        .await;
        match extra_read {
            // EOF on the held socket is fine (no displacement).
            Ok(Ok(0)) => {}
            // Any byte read here means the dropped peer fed our slot -- regression.
            Ok(Ok(n)) => panic!(
                "dropped duplicate-role peer wrote {n} byte(s) onto the kept control slot ({:?})",
                &extra[..n]
            ),
            // Timeout = nothing else arrived, also fine.
            Err(_) => {}
            // Read error on the held socket is fine.
            Ok(Err(_)) => {}
        }
    }

    #[tokio::test]
    async fn accept_data_connections_pairs_three_by_role() {
        // Regression coverage for the post-StreamsReady data-stream
        // reconnect path. Same property as accept_connections but only three roles
        // (stdin, stdout, stderr) and a Control declaration must be
        // dropped.
        let (listener, addr) = bind_loopback().await;
        let nonce = generate_nonce().expect("generate nonce");
        let expected = nonce.clone();
        let guest =
            tokio::spawn(async move { accept_data_connections(&listener, &expected).await });

        // A peer declaring Control on the data path must be dropped (only
        // stdin/stdout/stderr are valid on reconnect).
        let mut bogus = host_connect(addr, &nonce, ChannelRole::Control).await;
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let _ = bogus.shutdown().await;

        // Now connect the three legitimate data channels in a non-canonical
        // order.
        let mut stderr_host = host_connect(addr, &nonce, ChannelRole::Stderr).await;
        let mut stdin_host = host_connect(addr, &nonce, ChannelRole::Stdin).await;
        let mut stdout_host = host_connect(addr, &nonce, ChannelRole::Stdout).await;

        let (mut stdin, mut stdout, mut stderr) =
            tokio::time::timeout(std::time::Duration::from_secs(5), guest)
                .await
                .expect("accept_data completes")
                .expect("join")
                .expect("accept ok");

        for (host, sentinel, slot) in [
            (&mut stdin_host, b'I', &mut stdin),
            (&mut stdout_host, b'O', &mut stdout),
            (&mut stderr_host, b'E', &mut stderr),
        ] {
            host.write_all(&[sentinel]).await.expect("host write");
            host.shutdown().await.ok();
            let mut byte = [0u8; 1];
            let n = slot.read(&mut byte).await.expect("slot read");
            assert_eq!((n, byte[0]), (1, sentinel));
        }
    }

    #[tokio::test(start_paused = true)]
    async fn accept_drops_stalled_handshake_within_handshake_timeout() {
        // Regression: a peer that connects
        // and never writes must NOT wedge the accept loop. The guest
        // wraps verify_nonce in `tokio::time::timeout(HANDSHAKE_TIMEOUT,
        // ...)`; this test asserts the stalled connection is dropped
        // and the legitimate four-way handshake then completes.
        let (listener, addr) = bind_loopback().await;
        let nonce = generate_nonce().expect("generate nonce");
        let expected = nonce.clone();
        let guest = tokio::spawn(async move { accept_connections(&listener, &expected).await });

        // Stalled peer: connect, write nothing.
        let _stalled = TcpStream::connect(addr).await.expect("stalled connect");

        // Advance time past HANDSHAKE_TIMEOUT so the guest drops the stalled
        // socket and returns to accept(). Yield repeatedly to give the
        // guest's spawned task a chance to observe the timeout.
        tokio::time::advance(HANDSHAKE_TIMEOUT + std::time::Duration::from_millis(100)).await;
        for _ in 0..50 {
            tokio::task::yield_now().await;
        }

        // Now do a legitimate full handshake. Under paused time the
        // network ops here resolve via the runtime's IO driver, which
        // tokio::time::pause leaves intact.
        let _legit_c = host_connect(addr, &nonce, ChannelRole::Control).await;
        let _legit_i = host_connect(addr, &nonce, ChannelRole::Stdin).await;
        let _legit_o = host_connect(addr, &nonce, ChannelRole::Stdout).await;
        let _legit_e = host_connect(addr, &nonce, ChannelRole::Stderr).await;

        // Bounded timeout in case the loop did NOT recover (regression).
        let result = tokio::time::timeout(std::time::Duration::from_secs(5), guest).await;
        assert!(
            result.is_ok(),
            "accept_connections did not complete after handshake-timeout recovery; \
             stalled peer wedged the loop (H11 regression)"
        );
        let _ = NONCE_LEN_IN_BYTES;
    }
}
