// netcheck — minimal TCP reachability probe for the MXC `allowLocalNetwork`
// tests. One binary, two roles selected by the first argument:
//
//   netcheck serve   --port <P> [--hold <S>]
//       Bind 0.0.0.0:P, accept ONE client, reply "PONG". Exits 0 after serving
//       a client, or after <hold> seconds with no client (so a DROP rule can
//       never hang the container). Run this INSIDE the sandbox via MXC.
//
//   netcheck connect --host <H> --port <P> [--timeout <S>]
//       Connect to H:P, send "PING", expect "PONG". Exit 0 = reachable,
//       exit 1 = blocked/unreachable. Run this as the client (host or peer).
//
// std-only so it builds as a fully static musl binary and runs unmodified in
// the Alpine sandbox rootfs:
//   rustc --edition 2021 -O --target x86_64-unknown-linux-musl \
//         -C target-feature=+crt-static netcheck.rs -o netcheck

use std::env;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream, ToSocketAddrs};
use std::process::exit;
use std::thread;
use std::time::Duration;

fn arg_val(args: &[String], key: &str) -> Option<String> {
    args.iter()
        .position(|a| a == key)
        .and_then(|i| args.get(i + 1))
        .cloned()
}

fn main() {
    let args: Vec<String> = env::args().collect();
    match args.get(1).map(String::as_str) {
        Some("serve") => serve(&args),
        Some("connect") => connect(&args),
        _ => {
            eprintln!(
                "usage: netcheck <serve|connect> [--host H] [--port P] [--hold S] [--timeout S]"
            );
            exit(2);
        }
    }
}

fn serve(args: &[String]) {
    let port: u16 = arg_val(args, "--port")
        .and_then(|v| v.parse().ok())
        .unwrap_or(5000);
    let hold: u64 = arg_val(args, "--hold")
        .and_then(|v| v.parse().ok())
        .unwrap_or(30);
    let addr = format!("0.0.0.0:{port}");

    // Bound the process lifetime: if a DROP rule prevents any client from
    // arriving, exit cleanly rather than blocking until the MXC timeout.
    thread::spawn(move || {
        thread::sleep(Duration::from_secs(hold));
        println!("NETCHECK_NO_CLIENT after {hold}s");
        exit(0);
    });

    let listener = match TcpListener::bind(&addr) {
        Ok(l) => l,
        Err(e) => {
            eprintln!("NETCHECK_BIND_FAIL {addr} {e}");
            exit(1);
        }
    };
    println!("NETCHECK_SERVER_READY {addr}");

    match listener.accept() {
        Ok((mut stream, peer)) => {
            let mut buf = [0u8; 16];
            stream.set_read_timeout(Some(Duration::from_secs(5))).ok();
            let n = stream.read(&mut buf).unwrap_or(0);
            let _ = stream.write_all(b"PONG");
            println!("NETCHECK_SERVED {peer} bytes={n}");
            exit(0);
        }
        Err(e) => {
            eprintln!("NETCHECK_ACCEPT_FAIL {e}");
            exit(1);
        }
    }
}

fn connect(args: &[String]) {
    let host = arg_val(args, "--host").unwrap_or_else(|| "127.0.0.1".to_string());
    let port: u16 = arg_val(args, "--port")
        .and_then(|v| v.parse().ok())
        .unwrap_or(5000);
    let timeout: u64 = arg_val(args, "--timeout")
        .and_then(|v| v.parse().ok())
        .unwrap_or(5);
    let target = format!("{host}:{port}");

    let addr = match target.to_socket_addrs().ok().and_then(|mut it| it.next()) {
        Some(a) => a,
        None => {
            eprintln!("NETCHECK_RESOLVE_FAIL {target}");
            exit(1);
        }
    };
    let mut stream = match TcpStream::connect_timeout(&addr, Duration::from_secs(timeout)) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("NETCHECK_CONNECT_FAIL {target} {e}");
            exit(1);
        }
    };
    stream.set_read_timeout(Some(Duration::from_secs(timeout))).ok();
    stream
        .set_write_timeout(Some(Duration::from_secs(timeout)))
        .ok();
    if let Err(e) = stream.write_all(b"PING") {
        eprintln!("NETCHECK_SEND_FAIL {e}");
        exit(1);
    }
    let mut buf = [0u8; 16];
    let n = stream.read(&mut buf).unwrap_or(0);
    if &buf[..n] == b"PONG" {
        println!("NETCHECK_OK {target}");
        exit(0);
    }
    eprintln!("NETCHECK_BAD_REPLY {target} bytes={n}");
    exit(1);
}
