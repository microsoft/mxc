// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Records the outbound connections a sandbox's firewall blocked
//! (`network.egress.blockedLog`).
//!
//! Every blocking verdict in the sandbox's egress chain is preceded by an
//! `NFLOG` copy of the packet to [`BLOCKED_LOG_GROUP`]. This module listens on
//! that group from *inside* the sandbox's network namespace, where `NFLOG`
//! delivers, and appends one JSON line per distinct destination to the file
//! the caller named:
//!
//! ```json
//! {"protocol":"tcp","host":"172.17.0.4","port":5432}
//! {"protocol":"udp","host":"10.0.2.3","port":53,"name":"rubygems.org"}
//! ```
//!
//! `name` is a DNS question's name, for a lookup the firewall blocked.
//!
//! The listening socket is made by a short-lived child: joining the
//! namespace needs `setns` into the sandbox's user namespace first, which a
//! multithreaded process can't do. The child joins both, opens and binds the
//! netlink socket, hands it back over a socket pair and exits. A netlink
//! socket stays in the namespace it was made in, so this process reads the
//! sandbox's log from its own. It is started after the rules are in force and
//! before the workload is released, so nothing the workload sends is missed.

use std::collections::HashSet;
use std::ffi::CString;
use std::fs::{File, OpenOptions};
use std::io::Write;
use std::net::Ipv4Addr;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::fs::OpenOptionsExt;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread::JoinHandle;

use super::network_rules::{BLOCKED_LOG_GROUP, BLOCKED_LOG_SNAPLEN};

/// `NETLINK_NETFILTER`.
const NETLINK_NETFILTER: libc::c_int = 12;
/// `NFNL_SUBSYS_ULOG`, the subsystem `nfnetlink_log` answers on.
const NFNL_SUBSYS_ULOG: u16 = 4;
const NFULNL_MSG_PACKET: u16 = 0;
const NFULNL_MSG_CONFIG: u16 = 1;
const NFULA_CFG_CMD: u16 = 1;
const NFULA_CFG_MODE: u16 = 2;
/// How many packets the kernel batches before it sends them (100 by
/// default, or a second's worth): one, so a short command's last refusal
/// isn't still waiting when it ends.
const NFULA_CFG_QTHRESH: u16 = 4;
const NFULNL_CFG_CMD_BIND: u8 = 1;
const NFULNL_COPY_PACKET: u8 = 2;
const NFULA_PAYLOAD: u16 = 9;
/// `NS_GET_USERNS`: the user namespace that owns a namespace.
const NS_GET_USERNS: libc::c_ulong = 0xb701;
/// At most this many distinct destinations are written: a scan of a whole
/// network is reported by its start, not line by line.
const MAX_ENTRIES: usize = 256;
/// How often the reader looks for its stop.
const POLL_MS: libc::c_int = 100;

/// A running reader. Dropping it stops the reader and closes its socket,
/// after reading what is already queued.
pub(crate) struct BlockedLog {
    stop: Arc<AtomicBool>,
    thread: Option<JoinHandle<()>>,
}

impl BlockedLog {
    /// Listen to the blocked-connection log of the network namespace
    /// `child_pid` is in, appending to `path` (made `0600` if missing).
    pub(crate) fn start(child_pid: u32, path: &str) -> Result<Self, String> {
        let file = OpenOptions::new()
            .append(true)
            .create(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW)
            .open(path)
            .map_err(|error| {
                format!("Bubblewrap: failed to open the blocked-connection log: {error}")
            })?;
        let socket = socket_in_namespace(child_pid)?;
        configure(&socket)?;
        let stop = Arc::new(AtomicBool::new(false));
        let thread = std::thread::Builder::new()
            .name("mxc-blocked-log".to_string())
            .spawn({
                let stop = stop.clone();
                move || read(socket, file, &stop)
            })
            .map_err(|error| format!("Bubblewrap: failed to start the blocked log: {error}"))?;
        Ok(Self {
            stop,
            thread: Some(thread),
        })
    }
}

impl Drop for BlockedLog {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

/// A netlink socket made in `child_pid`'s network namespace.
fn socket_in_namespace(child_pid: u32) -> Result<OwnedFd, String> {
    let net = CString::new(format!("/proc/{child_pid}/ns/net")).expect("no NUL in a path");
    let mut pair = [0 as RawFd; 2];
    // SAFETY: `pair` has room for the two descriptors socketpair writes.
    if unsafe {
        libc::socketpair(
            libc::AF_UNIX,
            libc::SOCK_DGRAM | libc::SOCK_CLOEXEC,
            0,
            pair.as_mut_ptr(),
        )
    } != 0
    {
        return Err(format!(
            "Bubblewrap: socketpair failed: {}",
            std::io::Error::last_os_error()
        ));
    }
    // SAFETY: socketpair succeeded, so both are open descriptors we own.
    let (ours, theirs) = unsafe { (OwnedFd::from_raw_fd(pair[0]), OwnedFd::from_raw_fd(pair[1])) };
    // SAFETY: the child calls only async-signal-safe system calls on memory
    // prepared before the fork, then `_exit`s; it never returns here.
    let pid = unsafe { libc::fork() };
    if pid < 0 {
        return Err(format!(
            "Bubblewrap: fork failed: {}",
            std::io::Error::last_os_error()
        ));
    }
    if pid == 0 {
        // SAFETY: as above; this is the child.
        unsafe { libc::_exit(child(net.as_ptr(), theirs.as_raw_fd())) };
    }
    drop(theirs);
    let mut status = 0;
    // SAFETY: waiting for the child just forked.
    unsafe { libc::waitpid(pid, &mut status, 0) };
    if !libc::WIFEXITED(status) || libc::WEXITSTATUS(status) != 0 {
        let step = match libc::WEXITSTATUS(status) {
            2 => "open the sandbox's network namespace",
            3 => "find its user namespace",
            4 => "join its user namespace",
            5 => "join its network namespace",
            6 => "open a netlink socket there",
            7 => "bind it",
            8 => "hand it back",
            _ => "start",
        };
        return Err(format!(
            "Bubblewrap: the blocked-connection log couldn't {step} (status {status})"
        ));
    }
    receive_fd(&ours)
}

/// The forked child: join the namespaces, make and bind the socket, send it.
/// Only system calls, no allocation.
unsafe fn child(net_path: *const libc::c_char, channel: RawFd) -> libc::c_int {
    unsafe {
        let net = libc::open(net_path, libc::O_RDONLY | libc::O_CLOEXEC);
        if net < 0 {
            return 2;
        }
        let user = libc::ioctl(net, NS_GET_USERNS as _);
        if user < 0 {
            return 3;
        }
        if libc::setns(user, libc::CLONE_NEWUSER) != 0 {
            return 4;
        }
        if libc::setns(net, libc::CLONE_NEWNET) != 0 {
            return 5;
        }
        let socket = libc::socket(
            libc::AF_NETLINK,
            libc::SOCK_RAW | libc::SOCK_CLOEXEC,
            NETLINK_NETFILTER,
        );
        if socket < 0 {
            return 6;
        }
        let mut address: libc::sockaddr_nl = std::mem::zeroed();
        address.nl_family = libc::AF_NETLINK as libc::sa_family_t;
        if libc::bind(
            socket,
            &address as *const libc::sockaddr_nl as *const libc::sockaddr,
            std::mem::size_of::<libc::sockaddr_nl>() as libc::socklen_t,
        ) != 0
        {
            return 7;
        }
        if send_fd(channel, socket) != 0 {
            return 8;
        }
        0
    }
}

/// Send `fd` over `channel` (`SCM_RIGHTS`), with stack buffers only.
unsafe fn send_fd(channel: RawFd, fd: RawFd) -> libc::c_int {
    unsafe {
        let mut byte = [0u8; 1];
        let mut iov = libc::iovec {
            iov_base: byte.as_mut_ptr() as *mut libc::c_void,
            iov_len: 1,
        };
        let mut control = [0u64; 4];
        let mut message: libc::msghdr = std::mem::zeroed();
        message.msg_iov = &mut iov;
        message.msg_iovlen = 1;
        message.msg_control = control.as_mut_ptr() as *mut libc::c_void;
        message.msg_controllen = libc::CMSG_SPACE(std::mem::size_of::<RawFd>() as u32) as _;
        let header = libc::CMSG_FIRSTHDR(&message);
        (*header).cmsg_level = libc::SOL_SOCKET;
        (*header).cmsg_type = libc::SCM_RIGHTS;
        (*header).cmsg_len = libc::CMSG_LEN(std::mem::size_of::<RawFd>() as u32) as _;
        std::ptr::write_unaligned(libc::CMSG_DATA(header) as *mut RawFd, fd);
        if libc::sendmsg(channel, &message, 0) < 0 {
            1
        } else {
            0
        }
    }
}

fn receive_fd(channel: &OwnedFd) -> Result<OwnedFd, String> {
    let mut byte = [0u8; 1];
    let mut iov = libc::iovec {
        iov_base: byte.as_mut_ptr() as *mut libc::c_void,
        iov_len: 1,
    };
    let mut control = [0u64; 4];
    // SAFETY: zeroed msghdr is a valid empty message header.
    let mut message: libc::msghdr = unsafe { std::mem::zeroed() };
    message.msg_iov = &mut iov;
    message.msg_iovlen = 1;
    message.msg_control = control.as_mut_ptr() as *mut libc::c_void;
    message.msg_controllen = std::mem::size_of_val(&control) as _;
    // SAFETY: the buffers above outlive the call.
    let received =
        unsafe { libc::recvmsg(channel.as_raw_fd(), &mut message, libc::MSG_CMSG_CLOEXEC) };
    if received < 0 {
        return Err(format!(
            "Bubblewrap: failed to receive the blocked-connection socket: {}",
            std::io::Error::last_os_error()
        ));
    }
    // SAFETY: the header and data are read within the received control buffer.
    unsafe {
        let header = libc::CMSG_FIRSTHDR(&message);
        if header.is_null()
            || (*header).cmsg_level != libc::SOL_SOCKET
            || (*header).cmsg_type != libc::SCM_RIGHTS
        {
            return Err("Bubblewrap: the blocked-connection socket didn't arrive".to_string());
        }
        let fd = std::ptr::read_unaligned(libc::CMSG_DATA(header) as *const RawFd);
        Ok(OwnedFd::from_raw_fd(fd))
    }
}

/// One netlink message to `nfnetlink_log`: header, `nfgenmsg`, one attribute.
fn config_message(family: u8, attribute: u16, value: &[u8], sequence: u32) -> Vec<u8> {
    let attribute_length = 4 + value.len();
    let padded = (attribute_length + 3) & !3;
    let length = 16 + 4 + padded;
    let mut message = Vec::with_capacity(length);
    message.extend_from_slice(&(length as u32).to_ne_bytes());
    let kind = (NFNL_SUBSYS_ULOG << 8) | NFULNL_MSG_CONFIG;
    message.extend_from_slice(&kind.to_ne_bytes());
    let flags = (libc::NLM_F_REQUEST | libc::NLM_F_ACK) as u16;
    message.extend_from_slice(&flags.to_ne_bytes());
    message.extend_from_slice(&sequence.to_ne_bytes());
    message.extend_from_slice(&0u32.to_ne_bytes());
    // nfgenmsg: family, version, resource id (the group, big-endian).
    message.push(family);
    message.push(0);
    message.extend_from_slice(&BLOCKED_LOG_GROUP.to_be_bytes());
    message.extend_from_slice(&(attribute_length as u16).to_ne_bytes());
    message.extend_from_slice(&attribute.to_ne_bytes());
    message.extend_from_slice(value);
    message.resize(length, 0);
    message
}

/// Bind the socket to the group, ask for each packet's start, and have each
/// sent at once.
fn configure(socket: &OwnedFd) -> Result<(), String> {
    let mut mode = Vec::new();
    mode.extend_from_slice(&BLOCKED_LOG_SNAPLEN.to_be_bytes());
    mode.push(NFULNL_COPY_PACKET);
    mode.push(0);
    for (sequence, message) in [
        config_message(
            libc::AF_UNSPEC as u8,
            NFULA_CFG_CMD,
            &[NFULNL_CFG_CMD_BIND],
            1,
        ),
        config_message(libc::AF_UNSPEC as u8, NFULA_CFG_MODE, &mode, 2),
        config_message(
            libc::AF_UNSPEC as u8,
            NFULA_CFG_QTHRESH,
            &1u32.to_be_bytes(),
            3,
        ),
    ]
    .into_iter()
    .enumerate()
    {
        // SAFETY: sending an owned buffer on an open socket.
        let sent = unsafe {
            libc::send(
                socket.as_raw_fd(),
                message.as_ptr() as *const libc::c_void,
                message.len(),
                0,
            )
        };
        if sent < 0 {
            return Err(format!(
                "Bubblewrap: failed to configure the blocked-connection log: {}",
                std::io::Error::last_os_error()
            ));
        }
        let mut answer = [0u8; 256];
        // SAFETY: reading into a stack buffer.
        let read = unsafe {
            libc::recv(
                socket.as_raw_fd(),
                answer.as_mut_ptr() as *mut libc::c_void,
                answer.len(),
                0,
            )
        };
        if read >= 20 {
            let kind = u16::from_ne_bytes([answer[4], answer[5]]);
            let error = i32::from_ne_bytes([answer[16], answer[17], answer[18], answer[19]]);
            if kind == libc::NLMSG_ERROR as u16 && error != 0 {
                return Err(format!(
                    "Bubblewrap: the kernel refused the blocked-connection log (step {}): {}",
                    sequence + 1,
                    std::io::Error::from_raw_os_error(-error)
                ));
            }
        }
    }
    Ok(())
}

/// A blocked destination, as one line of the log.
#[derive(Debug, Clone, PartialEq, Eq, Hash, serde::Serialize)]
pub(crate) struct Blocked {
    pub protocol: &'static str,
    pub host: String,
    pub port: u16,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
}

fn read(socket: OwnedFd, mut file: File, stop: &AtomicBool) {
    let mut seen: HashSet<Blocked> = HashSet::new();
    let mut buffer = vec![0u8; 65536];
    loop {
        let stopping = stop.load(Ordering::SeqCst);
        let mut poll = libc::pollfd {
            fd: socket.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        // SAFETY: polling one open descriptor.
        let ready = unsafe { libc::poll(&mut poll, 1, if stopping { 0 } else { POLL_MS }) };
        if ready <= 0 {
            if stopping {
                return;
            }
            continue;
        }
        // SAFETY: reading into an owned buffer.
        let read = unsafe {
            libc::recv(
                socket.as_raw_fd(),
                buffer.as_mut_ptr() as *mut libc::c_void,
                buffer.len(),
                libc::MSG_DONTWAIT,
            )
        };
        if read <= 0 {
            // ENOBUFS means some copies were lost under load: keep reading.
            continue;
        }
        for payload in packets(&buffer[..read as usize]) {
            let Some(blocked) = parse_packet(payload) else {
                continue;
            };
            if seen.len() >= MAX_ENTRIES || !seen.insert(blocked.clone()) {
                continue;
            }
            if let Ok(mut line) = serde_json::to_string(&blocked) {
                line.push('\n');
                let _ = file.write_all(line.as_bytes());
            }
        }
    }
}

/// The packet payloads in one read of netlink messages.
pub(crate) fn packets(mut data: &[u8]) -> Vec<&[u8]> {
    let mut found = Vec::new();
    while data.len() >= 16 {
        let length = u32::from_ne_bytes([data[0], data[1], data[2], data[3]]) as usize;
        let kind = u16::from_ne_bytes([data[4], data[5]]);
        if length < 16 || length > data.len() {
            break;
        }
        if kind == (NFNL_SUBSYS_ULOG << 8) | NFULNL_MSG_PACKET && length > 20 {
            let mut attributes = &data[20..length];
            while attributes.len() >= 4 {
                let size = u16::from_ne_bytes([attributes[0], attributes[1]]) as usize;
                let kind = u16::from_ne_bytes([attributes[2], attributes[3]]) & 0x3fff;
                if size < 4 || size > attributes.len() {
                    break;
                }
                if kind == NFULA_PAYLOAD {
                    found.push(&attributes[4..size]);
                }
                let next = (size + 3) & !3;
                attributes = &attributes[next.min(attributes.len())..];
            }
        }
        let next = (length + 3) & !3;
        data = &data[next.min(data.len())..];
    }
    found
}

/// The destination of an IPv4 packet, and a DNS question's name.
pub(crate) fn parse_packet(packet: &[u8]) -> Option<Blocked> {
    if packet.len() < 20 || packet[0] >> 4 != 4 {
        return None;
    }
    let header = usize::from(packet[0] & 0x0f) * 4;
    let destination = Ipv4Addr::new(packet[16], packet[17], packet[18], packet[19]);
    let protocol = match packet[9] {
        6 => "tcp",
        17 => "udp",
        _ => return None,
    };
    let transport = packet.get(header..)?;
    let port = u16::from_be_bytes([*transport.get(2)?, *transport.get(3)?]);
    let name = if protocol == "udp" && port == 53 {
        transport.get(8..).and_then(dns_question)
    } else {
        None
    };
    Some(Blocked {
        protocol,
        host: destination.to_string(),
        port,
        name,
    })
}

/// The first question's name in a DNS query, in lower case.
fn dns_question(message: &[u8]) -> Option<String> {
    let mut labels: Vec<String> = Vec::new();
    let mut at = 12;
    loop {
        let length = usize::from(*message.get(at)?);
        if length == 0 {
            break;
        }
        if length > 63 || labels.len() > 127 {
            return None;
        }
        let label = message.get(at + 1..at + 1 + length)?;
        if !label
            .iter()
            .all(|b| b.is_ascii_alphanumeric() || *b == b'-' || *b == b'_')
        {
            return None;
        }
        labels.push(String::from_utf8_lossy(label).to_ascii_lowercase());
        at += 1 + length;
    }
    (!labels.is_empty()).then(|| labels.join("."))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ipv4(protocol: u8, destination: [u8; 4], transport: &[u8]) -> Vec<u8> {
        let mut packet = vec![0x45, 0, 0, 0, 0, 0, 0, 0, 64, protocol, 0, 0, 10, 0, 2, 100];
        packet.extend_from_slice(&destination);
        packet.extend_from_slice(transport);
        packet
    }

    #[test]
    fn a_tcp_packet_names_its_destination() {
        let packet = ipv4(6, [172, 17, 0, 4], &[0xc3, 0x50, 0x15, 0x38, 0, 0, 0, 0]);
        assert_eq!(
            parse_packet(&packet),
            Some(Blocked {
                protocol: "tcp",
                host: "172.17.0.4".to_string(),
                port: 5432,
                name: None,
            })
        );
    }

    #[test]
    fn a_dns_query_names_what_it_looked_up() {
        let mut udp = vec![0xc3, 0x50, 0, 53, 0, 0, 0, 0];
        udp.extend_from_slice(&[0x12, 0x34, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0]);
        udp.extend_from_slice(b"\x08RubyGems\x03org\x00\x00\x01\x00\x01");
        let blocked = parse_packet(&ipv4(17, [10, 0, 2, 3], &udp)).unwrap();
        assert_eq!(blocked.port, 53);
        assert_eq!(blocked.name.as_deref(), Some("rubygems.org"));
    }

    #[test]
    fn other_protocols_and_short_packets_are_skipped() {
        assert_eq!(parse_packet(&ipv4(1, [8, 8, 8, 8], &[8, 0, 0, 0])), None);
        assert_eq!(parse_packet(&[0x45, 0, 0]), None);
        assert_eq!(parse_packet(&ipv4(6, [8, 8, 8, 8], &[0, 1])), None);
    }

    #[test]
    fn packets_are_found_in_their_netlink_messages() {
        let payload = ipv4(6, [1, 2, 3, 4], &[0, 1, 1, 187]);
        let mut message = Vec::new();
        let attribute_length = 4 + payload.len();
        let padded = (attribute_length + 3) & !3;
        let length = 20 + padded;
        message.extend_from_slice(&(length as u32).to_ne_bytes());
        message.extend_from_slice(&((NFNL_SUBSYS_ULOG << 8) | NFULNL_MSG_PACKET).to_ne_bytes());
        message.extend_from_slice(&[0; 10]);
        message.extend_from_slice(&[2, 0, 0x4d, 0x58]);
        message.extend_from_slice(&(attribute_length as u16).to_ne_bytes());
        message.extend_from_slice(&NFULA_PAYLOAD.to_ne_bytes());
        message.extend_from_slice(&payload);
        message.resize(length, 0);
        let found = packets(&message);
        assert_eq!(found, vec![payload.as_slice()]);
        assert_eq!(parse_packet(found[0]).unwrap().port, 443);
    }

    #[test]
    fn config_messages_name_the_group() {
        let message = config_message(0, NFULA_CFG_CMD, &[NFULNL_CFG_CMD_BIND], 1);
        assert_eq!(message.len(), 28);
        assert_eq!(&message[18..20], &BLOCKED_LOG_GROUP.to_be_bytes());
    }
}
