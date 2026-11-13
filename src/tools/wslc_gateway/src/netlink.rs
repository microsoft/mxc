// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Minimal netlink: add the relay address (rtnetlink) and install the nftables redirect.
//! Constants come from linux/netlink.h, linux/rtnetlink.h and linux/netfilter/nf_tables.h.

use std::io;
use std::mem::{size_of, zeroed};
use std::net::Ipv4Addr;

const NLMSG_ERROR: u16 = 2;
const NLM_F_REQUEST: u16 = 0x1;
const NLM_F_ACK: u16 = 0x4;
const NLM_F_EXCL: u16 = 0x200;
const NLM_F_CREATE: u16 = 0x400;
const NLM_F_APPEND: u16 = 0x800;
const NLA_F_NESTED: u16 = 0x8000;

const RTM_NEWADDR: u16 = 20;
const IFA_ADDRESS: u16 = 1;
const IFA_LOCAL: u16 = 2;

const NETLINK_NETFILTER: i32 = 12;
const NFNL_SUBSYS_NFTABLES: u16 = 10;
const NFNL_MSG_BATCH_BEGIN: u16 = 16;
const NFNL_MSG_BATCH_END: u16 = 17;
const NFT_MSG_NEWTABLE: u16 = 0;
const NFT_MSG_NEWCHAIN: u16 = 3;
const NFT_MSG_NEWRULE: u16 = 6;
const NFPROTO_IPV4: u8 = 2;
const NF_INET_PRE_ROUTING: u32 = 0;
const NF_IP_PRI_NAT_DST: i32 = -100;

const NFTA_TABLE_NAME: u16 = 1;
const NFTA_CHAIN_TABLE: u16 = 1;
const NFTA_CHAIN_NAME: u16 = 3;
const NFTA_CHAIN_HOOK: u16 = 4;
const NFTA_CHAIN_TYPE: u16 = 7;
const NFTA_HOOK_HOOKNUM: u16 = 1;
const NFTA_HOOK_PRIORITY: u16 = 2;
const NFTA_RULE_TABLE: u16 = 1;
const NFTA_RULE_CHAIN: u16 = 2;
const NFTA_RULE_EXPRESSIONS: u16 = 4;
const NFTA_LIST_ELEM: u16 = 1;
const NFTA_EXPR_NAME: u16 = 1;
const NFTA_EXPR_DATA: u16 = 2;
const NFTA_DATA_VALUE: u16 = 1;
const NFTA_PAYLOAD_DREG: u16 = 1;
const NFTA_PAYLOAD_BASE: u16 = 2;
const NFTA_PAYLOAD_OFFSET: u16 = 3;
const NFTA_PAYLOAD_LEN: u16 = 4;
const NFT_PAYLOAD_NETWORK_HEADER: u32 = 1;
const NFTA_CMP_SREG: u16 = 1;
const NFTA_CMP_OP: u16 = 2;
const NFTA_CMP_DATA: u16 = 3;
const NFT_CMP_EQ: u32 = 0;
const NFTA_META_DREG: u16 = 1;
const NFTA_META_KEY: u16 = 2;
const NFT_META_L4PROTO: u32 = 16;
const NFTA_IMMEDIATE_DREG: u16 = 1;
const NFTA_IMMEDIATE_DATA: u16 = 2;
const NFTA_REDIR_REG_PROTO_MIN: u16 = 1;
const NFT_REG_1: u32 = 1;

const TABLE: &str = "mxc";
const CHAIN: &str = "relay";

struct Msg {
    buf: Vec<u8>,
    nests: Vec<usize>,
}

impl Msg {
    fn new(ty: u16, flags: u16, seq: u32) -> Self {
        let mut buf = vec![0u8; 16];
        buf[4..6].copy_from_slice(&ty.to_ne_bytes());
        buf[6..8].copy_from_slice(&flags.to_ne_bytes());
        buf[8..12].copy_from_slice(&seq.to_ne_bytes());
        Msg {
            buf,
            nests: Vec::new(),
        }
    }

    // nfgenmsg: family, version 0, big-endian resource id.
    fn nft(msg: u16, flags: u16, seq: u32, family: u8, res_id: u16) -> Self {
        let ty = if msg >= NFNL_MSG_BATCH_BEGIN {
            msg
        } else {
            (NFNL_SUBSYS_NFTABLES << 8) | msg
        };
        let mut m = Msg::new(ty, flags, seq);
        let res = res_id.to_be_bytes();
        m.raw(&[family, 0, res[0], res[1]]);
        m
    }

    fn pad(&mut self) {
        while !self.buf.len().is_multiple_of(4) {
            self.buf.push(0);
        }
    }

    fn raw(&mut self, data: &[u8]) {
        self.buf.extend_from_slice(data);
        self.pad();
    }

    fn attr(&mut self, ty: u16, data: &[u8]) {
        self.buf
            .extend_from_slice(&((4 + data.len()) as u16).to_ne_bytes());
        self.buf.extend_from_slice(&ty.to_ne_bytes());
        self.raw(data);
    }

    fn str(&mut self, ty: u16, s: &str) {
        let mut v = s.as_bytes().to_vec();
        v.push(0);
        self.attr(ty, &v);
    }

    fn be32(&mut self, ty: u16, v: u32) {
        self.attr(ty, &v.to_be_bytes());
    }

    fn begin(&mut self, ty: u16) {
        self.nests.push(self.buf.len());
        self.buf.extend_from_slice(&[0, 0]);
        self.buf
            .extend_from_slice(&(ty | NLA_F_NESTED).to_ne_bytes());
    }

    fn end(&mut self) {
        let start = self.nests.pop().expect("unbalanced nest");
        let len = (self.buf.len() - start) as u16;
        self.buf[start..start + 2].copy_from_slice(&len.to_ne_bytes());
    }

    fn expr(&mut self, name: &str, body: impl FnOnce(&mut Msg)) {
        self.begin(NFTA_LIST_ELEM);
        self.str(NFTA_EXPR_NAME, name);
        self.begin(NFTA_EXPR_DATA);
        body(self);
        self.end();
        self.end();
    }

    fn data_value(&mut self, ty: u16, value: &[u8]) {
        self.begin(ty);
        self.attr(NFTA_DATA_VALUE, value);
        self.end();
    }

    fn finish(mut self) -> Vec<u8> {
        let len = self.buf.len() as u32;
        self.buf[0..4].copy_from_slice(&len.to_ne_bytes());
        self.buf
    }
}

struct Socket(i32);

impl Drop for Socket {
    fn drop(&mut self) {
        unsafe { libc::close(self.0) };
    }
}

impl Socket {
    fn open(protocol: i32) -> io::Result<Self> {
        let fd = unsafe {
            libc::socket(
                libc::AF_NETLINK,
                libc::SOCK_RAW | libc::SOCK_CLOEXEC,
                protocol,
            )
        };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        let sock = Socket(fd);
        let timeout = libc::timeval {
            tv_sec: 5,
            tv_usec: 0,
        };
        let mut addr: libc::sockaddr_nl = unsafe { zeroed() };
        addr.nl_family = libc::AF_NETLINK as u16;
        unsafe {
            libc::setsockopt(
                fd,
                libc::SOL_SOCKET,
                libc::SO_RCVTIMEO,
                &timeout as *const _ as *const _,
                size_of::<libc::timeval>() as u32,
            );
            if libc::bind(
                fd,
                &addr as *const _ as *const libc::sockaddr,
                size_of::<libc::sockaddr_nl>() as u32,
            ) < 0
            {
                return Err(io::Error::last_os_error());
            }
        }
        Ok(sock)
    }

    fn send(&self, data: &[u8]) -> io::Result<()> {
        let mut addr: libc::sockaddr_nl = unsafe { zeroed() };
        addr.nl_family = libc::AF_NETLINK as u16;
        let n = unsafe {
            libc::sendto(
                self.0,
                data.as_ptr() as *const _,
                data.len(),
                0,
                &addr as *const _ as *const libc::sockaddr,
                size_of::<libc::sockaddr_nl>() as u32,
            )
        };
        if n < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }

    /// Sends `messages` and waits for an acknowledgement of each one that
    /// requests it. Any netlink error fails the whole setup.
    fn request(&self, messages: &[u8]) -> io::Result<()> {
        self.send(messages)?;
        let expected = acks_requested(messages);
        let mut buf = vec![0u8; 65536];
        let mut got = 0;
        while got < expected {
            let n = unsafe { libc::recv(self.0, buf.as_mut_ptr() as *mut _, buf.len(), 0) };
            if n < 0 {
                return Err(io::Error::last_os_error());
            }
            got += read_acks(&buf[..n as usize])?;
        }
        Ok(())
    }
}

/// Splits concatenated netlink messages into (type, flags, whole message).
fn messages(buf: &[u8]) -> impl Iterator<Item = (u16, u16, &[u8])> {
    let mut off = 0;
    std::iter::from_fn(move || {
        let header = buf.get(off..off + 16)?;
        let len = u32::from_ne_bytes(header[0..4].try_into().unwrap()) as usize;
        let message = buf.get(off..off + len).filter(|_| len >= 16)?;
        off += (len + 3) & !3;
        Some((
            u16::from_ne_bytes(header[4..6].try_into().unwrap()),
            u16::from_ne_bytes(header[6..8].try_into().unwrap()),
            message,
        ))
    })
}

fn acks_requested(batch: &[u8]) -> usize {
    messages(batch)
        .filter(|(_, flags, _)| flags & NLM_F_ACK != 0)
        .count()
}

/// Counts the acknowledgements in a netlink reply, or returns the first error.
fn read_acks(buf: &[u8]) -> io::Result<usize> {
    let mut acks = 0;
    for (ty, _, message) in messages(buf) {
        if ty != NLMSG_ERROR {
            continue;
        }
        let errno = message
            .get(16..20)
            .map(|b| i32::from_ne_bytes(b.try_into().unwrap()))
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "short netlink error"))?;
        if errno != 0 {
            return Err(io::Error::from_raw_os_error(-errno));
        }
        acks += 1;
    }
    Ok(acks)
}

pub fn interface_with_address(ip: Ipv4Addr) -> io::Result<u32> {
    let mut list = std::mem::MaybeUninit::<*mut libc::ifaddrs>::uninit();
    if unsafe { libc::getifaddrs(list.as_mut_ptr()) } < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: getifaddrs succeeded, so it set the list head.
    let list = unsafe { list.assume_init() };
    let mut found = None;
    let mut cur = list;
    while !cur.is_null() {
        let ifa = unsafe { &*cur };
        if !ifa.ifa_addr.is_null() && unsafe { (*ifa.ifa_addr).sa_family } as i32 == libc::AF_INET {
            let sin = unsafe { &*(ifa.ifa_addr as *const libc::sockaddr_in) };
            if Ipv4Addr::from(u32::from_be(sin.sin_addr.s_addr)) == ip {
                found = Some(unsafe { libc::if_nametoindex(ifa.ifa_name) });
                break;
            }
        }
        cur = ifa.ifa_next;
    }
    unsafe { libc::freeifaddrs(list) };
    match found {
        Some(index) if index != 0 => Ok(index),
        _ => Err(io::Error::new(
            io::ErrorKind::NotFound,
            format!("no interface has address {ip}"),
        )),
    }
}

pub fn add_address(ifindex: u32, ip: Ipv4Addr, prefix: u8) -> io::Result<()> {
    let sock = Socket::open(libc::NETLINK_ROUTE)?;
    let mut m = Msg::new(
        RTM_NEWADDR,
        NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_EXCL,
        1,
    );
    // ifaddrmsg: family, prefix length, flags, scope, interface index.
    m.raw(&[libc::AF_INET as u8, prefix, 0, 0]);
    m.raw(&ifindex.to_ne_bytes());
    m.attr(IFA_LOCAL, &ip.octets());
    m.attr(IFA_ADDRESS, &ip.octets());
    sock.request(&m.finish())
}

/// `table ip mxc { chain relay { type nat hook prerouting priority dstnat;
///   ip daddr <relay> meta l4proto tcp redirect to :<port> } }`
pub fn redirect_to_relay(relay: Ipv4Addr, port: u16) -> io::Result<()> {
    Socket::open(NETLINK_NETFILTER)?.request(&redirect_batch(relay, port))
}

fn redirect_batch(relay: Ipv4Addr, port: u16) -> Vec<u8> {
    let create = NLM_F_REQUEST | NLM_F_CREATE | NLM_F_ACK;
    let mut batch = Msg::nft(
        NFNL_MSG_BATCH_BEGIN,
        NLM_F_REQUEST,
        1,
        0,
        NFNL_SUBSYS_NFTABLES,
    )
    .finish();

    let mut table = Msg::nft(NFT_MSG_NEWTABLE, create, 2, NFPROTO_IPV4, 0);
    table.str(NFTA_TABLE_NAME, TABLE);
    batch.extend(table.finish());

    let mut chain = Msg::nft(NFT_MSG_NEWCHAIN, create, 3, NFPROTO_IPV4, 0);
    chain.str(NFTA_CHAIN_TABLE, TABLE);
    chain.str(NFTA_CHAIN_NAME, CHAIN);
    chain.begin(NFTA_CHAIN_HOOK);
    chain.be32(NFTA_HOOK_HOOKNUM, NF_INET_PRE_ROUTING);
    chain.be32(NFTA_HOOK_PRIORITY, NF_IP_PRI_NAT_DST as u32);
    chain.end();
    chain.str(NFTA_CHAIN_TYPE, "nat");
    batch.extend(chain.finish());

    let mut rule = Msg::nft(NFT_MSG_NEWRULE, create | NLM_F_APPEND, 4, NFPROTO_IPV4, 0);
    rule.str(NFTA_RULE_TABLE, TABLE);
    rule.str(NFTA_RULE_CHAIN, CHAIN);
    rule.begin(NFTA_RULE_EXPRESSIONS);
    rule.expr("payload", |m| {
        m.be32(NFTA_PAYLOAD_DREG, NFT_REG_1);
        m.be32(NFTA_PAYLOAD_BASE, NFT_PAYLOAD_NETWORK_HEADER);
        m.be32(NFTA_PAYLOAD_OFFSET, 16);
        m.be32(NFTA_PAYLOAD_LEN, 4);
    });
    rule.expr("cmp", |m| {
        m.be32(NFTA_CMP_SREG, NFT_REG_1);
        m.be32(NFTA_CMP_OP, NFT_CMP_EQ);
        m.data_value(NFTA_CMP_DATA, &relay.octets());
    });
    rule.expr("meta", |m| {
        m.be32(NFTA_META_DREG, NFT_REG_1);
        m.be32(NFTA_META_KEY, NFT_META_L4PROTO);
    });
    rule.expr("cmp", |m| {
        m.be32(NFTA_CMP_SREG, NFT_REG_1);
        m.be32(NFTA_CMP_OP, NFT_CMP_EQ);
        m.data_value(NFTA_CMP_DATA, &[libc::IPPROTO_TCP as u8]);
    });
    rule.expr("immediate", |m| {
        m.be32(NFTA_IMMEDIATE_DREG, NFT_REG_1);
        m.data_value(NFTA_IMMEDIATE_DATA, &port.to_be_bytes());
    });
    rule.expr("redir", |m| m.be32(NFTA_REDIR_REG_PROTO_MIN, NFT_REG_1));
    rule.end();
    batch.extend(rule.finish());

    batch.extend(
        Msg::nft(
            NFNL_MSG_BATCH_END,
            NLM_F_REQUEST,
            5,
            0,
            NFNL_SUBSYS_NFTABLES,
        )
        .finish(),
    );
    batch
}

/// Destination before the nftables redirect (`SO_ORIGINAL_DST`).
pub fn original_destination(fd: i32) -> io::Result<(Ipv4Addr, u16)> {
    const SO_ORIGINAL_DST: i32 = 80;
    let mut addr: libc::sockaddr_in = unsafe { zeroed() };
    let mut len = size_of::<libc::sockaddr_in>() as libc::socklen_t;
    if unsafe {
        libc::getsockopt(
            fd,
            libc::SOL_IP,
            SO_ORIGINAL_DST,
            &mut addr as *mut _ as *mut _,
            &mut len,
        )
    } < 0
    {
        return Err(io::Error::last_os_error());
    }
    Ok((
        Ipv4Addr::from(u32::from_be(addr.sin_addr.s_addr)),
        u16::from_be(addr.sin_port),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn contains(haystack: &[u8], needle: &[u8]) -> bool {
        haystack.windows(needle.len()).any(|w| w == needle)
    }

    fn error_message(errno: i32) -> Vec<u8> {
        let mut m = Msg::new(NLMSG_ERROR, 0, 1);
        m.raw(&errno.to_ne_bytes());
        m.raw(&[0u8; 16]);
        m.finish()
    }

    #[test]
    fn redirect_batch_is_one_transaction_with_three_acked_messages() {
        let relay = Ipv4Addr::new(10, 231, 1, 3);
        let batch = redirect_batch(relay, 41234);
        let parsed: Vec<_> = messages(&batch).collect();
        let types: Vec<u16> = parsed.iter().map(|(ty, _, _)| *ty).collect();
        let nft = NFNL_SUBSYS_NFTABLES << 8;
        assert_eq!(
            types,
            [
                NFNL_MSG_BATCH_BEGIN,
                nft | NFT_MSG_NEWTABLE,
                nft | NFT_MSG_NEWCHAIN,
                nft | NFT_MSG_NEWRULE,
                NFNL_MSG_BATCH_END,
            ]
        );
        let seqs: Vec<u32> = parsed
            .iter()
            .map(|(_, _, m)| u32::from_ne_bytes(m[8..12].try_into().unwrap()))
            .collect();
        assert_eq!(seqs, [1, 2, 3, 4, 5]);
        let consumed: usize = parsed.iter().map(|(_, _, m)| (m.len() + 3) & !3).sum();
        assert_eq!(consumed, batch.len());
        assert_eq!(acks_requested(&batch), 3);

        let rule = parsed[3].2;
        assert!(contains(rule, &relay.octets()));
        assert!(contains(rule, &41234u16.to_be_bytes()));
    }

    #[test]
    fn read_acks_counts_acks_and_reports_errors() {
        let mut reply = error_message(0);
        reply.extend(Msg::new(3, 0, 2).finish());
        reply.extend(error_message(0));
        assert_eq!(read_acks(&reply).unwrap(), 2);

        let mut reply = error_message(0);
        reply.extend(error_message(-libc::EEXIST));
        let error = read_acks(&reply).unwrap_err();
        assert_eq!(error.raw_os_error(), Some(libc::EEXIST));

        let short = Msg::new(NLMSG_ERROR, 0, 1).finish();
        assert_eq!(
            read_acks(&short).unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );
        assert_eq!(read_acks(&[0u8; 10]).unwrap(), 0);
    }
}
