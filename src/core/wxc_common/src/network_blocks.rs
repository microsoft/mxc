// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! CIDR block arithmetic for lowering an egress policy onto a packet filter.
//!
//! A filter rule matches one destination block and cannot carry an exclusion,
//! so a peer's `except` entries are subtracted from its CIDR instead.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use crate::models::{NetworkCidr, NetworkPeer};

/// The address family a block is programmed in.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IpFamily {
    V4,
    V6,
}

impl IpFamily {
    /// Bits in an address of this family.
    pub fn width(self) -> u8 {
        match self {
            IpFamily::V4 => 32,
            IpFamily::V6 => 128,
        }
    }
}

/// A CIDR as a number, with `base` masked to the block's first address so
/// comparisons are integer ordering.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AddressBlock {
    base: u128,
    prefix: u8,
}

impl AddressBlock {
    pub fn prefix(self) -> u8 {
        self.prefix
    }

    /// The block's first address, rendered in `family`.
    pub fn address(self, family: IpFamily) -> IpAddr {
        match family {
            IpFamily::V4 => IpAddr::V4(Ipv4Addr::from(self.base as u32)),
            IpFamily::V6 => IpAddr::V6(Ipv6Addr::from(self.base)),
        }
    }

    fn last(self, width: u8) -> u128 {
        self.base | host_mask(width - self.prefix)
    }

    fn contains(self, inner: Self, width: u8) -> bool {
        self.base <= inner.base && inner.last(width) <= self.last(width)
    }

    fn intersects(self, other: Self, width: u8) -> bool {
        self.base <= other.last(width) && other.base <= self.last(width)
    }
}

/// `::ffff:0:0/96`, the range a destination is rewritten out of and programmed
/// as IPv4 in.
const IPV4_MAPPED_BLOCK: AddressBlock = AddressBlock {
    base: 0xffff_0000_0000,
    prefix: 96,
};

/// Ceiling on the blocks one peer may expand into.
///
/// Subtracting an exclusion splits the surrounding block once per prefix level,
/// so a `/32` taken out of a `/8` is 24 blocks and several exclusions add up.
pub const MAX_BLOCKS_PER_PEER: usize = 256;

/// Ceiling on the entries one egress policy may lower into.
///
/// An entry is a cross product of blocks and ports, and the wire contract
/// bounds neither the peer list, the port list, nor the rule list.
pub const MAX_EGRESS_ENTRIES: usize = 65_536;

/// Mask covering the low `bits` bits, saturating at the full width.
fn host_mask(bits: u8) -> u128 {
    if bits >= 128 {
        u128::MAX
    } else {
        (1u128 << bits) - 1
    }
}

/// A CIDR as it was written, rather than as the block it resolves to.
pub fn cidr_text(cidr: &NetworkCidr) -> String {
    format!("{}/{}", cidr.address, cidr.prefix_length)
}

/// A CIDR as the family it is programmed in and the block it covers there.
pub fn resolve(cidr: &NetworkCidr) -> Option<(IpFamily, AddressBlock)> {
    let (family, raw, prefix) = match cidr.address {
        IpAddr::V4(ip) => (IpFamily::V4, u128::from(u32::from(ip)), cidr.prefix_length),
        IpAddr::V6(ip) => match ip.to_ipv4_mapped() {
            // Below /96 the block reaches outside the mapped range, so it
            // stays IPv6 and keeps covering what it actually names.
            Some(v4) if cidr.prefix_length >= 96 => (
                IpFamily::V4,
                u128::from(u32::from(v4)),
                cidr.prefix_length - 96,
            ),
            _ => (IpFamily::V6, u128::from(ip), cidr.prefix_length),
        },
    };

    let width = family.width();
    if prefix > width {
        return None;
    }
    Some((
        family,
        AddressBlock {
            base: raw & !host_mask(width - prefix),
            prefix,
        },
    ))
}

/// The blocks a peer covers once its exclusions are removed.
///
/// `Ok(None)` reports a peer that names no address, leaving the caller to
/// render it as an unresolvable destination rather than as a policy failure.
///
/// # Errors
///
/// Refuses an exclusion whose prefix is wider than its own address family, an
/// exclusion programmed for the family the peer is not in, a subtraction that
/// would leave an IPv6 peer covering the IPv4-mapped range, and an expansion
/// past [`MAX_BLOCKS_PER_PEER`].
pub fn peer_blocks(peer: &NetworkPeer) -> Result<Option<(IpFamily, Vec<AddressBlock>)>, String> {
    // Run before the peer resolves, so a malformed exclusion is refused even
    // when its peer names no address.
    for excluded in &peer.except {
        let excluded_width = match excluded.address {
            IpAddr::V4(_) => IpFamily::V4,
            IpAddr::V6(_) => IpFamily::V6,
        }
        .width();
        if excluded.prefix_length > excluded_width {
            return Err(format!(
                "network.egress peer '{}' carries the 'except' entry '{}/{}', whose prefix is \
                 wider than its address family (max /{excluded_width}).",
                cidr_text(&peer.cidr),
                excluded.address,
                excluded.prefix_length
            ));
        }
    }

    let Some((family, block)) = resolve(&peer.cidr) else {
        return Ok(None);
    };
    let width = family.width();

    let mut exclusions = Vec::new();
    for excluded in &peer.except {
        // An out-of-range prefix is refused above, so every entry resolves.
        let Some((excluded_family, excluded_block)) = resolve(excluded) else {
            continue;
        };
        if excluded_family != family {
            return Err(format!(
                "network.egress peer '{}' carries the 'except' entry '{}/{}', which is programmed \
                 for the other address family and so names no address the peer covers. State an \
                 exclusion inside the peer's own range.",
                cidr_text(&peer.cidr),
                excluded.address,
                excluded.prefix_length
            ));
        }
        exclusions.push(excluded_block);
    }

    let mut blocks = Vec::new();
    let mut remaining = MAX_BLOCKS_PER_PEER;
    subtract(block, &exclusions, width, &mut blocks, &mut remaining)?;

    // A generated block inside `::ffff:0:0/96` is programmed as IPv4, so
    // subtraction must not hand back a piece that opens addresses an IPv6 peer
    // never named.
    if family == IpFamily::V6 && !IPV4_MAPPED_BLOCK.contains(block, width) {
        if let Some(crossing) = blocks
            .iter()
            .find(|candidate| IPV4_MAPPED_BLOCK.contains(**candidate, width))
        {
            return Err(format!(
                "network.egress peer '{}' cannot carry an 'except' that splits the IPv4-mapped \
                 range: removing it leaves '{}/{}', which is programmed as IPv4 and would open \
                 addresses this IPv6 peer never named. State the IPv4 range as its own peer \
                 instead.",
                cidr_text(&peer.cidr),
                crossing.address(family),
                crossing.prefix()
            ));
        }
    }

    Ok(Some((family, blocks)))
}

/// `block` minus `exclusions`, as the smallest set of whole CIDR blocks.
fn subtract(
    block: AddressBlock,
    exclusions: &[AddressBlock],
    width: u8,
    out: &mut Vec<AddressBlock>,
    remaining: &mut usize,
) -> Result<(), String> {
    if exclusions
        .iter()
        .any(|excluded| excluded.contains(block, width))
    {
        return Ok(());
    }

    if !exclusions
        .iter()
        .any(|excluded| excluded.intersects(block, width))
    {
        if *remaining == 0 {
            return Err(format!(
                "a network.egress peer expands into more than {MAX_BLOCKS_PER_PEER} address \
                 blocks once its 'except' entries are removed. Narrow the peer's CIDR or use \
                 fewer exclusions."
            ));
        }
        *remaining -= 1;
        out.push(block);
        return Ok(());
    }

    // Part of the block survives, so split it and test each half. A single
    // address never reaches here: it is contained or disjoint.
    if block.prefix >= width {
        return Ok(());
    }

    let child_prefix = block.prefix + 1;
    let step = host_mask(width - child_prefix) + 1;
    for base in [block.base, block.base + step] {
        subtract(
            AddressBlock {
                base,
                prefix: child_prefix,
            },
            exclusions,
            width,
            out,
            remaining,
        )?;
    }
    Ok(())
}

#[cfg(test)]
#[path = "network_blocks_spec.rs"]
mod spec;
