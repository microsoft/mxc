// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use super::*;

fn cidr(value: &str) -> NetworkCidr {
    value
        .parse()
        .unwrap_or_else(|error| panic!("invalid test CIDR {value:?}: {error}"))
}

fn peer(value: &str, except: &[&str]) -> NetworkPeer {
    NetworkPeer {
        cidr: cidr(value),
        except: except.iter().map(|value| cidr(value)).collect(),
    }
}

fn covered(value: &str, except: &[&str]) -> Vec<String> {
    let (family, blocks) = peer_blocks(&peer(value, except))
        .unwrap_or_else(|error| panic!("peer {value:?} except {except:?} was refused: {error}"))
        .unwrap_or_else(|| panic!("peer {value:?} except {except:?} resolved to no address"));

    blocks
        .into_iter()
        .map(|block| format!("{}/{}", block.address(family), block.prefix()))
        .collect()
}

fn refusal(value: &str, except: &[&str]) -> String {
    match peer_blocks(&peer(value, except)) {
        Err(message) => message,
        Ok(other) => panic!("peer {value:?} except {except:?} was accepted as {other:?}"),
    }
}

/// Walks every address in `range`, so a caller must keep it small.
fn covers_exactly(value: &str, except: &[&str], range: std::ops::RangeInclusive<u32>) -> bool {
    let blocks = covered(value, except)
        .into_iter()
        .map(|block| cidr(&block))
        .collect::<Vec<_>>();
    let peer_cidr = cidr(value);
    let exclusions = except.iter().map(|value| cidr(value)).collect::<Vec<_>>();

    range.into_iter().all(|address| {
        let host = NetworkCidr {
            address: IpAddr::V4(Ipv4Addr::from(address)),
            prefix_length: 32,
        };
        let expected = peer_cidr.contains_cidr(&host)
            && !exclusions
                .iter()
                .any(|excluded| excluded.contains_cidr(&host));
        let actual = blocks.iter().any(|block| block.contains_cidr(&host));
        expected == actual
    })
}

#[test]
fn a_peer_without_exclusions_keeps_its_own_block() {
    assert_eq!(covered("198.51.100.0/24", &[]), ["198.51.100.0/24"]);
    assert_eq!(covered("2001:db8::/32", &[]), ["2001:db8::/32"]);
}

#[test]
fn an_exclusion_is_replaced_by_the_blocks_that_surround_it() {
    assert_eq!(
        covered("198.51.100.0/24", &["198.51.100.128/25"]),
        ["198.51.100.0/25"]
    );
}

#[test]
fn the_surviving_blocks_cover_the_peer_without_its_exclusion() {
    assert!(
        covers_exactly(
            "198.51.100.0/24",
            &["198.51.100.37/32"],
            u32::from(Ipv4Addr::new(198, 51, 99, 0))..=u32::from(Ipv4Addr::new(198, 51, 101, 255)),
        ),
        "the emitted blocks must admit every address the peer names except the excluded one"
    );
}

#[test]
fn several_exclusions_are_all_removed() {
    assert!(
        covers_exactly(
            "10.0.0.0/24",
            &["10.0.0.0/28", "10.0.0.64/26", "10.0.0.255/32"],
            u32::from(Ipv4Addr::new(9, 255, 255, 255))..=u32::from(Ipv4Addr::new(10, 0, 1, 0)),
        ),
        "every exclusion must be removed from the emitted blocks"
    );
}

#[test]
fn an_exclusion_covering_the_whole_peer_leaves_nothing() {
    assert!(covered("198.51.100.0/24", &["198.51.100.0/24"]).is_empty());
    assert!(covered("198.51.100.0/24", &["198.51.0.0/16"]).is_empty());
}

#[test]
fn an_exclusion_outside_the_peer_leaves_the_peer_whole() {
    assert_eq!(
        covered("198.51.100.0/24", &["203.0.113.0/24"]),
        ["198.51.100.0/24"]
    );
}

#[test]
fn an_ipv6_exclusion_is_subtracted_within_its_own_family() {
    assert_eq!(
        covered("2001:db8::/32", &["2001:db8:8000::/33"]),
        ["2001:db8::/33"]
    );
}

#[test]
fn a_mapped_cidr_at_or_below_the_mapped_range_resolves_as_ipv4() {
    let (family, block) = resolve(&cidr("::ffff:198.51.100.0/120")).expect("a /120 must resolve");

    assert_eq!(family, IpFamily::V4);
    assert_eq!(
        format!("{}/{}", block.address(family), block.prefix()),
        "198.51.100.0/24"
    );
}

#[test]
fn a_mapped_cidr_reaching_outside_the_mapped_range_stays_ipv6() {
    let below_the_mapped_range = NetworkCidr {
        address: IpAddr::V6(Ipv6Addr::from(0xffff_0000_0000u128)),
        prefix_length: 95,
    };

    let (family, block) = resolve(&below_the_mapped_range).expect("a /95 must resolve");

    assert_eq!(family, IpFamily::V6);
    assert_eq!(
        format!("{}/{}", block.address(family), block.prefix()),
        "::fffe:0:0/95"
    );
}

#[test]
fn a_cidr_is_masked_down_to_its_own_block() {
    let with_host_bits = NetworkCidr {
        address: IpAddr::V4(Ipv4Addr::new(198, 51, 100, 37)),
        prefix_length: 24,
    };

    let (family, block) = resolve(&with_host_bits).expect("a /24 must resolve");

    assert_eq!(
        format!("{}/{}", block.address(family), block.prefix()),
        "198.51.100.0/24"
    );
}

#[test]
fn an_ipv4_peer_subtracts_an_exclusion_written_in_mapped_notation() {
    assert_eq!(
        covered("198.51.100.0/24", &["::ffff:198.51.100.128/121"]),
        ["198.51.100.0/25"]
    );
}

#[test]
fn a_mapped_peer_subtracts_an_exclusion_written_in_plain_ipv4() {
    assert_eq!(
        covered("::ffff:198.51.100.0/120", &["198.51.100.128/25"]),
        ["198.51.100.0/25"]
    );
}

#[test]
fn a_peer_naming_no_address_is_reported_rather_than_refused() {
    let unresolvable = NetworkPeer {
        cidr: NetworkCidr {
            address: IpAddr::V4(Ipv4Addr::new(198, 51, 100, 0)),
            prefix_length: 33,
        },
        except: Vec::new(),
    };

    assert_eq!(peer_blocks(&unresolvable), Ok(None));
}

#[test]
fn an_exclusion_in_the_other_family_is_refused_rather_than_dropped() {
    let message = refusal("198.51.100.0/24", &["2001:db8::/32"]);

    assert_eq!(
        message,
        "network.egress peer '198.51.100.0/24' carries the 'except' entry '2001:db8::/32', which \
         is programmed for the other address family and so names no address the peer covers. \
         State an exclusion inside the peer's own range."
    );
}

#[test]
fn an_ipv4_exclusion_on_an_ipv6_peer_is_refused_in_the_same_way() {
    let message = refusal("2001:db8::/32", &["198.51.100.0/24"]);

    assert!(
        message.contains("programmed for the other address family"),
        "a cross-family exclusion must be refused, got {message:?}"
    );
}

#[test]
fn an_exclusion_with_a_prefix_past_its_family_is_refused() {
    let wide = NetworkPeer {
        cidr: cidr("198.51.100.0/24"),
        except: vec![NetworkCidr {
            address: IpAddr::V4(Ipv4Addr::new(198, 51, 100, 128)),
            prefix_length: 33,
        }],
    };

    let message = peer_blocks(&wide).expect_err("a /33 exclusion must be refused");

    assert_eq!(
        message,
        "network.egress peer '198.51.100.0/24' carries the 'except' entry '198.51.100.128/33', \
         whose prefix is wider than its address family (max /32)."
    );
}

#[test]
fn an_other_family_exclusion_is_validated_before_it_is_filtered_out() {
    let unresolvable_peer = NetworkPeer {
        cidr: NetworkCidr {
            address: IpAddr::V4(Ipv4Addr::new(198, 51, 100, 0)),
            prefix_length: 33,
        },
        except: vec![NetworkCidr {
            address: IpAddr::V4(Ipv4Addr::new(198, 51, 100, 128)),
            prefix_length: 33,
        }],
    };

    let message =
        peer_blocks(&unresolvable_peer).expect_err("a malformed exclusion must be refused");

    assert!(
        message.contains("wider than its address family"),
        "a malformed exclusion must be refused even when its peer names no address, got {message:?}"
    );
}

#[test]
fn an_ipv6_peer_whose_exclusion_is_programmed_as_ipv4_is_refused() {
    let message = refusal("::/0", &["::ffff:10.0.0.0/104"]);

    assert!(
        message.contains("programmed for the other address family"),
        "a mapped exclusion narrows nothing under an IPv6 peer and must be refused, got {message:?}"
    );
}

#[test]
fn an_ipv6_peer_whose_exclusion_neighbours_the_mapped_range_is_refused() {
    let message = refusal("::/0", &["::fffe:0:0/96"]);

    assert_eq!(
        message,
        "network.egress peer '::/0' cannot carry an 'except' that splits the IPv4-mapped range: \
         removing it leaves '::ffff:0.0.0.0/96', which is programmed as IPv4 and would open \
         addresses this IPv6 peer never named. State the IPv4 range as its own peer instead."
    );
}

#[test]
fn an_ipv6_catch_all_without_an_exclusion_is_untouched_by_the_guard() {
    assert_eq!(covered("::/0", &[]), ["::/0"]);
}

#[test]
fn an_ipv6_peer_far_from_the_mapped_range_still_subtracts() {
    let (family, blocks) = peer_blocks(&peer("2001:db8::/32", &["2001:db8:1::/48"]))
        .expect("an ordinary IPv6 subtraction must not be refused")
        .expect("the peer must resolve");

    assert_eq!(family, IpFamily::V6);
    assert_eq!(blocks.len(), 16);
}

#[test]
fn a_peer_that_expands_past_the_block_ceiling_is_refused() {
    let scattered = (0..16)
        .map(|index| format!("10.{index}.{index}.{index}/32"))
        .collect::<Vec<_>>();
    let scattered = scattered.iter().map(String::as_str).collect::<Vec<_>>();

    let message = refusal("10.0.0.0/8", &scattered);

    assert_eq!(
        message,
        "a network.egress peer expands into more than 256 address blocks once its 'except' \
         entries are removed. Narrow the peer's CIDR or use fewer exclusions."
    );
}

#[test]
fn a_peer_under_the_block_ceiling_keeps_every_surviving_block() {
    let (family, blocks) = peer_blocks(&peer("::/0", &["::/128", "8000::/128"]))
        .expect("an expansion under the ceiling must be accepted")
        .expect("the peer must resolve");

    assert_eq!(family, IpFamily::V6);
    assert_eq!(blocks.len(), 254);
}

#[test]
fn the_ceilings_hold_the_values_the_wire_contract_is_bounded_by() {
    assert_eq!(MAX_BLOCKS_PER_PEER, 256);
    assert_eq!(MAX_EGRESS_ENTRIES, 65_536);
}

#[test]
fn each_family_reports_its_own_address_width() {
    assert_eq!(IpFamily::V4.width(), 32);
    assert_eq!(IpFamily::V6.width(), 128);
}

#[test]
fn a_cidr_renders_as_it_was_written() {
    assert_eq!(cidr_text(&cidr("198.51.100.0/24")), "198.51.100.0/24");
    assert_eq!(cidr_text(&cidr("2001:db8::/32")), "2001:db8::/32");
}
