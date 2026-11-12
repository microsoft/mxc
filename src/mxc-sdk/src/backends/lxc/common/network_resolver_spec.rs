// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use super::resolver_from_dhcp;

#[test]
fn dns_servers_and_domain_fallback_form_the_resolver_configuration() {
    let mut packet = vec![0; 240];
    packet[..3].copy_from_slice(&[2, 1, 6]);
    packet[236..240].copy_from_slice(&[99, 130, 83, 99]);
    packet.extend_from_slice(&[53, 1, 5, 6, 8, 192, 0, 2, 53, 198, 51, 100, 53, 15, 12]);
    packet.extend_from_slice(b"corp.example");
    packet.push(255);

    assert_eq!(
        resolver_from_dhcp(&packet),
        Ok(concat!(
            "nameserver 192.0.2.53\n",
            "nameserver 198.51.100.53\n",
            "search corp.example\n",
        )
        .to_owned()),
        "DHCPACK must preserve its DNS servers and domain fallback; packet={packet:?}"
    );
}

#[test]
fn domain_search_fragments_override_the_domain_fallback() {
    let mut packet = vec![0; 240];
    packet[..3].copy_from_slice(&[2, 1, 6]);
    packet[236..240].copy_from_slice(&[99, 130, 83, 99]);
    packet.extend_from_slice(&[53, 1, 5, 6, 4, 192, 0, 2, 53, 15, 16]);
    packet.extend_from_slice(b"fallback.example");

    // RFC 3397 makes C004 point to example.com in the concatenated search payload.
    let search = b"\x03eng\x07example\x03com\x00\x02qa\xc0\x04";
    for fragment in [&search[..9], &search[9..21], &search[21..]] {
        packet.extend_from_slice(&[119, fragment.len() as u8]);
        packet.extend_from_slice(fragment);
    }
    packet.push(255);

    assert_eq!(
        resolver_from_dhcp(&packet),
        Ok(concat!(
            "nameserver 192.0.2.53\n",
            "search eng.example.com qa.example.com\n",
        )
        .to_owned()),
        "fragmented compressed search domains must replace the domain fallback; packet={packet:?}"
    );
}

#[test]
fn overloaded_dns_fragments_follow_main_file_sname_order() {
    let mut packet = vec![0; 240];
    packet[..3].copy_from_slice(&[2, 1, 6]);
    packet[236..240].copy_from_slice(&[99, 130, 83, 99]);

    // RFC 3396 joins main, file, and sname fragments even when they split an IPv4 address.
    packet.extend_from_slice(&[53, 1, 5, 52, 1, 3, 6, 2, 192, 0, 255]);
    packet[108..115].copy_from_slice(&[6, 4, 2, 53, 198, 51, 255]);
    packet[44..53].copy_from_slice(&[6, 6, 100, 53, 203, 0, 113, 53, 255]);

    assert_eq!(
        resolver_from_dhcp(&packet),
        Ok(concat!(
            "nameserver 192.0.2.53\n",
            "nameserver 198.51.100.53\n",
            "nameserver 203.0.113.53\n",
        )
        .to_owned()),
        "overloaded DNS fragments must retain their aggregate order; packet={packet:?}"
    );
}

#[test]
fn malformed_search_compression_returns_an_error() {
    for search in [[0xc0, 0x00], [0xc0, 0xff]] {
        let mut packet = vec![0; 240];
        packet[..3].copy_from_slice(&[2, 1, 6]);
        packet[236..240].copy_from_slice(&[99, 130, 83, 99]);
        packet.extend_from_slice(&[53, 1, 5, 6, 4, 192, 0, 2, 53, 119, 2]);
        packet.extend_from_slice(&search);
        packet.push(255);

        assert!(
            resolver_from_dhcp(&packet).is_err(),
            "cyclic or out-of-bounds search compression must be rejected; packet={packet:?}"
        );
    }
}
