// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

use std::io::ErrorKind;
use std::net::{Ipv4Addr, SocketAddr, UdpSocket};
use std::time::{Duration, Instant};

pub(crate) fn query_resolver(
    mac: &str,
    address: Ipv4Addr,
    gateway: Ipv4Addr,
    prefix: u8,
) -> Result<String, String> {
    let mut request = vec![0; 240];

    // DHCPINFORM requests configuration for an assigned address without acquiring another lease.
    // https://www.rfc-editor.org/rfc/rfc2131#section-4.4.3
    request[..3].copy_from_slice(&[1, 1, 6]);
    getrandom::getrandom(&mut request[4..8])
        .map_err(|error| format!("Failed to generate DHCP transaction ID: {error}"))?;
    request[12..16].copy_from_slice(&address.octets());
    for (octet, field) in request[28..34].iter_mut().zip(mac.split(':')) {
        *octet = u8::from_str_radix(field, 16)
            .map_err(|error| format!("Invalid DHCP hardware address: {error}"))?;
    }
    request[236..240].copy_from_slice(&[99, 130, 83, 99]);
    request.extend_from_slice(&[53, 1, 8, 55, 3, 6, 15, 119, 255]);

    let socket = UdpSocket::bind((gateway, 0))
        .map_err(|error| format!("Failed to open DHCP configuration socket: {error}"))?;
    socket
        .set_broadcast(true)
        .map_err(|error| format!("Failed to enable DHCP configuration broadcast: {error}"))?;
    let broadcast =
        Ipv4Addr::from(u32::from(gateway) | u32::MAX.checked_shr(u32::from(prefix)).unwrap_or(0));
    let mut response = [0; 4096];
    for _ in 0..3 {
        socket
            .send_to(&request, (broadcast, 67))
            .map_err(|error| format!("Failed to request DHCP resolver settings: {error}"))?;
        let deadline = Instant::now() + Duration::from_secs(2);
        loop {
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                break;
            }
            socket
                .set_read_timeout(Some(remaining))
                .map_err(|error| format!("Failed to set DHCP configuration timeout: {error}"))?;
            let (length, sender) = match socket.recv_from(&mut response) {
                Ok(received) => received,
                Err(error)
                    if matches!(error.kind(), ErrorKind::TimedOut | ErrorKind::WouldBlock) =>
                {
                    break;
                }
                Err(error) if error.kind() == ErrorKind::Interrupted => continue,
                Err(error) => {
                    return Err(format!("Failed to receive DHCP resolver settings: {error}"));
                }
            };
            let packet = &response[..length];
            if sender != SocketAddr::from((gateway, 67))
                || packet.len() < 240
                || packet[..3] != [2, 1, 6]
                || packet[4..8] != request[4..8]
                || packet[12..16] != request[12..16]
                || packet[28..34] != request[28..34]
                || packet[236..240] != request[236..240]
            {
                continue;
            }
            return resolver_from_dhcp(packet);
        }
    }
    Err(format!(
        "DHCP server {gateway} did not return resolver settings for {address}"
    ))
}

fn resolver_from_dhcp(packet: &[u8]) -> Result<String, String> {
    let main = packet
        .get(240..)
        .ok_or("Truncated DHCP configuration response")?;
    let mut regions = vec![main];
    let mut nameservers = Vec::new();
    let mut domain = Vec::new();
    let mut search = Vec::new();
    let mut message_type = None;
    let mut overload = 0;
    let mut region = 0;
    while region < regions.len() {
        let data = regions[region];
        let mut offset = 0;
        while let Some(&code) = data.get(offset) {
            offset += 1;
            match code {
                0 => continue,
                255 => break,
                _ => {}
            }
            let length = usize::from(*data.get(offset).ok_or("Truncated DHCP option length")?);
            offset += 1;
            let value = data
                .get(offset..offset + length)
                .ok_or("Truncated DHCP configuration option")?;
            offset += length;
            match code {
                6 => nameservers.extend_from_slice(value),
                15 => domain.extend_from_slice(value),
                119 => search.extend_from_slice(value),
                53 if value.len() == 1 => message_type = Some(value[0]),
                52 if region == 0 && value.len() == 1 => overload = value[0],
                _ => {}
            }
        }
        if region == 0 {
            if overload & 1 != 0 {
                regions.push(&packet[108..236]);
            }
            if overload & 2 != 0 {
                regions.push(&packet[44..108]);
            }
        }
        region += 1;
    }
    if message_type != Some(5) {
        return Err("DHCP resolver response is not an acknowledgement".into());
    }
    if nameservers.len() % 4 != 0 {
        return Err("DHCP resolver response contains an invalid IPv4 nameserver".into());
    }
    let mut resolver = String::new();
    for address in nameservers.chunks_exact(4) {
        resolver.push_str(&format!(
            "nameserver {}\n",
            Ipv4Addr::new(address[0], address[1], address[2], address[3])
        ));
    }
    let domains = if !search.is_empty() {
        decode_domain_search(&search)?
    } else if !domain.is_empty() {
        let domain = String::from_utf8(domain)
            .map_err(|error| format!("Invalid DHCP domain name: {error}"))?;
        if !domain
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b".-_".contains(&byte))
        {
            return Err("DHCP domain name contains an invalid character".into());
        }
        vec![domain]
    } else {
        Vec::new()
    };
    if !domains.is_empty() {
        resolver.push_str(&format!("search {}\n", domains.join(" ")));
    }
    Ok(resolver)
}

fn decode_domain_search(data: &[u8]) -> Result<Vec<String>, String> {
    let mut domains = Vec::new();
    let mut offset = 0;
    while offset < data.len() {
        let mut position = offset;
        let mut end = None;
        let mut labels = Vec::new();
        let mut remaining = data.len();
        loop {
            if remaining == 0 {
                return Err("DHCP domain search contains a compression cycle".into());
            }
            remaining -= 1;
            let length = usize::from(*data.get(position).ok_or("Truncated DHCP domain search")?);
            if length == 0 {
                offset = end.unwrap_or(position + 1);
                break;
            }

            // RFC 3397 compression offsets address the concatenated search option, not the packet.
            if length & 0xc0 == 0xc0 {
                let low = usize::from(
                    *data
                        .get(position + 1)
                        .ok_or("Truncated DHCP search compression pointer")?,
                );
                let target = ((length & 0x3f) << 8) | low;
                if target >= position {
                    return Err("Invalid DHCP search compression pointer".into());
                }
                end.get_or_insert(position + 2);
                position = target;
                continue;
            }
            if length > 63 {
                return Err("Invalid DHCP domain search label length".into());
            }
            position += 1;
            let label = data
                .get(position..position + length)
                .ok_or("Truncated DHCP domain search label")?;
            if !label
                .iter()
                .all(|byte| byte.is_ascii_alphanumeric() || b"-_".contains(byte))
            {
                return Err("DHCP domain search contains an invalid character".into());
            }
            labels.push(std::str::from_utf8(label).map_err(|error| error.to_string())?);
            position += length;
        }
        let domain = labels.join(".");
        if domain.is_empty() || domain.len() > 253 {
            return Err("DHCP domain search contains an invalid domain name".into());
        }
        domains.push(domain);
    }
    Ok(domains)
}

#[cfg(test)]
mod tests {
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
}
