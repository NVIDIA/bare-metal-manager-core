/*
 * SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

pub mod domain;
pub mod domain_metadata;
pub mod resource_record;

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use ipnetwork::IpNetwork;
use model::dns::NewDomain;
use sqlx::PgConnection;

use crate::DatabaseResult;

pub fn normalize_domain(name: &str) -> String {
    let normalized_domain = name.trim_end_matches('.').to_ascii_lowercase();
    tracing::debug!(input = %name, normalized = %normalized_domain, "normalized domain name");
    normalized_domain
}

/// Parse a reverse-DNS (PTR) query name into the address it points at -- the
/// inverse of the `in-addr.arpa` (IPv4) / `ip6.arpa` (IPv6) form. Returns `None`
/// for anything that is not a well-formed arpa name, so the caller answers
/// NotFound rather than guessing.
pub fn arpa_qname_to_ip(qname: &str) -> Option<IpAddr> {
    let name = qname.trim_end_matches('.').to_ascii_lowercase();

    if let Some(reversed) = name.strip_suffix(".in-addr.arpa") {
        // Four decimal octets, least-significant label first.
        let octets: Vec<&str> = reversed.split('.').collect();
        if octets.len() != 4 {
            return None;
        }
        let mut addr = [0u8; 4];
        for (byte, octet) in addr.iter_mut().zip(octets.iter().rev()) {
            *byte = octet.parse().ok()?;
        }
        Some(IpAddr::V4(Ipv4Addr::from(addr)))
    } else if let Some(reversed) = name.strip_suffix(".ip6.arpa") {
        // Thirty-two hex nibbles, least-significant label first.
        let nibbles: Vec<&str> = reversed.split('.').collect();
        if nibbles.len() != 32 {
            return None;
        }
        let mut addr = [0u8; 16];
        for (i, nibble) in nibbles.iter().rev().enumerate() {
            if nibble.len() != 1 {
                return None;
            }
            let value = u8::from_str_radix(nibble, 16).ok()?;
            if i % 2 == 0 {
                addr[i / 2] = value << 4;
            } else {
                addr[i / 2] |= value;
            }
        }
        Some(IpAddr::V6(Ipv6Addr::from(addr)))
    } else {
        None
    }
}

/// Build the reverse-DNS zone name for a network prefix: the network octets
/// (IPv4) or nibbles (IPv6) the prefix covers, in reverse, under `in-addr.arpa`
/// / `ip6.arpa`. The forward inverse of [`arpa_qname_to_ip`].
///
/// Returns `None` for a prefix that is not octet-aligned (IPv4: /8, /16, /24,
/// /32) or nibble-aligned (IPv6: a multiple of 4) -- RFC 2317 classless
/// delegation is out of scope.
pub fn cidr_to_reverse_zone(prefix: IpNetwork) -> Option<String> {
    match prefix {
        IpNetwork::V4(net) => {
            let bits = net.prefix();
            if bits == 0 || bits % 8 != 0 {
                return None;
            }
            let octets = net.network().octets();
            let labels = (bits / 8) as usize;
            let mut parts: Vec<String> = octets[..labels].iter().rev().map(u8::to_string).collect();
            parts.push("in-addr.arpa".to_string());
            Some(parts.join("."))
        }
        IpNetwork::V6(net) => {
            let bits = net.prefix();
            if bits == 0 || bits % 4 != 0 {
                return None;
            }
            let octets = net.network().octets();
            let nibbles = (bits / 4) as usize;
            let mut parts: Vec<String> = (0..nibbles)
                .map(|i| {
                    let byte = octets[i / 2];
                    let nibble = if i % 2 == 0 { byte >> 4 } else { byte & 0x0f };
                    format!("{nibble:x}")
                })
                .collect();
            parts.reverse();
            parts.push("ip6.arpa".to_string());
            Some(parts.join("."))
        }
    }
}

/// Ensure the reverse-DNS zone for a network prefix exists, deriving its name
/// from the prefix and creating the domain only if it is not already present.
/// A network's reverse zone is a consequence of the network existing, so this is
/// called wherever a network segment is created; non-aligned prefixes are skipped
/// (see [`cidr_to_reverse_zone`]).
///
/// The find-then-create avoids duplicating a zone an earlier same-prefix segment
/// already created (domain names are not unique). It does not need to guard
/// concurrent creation: network prefixes are globally non-overlapping
/// (`network_prefixes_prefix_excl`), so two segments never map to the same zone,
/// and a duplicate prefix fails in `network_segment::save` before this runs.
pub async fn ensure_reverse_zone(prefix: IpNetwork, txn: &mut PgConnection) -> DatabaseResult<()> {
    let Some(zone) = cidr_to_reverse_zone(prefix) else {
        tracing::debug!(%prefix, "no reverse zone: prefix is not octet/nibble aligned");
        return Ok(());
    };
    if domain::find_by_name(&mut *txn, &zone).await?.is_empty() {
        tracing::info!(zone = %zone, %prefix, "creating reverse-DNS zone for network prefix");
        domain::persist(NewDomain::new(zone), txn).await?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {

    #[test]
    fn cidr_to_reverse_zone_derives_aligned_prefixes() {
        use carbide_test_support::value_scenarios;

        value_scenarios!(
            run = |cidr: &str| super::cidr_to_reverse_zone(cidr.parse().unwrap());
            "ipv4 octet-aligned" {
                "10.0.0.0/8" => Some("10.in-addr.arpa".to_string()),
                "192.168.0.0/16" => Some("168.192.in-addr.arpa".to_string()),
                "192.0.2.0/24" => Some("2.0.192.in-addr.arpa".to_string()),
                "192.0.2.1/32" => Some("1.2.0.192.in-addr.arpa".to_string()),
            }
            "ipv6 nibble-aligned" {
                "fd00::/16" => Some("0.0.d.f.ip6.arpa".to_string()),
                "2001:db8::/32" => Some("8.b.d.0.1.0.0.2.ip6.arpa".to_string()),
            }
            "rejects prefixes that are not octet- or nibble-aligned" {
                "192.168.0.0/25" => None,
                "fd00::/17" => None,
                "0.0.0.0/0" => None,
            }
        );
    }

    #[crate::sqlx_test]
    async fn ensure_reverse_zone_creates_idempotently(pool: sqlx::PgPool) {
        let mut txn = pool.begin().await.unwrap();
        let prefix: ipnetwork::IpNetwork = "10.0.0.0/16".parse().unwrap();

        // First call creates the zone; the second is a no-op.
        super::ensure_reverse_zone(prefix, txn.as_mut())
            .await
            .unwrap();
        super::ensure_reverse_zone(prefix, txn.as_mut())
            .await
            .unwrap();
        let zones = super::domain::find_by_name(txn.as_mut(), "0.10.in-addr.arpa")
            .await
            .unwrap();
        assert_eq!(zones.len(), 1, "reverse zone created exactly once");

        // A non-aligned prefix derives no zone, so nothing is created.
        let unaligned: ipnetwork::IpNetwork = "10.1.0.0/25".parse().unwrap();
        super::ensure_reverse_zone(unaligned, txn.as_mut())
            .await
            .unwrap();
        assert!(super::cidr_to_reverse_zone(unaligned).is_none());
    }

    #[test]
    fn test_normalize_domain_name() {
        use carbide_test_support::value_scenarios;

        value_scenarios!(
            run = |name: &str| super::normalize_domain(name);
            "strips the trailing dot and folds case to ASCII lowercase" {
                "example.com." => "example.com".to_string(),
                "EXAMPLE.COM." => "example.com".to_string(),
                "Example.Com" => "example.com".to_string(),
            }
        );
    }

    #[test]
    fn parses_arpa_qname_to_ip() {
        use std::net::{IpAddr, Ipv4Addr};

        use carbide_test_support::value_scenarios;

        value_scenarios!(
            run = |qname: &str| super::arpa_qname_to_ip(qname);
            "ipv4 in-addr.arpa" {
                "1.0.168.192.in-addr.arpa." => Some(IpAddr::V4(Ipv4Addr::new(192, 168, 0, 1))),
                "3.2.1.10.in-addr.arpa." => Some(IpAddr::V4(Ipv4Addr::new(10, 1, 2, 3))),
            }
            "ipv6 ip6.arpa" {
                "1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa."
                    => Some("2001:db8::1".parse::<IpAddr>().unwrap()),
                "1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.ip6.arpa."
                    => Some("::1".parse::<IpAddr>().unwrap()),
            }
            "rejects non-arpa and malformed" {
                "host.example.com." => None,
                "1.2.3.in-addr.arpa." => None,
                "300.0.0.0.in-addr.arpa." => None,
                "1.0.168.192.in-addr.arpa.extra." => None,
            }
            "normalizes case" {
                "1.0.168.192.IN-ADDR.ARPA." => Some(IpAddr::V4(Ipv4Addr::new(192, 168, 0, 1))),
                "1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.B.D.0.1.0.0.2.IP6.ARPA."
                    => Some("2001:db8::1".parse::<IpAddr>().unwrap()),
            }
        );
    }

    #[crate::sqlx_test]
    async fn find_ptr_record_resolves_address_to_hostname(pool: sqlx::PgPool) {
        sqlx::query(
            "INSERT INTO domains (id, name)
             VALUES ('10000000-0000-0000-0000-000000000001', 'dwrt1.com')",
        )
        .execute(&pool)
        .await
        .unwrap();

        sqlx::query(
            "INSERT INTO network_segments (id, name, version)
             VALUES ('20000000-0000-0000-0000-000000000001', 'tenant-segment', 'test')",
        )
        .execute(&pool)
        .await
        .unwrap();

        sqlx::query(
            "INSERT INTO machines (id, dpf)
             VALUES ('host-1', '{\"enabled\": true, \"used_for_ingestion\": false}'::jsonb)",
        )
        .execute(&pool)
        .await
        .unwrap();

        // host-1 has three interfaces on the same domain: the primary, a BMC, and a
        // plain (non-primary, non-BMC) data interface.
        sqlx::query(
            "INSERT INTO machine_interfaces (
                id, machine_id, segment_id, mac_address, domain_id,
                primary_interface, hostname, association_type
             )
             VALUES (
                '30000000-0000-0000-0000-000000000001', 'host-1',
                '20000000-0000-0000-0000-000000000001', '02:00:00:00:00:01',
                '10000000-0000-0000-0000-000000000001', true, 'host-1', 'Machine'
             )",
        )
        .execute(&pool)
        .await
        .unwrap();

        sqlx::query(
            "INSERT INTO machine_interfaces (
                id, machine_id, segment_id, mac_address, domain_id,
                primary_interface, hostname, association_type, interface_type
             )
             VALUES (
                '30000000-0000-0000-0000-000000000002', 'host-1',
                '20000000-0000-0000-0000-000000000001', '02:00:00:00:00:02',
                '10000000-0000-0000-0000-000000000001', false, 'host-1-bmc', 'Machine', 'Bmc'
             )",
        )
        .execute(&pool)
        .await
        .unwrap();

        sqlx::query(
            "INSERT INTO machine_interfaces (
                id, machine_id, segment_id, mac_address, domain_id,
                primary_interface, hostname, association_type
             )
             VALUES (
                '30000000-0000-0000-0000-000000000003', 'host-1',
                '20000000-0000-0000-0000-000000000001', '02:00:00:00:00:03',
                '10000000-0000-0000-0000-000000000001', false, 'host-1-data', 'Machine'
             )",
        )
        .execute(&pool)
        .await
        .unwrap();

        for (interface_id, address) in [
            ("30000000-0000-0000-0000-000000000001", "192.168.0.1"),
            ("30000000-0000-0000-0000-000000000002", "192.168.0.2"),
            ("30000000-0000-0000-0000-000000000003", "192.168.0.3"),
        ] {
            sqlx::query(
                "INSERT INTO machine_interface_addresses (interface_id, address)
                 VALUES ($1::uuid, $2::inet)",
            )
            .bind(interface_id)
            .bind(address)
            .execute(&pool)
            .await
            .unwrap();
        }

        // Primary and BMC interfaces answer PTR (matching the forward shortname view);
        // the plain data interface and an address no interface holds do not.
        let cases = [
            ("192.168.0.1", Some("host-1.dwrt1.com.")),
            ("192.168.0.2", Some("host-1-bmc.dwrt1.com.")),
            ("192.168.0.3", None),
            ("10.9.9.9", None),
        ];
        for (address, expected) in cases {
            let records = super::resource_record::find_ptr_record(&pool, address.parse().unwrap())
                .await
                .unwrap();
            match expected {
                Some(fqdn) => {
                    assert_eq!(records.len(), 1, "address {address}");
                    assert_eq!(records[0].ptr_content, fqdn, "address {address}");
                }
                None => assert!(
                    records.is_empty(),
                    "address {address} should resolve to nothing"
                ),
            }
        }
    }
}
