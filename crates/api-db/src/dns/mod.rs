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

pub fn normalize_domain(name: &str) -> String {
    let normalize_domain = name.trim_end_matches('.').to_lowercase();
    tracing::debug!("Normalized domain name: {} to: {}", name, normalize_domain);
    normalize_domain
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

#[cfg(test)]
mod tests {
    use carbide_test_support::Outcome::*;
    use carbide_test_support::{Case, check_cases_async};
    use sqlx::Row;

    #[test]
    fn test_normalize_domain_name() {
        let domain_name = "example.com.";
        let expected = "example.com";
        let normalized = super::normalize_domain(domain_name);
        assert_eq!(normalized, expected);
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
    async fn test_dns_hostname_from_ipv6_expands_to_rust_format(pool: sqlx::PgPool) {
        check_cases_async(
            [
                Case {
                    scenario: "ipv4 dotted-quad becomes dashed octets",
                    input: "192.168.1.2",
                    expect: Yields("192-168-1-2".to_string()),
                },
                Case {
                    scenario: "unspecified address expands every hextet",
                    input: "::",
                    expect: Yields("0000-0000-0000-0000-0000-0000-0000-0000".to_string()),
                },
                Case {
                    scenario: "loopback keeps the low hextet",
                    input: "::1",
                    expect: Yields("0000-0000-0000-0000-0000-0000-0000-0001".to_string()),
                },
                Case {
                    scenario: "documentation prefix expands in full",
                    input: "2001:db8::2",
                    expect: Yields("2001-0db8-0000-0000-0000-0000-0000-0002".to_string()),
                },
                Case {
                    scenario: "ipv4-mapped folds into the trailing hextets",
                    input: "::ffff:192.0.2.128",
                    expect: Yields("0000-0000-0000-0000-0000-ffff-c000-0280".to_string()),
                },
            ],
            |address| {
                // Clone the (Arc-backed) pool per case so the future owns it and
                // the closure stays `Fn` — see check_cases_async's signature.
                let pool = pool.clone();
                async move {
                    sqlx::query_scalar::<_, String>("SELECT nico_inet_to_dns_hostname($1::inet)")
                        .bind(address)
                        .fetch_one(&pool)
                        .await
                        .map_err(drop)
                }
            },
        )
        .await;
    }

    #[crate::sqlx_test]
    async fn test_dns_records_instance_ipv6_qname_expands_hostname(pool: sqlx::PgPool) {
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

        sqlx::query(
            "INSERT INTO machine_interfaces (
                id,
                machine_id,
                segment_id,
                mac_address,
                domain_id,
                primary_interface,
                hostname,
                association_type
             )
             VALUES (
                '30000000-0000-0000-0000-000000000001',
                'host-1',
                '20000000-0000-0000-0000-000000000001',
                '02:00:00:00:00:01',
                '10000000-0000-0000-0000-000000000001',
                true,
                'host-1',
                'Machine'
             )",
        )
        .execute(&pool)
        .await
        .unwrap();

        let network_config = serde_json::json!({
            "interfaces": [
                {
                    "function_id": { "type": "physical" },
                    "ip_addrs": {
                        "unspecified": "::",
                        "loopback": "::1",
                        "tenant": "2001:db8::2"
                    }
                }
            ]
        });

        sqlx::query("INSERT INTO instances (machine_id, network_config) VALUES ($1, $2::jsonb)")
            .bind("host-1")
            .bind(network_config)
            .execute(&pool)
            .await
            .unwrap();

        let rows = sqlx::query(
            "SELECT DISTINCT q_name, host(resource_record) AS resource_record
             FROM dns_records_instance",
        )
        .fetch_all(&pool)
        .await
        .unwrap();

        let records = rows
            .iter()
            .map(|row| {
                (
                    row.try_get::<String, _>("resource_record").unwrap(),
                    row.try_get::<String, _>("q_name").unwrap(),
                )
            })
            .collect::<Vec<_>>();

        let expected_records = vec![
            (
                "::".to_string(),
                "0000-0000-0000-0000-0000-0000-0000-0000.dwrt1.com.".to_string(),
            ),
            (
                "::1".to_string(),
                "0000-0000-0000-0000-0000-0000-0000-0001.dwrt1.com.".to_string(),
            ),
            (
                "2001:db8::2".to_string(),
                "2001-0db8-0000-0000-0000-0000-0000-0002.dwrt1.com.".to_string(),
            ),
        ];

        assert_eq!(records.len(), expected_records.len());
        for expected_record in expected_records {
            assert!(records.contains(&expected_record));
        }
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
