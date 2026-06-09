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

pub fn normalize_domain(name: &str) -> String {
    let normalize_domain = name.trim_end_matches('.').to_lowercase();
    tracing::debug!("Normalized domain name: {} to: {}", name, normalize_domain);
    normalize_domain
}

#[cfg(test)]
mod tests {
    use sqlx::Row;

    #[test]
    fn test_normalize_domain_name() {
        let domain_name = "example.com.";
        let expected = "example.com";
        let normalized = super::normalize_domain(domain_name);
        assert_eq!(normalized, expected);
    }

    #[crate::sqlx_test]
    async fn test_dns_hostname_from_ipv6_expands_to_rust_format(pool: sqlx::PgPool) {
        let cases = [
            ("192.168.1.2", "192-168-1-2"),
            ("::", "0000-0000-0000-0000-0000-0000-0000-0000"),
            ("::1", "0000-0000-0000-0000-0000-0000-0000-0001"),
            ("2001:db8::2", "2001-0db8-0000-0000-0000-0000-0000-0002"),
            (
                "::ffff:192.0.2.128",
                "0000-0000-0000-0000-0000-ffff-c000-0280",
            ),
        ];

        for (address, expected_hostname) in cases {
            let hostname: String = sqlx::query_scalar("SELECT nico_inet_to_dns_hostname($1::inet)")
                .bind(address)
                .fetch_one(&pool)
                .await
                .unwrap();

            assert_eq!(hostname, expected_hostname);
        }
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
}
