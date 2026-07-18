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
use std::net::IpAddr;

use carbide_uuid::domain::DomainId;
use dns_record::SoaRecord;
use sqlx::postgres::PgRow;
use sqlx::{Error, FromRow, Row};

use crate::DatabaseError;
use crate::db_read::DbReader;

#[derive(Debug, Clone)]
pub struct DbResourceRecord {
    pub q_type: String,
    pub ttl: i32,
    pub q_name: String,
    pub record: String,
    pub domain_id: DomainId,
}

impl From<DbResourceRecord> for model::dns::ResourceRecord {
    fn from(r: DbResourceRecord) -> Self {
        Self {
            q_type: r.q_type,
            q_name: r.q_name,
            ttl: r.ttl as u32,
            content: r.record,
            domain_id: Some(r.domain_id.to_string()),
        }
    }
}

pub struct DbSoaRecord(pub SoaRecord);

impl<'r> FromRow<'r, PgRow> for DbSoaRecord {
    fn from_row(row: &'r PgRow) -> Result<Self, Error> {
        let soa: sqlx::types::Json<SoaRecord> = row.try_get("soa")?;
        Ok(DbSoaRecord(soa.0))
    }
}

impl<'r> FromRow<'r, PgRow> for DbResourceRecord {
    fn from_row(row: &'r PgRow) -> Result<Self, Error> {
        // Stored as IP address in the database
        let record: String = row
            .try_get("resource_record")
            .map(|i: IpAddr| i.to_string())?;
        let q_name: String = row.try_get("q_name")?;
        let q_type: String = row.try_get("q_type")?;
        let ttl: i32 = row.try_get("ttl")?;
        let domain_id = row.try_get("domain_id")?;

        Ok(DbResourceRecord {
            q_name,
            record,
            q_type,
            ttl,
            domain_id,
        })
    }
}

pub async fn get_soa_record(
    txn: impl DbReader<'_>,
    query_name: &str,
) -> Result<Option<DbSoaRecord>, DatabaseError> {
    let domain_name = crate::dns::normalize_domain(query_name);
    const QUERY: &str = "SELECT soa from domains WHERE name=$1";
    sqlx::query_as::<_, DbSoaRecord>(QUERY)
        .bind(domain_name)
        .fetch_optional(txn)
        .await
        .map_err(|e| DatabaseError::query(QUERY, e))
}

pub async fn find_record(
    txn: impl DbReader<'_>,
    query_name: &str,
) -> Result<Vec<DbResourceRecord>, DatabaseError> {
    // TODO: Configurable defaults for TTL
    let query = r#"
    SELECT
     q_name,
     resource_record,
     domain_id,
     COALESCE(ttl, 300) as ttl,
     COALESCE(q_type, CASE WHEN family(resource_record) = 6 THEN 'AAAA' ELSE 'A' END) as q_type
     from dns_records WHERE q_name=$1"#;

    tracing::info!(query_name, "Looking up DNS record",);
    let result = sqlx::query_as::<_, DbResourceRecord>(query)
        .bind(query_name)
        .fetch_all(txn)
        .await
        .map_err(|e| DatabaseError::query(query, e))?;

    Ok(result)
}

#[derive(Debug, Clone)]
pub struct DbPtrRecord {
    pub ttl: i32,
    /// The FQDN the PTR record answers with (e.g. `host-1.dwrt1.com.`).
    pub ptr_content: String,
    pub domain_id: DomainId,
}

impl<'r> FromRow<'r, PgRow> for DbPtrRecord {
    fn from_row(row: &'r PgRow) -> Result<Self, Error> {
        Ok(DbPtrRecord {
            ptr_content: row.try_get("ptr_content")?,
            ttl: row.try_get("ttl")?,
            domain_id: row.try_get("domain_id")?,
        })
    }
}

/// Find the PTR answers for an address: the FQDN(s) it resolves back to. Two
/// sources, each mirroring its forward counterpart so a forward A/AAAA record and
/// its PTR round-trip:
/// - a machine interface that holds the address -- the `dns_records_shortname_combined`
///   primary/BMC arm, with `COALESCE(meta.ttl, 300)` to match the forward TTL;
/// - an overlay instance allocated the address -- read straight from the
///   `dns_records_instance` forward view by IP, so forward and reverse share one
///   definition; that view already carries the stored hostname and excludes
///   `host_inband` (the host's own address, answered by the machine source).
///
/// Both look up by `address`, so the query rides the address indexes rather than
/// scanning. The two arms are disjoint (an overlay address is never a machine
/// interface address), so the `UNION` only ever merges an accidental exact match.
pub async fn find_ptr_record(
    txn: impl DbReader<'_>,
    address: IpAddr,
) -> Result<Vec<DbPtrRecord>, DatabaseError> {
    let query = r#"
    SELECT
        concat(mi.hostname, '.', d.name, '.') AS ptr_content,
        COALESCE(meta.ttl, 300) AS ttl,
        d.id AS domain_id
    FROM machine_interface_addresses mia
    JOIN machine_interfaces mi ON mi.id = mia.interface_id
    JOIN domains d ON d.id = mi.domain_id
    LEFT JOIN dns_record_metadata meta ON meta.id = mi.id
    WHERE mia.address = $1::inet
      AND (mi.primary_interface = TRUE OR mi.interface_type = 'Bmc')
    UNION
    SELECT
        q_name AS ptr_content,
        COALESCE(ttl, 300) AS ttl,
        domain_id
    FROM dns_records_instance
    WHERE resource_record = $1::inet"#;

    sqlx::query_as::<_, DbPtrRecord>(query)
        .bind(address.to_string())
        .fetch_all(txn)
        .await
        .map_err(|e| DatabaseError::query(query, e))
}

pub async fn get_all_records_all_domains(
    txn: impl DbReader<'_>,
) -> Result<Vec<DbResourceRecord>, DatabaseError> {
    let query = r#"
        SELECT dr.q_name, dr.resource_record, dr.domain_id,
               COALESCE(dr.ttl, 300) as ttl,
               COALESCE(dr.q_type, CASE WHEN family(dr.resource_record) = 6 THEN 'AAAA' ELSE 'A' END) as q_type
        FROM dns_records dr
        JOIN domains d ON d.id = dr.domain_id
        WHERE d.deleted IS NULL
        ORDER BY dr.q_name
    "#;

    sqlx::query_as::<_, DbResourceRecord>(query)
        .fetch_all(txn)
        .await
        .map_err(|e| DatabaseError::query(query, e))
}

pub async fn get_all_records(
    txn: impl DbReader<'_>,
    query_name: &str,
) -> Result<Vec<DbResourceRecord>, DatabaseError> {
    let domain_name = crate::dns::normalize_domain(query_name);
    let query = r#"
        SELECT dr.q_name, dr.resource_record, dr.domain_id,
               COALESCE(dr.ttl, 300) as ttl,
               COALESCE(dr.q_type, CASE WHEN family(dr.resource_record) = 6 THEN 'AAAA' ELSE 'A' END) as q_type
        FROM dns_records dr
        JOIN domains d ON d.id = dr.domain_id
        WHERE d.name = $1 AND d.deleted IS NULL
    "#;

    sqlx::query_as::<_, DbResourceRecord>(query)
        .bind(domain_name)
        .fetch_all(txn)
        .await
        .map_err(|e| DatabaseError::query(query, e))
}

#[cfg(test)]
mod tests {
    use carbide_uuid::instance::InstanceId;
    use carbide_uuid::network::NetworkSegmentId;
    use carbide_uuid::vpc::VpcId;
    use model::dns::NewDomain;

    use super::find_record;
    use crate::dns::domain;

    /// Seed a machine, an instance on it, a forward zone, and a network segment of
    /// `segment_type` whose forward zone is that domain. Returns the instance and
    /// segment so a caller can attach addresses and look them up.
    async fn seed_instance_segment(
        conn: &mut sqlx::PgConnection,
        zone: &str,
        segment_type: &str,
    ) -> (InstanceId, NetworkSegmentId, VpcId) {
        let zone_domain = domain::persist(NewDomain::new(zone.to_string()), conn)
            .await
            .unwrap();
        let vpc_id: VpcId =
            sqlx::query_scalar("INSERT INTO vpcs (name, version) VALUES ($1, $2) RETURNING id")
                .bind("vpc-2408")
                .bind("1")
                .fetch_one(&mut *conn)
                .await
                .unwrap();
        sqlx::query("INSERT INTO machines (id, dpf) VALUES ($1, '{}'::jsonb)")
            .bind("test-machine-2408")
            .execute(&mut *conn)
            .await
            .unwrap();
        let instance_id: InstanceId =
            sqlx::query_scalar("INSERT INTO instances (machine_id) VALUES ($1) RETURNING id")
                .bind("test-machine-2408")
                .fetch_one(&mut *conn)
                .await
                .unwrap();
        let segment_id: NetworkSegmentId = sqlx::query_scalar(
            "INSERT INTO network_segments (name, version, network_segment_type, subdomain_id, vpc_id)
             VALUES ($1, $2, $3::network_segment_type_t, $4, $5) RETURNING id",
        )
        .bind("seg-2408")
        .bind("1")
        .bind(segment_type)
        .bind(zone_domain.id)
        .bind(vpc_id)
        .fetch_one(&mut *conn)
        .await
        .unwrap();
        (instance_id, segment_id, vpc_id)
    }

    async fn add_address(
        conn: &mut sqlx::PgConnection,
        instance_id: InstanceId,
        segment_id: NetworkSegmentId,
        vpc_id: VpcId,
        address: &str,
        prefix: &str,
    ) {
        // The allocate path stores the IP-derived hostname; mirror that here so the
        // view has a name to publish.
        let hostname =
            crate::host_naming::address_to_hostname(&address.parse::<std::net::IpAddr>().unwrap())
                .unwrap();
        sqlx::query(
            "INSERT INTO instance_addresses (instance_id, address, segment_id, prefix, vpc_id, hostname)
             VALUES ($1::uuid, $2::inet, $3::uuid, $4::cidr, $5::uuid, $6)",
        )
        .bind(instance_id)
        .bind(address)
        .bind(segment_id)
        .bind(prefix)
        .bind(vpc_id)
        .bind(hostname)
        .execute(conn)
        .await
        .unwrap();
    }

    #[crate::sqlx_test]
    async fn overlay_instance_addresses_are_served_forward(pool: sqlx::PgPool) {
        struct Case {
            address: &'static str,
            prefix: &'static str,
            q_name: &'static str,
            q_type: &'static str,
        }
        // One row per address family: the served name is the address in dashed,
        // IP-derived form under the segment's forward zone.
        let cases = [
            Case {
                address: "10.1.2.3",
                prefix: "10.1.2.0/24",
                q_name: "10-1-2-3.tenant.example.com.",
                q_type: "A",
            },
            Case {
                address: "2001:db8:abcd::2",
                prefix: "2001:db8:abcd::/64",
                q_name: "2001-0db8-abcd-0000-0000-0000-0000-0002.tenant.example.com.",
                q_type: "AAAA",
            },
        ];

        let mut txn = pool.begin().await.unwrap();
        let (instance_id, segment_id, vpc_id) =
            seed_instance_segment(txn.as_mut(), "tenant.example.com", "tenant").await;
        for case in &cases {
            add_address(
                txn.as_mut(),
                instance_id,
                segment_id,
                vpc_id,
                case.address,
                case.prefix,
            )
            .await;
        }

        for case in &cases {
            let records = find_record(txn.as_mut(), case.q_name).await.unwrap();
            assert_eq!(
                records.len(),
                1,
                "one {} record for {}",
                case.q_type,
                case.address
            );
            assert_eq!(records[0].q_type, case.q_type);
            assert_eq!(
                records[0].record.parse::<std::net::IpAddr>().unwrap(),
                case.address.parse::<std::net::IpAddr>().unwrap()
            );
        }
    }

    #[crate::sqlx_test]
    async fn host_inband_instance_addresses_are_not_served_here(pool: sqlx::PgPool) {
        // A host_inband instance address *is* the host's own interface address,
        // already published by the shortname view -- the instance arm must skip it
        // so it is not served twice.
        let mut txn = pool.begin().await.unwrap();
        let (instance_id, segment_id, vpc_id) =
            seed_instance_segment(txn.as_mut(), "host.example.com", "host_inband").await;
        add_address(
            txn.as_mut(),
            instance_id,
            segment_id,
            vpc_id,
            "10.9.9.9",
            "10.9.9.0/24",
        )
        .await;

        let records = find_record(txn.as_mut(), "10-9-9-9.host.example.com.")
            .await
            .unwrap();
        assert!(
            records.is_empty(),
            "host_inband addresses are not published by the instance arm"
        );
    }

    #[crate::sqlx_test]
    async fn overlay_instance_addresses_resolve_reverse_ptr(pool: sqlx::PgPool) {
        struct Case {
            address: &'static str,
            prefix: &'static str,
            ptr: &'static str,
        }
        // One row per address family: the PTR answers with the instance's forward
        // FQDN -- the reverse of #2408's A/AAAA record, so the two round-trip.
        let cases = [
            Case {
                address: "10.1.2.3",
                prefix: "10.1.2.0/24",
                ptr: "10-1-2-3.tenant.example.com.",
            },
            Case {
                address: "2001:db8:abcd::2",
                prefix: "2001:db8:abcd::/64",
                ptr: "2001-0db8-abcd-0000-0000-0000-0000-0002.tenant.example.com.",
            },
        ];

        let mut txn = pool.begin().await.unwrap();
        let (instance_id, segment_id, vpc_id) =
            seed_instance_segment(txn.as_mut(), "tenant.example.com", "tenant").await;
        for case in &cases {
            add_address(
                txn.as_mut(),
                instance_id,
                segment_id,
                vpc_id,
                case.address,
                case.prefix,
            )
            .await;
        }

        for case in &cases {
            let ptrs = super::find_ptr_record(
                txn.as_mut(),
                case.address.parse::<std::net::IpAddr>().unwrap(),
            )
            .await
            .unwrap();
            assert_eq!(ptrs.len(), 1, "one PTR for {}", case.address);
            assert_eq!(ptrs[0].ptr_content, case.ptr);
            assert_eq!(ptrs[0].ttl, 300, "instance PTR uses the default TTL");
        }
    }

    #[crate::sqlx_test]
    async fn host_inband_instance_addresses_have_no_instance_ptr(pool: sqlx::PgPool) {
        // A host_inband address is the host's own; its PTR comes from the machine
        // source, not the instance arm. With no machine interface here there is no
        // answer -- proving the instance arm excludes host_inband.
        let mut txn = pool.begin().await.unwrap();
        let (instance_id, segment_id, vpc_id) =
            seed_instance_segment(txn.as_mut(), "host.example.com", "host_inband").await;
        add_address(
            txn.as_mut(),
            instance_id,
            segment_id,
            vpc_id,
            "10.9.9.9",
            "10.9.9.0/24",
        )
        .await;

        let ptrs = super::find_ptr_record(
            txn.as_mut(),
            "10.9.9.9".parse::<std::net::IpAddr>().unwrap(),
        )
        .await
        .unwrap();
        assert!(
            ptrs.is_empty(),
            "host_inband addresses are not answered by the instance arm"
        );
    }
}
