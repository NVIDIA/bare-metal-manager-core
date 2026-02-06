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
use std::ops::DerefMut;

use carbide_uuid::domain::DomainId;
use dns_record::SoaRecord;
use sqlx::postgres::PgRow;
use sqlx::{Error, FromRow, Postgres, Row, Transaction};

use crate::DatabaseError;

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
    txn: &mut Transaction<'_, Postgres>,
    query_name: &str,
) -> Result<Option<DbSoaRecord>, DatabaseError> {
    let domain_name = crate::dns::normalize_domain(query_name);
    const QUERY: &str = "SELECT soa from domains WHERE name=$1";
    sqlx::query_as::<_, DbSoaRecord>(QUERY)
        .bind(domain_name)
        .fetch_optional(txn.deref_mut())
        .await
        .map_err(|e| DatabaseError::query(QUERY, e))
}

pub async fn find_record(
    txn: &mut Transaction<'_, Postgres>,
    query_name: &str,
) -> Result<Vec<DbResourceRecord>, DatabaseError> {
    // TODO: Configurable defaults for TTL
    let query = r#"
    SELECT
     q_name,
     resource_record,
     domain_id,
     COALESCE(ttl, 300) as ttl,
     COALESCE(q_type, 'A') as q_type
     from dns_records WHERE q_name=$1"#;

    tracing::info!("Looking up record using query_name: {}", query_name);
    let result = sqlx::query_as::<_, DbResourceRecord>(query)
        .bind(query_name)
        .fetch_all(txn.deref_mut())
        .await
        .map_err(|e| DatabaseError::query(query, e))?;

    Ok(result)
}
pub async fn get_all_records(
    txn: &mut Transaction<'_, Postgres>,
    query_name: &str,
) -> Result<Vec<DbResourceRecord>, DatabaseError> {
    let domain_name = crate::dns::normalize_domain(query_name);
    let query = r#"
        SELECT dr.q_name, dr.resource_record, dr.domain_id,
               COALESCE(dr.ttl, 300) as ttl,
               COALESCE(dr.q_type, 'A') as q_type
        FROM dns_records dr
        JOIN domains d ON d.id = dr.domain_id
        WHERE d.name = $1 AND d.deleted IS NULL
    "#;

    sqlx::query_as::<_, DbResourceRecord>(query)
        .bind(domain_name)
        .fetch_all(txn.deref_mut())
        .await
        .map_err(|e| DatabaseError::query(query, e))
}
