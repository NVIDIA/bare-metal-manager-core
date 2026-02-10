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

use std::str::FromStr;

use carbide_uuid::domain::DomainId;
use chrono::{DateTime, Utc};
use hickory_proto::rr::Name;
use model::dns::{Domain, NewDomain, SoaSnapshot};
use sqlx::{FromRow, PgConnection};

use super::super::{ColumnInfo, FilterableQueryBuilder, ObjectColumnFilter};
use crate::db_read::DbReader;
use crate::{DatabaseError, DatabaseResult};

/// Validates a domain name according to DNS standards
fn validate_domain_name(name: &str) -> Result<(), DatabaseError> {
    if name != name.to_lowercase() {
        return Err(DatabaseError::InvalidArgument(
            "domain name must be lowercase".to_string(),
        ));
    }

    Name::from_str(name)
        .map_err(|_| DatabaseError::InvalidArgument(format!("invalid domain name: {}", name)))?;

    Ok(())
}

#[derive(Clone, Debug, FromRow)]
pub struct DbDomain {
    pub id: DomainId,
    pub name: String,
    pub created: DateTime<Utc>,
    pub updated: DateTime<Utc>,
    pub deleted: Option<DateTime<Utc>>,
    pub soa: sqlx::types::Json<Option<dns_record::SoaRecord>>,
    pub domain_metadata_id: Option<i32>,
}

impl From<DbDomain> for Domain {
    fn from(db: DbDomain) -> Self {
        Domain {
            id: db.id,
            name: db.name,
            created: db.created,
            updated: db.updated,
            deleted: db.deleted,
            soa: db.soa.0.map(SoaSnapshot),
            metadata: None,
        }
    }
}

#[derive(Copy, Clone)]
pub struct IdColumn;
impl ColumnInfo<'_> for crate::dns::domain::IdColumn {
    type TableType = Domain;
    type ColumnType = DomainId;

    fn column_name(&self) -> &'static str {
        "id"
    }
}

#[derive(Copy, Clone)]
pub struct NameColumn;
impl<'a> ColumnInfo<'a> for NameColumn {
    type TableType = Domain;
    type ColumnType = &'a str;

    fn column_name(&self) -> &'static str {
        "name"
    }
}

pub async fn persist(value: NewDomain, txn: &mut PgConnection) -> DatabaseResult<Domain> {
    validate_domain_name(&value.name)?;

    // Create default metadata entry
    let metadata_id = super::domain_metadata::DbMetadata::create_default(txn).await?;

    let query =
        "INSERT INTO domains (name, soa, domain_metadata_id) VALUES ($1, $2, $3) returning *";
    match persist_inner_with_metadata(&value, metadata_id, txn, query).await {
        Ok(Some(domain)) => Ok(domain),
        Ok(None) => Err(DatabaseError::NotFoundError {
            kind: "domain",
            id: value.name,
        }),
        Err(err) => Err(err),
    }
}

/// Create the domain only if it would be the first one
pub async fn persist_first(
    value: &NewDomain,
    txn: &mut PgConnection,
) -> DatabaseResult<Option<Domain>> {
    validate_domain_name(&value.name)?;

    let metadata_id = super::domain_metadata::DbMetadata::create_default(txn).await?;

    let query = "
            INSERT INTO domains (name, soa, domain_metadata_id) SELECT $1, $2, $3
            WHERE NOT EXISTS (SELECT name FROM domains)
            RETURNING *";
    persist_inner_with_metadata(value, metadata_id, txn, query).await
}

async fn persist_inner_with_metadata(
    value: &NewDomain,
    metadata_id: i32,
    txn: &mut PgConnection,
    query: &'static str,
) -> DatabaseResult<Option<Domain>> {
    sqlx::query_as::<_, DbDomain>(query)
        .bind(&value.name)
        .bind(sqlx::types::Json(&value.soa))
        .bind(metadata_id)
        .fetch_optional(txn)
        .await
        .map(|opt| opt.map(Domain::from))
        .map_err(|e| DatabaseError::query(query, e))
}

/// Finds `domains` based on specified criteria, excluding deleted entries.
///
/// Returns `Vec<Domain>`
///
/// # Arguments
///
/// * [`ObjectColumnFilter`] - An enum that determines the query criteria
///
/// # Examples
///
///
pub async fn find_by<'a, C: ColumnInfo<'a, TableType = Domain>>(
    txn: impl DbReader<'_>,
    filter: ObjectColumnFilter<'a, C>,
) -> Result<Vec<Domain>, DatabaseError> {
    find_all_by(txn, filter, false).await
}

/// Similar to [`Domain::find_by`] but lets you specify whether to include deleted results
pub async fn find_all_by<'a, C: ColumnInfo<'a, TableType = Domain>>(
    txn: impl DbReader<'_>,
    filter: ObjectColumnFilter<'a, C>,
    include_deleted: bool,
) -> Result<Vec<Domain>, DatabaseError> {
    let mut query = FilterableQueryBuilder::new("SELECT * FROM domains").filter(&filter);
    if !include_deleted {
        query.push(" AND deleted IS NULL");
    }
    query
        .build_query_as::<DbDomain>()
        .fetch_all(txn)
        .await
        .map(|domains| domains.into_iter().map(Domain::from).collect())
        .map_err(|e| DatabaseError::query(query.sql(), e))
}

pub async fn find_by_name(
    txn: impl DbReader<'_>,
    name: &str,
) -> Result<Vec<Domain>, DatabaseError> {
    find_by(txn, ObjectColumnFilter::One(NameColumn, &name)).await
}

/// Find the domain with the given ID, even if it is deleted.
pub async fn find_by_uuid(
    txn: &mut PgConnection,
    uuid: DomainId,
) -> Result<Option<Domain>, DatabaseError> {
    find_all_by(txn, ObjectColumnFilter::One(IdColumn, &uuid), true)
        .await
        .map(|f| f.first().cloned())
}

pub async fn delete(value: Domain, txn: &mut PgConnection) -> Result<Domain, DatabaseError> {
    let query = "UPDATE domains SET updated=NOW(), deleted=NOW() WHERE id=$1 RETURNING *";
    sqlx::query_as::<_, DbDomain>(query)
        .bind(value.id)
        .fetch_one(txn)
        .await
        .map(Domain::from)
        .map_err(|e| DatabaseError::query(query, e))
}

pub async fn update(value: &mut Domain, txn: &mut PgConnection) -> Result<Domain, DatabaseError> {
    validate_domain_name(&value.name)?;

    let query = "UPDATE domains SET name=$1, updated=NOW(), soa=$2 WHERE id=$3 RETURNING *";

    sqlx::query_as::<_, DbDomain>(query)
        .bind(&value.name)
        .bind(sqlx::types::Json(&value.soa))
        .bind(value.id)
        .fetch_one(txn)
        .await
        .map(Domain::from)
        .map_err(|e| DatabaseError::query(query, e))
}

#[cfg(test)]
#[test]
fn test_generate_domain_serial_format() {
    use chrono::Utc;
    let now = Utc::now();
    let expected_serial = now.format("%Y%m%d01").to_string().parse::<u32>().unwrap();

    let serial = dns_record::SoaRecord::generate_new_serial();

    assert_eq!(serial, expected_serial);
}
