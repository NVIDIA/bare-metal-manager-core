/*
 * SPDX-FileCopyrightText: Copyright (c) 2021-2023 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: LicenseRef-NvidiaProprietary
 *
 * NVIDIA CORPORATION, its affiliates and licensors retain all intellectual
 * property and proprietary rights in and to this material, related
 * documentation and any modifications thereto. Any use, reproduction,
 * disclosure or distribution of this material and related documentation
 * without an express license agreement from NVIDIA CORPORATION or
 * its affiliates is strictly prohibited.
 */

use forge_uuid::domain::DomainId;
use model::domain::{Domain, NewDomain};
use sqlx::PgConnection;

use super::{ColumnInfo, FilterableQueryBuilder, ObjectColumnFilter};
use crate::{DatabaseError, DatabaseResult};
const SQL_VIOLATION_INVALID_DOMAIN_NAME_REGEX: &str = "valid_domain_name_regex";
const SQL_VIOLATION_DOMAIN_NAME_LOWER_CASE: &str = "domain_name_lower_case";

#[test]
fn test_domain_metadata() {
    use model::domain::DomainMetadata;
    let mut domain_metadata = DomainMetadata::default();
    domain_metadata
        .update_allow_axfr_from(vec!["192.168.1.1".to_string(), "10.0.0.0/24".to_string()]);
}

#[derive(Copy, Clone)]
pub struct IdColumn;
impl ColumnInfo<'_> for crate::db::domain::IdColumn {
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
    let query = "INSERT INTO domains (name, soa) VALUES ($1, $2) returning *";
    match persist_inner(&value, txn, query).await {
        Ok(Some(domain)) => Ok(domain),
        Ok(None) => {
            // likely unreachable - needed because persist_inner uses fetch_optional
            Err(DatabaseError::NotFoundError {
                kind: "domain",
                id: value.name,
            })
        }
        Err(err) => Err(err),
    }
}

/// Create the domain only if it would be the first one
pub async fn persist_first(
    value: &NewDomain,
    txn: &mut PgConnection,
) -> DatabaseResult<Option<Domain>> {
    let query = "
            INSERT INTO domains (name) SELECT $1
            WHERE NOT EXISTS (SELECT name FROM domains)
            RETURNING *";
    persist_inner(value, txn, query).await
}

async fn persist_inner(
    value: &NewDomain,
    txn: &mut PgConnection,
    query: &'static str,
) -> DatabaseResult<Option<Domain>> {
    sqlx::query_as(query)
        .bind(&value.name)
        .bind(sqlx::types::Json(&value.soa))
        .fetch_optional(txn)
        .await
        .map_err(|err| match err {
            sqlx::Error::Database(e)
                if e.constraint() == Some(SQL_VIOLATION_DOMAIN_NAME_LOWER_CASE) =>
            {
                DatabaseError::InvalidArgument("name".to_string())
            }
            sqlx::Error::Database(e)
                if e.constraint() == Some(SQL_VIOLATION_INVALID_DOMAIN_NAME_REGEX) =>
            {
                DatabaseError::InvalidArgument("name".to_string())
            }
            e => DatabaseError::query(query, e),
        })
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
    txn: &mut PgConnection,
    filter: ObjectColumnFilter<'a, C>,
) -> Result<Vec<Domain>, DatabaseError> {
    find_all_by(txn, filter, false).await
}

/// Similar to [`Domain::find_by`] but lets you specify whether to include deleted results
pub async fn find_all_by<'a, C: ColumnInfo<'a, TableType = Domain>>(
    txn: &mut PgConnection,
    filter: ObjectColumnFilter<'a, C>,
    include_deleted: bool,
) -> Result<Vec<Domain>, DatabaseError> {
    let mut query = FilterableQueryBuilder::new("SELECT * FROM domains").filter(&filter);
    if !include_deleted {
        query.push(" AND deleted IS NULL");
    }
    query
        .build_query_as()
        .fetch_all(txn)
        .await
        .map_err(|e| DatabaseError::query(query.sql(), e))
}

pub async fn find_by_name(
    txn: &mut PgConnection,
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
    sqlx::query_as(query)
        .bind(value.id)
        .fetch_one(txn)
        .await
        .map_err(|e| DatabaseError::query(query, e))
}

pub async fn update(value: &mut Domain, txn: &mut PgConnection) -> Result<Domain, DatabaseError> {
    let query =
        "UPDATE domains SET name=$1, updated=NOW(), soa=$2, metadata=$3 WHERE id=$4 RETURNING *";

    if let Some(ref mut record) = value.soa {
        record.increment_serial();
    }

    sqlx::query_as(query)
        .bind(&value.name)
        .bind(sqlx::types::Json(&value.soa))
        .bind(sqlx::types::Json(&value.metadata))
        .bind(value.id)
        .fetch_one(txn)
        .await
        .map_err(|e| DatabaseError::query(query, e))
}

#[cfg(test)]
#[test]
fn test_generate_domain_serial_format() {
    use chrono::Utc;
    // Expected serial format
    let now = Utc::now();
    let expected_serial = now.format("%Y%m%d01").to_string().parse::<u32>().unwrap();

    // Call the function that generates the serial
    let serial = model::domain::Soa::generate_new_serial();

    assert_eq!(serial, expected_serial);
}
