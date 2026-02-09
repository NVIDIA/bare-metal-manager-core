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
use model::tenant::{TenantKeyset, TenantKeysetId, TenantKeysetIdentifier, UpdateTenantKeyset};
use sqlx::PgConnection;

use crate::{DatabaseError, ObjectFilter};

pub async fn create(
    value: &TenantKeyset,
    txn: &mut PgConnection,
) -> Result<TenantKeyset, DatabaseError> {
    let query = "INSERT INTO tenant_keysets VALUES($1, $2, $3, $4) RETURNING *";

    sqlx::query_as(query)
        .bind(value.keyset_identifier.organization_id.to_string())
        .bind(&value.keyset_identifier.keyset_id)
        .bind(sqlx::types::Json(&value.keyset_content))
        .bind(value.version.to_string())
        .fetch_one(txn)
        .await
        .map_err(|e| DatabaseError::query(query, e))
}

pub async fn find_ids(
    txn: &mut PgConnection,
    filter: rpc::forge::TenantKeysetSearchFilter,
) -> Result<Vec<TenantKeysetId>, DatabaseError> {
    // build query
    let mut builder =
        sqlx::QueryBuilder::new("SELECT organization_id, keyset_id FROM tenant_keysets");
    if let Some(tenant_org_id) = &filter.tenant_org_id {
        builder.push(" WHERE organization_id = ");
        builder.push_bind(tenant_org_id);
    }
    // execute
    let query = builder.build_query_as();
    let ids: Vec<TenantKeysetId> = query
        .fetch_all(txn)
        .await
        .map_err(|e| DatabaseError::new("tenant_keyset::find_ids", e))?;

    Ok(ids)
}

pub async fn find_by_ids(
    txn: &mut PgConnection,
    ids: Vec<rpc::forge::TenantKeysetIdentifier>,
    include_key_data: bool,
) -> Result<Vec<TenantKeyset>, DatabaseError> {
    // build query
    let mut builder = sqlx::QueryBuilder::new(
        "SELECT * FROM tenant_keysets WHERE (organization_id, keyset_id) IN ",
    );
    builder.push_tuples(ids.iter(), |mut b, id| {
        b.push_bind(&id.organization_id).push_bind(&id.keyset_id);
    });
    // execute
    let query = builder.build_query_as();
    let mut keysets: Vec<TenantKeyset> = query
        .fetch_all(txn)
        .await
        .map_err(|e| DatabaseError::new("tenant_keyset::find_by_ids", e))?;

    if !include_key_data {
        for data in &mut keysets {
            data.keyset_content.public_keys.clear();
        }
    }

    Ok(keysets)
}

pub async fn find(
    organization_id: Option<String>,
    keyset_filter: ObjectFilter<'_, String>,
    include_key_data: bool,
    txn: &mut PgConnection,
) -> Result<Vec<TenantKeyset>, DatabaseError> {
    let mut result = if let Some(organization_id) = organization_id {
        let base_query = "SELECT * FROM tenant_keysets WHERE organization_id = $1 {where}";

        match keyset_filter {
            ObjectFilter::All => sqlx::query_as(&base_query.replace("{where}", ""))
                .bind(organization_id.to_string())
                .fetch_all(txn)
                .await
                .map_err(|e| DatabaseError::new("keyset All", e)),

            ObjectFilter::One(keyset_id) => {
                sqlx::query_as(&base_query.replace("{where}", "AND keyset_id = $2"))
                    .bind(organization_id.to_string())
                    .bind(keyset_id)
                    .fetch_all(txn)
                    .await
                    .map_err(|e| DatabaseError::query(base_query, e))
            }

            ObjectFilter::List(keyset_ids) => {
                sqlx::query_as(&base_query.replace("{where}", "AND keyset_id = ANY($2)"))
                    .bind(organization_id.to_string())
                    .bind(keyset_ids)
                    .fetch_all(txn)
                    .await
                    .map_err(|e| DatabaseError::query(base_query, e))
            }
        }
    } else {
        let query = "SELECT * FROM tenant_keysets";
        sqlx::query_as::<_, TenantKeyset>(query)
            .fetch_all(txn)
            .await
            .map_err(|e| DatabaseError::query(query, e))
    }?;

    if !include_key_data {
        for data in &mut result {
            data.keyset_content.public_keys.clear();
        }
    }

    Ok(result)
}

/// Deletes the Keyset
/// - Returns `Ok(true)` if the keyset existed and got deleted
/// - Returns `Ok(false)` if the keyset did not exist
/// - Returns `Err(_)` in case of other errors
pub async fn delete(
    keyset_identifier: &TenantKeysetIdentifier,
    txn: &mut PgConnection,
) -> Result<bool, DatabaseError> {
    let query =
        "DELETE FROM tenant_keysets WHERE organization_id = $1 AND keyset_id = $2 RETURNING *";

    match sqlx::query_as::<_, TenantKeyset>(query)
        .bind(keyset_identifier.organization_id.as_str())
        .bind(&keyset_identifier.keyset_id)
        .fetch_one(txn)
        .await
    {
        Ok(_) => Ok(true),
        Err(sqlx::Error::RowNotFound) => Ok(false),
        Err(e) => Err(DatabaseError::query(query, e)),
    }
}

pub async fn update(
    value: &UpdateTenantKeyset,
    txn: &mut PgConnection,
) -> Result<(), DatabaseError> {
    // Validate if sent version is same.
    let current_keyset = find(
        Some(value.keyset_identifier.organization_id.to_string()),
        ObjectFilter::One(value.keyset_identifier.keyset_id.clone()),
        false,
        txn,
    )
    .await?;

    if current_keyset.is_empty() {
        return Err(DatabaseError::NotFoundError {
            kind: "keyset",
            id: format!("{:?}", value.keyset_identifier),
        });
    }

    let expected_version = value
        .if_version_match
        .clone()
        .unwrap_or(current_keyset[0].version.to_string());

    let query = "UPDATE tenant_keysets SET content=$1, version=$2 WHERE organization_id=$3 AND keyset_id=$4 AND version=$5 RETURNING *";
    match sqlx::query_as::<_, TenantKeyset>(query)
        .bind(sqlx::types::Json(&value.keyset_content))
        .bind(value.version.to_string())
        .bind(value.keyset_identifier.organization_id.to_string())
        .bind(&value.keyset_identifier.keyset_id)
        .bind(&expected_version)
        .fetch_one(txn)
        .await
    {
        Ok(_) => Ok(()),
        Err(sqlx::Error::RowNotFound) => Err(DatabaseError::ConcurrentModificationError(
            "keyset",
            expected_version,
        )),
        Err(e) => Err(DatabaseError::query(query, e)),
    }
}
