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

use carbide_uuid::nvlink::NvLinkLogicalPartitionId;
use config_version::ConfigVersion;
use model::nvl_logical_partition::{
    LogicalPartition, LogicalPartitionSnapshotPgJson, LogicalPartitionState, NewLogicalPartition,
};
use sqlx::PgConnection;

use crate::db_read::DbReader;
use crate::{ColumnInfo, DatabaseError, FilterableQueryBuilder, ObjectColumnFilter};

#[derive(Copy, Clone)]
pub struct IdColumn;
impl ColumnInfo<'_> for IdColumn {
    type TableType = LogicalPartition;
    type ColumnType = NvLinkLogicalPartitionId;

    fn column_name(&self) -> &'static str {
        "id"
    }
}

#[derive(Clone, Copy)]
pub struct NameColumn;
impl<'a> ColumnInfo<'a> for NameColumn {
    type TableType = LogicalPartition;
    type ColumnType = &'a str;

    fn column_name(&self) -> &'static str {
        "id"
    }
}

pub async fn create(
    value: &NewLogicalPartition,
    txn: &mut PgConnection,
) -> Result<LogicalPartition, DatabaseError> {
    let state = LogicalPartitionState::Ready;
    let config = &value.config;
    let config_version = ConfigVersion::initial();

    let query = "INSERT INTO nvlink_logical_partitions (
                id,
                name,
                description,
                tenant_organization_id,
                config_version,
                partition_state)
            VALUES ($1, $2, $3, $4, $5, $6)
            RETURNING row_to_json(nvlink_logical_partitions.*)";

    let partition: LogicalPartitionSnapshotPgJson = sqlx::query_as(query)
        .bind(value.id)
        .bind(&config.metadata.name)
        .bind(&config.metadata.description)
        .bind(config.tenant_organization_id.to_string())
        .bind(config_version)
        .bind(sqlx::types::Json(&state))
        .fetch_one(txn)
        .await
        .map_err(|e| DatabaseError::new(query, e))?;
    partition
        .try_into()
        .map_err(|e| DatabaseError::new(query, e))
}

/// Retrieves the IDs of all NvLink partitions
///
/// * `txn` - A reference to a currently open database transaction
pub async fn for_tenant(
    txn: impl DbReader<'_>,
    tenant_organization_id: String,
) -> Result<Vec<LogicalPartition>, DatabaseError> {
    let results: Vec<LogicalPartition> = {
        let query = "SELECT * FROM nvlink_logical_partitions WHERE tenant_organization_id=$1";
        let partitions: Vec<LogicalPartitionSnapshotPgJson> = sqlx::query_as(query)
            .bind(tenant_organization_id)
            .fetch_all(txn)
            .await
            .map_err(|e| DatabaseError::new(query, e))?;

        partitions
            .into_iter()
            .map(|p| p.try_into())
            .collect::<Result<Vec<LogicalPartition>, sqlx::Error>>()
            .map_err(|e| DatabaseError::new(query, e))?
    };

    Ok(results)
}

pub async fn find_ids(
    txn: impl DbReader<'_>,
    filter: model::nvl_logical_partition::NvLinkLogicalPartitionSearchFilter,
) -> Result<Vec<NvLinkLogicalPartitionId>, DatabaseError> {
    // build query
    let mut builder = sqlx::QueryBuilder::new("SELECT id FROM nvlink_logical_partitions");
    if let Some(name) = &filter.name {
        builder.push(" WHERE name = ");
        builder.push_bind(name);
    }

    let query = builder.build_query_as();
    let ids: Vec<NvLinkLogicalPartitionId> = query
        .fetch_all(txn)
        .await
        .map_err(|e| DatabaseError::new("nvlink_logical_partition::find_ids", e))?;

    Ok(ids)
}

pub async fn find_by<'a, C: ColumnInfo<'a, TableType = LogicalPartition>>(
    txn: impl DbReader<'_>,
    filter: ObjectColumnFilter<'a, C>,
) -> Result<Vec<LogicalPartition>, DatabaseError> {
    let mut query = FilterableQueryBuilder::new(
        "SELECT row_to_json(p.*) FROM (SELECT * FROM nvlink_logical_partitions) p",
    )
    .filter(&filter);

    let partitions: Vec<LogicalPartitionSnapshotPgJson> = query
        .build_query_as()
        .fetch_all(txn)
        .await
        .map_err(|e| DatabaseError::new(query.sql(), e))?;

    partitions
        .into_iter()
        .map(|p| p.try_into())
        .collect::<Result<Vec<LogicalPartition>, sqlx::Error>>()
        .map_err(|e| DatabaseError::new(query.sql(), e))
}

/// Updates the partition state that is owned by the state controller
/// under the premise that the curren controller state version didn't change.
pub async fn try_update_partition_state(
    txn: &mut PgConnection,
    partition_id: NvLinkLogicalPartitionId,
    expected_version: ConfigVersion,
    new_state: &LogicalPartitionState,
) -> Result<bool, DatabaseError> {
    let next_version = expected_version.increment();

    let query = "UPDATE nvlink_logical_partitions SET partition_state_version=$1, partition_state=$2::json WHERE id=$3::uuid AND partition_state_version=$4 RETURNING id";
    let query_result = sqlx::query_as::<_, NvLinkLogicalPartitionId>(query)
        .bind(next_version)
        .bind(sqlx::types::Json(new_state))
        .bind(partition_id)
        .bind(expected_version)
        .fetch_one(txn)
        .await;

    match query_result {
        Ok(_partition_id) => Ok(true),
        Err(sqlx::Error::RowNotFound) => Ok(false),
        Err(e) => Err(DatabaseError::new(query, e)),
    }
}
pub async fn mark_as_deleted(
    partition: &LogicalPartition,
    txn: &mut PgConnection,
) -> Result<NvLinkLogicalPartitionId, DatabaseError> {
    let query = "UPDATE nvlink_logical_partitions SET updated=NOW(), deleted=NOW() WHERE id=$1::uuid RETURNING id";
    let partition: NvLinkLogicalPartitionId = sqlx::query_as(query)
        .bind(partition.id)
        .fetch_one(txn)
        .await
        .map_err(|e| DatabaseError::new(query, e))?;

    Ok(partition)
}

pub async fn update(
    partition: &LogicalPartition,
    name: String,
    description: String,
    txn: &mut PgConnection,
) -> Result<NvLinkLogicalPartitionId, DatabaseError> {
    let query = "UPDATE nvlink_logical_partitions SET name=$1, description=$2, updated=NOW() WHERE id=$3::uuid RETURNING id";

    let partition: NvLinkLogicalPartitionId = sqlx::query_as(query)
        .bind(name)
        .bind(&description)
        .bind(partition.id)
        .fetch_one(txn)
        .await
        .map_err(|e| DatabaseError::new(query, e))?;

    Ok(partition)
}

pub async fn final_delete(
    partition_id: NvLinkLogicalPartitionId,
    txn: &mut PgConnection,
) -> Result<NvLinkLogicalPartitionId, DatabaseError> {
    let query = "DELETE FROM nvlink_logical_partitions WHERE id=$1::uuid RETURNING id";
    let partition: NvLinkLogicalPartitionId = sqlx::query_as(query)
        .bind(partition_id)
        .fetch_one(txn)
        .await
        .map_err(|e| DatabaseError::new(query, e))?;

    Ok(partition)
}
