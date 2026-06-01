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

use carbide_uuid::spx::SpxPartitionId;
use config_version::ConfigVersion;
use model::spx_partition::{NewSpxPartition, SpxPartition, SpxPartitionSnapshotPgJson};
use sqlx::PgConnection;

use crate::db_read::DbReader;
use crate::{
    ColumnInfo, DatabaseError, DatabaseResult, FilterableQueryBuilder, ObjectColumnFilter,
};

#[derive(Copy, Clone)]
pub struct IdColumn;
impl ColumnInfo<'_> for IdColumn {
    type TableType = SpxPartition;
    type ColumnType = SpxPartitionId;

    fn column_name(&self) -> &'static str {
        "id"
    }
}

#[derive(Copy, Clone)]
pub struct VniColumn;
impl ColumnInfo<'_> for VniColumn {
    type TableType = SpxPartition;
    type ColumnType = i32;

    fn column_name(&self) -> &'static str {
        "vni"
    }
}

pub async fn create(
    value: &NewSpxPartition,
    vni: i32,
    txn: &mut PgConnection,
) -> Result<SpxPartition, DatabaseError> {
    let config_version = ConfigVersion::initial();

    let query = "INSERT INTO spx_partitions (
                id,
                name,
                description,
                tenant_organization_id,
                vni,
                config_version)
            VALUES ($1, $2, $3, $4, $5, $6)
            RETURNING row_to_json(spx_partitions.*)";

    let partition: SpxPartitionSnapshotPgJson = sqlx::query_as(query)
        .bind(value.id)
        .bind(&value.name)
        .bind(&value.description)
        .bind(&value.tenant_organization_id)
        .bind(vni)
        .bind(config_version)
        .fetch_one(txn)
        .await
        .map_err(|e| DatabaseError::new(query, e))?;
    partition
        .try_into()
        .map_err(|e| DatabaseError::new(query, e))
}

pub async fn for_tenant(
    txn: impl DbReader<'_>,
    tenant_organization_id: String,
) -> Result<Vec<SpxPartition>, DatabaseError> {
    let query = "SELECT row_to_json(p.*) FROM (SELECT * FROM spx_partitions WHERE tenant_organization_id=$1) p";
    let partitions: Vec<SpxPartitionSnapshotPgJson> = sqlx::query_as(query)
        .bind(tenant_organization_id)
        .fetch_all(txn)
        .await
        .map_err(|e| DatabaseError::new(query, e))?;

    partitions
        .into_iter()
        .map(|p| p.try_into())
        .collect::<Result<Vec<SpxPartition>, sqlx::Error>>()
        .map_err(|e| DatabaseError::new(query, e))
}

pub async fn find_ids(
    txn: impl DbReader<'_>,
    filter: model::spx_partition::SpxPartitionSearchFilter,
) -> Result<Vec<SpxPartitionId>, DatabaseError> {
    let mut builder =
        sqlx::QueryBuilder::new("SELECT id FROM spx_partitions WHERE deleted IS NULL");

    if let Some(tenant_org_id) = &filter.tenant_org_id {
        builder.push(" AND tenant_organization_id = ");
        builder.push_bind(tenant_org_id);
    }
    if let Some(name) = &filter.name {
        builder.push(" AND name = ");
        builder.push_bind(name);
    }

    let query = builder.build_query_as();
    let ids: Vec<SpxPartitionId> = query
        .fetch_all(txn)
        .await
        .map_err(|e| DatabaseError::new("spx_partition::find_ids", e))?;

    Ok(ids)
}

pub async fn find_by<'a, C: ColumnInfo<'a, TableType = SpxPartition>, DB>(
    conn: &mut DB,
    filter: ObjectColumnFilter<'a, C>,
) -> Result<Vec<SpxPartition>, DatabaseError>
where
    for<'db> &'db mut DB: DbReader<'db>,
{
    let mut query = FilterableQueryBuilder::new(
        "SELECT row_to_json(p.*) FROM (SELECT * FROM spx_partitions) p",
    )
    .filter(&filter);

    let partitions: Vec<SpxPartitionSnapshotPgJson> = query
        .build_query_as()
        .fetch_all(&mut *conn)
        .await
        .map_err(|e| DatabaseError::new(query.sql(), e))?;

    partitions
        .into_iter()
        .map(|p| p.try_into())
        .collect::<Result<Vec<SpxPartition>, sqlx::Error>>()
        .map_err(|e| DatabaseError::new(query.sql(), e))
}

pub async fn mark_as_deleted(
    pid: SpxPartitionId,
    txn: &mut PgConnection,
) -> DatabaseResult<SpxPartition> {
    let query = "UPDATE spx_partitions SET updated=NOW(), deleted=NOW() WHERE id=$1 RETURNING row_to_json(spx_partitions.*)";
    let partition: SpxPartitionSnapshotPgJson = sqlx::query_as(query)
        .bind(pid)
        .fetch_one(txn)
        .await
        .map_err(|e| DatabaseError::new(query, e))?;

    partition
        .try_into()
        .map_err(|e| DatabaseError::new(query, e))
}

pub async fn final_delete(
    partition_id: SpxPartitionId,
    txn: &mut PgConnection,
) -> Result<SpxPartitionId, DatabaseError> {
    let query = "DELETE FROM spx_partitions WHERE id=$1::uuid RETURNING id";
    let partition: SpxPartitionId = sqlx::query_as(query)
        .bind(partition_id)
        .fetch_one(txn)
        .await
        .map_err(|e| DatabaseError::new(query, e))?;

    Ok(partition)
}
