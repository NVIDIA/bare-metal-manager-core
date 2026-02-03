/*
 * SPDX-FileCopyrightText: Copyright (c) 2021-2022 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
 * SPDX-License-Identifier: LicenseRef-NvidiaProprietary
 *
 * NVIDIA CORPORATION, its affiliates and licensors retain all intellectual
 * property and proprietary rights in and to this material, related
 * documentation and any modifications thereto. Any use, reproduction,
 * disclosure or distribution of this material and related documentation
 * without an express license agreement from NVIDIA CORPORATION or
 * its affiliates is strictly prohibited.
 */

use ::rpc::forge as rpc;
use carbide_uuid::nvlink::{NvLinkDomainId, NvLinkLogicalPartitionId, NvLinkPartitionId};
use chrono::prelude::*;
use serde::{Deserialize, Serialize};
use sqlx::postgres::PgRow;
use sqlx::{FromRow, PgConnection, Row};

use crate::{
    ColumnInfo, DatabaseError, DatabaseResult, FilterableQueryBuilder, ObjectColumnFilter,
};

#[derive(Copy, Clone)]
pub struct IdColumn;
impl ColumnInfo<'_> for IdColumn {
    type TableType = NvlPartition;
    type ColumnType = NvLinkPartitionId;

    fn column_name(&self) -> &'static str {
        "id"
    }
}

#[derive(Debug, Clone)]
pub struct NewNvlPartition {
    pub id: NvLinkPartitionId,
    pub name: NvlPartitionName,
    pub logical_partition_id: NvLinkLogicalPartitionId,
    pub domain_uuid: NvLinkDomainId,
    pub nmx_m_id: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct NvlPartitionStatus {
    pub partition: String,
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq, Hash, sqlx::Type, sqlx::FromRow)]
pub struct NvlPartitionName(String);

impl TryFrom<String> for NvlPartitionName {
    type Error = DatabaseError;
    fn try_from(value: String) -> Result<Self, Self::Error> {
        Ok(NvlPartitionName(value))
    }
}

impl From<NvlPartitionName> for String {
    fn from(value: NvlPartitionName) -> Self {
        value.0
    }
}
#[derive(Debug, Clone)]
pub struct NvlPartition {
    pub id: NvLinkPartitionId,
    pub nmx_m_id: String,
    pub domain_uuid: NvLinkDomainId,
    pub name: NvlPartitionName,
    pub created: DateTime<Utc>,
    pub updated: DateTime<Utc>,
    pub deleted: Option<DateTime<Utc>>,
    pub logical_partition_id: Option<NvLinkLogicalPartitionId>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct NvlPartitionSnapshotPgJson {
    id: NvLinkPartitionId,
    nmx_m_id: String,
    name: NvlPartitionName,
    domain_uuid: NvLinkDomainId,
    created: DateTime<Utc>,
    updated: DateTime<Utc>,
    deleted: Option<DateTime<Utc>>,

    logical_partition_id: Option<NvLinkLogicalPartitionId>,
}

impl TryFrom<NvlPartitionSnapshotPgJson> for NvlPartition {
    type Error = sqlx::Error;
    fn try_from(value: NvlPartitionSnapshotPgJson) -> sqlx::Result<Self> {
        Ok(Self {
            id: value.id,
            nmx_m_id: value.nmx_m_id,
            domain_uuid: value.domain_uuid,
            name: value.name,
            created: value.created,
            updated: value.updated,
            deleted: value.deleted,
            logical_partition_id: value.logical_partition_id,
        })
    }
}

impl<'r> FromRow<'r, PgRow> for NvlPartitionSnapshotPgJson {
    fn from_row(row: &'r PgRow) -> Result<Self, sqlx::Error> {
        let json: serde_json::value::Value = row.try_get(0)?;
        NvlPartitionSnapshotPgJson::deserialize(json).map_err(|err| sqlx::Error::Decode(err.into()))
    }
}

impl<'r> FromRow<'r, PgRow> for NvlPartition {
    fn from_row(row: &'r PgRow) -> Result<Self, sqlx::Error> {
        let json: serde_json::value::Value = row.try_get(0)?;
        NvlPartitionSnapshotPgJson::deserialize(json)
            .map_err(|err| sqlx::Error::Decode(err.into()))?
            .try_into()
    }
}

///
/// Marshal a Data Object (NvlPartition) into an RPC NvlPartition
///
impl TryFrom<NvlPartition> for rpc::NvLinkPartition {
    type Error = DatabaseError;
    fn try_from(src: NvlPartition) -> Result<Self, Self::Error> {
        Ok(rpc::NvLinkPartition {
            id: Some(src.id),
            name: src.name.clone().into(),
            nmx_m_id: src.nmx_m_id,
            domain_uuid: Some(src.domain_uuid),
            logical_partition_id: src.logical_partition_id,
        })
    }
}

impl NewNvlPartition {
    pub async fn create(&self, txn: &mut PgConnection) -> Result<NvlPartition, DatabaseError> {
        let query = "INSERT INTO nvlink_partitions (
                id,
                nmx_m_id,
                name,
                domain_uuid,
                logical_partition_id)
            VALUES ($1, $2, $3, $4, $5)
            RETURNING row_to_json(nvlink_partitions.*)";

        let partition: NvlPartitionSnapshotPgJson = sqlx::query_as(query)
            .bind(self.id)
            .bind(&self.nmx_m_id)
            .bind(&self.name.0)
            .bind(self.domain_uuid)
            .bind(self.logical_partition_id)
            .fetch_one(txn)
            .await
            .map_err(|e| DatabaseError::new(query, e))?;
        partition
            .try_into()
            .map_err(|e| DatabaseError::new(query, e))
    }
}

/// Retrieves the IDs of all NvLink partitions
///
/// * `txn` - A reference to a currently open database transaction
///
pub async fn for_tenant(
    txn: &mut PgConnection,
    tenant_organization_id: String,
) -> Result<Vec<NvlPartition>, DatabaseError> {
    let results: Vec<NvlPartition> = {
        let query = "SELECT * FROM nvlink_partitions WHERE config->>'tenant_organization_id' = $1";
        let partitions: Vec<NvlPartitionSnapshotPgJson> = sqlx::query_as(query)
            .bind(tenant_organization_id)
            .fetch_all(txn)
            .await
            .map_err(|e| DatabaseError::new(query, e))?;

        partitions
            .into_iter()
            .map(|p| p.try_into())
            .collect::<Result<Vec<NvlPartition>, sqlx::Error>>()
            .map_err(|e| DatabaseError::new(query, e))?
    };

    Ok(results)
}

pub async fn find_ids(
    txn: &mut PgConnection,
    filter: rpc::NvLinkPartitionSearchFilter,
) -> Result<Vec<NvLinkPartitionId>, DatabaseError> {
    // build query
    let mut builder = sqlx::QueryBuilder::new("SELECT id FROM nvlink_partitions");
    let tenant_org_id = &filter.tenant_organization_id;
    let name = &filter.name;

    if name.is_some() {
        builder.push(" WHERE config->>'name' = ");
        builder.push_bind(name);

        if tenant_org_id.is_some() {
            builder.push(" AND config->>'tenant_organization_id' = ");
            builder.push_bind(tenant_org_id);
        }
    } else if tenant_org_id.is_some() {
        builder.push(" WHERE config->>'tenant_organization_id' = ");
        builder.push_bind(tenant_org_id);
    }

    let query = builder.build_query_as();
    let ids: Vec<NvLinkPartitionId> = query
        .fetch_all(txn)
        .await
        .map_err(|e| DatabaseError::new("nvl_partition::find_ids", e))?;

    Ok(ids)
}

pub async fn find_by<'a, C: ColumnInfo<'a, TableType = NvlPartition>>(
    txn: &mut PgConnection,
    filter: ObjectColumnFilter<'a, C>,
) -> Result<Vec<NvlPartition>, DatabaseError> {
    let mut query = FilterableQueryBuilder::new(
        "SELECT row_to_json(p.*) FROM (SELECT * FROM nvlink_partitions) p",
    )
    .filter(&filter);
    let partitions: Vec<NvlPartitionSnapshotPgJson> =
        query
            .build_query_as()
            .fetch_all(txn)
            .await
            .map_err(|e| DatabaseError::new(query.sql(), e))?;

    partitions
        .into_iter()
        .map(|p| p.try_into())
        .collect::<Result<Vec<NvlPartition>, sqlx::Error>>()
        .map_err(|e| DatabaseError::new(query.sql(), e))
}

pub async fn mark_as_deleted(
    partition: &NvlPartition,
    txn: &mut PgConnection,
) -> DatabaseResult<NvlPartition> {
    let query = "UPDATE nvlink_partitions SET updated=NOW(), deleted=NOW() WHERE id=$1 RETURNING *";
    let partition: NvlPartitionSnapshotPgJson = sqlx::query_as(query)
        .bind(partition.id)
        .fetch_one(txn)
        .await
        .map_err(|e| DatabaseError::new(query, e))?;

    partition
        .try_into()
        .map_err(|e| DatabaseError::new(query, e))
}

/// Returns whether the NvLink partition was deleted
pub fn is_marked_as_deleted(partition: &NvlPartition) -> bool {
    partition.deleted.is_some()
}

pub async fn final_delete(
    partition_id: NvLinkPartitionId,
    txn: &mut PgConnection,
) -> Result<NvLinkPartitionId, DatabaseError> {
    let query = "DELETE FROM nvlink_partitions WHERE id=$1::uuid RETURNING id";
    let partition: NvLinkPartitionId = sqlx::query_as(query)
        .bind(partition_id)
        .fetch_one(txn)
        .await
        .map_err(|e| DatabaseError::new(query, e))?;

    Ok(partition)
}
