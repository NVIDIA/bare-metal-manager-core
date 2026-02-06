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

use ::rpc::forge as rpc;
use carbide_uuid::nvlink::NvLinkLogicalPartitionId;
use chrono::prelude::*;
use config_version::ConfigVersion;
use model::metadata::Metadata;
use model::tenant::TenantOrganizationId;
// use futures::StreamExt;
use serde::{Deserialize, Serialize};
use sqlx::postgres::PgRow;
use sqlx::{FromRow, PgConnection, Row};

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

#[derive(Debug, Clone)]
pub struct NewLogicalPartition {
    pub id: NvLinkLogicalPartitionId,
    pub config: LogicalPartitionConfig,
}

impl TryFrom<rpc::NvLinkLogicalPartitionCreationRequest> for NewLogicalPartition {
    type Error = DatabaseError;
    fn try_from(value: rpc::NvLinkLogicalPartitionCreationRequest) -> Result<Self, Self::Error> {
        let id: NvLinkLogicalPartitionId = value.id.unwrap_or_else(|| uuid::Uuid::new_v4().into());

        let conf = value.config.ok_or_else(|| {
            DatabaseError::InvalidArgument("NvLinkLogicalPartition config is empty".to_string())
        })?;

        Ok(NewLogicalPartition {
            id,
            config: LogicalPartitionConfig::try_from(conf)?,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Deserialize)]
pub struct LogicalPartitionConfig {
    pub metadata: Metadata,
    pub tenant_organization_id: TenantOrganizationId,
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
pub struct LogicalPartitionName(String);

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "lowercase")]
pub enum LogicalPartitionState {
    Provisioning,
    Ready,
    Updating,
    Error,
    Deleting,
}

#[derive(Debug, Clone)]
pub struct LogicalPartition {
    pub id: NvLinkLogicalPartitionId,

    pub name: String,
    pub description: String,
    pub tenant_organization_id: TenantOrganizationId,

    pub config_version: ConfigVersion,

    pub partition_state: LogicalPartitionState,

    pub created: DateTime<Utc>,
    pub updated: DateTime<Utc>,
    pub deleted: Option<DateTime<Utc>>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct LogicalPartitionSnapshotPgJson {
    id: NvLinkLogicalPartitionId,
    name: String,
    description: String,
    tenant_organization_id: TenantOrganizationId,
    config_version: ConfigVersion,
    partition_state: LogicalPartitionState,
    created: DateTime<Utc>,
    updated: DateTime<Utc>,
    deleted: Option<DateTime<Utc>>,
}

impl TryFrom<LogicalPartitionSnapshotPgJson> for LogicalPartition {
    type Error = sqlx::Error;
    fn try_from(value: LogicalPartitionSnapshotPgJson) -> sqlx::Result<Self> {
        Ok(Self {
            id: value.id,
            name: value.name,
            description: value.description,
            tenant_organization_id: value.tenant_organization_id,
            config_version: value.config_version,
            partition_state: value.partition_state,
            created: value.created,
            updated: value.updated,
            deleted: value.deleted,
        })
    }
}

impl<'r> FromRow<'r, PgRow> for LogicalPartitionSnapshotPgJson {
    fn from_row(row: &'r PgRow) -> Result<Self, sqlx::Error> {
        let json: serde_json::value::Value = row.try_get(0)?;
        LogicalPartitionSnapshotPgJson::deserialize(json)
            .map_err(|err| sqlx::Error::Decode(err.into()))
    }
}

/// Converts from Protobuf LogicalPartitionCreationRequest into LogicalPartition
///
/// Use try_from in order to return a Result where Result is an error if the conversion
/// from String -> UUID fails
///
impl TryFrom<rpc::NvLinkLogicalPartitionConfig> for LogicalPartitionConfig {
    type Error = DatabaseError;

    fn try_from(conf: rpc::NvLinkLogicalPartitionConfig) -> Result<Self, Self::Error> {
        if conf.tenant_organization_id.is_empty() {
            return Err(DatabaseError::InvalidArgument(
                "NvLinkLogicalPartition organization_id is empty".to_string(),
            ));
        }

        let tenant_organization_id =
            TenantOrganizationId::try_from(conf.tenant_organization_id.clone())
                .map_err(|_| DatabaseError::InvalidArgument(conf.tenant_organization_id))?;

        Ok(LogicalPartitionConfig {
            metadata: conf.metadata.unwrap_or_default().try_into()?,
            tenant_organization_id,
        })
    }
}

///
/// Marshal a Data Object (LogicalPartition) into an RPC LogicalPartition
///
impl TryFrom<LogicalPartition> for rpc::NvLinkLogicalPartition {
    type Error = DatabaseError;
    fn try_from(src: LogicalPartition) -> Result<Self, Self::Error> {
        let mut state = match &src.partition_state {
            LogicalPartitionState::Provisioning => rpc::TenantState::Provisioning,
            LogicalPartitionState::Ready => rpc::TenantState::Ready,
            LogicalPartitionState::Error => rpc::TenantState::Failed, // TODO include cause in rpc
            LogicalPartitionState::Deleting => rpc::TenantState::Terminating,
            LogicalPartitionState::Updating => rpc::TenantState::Updating,
        };

        // If deletion is requested, we immediately overwrite the state to terminating.
        // Even though the state controller hasn't caught up - it eventually will
        if is_marked_as_deleted(&src) {
            state = rpc::TenantState::Terminating;
        }
        let status = Some(rpc::NvLinkLogicalPartitionStatus {
            state: state as i32,
        });

        let config = rpc::NvLinkLogicalPartitionConfig {
            metadata: Some(rpc::Metadata {
                name: src.name,
                description: src.description,
                ..Default::default()
            }),
            tenant_organization_id: src.tenant_organization_id.to_string(),
        };

        Ok(rpc::NvLinkLogicalPartition {
            id: Some(src.id),
            config_version: src.config_version.version_string(),
            status,
            config: Some(config),
        })
    }
}

impl TryFrom<LogicalPartitionConfig> for rpc::NvLinkLogicalPartitionConfig {
    type Error = DatabaseError;
    fn try_from(src: LogicalPartitionConfig) -> Result<Self, Self::Error> {
        Ok(rpc::NvLinkLogicalPartitionConfig {
            metadata: Some(src.metadata.into()),
            tenant_organization_id: src.tenant_organization_id.to_string(),
        })
    }
}

impl NewLogicalPartition {
    pub async fn create(&self, txn: &mut PgConnection) -> Result<LogicalPartition, DatabaseError> {
        let state = LogicalPartitionState::Ready;
        let config = &self.config;
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
            .bind(self.id)
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
}

/// Retrieves the IDs of all NvLink partitions
///
/// * `txn` - A reference to a currently open database transaction
///
pub async fn for_tenant(
    txn: &mut PgConnection,
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
    txn: &mut PgConnection,
    filter: rpc::NvLinkLogicalPartitionSearchFilter,
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
    txn: &mut PgConnection,
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

/// Returns whether a logical partition was deleted by user
pub fn is_marked_as_deleted(partition: &LogicalPartition) -> bool {
    partition.deleted.is_some()
}

pub async fn update(
    partition: &LogicalPartition,
    name: String,
    txn: &mut PgConnection,
) -> Result<NvLinkLogicalPartitionId, DatabaseError> {
    let query = "UPDATE nvlink_logical_partitions SET name=$1, description=$2, updated=NOW() WHERE id=$3::uuid RETURNING id";

    let partition: NvLinkLogicalPartitionId = sqlx::query_as(query)
        .bind(name)
        .bind(&partition.description)
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
