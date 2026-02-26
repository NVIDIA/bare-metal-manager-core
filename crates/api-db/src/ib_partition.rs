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

use std::collections::HashMap;

use ::rpc::forge as rpc;
use carbide_uuid::infiniband::IBPartitionId;
use chrono::prelude::*;
use config_version::{ConfigVersion, Versioned};
use futures::StreamExt;
use model::controller_outcome::PersistentStateHandlerOutcome;
use model::ib::{IBMtu, IBNetwork, IBQosConf, IBRateLimit, IBServiceLevel};
use model::ib_partition::{IBPartitionControllerState, PartitionKey, state_sla};
use model::metadata::Metadata;
use model::tenant::TenantOrganizationId;
use serde::{Deserialize, Serialize};
use sqlx::postgres::PgRow;
use sqlx::{FromRow, PgConnection, Row};

use crate::db_read::DbReader;
use crate::{
    ColumnInfo, DatabaseError, DatabaseResult, FilterableQueryBuilder, ObjectColumnFilter,
};

#[derive(Copy, Clone)]
pub struct IdColumn;
impl ColumnInfo<'_> for IdColumn {
    type TableType = IBPartition;
    type ColumnType = IBPartitionId;

    fn column_name(&self) -> &'static str {
        "id"
    }
}

#[derive(Debug, Clone)]
pub struct NewIBPartition {
    pub id: IBPartitionId,

    pub config: IBPartitionConfig,
    pub metadata: Metadata,
}

impl TryFrom<rpc::IbPartitionCreationRequest> for NewIBPartition {
    type Error = DatabaseError;
    fn try_from(value: rpc::IbPartitionCreationRequest) -> Result<Self, Self::Error> {
        let conf = match value.config {
            Some(c) => c,
            None => {
                return Err(DatabaseError::InvalidArgument(
                    "IBPartition configuration is empty".to_string(),
                ));
            }
        };

        let id = value.id.unwrap_or(uuid::Uuid::new_v4().into());
        let name = conf.name.clone();

        Ok(NewIBPartition {
            id,
            config: IBPartitionConfig::try_from(conf)?,
            metadata: match value.metadata {
                Some(m) => Metadata::try_from(m)?,
                // Deprecated field handling
                None => Metadata {
                    name,
                    ..Default::default()
                },
            },
        })
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct IBPartitionConfig {
    pub name: String,
    pub pkey: Option<PartitionKey>,
    pub tenant_organization_id: TenantOrganizationId,
    pub mtu: Option<IBMtu>,
    pub rate_limit: Option<IBRateLimit>,
    pub service_level: Option<IBServiceLevel>,
}

impl From<IBPartitionConfig> for rpc::IbPartitionConfig {
    fn from(conf: IBPartitionConfig) -> Self {
        rpc::IbPartitionConfig {
            name: conf.name, // Deprecated field
            tenant_organization_id: conf.tenant_organization_id.to_string(),
            pkey: conf.pkey.map(|k| k.to_string()),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct IBPartitionStatus {
    pub partition: Option<String>,
    pub mtu: Option<IBMtu>,
    pub rate_limit: Option<IBRateLimit>,
    pub service_level: Option<IBServiceLevel>,
    pub pkey: Option<PartitionKey>,
}

#[derive(Debug, Clone)]
pub struct IBPartition {
    pub id: IBPartitionId,
    pub version: ConfigVersion,

    pub config: IBPartitionConfig,
    pub status: Option<IBPartitionStatus>,

    pub deleted: Option<DateTime<Utc>>,

    pub controller_state: Versioned<IBPartitionControllerState>,

    /// The result of the last attempt to change state
    pub controller_state_outcome: Option<PersistentStateHandlerOutcome>,
    // Columns for these exist, but are unused in rust code
    // pub created: DateTime<Utc>,
    // pub updated: DateTime<Utc>,
    pub metadata: Metadata,
}

impl From<&IBPartition> for IBNetwork {
    fn from(ib: &IBPartition) -> IBNetwork {
        Self {
            name: ib.metadata.name.clone(),
            // We have to pull from status.pkey here because
            // config.pkey can be None simply because the user
            // chose to allow auto-allocation.  Previously,
            // the auto-allocated value _is_ what was being used
            // here.
            pkey: ib
                .status
                .as_ref()
                .and_then(|s| s.pkey)
                .map(u16::from)
                .unwrap_or(0u16),
            ipoib: true,
            associated_guids: None, // Not stored in the DB
            membership: None,       // Not stored in the DB
            qos_conf: Some(IBQosConf {
                mtu: ib.config.mtu.clone().unwrap_or_default(),
                rate_limit: ib.config.rate_limit.clone().unwrap_or_default(),
                service_level: ib.config.service_level.clone().unwrap_or_default(),
            }),
            // Not implemented yet
            // enable_sharp: false,
            // index0: IBNETWORK_DEFAULT_INDEX0,
        }
    }
}

// We need to implement FromRow because we can't associate dependent tables with the default derive
// (i.e. it can't default unknown fields)
impl<'r> FromRow<'r, PgRow> for IBPartition {
    fn from_row(row: &'r PgRow) -> Result<Self, sqlx::Error> {
        let controller_state: sqlx::types::Json<IBPartitionControllerState> =
            row.try_get("controller_state")?;
        let state_outcome: Option<sqlx::types::Json<PersistentStateHandlerOutcome>> =
            row.try_get("controller_state_outcome")?;

        let status: Option<sqlx::types::Json<IBPartitionStatus>> = row.try_get("status")?;
        let status = status.map(|s| s.0);

        let tenant_organization_id_str: &str = row.try_get("organization_id")?;
        let tenant_organization_id =
            TenantOrganizationId::try_from(tenant_organization_id_str.to_string())
                .map_err(|e| sqlx::Error::Decode(Box::new(e)))?;

        let pkey: Option<i32> = row.try_get("pkey")?;
        let mtu: i32 = row.try_get("mtu")?;
        let rate_limit: i32 = row.try_get("rate_limit")?;
        let service_level: i32 = row.try_get("service_level")?;
        let labels: sqlx::types::Json<HashMap<String, String>> = row.try_get("labels")?;
        let description: String = row.try_get("description")?;
        let name: String = row.try_get("name")?;

        Ok(IBPartition {
            id: row.try_get("id")?,
            version: row.try_get("config_version")?,
            config: IBPartitionConfig {
                name: name.clone(), // Derprecated field
                pkey: pkey
                    .map(|p| PartitionKey::try_from(p as u16))
                    .transpose()
                    .map_err(|_| {
                        let err = eyre::eyre!("Pkey {} is not valid", pkey.unwrap_or_default());
                        sqlx::Error::Decode(err.into())
                    })?,
                tenant_organization_id,
                mtu: IBMtu::try_from(mtu).ok(),
                rate_limit: IBRateLimit::try_from(rate_limit).ok(),
                service_level: IBServiceLevel::try_from(service_level).ok(),
            },
            status,
            metadata: Metadata {
                name,
                labels: labels.0,
                description,
            },
            deleted: row.try_get("deleted")?,

            controller_state: Versioned::new(
                controller_state.0,
                row.try_get("controller_state_version")?,
            ),
            controller_state_outcome: state_outcome.map(|x| x.0),
            // Columns for these exist, but are unused in rust code
            // created: row.try_get("created")?,
            // updated: row.try_get("updated")?,
        })
    }
}

/// Converts from Protobuf IBPartitionCreationRequest into IBPartition
///
/// Use try_from in order to return a Result where Result is an error if the conversion
/// from String -> UUID fails
///
impl TryFrom<rpc::IbPartitionConfig> for IBPartitionConfig {
    type Error = DatabaseError;

    fn try_from(conf: rpc::IbPartitionConfig) -> Result<Self, Self::Error> {
        if conf.tenant_organization_id.is_empty() {
            return Err(DatabaseError::InvalidArgument(
                "IBPartition organization_id is empty".to_string(),
            ));
        }

        let tenant_organization_id =
            TenantOrganizationId::try_from(conf.tenant_organization_id.clone())
                .map_err(|_| DatabaseError::InvalidArgument(conf.tenant_organization_id))?;

        Ok(IBPartitionConfig {
            name: conf.name,
            pkey: None,
            tenant_organization_id,
            mtu: None,
            rate_limit: None,
            service_level: None,
        })
    }
}

///
/// Marshal a Data Object (IBPartition) into an RPC IBPartition
///
impl TryFrom<IBPartition> for rpc::IbPartition {
    type Error = DatabaseError;
    fn try_from(src: IBPartition) -> Result<Self, Self::Error> {
        let mut state = match &src.controller_state.value {
            IBPartitionControllerState::Provisioning => rpc::TenantState::Provisioning,
            IBPartitionControllerState::Ready => rpc::TenantState::Ready,
            IBPartitionControllerState::Error { cause: _cause } => rpc::TenantState::Failed, // TODO include cause in rpc
            IBPartitionControllerState::Deleting => rpc::TenantState::Terminating,
        };

        // If deletion is requested, we immediately overwrite the state to terminating.
        // Even though the state controller hasn't caught up - it eventually will
        if src.is_marked_as_deleted() {
            state = rpc::TenantState::Terminating;
        }

        let pkey = src
            .status
            .as_ref()
            .and_then(|s| s.pkey.map(|k| k.to_string()));

        let (partition, rate_limit, mtu, service_level) = match src.status {
            Some(s) => (
                s.partition,
                s.rate_limit.map(IBRateLimit::into),
                s.mtu.map(IBMtu::into),
                s.service_level.map(IBServiceLevel::into),
            ),
            None => (None, None, None, None),
        };

        let status = Some(rpc::IbPartitionStatus {
            state: state as i32,
            state_reason: src.controller_state_outcome.map(|r| r.into()),
            state_sla: Some(
                state_sla(&src.controller_state.value, &src.controller_state.version).into(),
            ),
            enable_sharp: Some(false),
            partition,
            pkey,
            rate_limit,
            mtu,
            service_level,
        });

        let meatadata = src.metadata.into();

        Ok(rpc::IbPartition {
            id: Some(src.id),
            config_version: src.version.version_string(),
            config: Some(src.config.into()),
            status,
            metadata: Some(meatadata),
        })
    }
}

pub async fn create(
    value: NewIBPartition,
    txn: &mut PgConnection,
    max_partition_per_tenant: i32,
    status: IBPartitionStatus,
) -> Result<IBPartition, DatabaseError> {
    value.metadata.validate(true).map_err(|e| {
        DatabaseError::InvalidArgument(format!("Invalid metadata for IBPartition: {}", e))
    })?;

    let version = ConfigVersion::initial();
    let state = IBPartitionControllerState::Provisioning;
    let conf = &value.config;

    let query = "INSERT INTO ib_partitions (
                id,
                name,
                labels,
                description,
                pkey,
                organization_id,
                mtu,
                rate_limit,
                service_level,
                config_version,
                controller_state_version,
                controller_state,
                status)
            SELECT $1, $2, $3::json, $4, $5, $6, $7, $8, $9, $10, $11, $12, $14
            WHERE (SELECT COUNT(*) FROM ib_partitions WHERE organization_id = $6) < $13
            RETURNING *";
    let segment: IBPartition = sqlx::query_as(query)
        .bind(value.id)
        .bind(&value.metadata.name)
        .bind(sqlx::types::Json(&value.metadata.labels))
        .bind(&value.metadata.description)
        .bind(status.pkey.map(|k| u16::from(k) as i32))
        .bind(conf.tenant_organization_id.to_string())
        .bind::<i32>(conf.mtu.clone().unwrap_or_default().into())
        .bind::<i32>(conf.rate_limit.clone().unwrap_or_default().into())
        .bind::<i32>(conf.service_level.clone().unwrap_or_default().into())
        .bind(version)
        .bind(version)
        .bind(sqlx::types::Json(state))
        .bind(max_partition_per_tenant)
        .bind(sqlx::types::Json(&status))
        .fetch_one(txn)
        .await
        .map_err(|e| DatabaseError::query(query, e))?;

    Ok(segment)
}

/// Retrieves the IDs of all IB partition
///
/// * `txn` - A reference to a currently open database transaction
///
pub async fn list_segment_ids(txn: &mut PgConnection) -> Result<Vec<IBPartitionId>, DatabaseError> {
    let query = "SELECT id FROM ib_partitions";
    let mut results = Vec::new();
    let mut segment_id_stream = sqlx::query_as(query).fetch(txn);
    while let Some(maybe_id) = segment_id_stream.next().await {
        let id = maybe_id.map_err(|e| DatabaseError::query(query, e))?;
        results.push(id);
    }

    Ok(results)
}

pub async fn for_tenant(
    txn: impl DbReader<'_>,
    tenant_organization_id: String,
) -> Result<Vec<IBPartition>, DatabaseError> {
    let results: Vec<IBPartition> = {
        let query = "SELECT * FROM ib_partitions WHERE organization_id=$1";
        sqlx::query_as(query)
            .bind(tenant_organization_id)
            .fetch_all(txn)
            .await
            .map_err(|e| DatabaseError::query(query, e))?
    };

    Ok(results)
}

pub async fn find_ids(
    txn: impl DbReader<'_>,
    filter: rpc::IbPartitionSearchFilter,
) -> Result<Vec<IBPartitionId>, DatabaseError> {
    // build query
    let mut builder = sqlx::QueryBuilder::new("SELECT id FROM ib_partitions");
    let mut has_filter = false;
    if let Some(tenant_org_id) = &filter.tenant_org_id {
        builder.push(" WHERE organization_id = ");
        builder.push_bind(tenant_org_id);
        has_filter = true;
    }
    if let Some(name) = &filter.name {
        if has_filter {
            builder.push(" AND name = ");
        } else {
            builder.push(" WHERE name = ");
        }
        builder.push_bind(name);
    }

    let query = builder.build_query_as();
    let ids: Vec<IBPartitionId> = query
        .fetch_all(txn)
        .await
        .map_err(|e| DatabaseError::new("ib_partition::find_ids", e))?;

    Ok(ids)
}

pub async fn find_by<'a, C: ColumnInfo<'a, TableType = IBPartition>>(
    txn: impl DbReader<'_>,
    filter: ObjectColumnFilter<'a, C>,
) -> Result<Vec<IBPartition>, DatabaseError> {
    let mut query = FilterableQueryBuilder::new("SELECT * FROM ib_partitions").filter(&filter);

    query
        .build_query_as()
        .fetch_all(txn)
        .await
        .map_err(|e| DatabaseError::query(query.sql(), e))
}

pub async fn find_pkey_by_partition_id(
    txn: &mut PgConnection,
    id: IBPartitionId,
) -> Result<Option<u16>, DatabaseError> {
    #[derive(Debug, Clone, FromRow)]
    pub struct Pkey(String);

    let mut query = FilterableQueryBuilder::new("SELECT status->>'pkey' FROM ib_partitions")
        .filter(&ObjectColumnFilter::One(IdColumn, &id));
    let pkey = query
        .build_query_as::<Pkey>()
        .fetch_optional(txn)
        .await
        .map_err(|e| DatabaseError::query(query.sql(), e))?;

    pkey.map(|id| u16::from_str_radix(id.0.trim_start_matches("0x"), 16))
        .transpose()
        .map_err(|e| DatabaseError::Internal {
            message: e.to_string(),
        })
}

/// Updates the IB partition state that is owned by the state controller
/// under the premise that the curren controller state version didn't change.
pub async fn try_update_controller_state(
    txn: &mut PgConnection,
    partition_id: IBPartitionId,
    expected_version: ConfigVersion,
    new_state: &IBPartitionControllerState,
) -> Result<bool, DatabaseError> {
    let next_version = expected_version.increment();

    let query = "UPDATE ib_partitions SET controller_state_version=$1, controller_state=$2::json where id=$3::uuid AND controller_state_version=$4 returning id";
    let query_result = sqlx::query_as::<_, IBPartitionId>(query)
        .bind(next_version)
        .bind(sqlx::types::Json(new_state))
        .bind(partition_id)
        .bind(expected_version)
        .fetch_one(txn)
        .await;

    match query_result {
        Ok(_partition_id) => Ok(true), // TODO(k82cn): Add state history if necessary.
        Err(sqlx::Error::RowNotFound) => Ok(false),
        Err(e) => Err(DatabaseError::query(query, e)),
    }
}

pub async fn update_controller_state_outcome(
    txn: &mut PgConnection,
    partition_id: IBPartitionId,
    outcome: PersistentStateHandlerOutcome,
) -> Result<(), DatabaseError> {
    let query = "UPDATE ib_partitions SET controller_state_outcome=$1::json WHERE id=$2::uuid";
    sqlx::query(query)
        .bind(sqlx::types::Json(outcome))
        .bind(partition_id)
        .execute(txn)
        .await
        .map_err(|e| DatabaseError::query(query, e))?;
    Ok(())
}

pub async fn mark_as_deleted(
    value: &IBPartition,
    txn: &mut PgConnection,
) -> DatabaseResult<IBPartition> {
    let query = "UPDATE ib_partitions SET updated=NOW(), deleted=NOW() WHERE id=$1 RETURNING *";
    let segment: IBPartition = sqlx::query_as(query)
        .bind(value.id)
        .fetch_one(txn)
        .await
        .map_err(|e| DatabaseError::query(query, e))?;

    Ok(segment)
}

impl IBPartition {
    /// Returns whether the IB partition was deleted by the user
    pub fn is_marked_as_deleted(&self) -> bool {
        self.deleted.is_some()
    }
}

pub async fn final_delete(
    partition_id: IBPartitionId,
    txn: &mut PgConnection,
) -> Result<IBPartitionId, DatabaseError> {
    let query = "DELETE FROM ib_partitions WHERE id=$1::uuid RETURNING id";
    let partition: IBPartitionId = sqlx::query_as(query)
        .bind(partition_id)
        .fetch_one(txn)
        .await
        .map_err(|e| DatabaseError::query(query, e))?;

    Ok(partition)
}

/// Counts the number of instances that reference a given IB partition in their ib_config.
pub async fn count_instances_referencing_partition(
    txn: impl DbReader<'_>,
    partition_id: IBPartitionId,
) -> Result<i64, DatabaseError> {
    let query = "
        SELECT count(*) FROM instances
        WHERE (ib_config -> 'ib_interfaces')
              @> jsonb_build_array(jsonb_build_object('ib_partition_id', $1::text))
    ";
    let (count,): (i64,) = sqlx::query_as(query)
        .bind(partition_id.to_string())
        .fetch_one(txn)
        .await
        .map_err(|e| DatabaseError::query(query, e))?;

    Ok(count)
}

pub async fn update(
    value: &IBPartition,
    txn: &mut PgConnection,
) -> Result<IBPartition, DatabaseError> {
    value.metadata.validate(true).map_err(|e| {
        DatabaseError::InvalidArgument(format!("Invalid metadata for IBPartition: {}", e))
    })?;

    let query = "UPDATE ib_partitions SET name=$1, labels=$2::json, description=$3, organization_id=$4, status=$5::json, updated=NOW()
                       WHERE id=$6::uuid RETURNING *";

    let segment: IBPartition = sqlx::query_as(query)
        .bind(&value.metadata.name)
        .bind(sqlx::types::Json(&value.metadata.labels))
        .bind(&value.metadata.description)
        .bind(value.config.tenant_organization_id.to_string())
        .bind(sqlx::types::Json(&value.status))
        .bind(value.id)
        .fetch_one(txn)
        .await
        .map_err(|e| DatabaseError::query(query, e))?;

    Ok(segment)
}
