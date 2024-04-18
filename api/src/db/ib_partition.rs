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

use std::collections::HashMap;
use std::env;

use ::rpc::forge as rpc;
use chrono::prelude::*;
use config_version::{ConfigVersion, Versioned};
use futures::StreamExt;
use serde::{Deserialize, Serialize};
use sqlx::postgres::PgRow;
use sqlx::{FromRow, Transaction};
use sqlx::{Postgres, Row};
use uuid::Uuid;

use super::machine::Machine;
use crate::ib::IBFabricManagerConfig;
use crate::model::controller_outcome::PersistentStateHandlerOutcome;
use crate::model::hardware_info::InfinibandInterface;
use crate::model::instance::config::{
    infiniband::InstanceInfinibandConfig, network::InterfaceFunctionId,
};
use crate::{
    db::{DatabaseError, UuidKeyedObjectFilter},
    model::ib_partition::{
        IBPartitionControllerState, IB_DEFAULT_MTU, IB_DEFAULT_RATE_LIMIT,
        IB_DEFAULT_SERVICE_LEVEL, IB_MTU_ENV, IB_RATE_LIMIT_ENV, IB_SERVICE_LEVEL_ENV,
    },
    model::tenant::TenantOrganizationId,
    CarbideError, CarbideResult,
};

#[derive(Debug, Clone, Copy, FromRow)]
pub struct IBPartitionId(uuid::Uuid);

impl From<IBPartitionId> for uuid::Uuid {
    fn from(id: IBPartitionId) -> Self {
        id.0
    }
}

impl From<rpc::IbPartitionSearchConfig> for IBPartitionSearchConfig {
    fn from(value: rpc::IbPartitionSearchConfig) -> Self {
        IBPartitionSearchConfig {
            include_history: value.include_history,
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct IBPartitionSearchConfig {
    pub include_history: bool,
}

#[derive(Debug, Clone)]
pub struct NewIBPartition {
    pub id: Uuid,

    pub config: IBPartitionConfig,
}

impl TryFrom<rpc::IbPartitionCreationRequest> for NewIBPartition {
    type Error = CarbideError;
    fn try_from(value: rpc::IbPartitionCreationRequest) -> Result<Self, Self::Error> {
        let conf = match value.config {
            Some(c) => c,
            None => {
                return Err(CarbideError::InvalidArgument(
                    "IBPartition configuration is empty".to_string(),
                ))
            }
        };

        let id = match value.id {
            Some(v) => uuid::Uuid::try_from(v)?,
            None => uuid::Uuid::new_v4(),
        };

        Ok(NewIBPartition {
            id,
            config: IBPartitionConfig::try_from(conf)?,
        })
    }
}

#[derive(Debug, Clone)]
pub struct IBPartitionConfig {
    pub name: String,
    pub pkey: Option<i16>,
    pub tenant_organization_id: TenantOrganizationId,
    pub mtu: i32,
    pub rate_limit: i32,
    pub service_level: i32,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct IBPartitionStatus {
    pub partition: String,
    pub mtu: i32,
    pub rate_limit: i32,
    pub service_level: i32,
}

#[derive(Debug, Clone)]
pub struct IBPartition {
    pub id: Uuid,
    pub version: ConfigVersion,

    pub config: IBPartitionConfig,
    pub status: Option<IBPartitionStatus>,

    pub created: DateTime<Utc>,
    pub updated: DateTime<Utc>,
    pub deleted: Option<DateTime<Utc>>,

    pub controller_state: Versioned<IBPartitionControllerState>,

    /// The result of the last attempt to change state
    pub controller_state_outcome: Option<PersistentStateHandlerOutcome>,
}

// We need to implement FromRow because we can't associate dependent tables with the default derive
// (i.e. it can't default unknown fields)
impl<'r> FromRow<'r, PgRow> for IBPartition {
    fn from_row(row: &'r PgRow) -> Result<Self, sqlx::Error> {
        let config_version_str: &str = row.try_get("config_version")?;
        let version = config_version_str
            .parse()
            .map_err(|e| sqlx::Error::Decode(Box::new(e)))?;

        let controller_state_version_str: &str = row.try_get("controller_state_version")?;
        let controller_state_version = controller_state_version_str
            .parse()
            .map_err(|e| sqlx::Error::Decode(Box::new(e)))?;
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

        Ok(IBPartition {
            id: row.try_get("id")?,
            version,
            config: IBPartitionConfig {
                name: row.try_get("name")?,
                pkey: Some(row.try_get("pkey")?),
                tenant_organization_id,
                mtu: row.try_get("mtu")?,
                rate_limit: row.try_get("rate_limit")?,
                service_level: row.try_get("service_level")?,
            },
            status,

            created: row.try_get("created")?,
            updated: row.try_get("updated")?,
            deleted: row.try_get("deleted")?,

            controller_state: Versioned::new(controller_state.0, controller_state_version),
            controller_state_outcome: state_outcome.map(|x| x.0),
        })
    }
}

/// Converts from Protobuf IBPartitionCreationRequest into IBPartition
///
/// Use try_from in order to return a Result where Result is an error if the conversion
/// from String -> UUID fails
///
impl TryFrom<rpc::IbPartitionConfig> for IBPartitionConfig {
    type Error = CarbideError;

    fn try_from(conf: rpc::IbPartitionConfig) -> Result<Self, Self::Error> {
        if conf.tenant_organization_id.is_empty() {
            return Err(CarbideError::InvalidArgument(
                "IBPartition organization_id is empty".to_string(),
            ));
        }

        let tenant_organization_id =
            TenantOrganizationId::try_from(conf.tenant_organization_id.clone())
                .map_err(|_| CarbideError::InvalidArgument(conf.tenant_organization_id))?;

        Ok(IBPartitionConfig {
            name: conf.name,
            pkey: None,
            tenant_organization_id,
            mtu: get_env(IB_MTU_ENV, IB_DEFAULT_MTU),
            rate_limit: get_env(IB_RATE_LIMIT_ENV, IB_DEFAULT_RATE_LIMIT),
            service_level: get_env(IB_SERVICE_LEVEL_ENV, IB_DEFAULT_SERVICE_LEVEL),
        })
    }
}

fn get_env<T: std::str::FromStr>(name: &str, default: T) -> T {
    match env::var(name) {
        Ok(v) => v.parse::<T>().unwrap_or(default),
        Err(_) => default,
    }
}

///
/// Marshal a Data Object (IBPartition) into an RPC IBPartition
///
impl TryFrom<IBPartition> for rpc::IbPartition {
    type Error = CarbideError;
    fn try_from(src: IBPartition) -> Result<Self, Self::Error> {
        let config = Some(rpc::IbPartitionConfig {
            name: src.config.name.clone(),
            tenant_organization_id: src.config.tenant_organization_id.clone().to_string(),
        });

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

        let (partition, rate_limit, mtu, service_level) = match src.status {
            Some(s) => (
                Some(s.partition),
                Some(s.rate_limit),
                Some(s.mtu),
                Some(s.service_level),
            ),
            None => (None, None, None, None),
        };

        let status = Some(rpc::IbPartitionStatus {
            state: state as i32,
            state_reason: src.controller_state_outcome.map(|r| r.into()),
            enable_sharp: Some(false),
            partition,
            pkey: src.config.pkey.map(|k| k.to_string()),
            rate_limit,
            mtu,
            service_level,
        });

        Ok(rpc::IbPartition {
            id: Some(src.id.into()),
            config_version: src.version.version_string(),
            config,
            status,
        })
    }
}

impl NewIBPartition {
    pub async fn create(
        &self,
        txn: &mut sqlx::Transaction<'_, Postgres>,
        ib_fabric_config: &IBFabricManagerConfig,
    ) -> Result<IBPartition, DatabaseError> {
        let version = ConfigVersion::initial();
        let version_string = version.version_string();
        let state = IBPartitionControllerState::Provisioning;
        let conf = &self.config;

        let query = "INSERT INTO ib_partitions (
                id,
                name,
                pkey,
                organization_id,
                mtu,
                rate_limit,
                service_level,
                config_version,
                controller_state_version,
                controller_state)
            SELECT $1, $2, $3, $4, $5, $6, $7, $8, $9, $10
            WHERE (SELECT COUNT(*) FROM ib_partitions WHERE organization_id = $4) < $11
            RETURNING *";
        let segment: IBPartition = sqlx::query_as(query)
            .bind(self.id)
            .bind(&conf.name)
            .bind(conf.pkey)
            .bind(&conf.tenant_organization_id.to_string())
            .bind(conf.mtu)
            .bind(conf.rate_limit)
            .bind(conf.service_level)
            .bind(&version_string)
            .bind(&version_string)
            .bind(sqlx::types::Json(state))
            .bind(ib_fabric_config.max_partition_per_tenant)
            .fetch_one(&mut **txn)
            .await
            .map_err(|e| DatabaseError::new(file!(), line!(), query, e))?;

        Ok(segment)
    }
}

impl IBPartition {
    pub fn id(&self) -> &uuid::Uuid {
        &self.id
    }

    /// Retrieves the IDs of all IB partition
    ///
    /// * `txn` - A reference to a currently open database transaction
    ///
    pub async fn list_segment_ids(
        txn: &mut Transaction<'_, Postgres>,
    ) -> Result<Vec<Uuid>, DatabaseError> {
        let query = "SELECT id FROM ib_partitions";
        let mut results = Vec::new();
        let mut segment_id_stream = sqlx::query_as::<_, IBPartitionId>(query).fetch(&mut **txn);
        while let Some(maybe_id) = segment_id_stream.next().await {
            let id = maybe_id.map_err(|e| DatabaseError::new(file!(), line!(), query, e))?;
            results.push(id.into());
        }

        Ok(results)
    }

    pub async fn for_tenant(
        txn: &mut sqlx::Transaction<'_, Postgres>,
        tenant_organization_id: String,
    ) -> Result<Vec<Self>, DatabaseError> {
        let results: Vec<IBPartition> = {
            let query = "SELECT * FROM ib_partitions WHERE organization_id=$1";
            sqlx::query_as(query)
                .bind(tenant_organization_id)
                .fetch_all(&mut **txn)
                .await
                .map_err(|e| DatabaseError::new(file!(), line!(), query, e))?
        };

        Ok(results)
    }

    pub async fn find(
        txn: &mut sqlx::Transaction<'_, Postgres>,
        filter: UuidKeyedObjectFilter<'_>,
        _search_config: IBPartitionSearchConfig,
    ) -> Result<Vec<Self>, DatabaseError> {
        let base_query = "SELECT * FROM ib_partitions {where}".to_owned();

        let all_records: Vec<IBPartition> = match filter {
            UuidKeyedObjectFilter::All => {
                sqlx::query_as::<_, IBPartition>(&base_query.replace("{where}", ""))
                    .fetch_all(&mut **txn)
                    .await
                    .map_err(|e| DatabaseError::new(file!(), line!(), "ib_partitions All", e))?
            }

            UuidKeyedObjectFilter::List(uuids) => sqlx::query_as::<_, IBPartition>(
                &base_query.replace("{where}", "WHERE ib_partitions.id=ANY($1)"),
            )
            .bind(uuids)
            .fetch_all(&mut **txn)
            .await
            .map_err(|e| DatabaseError::new(file!(), line!(), "ib_partitions List", e))?,

            UuidKeyedObjectFilter::One(uuid) => sqlx::query_as::<_, IBPartition>(
                &base_query.replace("{where}", "WHERE ib_partitions.id=$1"),
            )
            .bind(uuid)
            .fetch_all(&mut **txn)
            .await
            .map_err(|e| DatabaseError::new(file!(), line!(), "ib_partitions One", e))?,
        };

        Ok(all_records)
    }

    pub async fn find_pkey_by_partition_id(
        txn: &mut sqlx::Transaction<'_, Postgres>,
        id: Uuid,
    ) -> Result<Option<i16>, DatabaseError> {
        #[derive(Debug, Clone, Copy, FromRow)]
        pub struct Pkey(i16);

        let query = "SELECT pkey FROM ib_partitions WHERE id = $1";

        let pkey = sqlx::query_as::<_, Pkey>(query)
            .bind(id)
            .fetch_optional(&mut **txn)
            .await
            .map_err(|e| DatabaseError::new(file!(), line!(), query, e))?;

        Ok(pkey.map(|id| id.0))
    }

    /// Updates the IB partition state that is owned by the state controller
    /// under the premise that the curren controller state version didn't change.
    pub async fn try_update_controller_state(
        txn: &mut Transaction<'_, Postgres>,
        partition_id: uuid::Uuid,
        expected_version: ConfigVersion,
        new_state: &IBPartitionControllerState,
    ) -> Result<bool, DatabaseError> {
        let expected_version_str = expected_version.version_string();
        let next_version = expected_version.increment();
        let next_version_str = next_version.version_string();

        let query = "UPDATE ib_partitions SET controller_state_version=$1, controller_state=$2::json where id=$3::uuid AND controller_state_version=$4 returning id";
        let query_result: Result<IBPartitionId, _> = sqlx::query_as(query)
            .bind(&next_version_str)
            .bind(sqlx::types::Json(new_state))
            .bind(partition_id)
            .bind(&expected_version_str)
            .fetch_one(&mut **txn)
            .await;

        match query_result {
            Ok(_partition_id) => Ok(true), // TODO(k82cn): Add state history if necessary.
            Err(sqlx::Error::RowNotFound) => Ok(false),
            Err(e) => Err(DatabaseError::new(file!(), line!(), query, e)),
        }
    }

    pub async fn update_controller_state_outcome(
        txn: &mut sqlx::Transaction<'_, Postgres>,
        partition_id: uuid::Uuid,
        outcome: PersistentStateHandlerOutcome,
    ) -> Result<(), DatabaseError> {
        let query = "UPDATE ib_partitions SET controller_state_outcome=$1::json WHERE id=$2::uuid";
        sqlx::query(query)
            .bind(sqlx::types::Json(outcome))
            .bind(partition_id.to_string())
            .execute(&mut **txn)
            .await
            .map_err(|e| DatabaseError::new(file!(), line!(), query, e))?;
        Ok(())
    }

    pub async fn mark_as_deleted(
        &self,
        txn: &mut Transaction<'_, Postgres>,
    ) -> CarbideResult<IBPartition> {
        let query = "UPDATE ib_partitions SET updated=NOW(), deleted=NOW() WHERE id=$1 RETURNING *";
        let segment: IBPartition = sqlx::query_as(query)
            .bind(self.id)
            .fetch_one(&mut **txn)
            .await
            .map_err(|e| CarbideError::from(DatabaseError::new(file!(), line!(), query, e)))?;

        Ok(segment)
    }

    /// Returns whether the IB partition was deleted by the user
    pub fn is_marked_as_deleted(&self) -> bool {
        self.deleted.is_some()
    }

    pub async fn final_delete(
        segment_id: uuid::Uuid,
        txn: &mut Transaction<'_, Postgres>,
    ) -> Result<uuid::Uuid, DatabaseError> {
        let query = "DELETE FROM ib_partitions WHERE id=$1::uuid RETURNING id";
        let segment: IBPartitionId = sqlx::query_as(query)
            .bind(segment_id)
            .fetch_one(&mut **txn)
            .await
            .map_err(|e| DatabaseError::new(file!(), line!(), query, e))?;

        Ok(segment.0)
    }

    pub async fn update(
        &self,
        txn: &mut Transaction<'_, Postgres>,
    ) -> Result<IBPartition, DatabaseError> {
        let query = "UPDATE ib_partitions SET name=$1, organization_id=$2, status=$3::json, updated=NOW() WHERE id=$4::uuid RETURNING *";

        let segment: IBPartition = sqlx::query_as(query)
            .bind(&self.config.name)
            .bind(&self.config.tenant_organization_id.to_string())
            .bind(sqlx::types::Json(&self.status))
            .bind(self.id)
            .fetch_one(&mut **txn)
            .await
            .map_err(|e| DatabaseError::new(file!(), line!(), query, e))?;

        Ok(segment)
    }

    /// The result of the most recent state controller iteration, if any
    pub fn current_state_iteration_outcome(&self) -> Option<PersistentStateHandlerOutcome> {
        self.controller_state_outcome.clone()
    }
}

pub async fn allocate_port_guid(
    _txn: &mut Transaction<'_, Postgres>,
    _instance_id: uuid::Uuid,
    ib_config: &Versioned<InstanceInfinibandConfig>,
    machine: &Machine,
) -> CarbideResult<Versioned<InstanceInfinibandConfig>> {
    let mut ib_config = ib_config.clone();

    let ib_hw_info = &machine
        .hardware_info()
        .ok_or(CarbideError::MissingArgument("no hardware info"))?
        .infiniband_interfaces;

    // the key of ib_hw_map is device name such as "MT28908 Family [ConnectX-6]".
    // the value of ib_hw_map is a sorted vector of InfinibandInterface by slot.
    let ib_hw_map = sort_ib_by_slot(ib_hw_info);
    for request in &mut ib_config.value.ib_interfaces {
        tracing::debug!(
            "reqest IB device:{}, device_instance:{}",
            request.device.clone(),
            request.device_instance
        );

        // TOTO: will support VF in the future. Currently, it will return err when the function_id is not PF.
        if let InterfaceFunctionId::Virtual { .. } = request.function_id {
            return Err(CarbideError::InvalidArgument(format!(
                "Not support VF {}",
                request.device
            )));
        }

        if let Some(sorted_ibs) = ib_hw_map.get(&request.device) {
            if let Some(ib) = sorted_ibs.get(request.device_instance as usize) {
                request.pf_guid = Some(ib.guid.clone());
                request.guid = Some(ib.guid.clone());
                tracing::debug!("select IB device GUID {}", ib.guid.clone());
            } else {
                return Err(CarbideError::InvalidArgument(format!(
                    "not enough ib device {}",
                    request.device
                )));
            }
        } else {
            return Err(CarbideError::InvalidArgument(format!(
                "no ib device {}",
                request.device
            )));
        }
    }

    Ok(ib_config)
}

/// sort ib device by slot and add devices with the same name are added to hashmap
fn sort_ib_by_slot(
    ib_hw_info_vec: &[InfinibandInterface],
) -> HashMap<String, Vec<InfinibandInterface>> {
    let mut ib_hw_map = HashMap::new();
    let mut sorted_ib_hw_info_vec = ib_hw_info_vec.to_owned();
    sorted_ib_hw_info_vec.sort_by_key(|x| match &x.pci_properties {
        Some(pci_properties) => pci_properties.slot.clone().unwrap_or_default(),
        None => "".to_owned(),
    });

    for ib in sorted_ib_hw_info_vec {
        if let Some(ref pci_properties) = ib.pci_properties {
            // description in pci_properties are the value of ID_MODEL_FROM_DATABASE, such as "MT28908 Family [ConnectX-6]"
            if let Some(device) = &pci_properties.description {
                let entry: &mut Vec<InfinibandInterface> =
                    ib_hw_map.entry(device.clone()).or_default();
                entry.push(ib);
            }
        }
    }

    ib_hw_map
}
