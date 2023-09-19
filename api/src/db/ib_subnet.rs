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

use std::env;

use ::rpc::forge as rpc;
use chrono::prelude::*;
use futures::StreamExt;
use sqlx::postgres::PgRow;
use sqlx::{FromRow, Transaction};
use sqlx::{Postgres, Row};
use std::collections::HashMap;
use uuid::Uuid;

use serde::{Deserialize, Serialize};

use crate::model::hardware_info::InfinibandInterface;
use crate::model::instance::config::{
    infiniband::InstanceInfinibandConfig, network::InterfaceFunctionId,
};
use crate::{
    db::{DatabaseError, UuidKeyedObjectFilter},
    model::config_version::{ConfigVersion, Versioned},
    model::ib_subnet::{
        IBSubnetControllerState, IB_DEFAULT_MTU, IB_DEFAULT_RATE_LIMIT, IB_DEFAULT_SERVICE_LEVEL,
        IB_MTU_ENV, IB_RATE_LIMIT_ENV, IB_SERVICE_LEVEL_ENV,
    },
    CarbideError, CarbideResult,
};

use super::machine::Machine;

#[derive(Debug, Clone, Copy, FromRow)]
pub struct IBSubnetId(uuid::Uuid);

impl From<IBSubnetId> for uuid::Uuid {
    fn from(id: IBSubnetId) -> Self {
        id.0
    }
}

impl From<rpc::IbSubnetSearchConfig> for IBSubnetSearchConfig {
    fn from(value: rpc::IbSubnetSearchConfig) -> Self {
        IBSubnetSearchConfig {
            include_history: value.include_history,
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct IBSubnetSearchConfig {
    pub include_history: bool,
}

#[derive(Debug, Clone)]
pub struct IBSubnetConfig {
    pub name: String,
    pub pkey: Option<i16>,
    pub vpc_id: Uuid,
    pub mtu: i32,
    pub rate_limit: i32,
    pub service_level: i32,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct IBSubnetStatus {
    pub partition: String,
    pub mtu: i32,
    pub rate_limit: i32,
    pub service_level: i32,
}

#[derive(Debug, Clone)]
pub struct IBSubnet {
    pub id: Uuid,
    pub version: ConfigVersion,

    pub config: IBSubnetConfig,
    pub status: Option<IBSubnetStatus>,

    pub created: DateTime<Utc>,
    pub updated: DateTime<Utc>,
    pub deleted: Option<DateTime<Utc>>,

    pub controller_state: Versioned<IBSubnetControllerState>,
}

// We need to implement FromRow because we can't associate dependent tables with the default derive
// (i.e. it can't default unknown fields)
impl<'r> FromRow<'r, PgRow> for IBSubnet {
    fn from_row(row: &'r PgRow) -> Result<Self, sqlx::Error> {
        let config_version_str: &str = row.try_get("config_version")?;
        let version = config_version_str
            .parse()
            .map_err(|e| sqlx::Error::Decode(Box::new(e)))?;

        let controller_state_version_str: &str = row.try_get("controller_state_version")?;
        let controller_state_version = controller_state_version_str
            .parse()
            .map_err(|e| sqlx::Error::Decode(Box::new(e)))?;
        let controller_state: sqlx::types::Json<IBSubnetControllerState> =
            row.try_get("controller_state")?;

        let status: Option<sqlx::types::Json<IBSubnetStatus>> = row.try_get("status")?;
        let status = status.map(|s| s.0);

        Ok(IBSubnet {
            id: row.try_get("id")?,
            version,
            config: IBSubnetConfig {
                name: row.try_get("name")?,
                pkey: Some(row.try_get("pkey")?),
                vpc_id: row.try_get("vpc_id")?,
                mtu: row.try_get("mtu")?,
                rate_limit: row.try_get("rate_limit")?,
                service_level: row.try_get("service_level")?,
            },
            status,

            created: row.try_get("created")?,
            updated: row.try_get("updated")?,
            deleted: row.try_get("deleted")?,

            controller_state: Versioned::new(controller_state.0, controller_state_version),
        })
    }
}

/// Converts from Protobuf IBSubnetCreationRequest into IBSubnet
///
/// Use try_from in order to return a Result where Result is an error if the conversion
/// from String -> UUID fails
///
impl TryFrom<rpc::IbSubnetCreationRequest> for IBSubnetConfig {
    type Error = CarbideError;

    fn try_from(value: rpc::IbSubnetCreationRequest) -> Result<Self, Self::Error> {
        let conf = match value.config {
            Some(c) => c,
            None => {
                return Err(CarbideError::InvalidArgument(
                    "IBSubnet configuration is empty".to_string(),
                ))
            }
        };

        let vpc_id = match conf.vpc_id {
            Some(v) => uuid::Uuid::try_from(v)?,
            None => return Err(CarbideError::InvalidArgument("VPC ID is empty".to_string())),
        };

        Ok(IBSubnetConfig {
            name: conf.name,
            pkey: None,
            vpc_id,
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
/// Marshal a Data Object (IBSubnet) into an RPC IBSubnet
///
impl TryFrom<IBSubnet> for rpc::IbSubnet {
    type Error = CarbideError;
    fn try_from(src: IBSubnet) -> Result<Self, Self::Error> {
        let config = Some(rpc::IbSubnetConfig {
            name: src.config.name.clone(),
            vpc_id: Some(src.config.vpc_id).map(rpc::Uuid::from),
        });

        let mut state = match &src.controller_state.value {
            IBSubnetControllerState::Provisioning => rpc::TenantState::Provisioning,
            IBSubnetControllerState::Ready => rpc::TenantState::Ready,
            IBSubnetControllerState::Error => rpc::TenantState::Failed,
            IBSubnetControllerState::Deleting => rpc::TenantState::Terminating,
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

        let status = Some(rpc::IbSubnetStatus {
            state: state as i32,
            enable_sharp: Some(false),
            partition,
            pkey: src.config.pkey.map(|k| k.to_string()),
            rate_limit,
            mtu,
            service_level,
        });

        Ok(rpc::IbSubnet {
            id: Some(src.id.into()),
            config_version: src.version.version_string(),
            config,
            status,
        })
    }
}

impl IBSubnet {
    pub fn id(&self) -> &uuid::Uuid {
        &self.id
    }

    pub async fn create(
        txn: &mut sqlx::Transaction<'_, Postgres>,
        conf: &IBSubnetConfig,
    ) -> Result<IBSubnet, DatabaseError> {
        let version = ConfigVersion::initial();
        let version_string = version.version_string();
        let state = IBSubnetControllerState::Provisioning;

        let query = "INSERT INTO ib_subnets (
                name,
                pkey,
                vpc_id,
                mtu,
                rate_limit,
                service_level,
                config_version,
                controller_state_version,
                controller_state)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
            RETURNING *";
        let segment: IBSubnet = sqlx::query_as(query)
            .bind(&conf.name)
            .bind(conf.pkey)
            .bind(conf.vpc_id)
            .bind(conf.mtu)
            .bind(conf.rate_limit)
            .bind(conf.service_level)
            .bind(&version_string)
            .bind(&version_string)
            .bind(sqlx::types::Json(state))
            .fetch_one(&mut **txn)
            .await
            .map_err(|e| DatabaseError::new(file!(), line!(), query, e))?;

        Ok(segment)
    }

    /// Retrieves the IDs of all IB subnet
    ///
    /// * `txn` - A reference to a currently open database transaction
    ///
    pub async fn list_segment_ids(
        txn: &mut Transaction<'_, Postgres>,
    ) -> Result<Vec<Uuid>, DatabaseError> {
        let query = "SELECT id FROM ib_subnets";
        let mut results = Vec::new();
        let mut segment_id_stream = sqlx::query_as::<_, IBSubnetId>(query).fetch(&mut **txn);
        while let Some(maybe_id) = segment_id_stream.next().await {
            let id = maybe_id.map_err(|e| DatabaseError::new(file!(), line!(), query, e))?;
            results.push(id.into());
        }

        Ok(results)
    }

    pub async fn for_vpc(
        txn: &mut sqlx::Transaction<'_, Postgres>,
        vpc_id: uuid::Uuid,
    ) -> Result<Vec<Self>, DatabaseError> {
        let results: Vec<IBSubnet> = {
            let query = "SELECT * FROM ib_subnets WHERE vpc_id=$1::uuid";
            sqlx::query_as(query)
                .bind(vpc_id)
                .fetch_all(&mut **txn)
                .await
                .map_err(|e| DatabaseError::new(file!(), line!(), query, e))?
        };

        Ok(results)
    }

    pub async fn find(
        txn: &mut sqlx::Transaction<'_, Postgres>,
        filter: UuidKeyedObjectFilter<'_>,
        _search_config: IBSubnetSearchConfig,
    ) -> Result<Vec<Self>, DatabaseError> {
        let base_query = "SELECT * FROM ib_subnets {where}".to_owned();

        let all_records: Vec<IBSubnet> = match filter {
            UuidKeyedObjectFilter::All => {
                sqlx::query_as::<_, IBSubnet>(&base_query.replace("{where}", ""))
                    .fetch_all(&mut **txn)
                    .await
                    .map_err(|e| DatabaseError::new(file!(), line!(), "ib_subnets All", e))?
            }

            UuidKeyedObjectFilter::List(uuids) => sqlx::query_as::<_, IBSubnet>(
                &base_query.replace("{where}", "WHERE ib_subnets.id=ANY($1)"),
            )
            .bind(uuids)
            .fetch_all(&mut **txn)
            .await
            .map_err(|e| DatabaseError::new(file!(), line!(), "ib_subnets List", e))?,

            UuidKeyedObjectFilter::One(uuid) => sqlx::query_as::<_, IBSubnet>(
                &base_query.replace("{where}", "WHERE ib_subnets.id=$1"),
            )
            .bind(uuid)
            .fetch_all(&mut **txn)
            .await
            .map_err(|e| DatabaseError::new(file!(), line!(), "ib_subnets One", e))?,
        };

        Ok(all_records)
    }

    /// Updates the IB subnet state that is owned by the state controller
    /// under the premise that the curren controller state version didn't change.
    pub async fn try_update_controller_state(
        txn: &mut Transaction<'_, Postgres>,
        subnet_id: uuid::Uuid,
        expected_version: ConfigVersion,
        new_state: &IBSubnetControllerState,
    ) -> Result<bool, DatabaseError> {
        let expected_version_str = expected_version.version_string();
        let next_version = expected_version.increment();
        let next_version_str = next_version.version_string();

        let query = "UPDATE ib_subnets SET controller_state_version=$1, controller_state=$2::json where id=$3::uuid AND controller_state_version=$4 returning id";
        let query_result: Result<IBSubnetId, _> = sqlx::query_as(query)
            .bind(&next_version_str)
            .bind(sqlx::types::Json(new_state))
            .bind(subnet_id)
            .bind(&expected_version_str)
            .fetch_one(&mut **txn)
            .await;

        match query_result {
            Ok(_subnet_id) => Ok(true), // TODO(k82cn): Add state history if necessary.
            Err(sqlx::Error::RowNotFound) => Ok(false),
            Err(e) => Err(DatabaseError::new(file!(), line!(), query, e)),
        }
    }

    pub async fn mark_as_deleted(
        &self,
        txn: &mut Transaction<'_, Postgres>,
    ) -> CarbideResult<IBSubnet> {
        let query = "UPDATE ib_subnets SET updated=NOW(), deleted=NOW() WHERE id=$1 RETURNING *";
        let segment: IBSubnet = sqlx::query_as(query)
            .bind(self.id)
            .fetch_one(&mut **txn)
            .await
            .map_err(|e| CarbideError::from(DatabaseError::new(file!(), line!(), query, e)))?;

        Ok(segment)
    }

    /// Returns whether the IB subnet was deleted by the user
    pub fn is_marked_as_deleted(&self) -> bool {
        self.deleted.is_some()
    }

    pub async fn final_delete(
        segment_id: uuid::Uuid,
        txn: &mut Transaction<'_, Postgres>,
    ) -> Result<uuid::Uuid, DatabaseError> {
        let query = "DELETE FROM ib_subnets WHERE id=$1::uuid RETURNING id";
        let segment: IBSubnetId = sqlx::query_as(query)
            .bind(segment_id)
            .fetch_one(&mut **txn)
            .await
            .map_err(|e| DatabaseError::new(file!(), line!(), query, e))?;

        Ok(segment.0)
    }

    pub async fn update(
        &self,
        txn: &mut Transaction<'_, Postgres>,
    ) -> Result<IBSubnet, DatabaseError> {
        let query = "UPDATE ib_subnets SET name=$1, vpc_id=$2::uuid, status=$3::json, updated=NOW() WHERE id=$4::uuid RETURNING *";

        let segment: IBSubnet = sqlx::query_as(query)
            .bind(&self.config.name)
            .bind(self.config.vpc_id)
            .bind(sqlx::types::Json(&self.status))
            .bind(self.id)
            .fetch_one(&mut **txn)
            .await
            .map_err(|e| DatabaseError::new(file!(), line!(), query, e))?;

        Ok(segment)
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
