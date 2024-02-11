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

use std::collections::HashMap;

use chrono::prelude::*;
use itertools::Itertools;
use serde::{Deserialize, Serialize};
use sqlx::postgres::PgRow;
use sqlx::{FromRow, Postgres, Row, Transaction};

use super::DatabaseError;
use crate::db::machine::DbMachineId;
use crate::model::bmc_info::BmcInfo;
use crate::model::{hardware_info::HardwareInfo, machine::machine_id::MachineId};
use crate::{CarbideError, CarbideResult};

#[derive(Debug, Deserialize, Clone)]
pub struct MachineTopology {
    machine_id: MachineId,
    /// Topology data that is stored in json format in the database column
    topology: TopologyData,
    created: DateTime<Utc>,
    _updated: DateTime<Utc>,
    topology_update_needed: bool,
}

impl<'r> FromRow<'r, PgRow> for MachineTopology {
    fn from_row(row: &'r PgRow) -> Result<Self, sqlx::Error> {
        // The wrapper is required to teach sqlx to access the field
        // as a JSON field instead of a string.
        let topology: sqlx::types::Json<TopologyData> = row.try_get("topology")?;

        let machine_id: DbMachineId = row.try_get("machine_id")?;

        Ok(MachineTopology {
            machine_id: machine_id.into_inner(),
            topology: topology.0,
            created: row.try_get("created")?,
            _updated: row.try_get("updated")?,
            topology_update_needed: row.try_get("topology_update_needed")?,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DiscoveryData {
    /// Stores the hardware information that was fetched during discovery
    /// **Note that this field is renamed to uppercase because
    /// that is how the originally utilized protobuf message looked in serialized
    /// format**
    #[serde(rename = "Info")]
    pub info: HardwareInfo,
}

/// Describes the data format we store in the `topology` field of the `machine_topologies` table
///
/// Note that we don't need most of the fields here - they are just an artifact
/// of initially storing a protobuf message which also contained other data in this
/// field. For backward compatibility we emulate this behavior.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TopologyData {
    /// Stores the hardware information that was fetched during discovery
    pub discovery_data: DiscoveryData,
    /// The BMC information of the machine
    /// Note that this field is currently side-injected via the
    /// `crate::crate::db::ipmi::BmcMetaDataUpdateRequest::update_bmc_meta_data`
    /// Therefore no `write` function can be found here.
    pub bmc_info: BmcInfo,
}

impl MachineTopology {
    async fn update(
        txn: &mut Transaction<'_, Postgres>,
        machine_id: &MachineId,
        hardware_info: &HardwareInfo,
    ) -> CarbideResult<Self> {
        let discovery_data = DiscoveryData {
            info: hardware_info.clone(),
        };

        tracing::info!(
            %machine_id,
            "Discovery data for machine already exists. Updating now.",
        );
        let query =
                "UPDATE machine_topologies SET topology=jsonb_set(topology, '{discovery_data}', $2::jsonb), topology_update_needed=false WHERE machine_id=$1 RETURNING *";
        let res = sqlx::query_as(query)
            .bind(machine_id.to_string())
            .bind(sqlx::types::Json(&discovery_data))
            .fetch_one(&mut **txn)
            .await
            .map_err(|e| CarbideError::from(DatabaseError::new(file!(), line!(), query, e)))?;

        Ok(res)
    }

    pub async fn create_or_update(
        txn: &mut Transaction<'_, Postgres>,
        machine_id: &MachineId,
        hardware_info: &HardwareInfo,
    ) -> CarbideResult<Self> {
        let topology_data = Self::find_latest_by_machine_ids(txn, &[machine_id.clone()]).await?;
        let topology_data = topology_data.get(machine_id);

        if let Some(topology) = topology_data {
            if topology.topology_update_needed {
                return Self::update(txn, machine_id, hardware_info).await;
            }
            return Ok(topology.clone());
        }

        let topology_data = TopologyData {
            discovery_data: DiscoveryData {
                info: hardware_info.clone(),
            },
            bmc_info: BmcInfo {
                ip: None,
                port: None,
                mac: None,
                version: None,
                firmware_version: None,
            },
        };

        let query = "INSERT INTO machine_topologies VALUES ($1, $2::json) RETURNING *";
        let res = sqlx::query_as(query)
            .bind(machine_id.to_string())
            .bind(sqlx::types::Json(&topology_data))
            .fetch_one(&mut **txn)
            .await
            .map_err(|e| CarbideError::from(DatabaseError::new(file!(), line!(), query, e)))?;

        Ok(res)
    }

    pub async fn find_by_machine_ids(
        txn: &mut Transaction<'_, Postgres>,
        machine_ids: &[MachineId],
    ) -> Result<HashMap<MachineId, Vec<Self>>, DatabaseError> {
        // TODO: Actually this shouldn't be able to return multiple entries,
        // since there  is a check in create that for existing interfaces
        // But due to race conditions we can likely still have multiple of those interfaces
        let str_ids: Vec<String> = machine_ids.iter().map(|id| id.to_string()).collect();
        let query = "SELECT * FROM machine_topologies WHERE machine_id=ANY($1);";
        let topologies = sqlx::query_as(query)
            .bind(str_ids)
            .fetch_all(&mut **txn)
            .await
            .map_err(|e| DatabaseError::new(file!(), line!(), query, e))?
            .into_iter()
            .into_group_map_by(|t: &Self| t.machine_id.clone());
        Ok(topologies)
    }

    pub async fn find_latest_by_machine_ids(
        txn: &mut Transaction<'_, Postgres>,
        machine_ids: &[MachineId],
    ) -> Result<HashMap<MachineId, Self>, DatabaseError> {
        // TODO: So far this just moved code around
        // This way of doing fetching the latest topology is inefficient, because it will still fetch all
        // information. We can change the query - however if we store information
        // later on directly as part of the Machine or instance this might
        // be unnecessary.
        let all = Self::find_by_machine_ids(txn, machine_ids).await?;

        let mut result = HashMap::new();
        for (id, mut topos) in all {
            let topo = topos
                .drain(..)
                .reduce(|t1, t2| if t1.created() > t2.created() { t1 } else { t2 });
            if let Some(topo) = topo {
                result.insert(id, topo);
            }
        }

        Ok(result)
    }

    pub async fn find_machine_id_by_bmc_ip(
        txn: &mut Transaction<'_, Postgres>,
        address: &str,
    ) -> Result<Option<MachineId>, DatabaseError> {
        let query =
            "SELECT machine_id FROM machine_topologies WHERE topology->'bmc_info'->>'ip' = $1";
        Ok(sqlx::query_as::<_, DbMachineId>(query)
            .bind(address)
            .fetch_optional(&mut **txn)
            .await
            .map_err(|e| DatabaseError::new(file!(), line!(), query, e))?
            .map(|db_id| db_id.into_inner()))
    }

    pub async fn set_topology_update_needed(
        txn: &mut Transaction<'_, Postgres>,
        machine_id: &MachineId,
        value: bool,
    ) -> Result<(), DatabaseError> {
        let query =
                "UPDATE machine_topologies SET topology_update_needed=$2 WHERE machine_id=$1 RETURNING machine_id";
        let _id = sqlx::query_as::<_, DbMachineId>(query)
            .bind(machine_id.to_string())
            .bind(value)
            .fetch_one(&mut **txn)
            .await
            .map_err(|e| DatabaseError::new(file!(), line!(), query, e))?;

        Ok(())
    }

    pub fn topology(&self) -> &TopologyData {
        &self.topology
    }

    pub fn created(&self) -> DateTime<Utc> {
        self.created
    }

    pub fn topology_update_needed(&self) -> bool {
        self.topology_update_needed
    }
}
