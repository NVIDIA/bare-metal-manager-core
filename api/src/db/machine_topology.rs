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
use std::net::{IpAddr, Ipv4Addr};

use chrono::prelude::*;
use itertools::Itertools;
use serde::{Deserialize, Serialize};
use sqlx::postgres::PgRow;
use sqlx::{FromRow, Postgres, Row, Transaction};

use super::DatabaseError;
use crate::db::machine::{DbMachineId, Machine, MachineSearchConfig};
use crate::db::vpc_resource_leaf::NewVpcResourceLeaf;
use crate::model::{hardware_info::HardwareInfo, machine::machine_id::MachineId};
use crate::{CarbideError, CarbideResult};

#[derive(Debug, Deserialize)]
pub struct MachineTopology {
    machine_id: MachineId,
    /// Topology data that is stored in json format in the database column
    topology: TopologyData,
    created: DateTime<Utc>,
    _updated: DateTime<Utc>,
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
    /// The BMC IP of the machine
    /// Note that this field is currently side-injected via the
    /// `crate::crate::db::ipmi::BmcMetaDataUpdateRequest::update_bmc_meta_data`
    /// Therefore no `write` function can be found here.
    pub ipmi_ip: Option<String>,
    pub ipmi_mac: Option<String>,
}

#[derive(thiserror::Error, Debug)]
pub enum MachineTopologyConversionError {
    #[error("Machine topology conversion error: {0}")]
    ConversionError(String),

    #[error("Discovery info deserialization error: {0}")]
    DiscoveryInfoDeserializationError(#[from] serde_json::Error),
}

impl MachineTopology {
    pub async fn is_discovered(
        txn: &mut Transaction<'_, Postgres>,
        machine_id: &MachineId,
    ) -> Result<bool, DatabaseError> {
        let query = "SELECT * from machine_topologies WHERE machine_id=$1";
        let res = sqlx::query(query)
            .bind(machine_id.to_string())
            .fetch_optional(&mut *txn)
            .await
            .map_err(|e| DatabaseError::new(file!(), line!(), query, e))?;

        match res {
            None => {
                log::info!("We have never seen this discovery and machine data before");
                Ok(false)
            }
            Some(_pg_row) => {
                log::info!("Discovery data for machine already exists");
                Ok(true)
            }
        }
    }

    pub async fn create(
        txn: &mut Transaction<'_, Postgres>,
        machine_id: &MachineId,
        hardware_info: &HardwareInfo,
        loopback_ip: Option<Ipv4Addr>,
    ) -> CarbideResult<Option<Self>> {
        if Self::is_discovered(&mut *txn, machine_id).await? {
            log::info!("Discovery data for machine {} already exists", machine_id);
            Ok(None)
        } else {
            let topology_data = TopologyData {
                discovery_data: DiscoveryData {
                    info: hardware_info.clone(),
                },
                ipmi_ip: None,
                ipmi_mac: None,
            };

            let query = "INSERT INTO machine_topologies VALUES ($1, $2::json) RETURNING *";
            let res = sqlx::query_as(query)
                .bind(machine_id.to_string())
                .bind(sqlx::types::Json(&topology_data))
                .fetch_one(&mut *txn)
                .await
                .map_err(|e| CarbideError::from(DatabaseError::new(file!(), line!(), query, e)))?;

            if machine_id.machine_type().is_dpu() {
                // TODO part VPC, remove once it's replaced
                let mut new_leaf = NewVpcResourceLeaf::new(machine_id.clone())
                    .persist(&mut *txn)
                    .await?;
                if let Some(ip) = loopback_ip {
                    new_leaf
                        .update_loopback_ip_address(&mut *txn, IpAddr::V4(ip))
                        .await?;
                }

                log::info!(
                    "Discovered Machine {} is a DPU. Generating new leaf id {}",
                    machine_id,
                    new_leaf.id()
                );
                assert_eq!(new_leaf.id(), machine_id);

                // TODO 1: Why do we use the returned `machine_dpu.id()` from here
                // It should just be the same as the `machine_id` we pass in?
                // All of them are the DPU `machine_id`s?
                // TODO 2: This might no longer be needed, since we already have
                // a similar relation via attached_dpu_id
                let machine_dpu =
                    Machine::associate_vpc_leaf_id(&mut *txn, machine_id, new_leaf.id()).await?;

                if let Some(machine) =
                    Machine::find_one(&mut *txn, machine_dpu.id(), MachineSearchConfig::default())
                        .await?
                {
                    log::info!("Machine with ID: {} found", machine.id());
                    for mut interface in machine.interfaces().iter().cloned() {
                        if machine.vpc_leaf_id().is_some() {
                            log::info!("Machine VPC_LEAF_ID: {:?}", machine.vpc_leaf_id());
                            interface
                                .associate_interface_with_dpu_machine(&mut *txn, machine.id())
                                .await?;
                        }
                    }
                }

                //
            }
            Ok(Some(res))
        }
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
            .fetch_all(&mut *txn)
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

    pub fn topology(&self) -> &TopologyData {
        &self.topology
    }

    pub fn created(&self) -> DateTime<Utc> {
        self.created
    }
}
