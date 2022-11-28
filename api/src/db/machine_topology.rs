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
use std::collections::{BTreeMap, HashMap};

use chrono::prelude::*;
use itertools::Itertools;
use serde::{Deserialize, Serialize};
use sqlx::postgres::PgRow;
use sqlx::{Acquire, FromRow, Postgres, Row, Transaction};

use crate::db::dpu_machine::DpuMachine;
use crate::db::machine::Machine;
use crate::db::vpc_resource_leaf::NewVpcResourceLeaf;
use crate::kubernetes::VpcResourceActions;
use crate::model::hardware_info::HardwareInfo;
use crate::model::machine::DPU_PHYSICAL_NETWORK_INTERFACE;
use crate::vpc_resources::{host_interfaces, leaf};
use crate::CarbideResult;

#[derive(Debug, Deserialize)]
pub struct MachineTopology {
    machine_id: uuid::Uuid,
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

        Ok(MachineTopology {
            machine_id: row.try_get("machine_id")?,
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
    // Note that there was also originally stored a `machine_id` field as part
    // of the database schema - which did not identify the machine, but actually
    // a machine_interface_id. Since we do not read this value it is no longer
    // loaded here, and will not be stored for newly discovery machines.
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
        machine_id: &uuid::Uuid,
    ) -> CarbideResult<bool> {
        let res = sqlx::query("SELECT * from machine_topologies WHERE machine_id=$1::uuid")
            .bind(machine_id)
            .fetch_optional(&mut *txn)
            .await?;

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
        machine_id: &uuid::Uuid,
        hardware_info: &HardwareInfo,
    ) -> CarbideResult<Option<Self>> {
        if Self::is_discovered(&mut *txn, machine_id).await? {
            log::info!("Discovery data for machine {} already exists", machine_id);
            Ok(None)
        } else {
            let topology_data = TopologyData {
                discovery_data: DiscoveryData {
                    info: hardware_info.clone(),
                },
            };

            let res = sqlx::query_as(
                "INSERT INTO machine_topologies VALUES ($1::uuid, $2::json) RETURNING *",
            )
            .bind(machine_id)
            .bind(sqlx::types::Json(&topology_data))
            .fetch_one(&mut *txn)
            .await?;

            if hardware_info.is_dpu() {
                let new_leaf = NewVpcResourceLeaf::new().persist(&mut *txn).await?;

                log::info!("Generating new leaf id {}", new_leaf.id());

                let machine_dpu =
                    Machine::associate_vpc_leaf_id(&mut *txn, *machine_id, *new_leaf.id()).await?;

                if let Some(machine) = Machine::find_one(&mut *txn, *machine_dpu.id()).await? {
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
                let dpu = DpuMachine::find_by_machine_id(&mut *txn, machine_dpu.id()).await?;

                let leaf_spec = leaf::Leaf::new(
                    &new_leaf.id().to_string(),
                    leaf::LeafSpec {
                        control: Some(leaf::LeafControl {
                            maintenance_mode: Some(false),
                            management_ip: Some(dpu.address().ip().to_string()),
                            vendor: Some("DPU".to_string()),
                        }),
                        host_admin_i_ps: Some(BTreeMap::from([(
                            DPU_PHYSICAL_NETWORK_INTERFACE.to_string(),
                            "".to_string(),
                        )])),
                        host_interfaces: Some(host_interfaces(dpu.machine_id())),
                    },
                );

                log::info!("Leafspec sent to kubernetes: {:?}", leaf_spec);

                let db_conn = txn.acquire().await?;

                VpcResourceActions::CreateLeaf(leaf_spec)
                    .reconcile(db_conn)
                    .await?;
            }
            Ok(Some(res))
        }
    }
    pub async fn find_by_machine_ids(
        txn: &mut Transaction<'_, Postgres>,
        machine_ids: &[uuid::Uuid],
    ) -> Result<HashMap<uuid::Uuid, Vec<Self>>, sqlx::Error> {
        // TODO: Actually this shouldn't be able to return multiple entries,
        // since there  is a check in create that for existing interfaces
        // But due to race conditions we can likely still have multiple of those interfaces
        let query = "SELECT * FROM machine_topologies WHERE machine_id=ANY($1);";
        let topologies = sqlx::query_as(query)
            .bind(machine_ids)
            .fetch_all(&mut *txn)
            .await?
            .into_iter()
            .into_group_map_by(|t: &Self| t.machine_id);
        Ok(topologies)
    }

    pub async fn find_latest_by_machine_ids(
        txn: &mut Transaction<'_, Postgres>,
        machine_ids: &[uuid::Uuid],
    ) -> Result<HashMap<uuid::Uuid, Self>, sqlx::Error> {
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
