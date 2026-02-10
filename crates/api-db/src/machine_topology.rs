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
use std::net::IpAddr;

use carbide_uuid::machine::MachineId;
use chrono::{TimeDelta, Utc};
use itertools::Itertools;
use model::bmc_info::BmcInfo;
use model::hardware_info::HardwareInfo;
use model::machine::topology::{DiscoveryData, MachineTopology, TopologyData};
use sqlx::PgConnection;

use super::DatabaseError;
use crate::DatabaseResult;
use crate::db_read::DbReader;

async fn update(
    txn: &mut PgConnection,
    machine_id: &MachineId,
    hardware_info: &HardwareInfo,
) -> DatabaseResult<MachineTopology> {
    let discovery_data = DiscoveryData {
        info: hardware_info.clone(),
    };

    tracing::info!(
        %machine_id,
        "Discovery data for machine already exists. Updating now.",
    );
    let query = "UPDATE machine_topologies SET topology=jsonb_set(topology, '{discovery_data}', $2::jsonb), topology_update_needed=false, updated=NOW() WHERE machine_id=$1 RETURNING *";
    let res = sqlx::query_as(query)
        .bind(machine_id)
        .bind(sqlx::types::Json(&discovery_data))
        .fetch_one(txn)
        .await
        .map_err(|e| DatabaseError::query(query, e))?;

    Ok(res)
}

pub async fn create_or_update(
    txn: &mut PgConnection,
    machine_id: &MachineId,
    hardware_info: &HardwareInfo,
) -> DatabaseResult<MachineTopology> {
    let topology_data = find_latest_by_machine_ids(txn, &[*machine_id]).await?;
    let topology_data = topology_data.get(machine_id);

    if let Some(topology) = topology_data {
        if topology.topology_update_needed {
            return update(txn, machine_id, hardware_info).await;
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

    tracing::info!(
        %machine_id,
        "Discovery data for machine did not exist. Creating now.",
    );

    let query = "INSERT INTO machine_topologies VALUES ($1, $2::json) RETURNING *";
    let res = sqlx::query_as(query)
        .bind(machine_id)
        .bind(sqlx::types::Json(&topology_data))
        .fetch_one(txn)
        .await
        .map_err(|e| DatabaseError::query(query, e))?;

    Ok(res)
}

//  Wrapper for create_or_update to set topology_update_needed to true if bom_validation is enabled and
//  the last update was older than 1 day.
pub async fn create_or_update_with_bom_validation(
    txn: &mut PgConnection,
    machine_id: &MachineId,
    hardware_info: &HardwareInfo,
    bom_validation_enabled: bool,
) -> DatabaseResult<MachineTopology> {
    let topology_data = find_latest_by_machine_ids(txn, &[*machine_id]).await?;
    let topology_data = topology_data.get(machine_id);

    if let Some(topology) = topology_data {
        let age = Utc::now() - topology.updated;
        if bom_validation_enabled && age > TimeDelta::days(1) {
            tracing::debug!(
                "Received inventory update from {}, bom_validation is enabled, existing data is old, updating",
                machine_id
            );
            set_topology_update_needed(txn, machine_id, true).await?;
        }
    }

    create_or_update(txn, machine_id, hardware_info).await
}

// update_firmware_version_by_bmc_address updates the stored firmware version info, using the BMC IP under the assumption that this came from site explorer reading from that address.
pub async fn update_firmware_version_by_bmc_address(
    txn: &mut PgConnection,
    bmc_address: &IpAddr,
    bmc_version: &str,
    bios_version: &str,
) -> DatabaseResult<()> {
    // The IS NOT NULL checks that we're not partially creating stuff under an Option when adding a bios_version.  The firmware_version for the BMC gets implicitly checked when checking for the BMC IP.
    let query = r#"UPDATE machine_topologies SET topology =
                        jsonb_set(jsonb_set(topology, '{bmc_info}',
                            jsonb_set(topology->'bmc_info', '{firmware_version}', $2)),
                            '{discovery_data}',
                                 jsonb_set(topology->'discovery_data', '{Info}',
                                            jsonb_set(topology->'discovery_data'->'Info', '{dmi_data}',
                                                        jsonb_set(topology->'discovery_data'->'Info'->'dmi_data', '{bios_version}', $3))
                        )) WHERE topology->'bmc_info'->>'ip' = $1
                                            AND topology->'discovery_data'->'Info'->'dmi_data'->'bios_version' IS NOT NULL;"#;

    sqlx::query(query)
        .bind(bmc_address.to_string())
        .bind(sqlx::types::Json(bmc_version))
        .bind(sqlx::types::Json(bios_version))
        .execute(txn)
        .await
        .map_err(|e| DatabaseError::query(query, e))?;

    Ok(())
}

pub async fn find_by_machine_ids(
    txn: &mut PgConnection,
    machine_ids: &[MachineId],
) -> Result<HashMap<MachineId, Vec<MachineTopology>>, DatabaseError> {
    // TODO: Actually this shouldn't be able to return multiple entries,
    // since there is a check in create that for existing interfaces
    // But due to race conditions we can likely still have multiple of those interfaces
    let str_ids: Vec<String> = machine_ids.iter().map(|id| id.to_string()).collect();
    let query = "SELECT * FROM machine_topologies WHERE machine_id=ANY($1)";
    let topologies = sqlx::query_as(query)
        .bind(str_ids)
        .fetch_all(txn)
        .await
        .map_err(|e| DatabaseError::query(query, e))?
        .into_iter()
        .into_group_map_by(|t: &MachineTopology| t.machine_id);
    Ok(topologies)
}

pub async fn find_latest_by_machine_ids(
    txn: &mut PgConnection,
    machine_ids: &[MachineId],
) -> Result<HashMap<MachineId, MachineTopology>, DatabaseError> {
    // TODO: So far this just moved code around
    // This way of doing fetching the latest topology is inefficient, because it will still fetch all
    // information. We can change the query - however if we store information
    // later on directly as part of the Machine or instance this might
    // be unnecessary.
    let all = find_by_machine_ids(txn, machine_ids).await?;

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
    txn: &mut PgConnection,
    address: &str,
) -> Result<Option<MachineId>, DatabaseError> {
    let query = "SELECT machine_id FROM machine_topologies WHERE topology->'bmc_info'->>'ip' = $1";
    sqlx::query_as(query)
        .bind(address)
        .fetch_optional(txn)
        .await
        .map_err(|e| DatabaseError::query(query, e))
}

pub async fn find_machine_bmc_pairs(
    txn: impl DbReader<'_>,
    bmc_ips: Vec<String>,
) -> Result<Vec<(MachineId, String)>, DatabaseError> {
    let query = r#"SELECT machine_id, topology->'bmc_info'->>'ip'
            FROM machine_topologies
            WHERE topology->'bmc_info'->>'ip' = ANY($1)"#;
    sqlx::query_as(query)
        .bind(bmc_ips)
        .fetch_all(txn)
        .await
        .map_err(|e| DatabaseError::new("machine_topologies find_machine_bmc_pairs", e))
}

/// Find the BMC IP address for each of the given machine IDs.
///
/// Returns a list of (machine_id, bmc_ip) pairs. If a machine has multiple topology
/// records, only the most recent one (by `created` timestamp) is returned.
///
/// The BMC IP is returned as `Option<String>`:
/// - `Some(ip)` if the topology has a valid BMC IP
/// - `None` if the topology exists but has no BMC IP (caller can log/handle this case)
///
/// Note: Machines without topology records will be silently omitted from the result.
///
/// This query uses `DISTINCT ON` with `ORDER BY machine_id, created DESC` to efficiently
/// select the latest topology per machine. This is optimized by the composite index
/// `machine_topologies_machine_id_created_idx`.
pub async fn find_machine_bmc_pairs_by_machine_id(
    txn: &mut PgConnection,
    machine_ids: Vec<MachineId>,
) -> Result<Vec<(MachineId, Option<String>)>, DatabaseError> {
    let query = r#"
        SELECT DISTINCT ON (machine_id) machine_id, topology->'bmc_info'->>'ip'
        FROM machine_topologies
        WHERE machine_id = ANY($1)
        ORDER BY machine_id, created DESC
    "#;
    sqlx::query_as(query)
        .bind(machine_ids)
        .fetch_all(txn)
        .await
        .map_err(|e| {
            DatabaseError::new("machine_topologies find_machine_bmc_pairs_by_machine_id", e)
        })
}

/// Find any topology with a product, chassis, or board serial number exactly matching the input.
///
/// NOTE: This query must exactly match the index machine_topologies_serial_numbers_idx, which
/// will make this a fast operation that doesn't need to sequentially scan. DO NOT change this
/// query without also changing the index!
pub async fn find_by_serial(
    txn: impl DbReader<'_>,
    to_find: &str,
) -> Result<Vec<MachineId>, DatabaseError> {
    let query = r#"
            SELECT machine_id
            FROM   machine_topologies
            WHERE
            (
                jsonb_path_query_array(topology,
                    '$.discovery_data.Info.dmi_data.product_serial')
            ||
                jsonb_path_query_array(topology,
                    '$.discovery_data.Info.dmi_data.board_serial')
            ||
                jsonb_path_query_array(topology,
                    '$.discovery_data.Info.dmi_data.chassis_serial')
            ) @> to_jsonb(ARRAY[$1]);
        "#;
    sqlx::query_as::<_, MachineId>(query)
        .bind(to_find)
        .fetch_all(txn)
        .await
        .map_err(|e| DatabaseError::new("machine_topologies find_by_serial", e))
}

/// Search the topologyfor a string anywhere in the JSON.
/// Used by the serial number finder for non-exact matches
pub async fn find_freetext(
    txn: impl DbReader<'_>,
    to_find: &str,
) -> Result<Vec<MachineId>, DatabaseError> {
    let query =
        "SELECT machine_id FROM machine_topologies WHERE topology::text ilike '%' || $1 || '%'";
    sqlx::query_as::<_, MachineId>(query)
        .bind(to_find)
        .fetch_all(txn)
        .await
        .map_err(|e| DatabaseError::new("machine_topologies find_freetext", e))
}

pub async fn set_topology_update_needed(
    txn: &mut PgConnection,
    machine_id: &MachineId,
    value: bool,
) -> Result<(), DatabaseError> {
    let query = "UPDATE machine_topologies SET topology_update_needed=$2 WHERE machine_id=$1 RETURNING machine_id";
    let _id = sqlx::query_as::<_, MachineId>(query)
        .bind(machine_id)
        .bind(value)
        .fetch_one(txn)
        .await
        .map_err(|e| DatabaseError::query(query, e))?;

    Ok(())
}

// TODO: Remove when there's no longer a need to handle the old topology format
pub mod test_helpers {
    use model::hardware_info::{
        BlockDevice, Cpu, DmiData, DpuData, Gpu, InfinibandInterface, MemoryDevice,
        NetworkInterface, NvmeDevice, TpmEkCertificate,
    };
    use serde::{Deserialize, Serialize};
    use utils::models::arch::CpuArchitecture;

    use super::*;

    // TODO: Remove when there's no longer a need to handle the old topology format
    #[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
    pub struct HardwareInfoV1 {
        #[serde(default)]
        pub network_interfaces: Vec<NetworkInterface>,
        #[serde(default)]
        pub infiniband_interfaces: Vec<InfinibandInterface>,
        #[serde(default)]
        pub cpus: Vec<Cpu>,
        #[serde(default)]
        pub block_devices: Vec<BlockDevice>,
        // This should be called machine_arch, but it's serialized directly in/out of a JSONB field in
        // the DB, so renaming it requires a migration or custom Serialize impl.
        pub machine_type: CpuArchitecture,
        #[serde(default)]
        pub nvme_devices: Vec<NvmeDevice>,
        #[serde(default)]
        pub dmi_data: Option<DmiData>,
        pub tpm_ek_certificate: Option<TpmEkCertificate>,
        #[serde(default)]
        pub dpu_info: Option<DpuData>,
        #[serde(default)]
        pub gpus: Vec<Gpu>,
        #[serde(default)]
        pub memory_devices: Vec<MemoryDevice>,
    }

    // TODO: Remove when there's no longer a need to handle the old topology format
    #[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
    pub struct DiscoveryDataV1 {
        /// Stores the hardware information that was fetched during discovery
        /// **Note that this field is renamed to uppercase because
        /// that is how the originally utilized protobuf message looked in serialized
        /// format**
        #[serde(rename = "Info")]
        pub info: HardwareInfoV1,
    }

    // TODO: Remove when there's no longer a need to handle the old topology format
    #[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
    pub struct TopologyDataV1 {
        /// Stores the hardware information that was fetched during discovery
        pub discovery_data: DiscoveryDataV1,
        /// The BMC information of the machine
        /// Note that this field is currently side-injected via the
        /// `crate::crate::ipmi::BmcMetaDataUpdateRequest::update_bmc_meta_data`
        /// Therefore no `write` function can be found here.
        pub bmc_info: BmcInfo,
    }

    pub async fn update_v1(
        txn: &mut PgConnection,
        machine_id: &MachineId,
        hardware_info: &HardwareInfoV1,
    ) -> DatabaseResult<MachineTopology> {
        let discovery_data = DiscoveryDataV1 {
            info: hardware_info.clone(),
        };

        tracing::info!(
            %machine_id,
            "Discovery data for machine already exists. Updating now.",
        );
        let query = "UPDATE machine_topologies SET topology=jsonb_set(topology, '{discovery_data}', $2::jsonb), topology_update_needed=false, updated=NOW() WHERE machine_id=$1 RETURNING *";
        let res = sqlx::query_as(query)
            .bind(machine_id)
            .bind(sqlx::types::Json(&discovery_data))
            .fetch_one(txn)
            .await
            .map_err(|e| DatabaseError::query(query, e))?;

        Ok(res)
    }

    pub async fn create_or_update_v1(
        txn: &mut PgConnection,
        machine_id: &MachineId,
        hardware_info: &HardwareInfoV1,
    ) -> DatabaseResult<MachineTopology> {
        let topology_data = find_latest_by_machine_ids(txn, &[*machine_id]).await?;
        let topology_data = topology_data.get(machine_id);

        if let Some(topology) = topology_data {
            if topology.topology_update_needed {
                return update_v1(txn, machine_id, hardware_info).await;
            }
            return Ok(topology.clone());
        }

        let topology_data = TopologyDataV1 {
            discovery_data: DiscoveryDataV1 {
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

        tracing::info!(
            %machine_id,
            "Discovery data for machine did not exist. Creating now.",
        );

        let query = "INSERT INTO machine_topologies VALUES ($1, $2::json) RETURNING *";
        let res = sqlx::query_as(query)
            .bind(machine_id)
            .bind(sqlx::types::Json(&topology_data))
            .fetch_one(txn)
            .await
            .map_err(|e| DatabaseError::query(query, e))?;

        Ok(res)
    }
}
