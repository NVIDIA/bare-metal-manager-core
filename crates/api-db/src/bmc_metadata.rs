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

use carbide_uuid::machine::MachineId;
use model::bmc_info::BmcInfo;
use serde_json::json;
use sqlx::PgConnection;

use crate::{DatabaseError, DatabaseResult};

pub async fn update_bmc_network_into_topologies(
    txn: &mut PgConnection,
    machine_id: &MachineId,
    bmc_info: &BmcInfo,
) -> DatabaseResult<()> {
    if bmc_info.mac.is_none() {
        return Err(DatabaseError::internal(format!(
            "BMC Info in machine_topologies does not have a MAC address for machine {machine_id}"
        )));
    }
    tracing::info!("put bmc_info: {:?}", bmc_info);

    // A entry with same machine id is already created by discover_machine call.
    // Just update json by adding a ipmi_ip entry.
    let query = "UPDATE machine_topologies SET topology = jsonb_set(topology, '{bmc_info}', $1, true) WHERE machine_id=$2 RETURNING machine_id";
    sqlx::query_as::<_, MachineId>(query)
        .bind(json!(bmc_info))
        .bind(machine_id)
        .fetch_optional(txn)
        .await
        .map_err(|e| DatabaseError::query(query, e))?
        .ok_or(DatabaseError::NotFoundError {
            kind: "machine_topologies.machine_id",
            id: machine_id.to_string(),
        })?;
    Ok(())
}

// enrich_mac_address queries the MachineInterfaces table to populate the BMC mac address of the BmcMetaDataInfo structure in memory if it does not exist
// If this function populates the BMC mac address, and persist is speciifed as true, the function will update the machine_topologies table
// with the mac address for that BMC
pub async fn enrich_mac_address(
    bmc_info: &mut BmcInfo,
    caller: String,
    txn: &mut PgConnection,
    machine_id: &MachineId,
    persist: bool,
) -> DatabaseResult<()> {
    if bmc_info.ip.is_none() {
        return Err(DatabaseError::internal(format!(
            "{caller} cannot enrich BMC Info without a valid BMC IP address for machine {machine_id}: {bmc_info:#?}"
        )));
    }

    let bmc_ip_address = bmc_info.ip.clone().unwrap().parse()?;
    if bmc_info.mac.is_none() {
        if let Some(bmc_machine_interface) =
            crate::machine_interface::find_by_ip(txn, bmc_ip_address).await?
        {
            let bmc_mac_address = bmc_machine_interface.mac_address;

            tracing::info!(
                "{} is enriching BMC Info for machine {} with a BMC mac address of {:#?}",
                caller,
                machine_id,
                bmc_machine_interface.mac_address,
            );
            bmc_info.mac = Some(bmc_mac_address);
            if persist {
                update_bmc_network_into_topologies(txn, machine_id, bmc_info).await?;
            }
        } else {
            // This should never happen. Should we return an error here?
            tracing::info!(
                "{} failed to enrich the BMC Info for machine {} with a MAC: cannot cannot find a machine interface with IP address {bmc_ip_address}",
                caller,
                machine_id
            );
        }
    }
    Ok(())
}
