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
use std::fmt::{Display, Formatter};
use std::str::FromStr;

use ::rpc::forge as rpc;
use serde::{Deserialize, Serialize};
use serde_json::json;
use sqlx::PgConnection;

use super::DatabaseError;
use crate::db;
use crate::model::bmc_info::BmcInfo;
use crate::{CarbideError, CarbideResult};
use ::rpc::uuid::machine::MachineId;

#[derive(Debug, Copy, Clone, PartialEq, Eq, sqlx::Type, Serialize, Deserialize)]
#[sqlx(type_name = "user_roles")]
#[sqlx(rename_all = "lowercase")]
pub enum UserRoles {
    User,
    Administrator,
    Operator,
    Noaccess,
}

impl Display for UserRoles {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        let string = match self {
            UserRoles::User => "user",
            UserRoles::Administrator => "administrator",
            UserRoles::Operator => "operator",
            UserRoles::Noaccess => "noaccess",
        };

        write!(f, "{string}")
    }
}

impl From<rpc::UserRoles> for UserRoles {
    fn from(action: rpc::UserRoles) -> Self {
        match action {
            rpc::UserRoles::User => UserRoles::User,
            rpc::UserRoles::Administrator => UserRoles::Administrator,
            rpc::UserRoles::Operator => UserRoles::Operator,
            rpc::UserRoles::Noaccess => UserRoles::Noaccess,
        }
    }
}

impl From<UserRoles> for rpc::UserRoles {
    fn from(action: UserRoles) -> Self {
        match action {
            UserRoles::User => rpc::UserRoles::User,
            UserRoles::Administrator => rpc::UserRoles::Administrator,
            UserRoles::Operator => rpc::UserRoles::Operator,
            UserRoles::Noaccess => rpc::UserRoles::Noaccess,
        }
    }
}

impl FromStr for UserRoles {
    type Err = CarbideError;

    fn from_str(input: &str) -> Result<Self, Self::Err> {
        match input {
            "user" => Ok(UserRoles::User),
            "administrator" => Ok(UserRoles::Administrator),
            "operator" => Ok(UserRoles::Operator),
            "noaccess" => Ok(UserRoles::Noaccess),
            x => Err(CarbideError::internal(format!("Unknown role found: {x}"))),
        }
    }
}

pub async fn update_bmc_network_into_topologies(
    txn: &mut PgConnection,
    machine_id: &MachineId,
    bmc_info: &BmcInfo,
) -> CarbideResult<()> {
    if bmc_info.mac.is_none() {
        return Err(CarbideError::internal(format!(
            "BMC Info in machine_topologies does not have a MAC address for machine {machine_id}"
        )));
    }
    tracing::info!("put bmc_info: {:?}", bmc_info);

    // A entry with same machine id is already created by discover_machine call.
    // Just update json by adding a ipmi_ip entry.
    let query = "UPDATE machine_topologies SET topology = jsonb_set(topology, '{bmc_info}', $1, true) WHERE machine_id=$2 RETURNING machine_id";
    sqlx::query_as::<_, MachineId>(query)
        .bind(json!(bmc_info))
        .bind(machine_id.to_string())
        .fetch_optional(txn)
        .await
        .map_err(|e| DatabaseError::query(query, e))?
        .ok_or(CarbideError::NotFoundError {
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
) -> CarbideResult<()> {
    if bmc_info.ip.is_none() {
        return Err(CarbideError::internal(format!(
            "{caller} cannot enrich BMC Info without a valid BMC IP address for machine {machine_id}: {bmc_info:#?}"
        )));
    }

    let bmc_ip_address = bmc_info.ip.clone().unwrap().parse()?;
    if bmc_info.mac.is_none() {
        if let Some(bmc_machine_interface) =
            db::machine_interface::find_by_ip(txn, bmc_ip_address).await?
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
