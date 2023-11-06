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

use std::net::{IpAddr, Ipv4Addr};

pub use ::rpc::forge as rpc;
use futures::StreamExt;
use mac_address::MacAddress;
use sqlx::postgres::PgRow;
use sqlx::{FromRow, Postgres, Row, Transaction};
use uuid::Uuid;

use crate::model::bmc_machine::RpcBmcMachineTypeWrapper;
use crate::model::config_version::ConfigVersion;
use crate::model::machine::machine_id::MachineId;
use crate::model::{
    bmc_machine::{BmcMachineState, BmcMachineType},
    config_version::Versioned,
};
use crate::{CarbideError, CarbideResult};

use super::machine::DbMachineId;
use super::{DatabaseError, ObjectFilter};

#[derive(Debug, Clone)]
pub struct BmcMachine {
    pub id: Uuid,
    pub machine_interface_id: Uuid,
    pub bmc_type: BmcMachineType,
    pub controller_state: Versioned<BmcMachineState>,
    pub bmc_firmware_version: Option<String>,
    pub ip_address: IpAddr,
    pub mac_address: MacAddress,
    pub hostname: Option<String>,
    pub machine_id: Option<MachineId>,
}

impl<'r> FromRow<'r, PgRow> for BmcMachine {
    fn from_row(row: &'r PgRow) -> Result<Self, sqlx::Error> {
        let controller_state_version_str: &str = row.try_get("controller_state_version")?;
        let controller_state_version = controller_state_version_str
            .parse()
            .map_err(|e| sqlx::Error::Decode(Box::new(e)))?;
        let controller_state: sqlx::types::Json<BmcMachineState> =
            row.try_get("controller_state")?;
        let machine_id: Option<DbMachineId> = row.try_get("machine_id")?;

        Ok(BmcMachine {
            id: row.try_get("id")?,
            machine_interface_id: row.try_get("machine_interface_id")?,
            bmc_type: row.try_get("bmc_type")?,
            controller_state: Versioned::new(controller_state.0, controller_state_version),
            bmc_firmware_version: row.try_get("bmc_firmware_version")?,
            ip_address: row.try_get("address")?,
            mac_address: row.try_get("mac_address")?,
            hostname: row.try_get("hostname")?,
            machine_id: machine_id.map(|id| id.into_inner()),
        })
    }
}

impl BmcMachine {
    pub async fn find_or_create_bmc_machine(
        txn: &mut Transaction<'_, Postgres>,
        machine_interface_id: Uuid,
        bmc_type: BmcMachineType,
    ) -> CarbideResult<Self> {
        let mut bmc_machine = BmcMachine::find_by(
            txn,
            ObjectFilter::One(machine_interface_id.to_string()),
            "machine_interface_id",
        )
        .await?;
        if bmc_machine.is_empty() {
            Ok(BmcMachine::create(txn, machine_interface_id, bmc_type).await?)
        } else {
            Ok(bmc_machine.remove(0))
        }
    }

    pub async fn get_by_id(txn: &mut Transaction<'_, Postgres>, id: Uuid) -> CarbideResult<Self> {
        BmcMachine::find_by(txn, ObjectFilter::One(id.to_string()), "bm.id")
            .await?
            .first()
            .ok_or_else(|| CarbideError::NotFoundError {
                kind: "bmc_machine",
                id: id.to_string(),
            })
            .cloned()
    }

    pub async fn create(
        txn: &mut Transaction<'_, Postgres>,
        machine_interface_id: Uuid,
        bmc_type: BmcMachineType,
    ) -> CarbideResult<Self> {
        match bmc_type {
            BmcMachineType::Dpu => {
                let state_version = ConfigVersion::initial();
                let query = "INSERT INTO bmc_machine
                        (machine_interface_id, bmc_type, controller_state_version, controller_state)
                        VALUES
                        ($1::uuid, $2, $3, $4 ) RETURNING id";
                let machine_id: (Uuid,) = sqlx::query_as(query)
                    .bind(machine_interface_id)
                    .bind(bmc_type)
                    .bind(state_version.version_string())
                    .bind(sqlx::types::Json(BmcMachineState::Initializing))
                    .fetch_one(&mut **txn)
                    .await
                    .map_err(|e| DatabaseError::new(file!(), line!(), query, e))?;
                BmcMachine::get_by_id(txn, machine_id.0).await
            }
            BmcMachineType::Host => todo!(),
        }
    }

    pub async fn list_bmc_machines(
        txn: &mut Transaction<'_, Postgres>,
    ) -> Result<Vec<Uuid>, DatabaseError> {
        let query = "SELECT id FROM bmc_machine";
        let mut results = Vec::new();
        let mut bmc_id_stream = sqlx::query_as::<_, BmcMachineId>(query).fetch(&mut **txn);
        while let Some(maybe_id) = bmc_id_stream.next().await {
            let id = maybe_id.map_err(|e| DatabaseError::new(file!(), line!(), query, e))?;
            results.push(id.into());
        }

        Ok(results)
    }

    pub async fn find_by<'a>(
        txn: &mut Transaction<'_, Postgres>,
        filter: ObjectFilter<'_, String>,
        column: &'a str,
    ) -> Result<Vec<BmcMachine>, DatabaseError> {
        let base_query = "SELECT 
        bm.id, bm.machine_interface_id, bm.bmc_type, bm.controller_state_version, bm.controller_state,
        bm.bmc_firmware_version, mia.address, mi.hostname, mi.mac_address, mt.machine_id
        FROM bmc_machine bm
        JOIN machine_interfaces mi ON mi.id = bm.machine_interface_id
        INNER JOIN machine_interface_addresses mia on mia.interface_id=mi.id
        LEFT JOIN machine_topologies mt ON (mt.topology->>'bmc_machine_id')::uuid=bm.id 
        {where}"
            .to_owned();

        let machines = match filter {
            ObjectFilter::All => {
                sqlx::query_as::<_, BmcMachine>(&base_query.replace("{where}", ""))
                    .fetch_all(&mut **txn)
                    .await
                    .map_err(|e| DatabaseError::new(file!(), line!(), "bmc_machine All", e))?
            }
            ObjectFilter::One(id) => {
                let query = base_query
                    .replace("{where}", &format!("WHERE {column}='{}'", id))
                    .replace("{column}", column);
                sqlx::query_as::<_, BmcMachine>(&query)
                    .fetch_all(&mut **txn)
                    .await
                    .map_err(|e| DatabaseError::new(file!(), line!(), "bmc_machine One", e))?
            }
            ObjectFilter::List(list) => {
                if list.is_empty() {
                    return Ok(Vec::new());
                }

                let mut columns = String::new();
                for item in list {
                    if !columns.is_empty() {
                        columns.push(',');
                    }
                    columns.push('\'');
                    columns.push_str(item);
                    columns.push('\'');
                }
                let query = base_query
                    .replace("{where}", &format!("WHERE bm.{column} IN ({})", columns))
                    .replace("{column}", column);

                sqlx::query_as::<_, BmcMachine>(&query)
                    .fetch_all(&mut **txn)
                    .await
                    .map_err(|e| DatabaseError::new(file!(), line!(), "bmc_machine List", e))?
            }
        };

        Ok(machines)
    }

    pub async fn find_by_ip(
        txn: &mut Transaction<'_, Postgres>,
        ip: &Ipv4Addr,
    ) -> Result<Option<Self>, DatabaseError> {
        let query = r#"SELECT 
            bm.id, bm.machine_interface_id, bm.bmc_type, bm.controller_state_version, bm.controller_state,
            bm.bmc_firmware_version, mia.address, mi.hostname, mi.mac_address, mt.machine_id
            FROM bmc_machine bm
            JOIN machine_interfaces mi ON mi.id = bm.machine_interface_id
            INNER JOIN machine_interface_addresses mia on mia.interface_id=mi.id
            LEFT JOIN machine_topologies mt ON (mt.topology->>'bmc_machine_id')::uuid=bm.id
            WHERE mia.address = $1::inet"#;
        let bmc_machine: Option<Self> = sqlx::query_as(query)
            .bind(ip.to_string())
            .fetch_optional(&mut **txn)
            .await
            .map_err(|e| DatabaseError::new(file!(), line!(), query, e))?;

        Ok(bmc_machine)
    }

    /// Updates the BMC machine state that is owned by the state controller
    /// under the premise that the current controller state version didn't change.
    ///
    /// Returns `true` if the state could be updated, and `false` if the object
    /// either doesn't exist anymore or is at a different version.
    pub async fn try_update_controller_state(
        txn: &mut Transaction<'_, Postgres>,
        machine_id: uuid::Uuid,
        expected_version: ConfigVersion,
        new_state: &BmcMachineState,
    ) -> Result<bool, DatabaseError> {
        let expected_version_str = expected_version.version_string();
        let next_version = expected_version.increment();
        let next_version_str = next_version.version_string();

        let query = "UPDATE bmc_machine SET controller_state_version=$1, controller_state=$2::json where id=$3::uuid AND controller_state_version=$4 returning id";
        let query_result: Result<BmcMachineId, _> = sqlx::query_as(query)
            .bind(&next_version_str)
            .bind(sqlx::types::Json(new_state))
            .bind(machine_id)
            .bind(&expected_version_str)
            .fetch_one(&mut **txn)
            .await;

        match query_result {
            Ok(_machine_id) => Ok(true),
            Err(sqlx::Error::RowNotFound) => Ok(false),
            Err(e) => Err(DatabaseError::new(file!(), line!(), query, e)),
        }
    }

    pub async fn update_firmware_version(
        &mut self,
        txn: &mut Transaction<'_, Postgres>,
        fw_version: String,
    ) -> Result<bool, DatabaseError> {
        let query = "UPDATE bmc_machine SET bmc_firmware_version=$1 where id=$2::uuid returning id";
        let query_result: Result<BmcMachineId, _> = sqlx::query_as(query)
            .bind(&fw_version)
            .bind(self.id)
            .fetch_one(&mut **txn)
            .await;

        match query_result {
            Ok(_machine_id) => {
                self.bmc_firmware_version = Some(fw_version);
                Ok(true)
            }
            Err(sqlx::Error::RowNotFound) => Ok(false),
            Err(e) => Err(DatabaseError::new(file!(), line!(), query, e)),
        }
    }
}

#[derive(Debug, Clone, Copy, FromRow)]
pub struct BmcMachineId(uuid::Uuid);

impl From<BmcMachineId> for uuid::Uuid {
    fn from(id: BmcMachineId) -> Self {
        id.0
    }
}

///
/// Implements conversion from a database-backed `BmcMachine` to a Protobuf representation of the
/// BmcMachine.
///
impl From<BmcMachine> for rpc::BmcMachine {
    fn from(machine: BmcMachine) -> Self {
        rpc::BmcMachine {
            id: machine.id.to_string(),
            hostname: machine.hostname.unwrap_or("".to_string()),
            ip_address: machine.ip_address.to_string(),
            mac_address: machine.mac_address.to_string(),
            bmc_type: *RpcBmcMachineTypeWrapper::from(machine.bmc_type) as i32,
            fw_version: machine.bmc_firmware_version.unwrap_or("".to_string()),
            state: machine.controller_state.value.to_string(),
            machine_id: machine
                .machine_id
                .map_or_else(|| "".to_string(), |m| m.to_string()),
        }
    }
}
