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
//
// DpuMachine - represents a database-backed DpuMachine object
//

use std::net::IpAddr;

use mac_address::MacAddress;
use sqlx::postgres::PgRow;
use sqlx::{FromRow, Postgres, Row, Transaction};

use crate::{
    db::{machine::DbMachineId, machine_interface::MachineInterfaceId, DatabaseError},
    model::machine::machine_id::MachineId,
};

///
/// A machine is a standalone system that performs network booting via normal DHCP processes.
///
#[derive(Debug)]
pub struct DpuMachine {
    machine_id: MachineId,
    _machine_interface_id: MachineInterfaceId,
    _mac_address: MacAddress,
    address: IpAddr,
    _hostname: String,
}

// We need to implement FromRow because we can't associate dependent tables with the default derive
// (i.e. it can't default unknown fields)
impl<'r> FromRow<'r, PgRow> for DpuMachine {
    fn from_row(row: &'r PgRow) -> Result<Self, sqlx::Error> {
        let machine_id: DbMachineId = row.try_get("machine_id")?;
        Ok(DpuMachine {
            machine_id: machine_id.into_inner(),
            _machine_interface_id: row.try_get("machine_interfaces_id")?,
            _mac_address: row.try_get("mac_address")?,
            address: row.try_get("address")?,
            _hostname: row.try_get("hostname")?,
        })
    }
}

impl DpuMachine {
    pub fn machine_id(&self) -> &MachineId {
        &self.machine_id
    }

    pub fn _machine_interface_id(&self) -> &MachineInterfaceId {
        &self._machine_interface_id
    }

    pub fn _mac_address(&self) -> &MacAddress {
        &self._mac_address
    }

    pub fn address(&self) -> &IpAddr {
        &self.address
    }

    pub fn _hostname(&self) -> &str {
        &self._hostname
    }

    pub async fn find_by_machine_id(
        txn: &mut Transaction<'_, Postgres>,
        dpu_machine_id: &MachineId,
    ) -> Result<Self, DatabaseError> {
        let query = "SELECT * FROM dpu_machines WHERE machine_id = $1";
        sqlx::query_as(query)
            .bind(dpu_machine_id.to_string())
            .fetch_one(&mut **txn)
            .await
            .map_err(|e| DatabaseError::new(file!(), line!(), query, e))
    }

    pub async fn find_by_host_machine_id(
        txn: &mut Transaction<'_, Postgres>,
        machine_id: &MachineId,
    ) -> Result<Self, DatabaseError> {
        let query = "
SELECT dm.* FROM dpu_machines dm
JOIN machine_interfaces mi on dm.machine_id = mi.attached_dpu_machine_id
WHERE mi.machine_id=$1";
        sqlx::query_as(query)
            .bind(machine_id.to_string())
            .fetch_one(&mut **txn)
            .await
            .map_err(|e| DatabaseError::new(file!(), line!(), query, e))
    }
}
