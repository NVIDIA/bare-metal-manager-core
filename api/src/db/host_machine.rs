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
// HostMachine - represents a database-backed HostMachine object
//

use std::net::IpAddr;

use futures::StreamExt;
use mac_address::MacAddress;
use sqlx::postgres::PgRow;
use sqlx::{FromRow, Postgres, Row, Transaction};
use uuid::Uuid;

use crate::{
    db::{
        machine::{DbMachineId, Machine},
        DatabaseError,
    },
    model::machine::{machine_id::MachineId, ManagedHostState},
    CarbideError, CarbideResult,
};

///
/// A machine is a standalone system that performs network booting via normal DHCP processes.
///
#[derive(Debug)]
pub struct HostMachine {
    machine_id: MachineId,
    _machine_interface_id: uuid::Uuid,
    _mac_address: MacAddress,
    address: IpAddr,
    _hostname: String,
}

// We need to implement FromRow because we can't associate dependent tables with the default derive
// (i.e. it can't default unknown fields)
impl<'r> FromRow<'r, PgRow> for HostMachine {
    fn from_row(row: &'r PgRow) -> Result<Self, sqlx::Error> {
        let machine_id: DbMachineId = row.try_get("machine_id")?;
        Ok(HostMachine {
            machine_id: machine_id.into_inner(),
            _machine_interface_id: row.try_get("machine_interfaces_id")?,
            _mac_address: row.try_get("mac_address")?,
            address: row.try_get("address")?,
            _hostname: row.try_get("hostname")?,
        })
    }
}

impl HostMachine {
    pub fn machine_id(&self) -> &MachineId {
        &self.machine_id
    }

    pub fn _machine_interface_id(&self) -> &Uuid {
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

    /// Retrieves the IDs of all active Machines - which are machines that are not in
    /// the final state.
    ///
    /// * `txn` - A reference to a currently open database transaction
    ///
    pub async fn list_active_ids(
        txn: &mut Transaction<'_, Postgres>,
    ) -> Result<Vec<MachineId>, sqlx::Error> {
        let mut results = Vec::new();
        let mut machine_id_stream =
            sqlx::query_as::<_, DbMachineId>("SELECT machine_id FROM host_machines;")
                .fetch(&mut **txn);
        while let Some(maybe_id) = machine_id_stream.next().await {
            let id = maybe_id?;
            results.push(id.into_inner());
        }

        Ok(results)
    }

    pub async fn find_by_machine_id(
        txn: &mut Transaction<'_, Postgres>,
        host_machine_id: &MachineId,
    ) -> Result<Self, DatabaseError> {
        let query = "SELECT * FROM host_machines WHERE machine_id = $1";
        sqlx::query_as(query)
            .bind(host_machine_id.to_string())
            .fetch_one(&mut **txn)
            .await
            .map_err(|e| DatabaseError::new(file!(), line!(), query, e))
    }

    pub async fn find_by_dpu_machine_id(
        txn: &mut Transaction<'_, Postgres>,
        dpu_machine_id: &MachineId,
    ) -> Result<Self, DatabaseError> {
        //TODO: In multi DPU architecture, it should return Vec<Self>
        let query = "
SELECT hm.* FROM host_machines hm
JOIN machine_interfaces mi on hm.machine_id = hi.attached_dpu_machine_id
WHERE mi.machine_id=$1";
        sqlx::query_as(query)
            .bind(dpu_machine_id.to_string())
            .fetch_one(&mut **txn)
            .await
            .map_err(|e| DatabaseError::new(file!(), line!(), query, e))
    }

    pub async fn update_state(
        txn: &mut Transaction<'_, Postgres>,
        host_id: &MachineId,
        new_state: ManagedHostState,
    ) -> CarbideResult<()> {
        let host = Machine::find_one(
            txn,
            host_id,
            crate::db::machine::MachineSearchConfig::default(),
        )
        .await?
        .ok_or(CarbideError::NotFoundError {
            kind: "machine",
            id: host_id.to_string(),
        })?;

        let version = host.current_version().increment();
        tracing::info!(machine_id = %host.id(), %new_state, "Updating host state");
        host.advance(txn, new_state.clone(), Some(version)).await?;

        // Keep both host and dpu's states in sync.
        let Some(dpu) = Machine::find_dpu_by_host_machine_id(txn, host_id).await? else {
            return Ok(());
        };
        dpu.advance(txn, new_state, Some(version)).await?;
        Ok(())
    }
}

#[cfg(test)]
mod test {}
