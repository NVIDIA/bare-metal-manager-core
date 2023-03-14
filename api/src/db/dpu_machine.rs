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

use futures::StreamExt;
use ipnetwork::IpNetwork;
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
pub struct DpuMachine {
    machine_id: MachineId,
    _vpc_leaf_id: MachineId,
    _machine_interface_id: uuid::Uuid,
    _mac_address: MacAddress,
    address: IpNetwork,
    _hostname: String,
}

// We need to implement FromRow because we can't associate dependent tables with the default derive
// (i.e. it can't default unknown fields)
impl<'r> FromRow<'r, PgRow> for DpuMachine {
    fn from_row(row: &'r PgRow) -> Result<Self, sqlx::Error> {
        let machine_id: DbMachineId = row.try_get("machine_id")?;
        let vpc_leaf_id: DbMachineId = row.try_get("vpc_leaf_id")?;
        Ok(DpuMachine {
            machine_id: machine_id.into_inner(),
            _vpc_leaf_id: vpc_leaf_id.into_inner(),
            _machine_interface_id: row.try_get("machine_interfaces_id")?,
            _mac_address: row.try_get("mac_address")?,
            address: row.try_get("address")?,
            _hostname: row.try_get("hostname")?,
        })
    }
}

impl DpuMachine {
    pub fn _vpc_leaf_id(&self) -> &MachineId {
        &self._vpc_leaf_id
    }

    pub fn machine_id(&self) -> &MachineId {
        &self.machine_id
    }

    pub fn _machine_interface_id(&self) -> &Uuid {
        &self._machine_interface_id
    }

    pub fn _mac_address(&self) -> &MacAddress {
        &self._mac_address
    }

    pub fn address(&self) -> &IpNetwork {
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
    pub async fn list_active_dpu_ids(
        txn: &mut Transaction<'_, Postgres>,
    ) -> Result<Vec<MachineId>, sqlx::Error> {
        // TODO: Since the state is not directly part of the database and might move,
        // we currently assume all machines as active

        // TODO 2: This method returns a `sqlx::Error` instead of the `CarbideError` most
        // other methods return. The challenge with `CarbideError` is that if we would
        // use this function in another subcomponent of the project, it would also be forced
        // to use `CarbideError`, which gives callers not an option to have a finer grained
        // error type.

        let mut results = Vec::new();
        let mut machine_id_stream =
            sqlx::query_as::<_, DbMachineId>("SELECT machine_id FROM dpu_machines;").fetch(txn);
        while let Some(maybe_id) = machine_id_stream.next().await {
            let id = maybe_id?;
            results.push(id.into_inner());
        }

        Ok(results)
    }

    pub async fn find_by_machine_id(
        txn: &mut Transaction<'_, Postgres>,
        dpu_machine_id: &MachineId,
    ) -> Result<Self, DatabaseError> {
        let query = "SELECT * FROM dpu_machines WHERE machine_id = $1";
        sqlx::query_as(query)
            .bind(dpu_machine_id.to_string())
            .fetch_one(&mut *txn)
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
            .fetch_one(&mut *txn)
            .await
            .map_err(|e| DatabaseError::new(file!(), line!(), query, e))
    }

    pub async fn update_state(
        txn: &mut Transaction<'_, Postgres>,
        dpu_machine_id: &MachineId,
        new_state: ManagedHostState,
    ) -> CarbideResult<()> {
        let machine = Machine::find_one(
            txn,
            dpu_machine_id,
            crate::db::machine::MachineSearchConfig::default(),
        )
        .await?
        .ok_or(CarbideError::NotFoundError {
            kind: "machine",
            id: dpu_machine_id.to_string(),
        })?;

        let version = machine.current_version().increment();

        log::info!("Updating state of DPU {} to {}", machine.id(), new_state);

        machine
            .advance(txn, new_state.clone(), Some(version))
            .await?;

        // Keep both host and dpu's states in sync.
        let Some(host) = Machine::find_host_by_dpu_machine_id(txn, dpu_machine_id).await? else {return Ok(());};
        host.advance(txn, new_state, Some(version)).await?;
        Ok(())
    }
}

#[cfg(test)]
mod test {}
