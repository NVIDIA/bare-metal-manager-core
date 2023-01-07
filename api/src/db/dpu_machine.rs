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
//!
//! Machine - represents a database-backed Machine object
//!

use std::net::Ipv4Addr;

use ipnetwork::IpNetwork;
use mac_address::MacAddress;
use sqlx::postgres::PgRow;
use sqlx::{FromRow, Postgres, Row, Transaction};
use uuid::Uuid;

use crate::CarbideResult;

///
/// A machine is a standalone system that performs network booting via normal DHCP processes.
///
#[derive(Debug)]
pub struct DpuMachine {
    machine_id: uuid::Uuid,
    _vpc_leaf_id: uuid::Uuid,
    _machine_interface_id: uuid::Uuid,
    _mac_address: MacAddress,
    address: IpNetwork,
    _hostname: String,
}

// We need to implement FromRow because we can't associate dependent tables with the default derive
// (i.e. it can't default unknown fields)
impl<'r> FromRow<'r, PgRow> for DpuMachine {
    fn from_row(row: &'r PgRow) -> Result<Self, sqlx::Error> {
        Ok(DpuMachine {
            machine_id: row.try_get("machine_id")?,
            _vpc_leaf_id: row.try_get("vpc_leaf_id")?,
            _machine_interface_id: row.try_get("machine_interfaces_id")?,
            _mac_address: row.try_get("mac_address")?,
            address: row.try_get("address")?,
            _hostname: row.try_get("hostname")?,
        })
    }
}

impl DpuMachine {
    pub fn _vpc_leaf_id(&self) -> &Uuid {
        &self._vpc_leaf_id
    }

    pub fn machine_id(&self) -> &Uuid {
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

    pub async fn find_by_machine_id(
        txn: &mut Transaction<'_, Postgres>,
        dpu_machine_id: &uuid::Uuid,
    ) -> CarbideResult<Self> {
        Ok(
            sqlx::query_as("SELECT * FROM dpu_machines WHERE machine_id = $1::uuid")
                .bind(dpu_machine_id)
                .fetch_one(&mut *txn)
                .await?,
        )
    }

    pub async fn find_by_host_machine_id(
        txn: &mut Transaction<'_, Postgres>,
        machine_id: &uuid::Uuid,
    ) -> CarbideResult<Self> {
        Ok(
            sqlx::query_as("SELECT dm.* From dpu_machines dm JOIN machine_interfaces mi on dm.machine_id = mi.attached_dpu_machine_id WHERE mi.machine_id=$1::uuid")
                .bind(machine_id)
                .fetch_one(&mut *txn)
                .await?,
        )
    }

    pub async fn find_by_ip(
        txn: &mut Transaction<'_, Postgres>,
        query: &Ipv4Addr,
    ) -> CarbideResult<Self> {
        Ok(
            sqlx::query_as("SELECT * FROM dpu_machines WHERE address = $1::inet")
                .bind(query.to_string())
                .fetch_one(&mut *txn)
                .await?,
        )
    }

    pub async fn find_by_hostname(
        txn: &mut Transaction<'_, Postgres>,
        query: &str,
    ) -> CarbideResult<Self> {
        Ok(
            sqlx::query_as("SELECT * FROM dpu_machines WHERE hostname = $1")
                .bind(query)
                .fetch_one(&mut *txn)
                .await?,
        )
    }

    pub async fn find_by_mac_address(
        txn: &mut Transaction<'_, Postgres>,
        query: &MacAddress,
    ) -> CarbideResult<Self> {
        Ok(
            sqlx::query_as("SELECT * FROM dpu_machines WHERE mac_address = $1::macaddr")
                .bind(query)
                .fetch_one(&mut *txn)
                .await?,
        )
    }
}

#[cfg(test)]
mod test {}
