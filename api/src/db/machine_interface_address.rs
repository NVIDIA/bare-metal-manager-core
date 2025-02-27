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
use std::net::IpAddr;
use std::ops::DerefMut;

use sqlx::{FromRow, Postgres, Transaction};

use super::{DatabaseError, network_segment::NetworkSegmentType};
use forge_uuid::machine::MachineId;
use forge_uuid::machine::MachineInterfaceId;

#[derive(Debug, FromRow, Clone)]
pub struct MachineInterfaceAddress {
    pub address: IpAddr,
}

impl MachineInterfaceAddress {
    pub async fn find_ipv4_for_interface(
        txn: &mut Transaction<'_, Postgres>,
        interface_id: MachineInterfaceId,
    ) -> Result<MachineInterfaceAddress, DatabaseError> {
        let query = "SELECT * FROM machine_interface_addresses WHERE interface_id = $1 AND family(address) = 4";
        sqlx::query_as(query)
            .bind(interface_id)
            .fetch_one(txn.deref_mut())
            .await
            .map_err(|e| DatabaseError::new(file!(), line!(), query, e))
    }

    pub async fn find_by_address(
        txn: &mut Transaction<'_, Postgres>,
        address: IpAddr,
    ) -> Result<Option<MachineInterfaceSearchResult>, DatabaseError> {
        let query = "SELECT mi.id, mi.machine_id, ns.name, ns.network_segment_type
            FROM machine_interface_addresses mia
            INNER JOIN machine_interfaces mi ON mi.id = mia.interface_id
            INNER JOIN network_segments ns ON ns.id = mi.segment_id
            WHERE mia.address = $1::inet
        ";
        sqlx::query_as(query)
            .bind(address)
            .fetch_optional(txn.deref_mut())
            .await
            .map_err(|e| DatabaseError::new(file!(), line!(), query, e))
    }

    pub async fn delete(
        txn: &mut Transaction<'_, Postgres>,
        interface_id: &MachineInterfaceId,
    ) -> Result<(), DatabaseError> {
        let query = "DELETE FROM machine_interface_addresses WHERE interface_id = $1";
        sqlx::query(query)
            .bind(interface_id)
            .execute(txn.deref_mut())
            .await
            .map(|_| ())
            .map_err(|e| DatabaseError::new(file!(), line!(), query, e))
    }
}

#[derive(Debug, FromRow)]
pub struct MachineInterfaceSearchResult {
    pub id: MachineInterfaceId,
    pub machine_id: Option<MachineId>,
    pub name: String,
    pub network_segment_type: NetworkSegmentType,
}
