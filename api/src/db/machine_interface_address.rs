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
use std::collections::HashMap;
use std::net::IpAddr;
use std::ops::DerefMut;

use itertools::Itertools;
use sqlx::{FromRow, Postgres, Transaction};

use super::{
    network_segment::NetworkSegmentType, ColumnInfo, DatabaseError, FilterableQueryBuilder,
    ObjectColumnFilter,
};
use forge_uuid::machine::MachineId;
use forge_uuid::machine::MachineInterfaceId;

#[derive(Debug, FromRow, Clone)]
pub struct MachineInterfaceAddress {
    pub interface_id: MachineInterfaceId,
    pub address: IpAddr,
}

#[derive(Clone, Copy)]
pub struct MachineInterfaceIdColumn;
impl ColumnInfo<'_> for MachineInterfaceIdColumn {
    type TableType = MachineInterfaceAddress;
    type ColumnType = MachineInterfaceId;

    fn column_name(&self) -> &'static str {
        "interface_id"
    }
}

impl MachineInterfaceAddress {
    pub fn is_ipv4(&self) -> bool {
        self.address.is_ipv4()
    }

    pub fn is_ipv6(&self) -> bool {
        self.address.is_ipv6()
    }

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

    pub async fn find_by<'a, C: ColumnInfo<'a, TableType = MachineInterfaceAddress>>(
        txn: &mut Transaction<'_, Postgres>,
        filter: ObjectColumnFilter<'a, C>,
    ) -> Result<HashMap<MachineInterfaceId, Vec<MachineInterfaceAddress>>, DatabaseError> {
        let mut query = FilterableQueryBuilder::new("SELECT * FROM machine_interface_addresses")
            .filter(&filter);
        Ok(query
            .build_query_as()
            .fetch_all(txn.deref_mut())
            .await
            .map_err(|e| DatabaseError::new(file!(), line!(), query.sql(), e))?
            .into_iter()
            .into_group_map_by(|address: &MachineInterfaceAddress| address.interface_id))
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
